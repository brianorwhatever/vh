using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using J = System.Text.Json.Nodes.JsonNode;

namespace VHLog;

public sealed class ProtocolException(string code, int? version = null, J? fork = null) : Exception(code)
{
    public JsonObject Report { get; } = MakeReport(code, version, fork);
    private static JsonObject MakeReport(string code, int? version, J? fork)
    {
        var report = Log.Obj("code", code, "version", version, "message", code);
        if (fork is not null) report["fork"] = fork.DeepClone();
        return report;
    }
}

/// <summary>VH-Log interop profile 0, with Bouncy Castle Ed25519.</summary>
public static class Log
{
    private const string Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static readonly JsonSerializerOptions JsonOptions = new() { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    public static JsonObject Obj(params object?[] pairs)
    {
        var o = new JsonObject();
        for (int i = 0; i < pairs.Length; i += 2)
            o[(string)pairs[i]!] = pairs[i + 1] is J node ? node.DeepClone() : JsonSerializer.SerializeToNode(pairs[i + 1], JsonOptions);
        return o;
    }
    private static J? Get(J? v, string key) => v is JsonObject o ? o[key] : null;
    private static bool Has(J? v, string key) => v is JsonObject o && o.ContainsKey(key);
    private static string Str(J? v) => v!.GetValue<string>();
    private static bool IsString(J? v) => v is JsonValue j && j.TryGetValue<string>(out _);
    private static bool IsBool(J? v) => v is JsonValue j && j.TryGetValue<bool>(out _);
    private static double Num(J? v) => double.Parse(v!.ToJsonString(), CultureInfo.InvariantCulture);
    private static bool Integer(J? v) => v is JsonValue j && j.GetValueKind() == JsonValueKind.Number && double.IsFinite(Num(v)) && Num(v) == Math.Truncate(Num(v));
    private static bool Strings(J? v) => v is JsonArray a && a.All(IsString);
    private static JsonArray Arr(J? v) => (JsonArray)v!;
    private static void Fail(string code, int? version = null) => throw new ProtocolException(code, version);
    public static J? Parse(string text)
    {
        // Utf8JsonReader validates escapes; GetString also rejects lone surrogates.
        using var document = JsonDocument.Parse(text);
        return Convert(document.RootElement);
    }
    private static J? Convert(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.Object => ConvertObject(e),
        JsonValueKind.Array => new JsonArray(e.EnumerateArray().Select(Convert).ToArray()),
        JsonValueKind.String => JsonValue.Create(e.GetString()),
        JsonValueKind.Number => double.IsFinite(e.GetDouble()) ? JsonValue.Create(e.GetDouble()) : throw new ArgumentException("non-finite number"),
        JsonValueKind.True => JsonValue.Create(true),
        JsonValueKind.False => JsonValue.Create(false),
        JsonValueKind.Null => null,
        _ => throw new ArgumentException("invalid JSON")
    };
    private static JsonObject ConvertObject(JsonElement e)
    {
        var o = new JsonObject();
        foreach (var p in e.EnumerateObject()) o[p.Name] = Convert(p.Value);
        return o;
    }
    private static string Quote(string s)
    {
        var b = new StringBuilder("\"");
        foreach (char c in s)
            b.Append(c switch { '"' => "\\\"", '\\' => "\\\\", '\b' => "\\b", '\f' => "\\f", '\n' => "\\n", '\r' => "\\r", '\t' => "\\t", < ' ' => "\\u" + ((int)c).ToString("x4"), _ => c.ToString() });
        return b.Append('"').ToString();
    }
    public static string Number(double v)
    {
        if (!double.IsFinite(v)) throw new ArgumentException("non-finite number");
        if (v == 0) return "0";
        string[] parts = Math.Abs(v).ToString("R", CultureInfo.InvariantCulture).ToLowerInvariant().Split('e');
        string[] mantissa = parts[0].Split('.');
        string digits = string.Concat(mantissa).TrimEnd('0');
        int point = mantissa[0].Length + (parts.Length > 1 ? int.Parse(parts[1], CultureInfo.InvariantCulture) : 0);
        while (digits.StartsWith('0')) { digits = digits[1..]; point--; }
        string result;
        if (point > 0 && point <= 21) result = digits.Length <= point ? digits.PadRight(point, '0') : digits[..point] + "." + digits[point..];
        else if (point <= 0 && point > -6) result = "0." + new string('0', -point) + digits;
        else result = digits[0] + (digits.Length > 1 ? "." + digits[1..] : "") + "e" + (point - 1 >= 0 ? "+" : "") + (point - 1).ToString(CultureInfo.InvariantCulture);
        return (v < 0 ? "-" : "") + result;
    }
    public static string Canonicalize(J? v)
    {
        if (v is null) return "null";
        if (v is JsonObject o) return "{" + string.Join(",", o.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => Quote(p.Key) + ":" + Canonicalize(p.Value))) + "}";
        if (v is JsonArray a) return "[" + string.Join(",", a.Select(Canonicalize)) + "]";
        if (IsString(v)) return Quote(Str(v));
        if (IsBool(v)) return v.GetValue<bool>() ? "true" : "false";
        return Number(Num(v));
    }
    public static string Encode(byte[] bytes)
    {
        BigInteger n = new(bytes, isUnsigned: true, isBigEndian: true);
        var b = new StringBuilder();
        while (n > 0) { n = BigInteger.DivRem(n, 58, out var rem); b.Append(Alphabet[(int)rem]); }
        foreach (byte x in bytes) { if (x != 0) break; b.Append('1'); }
        return new string(b.ToString().Reverse().ToArray());
    }
    public static byte[]? Decode(string? s)
    {
        if (s is null) return null;
        BigInteger n = 0;
        foreach (char c in s) { int d = Alphabet.IndexOf(c); if (d < 0) return null; n = n * 58 + d; }
        int zeros = s.TakeWhile(c => c == '1').Count();
        return [.. new byte[zeros], .. (n == 0 ? Array.Empty<byte>() : n.ToByteArray(isUnsigned: true, isBigEndian: true))];
    }
    private static byte[] Sha(string s) => SHA256.HashData(Encoding.UTF8.GetBytes(s));
    public static string Hash(string s) => Encode([0x12, 0x20, .. Sha(s)]);
    private static string CheckHash(string s)
    {
        var b = Decode(s);
        return b is null ? "not-base58" : b.Length == 34 && b[0] == 0x12 && b[1] == 0x20 ? "ok" : "unsupported-algorithm";
    }
    public static byte[]? PublicKey(string? mk)
    {
        if (mk is null || !mk.StartsWith('z')) return null;
        var b = Decode(mk[1..]);
        return b is { Length: 34 } && b[0] == 0xed && b[1] == 1 ? b[2..] : null;
    }
    private static Ed25519PrivateKeyParameters Signer(string seed)
    {
        if (!Regex.IsMatch(seed, "\\A[0-9a-fA-F]{64}\\z")) throw new ArgumentException("seed must be 32-byte hex");
        return new Ed25519PrivateKeyParameters(System.Convert.FromHexString(seed), 0);
    }
    public static string Multikey(string seed) => "z" + Encode([0xed, 1, .. Signer(seed).GeneratePublicKey().GetEncoded()]);
    private static string? MethodKey(J? vm)
    {
        if (!IsString(vm)) return null;
        var m = Regex.Match(Str(vm), "\\Adid:key:([^#]+)#(.+)\\z");
        return m.Success && m.Groups[1].Value == m.Groups[2].Value && PublicKey(m.Groups[1].Value) is not null ? m.Groups[1].Value : null;
    }
    private static byte[] SigningInput(J? document, J config) => [.. Sha(Canonicalize(config)), .. Sha(Canonicalize(document))];
    public static JsonObject Sign(J? document, string seed, J? options = null)
    {
        string mk = Multikey(seed);
        var config = Obj("type", "DataIntegrityProof", "cryptosuite", "eddsa-jcs-2022", "verificationMethod", Has(options, "verificationMethod") ? Get(options, "verificationMethod") : JsonValue.Create($"did:key:{mk}#{mk}"));
        if (Has(options, "created")) config["created"] = Get(options, "created")?.DeepClone();
        config["proofPurpose"] = "assertionMethod";
        var signer = new Ed25519Signer(); signer.Init(true, Signer(seed));
        byte[] data = SigningInput(document, config); signer.BlockUpdate(data, 0, data.Length);
        config["proofValue"] = "z" + Encode(signer.GenerateSignature()); return config;
    }
    public static bool Verify(J? document, J? proof)
    {
        if (proof is not JsonObject || !IsString(Get(proof, "type")) || Str(Get(proof, "type")) != "DataIntegrityProof" || !IsString(Get(proof, "cryptosuite")) || Str(Get(proof, "cryptosuite")) != "eddsa-jcs-2022" || !IsString(Get(proof, "proofPurpose")) || Str(Get(proof, "proofPurpose")) != "assertionMethod") return false;
        string? mk = MethodKey(Get(proof, "verificationMethod")); J? value = Get(proof, "proofValue");
        if (mk is null || !IsString(value) || !Str(value).StartsWith('z')) return false;
        byte[]? signature = Decode(Str(value)[1..]); if (signature is not { Length: 64 }) return false;
        var config = (JsonObject)proof.DeepClone(); config.Remove("proofValue");
        try { var signer = new Ed25519Signer(); signer.Init(false, new Ed25519PublicKeyParameters(PublicKey(mk)!, 0)); byte[] data = SigningInput(document, config); signer.BlockUpdate(data, 0, data.Length); return signer.VerifySignature(signature); }
        catch (ArgumentException) { return false; }
    }
    private static JsonObject WithoutProof(J e) { var d = (JsonObject)e.DeepClone(); d.Remove("proof"); return d; }
    public static string Scid(J e) => Hash(Canonicalize(WithoutProof(e)));
    public static string EntryHash(J e, string previous)
    {
        var d = WithoutProof(e); d["versionId"] = previous;
        return Hash(Canonicalize(d));
    }
    private static List<string> Lines(string log) { var ls = log.Split('\n').ToList(); if (ls[^1] == "") ls.RemoveAt(ls.Count - 1); return ls; }
    public static JsonObject Create(J input)
    {
        var p = (JsonObject)Get(input, "parameters")!.DeepClone();
        if (!p.ContainsKey("logVersion")) p["logVersion"] = "vh-log:1.0";
        if (!p.ContainsKey("scid")) p["scid"] = "{SCID}";
        var e = Obj("versionId", "{SCID}", "versionTime", Get(input, "versionTime"), "parameters", p, "state", Get(input, "state"));
        string id = Scid(e); e = (JsonObject)Parse(Canonicalize(e).Replace("{SCID}", id))!;
        e["versionId"] = "1-" + EntryHash(e, id);
        var proofs = new JsonArray(); foreach (J? seed in Arr(Get(input, "signers"))) proofs.Add(Sign(e, Str(seed), Obj("created", Get(input, "versionTime")))); e["proof"] = proofs;
        return Obj("log", Canonicalize(e) + "\n", "scid", id, "versionId", e["versionId"]);
    }
    public static JsonObject Update(J input)
    {
        string log = Str(Get(input, "log")), previous = Str(Get(Parse(Lines(log)[^1]), "versionId"));
        var e = Obj("versionId", previous, "versionTime", Get(input, "versionTime"), "parameters", Get(input, "parameters") ?? Obj(), "state", Get(input, "state"));
        e["versionId"] = (long.Parse(previous.Split('-')[0], CultureInfo.InvariantCulture) + 1) + "-" + EntryHash(e, previous);
        var proofs = new JsonArray(); foreach (J? seed in Arr(Get(input, "signers"))) proofs.Add(Sign(e, Str(seed), Obj("created", Get(input, "versionTime")))); e["proof"] = proofs;
        return Obj("log", log + (log.EndsWith('\n') ? "" : "\n") + Canonicalize(e) + "\n", "versionId", e["versionId"]);
    }
    public static long? Time(J? value)
    {
        if (!IsString(value)) return null;
        var m = Regex.Match(Str(value), @"\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:Z|\+00:00)\z");
        if (!m.Success) return null;
        int[] v = m.Groups.Cast<Group>().Skip(1).Select(g => int.Parse(g.Value, CultureInfo.InvariantCulture)).ToArray();
        int y = v[0], mo = v[1], d = v[2], h = v[3], mi = v[4], s = v[5];
        bool leap = y % 4 == 0 && y % 100 != 0 || y % 400 == 0;
        int[] days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        if (mo < 1 || mo > 12 || d < 1 || d > days[mo - 1] || h > 23 || mi > 59 || s > 59) return null;
        // Use a 400-year shift for year zero, outside DateTime's range.
        return new DateTime(y == 0 ? 400 : y, mo, d, h, mi, s, DateTimeKind.Utc).Ticks / TimeSpan.TicksPerSecond - (y == 0 ? 146097L * 86400 : 0);
    }
    private static JsonObject Parameters(JsonObject raw, JsonObject? previous, int n)
    {
        if (raw.Any(p => p.Value is null)) Fail("invalid-parameter", n);
        if (previous is null && !Has(raw, "logVersion") || Has(raw, "logVersion") && (!IsString(raw["logVersion"]) || Str(raw["logVersion"]) != "vh-log:1.0")) Fail("unsupported-log-version", n);
        if (previous is not null ? Has(raw, "scid") : !IsString(raw["scid"]) || !Has(raw, "updateKeys")) Fail("invalid-parameter", n);
        if (Has(raw, "updateKeys")) { if (!Strings(raw["updateKeys"])) Fail("invalid-parameter", n); foreach (var k in Arr(raw["updateKeys"])) if (PublicKey(Str(k)) is null) Fail("invalid-parameter", n); }
        if (Has(raw, "nextKeyHashes")) { if (!Strings(raw["nextKeyHashes"])) Fail("invalid-parameter", n); foreach (var h in Arr(raw["nextKeyHashes"])) if (CheckHash(Str(h)) != "ok") Fail("invalid-parameter", n); }
        var p = previous is null ? Obj("nextKeyHashes", new JsonArray(), "witness", null, "watchers", new JsonArray(), "ttl", 3600) : (JsonObject)previous.DeepClone();
        foreach (string k in new[] { "logVersion", "scid", "updateKeys", "nextKeyHashes", "witness", "watchers", "ttl" }) if (Has(raw, k)) p[k] = raw[k]?.DeepClone();
        p["deactivated"] = Has(raw, "deactivated") ? raw["deactivated"]?.DeepClone() : JsonValue.Create(false);
        if (Has(raw, "witness"))
        {
            var w = raw["witness"]; if (w is not JsonObject) Fail("invalid-parameter", n);
            if (((JsonObject)w!).Count == 0) p["witness"] = null;
            else
            {
                var ws = Get(w, "witnesses"); if (ws is not JsonArray || Arr(ws).Count == 0) Fail("invalid-parameter", n);
                var ids = new HashSet<string>();
                foreach (var x in Arr(ws)) { var id = Get(x, "id"); if (!IsString(id) || !Str(id).StartsWith("did:key:", StringComparison.Ordinal) || PublicKey(Str(id)[8..]) is null || !ids.Add(Str(id))) Fail("invalid-parameter", n); }
                var t = Get(w, "threshold"); if (!Integer(t) || Num(t) < 1 || Num(t) > ids.Count) Fail("invalid-parameter", n);
                p["witness"] = Obj("threshold", t, "witnesses", ws);
            }
        }
        if (Has(raw, "watchers")) { if (!Strings(raw["watchers"])) Fail("invalid-parameter", n); foreach (var u in Arr(raw["watchers"])) if (!Regex.IsMatch(Str(u), @"\A[\x21-\x7e]+\z") || !Regex.IsMatch(Str(u), @"\Ahttps?://[^/?#]")) Fail("invalid-parameter", n); }
        if (!IsBool(p["deactivated"]) || !Integer(p["ttl"]) || Num(p["ttl"]) < 0 || Num(p["ttl"]) > 2147483648.0) Fail("invalid-parameter", n);
        if (previous is not null && Arr(previous["nextKeyHashes"]).Count > 0)
        {
            if (!Has(raw, "updateKeys") || !Has(raw, "nextKeyHashes")) Fail("prerotation-violation", n);
            foreach (var key in Arr(raw["updateKeys"])) if (!Arr(previous["nextKeyHashes"]).Any(h => Str(h) == Hash(Str(key)))) Fail("prerotation-violation", n);
        }
        return p;
    }
    private sealed record Entry(JsonObject E, JsonObject P, int N, long Time, J? Rule);
    private sealed record Verified(List<Entry> Entries, List<string> Lines, JsonObject? Failure);
    private static Entry VerifyEntry(JsonObject e, Entry? previous, long now)
    {
        int n = previous is null ? 1 : previous.N + 1;
        if (previous is not null && previous.P["deactivated"]!.GetValue<bool>()) Fail("entry-after-deactivation", n);
        if (!e.Select(p => p.Key).ToHashSet().SetEquals(["versionId", "versionTime", "parameters", "state", "proof"]) || !IsString(e["versionId"]) || !IsString(e["versionTime"]) || e["parameters"] is not JsonObject || e["state"] is not JsonObject || e["proof"] is not JsonArray) Fail("invalid-entry", n);
        var p = Parameters((JsonObject)e["parameters"]!, previous?.P, n);
        var active = Arr(previous is null || Arr(previous.P["nextKeyHashes"]).Count > 0 ? p["updateKeys"] : previous.P["updateKeys"]);
        var rule = previous is null || Has(e["parameters"], "witness") && previous.P["witness"] is null ? p["witness"] : previous.P["witness"];
        if (Arr(e["proof"]).Count == 0) Fail("invalid-proof", n);
        foreach (var proof in Arr(e["proof"])) { string? mk = MethodKey(Get(proof, "verificationMethod")); if (mk is null) Fail("invalid-proof", n); if (!active.Any(k => Str(k) == mk)) Fail("unauthorized-key", n); if (!Verify(WithoutProof(e), proof)) Fail("invalid-proof", n); }
        var m = Regex.Match(Str(e["versionId"]), @"\A([1-9][0-9]*)-([^-]+)\z"); if (!m.Success || m.Groups[1].Value != n.ToString(CultureInfo.InvariantCulture)) Fail("invalid-version-id", n);
        string check = CheckHash(m.Groups[2].Value); if (check == "not-base58") Fail("invalid-version-id", n); if (check != "ok") Fail("invalid-hash-algorithm", n);
        if (EntryHash(e, Str(previous is null ? p["scid"] : previous.E["versionId"])) != m.Groups[2].Value) Fail("entry-hash-mismatch", n);
        long? t = Time(e["versionTime"]); if (t is null || previous is not null && t <= previous.Time) Fail("invalid-version-time", n); if (t > now + 300) Fail("future-version-time", n);
        if (previous is null)
        {
            string id = Str(p["scid"]); check = CheckHash(id); if (check == "unsupported-algorithm") Fail("invalid-hash-algorithm", n); if (check != "ok") Fail("scid-mismatch", n);
            var rest = WithoutProof(e); rest["versionId"] = "{SCID}";
            if (Scid(Parse(Canonicalize(rest).Replace(id, "{SCID}"))!) != id) Fail("scid-mismatch", n);
        }
        return new(e, p, n, t!.Value, rule);
    }
    private static Verified VerifyLog(string log, J? witness, bool hasWitness, long now)
    {
        var ls = Lines(log); var entries = new List<Entry>(); JsonObject? failure = null;
        if (ls.Count == 0) return new(entries, ls, new ProtocolException("invalid-log").Report);
        for (int i = 0; i < ls.Count; i++)
        {
            try
            {
                J? raw = null;
                try { raw = Parse(ls[i]); } catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException) { Fail("invalid-log", i + 1); }
                if (raw is not JsonObject) Fail("invalid-log", i + 1);
                entries.Add(VerifyEntry((JsonObject)raw!, entries.Count > 0 ? entries[^1] : null, now));
            }
            catch (ProtocolException e) { failure = e.Report; break; }
        }
        for (int i = 0; i < entries.Count; i++)
        {
            var rule = entries[i].Rule; if (rule is null) continue;
            var file = hasWitness ? witness : new JsonArray(); string? code = null;
            bool valid = file is JsonArray && Arr(file).All(r => IsString(Get(r, "versionId")) && Get(r, "proof") is JsonArray);
            if (!valid) code = "invalid-witness-file";
            else
            {
                var allowed = Arr(Get(rule, "witnesses")).Select(w => Str(Get(w, "id"))).ToHashSet(); var approved = new HashSet<string>();
                foreach (var r in Arr(file))
                {
                    int index = entries.FindIndex(e => Str(e.E["versionId"]) == Str(Get(r, "versionId"))); if (index < i) continue;
                    foreach (var proof in Arr(Get(r, "proof"))) { string? mk = MethodKey(Get(proof, "verificationMethod")); string id = "did:key:" + mk; if (mk is not null && allowed.Contains(id) && Verify(Obj("versionId", Get(r, "versionId")), proof)) approved.Add(id); }
                }
                if (approved.Count < Num(Get(rule, "threshold"))) code = "witness-threshold-not-met";
            }
            if (code is not null) { failure = new ProtocolException(code, i + 1).Report; entries = entries.Take(i).ToList(); break; }
        }
        return new(entries, ls, failure);
    }
    private static J? LineValue(string? line) { try { return line is null ? null : Parse(line); } catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException) { return null; } }
    private static string? LineId(List<string> ls, int i) { var id = Get(LineValue(i >= 0 && i < ls.Count ? ls[i] : null), "versionId"); return IsString(id) ? Str(id) : null; }
    private static void Retained(Verified v, string source, J? id, JsonArray warnings)
    {
        var m = Regex.Match(IsString(id) ? Str(id) : "", @"\A([1-9][0-9]*)-"); if (!m.Success) Fail("invalid-option");
        var big = BigInteger.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
        if (big > v.Entries.Count) { warnings.Add(Obj("code", "retained-version-not-found", "message", "retained version not found")); return; }
        int n = (int)big; var actual = v.Entries[n - 1].E["versionId"];
        if (Str(actual) != Str(id)) throw new ProtocolException("fork-detected", n, Obj("version", n, "copies", new JsonArray(Obj("source", "retained", "versionId", id), Obj("source", source, "versionId", actual))));
    }
    private static JsonObject Result(Verified v, JsonObject options, JsonArray warnings, JsonArray? copies = null)
    {
        Entry? target = null; var failure = v.Failure;
        void Invalid() => Fail(Str(failure!["code"]), (int)Num(failure["version"]));
        if (Has(options, "versionId"))
        {
            target = v.Entries.Find(e => Str(e.E["versionId"]) == Str(options["versionId"]));
            if (target is null) for (int i = v.Entries.Count; i < v.Lines.Count; i++) if (LineId(v.Lines, i) == Str(options["versionId"])) Invalid();
        }
        else if (Has(options, "versionNumber"))
        {
            double n = Num(options["versionNumber"]); if (n <= v.Entries.Count) target = v.Entries[(int)n - 1]; else if (n <= v.Lines.Count) Invalid();
        }
        else if (Has(options, "versionTime"))
        {
            long t = Time(options["versionTime"])!.Value;
            if (failure is not null) { long? invalidTime = Time(Get(LineValue(v.Lines[v.Entries.Count]), "versionTime")); if (invalidTime is not null && invalidTime <= t) Invalid(); }
            target = v.Entries.FindLast(e => e.Time <= t);
        }
        else target = v.Entries[^1];
        if (target is null) Fail("not-found");
        var first = v.Entries[0]; var last = v.Entries[^1];
        if (failure is not null) warnings.Add(Obj("code", "invalid-entries", "message", failure["message"]));
        var meta = Obj("versionId", target!.E["versionId"], "versionTime", target.E["versionTime"], "versionNumber", target.N,
            "created", first.E["versionTime"], "updated", last.E["versionTime"], "scid", first.P["scid"], "deactivated", last.P["deactivated"],
            "ttl", last.P["ttl"], "witness", last.P["witness"], "watchers", last.P["watchers"], "updateKeys", target.P["updateKeys"], "nextKeyHashes", target.P["nextKeyHashes"], "warnings", warnings);
        if (copies is not null) meta["copies"] = copies.DeepClone();
        return Obj("valid", true, "state", target.E["state"], "metadata", meta, "firstInvalidVersion", failure is null ? null : v.Entries.Count + 1, "error", failure);
    }
    private static JsonObject ResolveCopies(J input, long now, JsonObject options)
    {
        var primary = Obj("source", "primary", "log", Get(input, "log")); if (Has(input, "witness")) primary["witness"] = Get(input, "witness")?.DeepClone();
        var all = new List<J?> { primary }; if (Get(input, "copies") is JsonArray extra) all.AddRange(extra);
        var warnings = new JsonArray(); var status = new Dictionary<int, string>(); var cache = new Dictionary<int, Verified>();
        Verified VerifyCopy(int i) { if (!cache.TryGetValue(i, out var v)) cache[i] = v = VerifyLog(Str(Get(all[i], "log")), Get(all[i], "witness"), Has(all[i], "witness"), now); return v; }
        void Invalid(int i) { status[i] = "invalid"; warnings.Add(Obj("code", "copy-invalid", "source", Get(all[i], "source"), "message", "copy fails verification")); }
        for (int i = 0; i < all.Count; i++) if (Has(all[i], "unavailable")) { status[i] = "unavailable"; warnings.Add(Obj("code", "copy-unavailable", "source", Get(all[i], "source"), "message", Get(all[i], "unavailable"))); }
        int reference = -1;
        for (int i = 0; i < all.Count; i++) { if (status.ContainsKey(i)) continue; if (VerifyCopy(i).Failure is null) { reference = i; break; } Invalid(i); }
        if (reference < 0) return Obj("valid", false, "error", VerifyCopy(0).Failure);
        var matched = new HashSet<int> { reference };
        for (int i = 0; i < all.Count; i++)
        {
            if (status.ContainsKey(i) || matched.Contains(i)) continue;
            var r = VerifyCopy(reference); var c = VerifyCopy(i); var rl = r.Lines; var cl = c.Lines;
            if (cl.Count == 0) { Invalid(i); continue; }
            bool same = cl.Count <= rl.Count && LineId(cl, cl.Count - 1) == Str(r.Entries[cl.Count - 1].E["versionId"]);
            bool extends = cl.Count > rl.Count && LineId(cl, rl.Count - 1) == Str(r.Entries[^1].E["versionId"]);
            if (same) matched.Add(i);
            else if (extends && c.Failure is null) { matched.Add(i); reference = i; }
            else if (c.Failure is not null) Invalid(i);
            else
            {
                int k = 0; while (k < Math.Min(rl.Count, cl.Count) && LineId(rl, k) == LineId(cl, k)) k++;
                throw new ProtocolException("fork-detected", k + 1, Obj("version", k + 1, "copies", new JsonArray(
                    Obj("source", Get(all[reference], "source"), "versionId", LineId(rl, k) ?? ""), Obj("source", Get(all[i], "source"), "versionId", LineId(cl, k) ?? ""))));
            }
        }
        var verified = VerifyCopy(reference);
        if (Has(input, "retainedVersionId")) Retained(verified, Str(Get(all[reference], "source")), Get(input, "retainedVersionId"), warnings);
        var copies = new JsonArray(); int usable = 0;
        for (int i = 0; i < all.Count; i++)
        {
            var source = Get(all[i], "source"); var report = Obj("source", source);
            if (status.TryGetValue(i, out string? s))
            {
                report["status"] = s;
                if (s != "unavailable") { var ls = VerifyCopy(i).Lines; string? id = LineId(ls, ls.Count - 1); if (id is not null) report["versionId"] = id; }
            }
            else
            {
                var ls = VerifyCopy(i).Lines; bool behind = ls.Count < verified.Lines.Count;
                report["status"] = behind ? "behind" : "current"; report["versionId"] = LineId(ls, ls.Count - 1); usable++;
                if (behind) warnings.Add(Obj("code", "copy-behind", "source", source, "message", "copy is behind"));
            }
            copies.Add(report);
        }
        if (usable < (Has(options, "minCopies") ? Num(options["minCopies"]) : 1)) Fail("min-copies-not-met");
        return Result(verified, options, warnings, copies);
    }
    public static JsonObject Resolve(J input)
    {
        try
        {
            long? now = Time(Get(input, "now")); if (now is null) Fail("invalid-option");
            J raw = Get(input, "options") ?? Obj(); if (raw is not JsonObject) Fail("invalid-option"); var options = (JsonObject)raw;
            string[] allowed = ["versionId", "versionTime", "versionNumber", "minCopies"];
            if (options.Any(p => !allowed.Contains(p.Key)) || options.Count(p => p.Key is "versionId" or "versionTime" or "versionNumber") > 1) Fail("invalid-option");
            if (Has(options, "versionId") && !IsString(options["versionId"])) Fail("invalid-option");
            if (Has(options, "versionTime") && Time(options["versionTime"]) is null) Fail("invalid-option");
            foreach (string k in new[] { "versionNumber", "minCopies" }) if (Has(options, k) && (!Integer(options[k]) || Num(options[k]) < 1)) Fail("invalid-option");
            if (Has(input, "copies") || Has(options, "minCopies") && Num(options["minCopies"]) > 1) return ResolveCopies(input, now!.Value, options);
            var v = VerifyLog(Str(Get(input, "log")), Get(input, "witness"), Has(input, "witness"), now!.Value);
            if (v.Entries.Count == 0) return Obj("valid", false, "error", v.Failure);
            var warnings = new JsonArray(); if (Has(input, "retainedVersionId")) Retained(v, "primary", Get(input, "retainedVersionId"), warnings);
            return Result(v, options, warnings);
        }
        catch (ProtocolException e) { return Obj("valid", false, "error", e.Report); }
    }
    public static J Dispatch(string op, J input) => op switch
    {
        "jcs" => Obj("output", Canonicalize(Parse(Str(Get(input, "text"))))),
        "hash" => Obj("output", Hash(Str(Get(input, "data")))),
        "key-hash" => Obj("output", Hash(Str(Get(input, "multikey")))),
        "multikey" => Obj("multikey", Multikey(Str(Get(input, "seed")))),
        "scid" => Obj("scid", Scid(Get(input, "entry")!)),
        "entry-hash" => Obj("hash", EntryHash(Get(input, "entry")!, Str(Get(input, "previousVersionId")))),
        "sign" => Obj("proof", Sign(Get(input, "document"), Str(Get(input, "seed")), input)),
        "verify" => Obj("valid", Verify(Get(input, "document"), Get(input, "proof"))),
        "witness" => Obj("proof", Sign(Obj("versionId", Get(input, "versionId")), Str(Get(input, "seed")), input)),
        "create" => Create(input),
        "update" => Update(input),
        "resolve" => Resolve(input),
        _ => throw new ArgumentException("unknown operation " + op)
    };
}
