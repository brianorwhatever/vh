using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using J = System.Text.Json.Nodes.JsonNode;

namespace VHLog;

/// <summary>A did:vh error: invalidDid, invalidDidUrl, invalidOptions, notFound, ...</summary>
public sealed class DidVhException(string code, string detail, JsonObject? vhLog = null) : Exception(detail)
{
    public string Code { get; } = code;
    public JsonObject? VhLog { get; } = vhLog;
}

/// <summary>
/// did:vh (docs/didvh-profile.md). A did:vh DID log is verified by the VH-Log code with the
/// did:vh specialisation; this class adds the DID syntax, the srcLog/srcWitness and DID URL
/// rules, the resolution options, and DID Resolution metadata and errors.
/// </summary>
public static class DidVh
{
    public const string Method = "did:vh:1.0";
    public const string Prefix = "did:vh:";
    private static readonly Regex MethodSyntax = new(@"\Adid:vh:(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\z");
    private static readonly Regex ScidSyntax = new(@"\A[1-9A-HJ-NP-Za-km-z]{46}\z");

    private static bool IsString(J? v) => v is JsonValue j && j.GetValueKind() == JsonValueKind.String;
    private static string? AsString(J? v) => IsString(v) ? v!.GetValue<string>() : null;
    private static double Num(J? v) => v!.GetValue<double>();
    private static bool IsNumber(J? v) => v is JsonValue j && j.GetValueKind() == JsonValueKind.Number;
    private static J? Clone(J? v) => v?.DeepClone();
    private static DidVhException Options(string why) => new("invalidOptions", why);
    private static DidVhException Url(string why) => new("invalidDidUrl", why);

    // ---------------------------------------------------------- the DID

    /// <summary>The SCID of a did:vh DID, or null if it does not match the ABNF.</summary>
    public static string? ParseDid(J? did)
    {
        var s = AsString(did);
        if (s is null || !s.StartsWith(Prefix, StringComparison.Ordinal)) return null;
        var scid = s[Prefix.Length..];
        return ScidSyntax.IsMatch(scid) ? scid : null;
    }

    /// <summary>
    /// The did:vh specialisation: method instead of logVersion, a closed parameter set, and
    /// state.id = did:vh:SCID in every entry. With expectedScid, the log must be for that DID.
    /// </summary>
    public static Spec Specialisation(string? expectedScid = null) => new("method", [Method], MethodSyntax, [], (state, scid, n) =>
    {
        if (expectedScid is not null && scid != expectedScid || AsString(state["id"]) != Prefix + scid)
            throw new ProtocolException("invalid-state", n);
    });

    // ---------------------------------------------------------- create / update

    /// <summary>Creates a did:vh DID log; like VH-Log generation it does not validate its input.</summary>
    public static JsonObject Create(J input)
    {
        var r = Log.Create(Log.Obj("state", input["document"], "parameters", input["parameters"], "versionTime", input["versionTime"], "signers", input["signers"]), "method", Method);
        return Log.Obj("log", r["log"], "did", Prefix + r["scid"]!.GetValue<string>(), "scid", r["scid"], "versionId", r["versionId"]);
    }

    /// <summary>Appends an entry; deactivate with parameters {deactivated: true}.</summary>
    public static JsonObject Update(J input)
    {
        var u = Log.Obj("log", input["log"], "state", input["document"], "versionTime", input["versionTime"], "signers", input["signers"]);
        if (input["parameters"] is not null) u["parameters"] = Clone(input["parameters"]);
        return Log.Update(u);
    }

    // ---------------------------------------------------------- shared URL checks

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>Percent-decodes s as UTF-8, or null if an escape or the UTF-8 is malformed.</summary>
    public static string? PercentDecode(string s)
    {
        var bytes = new List<byte>();
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] == '%')
            {
                if (i + 3 > s.Length || !Uri.IsHexDigit(s[i + 1]) || !Uri.IsHexDigit(s[i + 2])) return null;
                bytes.Add(System.Convert.ToByte(s.Substring(i + 1, 2), 16));
                i += 2;
            }
            else
            {
                int len = char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]) ? 2 : 1;
                try { bytes.AddRange(StrictUtf8.GetBytes(s.Substring(i, len))); } catch (ArgumentException) { return null; }
                i += len - 1;
            }
        }
        try { return StrictUtf8.GetString(bytes.ToArray()); } catch (ArgumentException) { return null; }
    }

    /// <summary>Unicode White_Space (profile §3.2).</summary>
    private static bool Whitespace(int c) =>
        c is >= 0x09 and <= 0x0d or 0x20 or 0x85 or 0xa0 or 0x1680 or >= 0x2000 and <= 0x200a or 0x2028 or 0x2029 or 0x202f or 0x205f or 0x3000;

    private static bool Octet(string s) => Regex.IsMatch(s, @"\A(0|[1-9][0-9]{0,2})\z") && int.Parse(s) <= 255;

    private static bool LoopbackHost(string host)
    {
        if (host is "localhost" or "[::1]") return true;
        var parts = host.Split('.');
        return parts.Length == 4 && parts.All(Octet) && parts[0] == "127";
    }

    private static bool DomainName(string host)
    {
        var name = host.EndsWith('.') ? host[..^1] : host;
        if (name.Length == 0 || name.Length > 253) return false;
        var labels = name.Split('.');
        if (Regex.IsMatch(labels[^1], @"\A[0-9]+\z")) return false;
        return labels.All(l => Regex.IsMatch(l, @"\A[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\z"));
    }

    private static readonly Regex Printable = new(@"\A[\x21-\x7e]+\z");
    private static readonly Regex SchemeSyntax = new(@"\A([A-Za-z][A-Za-z0-9+.-]*):(.*)\z", RegexOptions.Singleline);

    /// <summary>Splits scheme:rest (profile §3.1 steps 1–2), the scheme lowercased.</summary>
    private static (string Scheme, string Tail)? SplitScheme(J? value)
    {
        var s = AsString(value);
        if (s is null || !Printable.IsMatch(s)) return null;
        var m = SchemeSyntax.Match(s);
        return m.Success ? (m.Groups[1].Value.ToLowerInvariant(), m.Groups[2].Value) : null;
    }

    /// <summary>Checks an http(s) authority (profile §3.1 step 4).</summary>
    private static bool Authority(string authority, string scheme)
    {
        if (authority.Contains('@')) return false;
        string host; string? port = null;
        if (authority.StartsWith('['))
        {
            int close = authority.IndexOf(']');
            if (close < 0) return false;
            host = authority[..(close + 1)];
            var after = authority[(close + 1)..];
            if (after.Length > 0)
            {
                if (!after.StartsWith(':')) return false;
                port = after[1..];
            }
        }
        else
        {
            int colon = authority.IndexOf(':');
            host = colon < 0 ? authority : authority[..colon];
            if (colon >= 0) port = authority[(colon + 1)..];
        }
        host = host.ToLowerInvariant();
        if (port is not null && !(Regex.IsMatch(port, @"\A[0-9]{1,5}\z") && int.Parse(port) <= 65535)) return false;
        if (scheme == "http") return LoopbackHost(host);
        return !host.StartsWith('[') && DomainName(host);
    }

    /// <summary>
    /// Checks the segments of a path starting with "/": each is percent-decoded and must not be
    /// "." or ".." or contain "/", "\" or NUL. With strict (src), also non-empty and not
    /// starting or ending with White_Space.
    /// </summary>
    private static bool Segments(string path, bool strict)
    {
        foreach (var raw in path[1..].Split('/'))
        {
            var s = PercentDecode(raw);
            if (s is null || s is "." or ".." || s.IndexOfAny(['/', '\\', '\0']) >= 0) return false;
            if (strict && (s.Length == 0 || Whitespace(char.ConvertToUtf32(s, 0)) || Whitespace(LastCodePoint(s)))) return false;
        }
        return true;
    }

    private static int LastCodePoint(string s) =>
        s.Length >= 2 && char.IsSurrogatePair(s[^2], s[^1]) ? char.ConvertToUtf32(s[^2], s[^1]) : s[^1];

    // ---------------------------------------------------------- srcLog / srcWitness

    /// <summary>Validates a srcLog or srcWitness reference (profile §3.1); returns its kind.</summary>
    public static string CheckRef(J? reference)
    {
        var (scheme, rest) = SplitScheme(reference) ?? throw Options("not a printable-ASCII absolute URL");
        if (rest.Contains('#')) throw Options("reference must not have a fragment");
        if (scheme is "https" or "http")
        {
            if (!rest.StartsWith("//", StringComparison.Ordinal)) throw Options("missing authority");
            var tail = rest[2..];
            int end = tail.IndexOfAny(['/', '?']);
            var auth = end < 0 ? tail : tail[..end];
            var after = end < 0 ? "" : tail[end..];
            int q = after.IndexOf('?');
            var path = q < 0 ? after : after[..q];
            if (!Authority(auth, scheme)) throw Options(scheme == "http" ? "http is only allowed with a loopback host" : "invalid https host");
            if (path.Length == 0) throw Options("reference must have a path");
            if (!Segments(path, false)) throw Options("invalid path segment");
            return scheme == "http" ? "loopback" : "web";
        }
        if (scheme == "file")
        {
            if (rest.Contains('?')) throw Options("file URL must not have a query");
            string path;
            if (rest.StartsWith("//", StringComparison.Ordinal))
            {
                int slash = rest.IndexOf('/', 2);
                if (slash < 0) throw Options("file URL needs an absolute path");
                var host = rest[2..slash].ToLowerInvariant();
                if (host is not ("" or "localhost")) throw Options("file URL host must be empty or localhost");
                path = rest[slash..];
            }
            else
            {
                if (!rest.StartsWith('/')) throw Options("file URL needs an absolute path");
                path = rest;
            }
            if (!Segments(path, false)) throw Options("invalid path segment");
            return "file";
        }
        if (rest.Length == 0) throw Options("empty URL");
        return "other";
    }

    // ---------------------------------------------------------- the src DID URL parameter

    /// <summary>Validates a decoded src value and derives srcLog and srcWitness (profile §3.2).</summary>
    public static JsonObject SrcReferences(J? src)
    {
        var (scheme, rest) = SplitScheme(src) ?? throw Url("src is not a printable-ASCII absolute URL");
        if (rest.Contains('?') || rest.Contains('#')) throw Url("src must not have a query or fragment");
        if (scheme is "http" or "file") throw Url($"{scheme} is not allowed in a DID URL");
        if (!rest.StartsWith("//", StringComparison.Ordinal) || rest.Length == 2 || rest[2] == '/') throw Url("src is not a hierarchical URL with an authority");
        var b = rest.EndsWith('/') ? rest[..^1] : rest;
        if (scheme == "https")
        {
            int slash = b.IndexOf('/', 2);
            var auth = slash < 0 ? b[2..] : b[2..slash];
            var path = slash < 0 ? "" : b[slash..];
            if (!Authority(auth, "https")) throw Url("invalid https host");
            if (path.Length > 0 && !Segments(path, true)) throw Url("invalid path segment");
        }
        var location = $"{scheme}:{b}";
        return Log.Obj("srcLog", location + "/did.jsonl", "srcWitness", location + "/did-witness.json");
    }

    // ---------------------------------------------------------- DID URLs

    private static readonly string[] UrlParameters = ["src", "versionId", "versionTime", "versionNumber"];
    private static readonly string[] OptionOnly = ["didLog", "didWitness", "srcLog", "srcWitness", "checkWatchers", "extraWatchers", "minCopies", "includeDidLog"];

    /// <summary>Parses a did:vh DID URL as a dereferencer does (profile §4): {did, options, fragment?}.</summary>
    public static JsonObject ParseDidUrl(J? didUrl)
    {
        var s = AsString(didUrl) ?? throw Url("DID URL is not a string");
        int hash = s.IndexOf('#');
        var beforeFragment = hash < 0 ? s : s[..hash];
        int q = beforeFragment.IndexOf('?');
        var did = q < 0 ? beforeFragment : beforeFragment[..q];
        if (ParseDid(JsonValue.Create(did)) is null) throw Url("not a did:vh DID");
        var seen = new HashSet<string>();
        var options = new JsonObject();
        if (q >= 0)
        {
            foreach (var pair in beforeFragment[(q + 1)..].Split('&'))
            {
                int eq = pair.IndexOf('=');
                if (eq < 0) throw Url("query parameter has no value");
                var key = PercentDecode(pair[..eq]);
                var value = PercentDecode(pair[(eq + 1)..]);
                if (key is null || value is null) throw Url("malformed percent-encoding");
                if (OptionOnly.Contains(key)) throw Url($"{key} is a resolution option");
                if (!UrlParameters.Contains(key)) continue;
                if (!seen.Add(key)) throw Url($"{key} given more than once");
                switch (key)
                {
                    case "src":
                        foreach (var (k, v) in SrcReferences(JsonValue.Create(value))) options[k] = Clone(v);
                        break;
                    case "versionNumber":
                        if (!Regex.IsMatch(value, @"\A[1-9][0-9]{0,15}\z")) throw Url("versionNumber must be a positive integer");
                        options[key] = JsonValue.Create(double.Parse(value, System.Globalization.CultureInfo.InvariantCulture));
                        break;
                    default:
                        options[key] = value;
                        break;
                }
            }
        }
        var result = Log.Obj("did", did, "options", options);
        if (hash >= 0) result["fragment"] = s[(hash + 1)..];
        return result;
    }

    // ---------------------------------------------------------- resolve

    private static bool PositiveInteger(J? v) => Log.Integer(v) && Num(v) >= 1;

    private static bool WatcherUrl(J? v) =>
        AsString(v) is { } s && s.StartsWith("https://", StringComparison.Ordinal) && Printable.IsMatch(s) && s.Length > 8 && "/?#".IndexOf(s[8]) < 0;

    /// <summary>did:vh resolution options validation (profile §5, step 2).</summary>
    private static JsonObject ValidateOptions(J? raw, bool remote)
    {
        if (raw is not JsonObject o) throw Options("resolution options must be an object");
        bool Has(string k) => o.ContainsKey(k);
        if (Has("didLog") == Has("srcLog")) throw Options("exactly one of didLog and srcLog must be given");
        if (Has("didWitness") && Has("srcWitness")) throw Options("at most one of didWitness and srcWitness may be given");
        if (Has("didLog") && !IsString(o["didLog"])) throw Options("didLog must be a string");
        if (Has("didWitness") && o["didWitness"] is not JsonArray) throw Options("didWitness must be an array");
        foreach (var key in new[] { "srcLog", "srcWitness" })
        {
            if (!Has(key)) continue;
            var kind = CheckRef(o[key]);
            if (remote && kind is "file" or "loopback") throw Options($"{key}: a resolver that serves other systems must not use file or loopback references");
        }
        if (new[] { "versionId", "versionTime", "versionNumber" }.Count(Has) > 1) throw Options("at most one of versionId, versionTime and versionNumber may be given");
        if (Has("versionId") && !IsString(o["versionId"])) throw Options("versionId must be a string");
        if (Has("versionTime") && Log.Time(o["versionTime"]) is null) throw Options("versionTime must be a whole-second UTC ISO 8601 time");
        if (Has("versionNumber") && !PositiveInteger(o["versionNumber"])) throw Options("versionNumber must be a positive integer");
        if (Has("checkWatchers") && AsString(o["checkWatchers"]) != "all" && !(Log.Integer(o["checkWatchers"]) && Num(o["checkWatchers"]) >= 0))
            throw Options("checkWatchers must be a non-negative integer or \"all\"");
        if (Has("extraWatchers") && !(o["extraWatchers"] is JsonArray w && w.All(WatcherUrl))) throw Options("extraWatchers must be an array of https URLs");
        if (Has("minCopies") && !PositiveInteger(o["minCopies"])) throw Options("minCopies must be a positive integer");
        if (Has("includeDidLog") && o["includeDidLog"]?.GetValueKind() is not (JsonValueKind.True or JsonValueKind.False)) throw Options("includeDidLog must be a boolean");
        return o;
    }

    private static readonly Dictionary<string, string> Errors = new()
    {
        ["not-found"] = "notFound",
        ["invalid-option"] = "invalidOptions",
        ["fork-detected"] = "logForked",
        ["min-copies-not-met"] = "insufficientCopies",
        ["unsupported-log-version"] = "featureNotSupported",
    };

    private static DidVhException FromVhLog(J? report)
    {
        var code = AsString(report!["code"])!;
        return new(Errors.GetValueOrDefault(code, "invalidDid"), AsString(report["message"]) ?? code, (JsonObject)report.DeepClone());
    }

    private static JsonObject Failure(DidVhException e)
    {
        var details = Log.Obj("title", e.Code, "detail", e.Message);
        if (e.VhLog is not null) details["vhLog"] = e.VhLog;
        return Log.Obj("didResolutionMetadata", Log.Obj("error", e.Code, "problemDetails", details), "didDocument", null, "didDocumentMetadata", new JsonObject());
    }

    /// <summary>
    /// did:vh resolve(did, resolutionOptions) (profile §5). This resolver is offline: it verifies
    /// a log passed in didLog (and didWitness), and gives featureNotSupported where it would
    /// have to retrieve anything. now is an ISO 8601 time (null for the current time); remote
    /// says whether the resolver serves other systems.
    /// </summary>
    public static JsonObject Resolve(J? did, J? resolutionOptions, string? now = null, bool remote = false)
    {
        try
        {
            var scid = ParseDid(did) ?? throw new DidVhException("invalidDid", "not a did:vh DID");
            var o = ValidateOptions(resolutionOptions, remote);
            if (o.ContainsKey("srcLog")) throw new DidVhException("featureNotSupported", "this resolver does not retrieve srcLog references");
            if (o.ContainsKey("checkWatchers") && !(IsNumber(o["checkWatchers"]) && Num(o["checkWatchers"]) == 0) || o["extraWatchers"] is JsonArray { Count: > 0 })
                throw new DidVhException("featureNotSupported", "this resolver does not retrieve copies from watchers");
            var spec = Specialisation(scid);
            now ??= DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
            var log = AsString(o["didLog"])!;
            // Whether the log needs witnessing does not depend on the witness file. Without
            // one, the first entry that needs it fails, which cuts it from the entries.
            var unwitnessed = Log.VerifyLog(log, null, false, Log.Time(JsonValue.Create(now)) ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 62135596800L, spec);
            bool witnessed = AsString(unwitnessed.Failure?["code"]) == "witness-threshold-not-met" || unwitnessed.Entries.Any(e => e.Rule is not null);
            if (witnessed && o.ContainsKey("srcWitness")) throw new DidVhException("featureNotSupported", "this resolver does not retrieve srcWitness references");
            var vhOptions = new JsonObject();
            foreach (var k in new[] { "versionId", "versionTime", "versionNumber", "minCopies" }) if (o.ContainsKey(k)) vhOptions[k] = Clone(o[k]);
            var input = Log.Obj("log", log, "now", now, "options", vhOptions);
            if (o.ContainsKey("didWitness")) input["witness"] = Clone(o["didWitness"]);
            var result = Log.Resolve(input, spec);
            if (result["valid"]?.GetValue<bool>() != true) throw FromVhLog(result["error"]);
            bool selected = new[] { "versionId", "versionTime", "versionNumber" }.Any(o.ContainsKey);
            if (!selected && AsString(result["error"]?["code"]) == "unsupported-log-version") throw FromVhLog(result["error"]);
            var m = (JsonObject)result["metadata"]!;
            var docMeta = Log.Obj("versionId", m["versionId"], "versionTime", m["versionTime"], "created", m["created"], "updated", m["updated"],
                "scid", m["scid"], "deactivated", m["deactivated"], "ttl", m["ttl"]);
            if (m["witness"] is not null) docMeta["witness"] = Clone(m["witness"]);
            docMeta["watchers"] = Clone(m["watchers"]);
            var meta = Log.Obj("contentType", "application/did+json");
            if (m["warnings"] is JsonArray { Count: > 0 } warnings) meta["warnings"] = Clone(warnings);
            if (o["includeDidLog"]?.GetValueKind() == JsonValueKind.True)
            {
                var lines = Log.Lines(log);
                int valid = result["firstInvalidVersion"] is null ? lines.Count : (int)Num(result["firstInvalidVersion"]) - 1;
                meta["didLog"] = string.Concat(lines.Take(valid).Select(l => l + "\n"));
                if (witnessed) meta["didWitness"] = o["didWitness"] is JsonArray w ? w.DeepClone() : new JsonArray();
            }
            bool deactivated = m["deactivated"]?.GetValue<bool>() == true;
            return Log.Obj("didResolutionMetadata", meta, "didDocument", deactivated && !selected ? null : result["state"], "didDocumentMetadata", docMeta);
        }
        catch (DidVhException e) { return Failure(e); }
    }

    // ---------------------------------------------------------- driver operations

    /// <summary>Runs fn, turning a did:vh error into {valid: false, error}.</summary>
    private static JsonObject Rejected(Func<JsonObject> fn)
    {
        try
        {
            var result = Log.Obj("valid", true);
            foreach (var (k, v) in fn()) result[k] = Clone(v);
            return result;
        }
        catch (DidVhException e) { return Log.Obj("valid", false, "error", e.Code); }
    }

    /// <summary>The did:vh driver operations (docs/interop-protocol.md, "did:vh operations").</summary>
    public static J Dispatch(string op, J input) => op switch
    {
        "didvh-create" => Create(input),
        "didvh-update" => Update(input),
        "didvh-resolve" => Resolve(input["did"], input.AsObject().ContainsKey("options") ? input["options"] : new JsonObject(), AsString(input["now"]), input["remote"]?.GetValueKind() == JsonValueKind.True),
        "didvh-ref" => Rejected(() => Log.Obj("kind", CheckRef(input["ref"]))),
        "didvh-src" => Rejected(() => SrcReferences(input["src"])),
        "didvh-did-url" => Rejected(() => ParseDidUrl(input["didUrl"])),
        _ => throw new ArgumentException("unknown operation " + op)
    };
}
