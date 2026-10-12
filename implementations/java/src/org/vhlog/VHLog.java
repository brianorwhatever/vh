package org.vhlog;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.time.*;
import java.util.*;
import java.util.regex.*;

/** VH-Log controller and resolver; JDK Ed25519, SHA-256 and no runtime dependencies. */
public final class VHLog {
    private static final String ALPHABET =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final Object ABSENT = new Object();
    public static final class ProtocolError extends RuntimeException {
        public final Map<String, Object> report;
        ProtocolError(String code, Integer version, Object fork) {
            super(code);
            report = obj("code", code, "version", version, "message", code);
            if (fork != null)
                report.put("fork", fork);
        }
    }
    private static void fail(String code, Integer version) {
        throw new ProtocolError(code, version, null);
    }
    public static Map<String, Object> obj(Object... pairs) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2)
            m.put((String)pairs[i], pairs[i + 1]);
        return m;
    }
    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object v) {
        return (Map<String, Object>)v;
    }
    @SuppressWarnings("unchecked")
    private static List<Object> list(Object v) {
        return (List<Object>)v;
    }
    private static Object get(Object v, String k) {
        return v instanceof Map < ?, ? > m ? m.get(k) : null;
    }
    private static boolean has(Object v, String k) {
        return v instanceof Map < ?, ? > m && m.containsKey(k);
    }
    private static String str(Object v) { return (String)v; }
    private static byte[] bytes(String s) { return s.getBytes(StandardCharsets.UTF_8); }
    public static byte[] sha(String s) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes(s));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }
    public static String encode(byte[] b) {
        BigInteger n = new BigInteger(1, b);
        StringBuilder out = new StringBuilder();
        while (n.signum() > 0) {
            BigInteger[] qr = n.divideAndRemainder(BigInteger.valueOf(58));
            out.append(ALPHABET.charAt(qr[1].intValue()));
            n = qr[0];
        }
        for (byte x : b) {
            if (x != 0)
                break;
            out.append('1');
        }
        return out.reverse().toString();
    }
    public static byte[] decode(Object value) {
        if (!(value instanceof String s))
            return null;
        BigInteger n = BigInteger.ZERO;
        for (int i = 0; i < s.length(); i++) {
            int d = ALPHABET.indexOf(s.charAt(i));
            if (d < 0)
                return null;
            n = n.multiply(BigInteger.valueOf(58)).add(BigInteger.valueOf(d));
        }
        byte[] b = n.signum() == 0 ? new byte[0] : n.toByteArray();
        if (b.length > 0 && b[0] == 0)
            b = Arrays.copyOfRange(b, 1, b.length);
        int z = 0;
        while (z < s.length() && s.charAt(z) == '1')
            z++;
        return concat(new byte[z], b);
    }
    public static String hash(String s) { return encode(concat(new byte[] {0x12, 0x20}, sha(s))); }
    private static String checkHash(Object s) {
        byte[] b = decode(s);
        return b == null                                 ? "not-base58"
        : b.length == 34 && b[0] == 0x12 && b[1] == 0x20 ? "ok"
                                                         : "unsupported-algorithm";
    }
    public static byte[] publicKey(Object value) {
        if (!(value instanceof String s) || !s.startsWith("z"))
            return null;
        byte[] b = decode(s.substring(1));
        return b != null && b.length == 34 && b[0] == (byte)0xed && b[1] == 1
            ? Arrays.copyOfRange(b, 2, 34)
            : null;
    }
    private static KeyPair signer(String hex) {
        if (!hex.matches("[0-9a-fA-F]{64}"))
            throw new IllegalArgumentException("seed must be 32-byte hex");
        byte[] seed = HexFormat.of().parseHex(hex);
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519");
            g.initialize(NamedParameterSpec.ED25519, new SecureRandom() {
                @Override
                public void nextBytes(byte[] b) {
                    if (b.length != 32)
                        throw new IllegalStateException("unexpected seed request");
                    System.arraycopy(seed, 0, b, 0, 32);
                }
            });
            return g.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
    public static String multikey(String seed) {
        byte[] der = signer(seed).getPublic().getEncoded();
        return "z" + encode(concat(new byte[] {(byte)0xed, 1},
                                   Arrays.copyOfRange(der, der.length - 32, der.length)));
    }
    private static String methodKey(Object value) {
        if (!(value instanceof String s))
            return null;
        Matcher m = Pattern.compile("^did:key:([^#]+)#(.+)$").matcher(s);
        return m.matches() && m.group(1).equals(m.group(2)) && publicKey(m.group(1)) != null
            ? m.group(1)
            : null;
    }
    private static byte[] signingInput(Object document, Map<String, Object> config) {
        return concat(sha(Json.stringify(config)), sha(Json.stringify(document)));
    }
    public static Map<String, Object> sign(Object document, String seed,
                                           Map<String, Object> options) {
        String mk = multikey(seed);
        Map<String, Object> c =
            obj("type", "DataIntegrityProof", "cryptosuite", "eddsa-jcs-2022", "verificationMethod",
                options.getOrDefault("verificationMethod", "did:key:" + mk + "#" + mk));
        if (options.containsKey("created"))
            c.put("created", options.get("created"));
        c.put("proofPurpose", "assertionMethod");
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(signer(seed).getPrivate());
            sig.update(signingInput(document, c));
            c.put("proofValue", "z" + encode(sig.sign()));
            return c;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
    // Profile §2; the signature provider checks curve membership and the equation.
    private static boolean admissiblePoint(byte[] encoded) {
        byte[] y = encoded.clone();
        y[31] &= 127;
        String h = HexFormat.of().formatHex(y);
        if (java.util.Set.of("0000000000000000000000000000000000000000000000000000000000000000", "0100000000000000000000000000000000000000000000000000000000000000", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f").contains(h)) return false;
        for (int i = 31; i >= 0; i--) {
            int limit = i == 31 ? 127 : i == 0 ? 237 : 255;
            if ((y[i] & 255) != limit) return (y[i] & 255) < limit;
        }
        return false;
    }
    public static boolean verify(Object document, Object proof) {
        if(!(proof instanceof Map<?,?>) || !"DataIntegrityProof".equals(get(proof,"type")) || !"eddsa-jcs-2022".equals(get(proof,"cryptosuite")) || !"assertionMethod".equals(get(proof,"proofPurpose")))
            return false;
        String mk = methodKey(get(proof, "verificationMethod"));
        Object value = get(proof, "proofValue");
        if (mk == null || !(value instanceof String s) || !s.startsWith("z"))
            return false;
        byte[] signature = decode(s.substring(1));
        if (signature == null || signature.length != 64)
            return false;
        if (!admissiblePoint(publicKey(mk)) || !admissiblePoint(Arrays.copyOf(signature, 32))) return false;
        Map<String, Object> config = new LinkedHashMap<>(map(proof));
        config.remove("proofValue");
        try {
            byte[] der = concat(HexFormat.of().parseHex("302a300506032b6570032100"), publicKey(mk));
            PublicKey key =
                KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(key);
            sig.update(signingInput(document, config));
            return sig.verify(signature);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }
    private static Map<String, Object> withoutProof(Map<String, Object> e) {
        Map<String, Object> d = new LinkedHashMap<>(e);
        d.remove("proof");
        return d;
    }
    public static String scid(Map<String, Object> e) {
        return hash(Json.stringify(withoutProof(e)));
    }
    public static String entryHash(Map<String, Object> e, String previous) {
        Map<String, Object> d = withoutProof(e);
        d.put("versionId", previous);
        return hash(Json.stringify(d));
    }
    private static List<String> lines(String log) {
        List<String> ls = new ArrayList<>(Arrays.asList(log.split("\n", -1)));
        if (!ls.isEmpty() && ls.getLast().isEmpty())
            ls.removeLast();
        return ls;
    }
    public static Map<String, Object> create(Map<String, Object> in) {
        Map<String, Object> p = obj("logVersion", "vh-log:1.0", "scid", "{SCID}");
        p.putAll(map(in.get("parameters")));
        Map<String, Object> e = obj("versionId", "{SCID}", "versionTime", in.get("versionTime"),
                                    "parameters", p, "state", in.get("state"));
        String id = scid(e);
        e = map(Json.parse(Json.stringify(e).replace("{SCID}", id)));
        e.put("versionId", "1-" + entryHash(e, id));
        List<Object> proofs = new ArrayList<>();
        for (Object seed : list(in.get("signers")))
            proofs.add(sign(e, str(seed), obj("created", in.get("versionTime"))));
        e.put("proof", proofs);
        return obj("log", Json.stringify(e) + "\n", "scid", id, "versionId", e.get("versionId"));
    }
    public static Map<String, Object> update(Map<String, Object> in) {
        String log = str(in.get("log")),
               previous = str(get(Json.parse(lines(log).getLast()), "versionId"));
        Map<String, Object> e =
            obj("versionId", previous, "versionTime", in.get("versionTime"), "parameters",
                in.getOrDefault("parameters", obj()), "state", in.get("state"));
        e.put("versionId",
              (Long.parseLong(previous.split("-")[0]) + 1) + "-" + entryHash(e, previous));
        List<Object> proofs = new ArrayList<>();
        for (Object seed : list(in.get("signers")))
            proofs.add(sign(e, str(seed), obj("created", in.get("versionTime"))));
        e.put("proof", proofs);
        return obj("log", log + (log.endsWith("\n") ? "" : "\n") + Json.stringify(e) + "\n",
                   "versionId", e.get("versionId"));
    }
    public static Long time(Object value) {
        if (!(value instanceof String s) ||
            !s.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(Z|\\+00:00)"))
            return null;
        try {
            return LocalDateTime.parse(s.substring(0, 19)).toEpochSecond(ZoneOffset.UTC);
        } catch (DateTimeException e) {
            return null;
        }
    }
    private static boolean integer(Object v) {
        return v instanceof Number n && Double.isFinite(n.doubleValue()) &&
            n.doubleValue() == Math.rint(n.doubleValue());
    }
    private static boolean strings(Object v) {
        return v instanceof List<?> a && a.stream().allMatch(x -> x instanceof String);
    }
    private static Map<String, Object> parameters(Map<String, Object> raw,
                                                  Map<String, Object> previous, int n) {
        if (raw.values().stream().anyMatch(Objects::isNull))
            fail("invalid-parameter", n);
        if (previous == null && !raw.containsKey("logVersion") ||
            raw.containsKey("logVersion") && !"vh-log:1.0".equals(raw.get("logVersion")))
            fail("unsupported-log-version", n);
        if (previous != null
                ? raw.containsKey("scid")
                : !(raw.get("scid") instanceof String) || !raw.containsKey("updateKeys"))
            fail("invalid-parameter", n);
        if (raw.containsKey("updateKeys")) {
            if (!strings(raw.get("updateKeys")))
                fail("invalid-parameter", n);
            for (Object k : list(raw.get("updateKeys")))
                if (publicKey(k) == null)
                    fail("invalid-parameter", n);
        }
        if (raw.containsKey("nextKeyHashes")) {
            if (!strings(raw.get("nextKeyHashes")))
                fail("invalid-parameter", n);
            for (Object h : list(raw.get("nextKeyHashes")))
                if (!checkHash(h).equals("ok"))
                    fail("invalid-parameter", n);
        }
        Map<String, Object> p = previous == null
                                    ? obj("nextKeyHashes", new ArrayList<>(), "witness", null,
                                          "watchers", new ArrayList<>(), "ttl", 3600)
                                    : new LinkedHashMap<>(previous);
        for (String k : List.of("logVersion", "scid", "updateKeys", "nextKeyHashes", "witness",
                                "watchers", "ttl"))
            if (raw.containsKey(k))
                p.put(k, raw.get(k));
        p.put("deactivated", raw.getOrDefault("deactivated", false));
        if (raw.containsKey("witness")) {
            Object w = raw.get("witness"); if(!(w instanceof Map<?,?>))
                fail("invalid-parameter", n);
            if (map(w).isEmpty())
                p.put("witness", null);
            else {
                Object ws = get(w, "witnesses");
                if (!(ws instanceof List<?>) || list(ws).isEmpty())
                    fail("invalid-parameter", n);
                Set<String> ids = new HashSet<>();
                for (Object x : list(ws)) {
                    Object id = get(x, "id");
                    if (!(id instanceof String) || !str(id).startsWith("did:key:") ||
                        publicKey(str(id).substring(8)) == null || !ids.add(str(id)))
                        fail("invalid-parameter", n);
                }
                Object t = get(w, "threshold");
                if (!integer(t) || ((Number)t).doubleValue() < 1 ||
                    ((Number)t).doubleValue() > ids.size())
                    fail("invalid-parameter", n);
                p.put("witness", obj("threshold", t, "witnesses", ws));
            }
        }
        if (raw.containsKey("watchers")) {
            Object ws = raw.get("watchers");
            if (!strings(ws))
                fail("invalid-parameter", n);
            for (Object u : list(ws))
                if (!str(u).matches("[\\x21-\\x7e]+") ||
                    !Pattern.compile("^https?://[^/?#]").matcher(str(u)).find())
                    fail("invalid-parameter", n);
        }
        if (!(p.get("deactivated") instanceof Boolean) || !integer(p.get("ttl")) ||
            ((Number)p.get("ttl")).doubleValue() < 0 ||
            ((Number)p.get("ttl")).doubleValue() > 2147483648.0)
            fail("invalid-parameter", n);
        if (previous != null && !list(previous.get("nextKeyHashes")).isEmpty()) {
            if (!raw.containsKey("updateKeys") || !raw.containsKey("nextKeyHashes"))
                fail("prerotation-violation", n);
            for (Object key : list(raw.get("updateKeys")))
                if (!list(previous.get("nextKeyHashes")).contains(hash(str(key))))
                    fail("prerotation-violation", n);
        }
        return p;
    }
    private record
        Entry(Map<String, Object> e, Map<String, Object> p, int n, long time, Object rule) {}
    private record Verified(List<Entry> entries, List<String> lines, Map<String, Object> failure) {}
    private static Entry verifyEntry(Map<String, Object> e, Entry previous, long now) {
        int n = previous == null ? 1 : previous.n + 1;
        if (previous != null && Boolean.TRUE.equals(previous.p.get("deactivated")))
            fail("entry-after-deactivation", n);
        if(!e.keySet().equals(Set.of("versionId","versionTime","parameters","state","proof")) || !(e.get("versionId") instanceof String) || !(e.get("versionTime") instanceof String) || !(e.get("parameters") instanceof Map<?,?>) || !(e.get("state") instanceof Map<?,?>) || !(e.get("proof") instanceof List<?>))
            fail("invalid-entry", n);
        Map<String, Object> p =
            parameters(map(e.get("parameters")), previous == null ? null : previous.p, n);
        List<Object> active =
            list(previous == null || !list(previous.p.get("nextKeyHashes")).isEmpty()
                     ? p.get("updateKeys")
                     : previous.p.get("updateKeys"));
        Object rule = previous == null || has(e.get("parameters"), "witness") &&
                                              previous.p.get("witness") == null
                          ? p.get("witness")
                          : previous.p.get("witness");
        if (list(e.get("proof")).isEmpty())
            fail("invalid-proof", n);
        for (Object proof : list(e.get("proof"))) {
            String mk = methodKey(get(proof, "verificationMethod"));
            if (mk == null)
                fail("invalid-proof", n);
            if (!active.contains(mk))
                fail("unauthorized-key", n);
            if (!verify(withoutProof(e), proof))
                fail("invalid-proof", n);
        }
        Matcher m = Pattern.compile("([1-9][0-9]*)-([^-]+)").matcher(str(e.get("versionId")));
        if (!m.matches() || !m.group(1).equals(Integer.toString(n)))
            fail("invalid-version-id", n);
        String check = checkHash(m.group(2));
        if (check.equals("not-base58"))
            fail("invalid-version-id", n);
        if (!check.equals("ok"))
            fail("invalid-hash-algorithm", n);
        if (!entryHash(e, str(previous == null ? p.get("scid") : previous.e.get("versionId")))
                 .equals(m.group(2)))
            fail("entry-hash-mismatch", n);
        Long t = time(e.get("versionTime"));
        if (t == null || previous != null && t <= previous.time)
            fail("invalid-version-time", n);
        if (t > now + 300)
            fail("future-version-time", n);
        if (previous == null) {
            String id = str(p.get("scid"));
            check = checkHash(id);
            if (check.equals("unsupported-algorithm"))
                fail("invalid-hash-algorithm", n);
            if (!check.equals("ok"))
                fail("scid-mismatch", n);
            Map<String, Object> rest = withoutProof(e);
            rest.put("versionId", "{SCID}");
            rest = map(Json.parse(Json.stringify(rest).replace(id, "{SCID}")));
            if (!scid(rest).equals(id))
                fail("scid-mismatch", n);
        }
        return new Entry(e, p, n, t, rule);
    }
    private static Verified verifyLog(String log, Object witness, long now) {
        List<String> ls = lines(log);
        List<Entry> entries = new ArrayList<>();
        Map<String, Object> failure = null;
        if (ls.isEmpty())
            return new Verified(entries, ls, new ProtocolError("invalid-log", null, null).report);
        for (int i = 0; i < ls.size(); i++) {
            try {
                Object raw = null;
                try {
                    raw = Json.parse(ls.get(i));
                } catch (IllegalArgumentException e) {
                    fail("invalid-log", i + 1);
                }
                if(!(raw instanceof Map<?,?>))
                    fail("invalid-log", i + 1);
                entries.add(
                    verifyEntry(map(raw), entries.isEmpty() ? null : entries.getLast(), now));
            } catch (ProtocolError e) {
                failure = e.report;
                break;
            }
        }
        for (int i = 0; i < entries.size(); i++) {
            Object rule = entries.get(i).rule;
            if (rule == null)
                continue;
            Object file = witness == ABSENT ? new ArrayList<>() : witness;
            String code = null;
            boolean valid = file instanceof List<?>;
            if (valid)
                for (Object r : list(file))
                    if (!(get(r, "versionId") instanceof String) ||
                        !(get(r, "proof") instanceof List<?>)) {
                        valid = false;
                        break;
                    }
            if (!valid)
                code = "invalid-witness-file";
            else {
                Set<String> allowed = new HashSet<>(), approved = new HashSet<>();
                for (Object w : list(get(rule, "witnesses")))
                    allowed.add(str(get(w, "id")));
                for (Object r : list(file)) {
                    int index = -1;
                    for (int j = 0; j < entries.size(); j++)
                        if (entries.get(j).e.get("versionId").equals(get(r, "versionId"))) {
                            index = j;
                            break;
                        }
                    if (index < i)
                        continue;
                    for (Object proof : list(get(r, "proof"))) {
                        String mk = methodKey(get(proof, "verificationMethod")),
                               id = "did:key:" + mk;
                        if (mk != null && allowed.contains(id) &&
                            verify(obj("versionId", get(r, "versionId")), proof))
                            approved.add(id);
                    }
                }
                if (approved.size() < ((Number)get(rule, "threshold")).doubleValue())
                    code = "witness-threshold-not-met";
            }
            if (code != null) {
                failure = new ProtocolError(code, i + 1, null).report;
                entries = new ArrayList<>(entries.subList(0, i));
                break;
            }
        }
        return new Verified(entries, ls, failure);
    }
    private static Object lineValue(String line) {
        try {
            return line == null ? null : Json.parse(line);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
    private static String lineId(List<String> ls, int i) {
        Object id = get(lineValue(i >= 0 && i < ls.size() ? ls.get(i) : null), "versionId");
        return id instanceof String s ? s : null;
    }
    private static void retained(Verified v, String source, Object id, List<Object> warnings) {
        Matcher m = Pattern.compile("^([1-9][0-9]*)-").matcher(id instanceof String s ? s : "");
        if (!m.find())
            fail("invalid-option", null);
        BigInteger big = new BigInteger(m.group(1));
        if (big.compareTo(BigInteger.valueOf(v.entries.size())) > 0) {
            warnings.add(
                obj("code", "retained-version-not-found", "message", "retained version not found"));
            return;
        }
        int n = big.intValue();
        Object actual = v.entries.get(n - 1).e.get("versionId");
        if (!actual.equals(id))
            throw new ProtocolError("fork-detected", n,
                                    obj("version", n, "copies",
                                        List.of(obj("source", "retained", "versionId", id),
                                                obj("source", source, "versionId", actual))));
    }
    private static Map<String, Object> result(Verified v, Map<String, Object> options,
                                              List<Object> warnings, List<Object> copies) {
        Entry target = null;
        Map<String, Object> failure = v.failure;
        if (options.containsKey("versionId")) {
            for (Entry e : v.entries)
                if (e.e.get("versionId").equals(options.get("versionId"))) {
                    target = e;
                    break;
                }
            if (target == null)
                for (int i = v.entries.size(); i < v.lines.size(); i++)
                    if (Objects.equals(lineId(v.lines, i), options.get("versionId")))
                        fail(str(failure.get("code")), ((Number)failure.get("version")).intValue());
        } else if (options.containsKey("versionNumber")) {
            double n = ((Number)options.get("versionNumber")).doubleValue();
            if (n <= v.entries.size())
                target = v.entries.get((int)n - 1);
            else if (n <= v.lines.size())
                fail(str(failure.get("code")), ((Number)failure.get("version")).intValue());
        } else if (options.containsKey("versionTime")) {
            long t = time(options.get("versionTime"));
            if (failure != null) {
                Long it = time(get(lineValue(v.lines.get(v.entries.size())), "versionTime"));
                if (it != null && it <= t)
                    fail(str(failure.get("code")), ((Number)failure.get("version")).intValue());
            }
            for (int i = v.entries.size() - 1; i >= 0; i--)
                if (v.entries.get(i).time <= t) {
                    target = v.entries.get(i);
                    break;
                }
        } else
            target = v.entries.getLast();
        if (target == null)
            fail("not-found", null);
        Entry first = v.entries.getFirst(), last = v.entries.getLast();
        if (failure != null)
            warnings.add(obj("code", "invalid-entries", "message", failure.get("message")));
        Map<String, Object> meta = obj(
            "versionId", target.e.get("versionId"), "versionTime", target.e.get("versionTime"),
            "versionNumber", target.n, "created", first.e.get("versionTime"), "updated",
            last.e.get("versionTime"), "scid", first.p.get("scid"), "deactivated",
            last.p.get("deactivated"), "ttl", last.p.get("ttl"), "witness", last.p.get("witness"),
            "watchers", last.p.get("watchers"), "updateKeys", target.p.get("updateKeys"),
            "nextKeyHashes", target.p.get("nextKeyHashes"), "warnings", warnings);
        if (copies != null)
            meta.put("copies", copies);
        return obj("valid", true, "state", target.e.get("state"), "metadata", meta,
                   "firstInvalidVersion", failure == null ? null : v.entries.size() + 1, "error",
                   failure);
    }
    private static Map<String, Object> resolveCopies(Map<String, Object> in, long now,
                                                     Map<String, Object> options) {
        Map<String, Object> primary = obj("source", "primary", "log", in.get("log"), "witness",
                                          in.getOrDefault("witness", ABSENT));
        List<Object> all = new ArrayList<>(List.of(primary));
        all.addAll(list(in.getOrDefault("copies", new ArrayList<>())));
        List<Object> warnings = new ArrayList<>();
        Map<Integer, String> status = new HashMap<>();
        Map<Integer, Verified> cache = new HashMap<>();
        java.util.function.IntFunction<Verified> get = i -> cache.computeIfAbsent(i, k -> {
            Map<String, Object> c = map(all.get(k));
            return verifyLog(str(c.get("log")), c.getOrDefault("witness", ABSENT), now);
        });
        java.util.function.IntConsumer invalid = i -> {
            status.put(i, "invalid");
            warnings.add(obj("code", "copy-invalid", "source", get(all.get(i), "source"), "message",
                             "copy fails verification"));
        };
        for (int i = 0; i < all.size(); i++)
            if (has(all.get(i), "unavailable")) {
                status.put(i, "unavailable");
                warnings.add(obj("code", "copy-unavailable", "source", get(all.get(i), "source"),
                                 "message", get(all.get(i), "unavailable")));
            }
        int ref = -1;
        for (int i = 0; i < all.size(); i++) {
            if (status.containsKey(i))
                continue;
            if (get.apply(i).failure == null) {
                ref = i;
                break;
            }
            invalid.accept(i);
        }
        if (ref < 0)
            return obj("valid", false, "error", get.apply(0).failure);
        Set<Integer> matched = new HashSet<>(List.of(ref));
        for (int i = 0; i < all.size(); i++) {
            if (status.containsKey(i) || matched.contains(i))
                continue;
            Verified r = get.apply(ref), c = get.apply(i);
            List<String> rl = r.lines, cl = c.lines;
            if (cl.isEmpty()) {
                invalid.accept(i);
                continue;
            }
            boolean same = cl.size() <= rl.size() &&
                           Objects.equals(lineId(cl, cl.size() - 1),
                                          r.entries.get(cl.size() - 1).e.get("versionId"));
            boolean extendsLog =
                cl.size() > rl.size() &&
                Objects.equals(lineId(cl, rl.size() - 1), r.entries.getLast().e.get("versionId"));
            if (same)
                matched.add(i);
            else if (extendsLog && c.failure == null) {
                matched.add(i);
                ref = i;
            } else if (c.failure != null)
                invalid.accept(i);
            else {
                int k = 0;
                while (k < Math.min(rl.size(), cl.size()) &&
                       Objects.equals(lineId(rl, k), lineId(cl, k)))
                    k++;
                throw new ProtocolError(
                    "fork-detected", k + 1,
                    obj("version", k + 1, "copies",
                        List.of(obj("source", get(all.get(ref), "source"), "versionId",
                                    Objects.requireNonNullElse(lineId(rl, k), "")),
                                obj("source", get(all.get(i), "source"), "versionId",
                                    Objects.requireNonNullElse(lineId(cl, k), "")))));
            }
        }
        Verified r = get.apply(ref);
        if (in.containsKey("retainedVersionId"))
            retained(r, str(get(all.get(ref), "source")), in.get("retainedVersionId"), warnings);
        List<Object> copies = new ArrayList<>();
        int usable = 0;
        for (int i = 0; i < all.size(); i++) {
            Object source = get(all.get(i), "source");
            Map<String, Object> report = obj("source", source);
            if (status.containsKey(i)) {
                String s = status.get(i);
                report.put("status", s);
                if (!s.equals("unavailable")) {
                    List<String> ls = get.apply(i).lines;
                    String id = lineId(ls, ls.size() - 1);
                    if (id != null)
                        report.put("versionId", id);
                }
            } else {
                List<String> ls = get.apply(i).lines;
                boolean behind = ls.size() < r.lines.size();
                report.put("status", behind ? "behind" : "current");
                report.put("versionId", lineId(ls, ls.size() - 1));
                usable++;
                if (behind)
                    warnings.add(
                        obj("code", "copy-behind", "source", source, "message", "copy is behind"));
            }
            copies.add(report);
        }
        if (usable < ((Number)options.getOrDefault("minCopies", 1)).doubleValue())
            fail("min-copies-not-met", null);
        return result(r, options, warnings, copies);
    }
    public static Map<String, Object> resolve(Map<String, Object> in) {
        try {
            Long now = time(in.get("now"));
            if (now == null)
                fail("invalid-option", null);
            Object raw = in.get("options");
            if (raw == null)
                raw = obj(); if(!(raw instanceof Map<?,?>))
                fail("invalid-option", null);
            Map<String, Object> options = map(raw);
            if (!Set.of("versionId", "versionTime", "versionNumber", "minCopies")
                     .containsAll(options.keySet()) ||
                options.keySet()
                        .stream()
                        .filter(Set.of("versionId", "versionTime", "versionNumber")::contains)
                        .count() > 1)
                fail("invalid-option", null);
            if (options.containsKey("versionId") && !(options.get("versionId") instanceof String))
                fail("invalid-option", null);
            if (options.containsKey("versionTime") && time(options.get("versionTime")) == null)
                fail("invalid-option", null);
            for (String k : List.of("versionNumber", "minCopies"))
                if (options.containsKey(k) &&
                    (!integer(options.get(k)) || ((Number)options.get(k)).doubleValue() < 1))
                    fail("invalid-option", null);
            if (in.containsKey("copies") ||
                ((Number)options.getOrDefault("minCopies", 1)).doubleValue() > 1)
                return resolveCopies(in, now, options);
            Verified v = verifyLog(str(in.get("log")), in.getOrDefault("witness", ABSENT), now);
            if (v.entries.isEmpty())
                return obj("valid", false, "error", v.failure);
            List<Object> warnings = new ArrayList<>();
            if (in.containsKey("retainedVersionId"))
                retained(v, "primary", in.get("retainedVersionId"), warnings);
            return result(v, options, warnings, null);
        } catch (ProtocolError e) {
            return obj("valid", false, "error", e.report);
        }
    }
    public static Object dispatch(String op, Map<String, Object> in) {
        return switch (op) {
            case "jcs" -> obj("output", Json.stringify(Json.parse(str(in.get("text")))));
            case "hash" -> obj("output", hash(str(in.get("data"))));
            case "key-hash" -> obj("output", hash(str(in.get("multikey"))));
            case "multikey" -> obj("multikey", multikey(str(in.get("seed"))));
            case "scid" -> obj("scid", scid(map(in.get("entry"))));
            case "entry-hash" ->
                obj("hash", entryHash(map(in.get("entry")), str(in.get("previousVersionId"))));
            case "sign" -> obj("proof", sign(in.get("document"), str(in.get("seed")), in));
            case "verify" -> obj("valid", verify(in.get("document"), in.get("proof")));
            case "witness" ->
                obj("proof", sign(obj("versionId", in.get("versionId")), str(in.get("seed")), in));
            case "create" -> create(in);
            case "update" -> update(in);
            case "resolve" -> resolve(in);
            default -> throw new IllegalArgumentException("unknown operation " + op);
        };
    }
}
