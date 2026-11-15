package org.vhlog;

import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.time.Instant;
import java.util.*;
import java.util.regex.*;

import static org.vhlog.VHLog.obj;

/**
 * did:vh (docs/didvh-profile.md). A did:vh DID log is verified by the VH-Log code with the
 * did:vh specialisation; this class adds the DID syntax, the srcLog/srcWitness and DID URL
 * rules, the resolution options, and DID Resolution metadata and errors.
 */
public final class DidVh {
    private DidVh() {}

    public static final String METHOD = "did:vh:1.0";
    public static final String PREFIX = "did:vh:";
    private static final Pattern METHOD_SYNTAX =
        Pattern.compile("did:vh:(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)");
    private static final Pattern SCID = Pattern.compile("[1-9A-HJ-NP-Za-km-z]{46}");

    /** A did:vh error: invalidDid, invalidDidUrl, invalidOptions, notFound, ... */
    public static final class DidVhError extends RuntimeException {
        public final String code;
        public final Map<String, Object> vhLog;
        DidVhError(String code, String message, Map<String, Object> vhLog) {
            super(message);
            this.code = code;
            this.vhLog = vhLog;
        }
        DidVhError(String code, String message) { this(code, message, null); }
    }

    // ------------------------------------------------------------ the DID

    /** The SCID of a did:vh DID, or null if it does not match the ABNF. */
    public static String parseDid(Object did) {
        if (!(did instanceof String s) || !s.startsWith(PREFIX))
            return null;
        String scid = s.substring(PREFIX.length());
        return SCID.matcher(scid).matches() ? scid : null;
    }

    /**
     * The did:vh specialisation: method instead of logVersion, a closed parameter set, and
     * state.id = did:vh:SCID in every entry. With expectedScid, the log must be for that DID.
     */
    public static VHLog.Spec specialisation(String expectedScid) {
        return new VHLog.Spec("method", List.of(METHOD), METHOD_SYNTAX, List.of(), (state, scid, n) -> {
            if (expectedScid != null && !scid.equals(expectedScid) ||
                !(PREFIX + scid).equals(state.get("id")))
                throw new VHLog.ProtocolError("invalid-state", n, null);
        });
    }

    // ------------------------------------------------------------ create / update

    /** Creates a did:vh DID log; like VH-Log generation it does not validate its input. */
    public static Map<String, Object> create(Map<String, Object> in) {
        Map<String, Object> r = VHLog.create(
            obj("state", in.get("document"), "parameters", in.get("parameters"), "versionTime",
                in.get("versionTime"), "signers", in.get("signers")),
            "method", METHOD);
        return obj("log", r.get("log"), "did", PREFIX + r.get("scid"), "scid", r.get("scid"),
                   "versionId", r.get("versionId"));
    }

    /** Appends an entry; deactivate with parameters {deactivated: true}. */
    public static Map<String, Object> update(Map<String, Object> in) {
        Map<String, Object> u = obj("log", in.get("log"), "state", in.get("document"), "versionTime",
                                    in.get("versionTime"), "signers", in.get("signers"));
        if (in.get("parameters") != null)
            u.put("parameters", in.get("parameters"));
        return VHLog.update(u);
    }

    // ------------------------------------------------------------ shared URL checks

    /** Percent-decodes s as UTF-8, or null if an escape or the UTF-8 is malformed. */
    public static String percentDecode(String s) {
        ByteBuffer out = ByteBuffer.allocate(s.length() * 4);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%') {
                if (i + 3 > s.length())
                    return null;
                String hex = s.substring(i + 1, i + 3);
                if (!hex.matches("[0-9A-Fa-f]{2}"))
                    return null;
                out.put((byte)Integer.parseInt(hex, 16));
                i += 2;
            } else {
                int cp = s.codePointAt(i);
                if (Character.isSupplementaryCodePoint(cp))
                    i++;
                out.put(new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8));
            }
        }
        out.flip();
        try {
            return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(out)
                .toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }

    /** Unicode White_Space (profile §3.2). */
    private static boolean whitespace(int c) {
        return c >= 0x09 && c <= 0x0d || c == 0x20 || c == 0x85 || c == 0xa0 || c == 0x1680 ||
            c >= 0x2000 && c <= 0x200a || c == 0x2028 || c == 0x2029 || c == 0x202f ||
            c == 0x205f || c == 0x3000;
    }

    private static boolean octet(String s) {
        return s.matches("0|[1-9][0-9]{0,2}") && Integer.parseInt(s) <= 255;
    }

    private static boolean loopbackHost(String host) {
        if (host.equals("localhost") || host.equals("[::1]"))
            return true;
        String[] parts = host.split("\\.", -1);
        return parts.length == 4 && Arrays.stream(parts).allMatch(DidVh::octet) &&
            parts[0].equals("127");
    }

    private static boolean domainName(String host) {
        String name = host.endsWith(".") ? host.substring(0, host.length() - 1) : host;
        if (name.isEmpty() || name.length() > 253)
            return false;
        String[] labels = name.split("\\.", -1);
        if (labels[labels.length - 1].matches("[0-9]+"))
            return false;
        return Arrays.stream(labels).allMatch(l -> l.matches("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"));
    }

    private static final Pattern PRINTABLE = Pattern.compile("[\\x21-\\x7e]+");
    private static final Pattern SCHEME = Pattern.compile("([A-Za-z][A-Za-z0-9+.-]*):(.*)", Pattern.DOTALL);

    /** Splits scheme:rest (profile §3.1 steps 1–2), the scheme lowercased; null if invalid. */
    private static String[] splitScheme(Object value) {
        if (!(value instanceof String s) || !PRINTABLE.matcher(s).matches())
            return null;
        Matcher m = SCHEME.matcher(s);
        return m.matches() ? new String[] {m.group(1).toLowerCase(Locale.ROOT), m.group(2)} : null;
    }

    /** Checks an http(s) authority (profile §3.1 step 4). */
    private static boolean authority(String authority, String scheme) {
        if (authority.contains("@"))
            return false;
        String host, port = null;
        if (authority.startsWith("[")) {
            int close = authority.indexOf(']');
            if (close < 0)
                return false;
            host = authority.substring(0, close + 1);
            String after = authority.substring(close + 1);
            if (!after.isEmpty()) {
                if (!after.startsWith(":"))
                    return false;
                port = after.substring(1);
            }
        } else {
            int colon = authority.indexOf(':');
            host = colon < 0 ? authority : authority.substring(0, colon);
            if (colon >= 0)
                port = authority.substring(colon + 1);
        }
        host = host.toLowerCase(Locale.ROOT);
        if (port != null && !(port.matches("[0-9]{1,5}") && Integer.parseInt(port) <= 65535))
            return false;
        if (scheme.equals("http"))
            return loopbackHost(host);
        return !host.startsWith("[") && domainName(host);
    }

    /**
     * Checks the segments of a path starting with "/": each is percent-decoded and must not be
     * "." or ".." or contain "/", "\" or NUL. With strict (src), also non-empty and not starting
     * or ending with White_Space.
     */
    private static boolean segments(String path, boolean strict) {
        for (String raw : path.substring(1).split("/", -1)) {
            String s = percentDecode(raw);
            if (s == null || s.equals(".") || s.equals("..") || s.indexOf('/') >= 0 ||
                s.indexOf('\\') >= 0 || s.indexOf('\0') >= 0)
                return false;
            if (strict && (s.isEmpty() || whitespace(s.codePointAt(0)) ||
                           whitespace(s.codePointBefore(s.length()))))
                return false;
        }
        return true;
    }

    // ------------------------------------------------------------ srcLog / srcWitness

    /** Validates a srcLog or srcWitness reference (profile §3.1); returns its kind. */
    public static String checkRef(Object ref) {
        String[] parts = splitScheme(ref);
        if (parts == null)
            throw new DidVhError("invalidOptions", "reference is not a printable-ASCII absolute URL");
        String scheme = parts[0], rest = parts[1];
        if (rest.contains("#"))
            throw new DidVhError("invalidOptions", "reference must not have a fragment");
        if (scheme.equals("https") || scheme.equals("http")) {
            if (!rest.startsWith("//"))
                throw new DidVhError("invalidOptions", "reference is missing an authority");
            String tail = rest.substring(2);
            int end = -1;
            for (int i = 0; i < tail.length() && end < 0; i++)
                if (tail.charAt(i) == '/' || tail.charAt(i) == '?')
                    end = i;
            String auth = end < 0 ? tail : tail.substring(0, end);
            String after = end < 0 ? "" : tail.substring(end);
            int q = after.indexOf('?');
            String path = q < 0 ? after : after.substring(0, q);
            if (!authority(auth, scheme))
                throw new DidVhError("invalidOptions", scheme.equals("http")
                    ? "http is only allowed with a loopback host" : "invalid https host");
            if (path.isEmpty())
                throw new DidVhError("invalidOptions", "reference must have a path");
            if (!segments(path, false))
                throw new DidVhError("invalidOptions", "invalid path segment");
            return scheme.equals("http") ? "loopback" : "web";
        }
        if (scheme.equals("file")) {
            if (rest.contains("?"))
                throw new DidVhError("invalidOptions", "file URL must not have a query");
            String path;
            if (rest.startsWith("//")) {
                int slash = rest.indexOf('/', 2);
                if (slash < 0)
                    throw new DidVhError("invalidOptions", "file URL needs an absolute path");
                String host = rest.substring(2, slash).toLowerCase(Locale.ROOT);
                if (!host.isEmpty() && !host.equals("localhost"))
                    throw new DidVhError("invalidOptions", "file URL host must be empty or localhost");
                path = rest.substring(slash);
            } else {
                if (!rest.startsWith("/"))
                    throw new DidVhError("invalidOptions", "file URL needs an absolute path");
                path = rest;
            }
            if (!segments(path, false))
                throw new DidVhError("invalidOptions", "invalid path segment");
            return "file";
        }
        if (rest.isEmpty())
            throw new DidVhError("invalidOptions", "empty URL");
        return "other";
    }

    // ------------------------------------------------------------ the src DID URL parameter

    /** Validates a decoded src value and derives srcLog and srcWitness (profile §3.2). */
    public static Map<String, Object> srcReferences(Object src) {
        String[] parts = splitScheme(src);
        if (parts == null)
            throw new DidVhError("invalidDidUrl", "src is not a printable-ASCII absolute URL");
        String scheme = parts[0], rest = parts[1];
        if (rest.contains("?") || rest.contains("#"))
            throw new DidVhError("invalidDidUrl", "src must not have a query or fragment");
        if (scheme.equals("http") || scheme.equals("file"))
            throw new DidVhError("invalidDidUrl", scheme + " is not allowed in a DID URL");
        if (!rest.startsWith("//") || rest.length() == 2 || rest.charAt(2) == '/')
            throw new DidVhError("invalidDidUrl", "src is not a hierarchical URL with an authority");
        String base = rest.endsWith("/") ? rest.substring(0, rest.length() - 1) : rest;
        if (scheme.equals("https")) {
            int slash = base.indexOf('/', 2);
            String auth = slash < 0 ? base.substring(2) : base.substring(2, slash);
            String path = slash < 0 ? "" : base.substring(slash);
            if (!authority(auth, "https"))
                throw new DidVhError("invalidDidUrl", "invalid https host");
            if (!path.isEmpty() && !segments(path, true))
                throw new DidVhError("invalidDidUrl", "invalid path segment");
        }
        String location = scheme + ":" + base;
        return obj("srcLog", location + "/did.jsonl", "srcWitness", location + "/did-witness.json");
    }

    // ------------------------------------------------------------ DID URLs

    private static final List<String> URL_PARAMETERS =
        List.of("src", "versionId", "versionTime", "versionNumber");
    private static final List<String> OPTION_ONLY =
        List.of("didLog", "didWitness", "srcLog", "srcWitness", "checkWatchers", "extraWatchers",
                "minCopies", "includeDidLog");

    /** Parses a did:vh DID URL as a dereferencer does (profile §4): {did, options, fragment?}. */
    public static Map<String, Object> parseDidUrl(Object didUrl) {
        if (!(didUrl instanceof String url))
            throw new DidVhError("invalidDidUrl", "DID URL is not a string");
        int hash = url.indexOf('#');
        String beforeFragment = hash < 0 ? url : url.substring(0, hash);
        String fragment = hash < 0 ? null : url.substring(hash + 1);
        int q = beforeFragment.indexOf('?');
        String did = q < 0 ? beforeFragment : beforeFragment.substring(0, q);
        if (parseDid(did) == null)
            throw new DidVhError("invalidDidUrl", "not a did:vh DID");
        Set<String> seen = new HashSet<>();
        Map<String, Object> options = new LinkedHashMap<>();
        if (q >= 0) {
            for (String pair : beforeFragment.substring(q + 1).split("&", -1)) {
                int eq = pair.indexOf('=');
                if (eq < 0)
                    throw new DidVhError("invalidDidUrl", "query parameter has no value");
                String key = percentDecode(pair.substring(0, eq));
                String value = percentDecode(pair.substring(eq + 1));
                if (key == null || value == null)
                    throw new DidVhError("invalidDidUrl", "malformed percent-encoding");
                if (OPTION_ONLY.contains(key))
                    throw new DidVhError("invalidDidUrl", key + " is a resolution option");
                if (!URL_PARAMETERS.contains(key))
                    continue;
                if (!seen.add(key))
                    throw new DidVhError("invalidDidUrl", key + " given more than once");
                switch (key) {
                case "src" -> options.putAll(srcReferences(value));
                case "versionNumber" -> {
                    if (!value.matches("[1-9][0-9]{0,15}"))
                        throw new DidVhError("invalidDidUrl", "versionNumber must be a positive integer");
                    options.put(key, Double.parseDouble(value));
                }
                default -> options.put(key, value);
                }
            }
        }
        Map<String, Object> out = obj("did", did, "options", options);
        if (fragment != null)
            out.put("fragment", fragment);
        return out;
    }

    // ------------------------------------------------------------ resolve

    private static boolean positiveInteger(Object v) {
        return VHLog.integer(v) && ((Number)v).doubleValue() >= 1;
    }

    private static boolean watcherUrl(Object v) {
        return v instanceof String s && s.startsWith("https://") && PRINTABLE.matcher(s).matches() &&
            s.length() > 8 && "/?#".indexOf(s.charAt(8)) < 0;
    }

    /** did:vh resolution options validation (profile §5, step 2). */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> validateOptions(Object raw, boolean remote) {
        if (!(raw instanceof Map<?, ?>))
            throw new DidVhError("invalidOptions", "resolution options must be an object");
        Map<String, Object> o = (Map<String, Object>)raw;
        if (o.containsKey("didLog") == o.containsKey("srcLog"))
            throw new DidVhError("invalidOptions", "exactly one of didLog and srcLog must be given");
        if (o.containsKey("didWitness") && o.containsKey("srcWitness"))
            throw new DidVhError("invalidOptions", "at most one of didWitness and srcWitness may be given");
        if (o.containsKey("didLog") && !(o.get("didLog") instanceof String))
            throw new DidVhError("invalidOptions", "didLog must be a string");
        if (o.containsKey("didWitness") && !(o.get("didWitness") instanceof List<?>))
            throw new DidVhError("invalidOptions", "didWitness must be an array");
        for (String key : List.of("srcLog", "srcWitness")) {
            if (!o.containsKey(key))
                continue;
            String kind = checkRef(o.get(key));
            if (remote && (kind.equals("file") || kind.equals("loopback")))
                throw new DidVhError("invalidOptions",
                    key + ": a resolver that serves other systems must not use file or loopback references");
        }
        long selectors = List.of("versionId", "versionTime", "versionNumber").stream()
            .filter(o::containsKey).count();
        if (selectors > 1)
            throw new DidVhError("invalidOptions",
                "at most one of versionId, versionTime and versionNumber may be given");
        if (o.containsKey("versionId") && !(o.get("versionId") instanceof String))
            throw new DidVhError("invalidOptions", "versionId must be a string");
        if (o.containsKey("versionTime") && VHLog.time(o.get("versionTime")) == null)
            throw new DidVhError("invalidOptions", "versionTime must be a whole-second UTC ISO 8601 time");
        if (o.containsKey("versionNumber") && !positiveInteger(o.get("versionNumber")))
            throw new DidVhError("invalidOptions", "versionNumber must be a positive integer");
        if (o.containsKey("checkWatchers")) {
            Object c = o.get("checkWatchers");
            if (!"all".equals(c) && !(VHLog.integer(c) && ((Number)c).doubleValue() >= 0))
                throw new DidVhError("invalidOptions", "checkWatchers must be a non-negative integer or \"all\"");
        }
        if (o.containsKey("extraWatchers") &&
            !(o.get("extraWatchers") instanceof List<?> w && w.stream().allMatch(DidVh::watcherUrl)))
            throw new DidVhError("invalidOptions", "extraWatchers must be an array of https URLs");
        if (o.containsKey("minCopies") && !positiveInteger(o.get("minCopies")))
            throw new DidVhError("invalidOptions", "minCopies must be a positive integer");
        if (o.containsKey("includeDidLog") && !(o.get("includeDidLog") instanceof Boolean))
            throw new DidVhError("invalidOptions", "includeDidLog must be a boolean");
        return o;
    }

    private static final Map<String, String> ERRORS = Map.of(
        "not-found", "notFound", "invalid-option", "invalidOptions", "fork-detected", "logForked",
        "min-copies-not-met", "insufficientCopies", "unsupported-log-version", "featureNotSupported");

    private static Map<String, Object> failure(DidVhError e) {
        Map<String, Object> details = obj("title", e.code, "detail", e.getMessage());
        if (e.vhLog != null)
            details.put("vhLog", e.vhLog);
        return obj("didResolutionMetadata", obj("error", e.code, "problemDetails", details),
                   "didDocument", null, "didDocumentMetadata", obj());
    }

    private static DidVhError fromVhLog(Map<String, Object> report) {
        String code = (String)report.get("code");
        return new DidVhError(ERRORS.getOrDefault(code, "invalidDid"), (String)report.get("message"), report);
    }

    /**
     * did:vh resolve(did, resolutionOptions) (profile §5). This resolver is offline: it verifies
     * a log passed in didLog (and didWitness), and gives featureNotSupported where it would
     * have to retrieve anything. now is an ISO 8601 time (null for the current time); remote
     * says whether the resolver serves other systems.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> resolve(Object did, Object resolutionOptions, String now,
                                              boolean remote) {
        try {
            String scid = parseDid(did);
            if (scid == null)
                throw new DidVhError("invalidDid", "not a did:vh DID");
            Map<String, Object> options =
                validateOptions(resolutionOptions, remote);
            if (options.containsKey("srcLog"))
                throw new DidVhError("featureNotSupported", "this resolver does not retrieve srcLog references");
            Object cw = options.getOrDefault("checkWatchers", 0.0);
            if (!(cw instanceof Number n && n.doubleValue() == 0) ||
                !((List<Object>)options.getOrDefault("extraWatchers", List.of())).isEmpty())
                throw new DidVhError("featureNotSupported", "this resolver does not retrieve copies from watchers");
            VHLog.Spec spec = specialisation(scid);
            if (now == null)
                now = Instant.now().toString().replaceAll("\\.\\d+Z$", "Z");
            String log = (String)options.get("didLog");
            Long clock = VHLog.time(now);
            // Whether the log needs witnessing does not depend on the witness file. Without
            // one, the first entry that needs it fails, which cuts it from the entries.
            VHLog.Verified unwitnessed = VHLog.verifyLog(
                log, VHLog.ABSENT, clock != null ? clock : Instant.now().getEpochSecond(), spec);
            boolean witnessed =
                unwitnessed.failure() != null &&
                    "witness-threshold-not-met".equals(unwitnessed.failure().get("code")) ||
                unwitnessed.entries().stream().anyMatch(e -> e.rule() != null);
            if (witnessed && options.containsKey("srcWitness"))
                throw new DidVhError("featureNotSupported", "this resolver does not retrieve srcWitness references");
            Map<String, Object> vhOptions = new LinkedHashMap<>();
            for (String key : List.of("versionId", "versionTime", "versionNumber", "minCopies"))
                if (options.containsKey(key))
                    vhOptions.put(key, options.get(key));
            Map<String, Object> in = obj("log", log, "now", now, "options", vhOptions);
            if (options.containsKey("didWitness"))
                in.put("witness", options.get("didWitness"));
            Map<String, Object> result = VHLog.resolve(in, spec);
            if (!Boolean.TRUE.equals(result.get("valid")))
                throw fromVhLog((Map<String, Object>)result.get("error"));
            boolean selected = List.of("versionId", "versionTime", "versionNumber").stream()
                .anyMatch(options::containsKey);
            Map<String, Object> error = (Map<String, Object>)result.get("error");
            if (!selected && error != null && "unsupported-log-version".equals(error.get("code")))
                throw fromVhLog(error);
            Map<String, Object> m = (Map<String, Object>)result.get("metadata");
            Map<String, Object> docMeta = obj(
                "versionId", m.get("versionId"), "versionTime", m.get("versionTime"), "created",
                m.get("created"), "updated", m.get("updated"), "scid", m.get("scid"), "deactivated",
                m.get("deactivated"), "ttl", m.get("ttl"));
            if (m.get("witness") != null)
                docMeta.put("witness", m.get("witness"));
            docMeta.put("watchers", m.get("watchers"));
            Map<String, Object> meta = obj("contentType", "application/did+json");
            List<Object> warnings = (List<Object>)m.get("warnings");
            if (!warnings.isEmpty())
                meta.put("warnings", warnings);
            if (Boolean.TRUE.equals(options.get("includeDidLog"))) {
                List<String> lines = VHLog.lines(log);
                Object first = result.get("firstInvalidVersion");
                int valid = first == null ? lines.size() : ((Number)first).intValue() - 1;
                StringBuilder b = new StringBuilder();
                for (String line : lines.subList(0, valid))
                    b.append(line).append('\n');
                meta.put("didLog", b.toString());
                if (witnessed)
                    meta.put("didWitness", options.get("didWitness") instanceof List<?> w ? w : List.of());
            }
            boolean deactivated = Boolean.TRUE.equals(m.get("deactivated"));
            return obj("didResolutionMetadata", meta, "didDocument",
                       deactivated && !selected ? null : result.get("state"), "didDocumentMetadata", docMeta);
        } catch (DidVhError e) {
            return failure(e);
        }
    }

    // ------------------------------------------------------------ driver operations

    /** Runs fn, turning a did:vh error into {valid: false, error}. */
    private static Map<String, Object> rejected(java.util.function.Supplier<Map<String, Object>> fn) {
        try {
            Map<String, Object> out = obj("valid", true);
            out.putAll(fn.get());
            return out;
        } catch (DidVhError e) {
            return obj("valid", false, "error", e.code);
        }
    }

    /** The did:vh driver operations (docs/interop-protocol.md, "did:vh operations"). */
    public static Object dispatch(String op, Map<String, Object> in) {
        return switch (op) {
            case "didvh-create" -> create(in);
            case "didvh-update" -> update(in);
            case "didvh-resolve" -> resolve(in.get("did"), in.containsKey("options") ? in.get("options") : obj(),
                                            (String)in.get("now"),
                                            Boolean.TRUE.equals(in.get("remote")));
            case "didvh-ref" -> rejected(() -> obj("kind", checkRef(in.get("ref"))));
            case "didvh-src" -> rejected(() -> srcReferences(in.get("src")));
            case "didvh-did-url" -> rejected(() -> parseDidUrl(in.get("didUrl")));
            default -> throw new IllegalArgumentException("unknown operation " + op);
        };
    }
}
