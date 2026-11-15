// did:vh (docs/didvh-profile.md). A did:vh DID log has the same format and
// verification as a VH-Log log (did:vh and VH-Log are both derived from
// did:webvh), so the log is verified by the VH-Log code with the did:vh
// specialisation. This file adds the DID syntax, the srcLog/srcWitness and DID
// URL rules, the resolution options, and DID Resolution metadata and errors.
package org.vhlog

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.time.Instant
import java.time.temporal.ChronoUnit

/** A did:vh (DID Resolution) error code; [code] is the wire form. */
enum class DidVhErrorCode(val code: String) {
    INVALID_DID("invalidDid"),
    INVALID_DID_URL("invalidDidUrl"),
    INVALID_OPTIONS("invalidOptions"),
    NOT_FOUND("notFound"),
    FEATURE_NOT_SUPPORTED("featureNotSupported"),
    LOG_FORKED("logForked"),
    INSUFFICIENT_COPIES("insufficientCopies");

    override fun toString(): String = code
}

/** A did:vh failure, with the VH-Log error behind it where there is one. */
class DidVhException @JvmOverloads constructor(
    val code: DidVhErrorCode,
    message: String,
    val vhLog: ErrorReport? = null,
) : RuntimeException(message)

/** The kind of a `srcLog` or `srcWitness` reference. */
enum class RefKind(val wire: String) {
    WEB("web"), LOOPBACK("loopback"), FILE("file"), OTHER("other");

    override fun toString(): String = wire
}

/** The result of [DidVh.createDid]. */
data class CreatedDid(val log: String, val did: String, val scid: String, val versionId: String)

/** A dereferenced did:vh DID URL. [options] are in query order; `versionNumber` is a number. */
data class DidUrl(val did: String, val options: JsonObject, val fragment: String?)

/** The context of a did:vh resolver (profile §5). */
data class ResolverContext @JvmOverloads constructor(
    /** The resolver's clock in `versionTime` format; null means the current time. */
    val now: String? = null,
    /** True for a resolver that accepts requests from other systems. */
    val remote: Boolean = false,
)

/** did:vh DID document metadata. [witness] is set only when witnesses are active. */
data class DidDocumentMetadata(
    val versionId: String,
    val versionTime: String,
    val created: String,
    val updated: String,
    val scid: String,
    val deactivated: Boolean,
    val ttl: Long,
    val witness: WitnessConfig?,
    val watchers: List<String>,
) {
    fun toJson(): JsonObject {
        val m = linkedMapOf<String, JsonValue>(
            "versionId" to JsonString(versionId), "versionTime" to JsonString(versionTime),
            "created" to JsonString(created), "updated" to JsonString(updated), "scid" to JsonString(scid),
            "deactivated" to JsonBool.of(deactivated), "ttl" to JsonNumber(ttl),
        )
        if (witness != null) m["witness"] = witness.toJson()
        m["watchers"] = JsonArray(watchers.map(::JsonString))
        return JsonObject(m)
    }
}

/** The result of [DidVh.resolve]. */
sealed class DidResolution {
    abstract fun toJson(): JsonObject

    /**
     * A resolved DID. [document] is null for a deactivated DID; [didLog] and
     * [didWitness] are set when `includeDidLog` is true.
     */
    data class Resolved(
        val document: JsonObject?,
        val metadata: DidDocumentMetadata,
        val warnings: List<Warning>,
        val didLog: String? = null,
        val didWitness: JsonValue? = null,
    ) : DidResolution() {
        override fun toJson(): JsonObject {
            val meta = linkedMapOf<String, JsonValue>("contentType" to JsonString("application/did+json"))
            if (warnings.isNotEmpty()) meta["warnings"] = JsonArray(warnings.map { it.toJson() })
            if (didLog != null) meta["didLog"] = JsonString(didLog)
            if (didWitness != null) meta["didWitness"] = didWitness
            return JsonObject(
                "didResolutionMetadata" to JsonObject(meta),
                "didDocument" to (document ?: JsonNull),
                "didDocumentMetadata" to metadata.toJson(),
            )
        }
    }

    /** Resolution failed. */
    data class Failed(val code: DidVhErrorCode, val detail: String, val vhLog: ErrorReport? = null) : DidResolution() {
        override fun toJson(): JsonObject {
            val details = linkedMapOf<String, JsonValue>("title" to JsonString(code.code), "detail" to JsonString(detail))
            if (vhLog != null) details["vhLog"] = vhLog.toJson()
            return JsonObject(
                "didResolutionMetadata" to JsonObject("error" to JsonString(code.code), "problemDetails" to JsonObject(details)),
                "didDocument" to JsonNull,
                "didDocumentMetadata" to JsonObject(),
            )
        }
    }
}

/** did:vh: DIDs, DID URLs, `srcLog`/`srcWitness` references and resolution. */
object DidVh {
    /** The `method` parameter value this library supports. */
    const val METHOD = "did:vh:1.0"
    const val PREFIX = "did:vh:"

    private val SCID = Regex("[1-9A-HJ-NP-Za-km-z]{46}")
    private val METHOD_SYNTAX = Regex("did:vh:(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)")

    // ------------------------------------------------------------ the DID

    /** The SCID of a did:vh DID, or null if [did] does not match the ABNF. */
    @JvmStatic
    fun parseDid(did: String): String? =
        if (did.startsWith(PREFIX) && SCID.matches(did.substring(PREFIX.length))) did.substring(PREFIX.length) else null

    /**
     * The did:vh specialisation of VH-Log: `method` instead of `logVersion`, a closed
     * parameter set, and `state.id` = `did:vh:<SCID>` in every entry. With
     * [expectedScid], the log's SCID must also be that of the DID being resolved.
     */
    @JvmStatic
    @JvmOverloads
    fun specialisation(expectedScid: String? = null): Specialisation =
        Specialisation("method", listOf(METHOD), METHOD_SYNTAX, emptyList()) { state, scid, version ->
            if (expectedScid != null && scid != expectedScid) {
                throw VHLogException(ErrorCode.INVALID_STATE, "the log is for did:vh:$scid, not did:vh:$expectedScid", version)
            }
            if (state.string("id") != PREFIX + scid) {
                throw VHLogException(ErrorCode.INVALID_STATE, "state.id must be $PREFIX$scid", version)
            }
        }

    // ------------------------------------------------------------ create / update

    /**
     * Creates a did:vh DID log. The document uses `did:vh:{SCID}` wherever it refers
     * to the DID; `method` and `scid` are added to the parameters if absent. Like
     * VH-Log generation, it does not validate its input.
     */
    @JvmStatic
    fun createDid(document: JsonObject, parameters: JsonObject, versionTime: String, signers: List<String>): CreatedDid {
        val r = LogController.createLog(document, parameters, versionTime, signers, "method", METHOD)
        return CreatedDid(r.log, PREFIX + r.scid, r.scid, r.versionId)
    }

    /** Appends an entry to a did:vh DID log. Deactivate with parameters `{"deactivated": true}`. */
    @JvmStatic
    @JvmOverloads
    fun updateDid(
        log: String,
        document: JsonObject,
        versionTime: String,
        signers: List<String>,
        parameters: JsonObject = JsonObject(),
    ): UpdateResult = LogController.updateLog(log, document, versionTime, signers, parameters)

    // ------------------------------------------------------------ shared URL checks

    /**
     * Percent-decodes [s], or null if an escape or the resulting UTF-8 is malformed.
     * Unescaped characters are taken as whole code points (their UTF-8 bytes).
     */
    @JvmStatic
    fun percentDecode(s: String): String? {
        val input = s.toByteArray(Charsets.UTF_8)
        val out = java.io.ByteArrayOutputStream(input.size)
        var i = 0
        while (i < input.size) {
            if (input[i] == '%'.code.toByte()) {
                if (i + 2 >= input.size) return null
                val hi = Character.digit(input[i + 1].toInt(), 16)
                val lo = Character.digit(input[i + 2].toInt(), 16)
                if (hi < 0 || lo < 0) return null
                out.write(hi * 16 + lo)
                i += 3
            } else {
                out.write(input[i].toInt())
                i++
            }
        }
        return try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(out.toByteArray())).toString()
        } catch (e: CharacterCodingException) {
            null
        }
    }

    /** Unicode White_Space. */
    private fun isWhiteSpace(cp: Int): Boolean =
        cp in 0x09..0x0D || cp == 0x20 || cp == 0x85 || cp == 0xA0 || cp == 0x1680 || cp in 0x2000..0x200A ||
            cp == 0x2028 || cp == 0x2029 || cp == 0x202F || cp == 0x205F || cp == 0x3000

    private val OCTET = Regex("0|[1-9][0-9]{0,2}")
    private val LABEL = Regex("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
    private val DIGITS = Regex("[0-9]+")
    private val PORT = Regex("[0-9]{1,5}")
    private val SCHEME = Regex("([A-Za-z][A-Za-z0-9+.-]*):(.*)", RegexOption.DOT_MATCHES_ALL)

    private fun isLoopbackHost(host: String): Boolean {
        if (host == "localhost" || host == "[::1]") return true
        val parts = host.split(".")
        return parts.size == 4 && parts[0] == "127" && parts.all { OCTET.matches(it) && it.toInt() <= 255 }
    }

    private fun isDomainName(host: String): Boolean {
        val name = host.removeSuffix(".")
        if (name.isEmpty() || name.length > 253) return false
        val labels = name.split(".")
        if (DIGITS.matches(labels.last())) return false // an IPv4 literal, or ends in a number
        return labels.all { LABEL.matches(it) }
    }

    private fun lower(s: String): String = buildString { for (c in s) append(if (c in 'A'..'Z') c + 32 else c) }

    /** Splits `scheme:rest` (profile §3 steps 1–2), lowercasing the scheme; null unless printable ASCII with a scheme. */
    private fun splitScheme(value: String): Pair<String, String>? {
        if (value.isEmpty() || value.any { it.code !in 0x21..0x7e }) return null
        val m = SCHEME.matchEntire(value) ?: return null
        return lower(m.groupValues[1]) to m.groupValues[2]
    }

    /** Checks an `http(s)` authority (profile §3). */
    private fun checkAuthority(authority: String, https: Boolean): Boolean {
        if ('@' in authority) return false
        val host: String
        var port: String? = null
        if (authority.startsWith("[")) {
            val close = authority.indexOf(']')
            if (close == -1) return false
            host = authority.substring(0, close + 1)
            val after = authority.substring(close + 1)
            if (after.isNotEmpty()) {
                if (!after.startsWith(":")) return false
                port = after.substring(1)
            }
        } else {
            val colon = authority.indexOf(':')
            host = if (colon == -1) authority else authority.substring(0, colon)
            if (colon != -1) port = authority.substring(colon + 1)
        }
        val h = lower(host)
        if (port != null && !(PORT.matches(port) && port.toInt() <= 65535)) return false
        return if (https) !h.startsWith("[") && isDomainName(h) else isLoopbackHost(h)
    }

    /**
     * Checks the segments of a path that starts with `/` (profile §3). Each is
     * percent-decoded and must not be `.` or `..` or contain `/`, `\` or NUL. With
     * [strict] (the `src` DID URL parameter), it must also be non-empty and not
     * start or end with white space.
     */
    private fun checkSegments(path: String, strict: Boolean): Boolean = path.substring(1).split("/").all { raw ->
        val segment = percentDecode(raw)
        when {
            segment == null || segment == "." || segment == ".." -> false
            segment.any { it == '/' || it == '\\' || it == '\u0000' } -> false
            strict && segment.isEmpty() -> false
            strict && (isWhiteSpace(segment.codePointAt(0)) || isWhiteSpace(segment.codePointBefore(segment.length))) -> false
            else -> true
        }
    }

    // ------------------------------------------------------------ srcLog / srcWitness references

    /**
     * Validates a `srcLog` or `srcWitness` reference, which names a file (profile
     * §3.1), and returns its kind. Throws `invalidOptions`.
     */
    @JvmStatic
    fun checkRef(ref: String): RefKind {
        fun invalid(why: String) = DidVhException(DidVhErrorCode.INVALID_OPTIONS, "reference $ref: $why")
        val (scheme, rest) = splitScheme(ref) ?: throw invalid("not a printable-ASCII absolute URL")
        if ('#' in rest) throw invalid("must not have a fragment")
        when (scheme) {
            "https", "http" -> {
                if (!rest.startsWith("//")) throw invalid("missing authority")
                val after = rest.substring(2)
                val end = after.indexOfFirst { it == '/' || it == '?' }.let { if (it == -1) after.length else it }
                val afterAuthority = after.substring(end)
                val path = afterAuthority.substringBefore('?')
                if (!checkAuthority(after.substring(0, end), scheme == "https")) {
                    throw invalid(if (scheme == "http") "http is only allowed with a loopback host" else "invalid https host")
                }
                if (path.isEmpty()) throw invalid("must have a path")
                if (!checkSegments(path, false)) throw invalid("invalid path segment")
                return if (scheme == "http") RefKind.LOOPBACK else RefKind.WEB
            }
            "file" -> {
                if ('?' in rest) throw invalid("must not have a query")
                val path = if (rest.startsWith("//")) {
                    val slash = rest.indexOf('/', 2)
                    if (slash == -1) throw invalid("file URL needs an absolute path")
                    val host = lower(rest.substring(2, slash))
                    if (host != "" && host != "localhost") throw invalid("file URL host must be empty or localhost")
                    rest.substring(slash)
                } else {
                    if (!rest.startsWith("/")) throw invalid("file URL needs an absolute path")
                    rest
                }
                if (!checkSegments(path, false)) throw invalid("invalid path segment")
                return RefKind.FILE
            }
        }
        if (rest.isEmpty()) throw invalid("empty URL")
        return RefKind.OTHER
    }

    // ------------------------------------------------------------ the src DID URL parameter

    /**
     * Validates a (percent-decoded) `src` DID URL parameter and derives the `srcLog`
     * and `srcWitness` references from it (profile §3.2). Throws `invalidDidUrl`.
     */
    @JvmStatic
    fun srcReferences(src: String): Pair<String, String> {
        fun invalid(why: String) = DidVhException(DidVhErrorCode.INVALID_DID_URL, "src $src: $why")
        val (scheme, rest) = splitScheme(src) ?: throw invalid("not a printable-ASCII absolute URL")
        if ('?' in rest || '#' in rest) throw invalid("must not have a query or fragment")
        if (scheme == "http" || scheme == "file") throw invalid("$scheme is not allowed in a DID URL")
        if (!rest.startsWith("//") || rest.length == 2 || rest[2] == '/') {
            throw invalid("not a hierarchical URL with an authority")
        }
        val base = rest.removeSuffix("/")
        if (scheme == "https") {
            val slash = base.indexOf('/', 2)
            val authority = if (slash == -1) base.substring(2) else base.substring(2, slash)
            val path = if (slash == -1) "" else base.substring(slash)
            if (!checkAuthority(authority, true)) throw invalid("invalid https host")
            if (path.isNotEmpty() && !checkSegments(path, true)) throw invalid("invalid path segment")
        }
        val location = "$scheme:$base"
        return "$location/did.jsonl" to "$location/did-witness.json"
    }

    // ------------------------------------------------------------ DID URLs

    private val URL_PARAMETERS = listOf("src", "versionId", "versionTime", "versionNumber")
    private val OPTION_ONLY = listOf(
        "didLog", "didWitness", "srcLog", "srcWitness", "checkWatchers", "extraWatchers", "minCopies", "includeDidLog",
    )
    private val VERSION_NUMBER = Regex("[1-9][0-9]{0,15}")

    /** Parses a did:vh DID URL as a dereferencer does (profile §4). Throws `invalidDidUrl`. */
    @JvmStatic
    fun parseDidUrl(didUrl: String): DidUrl {
        fun invalid(why: String) = DidVhException(DidVhErrorCode.INVALID_DID_URL, "$didUrl: $why")
        val hash = didUrl.indexOf('#')
        val beforeFragment = if (hash == -1) didUrl else didUrl.substring(0, hash)
        val fragment = if (hash == -1) null else didUrl.substring(hash + 1)
        val q = beforeFragment.indexOf('?')
        val did = if (q == -1) beforeFragment else beforeFragment.substring(0, q)
        if (parseDid(did) == null) throw invalid("not a did:vh DID")
        val options = LinkedHashMap<String, JsonValue>()
        val seen = HashSet<String>()
        if (q != -1) {
            for (pair in beforeFragment.substring(q + 1).split("&")) {
                val eq = pair.indexOf('=')
                if (eq == -1) throw invalid("query parameter $pair has no value")
                val key = percentDecode(pair.substring(0, eq))
                val value = percentDecode(pair.substring(eq + 1))
                if (key == null || value == null) throw invalid("malformed percent-encoding")
                if (key in OPTION_ONLY) throw invalid("$key is a resolution option, not a DID URL parameter")
                if (key !in URL_PARAMETERS) continue
                if (!seen.add(key)) throw invalid("$key given more than once")
                when (key) {
                    "src" -> {
                        val (srcLog, srcWitness) = srcReferences(value)
                        options["srcLog"] = JsonString(srcLog)
                        options["srcWitness"] = JsonString(srcWitness)
                    }
                    "versionNumber" -> {
                        if (!VERSION_NUMBER.matches(value)) throw invalid("versionNumber must be a positive integer")
                        options[key] = JsonNumber(value.toDouble())
                    }
                    else -> options[key] = JsonString(value)
                }
            }
        }
        return DidUrl(did, JsonObject(options), fragment)
    }

    // ------------------------------------------------------------ resolve

    private fun isPositiveInteger(v: JsonValue?): Boolean = v is JsonNumber && v.isInteger && v.value >= 1

    /** did:vh Resolution Options validation (profile §5, step 2). */
    private fun validateOptions(options: JsonValue, remote: Boolean): JsonObject {
        fun invalid(why: String) = DidVhException(DidVhErrorCode.INVALID_OPTIONS, why)
        val o = options as? JsonObject ?: throw invalid("resolution options must be an object")
        if (("didLog" in o) == ("srcLog" in o)) throw invalid("exactly one of didLog and srcLog must be given")
        if ("didWitness" in o && "srcWitness" in o) throw invalid("at most one of didWitness and srcWitness may be given")
        if ("didLog" in o && o["didLog"] !is JsonString) throw invalid("didLog must be a string")
        if ("didWitness" in o && o["didWitness"] !is JsonArray) throw invalid("didWitness must be an array")
        for (key in listOf("srcLog", "srcWitness")) {
            val v = o[key] ?: continue
            val kind = checkRef((v as? JsonString)?.value ?: throw invalid("$key must be a string"))
            if (remote && (kind == RefKind.FILE || kind == RefKind.LOOPBACK)) {
                throw invalid("$key: a resolver that serves other systems must not use local file or loopback references")
            }
        }
        if (listOf("versionId", "versionTime", "versionNumber").count { it in o } > 1) {
            throw invalid("at most one of versionId, versionTime and versionNumber may be given")
        }
        if ("versionId" in o && o["versionId"] !is JsonString) throw invalid("versionId must be a string")
        if ("versionTime" in o && o.string("versionTime")?.let(Verifier::parseVersionTime) == null) {
            throw invalid("versionTime must be a whole-second UTC ISO 8601 time")
        }
        if ("versionNumber" in o && !isPositiveInteger(o["versionNumber"])) throw invalid("versionNumber must be a positive integer")
        o["checkWatchers"]?.let { c ->
            val ok = (c is JsonString && c.value == "all") || (c is JsonNumber && c.isInteger && c.value >= 0)
            if (!ok) throw invalid("checkWatchers must be a non-negative integer or \"all\"")
        }
        o["extraWatchers"]?.let { w ->
            val ok = w is JsonArray && w.all { it is JsonString && it.value.startsWith("https://") && Verifier.isWatcherUrl(it.value) }
            if (!ok) throw invalid("extraWatchers must be an array of https URLs")
        }
        if ("minCopies" in o && !isPositiveInteger(o["minCopies"])) throw invalid("minCopies must be a positive integer")
        if ("includeDidLog" in o && o["includeDidLog"] !is JsonBool) throw invalid("includeDidLog must be a boolean")
        return o
    }

    private fun fromVHLog(e: ErrorReport): DidResolution.Failed {
        val code = when (e.code) {
            ErrorCode.NOT_FOUND -> DidVhErrorCode.NOT_FOUND
            ErrorCode.INVALID_OPTION -> DidVhErrorCode.INVALID_OPTIONS
            ErrorCode.FORK_DETECTED -> DidVhErrorCode.LOG_FORKED
            ErrorCode.MIN_COPIES_NOT_MET -> DidVhErrorCode.INSUFFICIENT_COPIES
            ErrorCode.UNSUPPORTED_LOG_VERSION -> DidVhErrorCode.FEATURE_NOT_SUPPORTED
            else -> DidVhErrorCode.INVALID_DID
        }
        return DidResolution.Failed(code, e.message, e)
    }

    private fun currentTime(): String = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString()

    /**
     * did:vh `resolve(did, resolutionOptions)` (profile §5). This resolver is offline:
     * it verifies a log passed in `didLog` (and `didWitness`), and returns
     * `featureNotSupported` when it would have to retrieve anything.
     */
    @JvmStatic
    @JvmOverloads
    fun resolve(did: String, options: JsonValue = JsonObject(), context: ResolverContext = ResolverContext()): DidResolution {
        return try {
            resolveOrThrow(did, options, context)
        } catch (e: DidVhException) {
            DidResolution.Failed(e.code, e.message ?: e.code.code, e.vhLog)
        }
    }

    private fun resolveOrThrow(did: String, options: JsonValue, context: ResolverContext): DidResolution {
        val scid = parseDid(did) ?: throw DidVhException(DidVhErrorCode.INVALID_DID, "$did is not a did:vh DID")
        val o = validateOptions(options, context.remote)
        fun unsupported(why: String) = DidVhException(DidVhErrorCode.FEATURE_NOT_SUPPORTED, why)
        if ("srcLog" in o) throw unsupported("this resolver does not retrieve srcLog references")
        val checkWatchers = o["checkWatchers"]
        if ((checkWatchers != null && (checkWatchers as? JsonNumber)?.value != 0.0) || (o.array("extraWatchers")?.isNotEmpty() == true)) {
            throw unsupported("this resolver does not retrieve copies from watchers")
        }
        val spec = specialisation(scid)
        val now = context.now ?: currentTime()
        val log = o.string("didLog")!!
        val witness = o["didWitness"]
        // Whether the log needs witnessing does not depend on the witness file. Without
        // one, the first entry that needs it fails, which cuts it from `entries`.
        val clock = Verifier.parseVersionTime(now) ?: Verifier.parseVersionTime(currentTime())!!
        val unwitnessed = Verifier.verifyLog(log, null, clock, spec)
        val witnessed = unwitnessed.failure?.code == ErrorCode.WITNESS_THRESHOLD_NOT_MET ||
            unwitnessed.entries.any { it.witnessRule != null }
        if (witnessed && "srcWitness" in o) throw unsupported("this resolver does not retrieve srcWitness references")

        fun long(key: String) = (o[key] as? JsonNumber)?.value?.let { minOf(it, 9e15).toLong() }
        val vhOptions = ResolveOptions(o.string("versionId"), o.string("versionTime"), long("versionNumber"), long("minCopies"))
        val result = when (val r = Resolver.resolve(ResolveRequest(log, now, witness, vhOptions, specialisation = spec))) {
            is ResolveResult.Failed -> return fromVHLog(r.error)
            is ResolveResult.Resolved -> r
        }
        val selected = listOf("versionId", "versionTime", "versionNumber").any { it in o }
        val error = result.error
        if (!selected && error != null && error.code == ErrorCode.UNSUPPORTED_LOG_VERSION) {
            // Entries after the last valid one may change the document or its keys (profile §5).
            return fromVHLog(error)
        }
        val m = result.metadata
        var didLog: String? = null
        var didWitness: JsonValue? = null
        if ((o["includeDidLog"] as? JsonBool) == JsonBool.TRUE) {
            val lines = LogController.parseLogLines(log)
            val valid = result.firstInvalidVersion?.let { it - 1 } ?: lines.size
            didLog = lines.take(valid).joinToString("") { it + "\n" }
            if (witnessed) didWitness = witness ?: JsonArray(emptyList())
        }
        val metadata = DidDocumentMetadata(
            m.versionId, m.versionTime, m.created, m.updated, m.scid, m.deactivated, m.ttl, m.witness, m.watchers,
        )
        // A deactivated DID's document is returned only for an explicit version selector (profile §5).
        return DidResolution.Resolved(if (m.deactivated && !selected) null else result.state, metadata, m.warnings, didLog, didWitness)
    }
}
