package org.vhlog

/** Result of [VHLog.createLog]. */
data class CreateResult(val log: String, val scid: String, val versionId: String)

/** Result of [VHLog.updateLog]. */
data class UpdateResult(val log: String, val versionId: String)

/** Overrides for sealing entries; only for building deliberately invalid test data. */
data class SealOptions @JvmOverloads constructor(
    /** Proof options applied to every signer. */
    val proof: ProofOptions = ProofOptions(),
    /** Override for the version number written into `versionId`. */
    val versionNumber: String? = null,
    /** Override for the hash written into `versionId`. */
    val entryHash: String? = null,
)

/** A sealed (signed) entry plus, for a genesis entry, its SCID. */
data class SealedEntry(val entry: JsonObject, val scid: String?)

/** Log Controller operations and hash computations (profile §5). */
object LogController {
    const val SCID_PLACEHOLDER = "{SCID}"
    const val LOG_VERSION = "vh-log:1.0"

    private val FIELD_ORDER = listOf("versionId", "versionTime", "parameters", "state", "proof")

    /** SCID of a preliminary entry (placeholders in place, `versionId` = `{SCID}`). */
    @JvmStatic
    fun computeScid(preliminary: JsonObject): String = Hashes.hashB58(Jcs.canonicalize(preliminary.without("proof")))

    /** Entry hash: the entry without `proof`, with `versionId` set to its predecessor's. */
    @JvmStatic
    fun computeEntryHash(entry: JsonObject, previousVersionId: String): String =
        Hashes.hashB58(Jcs.canonicalize(entry.without("proof").with("versionId", JsonString(previousVersionId))))

    /** Compact JSON with the field order of profile §5, plus the trailing newline. */
    @JvmStatic
    fun serializeEntry(entry: JsonObject): String {
        val ordered = LinkedHashMap<String, JsonValue>()
        for (key in FIELD_ORDER) entry[key]?.let { ordered[key] = it }
        for ((key, value) in entry) if (key !in ordered) ordered[key] = value
        return JsonObject(ordered).toJson() + "\n"
    }

    /** Splits a JSON Lines log on `\n`, dropping the empty string after a final newline. */
    @JvmStatic
    fun parseLogLines(log: String): List<String> {
        val lines = log.split('\n').toMutableList()
        if (lines.last() == "") lines.removeAt(lines.size - 1)
        return lines
    }

    /** Replaces every occurrence of [from] by [to] in the JSON text of [value] and parses the result. */
    internal fun replaceInText(value: JsonObject, from: String, to: String): JsonObject =
        Json.parse(value.toJson().replace(from, to)) as JsonObject

    private fun sign(document: JsonObject, signers: List<String>, options: SealOptions): JsonArray {
        val created = options.proof.created ?: document.string("versionTime")
        return JsonArray(signers.map { Proofs.create(document, it, options.proof.copy(created = created)) })
    }

    /**
     * Turns a genesis body into a signed first entry: computes the SCID, replaces
     * the placeholder, computes the entry hash and signs. The body is not
     * validated, so tests can seal deliberately invalid entries.
     */
    @JvmStatic
    @JvmOverloads
    fun sealGenesis(body: JsonObject, signers: List<String>, options: SealOptions = SealOptions()): SealedEntry {
        val preliminary = body.with("versionId", JsonString(SCID_PLACEHOLDER))
        val scid = computeScid(preliminary)
        val replaced = replaceInText(preliminary, SCID_PLACEHOLDER, scid)
        val hash = options.entryHash ?: computeEntryHash(replaced, scid)
        val document = replaced.with("versionId", JsonString("${options.versionNumber ?: "1"}-$hash"))
        return SealedEntry(document.with("proof", sign(document, signers, options)), scid)
    }

    /** Signs a later entry whose predecessor has [previousVersionId]. */
    @JvmStatic
    @JvmOverloads
    fun sealEntry(body: JsonObject, previousVersionId: String, signers: List<String>, options: SealOptions = SealOptions()): JsonObject {
        val withPrevious = body.with("versionId", JsonString(previousVersionId))
        val hash = options.entryHash ?: computeEntryHash(withPrevious, previousVersionId)
        val number = options.versionNumber ?: nextVersionNumber(previousVersionId)
        val document = withPrevious.with("versionId", JsonString("$number-$hash"))
        return document.with("proof", sign(document, signers, options))
    }

    /** `parseInt(previous.split("-")[0]) + 1`, as the reference implementation computes it. */
    private fun nextVersionNumber(previousVersionId: String): String {
        val m = Regex("^\\s*([+-]?[0-9]+)").find(previousVersionId.substringBefore('-'))
            ?: return "NaN"
        val n = m.groupValues[1].toBigInteger() + java.math.BigInteger.ONE
        return Jcs.formatNumber(n.toDouble())
    }

    /** Creates a log whose first entry has [state] and [parameters] (profile §5). */
    @JvmStatic
    fun createLog(state: JsonObject, parameters: JsonObject, versionTime: String, signers: List<String>): CreateResult {
        val params = LinkedHashMap(parameters.members)
        if ("logVersion" !in params) params["logVersion"] = JsonString(LOG_VERSION)
        if ("scid" !in params) params["scid"] = JsonString(SCID_PLACEHOLDER)
        val body = JsonObject(
            "versionId" to JsonString(SCID_PLACEHOLDER),
            "versionTime" to JsonString(versionTime),
            "parameters" to JsonObject(params),
            "state" to state,
        )
        val sealed = sealGenesis(body, signers)
        return CreateResult(serializeEntry(sealed.entry), sealed.scid!!, sealed.entry.string("versionId")!!)
    }

    /** Appends an entry to [log], chaining from its last line. */
    @JvmStatic
    @JvmOverloads
    fun updateLog(
        log: String,
        state: JsonObject,
        versionTime: String,
        signers: List<String>,
        parameters: JsonObject = JsonObject(),
    ): UpdateResult {
        val lines = parseLogLines(log)
        require(lines.isNotEmpty()) { "cannot update an empty log" }
        val previous = Json.parse(lines.last()) as? JsonObject
            ?: throw IllegalArgumentException("the last log line is not a JSON object")
        val previousVersionId = previous.string("versionId")
            ?: throw IllegalArgumentException("the last log line has no versionId")
        val body = JsonObject(
            "versionId" to JsonString(previousVersionId),
            "versionTime" to JsonString(versionTime),
            "parameters" to parameters,
            "state" to state,
        )
        val entry = sealEntry(body, previousVersionId, signers)
        val prefix = if (log.endsWith("\n") || log.isEmpty()) log else log + "\n"
        return UpdateResult(prefix + serializeEntry(entry), entry.string("versionId")!!)
    }

    /** A witness proof: `eddsa-jcs-2022` over `{"versionId": …}` (profile §3). */
    @JvmStatic
    @JvmOverloads
    fun witnessProof(versionId: String, seedHex: String, created: String? = null): JsonObject =
        Proofs.create(JsonObject("versionId" to JsonString(versionId)), seedHex, ProofOptions(created = created))
}
