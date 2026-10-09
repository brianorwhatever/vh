package org.vhlog

import java.text.Normalizer
import java.time.LocalDate

/** An active witness configuration. [witnesses] are kept exactly as written in the log. */
data class WitnessConfig(val threshold: Int, val witnesses: List<JsonObject>) {
    /** The witness ids, NFC-normalised. */
    val ids: Set<String> get() = witnesses.mapTo(LinkedHashSet()) { nfc(it.string("id")!!) }

    fun toJson(): JsonObject = JsonObject("threshold" to JsonNumber(threshold), "witnesses" to JsonArray(witnesses))
}

/** The parameters active after an entry. */
data class Parameters(
    val logVersion: String,
    val scid: String,
    val updateKeys: List<String>,
    val nextKeyHashes: List<String>,
    /** null when no witnesses are configured (`{}`). */
    val witness: WitnessConfig?,
    val watchers: List<String>,
    val deactivated: Boolean,
    val ttl: Long,
)

/** An entry that passed every per-entry check. */
data class VerifiedEntry(
    val entry: JsonObject,
    val versionNumber: Int,
    /** Seconds since the epoch. */
    val time: Long,
    /** Parameters active after this entry. */
    val parameters: Parameters,
    /** Witness list this entry must satisfy, or null if it needs no witnessing. */
    val witnessRule: WitnessConfig?,
) {
    val versionId: String get() = entry.string("versionId")!!
    val versionTime: String get() = entry.string("versionTime")!!
    val state: JsonObject get() = entry.obj("state")!!
}

/** The outcome of verifying a whole log. */
data class VerifiedLog(
    /** The valid (and witnessed) prefix of the log. */
    val entries: List<VerifiedEntry>,
    /** The raw lines of the log. */
    val lines: List<String>,
    /** The first failure, or null if every entry is valid and witnessed. */
    val failure: ErrorReport?,
) {
    /** True when every line is a valid, witnessed entry. */
    val isFullyValid: Boolean get() = failure == null && entries.size == lines.size
}

internal fun nfc(s: String): String = Normalizer.normalize(s, Normalizer.Form.NFC)

/** Log verification (spec *Read (Resolve)*, profile §3–4). */
object Verifier {
    /** Seconds a `versionTime` may be ahead of the resolver's clock (profile §4). */
    const val FUTURE_TOLERANCE_SECONDS = 300L

    private val SUPPORTED_LOG_VERSIONS = listOf(LogController.LOG_VERSION)
    private val ENTRY_KEYS = listOf("versionId", "versionTime", "parameters", "state", "proof")
    private val VERSION_TIME = Regex("(\\d{4})-(\\d{2})-(\\d{2})T(\\d{2}):(\\d{2}):(\\d{2})(?:Z|\\+00:00)")
    private val VERSION_ID = Regex("([1-9][0-9]*)-([^-]+)")
    private const val TWO_31 = 2147483648.0

    /** Seconds since the epoch for a whole-second UTC `versionTime`, or null if it is malformed (profile §4). */
    @JvmStatic
    fun parseVersionTime(value: String): Long? {
        val m = VERSION_TIME.matchEntire(value) ?: return null
        val (y, mo, d, h, mi, s) = m.destructured.toList().map { it.toInt() }
        if (mo !in 1..12 || h > 23 || mi > 59 || s > 59) return null
        val leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
        val days = intArrayOf(31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)[mo - 1]
        if (d < 1 || d > days) return null
        return LocalDate.of(y, mo, d).toEpochDay() * 86400 + h * 3600L + mi * 60L + s
    }

    private operator fun <T> List<T>.component6(): T = this[5]

    /** Profile §4: an `http(s)` URL of printable ASCII with a non-empty authority. */
    @JvmStatic
    fun isWatcherUrl(value: String): Boolean {
        if (value.isEmpty() || value.any { it.code !in 0x21..0x7e }) return false
        val rest = when {
            value.startsWith("https://") -> value.substring(8)
            value.startsWith("http://") -> value.substring(7)
            else -> return false
        }
        return rest.isNotEmpty() && rest[0] != '/' && rest[0] != '?' && rest[0] != '#'
    }

    private fun stringList(value: JsonValue?): List<String>? =
        (value as? JsonArray)?.let { arr -> if (arr.all { it is JsonString }) arr.map { (it as JsonString).value } else null }

    private fun validateWitness(value: JsonValue, version: Int): WitnessConfig? {
        fun fail(why: String) = VHLogException(ErrorCode.INVALID_PARAMETER, "witness: $why", version)
        val obj = value as? JsonObject ?: throw fail("must be an object")
        if (obj.isEmpty()) return null
        val witnesses = obj.array("witnesses")
        if (witnesses == null || witnesses.isEmpty()) throw fail("witnesses must be a non-empty array")
        val ids = HashSet<String>()
        for (w in witnesses) {
            val id = (w as? JsonObject)?.string("id") ?: throw fail("each witness needs a string id")
            if (!id.startsWith("did:key:") || !Multikey.isValid(id.substring(8))) {
                throw fail("witness id $id is not an Ed25519 did:key")
            }
            if (!ids.add(nfc(id))) throw fail("duplicate witness id $id")
        }
        val threshold = obj["threshold"] as? JsonNumber
        if (threshold == null || !threshold.isInteger || threshold.value < 1 || threshold.value > ids.size) {
            throw fail("threshold must be an integer between 1 and the number of witnesses")
        }
        return WitnessConfig(threshold.value.toInt(), witnesses.map { it as JsonObject })
    }

    /** Applies an entry's `parameters` to the previously active set (Read step 1 and the pre-rotation rule of step 7). */
    private fun applyParameters(raw: JsonObject, previous: Parameters?, version: Int): Parameters {
        fun invalid(msg: String) = VHLogException(ErrorCode.INVALID_PARAMETER, msg, version)
        for ((key, value) in raw) if (value == JsonNull) throw invalid("$key must not be null")
        if (previous == null && "logVersion" !in raw) {
            throw VHLogException(ErrorCode.UNSUPPORTED_LOG_VERSION, "logVersion missing from first entry", 1)
        }
        raw["logVersion"]?.let { lv ->
            val s = (lv as? JsonString)?.value
            if (s == null || s !in SUPPORTED_LOG_VERSIONS) {
                throw VHLogException(ErrorCode.UNSUPPORTED_LOG_VERSION, "unsupported logVersion ${lv.toJson()}", version)
            }
            if (previous != null && SUPPORTED_LOG_VERSIONS.indexOf(s) < SUPPORTED_LOG_VERSIONS.indexOf(previous.logVersion)) {
                throw VHLogException(ErrorCode.UNSUPPORTED_LOG_VERSION, "logVersion may not be lowered", version)
            }
        }
        if (previous == null) {
            if (raw["scid"] !is JsonString) throw invalid("scid missing from first entry")
            if ("updateKeys" !in raw) throw invalid("updateKeys missing from first entry")
        } else if ("scid" in raw) {
            throw invalid("scid may only appear in the first entry")
        }
        val updateKeys = if ("updateKeys" in raw) {
            stringList(raw["updateKeys"])?.takeIf { keys -> keys.all(Multikey::isValid) }
                ?: throw invalid("updateKeys must be an array of Ed25519 multikeys")
        } else null
        val nextKeyHashes = if ("nextKeyHashes" in raw) {
            stringList(raw["nextKeyHashes"])?.takeIf { hs -> hs.all { Hashes.checkSha256Multihash(it) == MultihashCheck.OK } }
                ?: throw invalid("nextKeyHashes must be an array of SHA-256 multihashes")
        } else null
        val witness = raw["witness"].let { if (it != null) validateWitness(it, version) else previous?.witness }
        val watchers = if ("watchers" in raw) {
            stringList(raw["watchers"])?.takeIf { us -> us.all(::isWatcherUrl) }
                ?: throw invalid("watchers must be an array of URLs")
        } else null
        val deactivated = raw["deactivated"]?.let { (it as? JsonBool)?.value ?: throw invalid("deactivated must be a boolean") }
        val ttl = raw["ttl"]?.let {
            val n = it as? JsonNumber
            if (n == null || !n.isInteger || n.value < 0 || n.value > TWO_31) throw invalid("ttl must be an integer between 0 and 2^31")
            n.value.toLong()
        }

        if (previous != null && previous.nextKeyHashes.isNotEmpty()) {
            fun violation(msg: String) = VHLogException(ErrorCode.PREROTATION_VIOLATION, msg, version)
            if (updateKeys == null) throw violation("updateKeys must be explicit while pre-rotation is active")
            if (nextKeyHashes == null) throw violation("nextKeyHashes must be explicit while pre-rotation is active")
            for (key in updateKeys) {
                if (Hashes.keyHash(key) !in previous.nextKeyHashes) throw violation("key $key was not committed")
            }
        }

        return Parameters(
            logVersion = (raw["logVersion"] as? JsonString)?.value ?: previous!!.logVersion,
            scid = (raw["scid"] as? JsonString)?.value ?: previous!!.scid,
            updateKeys = updateKeys ?: previous!!.updateKeys,
            nextKeyHashes = nextKeyHashes ?: previous?.nextKeyHashes ?: emptyList(),
            witness = witness,
            watchers = watchers ?: previous?.watchers ?: emptyList(),
            deactivated = deactivated ?: false,
            ttl = ttl ?: previous?.ttl ?: 3600L,
        )
    }

    private fun verifyProofs(entry: JsonObject, activeKeys: List<String>, version: Int) {
        val proofs = entry.array("proof")!!
        if (proofs.isEmpty()) throw VHLogException(ErrorCode.INVALID_PROOF, "proof array is empty", version)
        val document = entry.without("proof")
        for (proof in proofs) {
            val multikey = (proof as? JsonObject)?.let { Proofs.multikeyFromVerificationMethod(it["verificationMethod"]) }
                ?: throw VHLogException(ErrorCode.INVALID_PROOF, "proof verificationMethod is not did:key:<mk>#<mk>", version)
            if (multikey !in activeKeys) {
                throw VHLogException(ErrorCode.UNAUTHORIZED_KEY, "$multikey is not an active update key", version)
            }
            if (!Proofs.verify(document, proof)) {
                throw VHLogException(ErrorCode.INVALID_PROOF, "proof failed verification", version)
            }
        }
    }

    private fun verifyVersionId(entry: JsonObject, expectedNumber: Int, previousVersionId: String) {
        val versionId = entry.string("versionId")!!
        val m = VERSION_ID.matchEntire(versionId)
        if (m == null || m.groupValues[1] != expectedNumber.toString()) {
            throw VHLogException(
                ErrorCode.INVALID_VERSION_ID, "expected versionId $expectedNumber-<hash>, got $versionId", expectedNumber,
            )
        }
        val hash = m.groupValues[2]
        when (Hashes.checkSha256Multihash(hash)) {
            MultihashCheck.NOT_BASE58 ->
                throw VHLogException(ErrorCode.INVALID_VERSION_ID, "entry hash is not base58btc", expectedNumber)
            MultihashCheck.UNSUPPORTED_ALGORITHM ->
                throw VHLogException(ErrorCode.INVALID_HASH_ALGORITHM, "entry hash is not a SHA-256 multihash", expectedNumber)
            MultihashCheck.OK -> {}
        }
        if (LogController.computeEntryHash(entry, previousVersionId) != hash) {
            throw VHLogException(ErrorCode.ENTRY_HASH_MISMATCH, "entry hash does not match", expectedNumber)
        }
    }

    private fun verifyScid(entry: JsonObject, scid: String) {
        when (Hashes.checkSha256Multihash(scid)) {
            MultihashCheck.UNSUPPORTED_ALGORITHM ->
                throw VHLogException(ErrorCode.INVALID_HASH_ALGORITHM, "SCID is not a SHA-256 multihash", 1)
            MultihashCheck.NOT_BASE58 -> throw VHLogException(ErrorCode.SCID_MISMATCH, "SCID is not base58btc", 1)
            MultihashCheck.OK -> {}
        }
        val preliminary = LogController.replaceInText(
            entry.without("proof").with("versionId", JsonString(LogController.SCID_PLACEHOLDER)),
            scid,
            LogController.SCID_PLACEHOLDER,
        )
        if (LogController.computeScid(preliminary) != scid) {
            throw VHLogException(ErrorCode.SCID_MISMATCH, "SCID does not match", 1)
        }
    }

    /** Runs the per-entry checks (profile §4, steps 1–7) on one parsed line. */
    private fun verifyEntry(raw: JsonObject, previous: VerifiedEntry?, now: Long): VerifiedEntry {
        val version = (previous?.versionNumber ?: 0) + 1
        if (previous?.parameters?.deactivated == true) {
            throw VHLogException(ErrorCode.ENTRY_AFTER_DEACTIVATION, "entry follows a deactivating entry", version)
        }
        if (raw.size != ENTRY_KEYS.size || !ENTRY_KEYS.all { it in raw } ||
            raw["versionId"] !is JsonString || raw["versionTime"] !is JsonString ||
            raw["parameters"] !is JsonObject || raw["state"] !is JsonObject || raw["proof"] !is JsonArray
        ) {
            throw VHLogException(ErrorCode.INVALID_ENTRY, "entry does not have the required properties and types", version)
        }
        val rawParameters = raw.obj("parameters")!!
        val parameters = applyParameters(rawParameters, previous?.parameters, version)

        val activeKeys: List<String>
        val witnessRule: WitnessConfig?
        if (previous == null) {
            activeKeys = parameters.updateKeys
            witnessRule = parameters.witness
        } else {
            activeKeys = if (previous.parameters.nextKeyHashes.isNotEmpty()) parameters.updateKeys else previous.parameters.updateKeys
            val enablesWitnesses = "witness" in rawParameters && previous.parameters.witness == null
            witnessRule = if (enablesWitnesses) parameters.witness else previous.parameters.witness
        }
        verifyProofs(raw, activeKeys, version)
        verifyVersionId(raw, version, previous?.versionId ?: parameters.scid)

        val versionTime = raw.string("versionTime")!!
        val time = parseVersionTime(versionTime)
            ?: throw VHLogException(ErrorCode.INVALID_VERSION_TIME, "invalid versionTime $versionTime", version)
        if (previous != null && time <= previous.time) {
            throw VHLogException(ErrorCode.INVALID_VERSION_TIME, "versionTime must be later than the previous entry's", version)
        }
        if (time > now + FUTURE_TOLERANCE_SECONDS) {
            throw VHLogException(ErrorCode.FUTURE_VERSION_TIME, "versionTime is in the future", version)
        }
        if (previous == null) verifyScid(raw, parameters.scid)

        return VerifiedEntry(raw, version, time, parameters, witnessRule)
    }

    private data class WitnessRecord(val versionId: String, val proof: List<JsonValue>)

    private fun asWitnessFile(witness: JsonValue): List<WitnessRecord>? {
        val arr = witness as? JsonArray ?: return null
        return arr.map { item ->
            val obj = item as? JsonObject ?: return null
            val versionId = obj.string("versionId") ?: return null
            val proof = obj.array("proof") ?: return null
            WitnessRecord(versionId, proof)
        }
    }

    private class Approval(val id: String, val index: Int, val proof: JsonValue, val versionId: String) {
        var valid: Boolean? = null
    }

    /** The index and error of the first entry that is not witnessed, or null (Verifying Witness Proofs During Resolution). */
    private fun checkWitnesses(entries: List<VerifiedEntry>, witness: JsonValue?): Pair<Int, VHLogException>? {
        val first = entries.indexOfFirst { it.witnessRule != null }
        if (first == -1) return null
        val file = if (witness == null) emptyList() else asWitnessFile(witness)
            ?: return first to VHLogException(ErrorCode.INVALID_WITNESS_FILE, "witness file is malformed", first + 1)
        val position = HashMap<String, Int>()
        entries.forEachIndexed { i, e -> position[e.versionId] = i }
        // A verified proof for entry j approves every entry <= j.
        val approvals = ArrayList<Approval>()
        for (record in file) {
            val index = position[record.versionId] ?: continue
            for (proof in record.proof) {
                val multikey = (proof as? JsonObject)?.let { Proofs.multikeyFromVerificationMethod(it["verificationMethod"]) } ?: continue
                approvals.add(Approval(nfc("did:key:$multikey"), index, proof, record.versionId))
            }
        }
        for (i in first until entries.size) {
            val rule = entries[i].witnessRule ?: continue
            val ids = rule.ids
            val approved = HashSet<String>()
            for (a in approvals) {
                if (a.index >= i && a.id in ids && a.id !in approved) {
                    val valid = a.valid ?: Proofs.verify(JsonObject("versionId" to JsonString(a.versionId)), a.proof).also { a.valid = it }
                    if (valid) approved.add(a.id)
                }
            }
            if (approved.size < rule.threshold) {
                return i to VHLogException(
                    ErrorCode.WITNESS_THRESHOLD_NOT_MET,
                    "entry ${i + 1} has ${approved.size} of ${rule.threshold} required witness approvals",
                    i + 1,
                )
            }
        }
        return null
    }

    /**
     * Verifies a whole log file, returning its valid, witnessed prefix and the first failure.
     *
     * @param witness the parsed witness file; Kotlin `null` means no file was found,
     *   while [JsonNull] (or any non-conforming value) is a malformed file.
     * @param now the resolver's clock, in seconds since the epoch.
     */
    @JvmStatic
    fun verifyLog(log: String, witness: JsonValue?, now: Long): VerifiedLog {
        val lines = LogController.parseLogLines(log)
        val entries = ArrayList<VerifiedEntry>()
        var failure: ErrorReport? = null
        if (lines.isEmpty()) return VerifiedLog(entries, lines, ErrorReport(ErrorCode.INVALID_LOG, null, "log is empty"))
        for ((i, line) in lines.withIndex()) {
            try {
                val raw = Json.parseOrNull(line)
                    ?: throw VHLogException(ErrorCode.INVALID_LOG, "line ${i + 1} is not JSON", i + 1)
                if (raw !is JsonObject) throw VHLogException(ErrorCode.INVALID_LOG, "line ${i + 1} is not a JSON object", i + 1)
                if (!isIJsonSafe(raw)) {
                    throw VHLogException(ErrorCode.INVALID_LOG, "line ${i + 1} has a non-finite number or a lone surrogate", i + 1)
                }
                entries.add(verifyEntry(raw, entries.lastOrNull(), now))
            } catch (e: VHLogException) {
                failure = e.toReport()
                break
            }
        }
        checkWitnesses(entries, witness)?.let { (index, error) ->
            while (entries.size > index) entries.removeAt(entries.size - 1)
            failure = error.toReport()
        }
        return VerifiedLog(entries, lines, failure)
    }
}
