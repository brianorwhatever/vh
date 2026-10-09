package org.vhlog

/** Resolution options. At most one of [versionId], [versionTime] and [versionNumber] may be set. */
data class ResolveOptions @JvmOverloads constructor(
    val versionId: String? = null,
    val versionTime: String? = null,
    val versionNumber: Long? = null,
    val minCopies: Long? = null,
) {
    /** Throws `invalid-option` unless the options are usable. */
    fun validate() {
        if (listOfNotNull(versionId, versionTime, versionNumber).size > 1) {
            throw VHLogException(ErrorCode.INVALID_OPTION, "at most one version selector may be given")
        }
        if (versionTime != null && Verifier.parseVersionTime(versionTime) == null) {
            throw VHLogException(ErrorCode.INVALID_OPTION, "versionTime must be a whole-second UTC ISO 8601 time")
        }
        if (versionNumber != null && versionNumber < 1) {
            throw VHLogException(ErrorCode.INVALID_OPTION, "versionNumber must be a positive integer")
        }
        if (minCopies != null && minCopies < 1) {
            throw VHLogException(ErrorCode.INVALID_OPTION, "minCopies must be a positive integer")
        }
    }

    companion object {
        private val KEYS = listOf("versionId", "versionTime", "versionNumber", "minCopies")

        /** Parses the wire form of the options; throws `invalid-option` for anything malformed. */
        @JvmStatic
        fun fromJson(json: JsonValue?): ResolveOptions {
            if (json == null || json == JsonNull) return ResolveOptions()
            fun invalid(msg: String) = VHLogException(ErrorCode.INVALID_OPTION, msg)
            val obj = when (json) {
                is JsonObject -> json
                is JsonArray -> if (json.isEmpty()) return ResolveOptions() else throw invalid("options must be an object")
                else -> throw invalid("options must be an object")
            }
            for (key in obj.keys) if (key !in KEYS) throw invalid("unsupported option $key")
            if (KEYS.take(3).count { it in obj } > 1) throw invalid("at most one version selector may be given")
            val versionId = obj["versionId"]?.let { (it as? JsonString)?.value ?: throw invalid("versionId must be a string") }
            val versionTime = obj["versionTime"]?.let {
                (it as? JsonString)?.value?.takeIf { t -> Verifier.parseVersionTime(t) != null }
                    ?: throw invalid("versionTime must be a whole-second UTC ISO 8601 time")
            }
            fun positive(key: String): Long? = obj[key]?.let {
                val n = it as? JsonNumber
                if (n == null || !n.isInteger || n.value < 1) throw invalid("$key must be a positive integer")
                n.value.toLong() // saturates for huge values, which only ever compare as "too large"
            }
            return ResolveOptions(versionId, versionTime, positive("versionNumber"), positive("minCopies"))
        }
    }
}

/** A copy of the log obtained from a watcher or other source (profile §4, *Multiple copies*). */
sealed class CopyInput {
    abstract val source: String

    /** A retrieved copy. [witness] follows the convention of [Verifier.verifyLog]. */
    data class Available @JvmOverloads constructor(
        override val source: String,
        val log: String,
        val witness: JsonValue? = null,
    ) : CopyInput()

    /** A copy that could not be retrieved, with the reason. */
    data class Unavailable(override val source: String, val reason: String) : CopyInput()
}

/** A resolution request (interop protocol `resolve`). */
data class ResolveRequest @JvmOverloads constructor(
    val log: String,
    /** The resolver's clock, a whole-second UTC time. */
    val now: String,
    /** The witness file; null means none was found, [JsonNull] is a malformed file. */
    val witness: JsonValue? = null,
    val options: ResolveOptions = ResolveOptions(),
    /** Further copies; non-null switches on copy comparison. */
    val copies: List<CopyInput>? = null,
    /** A `versionId` the client retained from an earlier resolution. */
    val retainedVersionId: String? = null,
) {
    companion object {
        /**
         * Parses the wire form. Throws [VHLogException] (`invalid-option`) for bad
         * options and [IllegalArgumentException] for a malformed request.
         */
        @JvmStatic
        fun fromJson(json: JsonObject): ResolveRequest {
            val log = json.string("log") ?: throw IllegalArgumentException("log must be a string")
            val now = json.string("now") ?: throw VHLogException(ErrorCode.INVALID_OPTION, "now must be a whole-second UTC ISO 8601 time")
            val options = ResolveOptions.fromJson(json["options"])
            val copies = json["copies"]?.let { value ->
                val items = when (value) {
                    JsonNull -> emptyList()
                    is JsonArray -> value.items
                    else -> throw IllegalArgumentException("copies must be an array")
                }
                items.map { item ->
                    val c = item as? JsonObject ?: throw IllegalArgumentException("each copy must be an object")
                    val source = c.string("source") ?: throw IllegalArgumentException("each copy needs a source")
                    val unavailable = c["unavailable"]
                    if (unavailable != null) {
                        CopyInput.Unavailable(source, (unavailable as? JsonString)?.value ?: unavailable.toJson())
                    } else {
                        CopyInput.Available(
                            source,
                            c.string("log") ?: throw IllegalArgumentException("copy log must be a string"),
                            c["witness"],
                        )
                    }
                }
            }
            // A non-string retained versionId can never match ^[1-9][0-9]*-, so it fails as invalid-option later.
            val retained = json["retainedVersionId"]?.let { (it as? JsonString)?.value ?: "" }
            return ResolveRequest(log, now, json["witness"], options, copies, retained)
        }
    }
}

/** Status of one copy after comparison. */
enum class CopyStatus(val wire: String) {
    CURRENT("current"), BEHIND("behind"), INVALID("invalid"), UNAVAILABLE("unavailable");

    override fun toString(): String = wire
}

/** One copy's outcome in `metadata.copies`. */
data class CopyReport(val source: String, val versionId: String?, val status: CopyStatus) {
    fun toJson(): JsonObject {
        val m = linkedMapOf<String, JsonValue>("source" to JsonString(source))
        if (versionId != null) m["versionId"] = JsonString(versionId)
        m["status"] = JsonString(status.wire)
        return JsonObject(m)
    }
}

/** A non-fatal resolution warning, e.g. `invalid-entries` or `copy-behind`. */
data class Warning @JvmOverloads constructor(val code: String, val message: String, val source: String? = null) {
    fun toJson(): JsonObject {
        val m = linkedMapOf<String, JsonValue>("code" to JsonString(code))
        if (source != null) m["source"] = JsonString(source)
        m["message"] = JsonString(message)
        return JsonObject(m)
    }
}

/** Resolution metadata (interop protocol `resolve` result). */
data class ResolutionMetadata(
    val versionId: String,
    val versionTime: String,
    val versionNumber: Int,
    val created: String,
    val updated: String,
    val scid: String,
    val deactivated: Boolean,
    val ttl: Long,
    /** Active witness configuration at the last valid entry, null if none. */
    val witness: WitnessConfig?,
    val watchers: List<String>,
    /** Active at the resolved entry. */
    val updateKeys: List<String>,
    /** Active at the resolved entry. */
    val nextKeyHashes: List<String>,
    val copies: List<CopyReport>?,
    val warnings: List<Warning>,
) {
    fun toJson(): JsonObject {
        val strings = { l: List<String> -> JsonArray(l.map(::JsonString)) }
        val m = linkedMapOf(
            "versionId" to JsonString(versionId),
            "versionTime" to JsonString(versionTime),
            "versionNumber" to JsonNumber(versionNumber),
            "created" to JsonString(created),
            "updated" to JsonString(updated),
            "scid" to JsonString(scid),
            "deactivated" to JsonBool.of(deactivated),
            "ttl" to JsonNumber(ttl),
            "witness" to (witness?.toJson() ?: JsonNull),
            "watchers" to strings(watchers),
            "updateKeys" to strings(updateKeys),
            "nextKeyHashes" to strings(nextKeyHashes),
        )
        if (copies != null) m["copies"] = JsonArray(copies.map { it.toJson() })
        m["warnings"] = JsonArray(warnings.map { it.toJson() })
        return JsonObject(m)
    }
}

/** The outcome of [VHLog.resolve]. */
sealed class ResolveResult {
    abstract val error: ErrorReport?

    abstract fun toJson(): JsonObject

    /**
     * A resolved version. [firstInvalidVersion] and [error] describe partial
     * validity: entries from [firstInvalidVersion] on failed verification.
     */
    data class Resolved(
        val state: JsonObject,
        val metadata: ResolutionMetadata,
        val firstInvalidVersion: Int?,
        override val error: ErrorReport?,
    ) : ResolveResult() {
        override fun toJson(): JsonObject = JsonObject(
            "valid" to JsonBool.TRUE,
            "state" to state,
            "metadata" to metadata.toJson(),
            "firstInvalidVersion" to (firstInvalidVersion?.let { JsonNumber(it) } ?: JsonNull),
            "error" to (error?.toJson() ?: JsonNull),
        )
    }

    /** Resolution failed. */
    data class Failed(override val error: ErrorReport) : ResolveResult() {
        override fun toJson(): JsonObject = JsonObject("valid" to JsonBool.FALSE, "error" to error.toJson())
    }
}

/** Resolution (spec *Read (Resolve)*, *Selecting a Version*, *Comparing Copies of a Log*; profile §4). */
object Resolver {
    private const val PRIMARY = "primary"
    private val RETAINED = Regex("^([1-9][0-9]*)-")

    /** Resolves [request]. VH-Log failures are returned as [ResolveResult.Failed], never thrown. */
    @JvmStatic
    fun resolve(request: ResolveRequest): ResolveResult = try {
        val now = Verifier.parseVersionTime(request.now)
            ?: throw VHLogException(ErrorCode.INVALID_OPTION, "now must be a whole-second UTC ISO 8601 time")
        request.options.validate()
        if (request.copies != null || (request.options.minCopies ?: 1) > 1) {
            resolveCopies(request, now)
        } else {
            val verified = Verifier.verifyLog(request.log, request.witness, now)
            if (verified.entries.isEmpty()) {
                ResolveResult.Failed(verified.failure!!)
            } else {
                val warnings = ArrayList<Warning>()
                request.retainedVersionId?.let { checkRetained(verified, PRIMARY, it, warnings) }
                buildResult(verified, request.options, warnings, null)
            }
        }
    } catch (e: VHLogException) {
        ResolveResult.Failed(e.toReport())
    }

    /** Parses the wire form of a request and resolves it; `invalid-option` failures become [ResolveResult.Failed]. */
    @JvmStatic
    fun resolve(request: JsonObject): ResolveResult = try {
        resolve(ResolveRequest.fromJson(request))
    } catch (e: VHLogException) {
        ResolveResult.Failed(e.toReport())
    }

    private fun lineVersionId(lines: List<String>, index: Int): String? {
        if (index !in lines.indices) return null
        return (Json.parseOrNull(lines[index]) as? JsonObject)?.string("versionId")
    }

    /** Picks the target entry. A target at or after the first invalid entry fails with that entry's error (profile §4). */
    private fun selectEntry(verified: VerifiedLog, options: ResolveOptions): VerifiedEntry {
        val entries = verified.entries
        val lines = verified.lines
        fun invalid(): VHLogException {
            val f = verified.failure!!
            return VHLogException(f.code, "requested version is invalid: ${f.message}", f.version)
        }
        options.versionId?.let { id ->
            entries.firstOrNull { it.versionId == id }?.let { return it }
            for (i in entries.size until lines.size) if (lineVersionId(lines, i) == id) throw invalid()
            throw VHLogException(ErrorCode.NOT_FOUND, "no entry with versionId $id")
        }
        options.versionNumber?.let { n ->
            if (n <= entries.size) return entries[(n - 1).toInt()]
            if (n <= lines.size) throw invalid()
            throw VHLogException(ErrorCode.NOT_FOUND, "no entry with version number $n")
        }
        options.versionTime?.let { t ->
            val time = Verifier.parseVersionTime(t)!!
            if (verified.failure != null && entries.size < lines.size) {
                val firstInvalid = (Json.parseOrNull(lines[entries.size]) as? JsonObject)?.string("versionTime")
                    ?.let(Verifier::parseVersionTime)
                if (firstInvalid != null && firstInvalid <= time) throw invalid()
            }
            return entries.lastOrNull { it.time <= time }
                ?: throw VHLogException(ErrorCode.NOT_FOUND, "no entry active at $t")
        }
        return entries.last()
    }

    private fun buildResult(
        verified: VerifiedLog,
        options: ResolveOptions,
        warnings: MutableList<Warning>,
        copies: List<CopyReport>?,
    ): ResolveResult {
        val target = selectEntry(verified, options)
        val first = verified.entries.first()
        val last = verified.entries.last()
        val failure = verified.failure
        if (failure != null) {
            warnings.add(Warning("invalid-entries", "entries from version ${failure.version} fail verification: ${failure.message}"))
        }
        val metadata = ResolutionMetadata(
            versionId = target.versionId,
            versionTime = target.versionTime,
            versionNumber = target.versionNumber,
            created = first.versionTime,
            updated = last.versionTime,
            scid = first.parameters.scid,
            deactivated = last.parameters.deactivated,
            ttl = last.parameters.ttl,
            witness = last.parameters.witness,
            watchers = last.parameters.watchers,
            updateKeys = target.parameters.updateKeys,
            nextKeyHashes = target.parameters.nextKeyHashes,
            copies = copies,
            warnings = warnings.toList(),
        )
        return ResolveResult.Resolved(
            target.state,
            metadata,
            if (failure != null) verified.entries.size + 1 else null,
            failure,
        )
    }

    private fun checkRetained(reference: VerifiedLog, referenceSource: String, retained: String, warnings: MutableList<Warning>) {
        val m = RETAINED.find(retained)
            ?: throw VHLogException(ErrorCode.INVALID_OPTION, "retainedVersionId is not a versionId")
        val n = m.groupValues[1].toBigInteger()
        if (n > reference.entries.size.toBigInteger()) {
            warnings.add(
                Warning(
                    "retained-version-not-found",
                    "the log has ${reference.entries.size} valid entries, fewer than retained version $n",
                ),
            )
            return
        }
        val version = n.toInt()
        val versionId = reference.entries[version - 1].versionId
        if (versionId != retained) {
            throw VHLogException(
                ErrorCode.FORK_DETECTED,
                "retained versionId differs at version $version",
                version,
                ForkReport(version, listOf(ForkCopy("retained", retained), ForkCopy(referenceSource, versionId))),
            )
        }
    }

    /** First version number at which two logs' versionIds differ. */
    private fun divergence(a: List<String>, b: List<String>): Int {
        val n = minOf(a.size, b.size)
        for (i in 0 until n) if (lineVersionId(a, i) != lineVersionId(b, i)) return i + 1
        return n + 1
    }

    /** Comparing Copies of a Log, with copies supplied in the request instead of fetched. */
    private fun resolveCopies(request: ResolveRequest, now: Long): ResolveResult {
        val all = listOf(CopyInput.Available(PRIMARY, request.log, request.witness)) + (request.copies ?: emptyList())
        val warnings = ArrayList<Warning>()
        val status = HashMap<Int, CopyStatus>()
        val verifiedCache = HashMap<Int, VerifiedLog>()
        fun verify(i: Int): VerifiedLog = verifiedCache.getOrPut(i) {
            val c = all[i] as CopyInput.Available
            Verifier.verifyLog(c.log, c.witness, now)
        }
        fun markInvalid(i: Int) {
            status[i] = CopyStatus.INVALID
            val f = verify(i).failure
            warnings.add(
                Warning(
                    "copy-invalid",
                    "copy fails verification at version ${f?.version ?: "?"}: ${f?.message ?: ""}",
                    all[i].source,
                ),
            )
        }

        all.forEachIndexed { i, c ->
            if (c is CopyInput.Unavailable) {
                status[i] = CopyStatus.UNAVAILABLE
                warnings.add(Warning("copy-unavailable", c.reason, c.source))
            }
        }

        var ref = -1
        for (i in all.indices) {
            if (ref != -1) break
            if (i in status) continue
            if (verify(i).isFullyValid) ref = i else markInvalid(i)
        }
        if (ref == -1) {
            val error = verify(0).failure ?: ErrorReport(ErrorCode.INVALID_LOG, null, "no copy verifies")
            return ResolveResult.Failed(error)
        }

        val matched = hashSetOf(ref)
        for (i in all.indices) {
            if (i in status || i in matched) continue
            val reference = verify(ref)
            val refLines = reference.lines
            val copyLines = verify(i).lines
            if (copyLines.isEmpty()) {
                markInvalid(i)
                continue
            }
            var extends = false
            var same = false
            if (copyLines.size <= refLines.size) {
                same = lineVersionId(copyLines, copyLines.size - 1) == reference.entries[copyLines.size - 1].versionId
            } else {
                extends = lineVersionId(copyLines, refLines.size - 1) == reference.entries.last().versionId
            }
            when {
                same -> matched.add(i)
                extends -> if (verify(i).isFullyValid) {
                    matched.add(i)
                    ref = i
                } else {
                    markInvalid(i)
                }
                !verify(i).isFullyValid -> markInvalid(i)
                else -> {
                    val version = divergence(refLines, copyLines)
                    throw VHLogException(
                        ErrorCode.FORK_DETECTED,
                        "copies diverge at version $version",
                        version,
                        ForkReport(
                            version,
                            listOf(
                                ForkCopy(all[ref].source, lineVersionId(refLines, version - 1) ?: ""),
                                ForkCopy(all[i].source, lineVersionId(copyLines, version - 1) ?: ""),
                            ),
                        ),
                    )
                }
            }
        }

        val reference = verify(ref)
        request.retainedVersionId?.let { checkRetained(reference, all[ref].source, it, warnings) }
        val copies = all.mapIndexed { i, c ->
            val s = status[i]
            if (s != null) {
                if (s == CopyStatus.UNAVAILABLE) {
                    CopyReport(c.source, null, s)
                } else {
                    val lines = verify(i).lines
                    CopyReport(c.source, lineVersionId(lines, lines.size - 1), s)
                }
            } else {
                val lines = verify(i).lines
                val behind = reference.lines.size - lines.size
                if (behind > 0) warnings.add(Warning("copy-behind", "copy is $behind entries behind", c.source))
                CopyReport(c.source, lineVersionId(lines, lines.size - 1), if (behind > 0) CopyStatus.BEHIND else CopyStatus.CURRENT)
            }
        }
        val usable = copies.count { it.status == CopyStatus.CURRENT || it.status == CopyStatus.BEHIND }
        val minCopies = request.options.minCopies ?: 1
        if (usable < minCopies) {
            throw VHLogException(ErrorCode.MIN_COPIES_NOT_MET, "$usable matching copies, $minCopies required")
        }
        return buildResult(reference, request.options, warnings, copies)
    }
}
