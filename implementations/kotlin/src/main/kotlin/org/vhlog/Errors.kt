package org.vhlog

/** The error codes of profile §6. [code] is the wire form, e.g. `entry-hash-mismatch`. */
enum class ErrorCode(val code: String) {
    INVALID_LOG("invalid-log"),
    INVALID_ENTRY("invalid-entry"),
    INVALID_PARAMETER("invalid-parameter"),
    UNSUPPORTED_LOG_VERSION("unsupported-log-version"),
    PREROTATION_VIOLATION("prerotation-violation"),
    INVALID_PROOF("invalid-proof"),
    UNAUTHORIZED_KEY("unauthorized-key"),
    INVALID_VERSION_ID("invalid-version-id"),
    INVALID_HASH_ALGORITHM("invalid-hash-algorithm"),
    ENTRY_HASH_MISMATCH("entry-hash-mismatch"),
    INVALID_VERSION_TIME("invalid-version-time"),
    FUTURE_VERSION_TIME("future-version-time"),
    SCID_MISMATCH("scid-mismatch"),
    ENTRY_AFTER_DEACTIVATION("entry-after-deactivation"),
    WITNESS_THRESHOLD_NOT_MET("witness-threshold-not-met"),
    INVALID_WITNESS_FILE("invalid-witness-file"),
    FORK_DETECTED("fork-detected"),
    MIN_COPIES_NOT_MET("min-copies-not-met"),
    NOT_FOUND("not-found"),
    INVALID_OPTION("invalid-option");

    override fun toString(): String = code

    companion object {
        /** The enum constant for a wire [code], or null. */
        @JvmStatic
        fun fromCode(code: String): ErrorCode? = entries.firstOrNull { it.code == code }
    }
}

/** One copy's `versionId` at the version where copies diverge. */
data class ForkCopy(val source: String, val versionId: String)

/** Details of a `fork-detected` error. */
data class ForkReport(val version: Int, val copies: List<ForkCopy>)

/** A verification or resolution failure, as reported to callers. */
data class ErrorReport(
    val code: ErrorCode,
    /** Version number of the entry that failed, where there is one. */
    val version: Int?,
    val message: String,
    val fork: ForkReport? = null,
) {
    fun toJson(): JsonObject {
        val m = linkedMapOf<String, JsonValue>(
            "code" to JsonString(code.code),
            "version" to (version?.let { JsonNumber(it) } ?: JsonNull),
            "message" to JsonString(message),
        )
        if (fork != null) {
            m["fork"] = JsonObject(
                "version" to JsonNumber(fork.version),
                "copies" to JsonArray(fork.copies.map {
                    JsonObject("source" to JsonString(it.source), "versionId" to JsonString(it.versionId))
                }),
            )
        }
        return JsonObject(m)
    }
}

/** Thrown inside the library for a VH-Log failure; carries an [ErrorCode]. */
class VHLogException @JvmOverloads constructor(
    val code: ErrorCode,
    message: String,
    val version: Int? = null,
    val fork: ForkReport? = null,
) : RuntimeException(message) {
    fun toReport(): ErrorReport = ErrorReport(code, version, message ?: code.code, fork)
}
