package org.vhlog

/**
 * Entry point to the VH-Log library (interop profile `vh-log-interop-0`).
 *
 * Every function is also reachable from Java as a static method, e.g.
 * `VHLog.createLog(state, parameters, versionTime, signers)`.
 */
object VHLog {
    const val LOG_VERSION = LogController.LOG_VERSION
    const val LOG_FILE_NAME = "vh-log.jsonl"
    const val WITNESS_FILE_NAME = "vh-log-witness.json"

    /** Creates a new log; `scid` and `logVersion` are added to [parameters] if absent. */
    @JvmStatic
    fun createLog(state: JsonObject, parameters: JsonObject, versionTime: String, signers: List<String>): CreateResult =
        LogController.createLog(state, parameters, versionTime, signers)

    /** Appends a new entry to [log]; pass `{"deactivated": true}` as [parameters] to deactivate. */
    @JvmStatic
    @JvmOverloads
    fun updateLog(
        log: String,
        state: JsonObject,
        versionTime: String,
        signers: List<String>,
        parameters: JsonObject = JsonObject(),
    ): UpdateResult = LogController.updateLog(log, state, versionTime, signers, parameters)

    /** A witness proof over `{"versionId": versionId}`. */
    @JvmStatic
    @JvmOverloads
    fun witnessProof(versionId: String, seedHex: String, created: String? = null): JsonObject =
        LogController.witnessProof(versionId, seedHex, created)

    /** Verifies a log; see [Verifier.verifyLog]. [now] is a whole-second UTC time. */
    @JvmStatic
    @JvmOverloads
    fun verifyLog(log: String, now: String, witness: JsonValue? = null): VerifiedLog {
        val clock = Verifier.parseVersionTime(now)
            ?: throw VHLogException(ErrorCode.INVALID_OPTION, "now must be a whole-second UTC ISO 8601 time")
        return Verifier.verifyLog(log, witness, clock)
    }

    /** Resolves a log; failures are returned as [ResolveResult.Failed]. */
    @JvmStatic
    fun resolve(request: ResolveRequest): ResolveResult = Resolver.resolve(request)

    /** Resolves the wire form of a request (interop protocol `resolve` input). */
    @JvmStatic
    fun resolve(request: JsonObject): ResolveResult = Resolver.resolve(request)
}
