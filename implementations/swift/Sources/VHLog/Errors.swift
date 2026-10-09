/// The interop profile's error codes (profile §6). Raw values are the exact codes.
public enum ErrorCode: String, Sendable, CaseIterable, Codable {
    case invalidLog = "invalid-log"
    case invalidEntry = "invalid-entry"
    case invalidParameter = "invalid-parameter"
    case unsupportedLogVersion = "unsupported-log-version"
    case prerotationViolation = "prerotation-violation"
    case invalidProof = "invalid-proof"
    case unauthorizedKey = "unauthorized-key"
    case invalidVersionId = "invalid-version-id"
    case invalidHashAlgorithm = "invalid-hash-algorithm"
    case entryHashMismatch = "entry-hash-mismatch"
    case invalidVersionTime = "invalid-version-time"
    case futureVersionTime = "future-version-time"
    case scidMismatch = "scid-mismatch"
    case entryAfterDeactivation = "entry-after-deactivation"
    case witnessThresholdNotMet = "witness-threshold-not-met"
    case invalidWitnessFile = "invalid-witness-file"
    case forkDetected = "fork-detected"
    case minCopiesNotMet = "min-copies-not-met"
    case notFound = "not-found"
    case invalidOption = "invalid-option"
}

/// Where two copies of a log (or a retained `versionId`) diverge.
public struct ForkReport: Sendable, Equatable {
    /// One side of the fork.
    public struct Copy: Sendable, Equatable {
        /// Copy source, `"primary"`, a watcher URL, or `"retained"`.
        public var source: String
        /// That copy's `versionId` at ``ForkReport/version``.
        public var versionId: String
    }
    /// First version number at which the copies differ.
    public var version: Int
    /// The two diverging copies.
    public var copies: [Copy]
}

/// A verification or resolution failure, carrying a profile ``ErrorCode``.
public struct VHLogError: Error, Sendable, Equatable, CustomStringConvertible {
    /// The profile error code.
    public var code: ErrorCode
    /// Version number of the entry that failed, where there is one.
    public var version: Int?
    /// Human-readable detail (not part of the interop contract).
    public var message: String
    /// Set for ``ErrorCode/forkDetected``.
    public var fork: ForkReport?

    public init(_ code: ErrorCode, _ message: String, version: Int? = nil, fork: ForkReport? = nil) {
        self.code = code
        self.message = message
        self.version = version
        self.fork = fork
    }

    public var description: String { "\(code.rawValue)\(version.map { " (version \($0))" } ?? ""): \(message)" }

    /// The error as the driver protocol's `error` object.
    public var json: JSONValue {
        var o: JSONObject = ["code": .string(code.rawValue), "version": version.map { .number(Double($0)) } ?? .null,
                             "message": .string(message)]
        if let fork {
            o["fork"] = .object([
                "version": .number(Double(fork.version)),
                "copies": .array(fork.copies.map { .object(["source": .string($0.source), "versionId": .string($0.versionId)]) }),
            ])
        }
        return .object(o)
    }
}

/// Malformed input to a generation or signing function (bad seed, a log
/// line that isn't JSON, …). These are caller errors, not verification results.
public enum VHLogInputError: Error, Sendable, Equatable, CustomStringConvertible {
    case invalidSeed(String)
    case invalidInput(String)

    public var description: String {
        switch self {
        case .invalidSeed(let m), .invalidInput(let m): m
        }
    }
}
