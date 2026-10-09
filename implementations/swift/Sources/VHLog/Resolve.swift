/// Version selection and copy options for ``resolve(_:)``.
public struct ResolveOptions: Sendable, Equatable {
    public var versionId: String?
    /// A `versionTime`-format timestamp.
    public var versionTime: String?
    public var versionNumber: Int?
    /// Minimum number of copies that must be `current` or `behind`.
    public var minCopies: Int?

    public init(versionId: String? = nil, versionTime: String? = nil, versionNumber: Int? = nil, minCopies: Int? = nil) {
        self.versionId = versionId
        self.versionTime = versionTime
        self.versionNumber = versionNumber
        self.minCopies = minCopies
    }

    static let keys = ["versionId", "versionTime", "versionNumber", "minCopies"]

    /// Reads options from JSON, rejecting unknown options and wrong types with
    /// ``ErrorCode/invalidOption``.
    public init(json: JSONValue?) throws(VHLogError) {
        self.init()
        guard let json, !json.isNull else { return }
        guard let o = json.objectValue else { throw VHLogError(.invalidOption, "options must be an object") }
        for key in o.keys where !Self.keys.contains(where: { $0.utf8.elementsEqual(key.utf8) }) {
            throw VHLogError(.invalidOption, "unsupported option \(key)")
        }
        if Self.keys.prefix(3).filter(o.contains).count > 1 {
            throw VHLogError(.invalidOption, "at most one version selector may be given")
        }
        if let v = o["versionId"] {
            guard let s = v.stringValue else { throw VHLogError(.invalidOption, "versionId must be a string") }
            versionId = s
        }
        if let v = o["versionTime"] {
            guard let s = v.stringValue, VersionTime.parse(s) != nil else {
                throw VHLogError(.invalidOption, "versionTime must be a whole-second UTC ISO 8601 time")
            }
            versionTime = s
        }
        func positive(_ key: String) throws(VHLogError) -> Int? {
            guard let v = o[key] else { return nil }
            guard let n = integerValue(v), n >= 1 else { throw VHLogError(.invalidOption, "\(key) must be a positive integer") }
            return n >= 9_007_199_254_740_992 ? Int.max : Int(n)
        }
        versionNumber = try positive("versionNumber")
        minCopies = try positive("minCopies")
    }

    func validate() throws(VHLogError) {
        if [versionId != nil, versionTime != nil, versionNumber != nil].filter({ $0 }).count > 1 {
            throw VHLogError(.invalidOption, "at most one version selector may be given")
        }
        if let t = versionTime, VersionTime.parse(t) == nil {
            throw VHLogError(.invalidOption, "versionTime must be a whole-second UTC ISO 8601 time")
        }
        if let n = versionNumber, n < 1 { throw VHLogError(.invalidOption, "versionNumber must be a positive integer") }
        if let n = minCopies, n < 1 { throw VHLogError(.invalidOption, "minCopies must be a positive integer") }
    }
}

/// A copy of the log obtained from a watcher (or the primary location).
public enum LogCopy: Sendable, Equatable {
    /// A copy that was retrieved. `witness` is `nil` when no witness file was found.
    case available(source: String, log: String, witness: JSONValue?)
    /// A copy that couldn't be retrieved, with the reason.
    case unavailable(source: String, reason: String)

    /// Where the copy came from.
    public var source: String {
        switch self {
        case .available(let s, _, _), .unavailable(let s, _): s
        }
    }
}

/// Everything a resolution needs. The harness has no network, so watcher copies are passed in.
public struct ResolveInput: Sendable {
    /// The primary copy's log text.
    public var log: String
    /// The primary copy's witness file; `nil` means none was found.
    public var witness: JSONValue?
    /// The resolver's clock, in `versionTime` format.
    public var now: String
    public var options: ResolveOptions
    /// Watcher copies; when set (or `minCopies > 1`), copies are compared.
    public var copies: [LogCopy]?
    /// A `versionId` the client retained from an earlier resolution.
    public var retainedVersionId: String?

    public init(log: String, witness: JSONValue? = nil, now: String, options: ResolveOptions = .init(),
                copies: [LogCopy]? = nil, retainedVersionId: String? = nil) {
        self.log = log
        self.witness = witness
        self.now = now
        self.options = options
        self.copies = copies
        self.retainedVersionId = retainedVersionId
    }
}

/// Status of a copy after comparison.
public enum CopyStatus: String, Sendable, Equatable {
    case current, behind, invalid, unavailable
}

/// A non-fatal resolution warning.
public struct Warning: Sendable, Equatable {
    /// e.g. `invalid-entries`, `copy-behind`, `copy-invalid`, `copy-unavailable`, `retained-version-not-found`.
    public var code: String
    public var source: String?
    public var message: String

    public var json: JSONValue {
        var o: JSONObject = ["code": .string(code)]
        if let source { o["source"] = .string(source) }
        o["message"] = .string(message)
        return .object(o)
    }
}

/// One copy's comparison result.
public struct CopyReport: Sendable, Equatable {
    public var source: String
    public var versionId: String?
    public var status: CopyStatus

    public var json: JSONValue {
        var o: JSONObject = ["source": .string(source)]
        if let versionId { o["versionId"] = .string(versionId) }
        o["status"] = .string(status.rawValue)
        return .object(o)
    }
}

/// Resolution metadata (interop protocol, *Resolve*).
public struct ResolutionMetadata: Sendable {
    public var versionId: String
    public var versionTime: String
    public var versionNumber: Int
    public var created: String
    /// `versionTime` of the last valid entry.
    public var updated: String
    public var scid: String
    public var deactivated: Bool
    public var ttl: Int
    /// Active witness configuration at the last valid entry; `nil` if `{}`.
    public var witness: WitnessConfig?
    public var watchers: [String]
    /// Active at the resolved entry.
    public var updateKeys: [String]
    /// Active at the resolved entry.
    public var nextKeyHashes: [String]
    public var copies: [CopyReport]?
    public var warnings: [Warning]

    public var json: JSONValue {
        var o: JSONObject = [
            "versionId": .string(versionId), "versionTime": .string(versionTime),
            "versionNumber": .number(Double(versionNumber)), "created": .string(created), "updated": .string(updated),
            "scid": .string(scid), "deactivated": .bool(deactivated), "ttl": .number(Double(ttl)),
            "witness": witness?.json ?? .null, "watchers": .array(watchers.map { .string($0) }),
            "updateKeys": .array(updateKeys.map { .string($0) }), "nextKeyHashes": .array(nextKeyHashes.map { .string($0) }),
        ]
        if let copies { o["copies"] = .array(copies.map(\.json)) }
        o["warnings"] = .array(warnings.map(\.json))
        return .object(o)
    }
}

/// A successful resolution, possibly of a partially valid log.
public struct Resolution: Sendable {
    public var state: JSONValue
    public var metadata: ResolutionMetadata
    /// First invalid version of the reference copy, if any.
    public var firstInvalidVersion: Int?
    /// The error that invalidated ``firstInvalidVersion``.
    public var error: VHLogError?
}

/// The outcome of ``resolve(_:)``.
public enum ResolveResult: Sendable {
    case resolved(Resolution)
    case failed(VHLogError)

    /// The result in the driver protocol's shape.
    public var json: JSONValue {
        switch self {
        case .resolved(let r):
            .object([
                "valid": true, "state": r.state, "metadata": r.metadata.json,
                "firstInvalidVersion": r.firstInvalidVersion.map { .number(Double($0)) } ?? .null,
                "error": r.error?.json ?? .null,
            ])
        case .failed(let e):
            .object(["valid": false, "error": e.json])
        }
    }
}

private let primarySource = "primary"

/// Picks the target entry (spec: *Selecting a Version*). A target at or after
/// the first invalid entry fails with that entry's error (profile §4).
private func selectEntry(_ verified: VerifiedLog, _ options: ResolveOptions) throws(VHLogError) -> VerifiedEntry {
    let entries = verified.entries, lines = verified.lines
    func invalid() -> VHLogError {
        let f = verified.failure!
        return VHLogError(f.code, "requested version is invalid: \(f.message)", version: f.version)
    }
    if let versionId = options.versionId {
        if let found = entries.first(where: { $0.versionId.utf8.elementsEqual(versionId.utf8) }) { return found }
        for i in entries.count..<lines.count where verified.lineVersionId(i)?.utf8.elementsEqual(versionId.utf8) == true {
            throw invalid()
        }
        throw VHLogError(.notFound, "no entry with versionId \(versionId)")
    }
    if let n = options.versionNumber {
        if n <= entries.count { return entries[n - 1] }
        if n <= lines.count { throw invalid() }
        throw VHLogError(.notFound, "no entry with version number \(n)")
    }
    if let versionTime = options.versionTime {
        let time = VersionTime.parse(versionTime)!
        if verified.failure != nil, entries.count < lines.count,
            let line = try? JSONValue.parse(lines[entries.count], replacingLoneSurrogates: true),
            let t = line["versionTime"]?.stringValue.flatMap(VersionTime.parse), t <= time
        {
            throw invalid()
        }
        guard let found = entries.last(where: { $0.time <= time }) else {
            throw VHLogError(.notFound, "no entry active at \(versionTime)")
        }
        return found
    }
    return entries[entries.count - 1]
}

private func buildResult(_ verified: VerifiedLog, _ options: ResolveOptions, warnings: [Warning],
                         copies: [CopyReport]? = nil) throws(VHLogError) -> Resolution {
    let target = try selectEntry(verified, options)
    let first = verified.entries[0], last = verified.entries[verified.entries.count - 1]
    var warnings = warnings
    if let failure = verified.failure {
        let from = failure.version.map(String.init) ?? "null"
        warnings.append(Warning(code: "invalid-entries", message: "entries from version \(from) fail verification: \(failure.message)"))
    }
    let metadata = ResolutionMetadata(
        versionId: target.versionId, versionTime: target.versionTime, versionNumber: target.versionNumber,
        created: first.versionTime, updated: last.versionTime, scid: first.parameters.scid,
        deactivated: last.parameters.deactivated, ttl: last.parameters.ttl, witness: last.parameters.witness,
        watchers: last.parameters.watchers, updateKeys: target.parameters.updateKeys,
        nextKeyHashes: target.parameters.nextKeyHashes, copies: copies, warnings: warnings)
    return Resolution(state: target.state, metadata: metadata,
                      firstInvalidVersion: verified.failure == nil ? nil : verified.entries.count + 1,
                      error: verified.failure)
}

private func checkRetained(_ reference: VerifiedLog, source: String, retained: String,
                           warnings: inout [Warning]) throws(VHLogError) {
    // ^([1-9][0-9]*)-
    let bytes = Array(retained.utf8)
    guard let dash = bytes.firstIndex(of: UInt8(ascii: "-")), dash > 0, bytes[0] != UInt8(ascii: "0"),
        bytes[..<dash].allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
        let n = Double(String(decoding: bytes[..<dash], as: UTF8.self))
    else { throw VHLogError(.invalidOption, "retainedVersionId is not a versionId") }
    if Double(reference.entries.count) < n {
        warnings.append(Warning(code: "retained-version-not-found",
                                message: "the log has \(reference.entries.count) valid entries, fewer than retained version \(formatECMAScriptNumber(n))"))
        return
    }
    let version = Int(n)
    let versionId = reference.entries[version - 1].versionId
    if !versionId.utf8.elementsEqual(retained.utf8) {
        throw VHLogError(.forkDetected, "retained versionId differs at version \(version)", version: version,
                         fork: ForkReport(version: version, copies: [.init(source: "retained", versionId: retained),
                                                                     .init(source: source, versionId: versionId)]))
    }
}

private func sameId(_ a: String?, _ b: String?) -> Bool {
    switch (a, b) {
    case (nil, nil): true
    case (let x?, let y?): x.utf8.elementsEqual(y.utf8)
    default: false
    }
}

/// Spec: *Comparing Copies of a Log*, with copies supplied instead of fetched.
private func resolveCopies(_ input: ResolveInput, now: Int64) throws(VHLogError) -> ResolveResult {
    let options = input.options
    let all: [LogCopy] = [.available(source: primarySource, log: input.log, witness: input.witness)] + (input.copies ?? [])
    var warnings: [Warning] = []
    var status: [Int: CopyStatus] = [:]
    var cache: [Int: VerifiedLog] = [:]
    func verify(_ i: Int) -> VerifiedLog {
        if let v = cache[i] { return v }
        guard case .available(_, let log, let witness) = all[i] else { preconditionFailure("unavailable copy") }
        let v = verifyLog(log, witness: witness, now: now)
        cache[i] = v
        return v
    }
    func markInvalid(_ i: Int) {
        status[i] = .invalid
        let f = verify(i).failure
        warnings.append(Warning(code: "copy-invalid", source: all[i].source,
                                message: "copy fails verification at version \(f?.version.map(String.init) ?? "?"): \(f?.message ?? "")"))
    }

    for (i, c) in all.enumerated() {
        if case .unavailable(let source, let reason) = c {
            status[i] = .unavailable
            warnings.append(Warning(code: "copy-unavailable", source: source, message: reason))
        }
    }

    var ref: Int?
    for i in all.indices where ref == nil && status[i] == nil {
        if verify(i).isFullyValid { ref = i } else { markInvalid(i) }
    }
    guard var ref else {
        let primary = verify(0)
        return .failed(primary.failure ?? VHLogError(.invalidLog, "no copy verifies"))
    }

    var matched: Set<Int> = [ref]
    for i in all.indices where status[i] == nil && !matched.contains(i) {
        let reference = verify(ref)
        let refLines = reference.lines
        let copy = verify(i)
        let copyLines = copy.lines
        if copyLines.isEmpty {
            markInvalid(i)
            continue
        }
        var extends = false, same = false
        if copyLines.count <= refLines.count {
            same = sameId(copy.lineVersionId(copyLines.count - 1), reference.entries[copyLines.count - 1].versionId)
        } else {
            extends = sameId(copy.lineVersionId(refLines.count - 1), reference.entries[reference.entries.count - 1].versionId)
        }
        if same {
            matched.insert(i)
        } else if extends {
            if copy.isFullyValid {
                matched.insert(i)
                ref = i
            } else {
                markInvalid(i)
            }
        } else if !copy.isFullyValid {
            markInvalid(i)
        } else {
            var version = min(refLines.count, copyLines.count) + 1
            for k in 0..<min(refLines.count, copyLines.count)
            where !sameId(reference.lineVersionId(k), copy.lineVersionId(k)) {
                version = k + 1
                break
            }
            let forkCopies: [ForkReport.Copy] = [
                .init(source: all[ref].source, versionId: reference.lineVersionId(version - 1) ?? ""),
                .init(source: all[i].source, versionId: copy.lineVersionId(version - 1) ?? ""),
            ]
            throw VHLogError(.forkDetected, "copies diverge at version \(version)", version: version,
                             fork: ForkReport(version: version, copies: forkCopies))
        }
    }

    let reference = verify(ref)
    if let retained = input.retainedVersionId {
        try checkRetained(reference, source: all[ref].source, retained: retained, warnings: &warnings)
    }
    var reports: [CopyReport] = []
    for (i, c) in all.enumerated() {
        if let s = status[i] {
            if s == .unavailable {
                reports.append(CopyReport(source: c.source, versionId: nil, status: s))
            } else {
                let v = verify(i)
                reports.append(CopyReport(source: c.source, versionId: v.lineVersionId(v.lines.count - 1), status: s))
            }
            continue
        }
        let v = verify(i)
        let behind = reference.lines.count - v.lines.count
        if behind > 0 {
            warnings.append(Warning(code: "copy-behind", source: c.source, message: "copy is \(behind) entries behind"))
        }
        reports.append(CopyReport(source: c.source, versionId: v.lineVersionId(v.lines.count - 1),
                                  status: behind > 0 ? .behind : .current))
    }
    let usable = reports.filter { $0.status == .current || $0.status == .behind }.count
    if usable < options.minCopies ?? 1 {
        throw VHLogError(.minCopiesNotMet, "\(usable) matching copies, \(options.minCopies ?? 1) required")
    }
    return .resolved(try buildResult(reference, options, warnings: warnings, copies: reports))
}

/// Resolves a log (spec: *Read*, *Selecting a Version*, *Comparing Copies of a
/// Log*) following the interop profile's partial-validity rules.
///
/// Verification failures are returned as ``ResolveResult/failed(_:)``, or,
/// for a partially valid log, inside ``Resolution/error``; this function doesn't throw.
public func resolve(_ input: ResolveInput) -> ResolveResult {
    do throws(VHLogError) {
        guard let now = VersionTime.parse(input.now) else {
            throw VHLogError(.invalidOption, "now must be a whole-second UTC ISO 8601 time")
        }
        try input.options.validate()
        if input.copies != nil || (input.options.minCopies ?? 1) > 1 {
            return try resolveCopies(input, now: now)
        }
        let verified = verifyLog(input.log, witness: input.witness, now: now)
        if verified.entries.isEmpty { return .failed(verified.failure!) }
        var warnings: [Warning] = []
        if let retained = input.retainedVersionId {
            try checkRetained(verified, source: primarySource, retained: retained, warnings: &warnings)
        }
        return .resolved(try buildResult(verified, input.options, warnings: warnings))
    } catch {
        return .failed(error)
    }
}

/// Resolves a request in the interop driver protocol's `resolve` input shape
/// (`log`, `witness?`, `now`, `options?`, `copies?`, `retainedVersionId?`).
///
/// Bad options are reported as an ``ErrorCode/invalidOption`` result; only a
/// request that can't be interpreted at all (e.g. `log` isn't a string) throws.
public func resolve(request i: JSONValue) throws(VHLogInputError) -> ResolveResult {
    let options: ResolveOptions
    do {
        options = try ResolveOptions(json: i["options"])
    } catch {
        return .failed(error)
    }
    var copies: [LogCopy]?
    if let value = i["copies"] {
        copies = []
        for c in value.arrayValue ?? [] {
            guard let source = c["source"]?.stringValue else { throw .invalidInput("copy.source must be a string") }
            if let reason = c["unavailable"] {
                copies?.append(.unavailable(source: source, reason: reason.stringValue ?? ((try? reason.serialized()) ?? "")))
            } else {
                guard let log = c["log"]?.stringValue else { throw .invalidInput("copy.log must be a string") }
                copies?.append(.available(source: source, log: log, witness: c["witness"]))
            }
        }
    }
    guard let log = i["log"]?.stringValue else { throw .invalidInput("log must be a string") }
    // A non-string `now` or `retainedVersionId` fails validation as invalid-option, as in the reference.
    return resolve(ResolveInput(log: log, witness: i["witness"], now: i["now"]?.stringValue ?? "", options: options,
                                copies: copies, retainedVersionId: i["retainedVersionId"].map { $0.stringValue ?? "" }))
}
