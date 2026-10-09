/// Seconds a `versionTime` may be ahead of the resolver's clock (profile §4).
public let futureToleranceSeconds: Int64 = 300

/// An active witness configuration (a non-empty `witness` parameter).
public struct WitnessConfig: Sendable, Equatable {
    /// Number of distinct witness approvals required.
    public var threshold: Int
    /// The witness objects as they appear in the log (each has a `did:key` `id`).
    public var witnesses: [JSONObject]
    /// The witness ids, in order.
    public var ids: [String] { witnesses.compactMap { $0["id"]?.stringValue } }

    /// The configuration as it appears in resolution metadata.
    public var json: JSONValue {
        .object(["threshold": .number(Double(threshold)), "witnesses": .array(witnesses.map { .object($0) })])
    }
}

/// The parameters active after an entry.
public struct Parameters: Sendable, Equatable {
    public var logVersion: String
    public var scid: String
    public var updateKeys: [String]
    public var nextKeyHashes: [String]
    /// `nil` when the parameter is `{}` (no witnesses).
    public var witness: WitnessConfig?
    public var watchers: [String]
    public var deactivated: Bool
    public var ttl: Int
}

/// An entry that passed every per-entry check.
public struct VerifiedEntry: Sendable {
    /// The entry as parsed.
    public var entry: JSONObject
    /// 1-based position in the log.
    public var versionNumber: Int
    /// `versionTime` as seconds since the Unix epoch.
    public var time: Int64
    /// Parameters active after this entry.
    public var parameters: Parameters
    /// The witness list this entry must satisfy, or `nil` if it needs no witnessing.
    public var witnessRule: WitnessConfig?

    public var versionId: String { entry["versionId"]?.stringValue ?? "" }
    public var versionTime: String { entry["versionTime"]?.stringValue ?? "" }
    public var state: JSONValue { entry["state"] ?? .null }
}

/// The outcome of ``verifyLog(_:witness:now:)``.
public struct VerifiedLog: Sendable {
    /// The valid (and witnessed) prefix of the log.
    public var entries: [VerifiedEntry]
    /// The raw lines of the log, for copy comparison.
    public var lines: [String]
    /// The first failure, if any.
    public var failure: VHLogError?

    /// Every entry is valid and witnessed.
    public var isFullyValid: Bool { failure == nil && entries.count == lines.count }

    /// The `versionId` of line `index`, read without verifying it.
    public func lineVersionId(_ index: Int) -> String? {
        guard lines.indices.contains(index) else { return nil }
        return try? JSONValue.parse(lines[index], replacingLoneSurrogates: true)["versionId"]?.stringValue
    }
}

/// `versionTime` parsing (profile §4).
public enum VersionTime {
    /// Seconds since the Unix epoch for a whole-second UTC timestamp
    /// (`YYYY-MM-DDTHH:MM:SSZ` or `…+00:00`), or `nil` if the value isn't one.
    public static func parse(_ value: String) -> Int64? {
        let b = Array(value.utf8)
        guard b.count == 20 || b.count == 25 else { return nil }
        func digits(_ range: Range<Int>) -> Int64? {
            var v: Int64 = 0
            for i in range {
                guard b[i] >= 0x30 && b[i] <= 0x39 else { return nil }
                v = v * 10 + Int64(b[i] - 0x30)
            }
            return v
        }
        guard b[4] == UInt8(ascii: "-"), b[7] == UInt8(ascii: "-"), b[10] == UInt8(ascii: "T"),
            b[13] == UInt8(ascii: ":"), b[16] == UInt8(ascii: ":"),
            let y = digits(0..<4), let mo = digits(5..<7), let d = digits(8..<10),
            let h = digits(11..<13), let mi = digits(14..<16), let s = digits(17..<19)
        else { return nil }
        let zone = b[19...]
        guard zone.elementsEqual("Z".utf8) || zone.elementsEqual("+00:00".utf8) else { return nil }
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
        let monthDays: [Int64] = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        guard (1...12).contains(mo), d >= 1, d <= monthDays[Int(mo - 1)], h <= 23, mi <= 59, s <= 59 else { return nil }
        return daysFromCivil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s
    }

    /// Days since 1970-01-01 in the proleptic Gregorian calendar (H. Hinnant's algorithm).
    static func daysFromCivil(_ year: Int64, _ month: Int64, _ day: Int64) -> Int64 {
        let y = month <= 2 ? year - 1 : year
        let era = (y >= 0 ? y : y - 399) / 400
        let yoe = y - era * 400
        let doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146097 + doe - 719468
    }
}

/// Profile §4: an `http`/`https` URL of printable ASCII with a non-empty authority.
public func isWatcherURL(_ value: String) -> Bool {
    let b = Array(value.utf8)
    guard !b.isEmpty, b.allSatisfy({ $0 >= 0x21 && $0 <= 0x7E }) else { return false }
    let rest: ArraySlice<UInt8>
    if b.starts(with: "https://".utf8) { rest = b[8...] } else if b.starts(with: "http://".utf8) { rest = b[7...] } else { return false }
    guard let first = rest.first else { return false }
    return first != UInt8(ascii: "/") && first != UInt8(ascii: "?") && first != UInt8(ascii: "#")
}

private let entryKeys = ["versionId", "versionTime", "parameters", "state", "proof"]
private let supportedLogVersions = [logVersion]

private func bytesEqual(_ a: String, _ b: String) -> Bool { a.utf8.elementsEqual(b.utf8) }
private func containsExactly(_ list: [String], _ value: String) -> Bool { list.contains { bytesEqual($0, value) } }

/// A JSON number that is an integer (ECMAScript `Number.isInteger`).
func integerValue(_ value: JSONValue?) -> Double? {
    guard let n = value?.numberValue, n.isFinite, n.rounded(.towardZero) == n else { return nil }
    return n
}

private func validateWitness(_ value: JSONValue, version: Int) throws(VHLogError) -> WitnessConfig? {
    func fail(_ why: String) -> VHLogError { VHLogError(.invalidParameter, "witness: \(why)", version: version) }
    guard let object = value.objectValue else { throw fail("must be an object") }
    if object.isEmpty { return nil }
    guard let witnesses = object["witnesses"]?.arrayValue, !witnesses.isEmpty else {
        throw fail("witnesses must be a non-empty array")
    }
    var ids: [String] = []
    var items: [JSONObject] = []
    for w in witnesses {
        guard let item = w.objectValue, let id = item["id"]?.stringValue else { throw fail("each witness needs a string id") }
        guard id.utf8.starts(with: "did:key:".utf8),
            Multikey.ed25519PublicKey(String(decoding: id.utf8.dropFirst(8), as: UTF8.self)) != nil
        else { throw fail("witness id \(id) is not an Ed25519 did:key") }
        // Ids are compared after NFC normalisation (profile §3); a valid did:key id
        // is ASCII, so NFC is the identity here and bytes are compared directly.
        if containsExactly(ids, id) { throw fail("duplicate witness id \(id)") }
        ids.append(id)
        items.append(item)
    }
    guard let threshold = integerValue(object["threshold"]), threshold >= 1, threshold <= Double(ids.count) else {
        throw fail("threshold must be an integer between 1 and the number of witnesses")
    }
    return WitnessConfig(threshold: Int(threshold), witnesses: items)
}

/// Applies an entry's `parameters` to the previously active set (Read step 1
/// and the pre-rotation rule of step 7).
private func applyParameters(_ raw: JSONObject, previous: Parameters?, version: Int) throws(VHLogError) -> Parameters {
    func invalid(_ message: String) -> VHLogError { VHLogError(.invalidParameter, message, version: version) }
    for m in raw.members where m.value.isNull { throw invalid("\(m.key) must not be null") }
    if previous == nil, !raw.contains("logVersion") {
        throw VHLogError(.unsupportedLogVersion, "logVersion missing from first entry", version: 1)
    }
    if let value = raw["logVersion"] {
        guard let v = value.stringValue, let index = supportedLogVersions.firstIndex(where: { bytesEqual($0, v) }) else {
            throw VHLogError(.unsupportedLogVersion, "unsupported logVersion", version: version)
        }
        if let previous, let old = supportedLogVersions.firstIndex(where: { bytesEqual($0, previous.logVersion) }), index < old {
            throw VHLogError(.unsupportedLogVersion, "logVersion may not be lowered", version: version)
        }
    }
    if previous == nil {
        guard raw["scid"]?.stringValue != nil else { throw invalid("scid missing from first entry") }
        guard raw.contains("updateKeys") else { throw invalid("updateKeys missing from first entry") }
    } else if raw.contains("scid") {
        throw invalid("scid may only appear in the first entry")
    }
    var updateKeys: [String]?
    if let value = raw["updateKeys"] {
        guard let keys = value.stringArrayValue, keys.allSatisfy({ Multikey.ed25519PublicKey($0) != nil }) else {
            throw invalid("updateKeys must be an array of Ed25519 multikeys")
        }
        updateKeys = keys
    }
    var nextKeyHashes: [String]?
    if let value = raw["nextKeyHashes"] {
        guard let hashes = value.stringArrayValue, hashes.allSatisfy({ Multihash.check($0) == .ok }) else {
            throw invalid("nextKeyHashes must be an array of SHA-256 multihashes")
        }
        nextKeyHashes = hashes
    }
    var witness = previous?.witness
    if let value = raw["witness"] { witness = try validateWitness(value, version: version) }
    var watchers: [String]?
    if let value = raw["watchers"] {
        guard let urls = value.stringArrayValue, urls.allSatisfy(isWatcherURL) else {
            throw invalid("watchers must be an array of URLs")
        }
        watchers = urls
    }
    var deactivated = false
    if let value = raw["deactivated"] {
        guard let b = value.boolValue else { throw invalid("deactivated must be a boolean") }
        deactivated = b
    }
    var ttl: Int?
    if let value = raw["ttl"] {
        guard let t = integerValue(value), t >= 0, t <= 2_147_483_648 else {
            throw invalid("ttl must be an integer between 0 and 2^31")
        }
        ttl = Int(t)
    }

    if let previous, !previous.nextKeyHashes.isEmpty {
        func violation(_ message: String) -> VHLogError { VHLogError(.prerotationViolation, message, version: version) }
        guard let keys = updateKeys else { throw violation("updateKeys must be explicit while pre-rotation is active") }
        guard nextKeyHashes != nil else { throw violation("nextKeyHashes must be explicit while pre-rotation is active") }
        for key in keys where !containsExactly(previous.nextKeyHashes, Multihash.keyHash(key)) {
            throw violation("key \(key) was not committed")
        }
    }

    return Parameters(
        logVersion: raw["logVersion"]?.stringValue ?? previous!.logVersion,
        scid: raw["scid"]?.stringValue ?? previous!.scid,
        updateKeys: updateKeys ?? previous!.updateKeys,
        nextKeyHashes: nextKeyHashes ?? previous?.nextKeyHashes ?? [],
        witness: witness,
        watchers: watchers ?? previous?.watchers ?? [],
        deactivated: deactivated,
        ttl: ttl ?? previous?.ttl ?? 3600
    )
}

private func verifyProofs(_ entry: JSONObject, activeKeys: [String], version: Int) throws(VHLogError) {
    let proofs = entry["proof"]?.arrayValue ?? []
    if proofs.isEmpty { throw VHLogError(.invalidProof, "proof array is empty", version: version) }
    let document = JSONValue.object(entry.removing("proof"))
    for proof in proofs {
        guard let vm = proof["verificationMethod"]?.stringValue, let multikey = Multikey.fromVerificationMethod(vm) else {
            throw VHLogError(.invalidProof, "proof verificationMethod is not did:key:<mk>#<mk>", version: version)
        }
        guard containsExactly(activeKeys, multikey) else {
            throw VHLogError(.unauthorizedKey, "\(multikey) is not an active update key", version: version)
        }
        guard DataIntegrity.verifyProof(document: document, proof: proof) else {
            throw VHLogError(.invalidProof, "proof failed verification", version: version)
        }
    }
}

private func verifyVersionId(_ entry: JSONObject, expected: Int, previousVersionId: String) throws(VHLogError) {
    let versionId = entry["versionId"]?.stringValue ?? ""
    let bytes = Array(versionId.utf8)
    func bad() -> VHLogError {
        VHLogError(.invalidVersionId, "expected versionId \(expected)-<hash>, got \(versionId)", version: expected)
    }
    // ^([1-9][0-9]*)-([^-]+)$
    guard let dash = bytes.firstIndex(of: UInt8(ascii: "-")), dash > 0, dash + 1 < bytes.count,
        bytes[0] != UInt8(ascii: "0"), bytes[..<dash].allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
        !bytes[(dash + 1)...].contains(UInt8(ascii: "-")),
        Double(String(decoding: bytes[..<dash], as: UTF8.self)) == Double(expected)
    else { throw bad() }
    let hash = String(decoding: bytes[(dash + 1)...], as: UTF8.self)
    switch Multihash.check(hash) {
    case .notBase58: throw VHLogError(.invalidVersionId, "entry hash is not base58btc", version: expected)
    case .unsupportedAlgorithm:
        throw VHLogError(.invalidHashAlgorithm, "entry hash is not a SHA-256 multihash", version: expected)
    case .ok: break
    }
    guard let computed = try? computeEntryHash(entry, previousVersionId: previousVersionId), bytesEqual(computed, hash) else {
        throw VHLogError(.entryHashMismatch, "entry hash does not match", version: expected)
    }
}

private func verifyScid(_ entry: JSONObject, scid: String) throws(VHLogError) {
    switch Multihash.check(scid) {
    case .unsupportedAlgorithm: throw VHLogError(.invalidHashAlgorithm, "SCID is not a SHA-256 multihash", version: 1)
    case .notBase58: throw VHLogError(.scidMismatch, "SCID is not base58btc", version: 1)
    case .ok: break
    }
    let preliminary = entry.removing("proof").setting("versionId", .string(scidPlaceholder))
    guard let restored = try? replacingText(in: preliminary, scid, with: scidPlaceholder),
        let computed = try? computeScid(restored), bytesEqual(computed, scid)
    else { throw VHLogError(.scidMismatch, "SCID does not match", version: 1) }
}

/// Runs the per-entry checks (profile §4, steps 1–7) on one parsed line.
private func verifyEntry(_ raw: JSONObject, previous: VerifiedEntry?, now: Int64) throws(VHLogError) -> VerifiedEntry {
    let version = (previous?.versionNumber ?? 0) + 1
    if previous?.parameters.deactivated == true {
        throw VHLogError(.entryAfterDeactivation, "entry follows a deactivating entry", version: version)
    }
    guard raw.count == entryKeys.count, entryKeys.allSatisfy(raw.contains),
        raw["versionId"]?.stringValue != nil, let versionTime = raw["versionTime"]?.stringValue,
        let rawParameters = raw["parameters"]?.objectValue, raw["state"]?.objectValue != nil,
        raw["proof"]?.arrayValue != nil
    else { throw VHLogError(.invalidEntry, "entry does not have the required properties and types", version: version) }

    let parameters = try applyParameters(rawParameters, previous: previous?.parameters, version: version)
    let activeKeys: [String]
    let witnessRule: WitnessConfig?
    if let previous {
        activeKeys = previous.parameters.nextKeyHashes.isEmpty ? previous.parameters.updateKeys : parameters.updateKeys
        let enablesWitnesses = rawParameters.contains("witness") && previous.parameters.witness == nil
        witnessRule = enablesWitnesses ? parameters.witness : previous.parameters.witness
    } else {
        activeKeys = parameters.updateKeys
        witnessRule = parameters.witness
    }
    try verifyProofs(raw, activeKeys: activeKeys, version: version)
    try verifyVersionId(raw, expected: version, previousVersionId: previous?.versionId ?? parameters.scid)

    guard let time = VersionTime.parse(versionTime) else {
        throw VHLogError(.invalidVersionTime, "invalid versionTime \(versionTime)", version: version)
    }
    if let previous, time <= previous.time {
        throw VHLogError(.invalidVersionTime, "versionTime must be later than the previous entry's", version: version)
    }
    if time > now + futureToleranceSeconds {
        throw VHLogError(.futureVersionTime, "versionTime is in the future", version: version)
    }
    if previous == nil { try verifyScid(raw, scid: parameters.scid) }
    return VerifiedEntry(entry: raw, versionNumber: version, time: time, parameters: parameters, witnessRule: witnessRule)
}

/// Returns the index of the first entry that isn't witnessed, with its error
/// (spec: *Verifying Witness Proofs During Resolution*, profile §3).
private func checkWitnesses(_ entries: [VerifiedEntry], witness: JSONValue?) -> (index: Int, error: VHLogError)? {
    guard let first = entries.firstIndex(where: { $0.witnessRule != nil }) else { return nil }
    // A witness file is an array of {versionId: string, proof: array}. Absent means none was found.
    var records: [(versionId: String, proofs: [JSONValue])] = []
    if let witness {
        guard let array = witness.arrayValue else {
            return (first, VHLogError(.invalidWitnessFile, "witness file is malformed", version: first + 1))
        }
        for item in array {
            guard let versionId = item["versionId"]?.stringValue, let proofs = item["proof"]?.arrayValue, item.objectValue != nil else {
                return (first, VHLogError(.invalidWitnessFile, "witness file is malformed", version: first + 1))
            }
            records.append((versionId, proofs))
        }
    }
    var position: [[UInt8]: Int] = [:]
    for (i, e) in entries.enumerated() { position[Array(e.versionId.utf8)] = i }

    struct Approval {
        var id: String
        var index: Int
        var proof: JSONValue
        var versionId: String
        var valid: Bool?
    }
    var approvals: [Approval] = []
    for record in records {
        guard let index = position[Array(record.versionId.utf8)] else { continue }
        for proof in record.proofs {
            if let vm = proof["verificationMethod"]?.stringValue, let multikey = Multikey.fromVerificationMethod(vm) {
                approvals.append(Approval(id: "did:key:\(multikey)", index: index, proof: proof, versionId: record.versionId))
            }
        }
    }
    for i in first..<entries.count {
        guard let rule = entries[i].witnessRule else { continue }
        let ids = rule.ids
        var approved: [String] = []
        for k in approvals.indices {
            let a = approvals[k]
            guard a.index >= i, containsExactly(ids, a.id), !containsExactly(approved, a.id) else { continue }
            if approvals[k].valid == nil {
                approvals[k].valid = DataIntegrity.verifyProof(document: .object(["versionId": .string(a.versionId)]), proof: a.proof)
            }
            if approvals[k].valid == true { approved.append(a.id) }
        }
        if approved.count < rule.threshold {
            let error = VHLogError(.witnessThresholdNotMet,
                                   "entry \(i + 1) has \(approved.count) of \(rule.threshold) required witness approvals",
                                   version: i + 1)
            return (i, error)
        }
    }
    return nil
}

/// Verifies a whole log, returning its valid, witnessed prefix and the first failure.
///
/// - Parameters:
///   - log: JSON Lines text (split on `\n` only).
///   - witness: The parsed witness file, or `nil` if none was found. An
///     explicit `.null` is a malformed file.
///   - now: The resolver's clock, in seconds since the Unix epoch.
public func verifyLog(_ log: String, witness: JSONValue?, now: Int64) -> VerifiedLog {
    let lines = parseLogLines(log)
    var entries: [VerifiedEntry] = []
    var failure: VHLogError?
    if lines.isEmpty {
        return VerifiedLog(entries: [], lines: [], failure: VHLogError(.invalidLog, "log is empty"))
    }
    for (i, line) in lines.enumerated() {
        let raw: JSONObject
        do {
            guard let object = try JSONValue.parse(line).objectValue else {
                failure = VHLogError(.invalidLog, "line \(i + 1) is not a JSON object", version: i + 1)
                break
            }
            raw = object
        } catch {
            let what = if case .loneSurrogate = error { "has a lone surrogate" } else { "is not JSON" }
            failure = VHLogError(.invalidLog, "line \(i + 1) \(what)", version: i + 1)
            break
        }
        guard JSONValue.object(raw).isIJSONSafe else {
            failure = VHLogError(.invalidLog, "line \(i + 1) has a non-finite number", version: i + 1)
            break
        }
        do {
            entries.append(try verifyEntry(raw, previous: entries.last, now: now))
        } catch {
            failure = error
            break
        }
    }
    if let unwitnessed = checkWitnesses(entries, witness: witness) {
        entries.removeSubrange(unwitnessed.index...)
        failure = unwitnessed.error
    }
    return VerifiedLog(entries: entries, lines: lines, failure: failure)
}
