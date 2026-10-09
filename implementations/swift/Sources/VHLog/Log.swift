/// The SCID placeholder replaced during log creation.
public let scidPlaceholder = "{SCID}"
/// The only supported `logVersion`.
public let logVersion = "vh-log:1.0"

/// Result of ``createLog(state:parameters:versionTime:signers:)``.
public struct CreatedLog: Sendable, Equatable {
    /// The log text (one line, `\n`-terminated).
    public var log: String
    /// The computed SCID.
    public var scid: String
    /// The first entry's `versionId`.
    public var versionId: String
}

/// Result of ``updateLog(log:state:parameters:versionTime:signers:)``.
public struct UpdatedLog: Sendable, Equatable {
    /// The log text with the new line appended.
    public var log: String
    /// The new entry's `versionId`.
    public var versionId: String
}

/// Splits a log into lines on `\n` (0x0A) only, dropping one trailing empty line.
public func parseLogLines(_ log: String) -> [String] {
    var lines = log.utf8.split(separator: UInt8(ascii: "\n"), omittingEmptySubsequences: false)
        .map { String(decoding: $0, as: UTF8.self) }
    if lines.last?.isEmpty == true { lines.removeLast() }
    return lines
}

/// SCID of a preliminary entry (placeholders in place, `versionId` = `{SCID}`):
/// `base58btc(multihash(JCS(entry without proof)))`.
public func computeScid(_ preliminary: JSONObject) throws(JSONSerializationError) -> String {
    Multihash.hashB58(try JCS.canonicalBytes(.object(preliminary.removing("proof"))))
}

/// Entry hash: the entry without `proof`, with `versionId` set to its predecessor's.
public func computeEntryHash(_ entry: JSONObject, previousVersionId: String) throws(JSONSerializationError) -> String {
    let document = entry.removing("proof").setting("versionId", .string(previousVersionId))
    return Multihash.hashB58(try JCS.canonicalBytes(.object(document)))
}

/// Compact JSON with the field order of profile §5, plus the trailing newline.
public func serializeEntry(_ entry: JSONObject) throws(JSONSerializationError) -> String {
    var ordered = JSONObject()
    for key in ["versionId", "versionTime", "parameters", "state", "proof"] {
        if let v = entry[key] { ordered[key] = v }
    }
    for m in entry.members where !ordered.contains(m.key) { ordered[m.key] = m.value }
    return try JSONValue.object(ordered).serialized() + "\n"
}

/// Replaces every occurrence of `target` in `text` by exact UTF-8 bytes (not
/// by Swift `Character`s, which would miss `{SCID}` followed by a combining mark).
func replacingBytes(in text: String, _ target: String, with replacement: String) -> String {
    let source = Array(text.utf8), needle = Array(target.utf8), with = Array(replacement.utf8)
    guard !needle.isEmpty, source.count >= needle.count else { return text }
    var out: [UInt8] = []
    out.reserveCapacity(source.count)
    var i = 0
    while i < source.count {
        if source[i] == needle[0], i + needle.count <= source.count,
            source[i..<(i + needle.count)].elementsEqual(needle)
        {
            out.append(contentsOf: with)
            i += needle.count
        } else {
            out.append(source[i])
            i += 1
        }
    }
    return String(decoding: out, as: UTF8.self)
}

/// Text replacement on the serialised object, then re-parse (spec: *Generate SCID*).
func replacingText(in object: JSONObject, _ target: String, with replacement: String) throws -> JSONObject {
    let text = replacingBytes(in: try JSONValue.object(object).serialized(), target, with: replacement)
    guard let result = try JSONValue.parse(text).objectValue else {
        throw VHLogInputError.invalidInput("replacement produced a non-object")
    }
    return result
}

func signDocument(_ document: JSONObject, signers: [Ed25519Signer]) throws -> JSONValue {
    var options = DataIntegrity.ProofOptions()
    options.created = document["versionTime"]
    return .array(try signers.map { .object(try DataIntegrity.createProof(document: .object(document), signer: $0, options: options)) })
}

/// Creates a new log (spec: *Create*). Adds `logVersion` and `"scid": "{SCID}"`
/// if absent, computes the SCID, replaces `{SCID}` everywhere by text
/// replacement, computes the entry hash and signs with every signer.
///
/// Inputs are not validated beyond what's needed to produce an entry (profile §5).
public func createLog(state: JSONValue, parameters: JSONObject, versionTime: String,
                      signers: [Ed25519Signer]) throws -> CreatedLog {
    var parameters = parameters
    if !parameters.contains("logVersion") { parameters["logVersion"] = .string(logVersion) }
    if !parameters.contains("scid") { parameters["scid"] = .string(scidPlaceholder) }
    let preliminary: JSONObject = [
        "versionId": .string(scidPlaceholder), "versionTime": .string(versionTime),
        "parameters": .object(parameters), "state": state,
    ]
    let scid = try computeScid(preliminary)
    let replaced = try replacingText(in: preliminary, scidPlaceholder, with: scid)
    let hash = try computeEntryHash(replaced, previousVersionId: scid)
    let document = replaced.setting("versionId", .string("1-\(hash)"))
    let entry = document.setting("proof", try signDocument(document, signers: signers))
    return CreatedLog(log: try serializeEntry(entry), scid: scid, versionId: "1-\(hash)")
}

/// Appends a signed entry to `log` (spec: *Update*). The hash chain continues
/// from the log's last line. Deactivate with `parameters: ["deactivated": true]`.
public func updateLog(log: String, state: JSONValue, parameters: JSONObject = [:], versionTime: String,
                      signers: [Ed25519Signer]) throws -> UpdatedLog {
    guard let last = parseLogLines(log).last else { throw VHLogInputError.invalidInput("cannot update an empty log") }
    guard let previousVersionId = try JSONValue.parse(last)["versionId"]?.stringValue else {
        throw VHLogInputError.invalidInput("the last log line has no string versionId")
    }
    let body: JSONObject = [
        "versionId": .string(previousVersionId), "versionTime": .string(versionTime),
        "parameters": .object(parameters), "state": state,
    ]
    let hash = try computeEntryHash(body, previousVersionId: previousVersionId)
    let number = javaScriptParseInt(String(decoding: previousVersionId.utf8.prefix { $0 != UInt8(ascii: "-") }, as: UTF8.self)) + 1
    let versionId = "\(formatECMAScriptNumber(number))-\(hash)"
    let document = body.setting("versionId", .string(versionId))
    let entry = document.setting("proof", try signDocument(document, signers: signers))
    let prefix = log.isEmpty || log.utf8.last == UInt8(ascii: "\n") ? log : log + "\n"
    return UpdatedLog(log: prefix + (try serializeEntry(entry)), versionId: versionId)
}

/// ECMAScript `parseInt(s, 10)` (ASCII whitespace only), as the reference
/// generator derives the next version number. NaN when there are no digits.
func javaScriptParseInt(_ s: String) -> Double {
    var bytes = Substring(s).utf8.drop { [0x20, 0x09, 0x0A, 0x0B, 0x0C, 0x0D].contains($0) }
    var sign = 1.0
    if let f = bytes.first, f == UInt8(ascii: "+") || f == UInt8(ascii: "-") {
        if f == UInt8(ascii: "-") { sign = -1 }
        bytes = bytes.dropFirst()
    }
    let digits = bytes.prefix { $0 >= 0x30 && $0 <= 0x39 }
    guard !digits.isEmpty, let v = Double(String(decoding: digits, as: UTF8.self)) else { return .nan }
    return sign * v
}

/// A witness proof: `eddsa-jcs-2022` over `{"versionId": …}` (profile §3).
public func witnessProof(versionId: String, signer: Ed25519Signer, created: String? = nil) throws -> JSONObject {
    try DataIntegrity.createProof(document: .object(["versionId": .string(versionId)]), signer: signer,
                                  options: .init(created: created))
}
