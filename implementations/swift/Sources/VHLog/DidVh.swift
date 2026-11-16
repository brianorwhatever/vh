// did:vh (docs/didvh-profile.md). A did:vh DID log has the same format and
// verification as a VH-Log log (did:vh and VH-Log are both derived from
// did:webvh), so the log is verified by the VH-Log code with the did:vh
// specialisation. This file adds the DID syntax, the srcLog/srcWitness and DID
// URL rules, the resolution options, and DID Resolution metadata and errors.
//
// Strings are compared and split as UTF-8 bytes: Swift's `==` on String uses
// canonical equivalence, which would, for example, equate U+212A KELVIN SIGN
// with "K".

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// A did:vh (DID Resolution) error code.
public enum DidVhErrorCode: String, Sendable, Equatable {
    case invalidDid, invalidDidUrl, invalidOptions, notFound, featureNotSupported, logForked, insufficientCopies
}

/// A did:vh failure, with the VH-Log error behind it where there is one.
public struct DidVhError: Error, Sendable, Equatable, CustomStringConvertible {
    public var code: DidVhErrorCode
    public var message: String
    public var vhLog: VHLogError?

    public init(_ code: DidVhErrorCode, _ message: String, vhLog: VHLogError? = nil) {
        self.code = code
        self.message = message
        self.vhLog = vhLog
    }

    public var description: String { "\(code.rawValue): \(message)" }
}

/// The kind of a `srcLog` or `srcWitness` reference.
public enum RefKind: String, Sendable, Equatable {
    case web, loopback, file, other
}

/// did:vh: DIDs, DID URLs, `srcLog`/`srcWitness` references and resolution.
public enum DidVh {
    /// The `method` parameter value this library supports.
    public static let method = "did:vh:1.0"
    public static let prefix = "did:vh:"

    // MARK: - The DID

    /// The SCID of a did:vh DID, or `nil` if `did` does not match the ABNF.
    public static func parseDid(_ did: String) -> String? {
        let b = Array(did.utf8)
        guard b.starts(with: prefix.utf8), b.count == prefix.utf8.count + 46,
            b.dropFirst(prefix.utf8.count).allSatisfy(isBase58)
        else { return nil }
        return String(decoding: b.dropFirst(prefix.utf8.count), as: UTF8.self)
    }

    private static func isBase58(_ c: UInt8) -> Bool {
        switch c {
        case UInt8(ascii: "1")...UInt8(ascii: "9"): true
        case UInt8(ascii: "A")...UInt8(ascii: "Z"): c != UInt8(ascii: "I") && c != UInt8(ascii: "O")
        case UInt8(ascii: "a")...UInt8(ascii: "z"): c != UInt8(ascii: "l")
        default: false
        }
    }

    /// A non-negative decimal integer without leading zeros.
    private static func isDecimal<C: Collection>(_ s: C) -> Bool where C.Element == UInt8 {
        !s.isEmpty && s.allSatisfy(isDigit) && (s.count == 1 || s.first != UInt8(ascii: "0"))
    }

    private static func isDigit(_ c: UInt8) -> Bool { c >= 0x30 && c <= 0x39 }

    /// A well-formed `method` value: `did:vh:<major>.<minor>`.
    static func isMethodSyntax(_ value: String) -> Bool {
        let b = Array(value.utf8)
        guard b.starts(with: prefix.utf8) else { return false }
        let parts = b.dropFirst(prefix.utf8.count).split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
        return parts.count == 2 && parts.allSatisfy { isDecimal($0) }
    }

    /// The did:vh specialisation of VH-Log: `method` instead of `logVersion`, a
    /// closed parameter set, and `state.id` = `did:vh:<SCID>` in every entry.
    /// With `expectedScid`, the log's SCID must also be that of the DID being resolved.
    public static func specialisation(expectedScid: String? = nil) -> Specialisation {
        Specialisation(versionParameter: "method", versions: [method], versionSyntax: isMethodSyntax,
                       extraParameters: []) { (state: JSONObject, scid: String, version: Int) throws(VHLogError) in
            if let expectedScid, !expectedScid.utf8.elementsEqual(scid.utf8) {
                throw VHLogError(.invalidState, "the log is for did:vh:\(scid), not did:vh:\(expectedScid)", version: version)
            }
            guard let id = state["id"]?.stringValue, id.utf8.elementsEqual((prefix + scid).utf8) else {
                throw VHLogError(.invalidState, "state.id must be \(prefix)\(scid)", version: version)
            }
        }
    }

    // MARK: - Create / update

    /// The result of ``createDid(document:parameters:versionTime:signers:)``.
    public struct CreatedDid: Sendable, Equatable {
        public var log: String
        public var did: String
        public var scid: String
        public var versionId: String
    }

    /// Creates a did:vh DID log. The document uses `did:vh:{SCID}` wherever it
    /// refers to the DID; `method` and `scid` are added to the parameters if
    /// absent. Like ``createLog(state:parameters:versionTime:signers:versionParameter:version:)``,
    /// it does not validate its input.
    public static func createDid(document: JSONValue, parameters: JSONObject, versionTime: String,
                                 signers: [any VHLogSigner]) throws -> CreatedDid {
        let created = try createLog(state: document, parameters: parameters, versionTime: versionTime, signers: signers,
                                    versionParameter: "method", version: method)
        return CreatedDid(log: created.log, did: prefix + created.scid, scid: created.scid, versionId: created.versionId)
    }

    /// Appends an entry to a did:vh DID log. Deactivate with `parameters: ["deactivated": true]`.
    public static func updateDid(log: String, document: JSONValue, parameters: JSONObject = [:], versionTime: String,
                                 signers: [any VHLogSigner]) throws -> UpdatedLog {
        try updateLog(log: log, state: document, parameters: parameters, versionTime: versionTime, signers: signers)
    }

    // MARK: - Shared URL checks

    /// Percent-decodes `s`, or `nil` if an escape or the resulting UTF-8 is malformed.
    public static func percentDecode(_ s: String) -> String? {
        let b = Array(s.utf8)
        var out: [UInt8] = []
        var i = 0
        while i < b.count {
            if b[i] == UInt8(ascii: "%") {
                guard i + 2 < b.count, let hi = hexValue(b[i + 1]), let lo = hexValue(b[i + 2]) else { return nil }
                out.append(hi << 4 | lo)
                i += 3
            } else {
                out.append(b[i])
                i += 1
            }
        }
        // Decoding replaces malformed UTF-8 with U+FFFD, which changes the bytes.
        let decoded = String(decoding: out, as: UTF8.self)
        return decoded.utf8.elementsEqual(out) ? decoded : nil
    }

    private static func hexValue(_ c: UInt8) -> UInt8? {
        switch c {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): c - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): c - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): c - UInt8(ascii: "A") + 10
        default: nil
        }
    }

    /// Unicode White_Space.
    private static func isWhiteSpace(_ s: Unicode.Scalar) -> Bool {
        switch s.value {
        case 0x09...0x0D, 0x20, 0x85, 0xA0, 0x1680, 0x2000...0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000: true
        default: false
        }
    }

    private static func isLoopbackHost(_ host: [UInt8]) -> Bool {
        if host.elementsEqual("localhost".utf8) || host.elementsEqual("[::1]".utf8) { return true }
        let parts = host.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
        return parts.count == 4 && parts[0].elementsEqual("127".utf8)
            && parts.allSatisfy { isDecimal($0) && $0.count <= 3 && Int(String(decoding: $0, as: UTF8.self))! <= 255 }
    }

    private static func isDomainName(_ host: [UInt8]) -> Bool {
        let name = host.last == UInt8(ascii: ".") ? host.dropLast() : host[...]
        guard !name.isEmpty, name.count <= 253 else { return false }
        let labels = name.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
        if labels.last!.allSatisfy(isDigit) { return false } // an IPv4 literal, or ends in a number
        return labels.allSatisfy { l in
            (1...63).contains(l.count) && l.first != UInt8(ascii: "-") && l.last != UInt8(ascii: "-")
                && l.allSatisfy { ($0 >= 0x61 && $0 <= 0x7A) || isDigit($0) || $0 == UInt8(ascii: "-") }
        }
    }

    /// Splits `scheme:rest` (profile §3 steps 1–2), lowercasing the scheme;
    /// `nil` unless `value` is printable ASCII starting with a scheme.
    private static func splitScheme(_ value: String) -> (scheme: String, rest: [UInt8])? {
        let b = Array(value.utf8)
        guard !b.isEmpty, b.allSatisfy({ $0 >= 0x21 && $0 <= 0x7E }), let colon = b.firstIndex(of: UInt8(ascii: ":")),
            colon > 0, isLetter(b[0]),
            b[1..<colon].allSatisfy({ isLetter($0) || isDigit($0) || $0 == UInt8(ascii: "+") || $0 == UInt8(ascii: ".") || $0 == UInt8(ascii: "-") })
        else { return nil }
        return (lowercased(b[..<colon]), Array(b[(colon + 1)...]))
    }

    private static func isLetter(_ c: UInt8) -> Bool { (c | 0x20) >= 0x61 && (c | 0x20) <= 0x7A }

    private static func lowercased<C: Collection>(_ b: C) -> String where C.Element == UInt8 {
        String(decoding: b.map { $0 >= 0x41 && $0 <= 0x5A ? $0 | 0x20 : $0 }, as: UTF8.self)
    }

    /// Checks an `http(s)` authority (profile §3).
    private static func checkAuthority(_ authority: ArraySlice<UInt8>, https: Bool) -> Bool {
        if authority.contains(UInt8(ascii: "@")) { return false }
        var host: ArraySlice<UInt8>
        var port: ArraySlice<UInt8>?
        if authority.first == UInt8(ascii: "[") {
            guard let close = authority.firstIndex(of: UInt8(ascii: "]")) else { return false }
            host = authority[...close]
            let after = authority[(close + 1)...]
            if !after.isEmpty {
                guard after.first == UInt8(ascii: ":") else { return false }
                port = after.dropFirst()
            }
        } else if let colon = authority.firstIndex(of: UInt8(ascii: ":")) {
            host = authority[..<colon]
            port = authority[(colon + 1)...]
        } else {
            host = authority
        }
        let lower = Array(lowercased(host).utf8)
        if let port {
            guard (1...5).contains(port.count), port.allSatisfy(isDigit),
                Int(String(decoding: port, as: UTF8.self))! <= 65535
            else { return false }
        }
        return https ? lower.first != UInt8(ascii: "[") && isDomainName(lower) : isLoopbackHost(lower)
    }

    /// Checks the segments of a path that starts with `/` (profile §3). Each is
    /// percent-decoded and must not be `.` or `..` or contain `/`, `\` or NUL.
    /// With `strict` (the `src` DID URL parameter), it must also be non-empty
    /// and not start or end with white space.
    private static func checkSegments(_ path: ArraySlice<UInt8>, strict: Bool) -> Bool {
        path.dropFirst().split(separator: UInt8(ascii: "/"), omittingEmptySubsequences: false).allSatisfy { raw in
            guard let segment = percentDecode(String(decoding: raw, as: UTF8.self)) else { return false }
            let bytes = Array(segment.utf8)
            if bytes.elementsEqual(".".utf8) || bytes.elementsEqual("..".utf8)
                || bytes.contains(where: { $0 == UInt8(ascii: "/") || $0 == UInt8(ascii: "\\") || $0 == 0 })
            {
                return false
            }
            if strict {
                guard let first = segment.unicodeScalars.first, let last = segment.unicodeScalars.last,
                    !isWhiteSpace(first), !isWhiteSpace(last)
                else { return false }
            }
            return true
        }
    }

    // MARK: - srcLog / srcWitness references

    /// Validates a `srcLog` or `srcWitness` reference, which names a file
    /// (profile §3.1), and returns its kind. Throws `invalidOptions`.
    public static func checkRef(_ ref: String) throws(DidVhError) -> RefKind {
        func invalid(_ why: String) -> DidVhError { DidVhError(.invalidOptions, "reference \(ref): \(why)") }
        guard let (scheme, rest) = splitScheme(ref) else { throw invalid("not a printable-ASCII absolute URL") }
        if rest.contains(UInt8(ascii: "#")) { throw invalid("must not have a fragment") }
        switch scheme {
        case "https", "http":
            guard rest.starts(with: "//".utf8) else { throw invalid("missing authority") }
            let after = rest[2...]
            let end = after.firstIndex(where: { $0 == UInt8(ascii: "/") || $0 == UInt8(ascii: "?") }) ?? after.endIndex
            let afterAuthority = after[end...]
            let path = afterAuthority[..<(afterAuthority.firstIndex(of: UInt8(ascii: "?")) ?? afterAuthority.endIndex)]
            guard checkAuthority(after[..<end], https: scheme == "https") else {
                throw invalid(scheme == "http" ? "http is only allowed with a loopback host" : "invalid https host")
            }
            if path.isEmpty { throw invalid("must have a path") }
            guard checkSegments(path, strict: false) else { throw invalid("invalid path segment") }
            return scheme == "http" ? .loopback : .web
        case "file":
            if rest.contains(UInt8(ascii: "?")) { throw invalid("must not have a query") }
            var path = rest[...]
            if rest.starts(with: "//".utf8) {
                guard let slash = rest[2...].firstIndex(of: UInt8(ascii: "/")) else {
                    throw invalid("file URL needs an absolute path")
                }
                let host = lowercased(rest[2..<slash])
                guard host.isEmpty || host == "localhost" else { throw invalid("file URL host must be empty or localhost") }
                path = rest[slash...]
            } else if rest.first != UInt8(ascii: "/") {
                throw invalid("file URL needs an absolute path")
            }
            guard checkSegments(path, strict: false) else { throw invalid("invalid path segment") }
            return .file
        default:
            if rest.isEmpty { throw invalid("empty URL") }
            return .other
        }
    }

    // MARK: - The src DID URL parameter

    /// Validates a (percent-decoded) `src` DID URL parameter and derives the
    /// `srcLog` and `srcWitness` references from it (profile §3.2). Throws `invalidDidUrl`.
    public static func srcReferences(_ src: String) throws(DidVhError) -> (srcLog: String, srcWitness: String) {
        func invalid(_ why: String) -> DidVhError { DidVhError(.invalidDidUrl, "src \(src): \(why)") }
        guard let (scheme, rest) = splitScheme(src) else { throw invalid("not a printable-ASCII absolute URL") }
        if rest.contains(UInt8(ascii: "?")) || rest.contains(UInt8(ascii: "#")) {
            throw invalid("must not have a query or fragment")
        }
        if scheme == "http" || scheme == "file" { throw invalid("\(scheme) is not allowed in a DID URL") }
        guard rest.starts(with: "//".utf8), rest.count > 2, rest[2] != UInt8(ascii: "/") else {
            throw invalid("not a hierarchical URL with an authority")
        }
        let base = rest.last == UInt8(ascii: "/") ? rest.dropLast() : rest[...]
        if scheme == "https" {
            let after = base.dropFirst(2)
            let slash = after.firstIndex(of: UInt8(ascii: "/")) ?? after.endIndex
            guard checkAuthority(after[..<slash], https: true) else { throw invalid("invalid https host") }
            let path = after[slash...]
            if !path.isEmpty, !checkSegments(path, strict: true) { throw invalid("invalid path segment") }
        }
        let location = scheme + ":" + String(decoding: base, as: UTF8.self)
        return (location + "/did.jsonl", location + "/did-witness.json")
    }

    // MARK: - DID URLs

    /// A dereferenced did:vh DID URL.
    public struct DidURL: Sendable, Equatable {
        public var did: String
        /// Resolution options from the query, in order: `srcLog` and `srcWitness`
        /// (from `src`), `versionId`, `versionTime`, `versionNumber` (a number).
        public var options: JSONObject
        public var fragment: String?
    }

    private static let urlParameters = ["src", "versionId", "versionTime", "versionNumber"]
    private static let optionOnly = ["didLog", "didWitness", "srcLog", "srcWitness", "checkWatchers", "extraWatchers",
                                     "minCopies", "includeDidLog"]

    private static func containsBytes(_ list: [String], _ value: String) -> Bool {
        list.contains { $0.utf8.elementsEqual(value.utf8) }
    }

    /// Parses a did:vh DID URL as a dereferencer does (profile §4). Throws `invalidDidUrl`.
    public static func parseDidURL(_ didURL: String) throws(DidVhError) -> DidURL {
        func invalid(_ why: String) -> DidVhError { DidVhError(.invalidDidUrl, "\(didURL): \(why)") }
        let b = Array(didURL.utf8)
        let hash = b.firstIndex(of: UInt8(ascii: "#"))
        let beforeFragment = b[..<(hash ?? b.endIndex)]
        let fragment = hash.map { String(decoding: b[($0 + 1)...], as: UTF8.self) }
        let q = beforeFragment.firstIndex(of: UInt8(ascii: "?"))
        let did = String(decoding: beforeFragment[..<(q ?? beforeFragment.endIndex)], as: UTF8.self)
        guard parseDid(did) != nil else { throw invalid("not a did:vh DID") }
        var options = JSONObject()
        var seen: [String] = []
        if let q {
            for pair in beforeFragment[(q + 1)...].split(separator: UInt8(ascii: "&"), omittingEmptySubsequences: false) {
                guard let eq = pair.firstIndex(of: UInt8(ascii: "=")) else {
                    throw invalid("query parameter \(String(decoding: pair, as: UTF8.self)) has no value")
                }
                guard let key = percentDecode(String(decoding: pair[..<eq], as: UTF8.self)),
                    let value = percentDecode(String(decoding: pair[(eq + 1)...], as: UTF8.self))
                else { throw invalid("malformed percent-encoding") }
                if containsBytes(optionOnly, key) { throw invalid("\(key) is a resolution option, not a DID URL parameter") }
                guard containsBytes(urlParameters, key) else { continue }
                if containsBytes(seen, key) { throw invalid("\(key) given more than once") }
                seen.append(key)
                switch key {
                case "src":
                    let refs = try srcReferences(value)
                    options["srcLog"] = .string(refs.srcLog)
                    options["srcWitness"] = .string(refs.srcWitness)
                case "versionNumber":
                    let digits = Array(value.utf8)
                    guard digits.count <= 16, isDecimal(digits), digits != [UInt8(ascii: "0")] else {
                        throw invalid("versionNumber must be a positive integer")
                    }
                    options[key] = .number(Double(value)!)
                default:
                    options[key] = .string(value)
                }
            }
        }
        return DidURL(did: did, options: options, fragment: fragment)
    }

    // MARK: - Resolution

    /// The context of a did:vh resolver (profile §5).
    public struct ResolverContext: Sendable {
        /// The resolver's clock in `versionTime` format; `nil` means the current time.
        public var now: String?
        /// True for a resolver that accepts requests from other systems.
        public var remote: Bool

        public init(now: String? = nil, remote: Bool = false) {
            self.now = now
            self.remote = remote
        }
    }

    /// did:vh DID document metadata.
    public struct DocumentMetadata: Sendable {
        public var versionId: String
        public var versionTime: String
        public var created: String
        public var updated: String
        public var scid: String
        public var deactivated: Bool
        public var ttl: Int
        /// Only when witnesses are active.
        public var witness: WitnessConfig?
        public var watchers: [String]

        public var json: JSONValue {
            var o: JSONObject = [
                "versionId": .string(versionId), "versionTime": .string(versionTime), "created": .string(created),
                "updated": .string(updated), "scid": .string(scid), "deactivated": .bool(deactivated),
                "ttl": .number(Double(ttl)),
            ]
            if let witness { o["witness"] = witness.json }
            o["watchers"] = .array(watchers.map { .string($0) })
            return .object(o)
        }
    }

    /// The result of ``resolve(did:options:context:)``.
    public enum Resolution: Sendable {
        /// A resolved DID. `document` is `nil` for a deactivated DID; `didLog`
        /// and `didWitness` are set when `includeDidLog` is true.
        case resolved(document: JSONObject?, metadata: DocumentMetadata, warnings: [Warning], didLog: String?,
                      didWitness: JSONValue?)
        case failed(DidVhError)

        /// `{didResolutionMetadata, didDocument, didDocumentMetadata}`.
        public var json: JSONValue {
            switch self {
            case .failed(let e):
                var details: JSONObject = ["title": .string(e.code.rawValue), "detail": .string(e.message)]
                if let vhLog = e.vhLog { details["vhLog"] = vhLog.json }
                return [
                    "didResolutionMetadata": ["error": .string(e.code.rawValue), "problemDetails": .object(details)],
                    "didDocument": .null, "didDocumentMetadata": .object([:]),
                ]
            case .resolved(let document, let metadata, let warnings, let didLog, let didWitness):
                var meta: JSONObject = ["contentType": "application/did+json"]
                if !warnings.isEmpty { meta["warnings"] = .array(warnings.map(\.json)) }
                if let didLog { meta["didLog"] = .string(didLog) }
                if let didWitness { meta["didWitness"] = didWitness }
                return [
                    "didResolutionMetadata": .object(meta), "didDocument": document.map { .object($0) } ?? .null,
                    "didDocumentMetadata": metadata.json,
                ]
            }
        }
    }

    private static func isPositiveInteger(_ v: JSONValue?) -> Bool { (integerValue(v) ?? 0) >= 1 }

    /// did:vh Resolution Options validation (profile §5, step 2).
    private static func validateOptions(_ options: JSONValue, remote: Bool) throws(DidVhError) -> JSONObject {
        func invalid(_ why: String) -> DidVhError { DidVhError(.invalidOptions, why) }
        guard let o = options.objectValue else { throw invalid("resolution options must be an object") }
        if o.contains("didLog") == o.contains("srcLog") { throw invalid("exactly one of didLog and srcLog must be given") }
        if o.contains("didWitness") && o.contains("srcWitness") {
            throw invalid("at most one of didWitness and srcWitness may be given")
        }
        if let v = o["didLog"], v.stringValue == nil { throw invalid("didLog must be a string") }
        if let v = o["didWitness"], v.arrayValue == nil { throw invalid("didWitness must be an array") }
        for key in ["srcLog", "srcWitness"] {
            guard let v = o[key] else { continue }
            guard let ref = v.stringValue else { throw invalid("\(key) must be a string") }
            let kind = try checkRef(ref)
            if remote && (kind == .file || kind == .loopback) {
                throw invalid("\(key): a resolver that serves other systems must not use local file or loopback references")
            }
        }
        if ["versionId", "versionTime", "versionNumber"].filter(o.contains).count > 1 {
            throw invalid("at most one of versionId, versionTime and versionNumber may be given")
        }
        if let v = o["versionId"], v.stringValue == nil { throw invalid("versionId must be a string") }
        if let v = o["versionTime"], v.stringValue.flatMap(VersionTime.parse) == nil {
            throw invalid("versionTime must be a whole-second UTC ISO 8601 time")
        }
        if let v = o["versionNumber"], !isPositiveInteger(v) { throw invalid("versionNumber must be a positive integer") }
        if let c = o["checkWatchers"], !(c.stringValue.map { $0.utf8.elementsEqual("all".utf8) } ?? ((integerValue(c) ?? -1) >= 0)) {
            throw invalid(#"checkWatchers must be a non-negative integer or "all""#)
        }
        if let w = o["extraWatchers"] {
            let ok = w.arrayValue?.allSatisfy { u in
                u.stringValue.map { $0.utf8.starts(with: "https://".utf8) && isWatcherURL($0) } ?? false
            } ?? false
            if !ok { throw invalid("extraWatchers must be an array of https URLs") }
        }
        if let v = o["minCopies"], !isPositiveInteger(v) { throw invalid("minCopies must be a positive integer") }
        if let v = o["includeDidLog"], v.boolValue == nil { throw invalid("includeDidLog must be a boolean") }
        return o
    }

    private static func fromVHLog(_ e: VHLogError) -> DidVhError {
        let code: DidVhErrorCode = switch e.code {
        case .notFound: .notFound
        case .invalidOption: .invalidOptions
        case .forkDetected: .logForked
        case .minCopiesNotMet: .insufficientCopies
        case .unsupportedLogVersion: .featureNotSupported
        default: .invalidDid
        }
        return DidVhError(code, e.message, vhLog: e)
    }

    /// The current time in `versionTime` format.
    static func currentTime() -> String {
        var t = time(nil)
        var parts = tm()
        gmtime_r(&t, &parts)
        func pad(_ n: Int32, _ width: Int) -> String {
            let s = String(n)
            return String(repeating: "0", count: max(0, width - s.count)) + s
        }
        return "\(pad(parts.tm_year + 1900, 4))-\(pad(parts.tm_mon + 1, 2))-\(pad(parts.tm_mday, 2))T"
            + "\(pad(parts.tm_hour, 2)):\(pad(parts.tm_min, 2)):\(pad(parts.tm_sec, 2))Z"
    }

    /// did:vh `resolve(did, resolutionOptions)` (profile §5). This resolver is
    /// offline: it verifies a log passed in `didLog` (and `didWitness`), and
    /// returns `featureNotSupported` when it would have to retrieve anything.
    public static func resolve(did: String, options: JSONValue = .object([:]), context: ResolverContext = .init()) -> Resolution {
        do throws(DidVhError) {
            return try resolveThrowing(did: did, options: options, context: context)
        } catch {
            return .failed(error)
        }
    }

    private static func resolveThrowing(did: String, options: JSONValue, context: ResolverContext) throws(DidVhError) -> Resolution {
        guard let scid = parseDid(did) else { throw DidVhError(.invalidDid, "\(did) is not a did:vh DID") }
        let o = try validateOptions(options, remote: context.remote)
        if o.contains("srcLog") { throw DidVhError(.featureNotSupported, "this resolver does not retrieve srcLog references") }
        if (o["checkWatchers"].map { $0.numberValue != 0 } ?? false) || !(o["extraWatchers"]?.arrayValue ?? []).isEmpty {
            throw DidVhError(.featureNotSupported, "this resolver does not retrieve copies from watchers")
        }
        let spec = specialisation(expectedScid: scid)
        let now = context.now ?? currentTime()
        let log = o["didLog"]!.stringValue!
        let witness = o["didWitness"]
        // Whether the log needs witnessing does not depend on the witness file. Without
        // one, the first entry that needs it fails, which cuts it from `entries`.
        let clock = VersionTime.parse(now) ?? VersionTime.parse(currentTime())!
        let unwitnessed = verifyLog(log, witness: nil, now: clock, specialisation: spec)
        let witnessed = unwitnessed.failure?.code == .witnessThresholdNotMet
            || unwitnessed.entries.contains { $0.witnessRule != nil }
        if witnessed && o.contains("srcWitness") {
            throw DidVhError(.featureNotSupported, "this resolver does not retrieve srcWitness references")
        }
        let vhOptions = ResolveOptions(
            versionId: o["versionId"]?.stringValue, versionTime: o["versionTime"]?.stringValue,
            versionNumber: integerValue(o["versionNumber"]).map { Int(min($0, 9e15)) },
            minCopies: integerValue(o["minCopies"]).map { Int(min($0, 9e15)) })
        let result: VHLog.Resolution
        switch VHLog.resolve(ResolveInput(log: log, witness: witness, now: now, options: vhOptions, specialisation: spec)) {
        case .failed(let e): throw fromVHLog(e)
        case .resolved(let r): result = r
        }
        let selected = ["versionId", "versionTime", "versionNumber"].contains(where: o.contains)
        if !selected, let e = result.error, e.code == .unsupportedLogVersion {
            // Entries after the last valid one may change the document or its keys (profile §5).
            throw fromVHLog(e)
        }
        let m = result.metadata
        var didLog: String?
        var didWitness: JSONValue?
        if o["includeDidLog"]?.boolValue == true {
            let lines = parseLogLines(log)
            let valid = result.firstInvalidVersion.map { $0 - 1 } ?? lines.count
            didLog = lines[..<valid].map { $0 + "\n" }.joined()
            if witnessed { didWitness = witness ?? .array([]) }
        }
        let metadata = DocumentMetadata(
            versionId: m.versionId, versionTime: m.versionTime, created: m.created, updated: m.updated, scid: m.scid,
            deactivated: m.deactivated, ttl: m.ttl, witness: m.witness, watchers: m.watchers)
        // A deactivated DID's document is returned only for an explicit version selector (profile §5).
        return .resolved(document: m.deactivated && !selected ? nil : result.state.objectValue, metadata: metadata,
                         warnings: m.warnings, didLog: didLog, didWitness: didWitness)
    }
}
