/// A JSON value with the data model RFC 8785 and ECMAScript use: every number
/// is an IEEE-754 double, and object members keep their insertion order.
///
/// Strings and object keys are compared by their exact Unicode scalars (UTF-8
/// bytes), never by Swift's canonical-equivalence `String ==`, so `"é"` (U+00E9)
/// and `"e\u{301}"` are different keys, as they are in JSON.
public enum JSONValue: Sendable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object(JSONObject)
}

/// An insertion-ordered JSON object whose keys are unique by exact code units.
///
/// Setting an existing key replaces its value in place, which matches
/// ECMAScript property semantics (and `JSON.parse`'s "last duplicate wins,
/// first position kept").
public struct JSONObject: Sendable {
    /// One object member.
    public struct Member: Sendable {
        public var key: String
        public var value: JSONValue
        public init(key: String, value: JSONValue) {
            self.key = key
            self.value = value
        }
    }

    /// Members in insertion order.
    public private(set) var members: [Member] = []

    /// Creates an empty object.
    public init() {}

    /// Creates an object from key/value pairs; later duplicates replace earlier ones.
    public init(_ pairs: [(String, JSONValue)]) {
        for (k, v) in pairs { self[k] = v }
    }

    /// The number of members.
    public var count: Int { members.count }
    /// Whether the object has no members.
    public var isEmpty: Bool { members.isEmpty }
    /// The keys, in insertion order.
    public var keys: [String] { members.map(\.key) }

    func index(of key: String) -> Int? {
        members.firstIndex { $0.key.utf8.elementsEqual(key.utf8) }
    }

    /// Whether `key` is present (exact code-unit comparison).
    public func contains(_ key: String) -> Bool { index(of: key) != nil }

    /// Gets, sets (in place or appended) or, with `nil`, removes a member.
    public subscript(key: String) -> JSONValue? {
        get { index(of: key).map { members[$0].value } }
        set {
            if let i = index(of: key) {
                if let newValue { members[i].value = newValue } else { members.remove(at: i) }
            } else if let newValue {
                members.append(Member(key: key, value: newValue))
            }
        }
    }

    /// A copy without `key`.
    public func removing(_ key: String) -> JSONObject {
        var copy = self
        copy[key] = nil
        return copy
    }

    /// A copy with `key` set to `value`.
    public func setting(_ key: String, _ value: JSONValue) -> JSONObject {
        var copy = self
        copy[key] = value
        return copy
    }

    mutating func appendUnchecked(_ key: String, _ value: JSONValue) {
        members.append(Member(key: key, value: value))
    }

    mutating func replaceValue(at index: Int, with value: JSONValue) {
        members[index].value = value
    }
}

extension JSONObject: ExpressibleByDictionaryLiteral {
    public init(dictionaryLiteral elements: (String, JSONValue)...) {
        self.init(elements)
    }
}

extension JSONValue: ExpressibleByBooleanLiteral, ExpressibleByIntegerLiteral,
    ExpressibleByFloatLiteral, ExpressibleByStringLiteral, ExpressibleByArrayLiteral, ExpressibleByDictionaryLiteral
{
    public init(booleanLiteral value: Bool) { self = .bool(value) }
    public init(integerLiteral value: Int) { self = .number(Double(value)) }
    public init(floatLiteral value: Double) { self = .number(value) }
    public init(stringLiteral value: String) { self = .string(value) }
    public init(arrayLiteral elements: JSONValue...) { self = .array(elements) }
    public init(dictionaryLiteral elements: (String, JSONValue)...) { self = .object(JSONObject(elements)) }
}

extension JSONValue {
    /// The string, if this is a string.
    public var stringValue: String? { if case .string(let s) = self { s } else { nil } }
    /// The number, if this is a number.
    public var numberValue: Double? { if case .number(let n) = self { n } else { nil } }
    /// The Boolean, if this is a Boolean.
    public var boolValue: Bool? { if case .bool(let b) = self { b } else { nil } }
    /// The elements, if this is an array.
    public var arrayValue: [JSONValue]? { if case .array(let a) = self { a } else { nil } }
    /// The object, if this is an object.
    public var objectValue: JSONObject? { if case .object(let o) = self { o } else { nil } }
    /// Whether this is `null`.
    public var isNull: Bool { if case .null = self { true } else { false } }

    /// Member lookup when this is an object; `nil` otherwise.
    public subscript(key: String) -> JSONValue? { objectValue?[key] }

    /// An array of strings, if this is an array whose elements are all strings.
    public var stringArrayValue: [String]? {
        guard let a = arrayValue else { return nil }
        var out: [String] = []
        out.reserveCapacity(a.count)
        for v in a {
            guard let s = v.stringValue else { return nil }
            out.append(s)
        }
        return out
    }
}

extension JSONValue: Equatable {
    /// Semantic equality: numbers by value, strings and keys by exact code
    /// units, objects regardless of member order.
    public static func == (a: JSONValue, b: JSONValue) -> Bool {
        switch (a, b) {
        case (.null, .null): return true
        case (.bool(let x), .bool(let y)): return x == y
        case (.number(let x), .number(let y)): return x == y
        case (.string(let x), .string(let y)): return x.utf8.elementsEqual(y.utf8)
        case (.array(let x), .array(let y)): return x == y
        case (.object(let x), .object(let y)):
            guard x.count == y.count else { return false }
            for m in x.members {
                guard let other = y[m.key], other == m.value else { return false }
            }
            return true
        default: return false
        }
    }
}

extension JSONObject: Equatable {
    public static func == (a: JSONObject, b: JSONObject) -> Bool { JSONValue.object(a) == .object(b) }
}

// MARK: - Parsing

/// Why JSON text could not be parsed.
public enum JSONParseError: Error, Sendable, Equatable {
    /// The text is not valid JSON; `offset` is the UTF-8 byte offset.
    case syntax(offset: Int, message: String)
    /// A string or key contains a `\uD800`-style escape that is not part of a surrogate pair.
    case loneSurrogate(offset: Int)
}

extension JSONValue {
    /// Parses JSON text the way ECMAScript `JSON.parse` does: numbers become
    /// doubles (`1e400` becomes infinity, so callers that need I-JSON must check
    /// ``isIJSONSafe``), and duplicate keys keep the last value. Strings that
    /// would contain a lone surrogate throw ``JSONParseError/loneSurrogate(offset:)``
    /// because Swift strings can't represent them.
    ///
    /// With `replacingLoneSurrogates`, a lone surrogate becomes U+FFFD instead
    /// of throwing (used only to read a `versionId` out of an invalid line).
    public static func parse(_ text: String, replacingLoneSurrogates: Bool = false) throws(JSONParseError) -> JSONValue {
        try parse(utf8: Array(text.utf8), replacingLoneSurrogates: replacingLoneSurrogates)
    }

    /// Parses UTF-8 JSON bytes. See ``parse(_:replacingLoneSurrogates:)``.
    public static func parse(utf8 bytes: [UInt8], replacingLoneSurrogates: Bool = false) throws(JSONParseError) -> JSONValue {
        // The closure returns a Result so this doesn't rely on typed-throws
        // overloads of withUnsafeBufferPointer (absent from older toolchains).
        let result = bytes.withUnsafeBufferPointer { buffer -> Result<JSONValue, JSONParseError> in
            var parser = JSONParser(bytes: buffer)
            parser.replaceLoneSurrogates = replacingLoneSurrogates
            do throws(JSONParseError) {
                parser.skipWhitespace()
                let value = try parser.parseValue(depth: 0)
                parser.skipWhitespace()
                if parser.pos != buffer.count { throw parser.error("unexpected trailing data") }
                return .success(value)
            } catch {
                return .failure(error)
            }
        }
        return try result.get()
    }

    /// I-JSON safety (profile §4): every number is finite. (Lone surrogates
    /// can't occur in a parsed value; the parser rejects them.)
    public var isIJSONSafe: Bool {
        switch self {
        case .number(let n): return n.isFinite
        case .array(let a): return a.allSatisfy(\.isIJSONSafe)
        case .object(let o): return o.members.allSatisfy { $0.value.isIJSONSafe }
        default: return true
        }
    }
}

private struct JSONParser {
    let bytes: UnsafeBufferPointer<UInt8>
    var pos = 0
    var replaceLoneSurrogates = false
    static let maxDepth = 512

    init(bytes: UnsafeBufferPointer<UInt8>) { self.bytes = bytes }

    func error(_ message: String) -> JSONParseError { .syntax(offset: pos, message: message) }

    mutating func skipWhitespace() {
        while pos < bytes.count {
            switch bytes[pos] {
            case 0x20, 0x09, 0x0A, 0x0D: pos += 1
            default: return
            }
        }
    }

    mutating func expectLiteral(_ literal: StaticString) throws(JSONParseError) {
        let n = literal.utf8CodeUnitCount
        guard pos + n <= bytes.count else { throw error("invalid literal") }
        let p = literal.utf8Start
        for i in 0..<n where bytes[pos + i] != p[i] { throw error("invalid literal") }
        pos += n
    }

    mutating func parseValue(depth: Int) throws(JSONParseError) -> JSONValue {
        guard depth < Self.maxDepth else { throw error("nesting too deep") }
        guard pos < bytes.count else { throw error("unexpected end of input") }
        switch bytes[pos] {
        case UInt8(ascii: "{"): return try parseObject(depth: depth)
        case UInt8(ascii: "["): return try parseArray(depth: depth)
        case UInt8(ascii: "\""): return .string(try parseString())
        case UInt8(ascii: "t"): try expectLiteral("true"); return .bool(true)
        case UInt8(ascii: "f"): try expectLiteral("false"); return .bool(false)
        case UInt8(ascii: "n"): try expectLiteral("null"); return .null
        case UInt8(ascii: "-"), UInt8(ascii: "0")...UInt8(ascii: "9"): return .number(try parseNumber())
        default: throw error("unexpected character")
        }
    }

    mutating func parseObject(depth: Int) throws(JSONParseError) -> JSONValue {
        pos += 1
        var object = JSONObject()
        var index: [[UInt8]: Int] = [:]
        skipWhitespace()
        if pos < bytes.count, bytes[pos] == UInt8(ascii: "}") {
            pos += 1
            return .object(object)
        }
        while true {
            skipWhitespace()
            guard pos < bytes.count, bytes[pos] == UInt8(ascii: "\"") else { throw error("expected key") }
            let key = try parseString()
            skipWhitespace()
            guard pos < bytes.count, bytes[pos] == UInt8(ascii: ":") else { throw error("expected ':'") }
            pos += 1
            skipWhitespace()
            let value = try parseValue(depth: depth + 1)
            let keyBytes = Array(key.utf8)
            if let i = index[keyBytes] {
                object.replaceValue(at: i, with: value)
            } else {
                index[keyBytes] = object.count
                object.appendUnchecked(key, value)
            }
            skipWhitespace()
            guard pos < bytes.count else { throw error("unterminated object") }
            if bytes[pos] == UInt8(ascii: ",") { pos += 1; continue }
            if bytes[pos] == UInt8(ascii: "}") { pos += 1; return .object(object) }
            throw error("expected ',' or '}'")
        }
    }

    mutating func parseArray(depth: Int) throws(JSONParseError) -> JSONValue {
        pos += 1
        var array: [JSONValue] = []
        skipWhitespace()
        if pos < bytes.count, bytes[pos] == UInt8(ascii: "]") {
            pos += 1
            return .array(array)
        }
        while true {
            skipWhitespace()
            array.append(try parseValue(depth: depth + 1))
            skipWhitespace()
            guard pos < bytes.count else { throw error("unterminated array") }
            if bytes[pos] == UInt8(ascii: ",") { pos += 1; continue }
            if bytes[pos] == UInt8(ascii: "]") { pos += 1; return .array(array) }
            throw error("expected ',' or ']'")
        }
    }

    mutating func hex4() throws(JSONParseError) -> UInt32 {
        guard pos + 4 <= bytes.count else { throw error("truncated \\u escape") }
        var v: UInt32 = 0
        for _ in 0..<4 {
            let c = bytes[pos]
            let d: UInt32
            switch c {
            case UInt8(ascii: "0")...UInt8(ascii: "9"): d = UInt32(c - UInt8(ascii: "0"))
            case UInt8(ascii: "a")...UInt8(ascii: "f"): d = UInt32(c - UInt8(ascii: "a") + 10)
            case UInt8(ascii: "A")...UInt8(ascii: "F"): d = UInt32(c - UInt8(ascii: "A") + 10)
            default: throw error("invalid \\u escape")
            }
            v = v << 4 | d
            pos += 1
        }
        return v
    }

    mutating func parseString() throws(JSONParseError) -> String {
        pos += 1
        var out: [UInt8] = []
        while true {
            guard pos < bytes.count else { throw error("unterminated string") }
            let c = bytes[pos]
            if c == UInt8(ascii: "\"") {
                pos += 1
                break
            }
            if c < 0x20 { throw error("control character in string") }
            if c != UInt8(ascii: "\\") {
                out.append(c)
                pos += 1
                continue
            }
            let escapeStart = pos
            pos += 1
            guard pos < bytes.count else { throw error("unterminated escape") }
            let e = bytes[pos]
            pos += 1
            switch e {
            case UInt8(ascii: "\""): out.append(0x22)
            case UInt8(ascii: "\\"): out.append(0x5C)
            case UInt8(ascii: "/"): out.append(0x2F)
            case UInt8(ascii: "b"): out.append(0x08)
            case UInt8(ascii: "f"): out.append(0x0C)
            case UInt8(ascii: "n"): out.append(0x0A)
            case UInt8(ascii: "r"): out.append(0x0D)
            case UInt8(ascii: "t"): out.append(0x09)
            case UInt8(ascii: "u"):
                var scalar = try hex4()
                if (0xD800...0xDBFF).contains(scalar) {
                    // A high surrogate must be followed by an escaped low surrogate.
                    var low: UInt32 = 0
                    if pos + 6 <= bytes.count, bytes[pos] == UInt8(ascii: "\\"), bytes[pos + 1] == UInt8(ascii: "u") {
                        let save = pos
                        pos += 2
                        low = try hex4()
                        if !(0xDC00...0xDFFF).contains(low) { pos = save }
                    }
                    if (0xDC00...0xDFFF).contains(low) {
                        scalar = 0x10000 + ((scalar - 0xD800) << 10) + (low - 0xDC00)
                    } else if replaceLoneSurrogates {
                        scalar = 0xFFFD
                    } else {
                        throw JSONParseError.loneSurrogate(offset: escapeStart)
                    }
                } else if (0xDC00...0xDFFF).contains(scalar) {
                    if !replaceLoneSurrogates { throw JSONParseError.loneSurrogate(offset: escapeStart) }
                    scalar = 0xFFFD
                }
                appendUTF8(scalar, to: &out)
            default:
                throw error("invalid escape")
            }
        }
        return String(decoding: out, as: UTF8.self)
    }

    mutating func parseNumber() throws(JSONParseError) -> Double {
        let start = pos
        func isDigit(_ c: UInt8) -> Bool { c >= 0x30 && c <= 0x39 }
        if bytes[pos] == UInt8(ascii: "-") { pos += 1 }
        guard pos < bytes.count, isDigit(bytes[pos]) else { throw error("invalid number") }
        if bytes[pos] == UInt8(ascii: "0") {
            pos += 1
        } else {
            while pos < bytes.count, isDigit(bytes[pos]) { pos += 1 }
        }
        if pos < bytes.count, bytes[pos] == UInt8(ascii: ".") {
            pos += 1
            guard pos < bytes.count, isDigit(bytes[pos]) else { throw error("invalid number") }
            while pos < bytes.count, isDigit(bytes[pos]) { pos += 1 }
        }
        if pos < bytes.count, bytes[pos] == UInt8(ascii: "e") || bytes[pos] == UInt8(ascii: "E") {
            pos += 1
            if pos < bytes.count, bytes[pos] == UInt8(ascii: "+") || bytes[pos] == UInt8(ascii: "-") { pos += 1 }
            guard pos < bytes.count, isDigit(bytes[pos]) else { throw error("invalid number") }
            while pos < bytes.count, isDigit(bytes[pos]) { pos += 1 }
        }
        let text = String(decoding: UnsafeBufferPointer(rebasing: bytes[start..<pos]), as: UTF8.self)
        // Swift's Double(String) is correctly rounded and yields ±infinity on overflow.
        guard let value = Double(text) else { throw error("invalid number") }
        return value
    }
}

@inline(__always)
func appendUTF8(_ scalar: UInt32, to out: inout [UInt8]) {
    switch scalar {
    case 0..<0x80:
        out.append(UInt8(scalar))
    case 0x80..<0x800:
        out.append(UInt8(0xC0 | scalar >> 6))
        out.append(UInt8(0x80 | scalar & 0x3F))
    case 0x800..<0x10000:
        out.append(UInt8(0xE0 | scalar >> 12))
        out.append(UInt8(0x80 | scalar >> 6 & 0x3F))
        out.append(UInt8(0x80 | scalar & 0x3F))
    default:
        out.append(UInt8(0xF0 | scalar >> 18))
        out.append(UInt8(0x80 | scalar >> 12 & 0x3F))
        out.append(UInt8(0x80 | scalar >> 6 & 0x3F))
        out.append(UInt8(0x80 | scalar & 0x3F))
    }
}

// MARK: - Serialising

extension JSONParseError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .syntax(let offset, let message): "invalid JSON at byte \(offset): \(message)"
        case .loneSurrogate(let offset): "lone surrogate escape at byte \(offset)"
        }
    }
}

/// Why a value could not be serialised.
public enum JSONSerializationError: Error, Sendable, Equatable, CustomStringConvertible {
    /// RFC 8785 and JSON have no representation for NaN or infinity.
    case nonFiniteNumber

    public var description: String { "JSON has no representation for a non-finite number" }
}

extension JSONValue {
    /// Compact JSON in member insertion order, with `JSON.stringify` string
    /// escaping and ECMAScript number formatting.
    public func serialized() throws(JSONSerializationError) -> String {
        var out: [UInt8] = []
        try write(to: &out, sorted: false)
        return String(decoding: out, as: UTF8.self)
    }

    func write(to out: inout [UInt8], sorted: Bool) throws(JSONSerializationError) {
        switch self {
        case .null: out.append(contentsOf: "null".utf8)
        case .bool(let b): out.append(contentsOf: (b ? "true" : "false").utf8)
        case .number(let n):
            guard n.isFinite else { throw .nonFiniteNumber }
            out.append(contentsOf: formatECMAScriptNumber(n).utf8)
        case .string(let s): writeJSONString(s, to: &out)
        case .array(let a):
            out.append(UInt8(ascii: "["))
            for (i, v) in a.enumerated() {
                if i > 0 { out.append(UInt8(ascii: ",")) }
                try v.write(to: &out, sorted: sorted)
            }
            out.append(UInt8(ascii: "]"))
        case .object(let o):
            out.append(UInt8(ascii: "{"))
            var members = o.members
            if sorted {
                // RFC 8785 §3.2.3: sort by UTF-16 code units.
                members.sort { $0.key.utf16.lexicographicallyPrecedes($1.key.utf16) }
            }
            for (i, m) in members.enumerated() {
                if i > 0 { out.append(UInt8(ascii: ",")) }
                writeJSONString(m.key, to: &out)
                out.append(UInt8(ascii: ":"))
                try m.value.write(to: &out, sorted: sorted)
            }
            out.append(UInt8(ascii: "}"))
        }
    }
}

/// `JSON.stringify` / RFC 8785 string escaping.
func writeJSONString(_ s: String, to out: inout [UInt8]) {
    let hex = Array("0123456789abcdef".utf8)
    out.append(0x22)
    for c in s.utf8 {
        switch c {
        case 0x22: out.append(0x5C); out.append(0x22)
        case 0x5C: out.append(0x5C); out.append(0x5C)
        case 0x08: out.append(0x5C); out.append(UInt8(ascii: "b"))
        case 0x0C: out.append(0x5C); out.append(UInt8(ascii: "f"))
        case 0x0A: out.append(0x5C); out.append(UInt8(ascii: "n"))
        case 0x0D: out.append(0x5C); out.append(UInt8(ascii: "r"))
        case 0x09: out.append(0x5C); out.append(UInt8(ascii: "t"))
        case 0..<0x20:
            out.append(contentsOf: [0x5C, UInt8(ascii: "u"), 0x30, 0x30, hex[Int(c >> 4)], hex[Int(c & 0xF)]])
        default: out.append(c)
        }
    }
    out.append(0x22)
}
