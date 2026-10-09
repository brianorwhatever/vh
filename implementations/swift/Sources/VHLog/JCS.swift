/// RFC 8785 JSON Canonicalization Scheme.
public enum JCS {
    /// Canonicalises a value: members sorted by UTF-16 code units, no
    /// whitespace, ECMAScript number formatting, minimal string escaping.
    ///
    /// - Throws: ``JSONSerializationError/nonFiniteNumber`` for NaN or infinity.
    public static func canonicalize(_ value: JSONValue) throws(JSONSerializationError) -> String {
        String(decoding: try canonicalBytes(value), as: UTF8.self)
    }

    /// The UTF-8 bytes of ``canonicalize(_:)``.
    public static func canonicalBytes(_ value: JSONValue) throws(JSONSerializationError) -> [UInt8] {
        var out: [UInt8] = []
        try value.write(to: &out, sorted: true)
        return out
    }

    /// Parses JSON text (as ``JSONValue/parse(_:)``) and canonicalises it.
    public static func canonicalize(text: String) throws -> String {
        try canonicalize(JSONValue.parse(text))
    }
}

/// Formats a finite double as ECMAScript `Number::toString` does (ECMA-262
/// §6.1.6.1.20), which is what RFC 8785 requires.
///
/// Swift's `description` already yields the shortest round-tripping digits
/// (closest to the exact value when there is a choice), so only the notation
/// is rewritten here.
public func formatECMAScriptNumber(_ value: Double) -> String {
    if value.isNaN { return "NaN" }
    if value == 0 { return "0" }
    if value.isInfinite { return value < 0 ? "-Infinity" : "Infinity" }
    if value < 0 { return "-" + formatECMAScriptNumber(-value) }

    // Split Swift's description ("1.2345e-07", "100.0", "5e-324") into digits and exponent.
    let text = value.description
    var mantissa = Substring(text)
    var exponent = 0
    if let e = text.firstIndex(where: { $0 == "e" || $0 == "E" }) {
        mantissa = text[..<e]
        exponent = Int(text[text.index(after: e)...])!
    }
    var digits: [UInt8] = []
    var pointPosition = -1
    for c in mantissa.utf8 {
        if c == UInt8(ascii: ".") { pointPosition = digits.count } else { digits.append(c) }
    }
    if pointPosition < 0 { pointPosition = digits.count }
    // value = 0.d1d2d3… × 10^n
    var n = pointPosition + exponent
    while let first = digits.first, first == UInt8(ascii: "0") {
        digits.removeFirst()
        n -= 1
    }
    while let last = digits.last, last == UInt8(ascii: "0") { digits.removeLast() }
    let k = digits.count
    let s = String(decoding: digits, as: UTF8.self)

    if k <= n && n <= 21 {
        return s + String(repeating: "0", count: n - k)
    }
    if 0 < n && n <= 21 {
        let i = s.index(s.startIndex, offsetBy: n)
        return s[..<i] + "." + s[i...]
    }
    if -6 < n && n <= 0 {
        return "0." + String(repeating: "0", count: -n) + s
    }
    let e = n - 1
    let expText = (e < 0 ? "-" : "+") + String(abs(e))
    if k == 1 { return s + "e" + expText }
    return s.prefix(1) + "." + s.dropFirst() + "e" + expText
}
