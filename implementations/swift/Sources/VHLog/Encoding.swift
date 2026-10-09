import Crypto

/// Base58 (Bitcoin alphabet), without a multibase prefix.
public enum Base58 {
    static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)
    static let reverse: [Int8] = {
        var table = [Int8](repeating: -1, count: 256)
        for (i, c) in alphabet.enumerated() { table[Int(c)] = Int8(i) }
        return table
    }()

    /// Encodes bytes as base58btc.
    public static func encode<Bytes: Collection<UInt8>>(_ bytes: Bytes) -> String {
        let input = Array(bytes)
        var zeros = 0
        while zeros < input.count && input[zeros] == 0 { zeros += 1 }
        var digits: [UInt32] = []
        for byte in input[zeros...] {
            var carry = UInt32(byte)
            for j in digits.indices {
                carry += digits[j] << 8
                digits[j] = carry % 58
                carry /= 58
            }
            while carry > 0 {
                digits.append(carry % 58)
                carry /= 58
            }
        }
        var out = [UInt8](repeating: UInt8(ascii: "1"), count: zeros)
        for d in digits.reversed() { out.append(alphabet[Int(d)]) }
        return String(decoding: out, as: UTF8.self)
    }

    /// Decodes base58btc, or returns `nil` if `text` has a character outside the alphabet.
    public static func decode(_ text: String) -> [UInt8]? {
        let input = Array(text.utf8)
        var zeros = 0
        while zeros < input.count && input[zeros] == UInt8(ascii: "1") { zeros += 1 }
        var bytes: [UInt32] = []
        for c in input[zeros...] {
            let value = reverse[Int(c)]
            if value < 0 { return nil }
            var carry = UInt32(value)
            for j in bytes.indices {
                carry += bytes[j] * 58
                bytes[j] = carry & 0xFF
                carry >>= 8
            }
            while carry > 0 {
                bytes.append(carry & 0xFF)
                carry >>= 8
            }
        }
        return [UInt8](repeating: 0, count: zeros) + bytes.reversed().map { UInt8($0) }
    }
}

/// Hex encoding of byte strings.
public enum Hex {
    /// Decodes an even-length hex string (either case), or returns `nil`.
    public static func decode(_ text: String) -> [UInt8]? {
        let chars = Array(text.utf8)
        guard chars.count % 2 == 0 else { return nil }
        func nibble(_ c: UInt8) -> UInt8? {
            switch c {
            case UInt8(ascii: "0")...UInt8(ascii: "9"): c - UInt8(ascii: "0")
            case UInt8(ascii: "a")...UInt8(ascii: "f"): c - UInt8(ascii: "a") + 10
            case UInt8(ascii: "A")...UInt8(ascii: "F"): c - UInt8(ascii: "A") + 10
            default: nil
            }
        }
        var out: [UInt8] = []
        out.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let hi = nibble(chars[i]), let lo = nibble(chars[i + 1]) else { return nil }
            out.append(hi << 4 | lo)
            i += 2
        }
        return out
    }

    /// Lower-case hex.
    public static func encode<Bytes: Sequence<UInt8>>(_ bytes: Bytes) -> String {
        let digits = Array("0123456789abcdef".utf8)
        var out: [UInt8] = []
        for b in bytes {
            out.append(digits[Int(b >> 4)])
            out.append(digits[Int(b & 0xF)])
        }
        return String(decoding: out, as: UTF8.self)
    }
}

/// SHA-256 multihashes, the only hash `vh-log:1.0` permits (profile §1).
public enum Multihash {
    /// Multihash code for SHA-256.
    public static let sha256Code: UInt8 = 0x12
    /// SHA-256 digest length.
    public static let sha256Length: UInt8 = 32

    /// How a base58btc string relates to a SHA-256 multihash.
    public enum Check: Sendable, Equatable {
        /// A 34-byte SHA-256 multihash.
        case ok
        /// Not base58btc, or empty.
        case notBase58
        /// Valid base58btc but not a SHA-256 multihash.
        case unsupportedAlgorithm
    }

    /// Raw SHA-256 digest.
    public static func sha256<Bytes: Sequence<UInt8>>(_ data: Bytes) -> [UInt8] {
        var hasher = SHA256()
        hasher.update(data: Array(data))
        return Array(hasher.finalize())
    }

    /// `base58btc(0x12 0x20 ‖ SHA-256(data))` — SCIDs, entry hashes and key hashes.
    public static func hashB58<Bytes: Sequence<UInt8>>(_ data: Bytes) -> String {
        Base58.encode([sha256Code, sha256Length] + sha256(data))
    }

    /// `hashB58` of a string's UTF-8 bytes.
    public static func hashB58(_ text: String) -> String { hashB58(text.utf8) }

    /// Classifies a base58btc string.
    public static func check(_ value: String) -> Check {
        guard let bytes = Base58.decode(value), !bytes.isEmpty else { return .notBase58 }
        guard bytes.count == 34, bytes[0] == sha256Code, bytes[1] == sha256Length else { return .unsupportedAlgorithm }
        return .ok
    }

    /// Pre-rotation key hash: the multikey *string* is hashed.
    public static func keyHash(_ multikey: String) -> String { hashB58(multikey) }
}

/// Ed25519 multikeys (`"z" + base58btc(0xed 0x01 ‖ pubkey)`).
public enum Multikey {
    static let ed25519Prefix: [UInt8] = [0xED, 0x01]

    /// Encodes a 32-byte Ed25519 public key.
    public static func encode(ed25519PublicKey key: [UInt8]) -> String {
        "z" + Base58.encode(ed25519Prefix + key)
    }

    /// The raw public key, or `nil` if `multikey` isn't an Ed25519 multikey.
    public static func ed25519PublicKey(_ multikey: String) -> [UInt8]? {
        guard multikey.utf8.first == UInt8(ascii: "z") else { return nil }
        guard let bytes = Base58.decode(String(multikey.utf8.dropFirst())!),
            bytes.count == 34, bytes[0] == 0xED, bytes[1] == 0x01
        else { return nil }
        return Array(bytes[2...])
    }

    /// `did:key:<mk>#<mk>`.
    public static func verificationMethod(_ multikey: String) -> String { "did:key:\(multikey)#\(multikey)" }

    /// The multikey named by a `did:key:<mk>#<mk>` verification method, or `nil`
    /// if the value isn't in that form or `<mk>` isn't an Ed25519 multikey.
    public static func fromVerificationMethod(_ vm: String) -> String? {
        let bytes = Array(vm.utf8)
        let prefix = Array("did:key:".utf8)
        guard bytes.count > prefix.count, bytes.starts(with: prefix) else { return nil }
        let rest = bytes[prefix.count...]
        guard let hash = rest.firstIndex(of: UInt8(ascii: "#")) else { return nil }
        let a = rest[..<hash], b = rest[(hash + 1)...]
        guard !a.isEmpty, a.elementsEqual(b) else { return nil }
        let mk = String(decoding: a, as: UTF8.self)
        return ed25519PublicKey(mk) == nil ? nil : mk
    }
}
