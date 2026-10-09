import Crypto
import VHLog

/// A deterministic RFC 8032 Ed25519 signer, for interop tests only.
///
/// > Important: This is an **unaudited** port of TweetNaCl's field and scalar
/// > arithmetic. It makes no constant-time guarantees beyond TweetNaCl's
/// > branch-free structure and must not be used to protect real keys.
///
/// It exists because the library's default ``VHLog/Ed25519Signer`` signs with
/// CryptoKit on Apple platforms, which produces *randomised* (still valid)
/// Ed25519 signatures. The interop vectors compare generated log lines and
/// proofs byte for byte, so the test suite and the `vh-log-driver` executable
/// inject this signer instead. It is not part of any library product.
public struct DeterministicEd25519Signer: VHLogSigner {
    /// The raw 32-byte public key.
    public let publicKey: [UInt8]
    private let scalar: [UInt8]
    private let prefix: [UInt8]

    /// Creates a signer from a 32-byte seed (RFC 8032 §5.1.5).
    public init(seed: [UInt8]) throws(VHLogInputError) {
        guard seed.count == 32 else { throw .invalidSeed("Ed25519 seed must be 32 bytes") }
        var d = Array(SHA512.hash(data: seed))
        d[0] &= 248
        d[31] &= 127
        d[31] |= 64
        scalar = Array(d[0..<32])
        prefix = Array(d[32..<64])
        publicKey = Ed25519Math.packPoint(Ed25519Math.scalarBase(scalar))
    }

    /// Creates a signer from a hex-encoded 32-byte seed.
    public init(seedHex: String) throws(VHLogInputError) {
        guard let seed = Hex.decode(seedHex) else { throw .invalidSeed("seed is not hex: \(seedHex)") }
        try self.init(seed: seed)
    }

    /// The Ed25519 multikey of ``publicKey``.
    public var multikey: String { Multikey.encode(ed25519PublicKey: publicKey) }

    /// A deterministic 64-byte RFC 8032 signature.
    public func sign(_ message: [UInt8]) -> [UInt8] {
        let r = Ed25519Math.reduce(Array(SHA512.hash(data: prefix + message)))
        let R = Ed25519Math.packPoint(Ed25519Math.scalarBase(r))
        let h = Ed25519Math.reduce(Array(SHA512.hash(data: R + publicKey + message)))
        var x = [Int64](repeating: 0, count: 64)
        for i in 0..<32 { x[i] = Int64(r[i]) }
        for i in 0..<32 {
            for j in 0..<32 { x[i + j] += Int64(h[i]) * Int64(scalar[j]) }
        }
        return R + Ed25519Math.modL(&x)
    }
}

/// GF(2^255-19) and scalar arithmetic in TweetNaCl's 16 × 16-bit limb representation.
enum Ed25519Math {
    typealias FE = [Int64]
    typealias Point = [FE]

    static let gf0: FE = .init(repeating: 0, count: 16)
    static let gf1: FE = [1] + .init(repeating: 0, count: 15)
    static let d2: FE = [0xF159, 0x26B2, 0x9B94, 0xEBD6, 0xB156, 0x8283, 0x149A, 0x00E0,
                         0xD130, 0xEEF3, 0x80F2, 0x198E, 0xFCE7, 0x56DF, 0xD9DC, 0x2406]
    static let baseX: FE = [0xD51A, 0x8F25, 0x2D60, 0xC956, 0xA7B2, 0x9525, 0xC760, 0x692C,
                            0xDC5C, 0xFDD6, 0xE231, 0xC0A4, 0x53FE, 0xCD6E, 0x36D3, 0x2169]
    static let baseY: FE = [0x6658] + .init(repeating: 0x6666, count: 15)
    static let L: [Int64] = [0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]

    static func carry(_ o: inout FE) {
        for i in 0..<16 {
            o[i] += 1 << 16
            let c = o[i] >> 16
            if i < 15 { o[i + 1] += c - 1 } else { o[0] += 38 * (c - 1) }
            o[i] -= c << 16
        }
    }

    static func select(_ p: inout FE, _ q: inout FE, _ b: Int64) {
        let c = ~(b - 1)
        for i in 0..<16 {
            let t = c & (p[i] ^ q[i])
            p[i] ^= t
            q[i] ^= t
        }
    }

    static func pack(_ n: FE) -> [UInt8] {
        var t = n
        carry(&t); carry(&t); carry(&t)
        var m = gf0
        for _ in 0..<2 {
            m[0] = t[0] - 0xFFED
            for i in 1..<15 {
                m[i] = t[i] - 0xFFFF - ((m[i - 1] >> 16) & 1)
                m[i - 1] &= 0xFFFF
            }
            m[15] = t[15] - 0x7FFF - ((m[14] >> 16) & 1)
            let b = (m[15] >> 16) & 1
            m[14] &= 0xFFFF
            select(&t, &m, 1 - b)
        }
        var out = [UInt8](repeating: 0, count: 32)
        for i in 0..<16 {
            out[2 * i] = UInt8(t[i] & 0xFF)
            out[2 * i + 1] = UInt8((t[i] >> 8) & 0xFF)
        }
        return out
    }

    static func add(_ a: FE, _ b: FE) -> FE { (0..<16).map { a[$0] + b[$0] } }
    static func sub(_ a: FE, _ b: FE) -> FE { (0..<16).map { a[$0] - b[$0] } }

    static func mul(_ a: FE, _ b: FE) -> FE {
        var t = [Int64](repeating: 0, count: 31)
        for i in 0..<16 {
            for j in 0..<16 { t[i + j] += a[i] * b[j] }
        }
        for i in 0..<15 { t[i] += 38 * t[i + 16] }
        var o = Array(t[0..<16])
        carry(&o)
        carry(&o)
        return o
    }

    static func invert(_ i: FE) -> FE {
        var c = i
        for a in stride(from: 253, through: 0, by: -1) {
            c = mul(c, c)
            if a != 2 && a != 4 { c = mul(c, i) }
        }
        return c
    }

    static func addPoints(_ p: inout Point, _ q: Point) {
        let a = mul(sub(p[1], p[0]), sub(q[1], q[0]))
        let b = mul(add(p[0], p[1]), add(q[0], q[1]))
        let c = mul(mul(p[3], q[3]), d2)
        var d = mul(p[2], q[2])
        d = add(d, d)
        let e = sub(b, a), f = sub(d, c), g = add(d, c), h = add(b, a)
        p[0] = mul(e, f)
        p[1] = mul(h, g)
        p[2] = mul(g, f)
        p[3] = mul(e, h)
    }

    static func swap(_ p: inout Point, _ q: inout Point, _ b: Int64) {
        for i in 0..<4 { select(&p[i], &q[i], b) }
    }

    static func scalarBase(_ s: [UInt8]) -> Point {
        var q: Point = [baseX, baseY, gf1, mul(baseX, baseY)]
        var p: Point = [gf0, gf1, gf1, gf0]
        for i in stride(from: 255, through: 0, by: -1) {
            let b = Int64((s[i / 8] >> (i & 7)) & 1)
            swap(&p, &q, b)
            addPoints(&q, p)
            let copy = p
            addPoints(&p, copy)
            swap(&p, &q, b)
        }
        return p
    }

    static func packPoint(_ p: Point) -> [UInt8] {
        let zi = invert(p[2])
        let tx = mul(p[0], zi), ty = mul(p[1], zi)
        var r = pack(ty)
        r[31] ^= (pack(tx)[0] & 1) << 7
        return r
    }

    /// Reduces a 64-limb little-endian number modulo the group order L.
    static func modL(_ x: inout [Int64]) -> [UInt8] {
        for i in stride(from: 63, through: 32, by: -1) {
            var carry: Int64 = 0
            var j = i - 32
            while j < i - 12 {
                x[j] += carry - 16 * x[i] * L[j - (i - 32)]
                carry = (x[j] + 128) >> 8
                x[j] -= carry << 8
                j += 1
            }
            x[j] += carry
            x[i] = 0
        }
        var carry: Int64 = 0
        for j in 0..<32 {
            x[j] += carry - (x[31] >> 4) * L[j]
            carry = x[j] >> 8
            x[j] &= 255
        }
        for j in 0..<32 { x[j] -= carry * L[j] }
        var r = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 {
            x[i + 1] += x[i] >> 8
            r[i] = UInt8(x[i] & 255)
        }
        return r
    }

    /// Reduces a 64-byte little-endian hash modulo L.
    static func reduce(_ bytes: [UInt8]) -> [UInt8] {
        var x = bytes.map { Int64($0) }
        return modL(&x)
    }
}
