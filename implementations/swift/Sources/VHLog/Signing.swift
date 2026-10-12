import Crypto

/// Something that signs `eddsa-jcs-2022` proofs with an Ed25519 key.
///
/// The library's default is ``Ed25519Signer`` (swift-crypto, which is
/// CryptoKit on Apple platforms). Conform your own type to use an HSM or a
/// remote signer.
public protocol VHLogSigner: Sendable {
    /// The signer's Ed25519 multikey (`z6Mk…`), used in `verificationMethod`.
    var multikey: String { get }
    /// Returns a 64-byte Ed25519 signature over `message`.
    func sign(_ message: [UInt8]) throws -> [UInt8]
}

/// The default signer: an Ed25519 key held by swift-crypto
/// (`Curve25519.Signing.PrivateKey`).
///
/// On Apple platforms CryptoKit produces randomised Ed25519 signatures, so two
/// proofs over the same document differ byte for byte; both verify.
public struct Ed25519Signer: VHLogSigner {
    private let key: Curve25519.Signing.PrivateKey

    /// Wraps an existing swift-crypto key.
    public init(privateKey: Curve25519.Signing.PrivateKey) { key = privateKey }

    /// Creates a signer from a 32-byte seed (RFC 8032 §5.1.5).
    public init(seed: [UInt8]) throws(VHLogInputError) {
        guard seed.count == 32, let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: seed) else {
            throw .invalidSeed("Ed25519 seed must be 32 bytes")
        }
        self.key = key
    }

    /// Creates a signer from a hex-encoded 32-byte seed.
    public init(seedHex: String) throws(VHLogInputError) {
        guard let seed = Hex.decode(seedHex) else { throw .invalidSeed("seed is not hex: \(seedHex)") }
        try self.init(seed: seed)
    }

    /// The raw 32-byte public key.
    public var publicKey: [UInt8] { Array(key.publicKey.rawRepresentation) }

    /// The Ed25519 multikey of ``publicKey``.
    public var multikey: String { Multikey.encode(ed25519PublicKey: publicKey) }

    /// A 64-byte Ed25519 signature (randomised on Apple platforms).
    public func sign(_ message: [UInt8]) throws -> [UInt8] { Array(try key.signature(for: message)) }

    // Profile §2; Crypto checks curve membership and the equation.
    private static func admissiblePoint(_ encoded: [UInt8]) -> Bool {
        var y = encoded; y[31] &= 127
        let small = ["0000000000000000000000000000000000000000000000000000000000000000", "0100000000000000000000000000000000000000000000000000000000000000", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"]
        if small.contains(where: { Hex.decode($0) == y }) { return false }
        var p = [UInt8](repeating: 255, count: 32); p[0] = 237; p[31] = 127
        return y.reversed().lexicographicallyPrecedes(p.reversed())
    }

    /// Verifies an Ed25519 signature with swift-crypto.
    public static func verify(publicKey: [UInt8], message: [UInt8], signature: [UInt8]) -> Bool {
        guard publicKey.count == 32, signature.count == 64,
            admissiblePoint(publicKey), admissiblePoint(Array(signature.prefix(32))),
            let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
        else { return false }
        return key.isValidSignature(signature, for: message)
    }
}
