/// `eddsa-jcs-2022` Data Integrity proofs (profile §2).
public enum DataIntegrity {
    /// The only cryptosuite the profile uses.
    public static let cryptosuite = "eddsa-jcs-2022"
    /// Proof `type`.
    public static let proofType = "DataIntegrityProof"
    /// Proof purpose.
    public static let proofPurpose = "assertionMethod"

    /// Options for ``createProof(document:signer:options:)``.
    public struct ProofOptions: Sendable {
        /// Defaults to `did:key:<mk>#<mk>` of the signer.
        public var verificationMethod: String?
        /// Omitted from the proof when `nil`.
        public var created: JSONValue?
        /// Override for building invalid test vectors only.
        public var proofPurpose: String?
        /// Override for building invalid test vectors only.
        public var cryptosuite: String?

        public init(verificationMethod: String? = nil, created: String? = nil,
                    proofPurpose: String? = nil, cryptosuite: String? = nil) {
            self.verificationMethod = verificationMethod
            self.created = created.map { .string($0) }
            self.proofPurpose = proofPurpose
            self.cryptosuite = cryptosuite
        }
    }

    /// `SHA-256(JCS(proofConfig)) ‖ SHA-256(JCS(document))`.
    static func signingInput(document: JSONValue, config: JSONObject) throws(JSONSerializationError) -> [UInt8] {
        Multihash.sha256(try JCS.canonicalBytes(.object(config))) + Multihash.sha256(try JCS.canonicalBytes(document))
    }

    /// Creates a proof over `document`. Field order: `type, cryptosuite,
    /// verificationMethod, created?, proofPurpose, proofValue`.
    public static func createProof(document: JSONValue, signer: Ed25519Signer,
                                   options: ProofOptions = .init()) throws(JSONSerializationError) -> JSONObject {
        var config: JSONObject = [
            "type": .string(proofType),
            "cryptosuite": .string(options.cryptosuite ?? cryptosuite),
            "verificationMethod": .string(options.verificationMethod ?? Multikey.verificationMethod(signer.multikey)),
        ]
        if let created = options.created { config["created"] = created }
        config["proofPurpose"] = .string(options.proofPurpose ?? proofPurpose)
        let signature = signer.sign(try signingInput(document: document, config: config))
        config["proofValue"] = .string("z" + Base58.encode(signature))
        return config
    }

    /// Checks a proof's structure and signature over `document`. It doesn't
    /// check whether the key is authorised.
    public static func verifyProof(document: JSONValue, proof: JSONValue) -> Bool {
        guard let p = proof.objectValue,
            p["type"]?.stringValue.map({ $0.utf8.elementsEqual(proofType.utf8) }) == true,
            p["cryptosuite"]?.stringValue.map({ $0.utf8.elementsEqual(cryptosuite.utf8) }) == true,
            p["proofPurpose"]?.stringValue.map({ $0.utf8.elementsEqual(proofPurpose.utf8) }) == true,
            let vm = p["verificationMethod"]?.stringValue,
            let multikey = Multikey.fromVerificationMethod(vm),
            let publicKey = Multikey.ed25519PublicKey(multikey),
            let proofValue = p["proofValue"]?.stringValue,
            proofValue.utf8.first == UInt8(ascii: "z"),
            let signature = Base58.decode(String(decoding: proofValue.utf8.dropFirst(), as: UTF8.self)),
            let input = try? signingInput(document: document, config: p.removing("proofValue"))
        else { return false }
        return Ed25519Signer.verify(publicKey: publicKey, message: input, signature: signature)
    }
}
