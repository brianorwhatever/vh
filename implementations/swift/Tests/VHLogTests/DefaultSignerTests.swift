import Testing
import VHLog
import VHLogDeterministicSigning

/// The library's default signer (swift-crypto / CryptoKit) may produce
/// randomised signatures: its proofs must verify, but needn't equal the
/// deterministic RFC 8032 ones the vectors were generated with.
@Suite struct DefaultSignerTests {
    let seed = "90930409d492fb6cd7b50542c97fc6003fcedd59012b47ac114417373796eaaa"
    let now = "2026-06-01T00:00:00Z"

    @Test func sameKeyAsDeterministicSigner() throws {
        let a = try Ed25519Signer(seedHex: seed), b = try DeterministicEd25519Signer(seedHex: seed)
        #expect(a.publicKey == b.publicKey)
        #expect(a.multikey == "z6MkwTAY3aCT7UL96ddvxWr1upj2VFQDMPFFRYxM1fRneSrv")
        #expect(throws: VHLogInputError.self) { try Ed25519Signer(seedHex: "abcd") }
    }

    @Test func proofsVerifyAndMayDiffer() throws {
        let document: JSONValue = ["versionId": "1-QmX", "n": 1.5]
        let options = DataIntegrity.ProofOptions(created: "2026-01-01T00:00:00Z")
        let p1 = try DataIntegrity.createProof(document: document, seedHex: seed, options: options)
        let p2 = try DataIntegrity.createProof(document: document, signer: Ed25519Signer(seedHex: seed), options: options)
        let deterministic = try DataIntegrity.createProof(document: document, signer: DeterministicEd25519Signer(seedHex: seed),
                                                         options: options)
        for proof in [p1, p2, deterministic] {
            #expect(DataIntegrity.verifyProof(document: document, proof: .object(proof)))
            #expect(!DataIntegrity.verifyProof(document: ["versionId": "1-QmY", "n": 1.5], proof: .object(proof)))
            // Everything but the signature is identical.
            #expect(proof.removing("proofValue") == deterministic.removing("proofValue"))
        }
        // Not asserted equal: CryptoKit's signatures are randomised on Apple platforms.
        if p1["proofValue"] != deterministic["proofValue"] {
            print("default signer produced a non-deterministic signature (expected with CryptoKit)")
        }
    }

    @Test func logsMadeWithTheDefaultSignerResolve() throws {
        let mk = try Ed25519Signer(seedHex: seed).multikey
        let created = try createLog(state: ["id": "example:{SCID}"], parameters: ["updateKeys": [.string(mk)]],
                                    versionTime: "2026-01-01T00:00:00Z", seedsHex: [seed])
        // Hashes don't cover proofs, so the versionId matches the deterministic run.
        let reference = try createLog(state: ["id": "example:{SCID}"], parameters: ["updateKeys": [.string(mk)]],
                                      versionTime: "2026-01-01T00:00:00Z", signers: [DeterministicEd25519Signer(seedHex: seed)])
        #expect(created.versionId == reference.versionId)
        let updated = try updateLog(log: created.log, state: ["n": 2], versionTime: "2026-01-02T00:00:00Z", seedsHex: [seed])
        let witness = try witnessProof(versionId: updated.versionId, seedHex: seed)
        #expect(DataIntegrity.verifyProof(document: ["versionId": .string(updated.versionId)], proof: .object(witness)))
        guard case .resolved(let r) = resolve(ResolveInput(log: updated.log, now: now)) else {
            Issue.record("did not resolve"); return
        }
        #expect(r.error == nil)
        #expect(r.metadata.versionNumber == 2)
        #expect(r.state == ["n": 2])
    }
}
