package org.vhlog

/** Options for [Proofs.create]. `cryptosuite`/`proofPurpose` overrides exist only to build invalid test data. */
data class ProofOptions @JvmOverloads constructor(
    val verificationMethod: String? = null,
    val created: String? = null,
    val proofPurpose: String? = null,
    val cryptosuite: String? = null,
)

/** `eddsa-jcs-2022` Data Integrity proofs (profile §2). */
object Proofs {
    const val TYPE = "DataIntegrityProof"
    const val CRYPTOSUITE = "eddsa-jcs-2022"
    const val PROOF_PURPOSE = "assertionMethod"

    /** `did:key:<mk>#<mk>`. */
    @JvmStatic
    fun didKeyVerificationMethod(multikey: String): String = "did:key:$multikey#$multikey"

    /** The multikey named by a `did:key:<mk>#<mk>` verification method, or null if it is not in that form. */
    @JvmStatic
    fun multikeyFromVerificationMethod(vm: JsonValue?): String? {
        val s = (vm as? JsonString)?.value ?: return null
        if (!s.startsWith("did:key:")) return null
        val hash = s.indexOf('#', 8)
        if (hash <= 8) return null
        val multikey = s.substring(8, hash)
        if (s.substring(hash + 1) != multikey || !Multikey.isValid(multikey)) return null
        return multikey
    }

    private fun signingInput(document: JsonValue, proofConfig: JsonObject): ByteArray =
        Hashes.sha256(Jcs.canonicalize(proofConfig)) + Hashes.sha256(Jcs.canonicalize(document))

    /** Creates a proof over [document] with the key derived from [seedHex]. */
    @JvmStatic
    @JvmOverloads
    fun create(document: JsonValue, seedHex: String, options: ProofOptions = ProofOptions()): JsonObject =
        create(document, Ed25519Signer.fromSeedHex(seedHex), options)

    /** Creates a proof over [document] with [signer]. */
    @JvmStatic
    @JvmOverloads
    fun create(document: JsonValue, signer: Ed25519Signer, options: ProofOptions = ProofOptions()): JsonObject {
        val config = linkedMapOf<String, JsonValue>(
            "type" to JsonString(TYPE),
            "cryptosuite" to JsonString(options.cryptosuite ?: CRYPTOSUITE),
            "verificationMethod" to JsonString(options.verificationMethod ?: didKeyVerificationMethod(signer.multikey)),
        )
        if (options.created != null) config["created"] = JsonString(options.created)
        config["proofPurpose"] = JsonString(options.proofPurpose ?: PROOF_PURPOSE)
        val signature = signer.sign(signingInput(document, JsonObject(LinkedHashMap(config))))
        config["proofValue"] = JsonString("z" + Base58.encode(signature))
        return JsonObject(config)
    }

    /**
     * Checks a proof's structure and signature over [document]. It does not
     * check whether the key is authorised.
     */
    @JvmStatic
    fun verify(document: JsonValue, proof: JsonValue): Boolean {
        val p = proof as? JsonObject ?: return false
        if (p.string("type") != TYPE || p.string("cryptosuite") != CRYPTOSUITE || p.string("proofPurpose") != PROOF_PURPOSE) {
            return false
        }
        val multikey = multikeyFromVerificationMethod(p["verificationMethod"]) ?: return false
        val proofValue = p.string("proofValue") ?: return false
        if (!proofValue.startsWith("z")) return false
        val signature = Base58.decodeOrNull(proofValue.substring(1)) ?: return false
        val publicKey = Multikey.publicKeyOrNull(multikey) ?: return false
        return Ed25519Signer.verify(publicKey, signingInput(document, p.without("proofValue")), signature)
    }
}
