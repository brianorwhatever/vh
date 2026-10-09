package vhlog

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
)

// Cryptosuite is the only Data Integrity cryptosuite VH-Log entries use.
const Cryptosuite = "eddsa-jcs-2022"

// DidKeyVerificationMethod returns "did:key:<mk>#<mk>", the verification
// method form the profile requires.
func DidKeyVerificationMethod(multikey string) string {
	return "did:key:" + multikey + "#" + multikey
}

// MultikeyFromVerificationMethod returns the Ed25519 multikey named by a
// "did:key:<mk>#<mk>" verification method, or false if vm is not in that form
// (including when the two halves differ).
func MultikeyFromVerificationMethod(vm any) (string, bool) {
	s, ok := vm.(string)
	if !ok {
		return "", false
	}
	rest, ok := strings.CutPrefix(s, "did:key:")
	if !ok {
		return "", false
	}
	mk, fragment, ok := strings.Cut(rest, "#")
	if !ok || mk == "" || mk != fragment {
		return "", false
	}
	if _, ok := PublicKeyFromMultikey(mk); !ok {
		return "", false
	}
	return mk, true
}

// signingInput is SHA-256(JCS(proofConfig)) ‖ SHA-256(JCS(document)).
func signingInput(document any, config *Object) ([]byte, error) {
	c, err := Canonicalize(config)
	if err != nil {
		return nil, err
	}
	d, err := Canonicalize(document)
	if err != nil {
		return nil, err
	}
	hc := sha256.Sum256(toUTF8(c))
	hd := sha256.Sum256(toUTF8(d))
	return append(hc[:], hd[:]...), nil
}

// ProofOptions customises CreateProof. Zero values select the defaults.
type ProofOptions struct {
	// VerificationMethod defaults to did:key:<mk>#<mk> for the signing key.
	VerificationMethod string
	// Created is omitted when empty.
	Created string
	// ProofPurpose defaults to "assertionMethod". Overriding it (or
	// Cryptosuite) only makes sense when building invalid test vectors.
	ProofPurpose string
	// Cryptosuite defaults to "eddsa-jcs-2022".
	Cryptosuite string
}

// CreateProof creates an eddsa-jcs-2022 Data Integrity proof over document.
// The proof's members are, in order: type, cryptosuite, verificationMethod,
// created (if set), proofPurpose, proofValue.
func CreateProof(document any, key ed25519.PrivateKey, opts ProofOptions) (*Object, error) {
	config := NewObject()
	config.Set("type", "DataIntegrityProof")
	config.Set("cryptosuite", orDefault(opts.Cryptosuite, Cryptosuite))
	config.Set("verificationMethod", orDefault(opts.VerificationMethod, DidKeyVerificationMethod(Multikey(key))))
	if opts.Created != "" {
		config.Set("created", opts.Created)
	}
	config.Set("proofPurpose", orDefault(opts.ProofPurpose, "assertionMethod"))
	input, err := signingInput(document, config)
	if err != nil {
		return nil, err
	}
	proof := config.Clone()
	proof.Set("proofValue", "z"+Base58btcEncode(ed25519.Sign(key, input)))
	return proof, nil
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// VerifyProof checks a proof's structure (type, cryptosuite, proofPurpose,
// did:key verification method, proofValue) and its eddsa-jcs-2022 signature
// over document. It does not check whether the key is authorised.
func VerifyProof(document any, proof any) bool {
	p, ok := proof.(*Object)
	if !ok {
		return false
	}
	if !memberEquals(p, "type", "DataIntegrityProof") || !memberEquals(p, "cryptosuite", Cryptosuite) ||
		!memberEquals(p, "proofPurpose", "assertionMethod") {
		return false
	}
	vm, _ := p.Get("verificationMethod")
	multikey, ok := MultikeyFromVerificationMethod(vm)
	if !ok {
		return false
	}
	pv, _ := p.Get("proofValue")
	value, ok := pv.(string)
	if !ok || !strings.HasPrefix(value, "z") {
		return false
	}
	signature, ok := Base58btcDecode(value[1:])
	if !ok || len(signature) != ed25519.SignatureSize {
		return false
	}
	input, err := signingInput(document, p.without("proofValue"))
	if err != nil {
		return false
	}
	pub, _ := PublicKeyFromMultikey(multikey)
	return ed25519.Verify(pub, input, signature)
}

func memberEquals(o *Object, key, want string) bool {
	v, _ := o.Get(key)
	s, ok := v.(string)
	return ok && s == want
}
