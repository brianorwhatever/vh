//! Ed25519 keys and `eddsa-jcs-2022` Data Integrity proofs (profile §2).

use crate::encoding::{
    base58btc_decode, base58btc_encode, hex_decode, multikey_from_public_key,
    public_key_from_multikey,
};
use crate::error::GenerateError;
use crate::hash::sha256;
use crate::jcs::canonicalize;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fmt;

pub const CRYPTOSUITE: &str = "eddsa-jcs-2022";
pub const PROOF_TYPE: &str = "DataIntegrityProof";
pub const PROOF_PURPOSE: &str = "assertionMethod";

/// An Ed25519 signing key, created from a 32-byte seed (RFC 8032 §5.1.5).
#[derive(Clone)]
pub struct Signer {
    key: SigningKey,
    multikey: String,
}

impl Signer {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let key = SigningKey::from_bytes(seed);
        let multikey = multikey_from_public_key(key.verifying_key().as_bytes());
        Signer { key, multikey }
    }

    /// Creates a signer from a hex-encoded 32-byte seed.
    pub fn from_seed_hex(seed_hex: &str) -> Result<Self, GenerateError> {
        let bytes = hex_decode(seed_hex)?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| GenerateError::InvalidSeed("Ed25519 seed must be 32 bytes".into()))?;
        Ok(Self::from_seed(&seed))
    }

    /// The public key as an Ed25519 multikey (`z6Mk…`).
    pub fn multikey(&self) -> &str {
        &self.multikey
    }

    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.key.sign(data).to_bytes()
    }
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer")
            .field("multikey", &self.multikey)
            .finish_non_exhaustive()
    }
}

/// Verifies a raw Ed25519 signature; returns false for malformed keys or signatures.
pub fn verify_signature(public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    let (Ok(pk), Ok(sig)) = (
        <&[u8; 32]>::try_from(public_key),
        <&[u8; 64]>::try_from(signature),
    ) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(pk) else {
        return false;
    };
    // verify_strict rejects small-order points; require canonical A as well.
    let mut y = *pk;
    y[31] &= 127;
    let mut p = [255u8; 32];
    p[0] = 237;
    p[31] = 127;
    y.iter().rev().cmp(p.iter().rev()).is_lt()
        && key.verify_strict(data, &Signature::from_bytes(sig)).is_ok()
}

/// A Data Integrity proof as produced by [`create_proof`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub cryptosuite: String,
    pub verification_method: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub created: Option<String>,
    pub proof_purpose: String,
    pub proof_value: String,
}

impl Proof {
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("proof serialises")
    }
}

/// Options for [`create_proof`]. `cryptosuite`/`proof_purpose` overrides exist only to build invalid test logs.
#[derive(Debug, Clone, Default)]
pub struct ProofOptions {
    pub verification_method: Option<String>,
    pub created: Option<String>,
    pub proof_purpose: Option<String>,
    pub cryptosuite: Option<String>,
}

/// `did:key:<mk>#<mk>`.
pub fn did_key_verification_method(multikey: &str) -> String {
    format!("did:key:{multikey}#{multikey}")
}

/// Returns the multikey named by a `did:key:<mk>#<mk>` verification method, or
/// `None` if the value is not in that form.
pub fn multikey_from_verification_method(vm: &str) -> Option<&str> {
    let rest = vm.strip_prefix("did:key:")?;
    let (first, second) = rest.split_once('#')?;
    if first.is_empty() || first != second {
        return None;
    }
    public_key_from_multikey(first)?;
    Some(first)
}

fn signing_input(document: &Value, config: &Map<String, Value>) -> Vec<u8> {
    let mut input = sha256(canonicalize(&Value::Object(config.clone())).as_bytes()).to_vec();
    input.extend_from_slice(&sha256(canonicalize(document).as_bytes()));
    input
}

/// Creates an `eddsa-jcs-2022` proof over `document`.
pub fn create_proof(document: &Value, signer: &Signer, options: &ProofOptions) -> Proof {
    let mut proof = Proof {
        proof_type: PROOF_TYPE.into(),
        cryptosuite: options
            .cryptosuite
            .clone()
            .unwrap_or_else(|| CRYPTOSUITE.into()),
        verification_method: options
            .verification_method
            .clone()
            .unwrap_or_else(|| did_key_verification_method(signer.multikey())),
        created: options.created.clone(),
        proof_purpose: options
            .proof_purpose
            .clone()
            .unwrap_or_else(|| PROOF_PURPOSE.into()),
        proof_value: String::new(),
    };
    let Value::Object(mut config) = proof.to_value() else {
        unreachable!()
    };
    config.remove("proofValue");
    proof.proof_value = format!(
        "z{}",
        base58btc_encode(&signer.sign(&signing_input(document, &config)))
    );
    proof
}

/// Checks a proof's structure and `eddsa-jcs-2022` signature over `document`.
/// Does not check whether the key is authorised.
pub fn verify_proof(document: &Value, proof: &Value) -> bool {
    let Value::Object(p) = proof else {
        return false;
    };
    let is = |key: &str, want: &str| p.get(key).and_then(Value::as_str) == Some(want);
    if !is("type", PROOF_TYPE)
        || !is("cryptosuite", CRYPTOSUITE)
        || !is("proofPurpose", PROOF_PURPOSE)
    {
        return false;
    }
    let Some(multikey) = p
        .get("verificationMethod")
        .and_then(Value::as_str)
        .and_then(multikey_from_verification_method)
    else {
        return false;
    };
    let Some(signature) = p
        .get("proofValue")
        .and_then(Value::as_str)
        .and_then(|v| v.strip_prefix('z'))
        .and_then(base58btc_decode)
    else {
        return false;
    };
    let public_key = public_key_from_multikey(multikey).expect("checked above");
    let mut config = p.clone();
    config.remove("proofValue");
    verify_signature(&public_key, &signing_input(document, &config), &signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sign_and_verify() {
        let signer = Signer::from_seed(&[0u8; 32]);
        assert_eq!(
            signer.multikey(),
            "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
        );
        let doc = json!({"versionId": "1-Qm"});
        let proof = create_proof(&doc, &signer, &ProofOptions::default()).to_value();
        assert!(verify_proof(&doc, &proof));
        assert!(!verify_proof(&json!({"versionId": "2-Qm"}), &proof));
        let mut wrong = proof.clone();
        wrong["proofPurpose"] = json!("authentication");
        assert!(!verify_proof(&doc, &wrong));
    }

    #[test]
    fn verification_method_form() {
        let mk = Signer::from_seed(&[1u8; 32]).multikey().to_string();
        assert_eq!(
            multikey_from_verification_method(&did_key_verification_method(&mk)),
            Some(mk.as_str())
        );
        assert_eq!(
            multikey_from_verification_method(&format!("did:key:{mk}#key-1")),
            None
        );
        assert_eq!(
            multikey_from_verification_method(&format!("did:web:{mk}#{mk}")),
            None
        );
    }
}
