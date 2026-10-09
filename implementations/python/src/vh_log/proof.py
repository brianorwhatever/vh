"""``eddsa-jcs-2022`` Data Integrity proofs (profile section 2)."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, NotRequired, TypedDict

from .ed25519 import signer_from_seed, verify_signature
from .encoding import base58btc_decode, base58btc_encode, public_key_from_multikey
from .hashing import sha256
from .jcs import canonicalize

__all__ = [
    "CRYPTOSUITE",
    "Proof",
    "create_proof",
    "did_key_verification_method",
    "multikey_from_verification_method",
    "verify_proof",
]

CRYPTOSUITE = "eddsa-jcs-2022"
_DID_KEY_VM = re.compile(r"did:key:([^#]+)#(.+)", re.DOTALL)


class Proof(TypedDict):
    type: str
    cryptosuite: str
    verificationMethod: str
    created: NotRequired[str]
    proofPurpose: str
    proofValue: str


def did_key_verification_method(multikey: str) -> str:
    return f"did:key:{multikey}#{multikey}"


def multikey_from_verification_method(vm: object) -> str | None:
    """Returns the multikey named by ``did:key:<mk>#<mk>``, or ``None`` if ``vm`` is not in that form."""
    if not isinstance(vm, str):
        return None
    match = _DID_KEY_VM.fullmatch(vm)
    if not match or match[1] != match[2] or public_key_from_multikey(match[1]) is None:
        return None
    return match[1]


def _signing_input(document: Any, proof_config: Mapping[str, Any]) -> bytes:
    return sha256(canonicalize(proof_config)) + sha256(canonicalize(document))


def create_proof(
    document: Any,
    seed: str | bytes,
    *,
    verification_method: str | None = None,
    created: str | None = None,
    proof_purpose: str = "assertionMethod",
    cryptosuite: str = CRYPTOSUITE,
) -> Proof:
    """Creates an eddsa-jcs-2022 proof over ``document``.

    ``proof_purpose``/``cryptosuite`` overrides exist only to build invalid test vectors.
    """
    signer = signer_from_seed(seed)
    config: dict[str, Any] = {
        "type": "DataIntegrityProof",
        "cryptosuite": cryptosuite,
        "verificationMethod": (
            did_key_verification_method(signer.multikey)
            if verification_method is None
            else verification_method
        ),
    }
    if created is not None:
        config["created"] = created
    config["proofPurpose"] = proof_purpose
    signature = signer.sign(_signing_input(document, config))
    proof: Proof = {**config, "proofValue": "z" + base58btc_encode(signature)}  # type: ignore[typeddict-item]
    return proof


def verify_proof(document: Any, proof: Any) -> bool:
    """Checks a proof's structure and signature over ``document``. Does not check authorisation."""
    if not isinstance(proof, Mapping):
        return False
    if (
        proof.get("type") != "DataIntegrityProof"
        or proof.get("cryptosuite") != CRYPTOSUITE
        or proof.get("proofPurpose") != "assertionMethod"
    ):
        return False
    multikey = multikey_from_verification_method(proof.get("verificationMethod"))
    proof_value = proof.get("proofValue")
    if multikey is None or not isinstance(proof_value, str) or not proof_value.startswith("z"):
        return False
    signature = base58btc_decode(proof_value[1:])
    public_key = public_key_from_multikey(multikey)
    if signature is None or public_key is None:
        return False
    config = {k: v for k, v in proof.items() if k != "proofValue"}
    return verify_signature(public_key, _signing_input(document, config), signature)
