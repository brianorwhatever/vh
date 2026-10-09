"""Ed25519 signing from 32-byte seeds (RFC 8032) via :mod:`cryptography`."""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .encoding import hex_to_bytes, multikey_from_public_key

__all__ = ["Signer", "signer_from_seed", "verify_signature"]


@dataclass(frozen=True)
class Signer:
    """An Ed25519 key pair derived from a seed."""

    public_key: bytes
    multikey: str
    _private_key: Ed25519PrivateKey = field(repr=False, compare=False)

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data)


def signer_from_seed(seed: str | bytes) -> Signer:
    """Builds a signer from a 32-byte seed, given as bytes or hex."""
    raw = hex_to_bytes(seed) if isinstance(seed, str) else bytes(seed)
    if len(raw) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    private_key = Ed25519PrivateKey.from_private_bytes(raw)
    public_key = private_key.public_key().public_bytes_raw()
    return Signer(public_key, multikey_from_public_key(public_key), private_key)


def verify_signature(public_key: bytes, data: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, data)
    except Exception:
        return False
    return True
