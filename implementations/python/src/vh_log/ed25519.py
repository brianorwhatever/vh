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


# Profile §2: canonical encodings and no points of order dividing 8.
# The backend still checks curve membership and the uncofactored equation.
_P = 57896044618658097711785492504343953926634992332820282019728792003956564819949
_L = 7237005577332262213973186563042994240857116359379907606001950938285454250989
_SMALL_Y = frozenset(
    [
        0,
        1,
        2707385501144840649318225287225658788936804267575313519463743609750303402022,
        55188659117513257062467267217118295137698188065244968500265048394206261417927,
        57896044618658097711785492504343953926634992332820282019728792003956564819948,
    ]
)


def _admissible_point(encoded: bytes) -> bool:
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    return y < _P and y not in _SMALL_Y


def verify_signature(public_key: bytes, data: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    if (
        not _admissible_point(public_key)
        or not _admissible_point(signature[:32])
        or int.from_bytes(signature[32:], "little") >= _L
    ):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, data)
    except Exception:
        return False
    return True
