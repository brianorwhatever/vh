"""SHA-256 multihashes encoded with base58btc (SCIDs, entry hashes and key hashes)."""

from __future__ import annotations

import hashlib
from enum import StrEnum

from .encoding import base58btc_decode, base58btc_encode
from .jcs import utf8

__all__ = ["MultihashCheck", "check_sha256_multihash", "hash_b58", "key_hash", "sha256"]

#: Multihash code and digest length for SHA-256, the only algorithm ``vh-log:1.0`` permits.
SHA256_CODE = 0x12
SHA256_LENGTH = 32


def sha256(data: bytes | str) -> bytes:
    return hashlib.sha256(utf8(data) if isinstance(data, str) else data).digest()


def hash_b58(data: bytes | str) -> str:
    """``base58btc(multihash(data, SHA-256))``; strings are UTF-8 encoded."""
    return base58btc_encode(bytes([SHA256_CODE, SHA256_LENGTH]) + sha256(data))


class MultihashCheck(StrEnum):
    OK = "ok"
    NOT_BASE58 = "not-base58"
    UNSUPPORTED_ALGORITHM = "unsupported-algorithm"


def check_sha256_multihash(value: str) -> MultihashCheck:
    """Classifies a base58btc string as a SHA-256 multihash, some other bytes, or not base58."""
    data = base58btc_decode(value)
    if not data:
        return MultihashCheck.NOT_BASE58
    if len(data) != 2 + SHA256_LENGTH or data[0] != SHA256_CODE or data[1] != SHA256_LENGTH:
        return MultihashCheck.UNSUPPORTED_ALGORITHM
    return MultihashCheck.OK


def key_hash(multikey: str) -> str:
    """Pre-rotation key hash: the multikey *string* itself is hashed."""
    return hash_b58(multikey)
