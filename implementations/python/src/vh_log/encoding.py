"""base58btc, Ed25519 multikeys and hex helpers (profile section 1)."""

from __future__ import annotations

import re

__all__ = [
    "base58btc_decode",
    "base58btc_encode",
    "bytes_to_hex",
    "hex_to_bytes",
    "multikey_from_public_key",
    "public_key_from_multikey",
]

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ALPHABET_MAP = {c: i for i, c in enumerate(ALPHABET)}

#: Ed25519 public key multicodec prefix (0xed, varint-encoded).
ED25519_PUB = b"\xed\x01"

_HEX = re.compile(r"(?:[0-9a-fA-F]{2})*")


def base58btc_encode(data: bytes) -> str:
    """Bitcoin-alphabet base58, without a multibase prefix."""
    zeros = len(data) - len(data.lstrip(b"\0"))
    num = int.from_bytes(data, "big")
    out: list[str] = []
    while num > 0:
        num, rem = divmod(num, 58)
        out.append(ALPHABET[rem])
    return "1" * zeros + "".join(reversed(out))


def base58btc_decode(s: str) -> bytes | None:
    """Decodes base58btc; returns ``None`` if ``s`` contains a non-alphabet character."""
    zeros = len(s) - len(s.lstrip("1"))
    num = 0
    for c in s[zeros:]:
        value = _ALPHABET_MAP.get(c)
        if value is None:
            return None
        num = num * 58 + value
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    return b"\0" * zeros + body


def multikey_from_public_key(public_key: bytes) -> str:
    """``"z" + base58btc(0xed 0x01 || pubkey)``."""
    return "z" + base58btc_encode(ED25519_PUB + public_key)


def public_key_from_multikey(multikey: object) -> bytes | None:
    """Returns the raw Ed25519 public key, or ``None`` if ``multikey`` is not an Ed25519 multikey."""
    if not isinstance(multikey, str) or not multikey.startswith("z"):
        return None
    data = base58btc_decode(multikey[1:])
    if data is None or len(data) != 34 or data[:2] != ED25519_PUB:
        return None
    return data[2:]


def hex_to_bytes(hex_text: str) -> bytes:
    if not isinstance(hex_text, str) or not _HEX.fullmatch(hex_text):
        raise ValueError(f"invalid hex: {hex_text}")
    return bytes.fromhex(hex_text)


def bytes_to_hex(data: bytes) -> str:
    return data.hex()
