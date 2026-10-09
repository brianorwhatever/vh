"""JSON with ECMAScript semantics, and RFC 8785 (JCS) canonicalisation.

RFC 8785 treats every JSON number as an IEEE-754 double. Python's :mod:`json`
parses integers with arbitrary precision, so :func:`parse_json` converts every
number to a double first. Integral doubles are returned as :class:`int` (so
``1.0`` and ``1`` both become ``1`` and ``123456789012345678`` becomes
``123456789012345680``), which keeps integer checks natural; other values stay
:class:`float`.

:func:`to_json` mirrors ``JSON.stringify`` (insertion key order) and
:func:`canonicalize` mirrors the TypeScript reference (UTF-16 code unit key
order). Both serialise numbers with ECMAScript ``Number::toString`` rules.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any

__all__ = ["canonicalize", "format_number", "parse_json", "to_json", "utf8"]

_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
_NEEDS_ESCAPE = re.compile('[\ud800-\udbff][\udc00-\udfff]|["\\\\\x00-\x1f\ud800-\udfff]')


def _number(text: str) -> int | float:
    value = float(text)
    if math.isfinite(value) and value.is_integer():
        return int(value)
    return value


def _reject_constant(name: str) -> Any:
    raise ValueError(f"invalid JSON literal {name}")


def parse_json(text: str) -> Any:
    """Parses JSON text, treating every number as an IEEE-754 double.

    Raises :class:`ValueError` on invalid JSON (``NaN``/``Infinity`` literals are rejected).
    """
    try:
        return json.loads(text, parse_int=_number, parse_float=_number, parse_constant=_reject_constant)
    except RecursionError as e:
        raise ValueError("JSON nested too deeply") from e


def format_number(value: int | float) -> str:
    """Serialises a number as ECMAScript ``Number::toString`` does (after conversion to a double)."""
    x = float(value)
    if not math.isfinite(x):
        raise ValueError("JSON: non-finite number")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    # repr gives the shortest digit string that round-trips, as ECMAScript requires.
    parsed = Decimal(repr(abs(x))).normalize().as_tuple()
    digits = "".join(map(str, parsed.digits))
    # n: position of the decimal point relative to the start of `digits`.
    n = len(digits) + int(parsed.exponent)
    k = len(digits)
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        exponent = ("+" if e >= 0 else "-") + str(abs(e))
        out = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + exponent
    return sign + out


def _escape(match: re.Match[str]) -> str:
    s = match.group(0)
    if len(s) == 2:  # a surrogate pair stored as two code points: emit the character
        return chr(0x10000 + ((ord(s[0]) - 0xD800) << 10) + (ord(s[1]) - 0xDC00))
    return _ESCAPES.get(s) or f"\\u{ord(s):04x}"


def _string(s: str) -> str:
    return '"' + _NEEDS_ESCAPE.sub(_escape, s) + '"'


def _utf16_key(key: str) -> bytes:
    return key.encode("utf-16-be", "surrogatepass")


def _serialize(value: Any, canonical: bool) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, int | float):
        if not canonical and not math.isfinite(value):
            return "null"  # JSON.stringify behaviour
        return format_number(value)
    if isinstance(value, Mapping):
        keys = [k for k in value if isinstance(k, str)]
        if len(keys) != len(value):
            raise TypeError("JSON object keys must be strings")
        if canonical:
            keys.sort(key=_utf16_key)
        return "{" + ",".join(_string(k) + ":" + _serialize(value[k], canonical) for k in keys) + "}"
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        return "[" + ",".join(_serialize(v, canonical) for v in value) + "]"
    raise TypeError(f"JSON: unsupported type {type(value).__name__}")


def canonicalize(value: Any) -> str:
    """RFC 8785 canonical JSON. Keys sort by UTF-16 code units; numbers are doubles."""
    return _serialize(value, True)


def to_json(value: Any) -> str:
    """Compact JSON like ECMAScript ``JSON.stringify`` (keys in insertion order, raw non-ASCII)."""
    return _serialize(value, False)


def utf8(s: str) -> bytes:
    """UTF-8 encodes ``s``; lone surrogates become U+FFFD, as in Node.js."""
    try:
        return s.encode("utf-8")
    except UnicodeEncodeError:
        return s.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace").encode("utf-8")
