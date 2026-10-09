from __future__ import annotations

from pathlib import Path
from typing import Any

from vh_log import canonicalize, parse_json

VECTORS = Path(__file__).resolve().parents[3] / "vectors"


def load(name: str) -> Any:
    """Loads a vector file with the library's own (double-precision) JSON parser."""
    return parse_json((VECTORS / name).read_text(encoding="utf-8"))


def same(a: Any, b: Any) -> bool:
    return canonicalize(a) == canonicalize(b)
