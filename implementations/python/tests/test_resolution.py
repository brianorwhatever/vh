"""Runs every resolution vector through :func:`vh_log.resolve_request`."""

from __future__ import annotations

from typing import Any

import pytest

from conftest import VECTORS, load, same
from vh_log import resolve_request

CASES = [
    pytest.param(case, id=f"{path.stem}/{case['name']}")
    for path in sorted((VECTORS / "resolution").glob("*.json"))
    for case in load(f"resolution/{path.name}")["cases"]
]


@pytest.mark.parametrize("case", CASES)
def test_resolution_vector(case: dict[str, Any]) -> None:
    expect = case["expect"]
    got: Any = resolve_request(case["input"])
    assert got["valid"] == expect["valid"]
    error = got.get("error")
    if expect.get("error"):
        codes = expect["error"].get("oneOf", [expect["error"].get("code")])
        assert error is not None and error["code"] in codes
        if "version" in expect["error"]:
            assert error["version"] == expect["error"]["version"]
    else:
        assert error is None
    if expect["valid"]:
        assert same(got["state"], expect["state"])
        assert got["firstInvalidVersion"] == expect.get("firstInvalidVersion")
        assert sorted(w["code"] for w in got["metadata"]["warnings"]) == expect.get("warnings", [])
        for key, value in expect.get("metadata", {}).items():
            assert same(got["metadata"].get(key), value), key
