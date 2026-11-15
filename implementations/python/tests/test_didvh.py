"""did:vh: the library must reproduce every did:vh vector, and the specialisation hook
must keep VH-Log and did:vh logs apart."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest

from conftest import VECTORS, load, same
from vh_log import (
    DidVhError,
    check_ref,
    create_did,
    create_log,
    parse_did,
    parse_did_url,
    resolve,
    resolve_did,
    signer_from_seed,
    src_references,
    update_did,
)

SEED = "11" * 32
MK = signer_from_seed(SEED).multikey
NOW = "2026-06-01T00:00:00Z"

RESOLUTION = [
    pytest.param(case, id=f"{path.stem}/{case['name']}")
    for path in sorted((VECTORS / "didvh" / "resolution").glob("*.json"))
    for case in load(f"didvh/resolution/{path.name}")["cases"]
]


@pytest.mark.parametrize("case", RESOLUTION)
def test_resolution_vector(case: dict[str, Any]) -> None:
    i, expect = case["input"], case["expect"]
    got = resolve_did(i["did"], i["options"], now=i["now"], remote=i.get("remote", False))
    meta = got["didResolutionMetadata"]
    if expect.get("error"):
        assert meta["error"] == expect["error"]
        assert meta["problemDetails"].get("vhLog", {}).get("code") == expect.get("vhLogError")
        assert got["didDocument"] is None
    else:
        assert "error" not in meta
        assert same(got["didDocument"], expect["didDocument"])
        assert same(got["didDocumentMetadata"], expect["didDocumentMetadata"])
        # Integers stay integers (ttl, witness threshold).
        assert isinstance(got["didDocumentMetadata"]["ttl"], int)
        if "witness" in got["didDocumentMetadata"]:
            assert isinstance(got["didDocumentMetadata"]["witness"]["threshold"], int)
        assert sorted(w["code"] for w in meta.get("warnings", [])) == expect.get("warnings", [])
        assert meta.get("didLog") == expect.get("didLog")
        assert same(meta.get("didWitness"), expect.get("didWitness"))


def _attempt(fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return {"valid": True, **fn()}
    except DidVhError as e:
        return {"valid": False, "error": e.code}


SIMPLE: list[tuple[str, str, Callable[[Any], dict[str, Any]]]] = [
    ("ref.json", "ref", lambda v: {"kind": check_ref(v)}),
    ("src.json", "src", src_references),
    ("did-url.json", "didUrl", parse_did_url),
]


@pytest.mark.parametrize(
    ("case", "field", "fn"),
    [
        pytest.param(case, field, fn, id=f"{file}/{case['name']}")
        for file, field, fn in SIMPLE
        for case in load(f"didvh/{file}")["cases"]
    ],
)
def test_reference_vector(case: dict[str, Any], field: str, fn: Callable[[Any], dict[str, Any]]) -> None:
    got = _attempt(lambda: fn(case[field]))
    assert same(got, case["expect"])
    if "options" in got and "versionNumber" in got["options"]:
        assert isinstance(got["options"]["versionNumber"], int)


def test_create_update_resolve() -> None:
    document = {"id": "did:vh:{SCID}", "controller": "did:vh:{SCID}"}
    created = create_did(document, {"updateKeys": [MK]}, "2026-01-01T00:00:00Z", [SEED])
    assert parse_did(created["did"]) == created["scid"]
    line = json.loads(created["log"])
    assert line["parameters"]["method"] == "did:vh:1.0"
    assert "logVersion" not in line["parameters"]
    assert line["state"]["controller"] == created["did"]

    updated = update_did(created["log"], {"id": created["did"], "v": 2}, None, "2026-01-02T00:00:00Z", [SEED])
    r = resolve_did(created["did"], {"didLog": updated["log"]}, now=NOW)
    assert r["didDocument"] == {"id": created["did"], "v": 2}
    assert r["didDocumentMetadata"]["versionId"] == updated["versionId"]


def test_vh_log_and_did_vh_logs_are_not_interchangeable() -> None:
    vh = create_log({"id": "did:vh:{SCID}"}, {"updateKeys": [MK]}, "2026-01-01T00:00:00Z", [SEED])
    as_did = resolve_did(f"did:vh:{vh.scid}", {"didLog": vh.log}, now=NOW)
    assert as_did["didResolutionMetadata"]["error"] == "invalidDid"

    did = create_did({"id": "did:vh:{SCID}"}, {"updateKeys": [MK]}, "2026-01-01T00:00:00Z", [SEED])
    as_log: Any = resolve(did["log"], now=NOW)
    assert as_log["valid"] is False
    assert as_log["error"]["code"] == "unsupported-log-version"
