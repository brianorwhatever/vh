"""End-to-end create / update / witness / resolve paths, and the driver."""

from __future__ import annotations

import io
import json
from typing import Any

import pytest

from conftest import load, same
from vh_log import (
    ErrorCode,
    create_log,
    key_hash,
    parse_json,
    resolve,
    resolve_request,
    signer_from_seed,
    update_log,
    verify_log,
    witness_proof,
)
from vh_log.driver import serve

SEED_A = "90930409d492fb6cd7b50542c97fc6003fcedd59012b47ac114417373796eaaa"
SEED_B = "e0203d7f35f898d2c66bbc45b1d5ed23410af56e775d3601a1f4ee3f22987ea6"
WITNESS_SEED = "01" * 32
KEY_A = signer_from_seed(SEED_A).multikey
KEY_B = signer_from_seed(SEED_B).multikey
NOW = "2026-06-01T00:00:00Z"

SCENARIOS = load("generation.json")["scenarios"]


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s["name"])
def test_generation_scenario(scenario: dict[str, Any]) -> None:
    log, scid = "", ""
    version_ids: list[str] = []
    for step in scenario["steps"]:
        i = step["input"]
        if step["op"] == "create":
            created = create_log(i["state"], i.get("parameters"), i["versionTime"], i["signers"])
            log, scid, version_id = created.log, created.scid, created.version_id
            assert scid == step["expect"]["scid"]
        else:
            i = parse_json(json.dumps(i).replace("{SCID}", scid))
            updated = update_log(log, i["state"], i.get("parameters"), i["versionTime"], i["signers"])
            log, version_id = updated.log, updated.version_id
        assert version_id == step["expect"]["versionId"]
        assert same(parse_json(log.rstrip("\n").split("\n")[-1]), step["expect"]["line"])
        version_ids.append(version_id)
    witness = None
    if "witness" in scenario:
        witness = [
            {
                "versionId": version_ids[w["step"] - 1],
                "proof": [witness_proof(version_ids[w["step"] - 1], seed) for seed in w["seeds"]],
            }
            for w in scenario["witness"]
        ]
        assert same(witness, scenario["witnessFile"])
    result: Any = resolve(log, now=scenario["resolve"]["now"], witness=witness)
    assert result["valid"] and result["error"] is None
    assert same(result["state"], scenario["resolve"]["state"])
    assert result["metadata"]["versionId"] == scenario["resolve"]["versionId"]


def test_create_update_resolve_with_rotation_and_selection() -> None:
    created = create_log(
        {"id": "example:{SCID}"},
        {"updateKeys": [KEY_A], "nextKeyHashes": [key_hash(KEY_B)]},
        "2026-01-01T00:00:00Z",
        [SEED_A],
    )
    assert created.version_id.startswith("1-Qm")
    v2 = update_log(
        created.log,
        {"id": f"example:{created.scid}", "n": 2},
        {"updateKeys": [KEY_B], "nextKeyHashes": []},
        "2026-01-02T00:00:00Z",
        [SEED_B],
    )
    v3 = update_log(v2.log, {"id": f"example:{created.scid}", "n": 3}, None, "2026-01-03T00:00:00Z", [SEED_B])

    latest: Any = resolve(v3.log, now=NOW)
    assert latest["valid"]
    assert latest["state"]["n"] == 3
    assert latest["metadata"]["versionNumber"] == 3
    assert latest["metadata"]["scid"] == created.scid
    assert latest["metadata"]["updateKeys"] == [KEY_B]

    second: Any = resolve(v3.log, now=NOW, options={"versionTime": "2026-01-02T12:00:00Z"})
    assert second["metadata"]["versionId"] == v2.version_id

    missing: Any = resolve(v3.log, now=NOW, options={"versionNumber": 9})
    assert missing == {
        "valid": False,
        "error": {"code": "not-found", "version": None, "message": missing["error"]["message"]},
    }


def test_unauthorised_update_gives_partial_validity() -> None:
    created = create_log({"id": "x"}, {"updateKeys": [KEY_A]}, "2026-01-01T00:00:00Z", [SEED_A])
    bad = update_log(created.log, {"id": "y"}, None, "2026-01-02T00:00:00Z", [SEED_B])
    verified = verify_log(bad.log, now=NOW)
    assert len(verified.entries) == 1
    assert verified.failure is not None and verified.failure["code"] == ErrorCode.UNAUTHORIZED_KEY

    result: Any = resolve(bad.log, now=NOW)
    assert result["valid"] and result["firstInvalidVersion"] == 2
    assert [w["code"] for w in result["metadata"]["warnings"]] == ["invalid-entries"]
    assert resolve(bad.log, now=NOW, options={"versionNumber": 2})["error"]["code"] == "unauthorized-key"  # type: ignore[index]


def test_witnessing_and_deactivation() -> None:
    witness_id = "did:key:" + signer_from_seed(WITNESS_SEED).multikey
    created = create_log(
        {"id": "x"},
        {"updateKeys": [KEY_A], "witness": {"threshold": 1, "witnesses": [{"id": witness_id}]}},
        "2026-01-01T00:00:00Z",
        [SEED_A],
    )
    deactivated = update_log(
        created.log, {"id": "x"}, {"deactivated": True}, "2026-01-02T00:00:00Z", [SEED_A]
    )

    unwitnessed: Any = resolve(deactivated.log, now=NOW)
    assert unwitnessed["error"]["code"] == "witness-threshold-not-met"

    # A proof for the later entry covers the earlier one too.
    witness = [
        {"versionId": deactivated.version_id, "proof": [witness_proof(deactivated.version_id, WITNESS_SEED)]}
    ]
    result: Any = resolve(deactivated.log, now=NOW, witness=witness)
    assert result["valid"] and result["error"] is None
    assert result["metadata"]["deactivated"] is True
    assert result["metadata"]["witness"]["threshold"] == 1


def test_copies_and_retained_version_id() -> None:
    created = create_log({"id": "x"}, {"updateKeys": [KEY_A]}, "2026-01-01T00:00:00Z", [SEED_A])
    v2 = update_log(created.log, {"id": "y"}, None, "2026-01-02T00:00:00Z", [SEED_A])
    fork = update_log(created.log, {"id": "z"}, None, "2026-01-02T00:00:00Z", [SEED_A])

    behind: Any = resolve(v2.log, now=NOW, copies=[{"source": "w1", "log": created.log}])
    assert [c["status"] for c in behind["metadata"]["copies"]] == ["current", "behind"]

    forked: Any = resolve(v2.log, now=NOW, copies=[{"source": "w1", "log": fork.log}])
    assert forked["error"]["code"] == "fork-detected" and forked["error"]["fork"]["version"] == 2

    retained: Any = resolve(v2.log, now=NOW, retained_version_id=fork.version_id)
    assert retained["error"]["code"] == "fork-detected"


def test_driver_splits_on_newline_only() -> None:
    requests = [
        {"id": 1, "op": "jcs", "input": {"text": '{"b":"\u2028","a":1.0}'}},
        {"id": 2, "op": "nope", "input": {}},
        {"id": 3, "op": "hash", "input": {"data": "abc"}},
    ]
    stdin = io.BytesIO("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in requests).encode())
    stdout = io.BytesIO()
    serve(stdin, stdout)
    responses = [json.loads(line) for line in stdout.getvalue().decode().split("\n") if line]
    assert responses[0] == {"id": 1, "ok": True, "result": {"output": '{"a":1,"b":"\u2028"}'}}
    assert responses[1]["id"] == 2 and responses[1]["ok"] is False
    assert responses[2]["result"]["output"] == "QmatYkNGZnELf8cAGdyJpUca2PyY4szai3RHyyWofNY1pY"


def test_unsafe_log_lines_are_invalid_log() -> None:
    created = create_log({"id": "x"}, {"updateKeys": [KEY_A]}, "2026-01-01T00:00:00Z", [SEED_A])
    for bad in ('{"n":1e400}', '{"s":"\\ud800"}', '{"\\udc00":1}'):
        line = created.log.rstrip("\n").replace('"state":{"id":"x"}', f'"state":{bad}')
        verified = verify_log(created.log + line + "\n", now=NOW)
        assert verified.failure is not None
        assert (verified.failure["code"], verified.failure["version"]) == ("invalid-log", 2)


def test_null_witness_file_is_malformed() -> None:
    witness_id = "did:key:" + signer_from_seed(WITNESS_SEED).multikey
    created = create_log(
        {"id": "x"},
        {"updateKeys": [KEY_A], "witness": {"threshold": 1, "witnesses": [{"id": witness_id}]}},
        "2026-01-01T00:00:00Z",
        [SEED_A],
    )
    request = {"log": created.log, "now": NOW, "witness": None}
    result: Any = resolve_request(request)
    assert result["error"]["code"] == "invalid-witness-file"
    del request["witness"]
    result = resolve_request(request)
    assert result["error"]["code"] == "witness-threshold-not-met"
