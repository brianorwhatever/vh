"""Independent published corpora, not the shared TypeScript oracle."""

import json
from pathlib import Path

from vh_log.ed25519 import verify_signature

DIRECTORY = Path(__file__).resolve().parents[3] / "vectors" / "ed25519"
REJECT = {"low_order_A", "low_order_R", "non_canonical_A", "non_canonical_R", "low_order_residue"}


def test_cctv() -> None:
    vectors = json.loads((DIRECTORY / "cctv.json").read_text())
    for v in vectors:
        expected = not REJECT.intersection(v["flags"] or [])
        assert (
            verify_signature(bytes.fromhex(v["key"]), v["msg"].encode(), bytes.fromhex(v["sig"])) == expected
        ), v


def test_wycheproof() -> None:
    corpus = json.loads((DIRECTORY / "wycheproof.json").read_text())
    for group in corpus["testGroups"]:
        for v in group["tests"]:
            expected = v["result"] == "valid"
            assert (
                verify_signature(
                    bytes.fromhex(group["publicKey"]["pk"]), bytes.fromhex(v["msg"]), bytes.fromhex(v["sig"])
                )
                == expected
            ), v
