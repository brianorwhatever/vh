from __future__ import annotations

from typing import Any

import pytest

from conftest import load
from vh_log import (
    base58btc_decode,
    base58btc_encode,
    canonicalize,
    check_sha256_multihash,
    compute_entry_hash,
    compute_scid,
    create_proof,
    format_number,
    hash_b58,
    key_hash,
    parse_json,
    public_key_from_multikey,
    signer_from_seed,
    to_json,
    verify_proof,
)
from vh_log.hashing import MultihashCheck

PRIMITIVES = load("primitives.json")


def cases(kind: str) -> list[Any]:
    return list(PRIMITIVES[kind])


@pytest.mark.parametrize("case", cases("jcs"))
def test_jcs_vectors(case: dict[str, str]) -> None:
    assert canonicalize(parse_json(case["text"])) == case["output"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1e21, "1e+21"),
        (1e20, "100000000000000000000"),
        (1e-7, "1e-7"),
        (1e-6, "0.000001"),
        (-0.0, "0"),
        (1.0, "1"),
        (123456789012345678, "123456789012345680"),
        (0.1, "0.1"),
        (-1.5e-9, "-1.5e-9"),
        (5e-324, "5e-324"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
    ],
)
def test_number_formatting(value: float, expected: str) -> None:
    assert format_number(value) == expected


def test_numbers_parse_as_doubles() -> None:
    assert parse_json("[1.0, 9007199254740993, -0]") == [1, 9007199254740992, 0]
    with pytest.raises(ValueError):
        parse_json("NaN")
    with pytest.raises(ValueError):
        canonicalize(float("inf"))


def test_keys_sort_by_utf16_code_units() -> None:
    # U+1F600 is D83D DE00 in UTF-16, which sorts before U+FB33 although its code point is larger.
    assert canonicalize({"דּ": 1, "\U0001f600": 2}) == '{"\U0001f600":2,"דּ":1}'


def test_string_escaping_matches_ecmascript() -> None:
    assert to_json("\u2028\x7f\x0f\ud800") == '"\u2028\x7f\\u000f\\ud800"'


@pytest.mark.parametrize("data", [b"", b"\0\0abc", bytes(range(256)), b"\xff" * 40])
def test_base58_round_trip(data: bytes) -> None:
    assert base58btc_decode(base58btc_encode(data)) == data


def test_base58_rejects_bad_characters() -> None:
    assert base58btc_decode("0OIl") is None


@pytest.mark.parametrize("case", cases("hash"))
def test_hash_vectors(case: dict[str, str]) -> None:
    assert hash_b58(case["data"]) == case["output"]
    assert check_sha256_multihash(case["output"]) is MultihashCheck.OK


@pytest.mark.parametrize("case", cases("multikey"))
def test_multikey_vectors(case: dict[str, str]) -> None:
    signer = signer_from_seed(case["seed"])
    assert signer.multikey == case["multikey"]
    assert public_key_from_multikey(signer.multikey) == signer.public_key


@pytest.mark.parametrize("case", cases("keyHash"))
def test_key_hash_vectors(case: dict[str, str]) -> None:
    assert key_hash(case["multikey"]) == case["output"]


@pytest.mark.parametrize("case", cases("scid"))
def test_scid_vectors(case: dict[str, Any]) -> None:
    assert compute_scid(case["entry"]) == case["scid"]


@pytest.mark.parametrize("case", cases("entryHash"))
def test_entry_hash_vectors(case: dict[str, Any]) -> None:
    assert compute_entry_hash(case["entry"], case["previousVersionId"]) == case["hash"]


@pytest.mark.parametrize("case", cases("sign"))
def test_sign_and_verify_vectors(case: dict[str, Any]) -> None:
    proof = create_proof(case["document"], case["seed"], created=case.get("created"))
    assert canonicalize(proof) == canonicalize(case["proof"])
    assert verify_proof(case["document"], case["proof"])
    assert not verify_proof({**case["document"], "extra": 1}, case["proof"])
    assert not verify_proof(case["document"], {**case["proof"], "proofPurpose": "authentication"})
