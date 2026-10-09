"""Log Controller operations: create, update and witness (profile section 5)."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, TypedDict

from .hashing import hash_b58
from .jcs import canonicalize, parse_json, to_json
from .proof import Proof, create_proof

__all__ = [
    "ENTRY_FIELDS",
    "LOG_VERSION",
    "SCID_PLACEHOLDER",
    "CreatedLog",
    "LogEntry",
    "UpdatedLog",
    "compute_entry_hash",
    "compute_scid",
    "create_log",
    "parse_log_lines",
    "seal_entry",
    "seal_genesis",
    "serialize_entry",
    "update_log",
    "witness_proof",
]

SCID_PLACEHOLDER = "{SCID}"
LOG_VERSION = "vh-log:1.0"
#: Field order of a serialised entry.
ENTRY_FIELDS = ("versionId", "versionTime", "parameters", "state", "proof")


class LogEntry(TypedDict):
    versionId: str
    versionTime: str
    parameters: dict[str, Any]
    state: dict[str, Any]
    proof: list[Proof]


def _without_proof(entry: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in entry.items() if k != "proof"}


def compute_scid(preliminary: Mapping[str, Any]) -> str:
    """SCID of a preliminary entry (placeholders in place, ``versionId`` = ``{SCID}``)."""
    return hash_b58(canonicalize(_without_proof(preliminary)))


def compute_entry_hash(entry: Mapping[str, Any], previous_version_id: str) -> str:
    """Entry hash: the entry without ``proof``, with ``versionId`` set to its predecessor's."""
    return hash_b58(canonicalize({**_without_proof(entry), "versionId": previous_version_id}))


def serialize_entry(entry: Mapping[str, Any]) -> str:
    """Compact JSON with the field order from profile section 5, plus the trailing newline."""
    ordered = {k: entry[k] for k in ENTRY_FIELDS if k in entry}
    ordered.update({k: v for k, v in entry.items() if k not in ordered})
    return to_json(ordered) + "\n"


def parse_log_lines(log: str) -> list[str]:
    """Splits a JSON Lines log on ``\\n`` only, dropping the final empty line."""
    lines = log.split("\n")
    if lines[-1] == "":
        lines.pop()
    return lines


def _sign(
    document: Mapping[str, Any], signers: Sequence[str | bytes], proof_options: Mapping[str, Any] | None
) -> list[Proof]:
    options = dict(proof_options or {})
    created = options.pop("created", None)
    if created is None:
        created = document.get("versionTime")
    return [create_proof(document, seed, created=created, **options) for seed in signers]


def seal_genesis(
    body: Mapping[str, Any],
    signers: Sequence[str | bytes],
    *,
    proof_options: Mapping[str, Any] | None = None,
    version_number: int | str | None = None,
    entry_hash: str | None = None,
) -> tuple[LogEntry, str]:
    """Turns a genesis body into a signed first entry; returns ``(entry, scid)``.

    The body is not validated, so tests can seal deliberately invalid entries.
    ``proof_options`` (keyword arguments of :func:`create_proof`), ``version_number``
    and ``entry_hash`` overrides exist to build invalid test vectors.
    """
    preliminary = {**body, "versionId": SCID_PLACEHOLDER}
    scid = compute_scid(preliminary)
    replaced: dict[str, Any] = parse_json(to_json(preliminary).replace(SCID_PLACEHOLDER, scid))
    hash_ = entry_hash if entry_hash is not None else compute_entry_hash(replaced, scid)
    number = 1 if version_number is None else version_number
    document = {**replaced, "versionId": f"{number}-{hash_}"}
    entry: Any = {**document, "proof": _sign(document, signers, proof_options)}
    return entry, scid


def _parse_int_prefix(text: str) -> int | None:
    """ECMAScript ``parseInt(text, 10)``, returning ``None`` for NaN."""
    match = re.match(r"\s*([+-]?[0-9]+)", text)
    return int(match[1]) if match else None


def seal_entry(
    body: Mapping[str, Any],
    previous_version_id: str,
    signers: Sequence[str | bytes],
    *,
    proof_options: Mapping[str, Any] | None = None,
    version_number: int | str | None = None,
    entry_hash: str | None = None,
) -> LogEntry:
    """Signs a later entry whose predecessor has ``previous_version_id``."""
    if version_number is None:
        previous = _parse_int_prefix(previous_version_id.split("-")[0])
        version_number = "NaN" if previous is None else previous + 1
    if entry_hash is None:
        entry_hash = compute_entry_hash({**body, "versionId": previous_version_id}, previous_version_id)
    document = {**body, "versionId": f"{version_number}-{entry_hash}"}
    entry: Any = {**document, "proof": _sign(document, signers, proof_options)}
    return entry  # type: ignore[no-any-return]


@dataclass(frozen=True)
class CreatedLog:
    log: str
    scid: str
    version_id: str


@dataclass(frozen=True)
class UpdatedLog:
    log: str
    version_id: str


def create_log(
    state: Mapping[str, Any],
    parameters: Mapping[str, Any] | None,
    version_time: str,
    signers: Sequence[str | bytes],
) -> CreatedLog:
    """Creates a one-entry log. ``scid`` and ``logVersion`` parameters are added if absent.

    ``{SCID}`` placeholders in ``state`` and ``parameters`` are replaced by the SCID.
    ``signers`` are Ed25519 seeds (hex or bytes); each adds one proof, in order.
    """
    params = dict(parameters or {})
    params.setdefault("logVersion", LOG_VERSION)
    params.setdefault("scid", SCID_PLACEHOLDER)
    entry, scid = seal_genesis(
        {"versionId": SCID_PLACEHOLDER, "versionTime": version_time, "parameters": params, "state": state},
        signers,
    )
    return CreatedLog(serialize_entry(entry), scid, entry["versionId"])


def update_log(
    log: str,
    state: Mapping[str, Any],
    parameters: Mapping[str, Any] | None,
    version_time: str,
    signers: Sequence[str | bytes],
) -> UpdatedLog:
    """Appends a signed entry to ``log``, chaining from its last line.

    Use ``parameters={"deactivated": True}`` to deactivate. Inputs are not validated.
    """
    lines = parse_log_lines(log)
    if not lines:
        raise ValueError("cannot update an empty log")
    previous = parse_json(lines[-1])
    previous_version_id = previous["versionId"]
    entry = seal_entry(
        {
            "versionId": previous_version_id,
            "versionTime": version_time,
            "parameters": dict(parameters) if parameters is not None else {},
            "state": state,
        },
        previous_version_id,
        signers,
    )
    prefix = log if log.endswith("\n") or log == "" else log + "\n"
    return UpdatedLog(prefix + serialize_entry(entry), entry["versionId"])


def witness_proof(version_id: str, seed: str | bytes, created: str | None = None) -> Proof:
    """A witness proof: eddsa-jcs-2022 over ``{"versionId": version_id}`` (profile section 3)."""
    return create_proof({"versionId": version_id}, seed, created=created)
