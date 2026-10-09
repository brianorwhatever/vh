"""Log verification: the per-entry checks of profile section 4 and witness verification."""

from __future__ import annotations

import calendar
import math
import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, TypedDict

from .encoding import public_key_from_multikey
from .errors import ErrorCode, ErrorReport, VHLogError
from .hashing import MultihashCheck, check_sha256_multihash, key_hash
from .jcs import parse_json, to_json
from .log import (
    ENTRY_FIELDS,
    LOG_VERSION,
    SCID_PLACEHOLDER,
    compute_entry_hash,
    compute_scid,
    parse_log_lines,
)
from .proof import multikey_from_verification_method, verify_proof

__all__ = [
    "ABSENT",
    "FUTURE_TOLERANCE_SECONDS",
    "Parameters",
    "VerifiedEntry",
    "VerifiedLog",
    "WitnessConfig",
    "is_safe_json",
    "is_watcher_url",
    "parse_version_time",
    "verify_log",
]

#: Seconds a ``versionTime`` may be ahead of the resolver's clock (profile section 4).
FUTURE_TOLERANCE_SECONDS: Final = 300
SUPPORTED_LOG_VERSIONS: Final = (LOG_VERSION,)

_VERSION_TIME = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:Z|\+00:00)")
_VERSION_ID = re.compile(r"([1-9][0-9]*)-([^-]+)", re.DOTALL)
_MONTH_DAYS: Final = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
_SURROGATE = re.compile("[\ud800-\udfff]")


class _Absent:
    """Marker for "no witness file supplied" (distinct from a JSON ``null``)."""

    def __repr__(self) -> str:
        return "ABSENT"


ABSENT: Final = _Absent()


class WitnessConfig(TypedDict):
    threshold: int
    witnesses: list[dict[str, Any]]


@dataclass(frozen=True)
class Parameters:
    """Parameters active after an entry."""

    log_version: str
    scid: str
    update_keys: list[str]
    next_key_hashes: list[str]
    #: ``None`` when the parameter is ``{}`` (no witnesses).
    witness: WitnessConfig | None
    watchers: list[str]
    deactivated: bool
    ttl: int


@dataclass(frozen=True)
class VerifiedEntry:
    entry: dict[str, Any]
    version_number: int
    #: Seconds since the epoch.
    time: int
    #: Parameters active after this entry.
    parameters: Parameters
    #: Witness list this entry must satisfy, or ``None`` if it needs no witnessing.
    witness_rule: WitnessConfig | None

    @property
    def version_id(self) -> str:
        return str(self.entry["versionId"])


@dataclass
class VerifiedLog:
    #: The valid (and witnessed) prefix of the log.
    entries: list[VerifiedEntry]
    #: The raw lines of the log, for copy comparison.
    lines: list[str]
    failure: ErrorReport | None = None

    @property
    def fully_valid(self) -> bool:
        return self.failure is None and len(self.entries) == len(self.lines)


def _is_number(v: object) -> bool:
    return isinstance(v, int | float) and not isinstance(v, bool)


def _is_integer(v: object) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True
    return isinstance(v, float) and v.is_integer()


def _is_string_list(v: object) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def _nfc(s: str) -> str:
    return unicodedata.normalize("NFC", s)


def is_watcher_url(value: str) -> bool:
    """Profile section 4: an ``http``/``https`` URL of printable ASCII (U+0021-U+007E) with an authority."""
    if not value or not all("\x21" <= c <= "\x7e" for c in value):
        return False
    for prefix in ("https://", "http://"):
        if value.startswith(prefix):
            rest = value[len(prefix) :]
            return rest != "" and rest[0] not in "/?#"
    return False


def _is_well_formed(s: str) -> bool:
    """True unless ``s`` has a lone surrogate (a surrogate pair stored as two code points is fine)."""
    if not _SURROGATE.search(s):
        return True
    try:
        s.encode("utf-16-le", "surrogatepass").decode("utf-16-le")
    except UnicodeDecodeError:
        return False
    return True


def is_safe_json(value: object) -> bool:
    """Profile section 4: I-JSON-safe -- finite numbers and strings/keys without lone surrogates."""
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, str):
        return _is_well_formed(value)
    if isinstance(value, list):
        return all(is_safe_json(v) for v in value)
    if isinstance(value, dict):
        return all(_is_well_formed(k) and is_safe_json(v) for k, v in value.items())
    return True


def _days_from_civil(y: int, m: int, d: int) -> int:
    """Days since 1970-01-01 in the proleptic Gregorian calendar (H. Hinnant's algorithm)."""
    y -= m <= 2
    era = y // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def parse_version_time(value: object) -> int | None:
    """Parses a ``versionTime``; returns epoch seconds, or ``None`` unless it is a whole-second UTC time."""
    if not isinstance(value, str):
        return None
    m = _VERSION_TIME.fullmatch(value)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(g) for g in m.groups())
    if not 1 <= mo <= 12 or h > 23 or mi > 59 or s > 59:
        return None
    leap = (y % 4 == 0 and y % 100 != 0) or y % 400 == 0
    if not 1 <= d <= (29 if mo == 2 and leap else _MONTH_DAYS[mo - 1]):
        return None
    return _days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s


def _to_epoch(now: int | datetime | str) -> int:
    if isinstance(now, datetime):
        return calendar.timegm(now.astimezone(UTC).utctimetuple())
    if isinstance(now, str):
        parsed = parse_version_time(now)
        if parsed is None:
            raise ValueError(f"invalid time {now!r}")
        return parsed
    return now


def _validate_witness(value: object, version: int) -> WitnessConfig | None:
    def fail(why: str) -> VHLogError:
        return VHLogError(ErrorCode.INVALID_PARAMETER, f"witness: {why}", version)

    if not isinstance(value, dict):
        raise fail("must be an object")
    if not value:
        return None
    threshold = value.get("threshold")
    witnesses = value.get("witnesses")
    if not isinstance(witnesses, list) or not witnesses:
        raise fail("witnesses must be a non-empty array")
    ids: set[str] = set()
    for w in witnesses:
        if not isinstance(w, dict) or not isinstance(w.get("id"), str):
            raise fail("each witness needs a string id")
        wid: str = w["id"]
        if not wid.startswith("did:key:") or public_key_from_multikey(wid[len("did:key:") :]) is None:
            raise fail(f"witness id {wid} is not an Ed25519 did:key")
        if _nfc(wid) in ids:
            raise fail(f"duplicate witness id {wid}")
        ids.add(_nfc(wid))
    if not _is_integer(threshold) or threshold < 1 or threshold > len(ids):  # type: ignore[operator]
        raise fail("threshold must be an integer between 1 and the number of witnesses")
    return {"threshold": int(threshold), "witnesses": witnesses}  # type: ignore[arg-type, return-value]


def _apply_parameters(raw: dict[str, Any], previous: Parameters | None, version: int) -> Parameters:
    """Applies an entry's ``parameters`` (Read step 1 and the pre-rotation rule of step 7)."""

    def invalid(msg: str) -> VHLogError:
        return VHLogError(ErrorCode.INVALID_PARAMETER, msg, version)

    for key, value in raw.items():
        if value is None:
            raise invalid(f"{key} must not be null")
    if previous is None and "logVersion" not in raw:
        raise VHLogError(ErrorCode.UNSUPPORTED_LOG_VERSION, "logVersion missing from first entry", 1)
    if "logVersion" in raw:
        log_version = raw["logVersion"]
        if not isinstance(log_version, str) or log_version not in SUPPORTED_LOG_VERSIONS:
            raise VHLogError(
                ErrorCode.UNSUPPORTED_LOG_VERSION, f"unsupported logVersion {to_json(log_version)}", version
            )
        if previous is not None and SUPPORTED_LOG_VERSIONS.index(log_version) < SUPPORTED_LOG_VERSIONS.index(
            previous.log_version
        ):
            raise VHLogError(ErrorCode.UNSUPPORTED_LOG_VERSION, "logVersion may not be lowered", version)
    if previous is None:
        if not isinstance(raw.get("scid"), str):
            raise invalid("scid missing from first entry")
        if "updateKeys" not in raw:
            raise invalid("updateKeys missing from first entry")
    elif "scid" in raw:
        raise invalid("scid may only appear in the first entry")
    if "updateKeys" in raw and (
        not _is_string_list(raw["updateKeys"])
        or any(public_key_from_multikey(k) is None for k in raw["updateKeys"])
    ):
        raise invalid("updateKeys must be an array of Ed25519 multikeys")
    if "nextKeyHashes" in raw and (
        not _is_string_list(raw["nextKeyHashes"])
        or any(check_sha256_multihash(h) is not MultihashCheck.OK for h in raw["nextKeyHashes"])
    ):
        raise invalid("nextKeyHashes must be an array of SHA-256 multihashes")
    if "witness" in raw:
        witness = _validate_witness(raw["witness"], version)
    else:
        witness = previous.witness if previous is not None else None
    if "watchers" in raw and (
        not _is_string_list(raw["watchers"]) or not all(is_watcher_url(u) for u in raw["watchers"])
    ):
        raise invalid("watchers must be an array of URLs")
    if "deactivated" in raw and not isinstance(raw["deactivated"], bool):
        raise invalid("deactivated must be a boolean")
    if "ttl" in raw:
        ttl = raw["ttl"]
        if not _is_integer(ttl) or ttl < 0 or ttl > 2**31:
            raise invalid("ttl must be an integer between 0 and 2^31")

    if previous is not None and previous.next_key_hashes:

        def violation(msg: str) -> VHLogError:
            return VHLogError(ErrorCode.PREROTATION_VIOLATION, msg, version)

        if "updateKeys" not in raw:
            raise violation("updateKeys must be explicit while pre-rotation is active")
        if "nextKeyHashes" not in raw:
            raise violation("nextKeyHashes must be explicit while pre-rotation is active")
        for key in raw["updateKeys"]:
            if key_hash(key) not in previous.next_key_hashes:
                raise violation(f"key {key} was not committed")

    if previous is None:
        return Parameters(
            log_version=raw["logVersion"],
            scid=raw["scid"],
            update_keys=raw["updateKeys"],
            next_key_hashes=raw.get("nextKeyHashes", []),
            witness=witness,
            watchers=raw.get("watchers", []),
            deactivated=raw.get("deactivated", False),
            ttl=int(raw.get("ttl", 3600)),
        )
    return Parameters(
        log_version=raw.get("logVersion", previous.log_version),
        scid=previous.scid,
        update_keys=raw.get("updateKeys", previous.update_keys),
        next_key_hashes=raw.get("nextKeyHashes", previous.next_key_hashes),
        witness=witness,
        watchers=raw.get("watchers", previous.watchers),
        deactivated=raw.get("deactivated", False),
        ttl=int(raw.get("ttl", previous.ttl)),
    )


def _verify_proofs(entry: dict[str, Any], active_keys: Sequence[str], version: int) -> None:
    proofs: list[Any] = entry["proof"]
    if not proofs:
        raise VHLogError(ErrorCode.INVALID_PROOF, "proof array is empty", version)
    document = {k: v for k, v in entry.items() if k != "proof"}
    for proof in proofs:
        multikey = (
            multikey_from_verification_method(proof.get("verificationMethod"))
            if isinstance(proof, dict)
            else None
        )
        if multikey is None:
            raise VHLogError(
                ErrorCode.INVALID_PROOF, "proof verificationMethod is not did:key:<mk>#<mk>", version
            )
        if multikey not in active_keys:
            raise VHLogError(ErrorCode.UNAUTHORIZED_KEY, f"{multikey} is not an active update key", version)
        if not verify_proof(document, proof):
            raise VHLogError(ErrorCode.INVALID_PROOF, "proof failed verification", version)


def _verify_version_id(entry: dict[str, Any], expected: int, previous_version_id: str) -> None:
    version_id: str = entry["versionId"]
    m = _VERSION_ID.fullmatch(version_id)
    if not m or int(m[1]) != expected:
        raise VHLogError(
            ErrorCode.INVALID_VERSION_ID, f"expected versionId {expected}-<hash>, got {version_id}", expected
        )
    check = check_sha256_multihash(m[2])
    if check is MultihashCheck.NOT_BASE58:
        raise VHLogError(ErrorCode.INVALID_VERSION_ID, "entry hash is not base58btc", expected)
    if check is MultihashCheck.UNSUPPORTED_ALGORITHM:
        raise VHLogError(ErrorCode.INVALID_HASH_ALGORITHM, "entry hash is not a SHA-256 multihash", expected)
    if compute_entry_hash(entry, previous_version_id) != m[2]:
        raise VHLogError(ErrorCode.ENTRY_HASH_MISMATCH, "entry hash does not match", expected)


def _verify_scid(entry: dict[str, Any], scid: str) -> None:
    check = check_sha256_multihash(scid)
    if check is MultihashCheck.UNSUPPORTED_ALGORITHM:
        raise VHLogError(ErrorCode.INVALID_HASH_ALGORITHM, "SCID is not a SHA-256 multihash", 1)
    if check is MultihashCheck.NOT_BASE58:
        raise VHLogError(ErrorCode.SCID_MISMATCH, "SCID is not base58btc", 1)
    rest = {k: v for k, v in entry.items() if k != "proof"}
    # Textual replacement on the serialised entry, as the spec describes.
    text = to_json({**rest, "versionId": SCID_PLACEHOLDER}).replace(scid, SCID_PLACEHOLDER)
    if compute_scid(parse_json(text)) != scid:
        raise VHLogError(ErrorCode.SCID_MISMATCH, "SCID does not match", 1)


def _verify_entry(raw: dict[str, Any], previous: VerifiedEntry | None, now: int) -> VerifiedEntry:
    """Runs the per-entry checks (profile section 4, steps 1-7) on one parsed line."""
    version = previous.version_number + 1 if previous else 1
    if previous is not None and previous.parameters.deactivated:
        raise VHLogError(ErrorCode.ENTRY_AFTER_DEACTIVATION, "entry follows a deactivating entry", version)
    if (
        len(raw) != len(ENTRY_FIELDS)
        or not all(k in raw for k in ENTRY_FIELDS)
        or not isinstance(raw["versionId"], str)
        or not isinstance(raw["versionTime"], str)
        or not isinstance(raw["parameters"], dict)
        or not isinstance(raw["state"], dict)
        or not isinstance(raw["proof"], list)
    ):
        raise VHLogError(
            ErrorCode.INVALID_ENTRY, "entry does not have the required properties and types", version
        )
    raw_parameters: dict[str, Any] = raw["parameters"]
    parameters = _apply_parameters(raw_parameters, previous.parameters if previous else None, version)

    if previous is None:
        active_keys = parameters.update_keys
        witness_rule = parameters.witness
    else:
        before = previous.parameters
        active_keys = parameters.update_keys if before.next_key_hashes else before.update_keys
        enables_witnesses = "witness" in raw_parameters and before.witness is None
        witness_rule = parameters.witness if enables_witnesses else before.witness
    _verify_proofs(raw, active_keys, version)
    _verify_version_id(raw, version, previous.version_id if previous else parameters.scid)

    time = parse_version_time(raw["versionTime"])
    if time is None:
        raise VHLogError(ErrorCode.INVALID_VERSION_TIME, f"invalid versionTime {raw['versionTime']}", version)
    if previous is not None and time <= previous.time:
        raise VHLogError(
            ErrorCode.INVALID_VERSION_TIME, "versionTime must be later than the previous entry's", version
        )
    if time > now + FUTURE_TOLERANCE_SECONDS:
        raise VHLogError(ErrorCode.FUTURE_VERSION_TIME, "versionTime is in the future", version)
    if previous is None:
        _verify_scid(raw, parameters.scid)

    return VerifiedEntry(raw, version, time, parameters, witness_rule)


def _as_witness_file(witness: object) -> list[dict[str, Any]] | None:
    if not isinstance(witness, list):
        return None
    for item in witness:
        if not isinstance(item, dict) or not isinstance(item.get("versionId"), str):
            return None
        if not isinstance(item.get("proof"), list):
            return None
    return witness


@dataclass
class _Approval:
    id: str
    index: int
    proof: Any
    version_id: str


def _check_witnesses(entries: list[VerifiedEntry], witness: object) -> tuple[int, VHLogError] | None:
    """Returns the index of the first entry that is not witnessed, with its error, or ``None``."""
    first = next((i for i, e in enumerate(entries) if e.witness_rule is not None), -1)
    if first == -1:
        return None
    file = [] if witness is ABSENT else _as_witness_file(witness)
    if file is None:
        return first, VHLogError(ErrorCode.INVALID_WITNESS_FILE, "witness file is malformed", first + 1)
    position = {e.version_id: i for i, e in enumerate(entries)}
    # A proof for entry j approves every entry <= j.
    approvals: list[_Approval] = []
    for record in file:
        index = position.get(record["versionId"])
        if index is None:
            continue
        for proof in record["proof"]:
            multikey = (
                multikey_from_verification_method(proof.get("verificationMethod"))
                if isinstance(proof, dict)
                else None
            )
            if multikey is not None:
                approvals.append(_Approval(_nfc(f"did:key:{multikey}"), index, proof, record["versionId"]))
    verified: dict[int, bool] = {}

    def is_valid(a: _Approval) -> bool:
        key = id(a.proof)
        if key not in verified:
            verified[key] = verify_proof({"versionId": a.version_id}, a.proof)
        return verified[key]

    for i in range(first, len(entries)):
        rule = entries[i].witness_rule
        if rule is None:
            continue
        ids = {_nfc(w["id"]) for w in rule["witnesses"]}
        approved: set[str] = set()
        for a in approvals:
            if a.index >= i and a.id in ids and a.id not in approved and is_valid(a):
                approved.add(a.id)
        if len(approved) < rule["threshold"]:
            return i, VHLogError(
                ErrorCode.WITNESS_THRESHOLD_NOT_MET,
                f"entry {i + 1} has {len(approved)} of {rule['threshold']} required witness approvals",
                i + 1,
            )
    return None


def verify_log(log: str, witness: object = ABSENT, now: int | datetime | str | None = None) -> VerifiedLog:
    """Verifies a whole log, returning its valid, witnessed prefix and the first failure.

    ``witness`` is the parsed witness file (``ABSENT`` if there is none). ``now`` is the
    resolver's clock: epoch seconds, a ``datetime`` or a ``versionTime`` string (default: now).
    """
    clock = _to_epoch(now) if now is not None else int(datetime.now(UTC).timestamp())
    lines = parse_log_lines(log)
    entries: list[VerifiedEntry] = []
    if not lines:
        return VerifiedLog(
            entries, lines, {"code": ErrorCode.INVALID_LOG.value, "version": None, "message": "log is empty"}
        )
    failure: ErrorReport | None = None
    for i, line in enumerate(lines):
        try:
            try:
                raw = parse_json(line)
            except ValueError:
                raise VHLogError(ErrorCode.INVALID_LOG, f"line {i + 1} is not JSON", i + 1) from None
            if not isinstance(raw, dict):
                raise VHLogError(ErrorCode.INVALID_LOG, f"line {i + 1} is not a JSON object", i + 1)
            if not is_safe_json(raw):
                raise VHLogError(
                    ErrorCode.INVALID_LOG, f"line {i + 1} has a non-finite number or a lone surrogate", i + 1
                )
            entries.append(_verify_entry(raw, entries[-1] if entries else None, clock))
        except VHLogError as e:
            failure = e.to_report()
            break
    unwitnessed = _check_witnesses(entries, witness)
    if unwitnessed is not None:
        index, error = unwitnessed
        del entries[index:]
        failure = error.to_report()
    return VerifiedLog(entries, lines, failure)
