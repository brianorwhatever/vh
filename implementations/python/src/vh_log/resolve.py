"""Resolution: version selection, partial validity, copies and retained versionIds (profile section 4).

Results use the JSON shape of the interop protocol (camelCase keys), so they can
be serialised directly.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Final, Literal, NotRequired, TypedDict

from .errors import ErrorCode, ErrorReport, VHLogError
from .jcs import parse_json
from .verify import (
    ABSENT,
    VerifiedEntry,
    VerifiedLog,
    WitnessConfig,
    _is_integer,
    _to_epoch,
    parse_version_time,
    verify_log,
)

__all__ = [
    "CopyInput",
    "CopyReport",
    "CopyStatus",
    "ResolutionMetadata",
    "ResolveFailure",
    "ResolveOptions",
    "ResolveResult",
    "ResolveSuccess",
    "Warning",
    "resolve",
    "resolve_request",
]

PRIMARY: Final = "primary"
_OPTION_KEYS: Final = ("versionId", "versionTime", "versionNumber", "minCopies")
_SELECTORS: Final = ("versionId", "versionTime", "versionNumber")
_RETAINED: Final = re.compile(r"([1-9][0-9]*)-")

CopyStatus = Literal["current", "behind", "invalid", "unavailable"]


class ResolveOptions(TypedDict, total=False):
    versionId: str
    versionTime: str
    versionNumber: int
    minCopies: int


class CopyInput(TypedDict, total=False):
    """A watcher copy: either ``{source, log, witness?}`` or ``{source, unavailable}``."""

    source: str
    log: str
    witness: Any
    unavailable: str


class Warning(TypedDict):
    code: str
    message: str
    source: NotRequired[str]


class CopyReport(TypedDict):
    source: str
    versionId: NotRequired[str]
    status: CopyStatus


class ResolutionMetadata(TypedDict):
    versionId: str
    versionTime: str
    versionNumber: int
    created: str
    updated: str
    scid: str
    deactivated: bool
    ttl: int
    witness: WitnessConfig | None
    watchers: list[str]
    updateKeys: list[str]
    nextKeyHashes: list[str]
    copies: NotRequired[list[CopyReport]]
    warnings: list[Warning]


class ResolveSuccess(TypedDict):
    valid: Literal[True]
    state: dict[str, Any]
    metadata: ResolutionMetadata
    firstInvalidVersion: int | None
    error: ErrorReport | None


class ResolveFailure(TypedDict):
    valid: Literal[False]
    error: ErrorReport


ResolveResult = ResolveSuccess | ResolveFailure


def _validate_options(options: Mapping[str, Any]) -> None:
    for key in options:
        if key not in _OPTION_KEYS:
            raise VHLogError(ErrorCode.INVALID_OPTION, f"unsupported option {key}")
    if sum(1 for k in _SELECTORS if k in options) > 1:
        raise VHLogError(ErrorCode.INVALID_OPTION, "at most one version selector may be given")
    if "versionId" in options and not isinstance(options["versionId"], str):
        raise VHLogError(ErrorCode.INVALID_OPTION, "versionId must be a string")
    if "versionTime" in options and parse_version_time(options["versionTime"]) is None:
        raise VHLogError(ErrorCode.INVALID_OPTION, "versionTime must be a whole-second UTC ISO 8601 time")
    for key in ("versionNumber", "minCopies"):
        if key in options and (not _is_integer(options[key]) or options[key] < 1):
            raise VHLogError(ErrorCode.INVALID_OPTION, f"{key} must be a positive integer")


def _line_value(lines: Sequence[str], index: int) -> Any:
    if not 0 <= index < len(lines):
        return None
    try:
        return parse_json(lines[index])
    except ValueError:
        return None


def _line_version_id(lines: Sequence[str], index: int) -> str | None:
    value = _line_value(lines, index)
    version_id = value.get("versionId") if isinstance(value, dict) else None
    return version_id if isinstance(version_id, str) else None


def _select_entry(verified: VerifiedLog, options: Mapping[str, Any]) -> VerifiedEntry:
    """Picks the target entry. A target at or after the first invalid entry fails with its error."""
    entries, lines, failure = verified.entries, verified.lines, verified.failure

    def invalid() -> VHLogError:
        assert failure is not None
        return VHLogError(
            ErrorCode(failure["code"]),
            f"requested version is invalid: {failure['message']}",
            failure["version"],
        )

    if "versionId" in options:
        target_id = options["versionId"]
        for e in entries:
            if e.version_id == target_id:
                return e
        for i in range(len(entries), len(lines)):
            if _line_version_id(lines, i) == target_id:
                raise invalid()
        raise VHLogError(ErrorCode.NOT_FOUND, f"no entry with versionId {target_id}")
    if "versionNumber" in options:
        number = int(options["versionNumber"])
        if number <= len(entries):
            return entries[number - 1]
        if number <= len(lines):
            raise invalid()
        raise VHLogError(ErrorCode.NOT_FOUND, f"no entry with version number {number}")
    if "versionTime" in options:
        time = parse_version_time(options["versionTime"])
        assert time is not None
        if failure is not None and len(entries) < len(lines):
            value = _line_value(lines, len(entries))
            first_invalid = parse_version_time(value.get("versionTime") if isinstance(value, dict) else None)
            if first_invalid is not None and first_invalid <= time:
                raise invalid()
        for e in reversed(entries):
            if e.time <= time:
                return e
        raise VHLogError(ErrorCode.NOT_FOUND, f"no entry active at {options['versionTime']}")
    return entries[-1]


def _build_result(
    verified: VerifiedLog,
    options: Mapping[str, Any],
    warnings: list[Warning],
    copies: list[CopyReport] | None = None,
) -> ResolveSuccess:
    target = _select_entry(verified, options)
    first = verified.entries[0]
    last = verified.entries[-1]
    failure = verified.failure
    if failure is not None:
        warnings.append(
            {
                "code": "invalid-entries",
                "message": (
                    f"entries from version {failure['version']} fail verification: {failure['message']}"
                ),
            }
        )
    metadata: ResolutionMetadata = {
        "versionId": target.version_id,
        "versionTime": target.entry["versionTime"],
        "versionNumber": target.version_number,
        "created": first.entry["versionTime"],
        "updated": last.entry["versionTime"],
        "scid": first.parameters.scid,
        "deactivated": last.parameters.deactivated,
        "ttl": last.parameters.ttl,
        "witness": last.parameters.witness,
        "watchers": last.parameters.watchers,
        "updateKeys": target.parameters.update_keys,
        "nextKeyHashes": target.parameters.next_key_hashes,
        "warnings": warnings,
    }
    if copies is not None:
        metadata["copies"] = copies
    return {
        "valid": True,
        "state": target.entry["state"],
        "metadata": metadata,
        "firstInvalidVersion": len(verified.entries) + 1 if failure is not None else None,
        "error": failure,
    }


def _check_retained(reference: VerifiedLog, source: str, retained: object, warnings: list[Warning]) -> None:
    m = _RETAINED.match(retained) if isinstance(retained, str) else None
    if not m:
        raise VHLogError(ErrorCode.INVALID_OPTION, "retainedVersionId is not a versionId")
    n = int(m[1])
    if len(reference.entries) < n:
        warnings.append(
            {
                "code": "retained-version-not-found",
                "message": (
                    f"the log has {len(reference.entries)} valid entries, fewer than retained version {n}"
                ),
            }
        )
        return
    version_id = reference.entries[n - 1].version_id
    if version_id != retained:
        assert isinstance(retained, str)
        raise VHLogError(
            ErrorCode.FORK_DETECTED,
            f"retained versionId differs at version {n}",
            n,
            {
                "version": n,
                "copies": [
                    {"source": "retained", "versionId": retained},
                    {"source": source, "versionId": version_id},
                ],
            },
        )


def _divergence(a: Sequence[str], b: Sequence[str]) -> int:
    """First version number at which two logs' versionIds differ."""
    n = min(len(a), len(b))
    for i in range(n):
        if _line_version_id(a, i) != _line_version_id(b, i):
            return i + 1
    return n + 1


def _resolve_copies(request: Mapping[str, Any], now: int, options: Mapping[str, Any]) -> ResolveSuccess:
    """Comparing Copies of a Log, with copies supplied in the request instead of fetched."""
    primary: dict[str, Any] = {"source": PRIMARY, "log": request.get("log")}
    if "witness" in request:
        primary["witness"] = request["witness"]
    all_copies: list[Mapping[str, Any]] = [primary, *(request.get("copies") or [])]
    warnings: list[Warning] = []
    status: dict[int, CopyStatus] = {}
    cache: dict[int, VerifiedLog] = {}

    def verify(i: int) -> VerifiedLog:
        if i not in cache:
            c = all_copies[i]
            cache[i] = verify_log(c["log"], c.get("witness", ABSENT), now)
        return cache[i]

    def mark_invalid(i: int) -> None:
        status[i] = "invalid"
        f = verify(i).failure
        version = "?" if f is None or f["version"] is None else f["version"]
        warnings.append(
            {
                "code": "copy-invalid",
                "source": all_copies[i]["source"],
                "message": f"copy fails verification at version {version}: {f['message'] if f else ''}",
            }
        )

    for i, c in enumerate(all_copies):
        if "unavailable" in c:
            status[i] = "unavailable"
            warnings.append(
                {"code": "copy-unavailable", "source": c["source"], "message": str(c["unavailable"])}
            )

    ref = -1
    for i in range(len(all_copies)):
        if ref != -1:
            break
        if i in status:
            continue
        if verify(i).fully_valid:
            ref = i
        else:
            mark_invalid(i)
    if ref == -1:
        failure = verify(0).failure
        raise _ReportError(
            failure or {"code": ErrorCode.INVALID_LOG.value, "version": None, "message": "no copy verifies"}
        )

    matched = {ref}
    for i in range(len(all_copies)):
        if i in status or i in matched:
            continue
        reference = verify(ref)
        ref_lines = reference.lines
        copy_lines = verify(i).lines
        if not copy_lines:
            mark_invalid(i)
            continue
        extends = same = False
        if len(copy_lines) <= len(ref_lines):
            same = (
                _line_version_id(copy_lines, len(copy_lines) - 1)
                == reference.entries[len(copy_lines) - 1].version_id
            )
        else:
            extends = _line_version_id(copy_lines, len(ref_lines) - 1) == reference.entries[-1].version_id
        if same:
            matched.add(i)
        elif extends:
            if verify(i).fully_valid:
                matched.add(i)
                ref = i
            else:
                mark_invalid(i)
        elif not verify(i).fully_valid:
            mark_invalid(i)
        else:
            version = _divergence(ref_lines, copy_lines)
            raise VHLogError(
                ErrorCode.FORK_DETECTED,
                f"copies diverge at version {version}",
                version,
                {
                    "version": version,
                    "copies": [
                        {
                            "source": all_copies[ref]["source"],
                            "versionId": _line_version_id(ref_lines, version - 1) or "",
                        },
                        {
                            "source": all_copies[i]["source"],
                            "versionId": _line_version_id(copy_lines, version - 1) or "",
                        },
                    ],
                },
            )

    reference = verify(ref)
    if "retainedVersionId" in request:
        _check_retained(reference, all_copies[ref]["source"], request["retainedVersionId"], warnings)
    copies: list[CopyReport] = []
    for i, c in enumerate(all_copies):
        if i in status:
            s = status[i]
            report: CopyReport = {"source": c["source"], "status": s}
            if s != "unavailable":
                lines = verify(i).lines
                last_id = _line_version_id(lines, len(lines) - 1)
                if last_id is not None:
                    report["versionId"] = last_id
            copies.append(report)
            continue
        lines = verify(i).lines
        behind = len(reference.lines) - len(lines)
        if behind > 0:
            warnings.append(
                {"code": "copy-behind", "source": c["source"], "message": f"copy is {behind} entries behind"}
            )
        copies.append(
            {
                "source": c["source"],
                "versionId": _line_version_id(lines, len(lines) - 1) or "",
                "status": "behind" if behind > 0 else "current",
            }
        )
    usable = sum(1 for c in copies if c["status"] in ("current", "behind"))
    min_copies = options.get("minCopies", 1)
    if usable < min_copies:
        raise VHLogError(ErrorCode.MIN_COPIES_NOT_MET, f"{usable} matching copies, {min_copies} required")
    return _build_result(reference, options, warnings, copies)


class _ReportError(Exception):
    """Carries a failure report that is not tied to a newly raised :class:`VHLogError`."""

    def __init__(self, report: ErrorReport) -> None:
        super().__init__(report["message"])
        self.report = report


def resolve_request(request: Mapping[str, Any]) -> ResolveResult:
    """Resolves a log described by a protocol ``resolve`` input object.

    Keys: ``log``, ``now``, and optionally ``witness``, ``options``, ``copies`` and
    ``retainedVersionId``. A missing ``witness`` means "no witness file"; a present
    but malformed one fails with ``invalid-witness-file`` when witnessing is required.
    """
    try:
        now = parse_version_time(request.get("now"))
        if now is None:
            raise VHLogError(ErrorCode.INVALID_OPTION, "now must be a whole-second UTC ISO 8601 time")
        options = request.get("options")
        if options is None:
            options = {}
        if not isinstance(options, Mapping):
            raise VHLogError(ErrorCode.INVALID_OPTION, "options must be an object")
        _validate_options(options)
        if "copies" in request or options.get("minCopies", 1) > 1:
            return _resolve_copies(request, now, options)
        verified = verify_log(request["log"], request.get("witness", ABSENT), now)
        if not verified.entries:
            assert verified.failure is not None
            return {"valid": False, "error": verified.failure}
        warnings: list[Warning] = []
        if "retainedVersionId" in request:
            _check_retained(verified, PRIMARY, request["retainedVersionId"], warnings)
        return _build_result(verified, options, warnings)
    except VHLogError as e:
        return {"valid": False, "error": e.to_report()}
    except _ReportError as f:
        return {"valid": False, "error": f.report}


def resolve(
    log: str,
    *,
    now: datetime | str | int,
    witness: Sequence[Any] | None = None,
    options: ResolveOptions | None = None,
    copies: Sequence[CopyInput] | None = None,
    retained_version_id: str | None = None,
) -> ResolveResult:
    """Resolves ``log`` (JSON Lines text) and returns the protocol-shaped result.

    ``now`` is the resolver's clock (``datetime``, ``versionTime`` string or epoch seconds).
    ``witness`` is the parsed witness file, ``copies`` are watcher copies to compare, and
    ``retained_version_id`` is a versionId the caller saw earlier. Verification failures are
    reported in the result (``valid: False``), not raised.
    """
    epoch = _to_epoch(now)
    request: dict[str, Any] = {
        "log": log,
        "now": datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if witness is not None:
        request["witness"] = witness
    if options is not None:
        request["options"] = options
    if copies is not None:
        request["copies"] = copies
    if retained_version_id is not None:
        request["retainedVersionId"] = retained_version_id
    return resolve_request(request)
