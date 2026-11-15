"""did:vh (``docs/didvh-profile.md``).

A did:vh DID log has the same format and verification as a VH-Log log (did:vh and
VH-Log both come from did:webvh), so the log is verified by the VH-Log code with the
did:vh :class:`~vh_log.verify.Specialisation`. This module adds the DID syntax, the
``srcLog``/``srcWitness`` and DID URL rules, the resolution options, and DID
Resolution metadata and errors.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Final, Literal

from .errors import ErrorCode, ErrorReport, VHLogError
from .log import create_log, parse_log_lines, update_log
from .resolve import resolve_request
from .verify import Specialisation as _Specialisation
from .verify import _is_integer, is_watcher_url, parse_version_time, verify_log

__all__ = [
    "DID_PREFIX",
    "DID_VH",
    "DID_VH_METHOD",
    "DidVhError",
    "check_ref",
    "create_did",
    "did_vh_specialisation",
    "parse_did",
    "parse_did_url",
    "resolve_did",
    "src_references",
    "update_did",
]

DID_VH_METHOD: Final = "did:vh:1.0"
DID_PREFIX: Final = "did:vh:"
#: A well-formed ``method`` value: ``did:vh:<major>.<minor>``, no leading zeros.
_METHOD_SYNTAX: Final = re.compile(r"did:vh:(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
_SCID: Final = re.compile(r"[1-9A-HJ-NP-Za-km-z]{46}")

RefKind = Literal["web", "loopback", "file", "other"]


class DidVhError(Exception):
    """A did:vh error: a DID Resolution error code, and the VH-Log error behind it, if any."""

    def __init__(self, code: str, message: str, vh_log: ErrorReport | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.vh_log = vh_log


# ---------------------------------------------------------------- the DID


def parse_did(did: object) -> str | None:
    """The SCID of a did:vh DID, or ``None`` if ``did`` does not match the ABNF."""
    if not isinstance(did, str) or not did.startswith(DID_PREFIX):
        return None
    scid = did[len(DID_PREFIX) :]
    return scid if _SCID.fullmatch(scid) else None


def did_vh_specialisation(expected_scid: str | None = None) -> _Specialisation:
    """The did:vh specialisation of VH-Log.

    ``method`` instead of ``logVersion``, a closed parameter set, and ``state.id`` =
    ``did:vh:<SCID>`` in every entry. With ``expected_scid``, the log's SCID must also be
    that of the DID being resolved.
    """

    def check_state(state: dict[str, Any], scid: str, version: int) -> None:
        if expected_scid is not None and scid != expected_scid:
            raise VHLogError(
                ErrorCode.INVALID_STATE,
                f"the log is for did:vh:{scid}, not did:vh:{expected_scid}",
                version,
            )
        if state.get("id") != DID_PREFIX + scid:
            raise VHLogError(ErrorCode.INVALID_STATE, f"state.id must be {DID_PREFIX}{scid}", version)

    return _Specialisation("method", (DID_VH_METHOD,), _METHOD_SYNTAX, (), check_state)


DID_VH: Final = did_vh_specialisation()


# ---------------------------------------------------------------- create / update


def create_did(
    document: Mapping[str, Any],
    parameters: Mapping[str, Any] | None,
    version_time: str,
    signers: Sequence[str | bytes],
) -> dict[str, str]:
    """Creates a did:vh DID log; returns ``{log, did, scid, versionId}``.

    ``document`` uses ``did:vh:{SCID}`` wherever it refers to the DID. ``method`` and
    ``scid`` are added to the parameters if absent. Like VH-Log generation, the input is
    not validated.
    """
    created = create_log(document, parameters, version_time, signers, "method", DID_VH_METHOD)
    did = DID_PREFIX + created.scid
    return {"log": created.log, "did": did, "scid": created.scid, "versionId": created.version_id}


def update_did(
    log: str,
    document: Mapping[str, Any],
    parameters: Mapping[str, Any] | None,
    version_time: str,
    signers: Sequence[str | bytes],
) -> dict[str, str]:
    """Appends an entry to a did:vh DID log. Deactivate with ``parameters={"deactivated": True}``."""
    updated = update_log(log, document, parameters, version_time, signers)
    return {"log": updated.log, "versionId": updated.version_id}


# ---------------------------------------------------------------- shared URL checks

#: Unicode White_Space (profile section 3).
_WHITESPACE_CODES: Final = (*range(0x09, 0x0E), 0x20, 0x85, 0xA0, 0x1680, *range(0x2000, 0x200B))
_WHITESPACE: Final = frozenset(chr(c) for c in (*_WHITESPACE_CODES, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000))
_HEX2: Final = re.compile(r"[0-9A-Fa-f]{2}")
_PRINTABLE: Final = re.compile(r"[\x21-\x7e]+")
_SCHEME: Final = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*):(.*)", re.DOTALL)
_OCTET: Final = re.compile(r"0|[1-9][0-9]{0,2}")
_LABEL: Final = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_DIGITS: Final = re.compile(r"[0-9]+")
_PORT: Final = re.compile(r"[0-9]{1,5}")
_VERSION_NUMBER: Final = re.compile(r"[1-9][0-9]{0,15}")


def percent_decode(s: str) -> str | None:
    """Percent-decodes ``s`` as UTF-8, or ``None`` if an escape or the UTF-8 is malformed."""
    out = bytearray()
    i = 0
    while i < len(s):
        if s[i] == "%":
            hex2 = s[i + 1 : i + 3]
            if not _HEX2.fullmatch(hex2):
                return None
            out.append(int(hex2, 16))
            i += 3
        else:
            try:
                out += s[i].encode("utf-8")
            except UnicodeEncodeError:
                return None
            i += 1
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _is_octet(s: str) -> bool:
    return bool(_OCTET.fullmatch(s)) and int(s) <= 255


def _is_loopback_host(host: str) -> bool:
    if host in ("localhost", "[::1]"):
        return True
    parts = host.split(".")
    return len(parts) == 4 and all(_is_octet(p) for p in parts) and parts[0] == "127"


def _is_domain_name(host: str) -> bool:
    name = host[:-1] if host.endswith(".") else host
    if not 0 < len(name) <= 253:
        return False
    labels = name.split(".")
    if _DIGITS.fullmatch(labels[-1]):  # an IPv4 literal, or ends in a number
        return False
    return all(_LABEL.fullmatch(label) for label in labels)


def _split_scheme(value: object) -> tuple[str, str] | None:
    """Splits ``scheme:rest`` (profile section 3, steps 1-2)."""
    if not isinstance(value, str) or not _PRINTABLE.fullmatch(value):
        return None
    m = _SCHEME.fullmatch(value)
    return (m[1].lower(), m[2]) if m else None


def _check_authority(authority: str, scheme: str) -> str | None:
    """Checks an ``http(s)`` authority (profile section 3); returns the lowercased host, or ``None``."""
    if "@" in authority:
        return None
    port: str | None = None
    if authority.startswith("["):
        close = authority.find("]")
        if close == -1:
            return None
        host = authority[: close + 1]
        after = authority[close + 1 :]
        if after:
            if not after.startswith(":"):
                return None
            port = after[1:]
    else:
        host, colon, rest = authority.partition(":")
        if colon:
            port = rest
    host = host.lower()
    if port is not None and not (_PORT.fullmatch(port) and int(port) <= 65535):
        return None
    if scheme == "http":
        return host if _is_loopback_host(host) else None
    return host if not host.startswith("[") and _is_domain_name(host) else None


def _check_segments(path: str, strict: bool) -> bool:
    """Checks the segments of a path that starts with ``/`` (profile section 3).

    Each is percent-decoded and must not be ``.`` or ``..`` or contain ``/``, ``\\`` or
    NUL. With ``strict`` (the ``src`` DID URL parameter), it must also be non-empty and
    not start or end with whitespace.
    """
    for raw in path[1:].split("/"):
        segment = percent_decode(raw)
        if segment is None or segment in (".", "..") or any(c in segment for c in "/\\\0"):
            return False
        if strict and (segment == "" or segment[0] in _WHITESPACE or segment[-1] in _WHITESPACE):
            return False
    return True


# ---------------------------------------------------------------- srcLog / srcWitness references


def check_ref(ref: object) -> RefKind:
    """Validates a ``srcLog`` or ``srcWitness`` reference (profile section 3.1) and returns its kind.

    Raises :class:`DidVhError` ``invalidOptions``.
    """

    def invalid(why: str) -> DidVhError:
        return DidVhError("invalidOptions", f"reference {ref!r}: {why}")

    parts = _split_scheme(ref)
    if parts is None:
        raise invalid("not a printable-ASCII absolute URL")
    scheme, rest = parts
    if "#" in rest:
        raise invalid("must not have a fragment")

    if scheme in ("https", "http"):
        if not rest.startswith("//"):
            raise invalid("missing authority")
        after_slashes = rest[2:]
        m = re.search(r"[/?]", after_slashes)
        authority = after_slashes if m is None else after_slashes[: m.start()]
        after_authority = "" if m is None else after_slashes[m.start() :]
        path = after_authority.partition("?")[0]
        if _check_authority(authority, scheme) is None:
            raise invalid("http needs a loopback host" if scheme == "http" else "invalid https host")
        if path == "":
            raise invalid("must have a path")
        if not _check_segments(path, False):
            raise invalid("invalid path segment")
        return "loopback" if scheme == "http" else "web"

    if scheme == "file":
        if "?" in rest:
            raise invalid("must not have a query")
        if rest.startswith("//"):
            slash = rest.find("/", 2)
            if slash == -1:
                raise invalid("file URL needs an absolute path")
            if rest[2:slash].lower() not in ("", "localhost"):
                raise invalid("file URL host must be empty or localhost")
            path = rest[slash:]
        else:
            if not rest.startswith("/"):
                raise invalid("file URL needs an absolute path")
            path = rest
        if not _check_segments(path, False):
            raise invalid("invalid path segment")
        return "file"

    if rest == "":
        raise invalid("empty URL")
    return "other"


# ---------------------------------------------------------------- the src DID URL parameter


def src_references(src: object) -> dict[str, str]:
    """Validates a (percent-decoded) ``src`` DID URL parameter and derives ``srcLog`` and
    ``srcWitness`` from it (profile section 3.2). Raises :class:`DidVhError` ``invalidDidUrl``.
    """

    def invalid(why: str) -> DidVhError:
        return DidVhError("invalidDidUrl", f"src {src!r}: {why}")

    parts = _split_scheme(src)
    if parts is None:
        raise invalid("not a printable-ASCII absolute URL")
    scheme, rest = parts
    if "?" in rest or "#" in rest:
        raise invalid("must not have a query or fragment")
    if scheme in ("http", "file"):
        raise invalid(f"{scheme} is not allowed in a DID URL")
    if not rest.startswith("//") or len(rest) == 2 or rest[2] == "/":
        raise invalid("not a hierarchical URL with an authority")
    base = rest[:-1] if rest.endswith("/") else rest
    if scheme == "https":
        slash = base.find("/", 2)
        authority = base[2:] if slash == -1 else base[2:slash]
        path = "" if slash == -1 else base[slash:]
        if _check_authority(authority, "https") is None:
            raise invalid("invalid https host")
        if path != "" and not _check_segments(path, True):
            raise invalid("invalid path segment")
    location = f"{scheme}:{base}"
    return {"srcLog": f"{location}/did.jsonl", "srcWitness": f"{location}/did-witness.json"}


# ---------------------------------------------------------------- DID URLs

_URL_PARAMETERS: Final = ("src", "versionId", "versionTime", "versionNumber")
_OPTION_ONLY: Final = (
    "didLog",
    "didWitness",
    "srcLog",
    "srcWitness",
    "checkWatchers",
    "extraWatchers",
    "minCopies",
    "includeDidLog",
)


def parse_did_url(did_url: object) -> dict[str, Any]:
    """Parses a did:vh DID URL as a dereferencer does (profile section 4).

    Returns ``{did, options, fragment?}``: ``src`` becomes the ``srcLog`` and ``srcWitness``
    options, and the version parameters become the options of the same name. Raises
    :class:`DidVhError` ``invalidDidUrl``.
    """

    def invalid(why: str) -> DidVhError:
        return DidVhError("invalidDidUrl", f"{did_url!r}: {why}")

    if not isinstance(did_url, str):
        raise invalid("not a string")
    before_fragment, hash_sign, fragment = did_url.partition("#")
    did, question, query = before_fragment.partition("?")
    if parse_did(did) is None:
        raise invalid("not a did:vh DID")
    seen: set[str] = set()
    options: dict[str, Any] = {}
    if question:
        for pair in query.split("&"):
            raw_key, eq, raw_value = pair.partition("=")
            if not eq:
                raise invalid(f"query parameter {pair!r} has no value")
            key, value = percent_decode(raw_key), percent_decode(raw_value)
            if key is None or value is None:
                raise invalid("malformed percent-encoding")
            if key in _OPTION_ONLY:
                raise invalid(f"{key} is a resolution option, not a DID URL parameter")
            if key not in _URL_PARAMETERS:
                continue
            if key in seen:
                raise invalid(f"{key} given more than once")
            seen.add(key)
            if key == "src":
                options.update(src_references(value))
            elif key == "versionNumber":
                if not _VERSION_NUMBER.fullmatch(value):
                    raise invalid("versionNumber must be a positive integer")
                options["versionNumber"] = int(value)
            else:
                options[key] = value
    result: dict[str, Any] = {"did": did, "options": options}
    if hash_sign:
        result["fragment"] = fragment
    return result


# ---------------------------------------------------------------- resolve

_SELECTORS: Final = ("versionId", "versionTime", "versionNumber")
_ERROR_MAP: Final = {
    "not-found": "notFound",
    "invalid-option": "invalidOptions",
    "fork-detected": "logForked",
    "min-copies-not-met": "insufficientCopies",
    "unsupported-log-version": "featureNotSupported",
}


def _is_positive_integer(v: object) -> bool:
    return _is_integer(v) and v >= 1  # type: ignore[operator]


def _validate_options(options: object, remote: bool) -> Mapping[str, Any]:
    """did:vh resolution options validation (profile section 5, step 2)."""

    def invalid(why: str) -> DidVhError:
        return DidVhError("invalidOptions", why)

    if not isinstance(options, Mapping):
        raise invalid("resolution options must be an object")
    o: Mapping[str, Any] = options
    if ("didLog" in o) == ("srcLog" in o):
        raise invalid("exactly one of didLog and srcLog must be given")
    if "didWitness" in o and "srcWitness" in o:
        raise invalid("at most one of didWitness and srcWitness may be given")
    if "didLog" in o and not isinstance(o["didLog"], str):
        raise invalid("didLog must be a string")
    if "didWitness" in o and not isinstance(o["didWitness"], list):
        raise invalid("didWitness must be an array")
    for key in ("srcLog", "srcWitness"):
        if key in o and check_ref(o[key]) in ("file", "loopback") and remote:
            raise invalid(f"{key}: a resolver that serves other systems must not use local references")
    if sum(1 for k in _SELECTORS if k in o) > 1:
        raise invalid("at most one of versionId, versionTime and versionNumber may be given")
    if "versionId" in o and not isinstance(o["versionId"], str):
        raise invalid("versionId must be a string")
    if "versionTime" in o and parse_version_time(o["versionTime"]) is None:
        raise invalid("versionTime must be a whole-second UTC ISO 8601 time")
    if "versionNumber" in o and not _is_positive_integer(o["versionNumber"]):
        raise invalid("versionNumber must be a positive integer")
    if "checkWatchers" in o:
        c = o["checkWatchers"]
        if c != "all" and not (_is_integer(c) and c >= 0):
            raise invalid('checkWatchers must be a non-negative integer or "all"')
    if "extraWatchers" in o:
        w = o["extraWatchers"]
        if not isinstance(w, list) or not all(
            isinstance(u, str) and u.startswith("https://") and is_watcher_url(u) for u in w
        ):
            raise invalid("extraWatchers must be an array of https URLs")
    if "minCopies" in o and not _is_positive_integer(o["minCopies"]):
        raise invalid("minCopies must be a positive integer")
    if "includeDidLog" in o and not isinstance(o["includeDidLog"], bool):
        raise invalid("includeDidLog must be a boolean")
    return o


def _failure(error: DidVhError) -> dict[str, Any]:
    problem_details: dict[str, Any] = {"title": error.code, "detail": error.message}
    if error.vh_log is not None:
        problem_details["vhLog"] = error.vh_log
    return {
        "didResolutionMetadata": {"error": error.code, "problemDetails": problem_details},
        "didDocument": None,
        "didDocumentMetadata": {},
    }


def resolve_did(
    did: object,
    resolution_options: object = None,
    *,
    now: str | None = None,
    remote: bool = False,
) -> dict[str, Any]:
    """did:vh ``resolve(did, resolutionOptions)`` (profile section 5).

    Returns ``{didResolutionMetadata, didDocument, didDocumentMetadata}``. This resolver is
    offline: it verifies a log passed in ``didLog`` (and ``didWitness``), and returns
    ``featureNotSupported`` when it would have to retrieve anything. ``now`` is the
    resolver's clock as a ``versionTime`` string (default: the current time), and
    ``remote`` says whether the resolver serves other systems.
    """
    try:
        scid = parse_did(did)
        if scid is None:
            raise DidVhError("invalidDid", f"{did!r} is not a did:vh DID")
        options = _validate_options({} if resolution_options is None else resolution_options, remote)
        if "srcLog" in options:
            raise DidVhError("featureNotSupported", "this resolver does not retrieve srcLog references")
        if options.get("checkWatchers", 0) != 0 or len(options.get("extraWatchers", [])) > 0:
            raise DidVhError("featureNotSupported", "this resolver does not retrieve copies from watchers")
        spec = did_vh_specialisation(scid)
        if now is None:
            now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        log: str = options["didLog"]
        # Whether the log needs witnessing does not depend on the witness file. Without one,
        # the first entry that needs it fails, which cuts it from ``entries``.
        clock = parse_version_time(now)
        unwitnessed = verify_log(log, now=clock if clock is not None else None, spec=spec)
        witnessed = (
            unwitnessed.failure is not None and unwitnessed.failure["code"] == "witness-threshold-not-met"
        ) or any(e.witness_rule is not None for e in unwitnessed.entries)
        if witnessed and "srcWitness" in options:
            raise DidVhError("featureNotSupported", "this resolver does not retrieve srcWitness references")
        request: dict[str, Any] = {
            "log": log,
            "now": now,
            "options": {k: options[k] for k in (*_SELECTORS, "minCopies") if k in options},
        }
        if "didWitness" in options:
            request["witness"] = options["didWitness"]
        result: Any = resolve_request(request, spec)
        if not result["valid"]:
            error = result["error"]
            raise DidVhError(_ERROR_MAP.get(error["code"], "invalidDid"), error["message"], error)
        selected = any(k in options for k in _SELECTORS)
        partial = result["error"]
        if not selected and partial is not None and partial["code"] == "unsupported-log-version":
            # Entries after the last valid one may change the document or its keys (profile section 5).
            raise DidVhError("featureNotSupported", result["error"]["message"], result["error"])
        m = result["metadata"]
        did_document_metadata: dict[str, Any] = {
            "versionId": m["versionId"],
            "versionTime": m["versionTime"],
            "created": m["created"],
            "updated": m["updated"],
            "scid": m["scid"],
            "deactivated": m["deactivated"],
            "ttl": int(m["ttl"]),
        }
        if m["witness"] is not None:
            did_document_metadata["witness"] = m["witness"]
        did_document_metadata["watchers"] = m["watchers"]
        meta: dict[str, Any] = {"contentType": "application/did+json"}
        if m["warnings"]:
            meta["warnings"] = m["warnings"]
        if options.get("includeDidLog") is True:
            lines = parse_log_lines(log)
            first_invalid = result["firstInvalidVersion"]
            valid = len(lines) if first_invalid is None else first_invalid - 1
            meta["didLog"] = "".join(line + "\n" for line in lines[:valid])
            if witnessed:
                meta["didWitness"] = options.get("didWitness", [])
        return {
            "didResolutionMetadata": meta,
            # A deactivated DID's document is returned only for a version selector (profile section 5).
            "didDocument": None if m["deactivated"] and not selected else result["state"],
            "didDocumentMetadata": did_document_metadata,
        }
    except DidVhError as e:
        return _failure(e)
