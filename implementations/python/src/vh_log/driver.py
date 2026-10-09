"""Interop driver: JSON Lines requests on stdin, responses on stdout.

See ``docs/interop-protocol.md``. Messages are split on ``\\n`` only (JSON strings
may contain raw U+2028/U+2029), one response line is written per request, and
the process exits with status 0 on EOF.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Mapping
from typing import Any, BinaryIO

from .ed25519 import signer_from_seed
from .hashing import hash_b58, key_hash
from .jcs import canonicalize, parse_json, to_json
from .log import compute_entry_hash, compute_scid, create_log, update_log, witness_proof
from .proof import create_proof, verify_proof
from .resolve import resolve_request

Input = Mapping[str, Any]


def _sign(i: Input) -> dict[str, Any]:
    vm = i.get("verificationMethod")
    proof = create_proof(i["document"], i["seed"], verification_method=vm, created=i.get("created"))
    return {"proof": proof}


def _create(i: Input) -> dict[str, Any]:
    created = create_log(i["state"], i.get("parameters"), i["versionTime"], i["signers"])
    return {"log": created.log, "scid": created.scid, "versionId": created.version_id}


def _update(i: Input) -> dict[str, Any]:
    updated = update_log(i["log"], i["state"], i.get("parameters"), i["versionTime"], i["signers"])
    return {"log": updated.log, "versionId": updated.version_id}


OPS: dict[str, Callable[[Input], Any]] = {
    "jcs": lambda i: {"output": canonicalize(parse_json(i["text"]))},
    "hash": lambda i: {"output": hash_b58(i["data"])},
    "multikey": lambda i: {"multikey": signer_from_seed(i["seed"]).multikey},
    "key-hash": lambda i: {"output": key_hash(i["multikey"])},
    "scid": lambda i: {"scid": compute_scid(i["entry"])},
    "entry-hash": lambda i: {"hash": compute_entry_hash(i["entry"], i["previousVersionId"])},
    "sign": _sign,
    "verify": lambda i: {"valid": verify_proof(i["document"], i["proof"])},
    "create": _create,
    "update": _update,
    "witness": lambda i: {"proof": witness_proof(i["versionId"], i["seed"], i.get("created"))},
    "resolve": resolve_request,
}


def handle(line: str) -> dict[str, Any]:
    """Handles one request line and returns the response object."""
    request_id: Any = None
    try:
        request = parse_json(line)
        if not isinstance(request, dict):
            raise ValueError("request must be a JSON object")
        request_id = request.get("id")
        op = OPS.get(request.get("op"))  # type: ignore[arg-type]
        if op is None:
            raise ValueError(f"unknown op {request.get('op')}")
        payload = request.get("input")
        result = op(payload if payload is not None else {})
        return {"id": request_id, "ok": True, "result": result}
    except Exception as e:  # driver failures are reported, never fatal
        print(f"vh_log.driver: {type(e).__name__}: {e}", file=sys.stderr)
        return {"id": request_id, "ok": False, "error": f"{type(e).__name__}: {e}"}


def serve(stdin: BinaryIO, stdout: BinaryIO) -> None:
    buffer = b""
    while True:
        chunk = stdin.read1(65536) if hasattr(stdin, "read1") else stdin.read(65536)
        if not chunk:
            break
        buffer += chunk
        *complete, buffer = buffer.split(b"\n")
        for raw in complete:
            _respond(raw, stdout)
    if buffer:
        _respond(buffer, stdout)


def _respond(raw: bytes, stdout: BinaryIO) -> None:
    line = raw.decode("utf-8", "replace")
    if not line.strip():
        return
    response = handle(line)
    try:
        text = to_json(response)
    except Exception as e:
        text = to_json({"id": response.get("id"), "ok": False, "error": f"unserialisable result: {e}"})
    stdout.write(text.encode("utf-8") + b"\n")
    stdout.flush()


def main() -> None:
    serve(sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    main()
