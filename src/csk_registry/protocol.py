from __future__ import annotations

import json
import re
from typing import Any

from .signing import MAX_SAFE_INTEGER, canonical_document_bytes


STATUSES = {"audited", "revoked", "deprecated", "pending"}
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]*$")
_COMMIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX256 = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^[0-9a-f]{16}$")
_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_WINDOWS_RESERVED = {"con", "prn", "aux", "nul"} | {
    f"{prefix}{number}" for prefix in ("com", "lpt") for number in range(1, 10)
}


class ProtocolError(ValueError):
    pass


def load_json(raw: bytes | str) -> Any:
    if (isinstance(raw, bytes) and raw.startswith(b"\xef\xbb\xbf")) or (
        isinstance(raw, str) and raw.startswith("\ufeff")
    ):
        raise ProtocolError("protocol JSON must not contain a byte-order mark")

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ProtocolError(f"duplicate JSON object key: {key!r}")
            result[key] = value
        return result

    def parse_integer(text: str) -> int:
        value = int(text)
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ProtocolError(f"JSON integer outside safe range: {text}")
        return value

    def reject_number(text: str) -> None:
        raise ProtocolError(f"registry JSON does not allow non-integer number {text!r}")

    try:
        value = json.loads(
            raw,
            object_pairs_hook=object_pairs,
            parse_int=parse_integer,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
        canonical_document_bytes(value)
        return value
    except ProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProtocolError(f"invalid protocol JSON: {exc}") from exc


def validate_record(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise ProtocolError("audit record must be an object")
    allowed = {
        "schema_version",
        "name",
        "source_identity",
        "commit",
        "content_sha256",
        "status",
        "audit",
        "endorsements",
        "sig",
    }
    if set(record) - allowed:
        raise ProtocolError("audit record contains unknown fields")
    if record.get("schema_version", 1) != 1:
        raise ProtocolError("audit record schema_version must be 1")
    name = record.get("name")
    if not isinstance(name, str) or len(name) > 128 or _IDENTIFIER.fullmatch(name) is None or not _portable_component(name):
        raise ProtocolError("audit record name must be a portable identifier")
    identity = record.get("source_identity")
    validate_source_identity(identity)
    commit = record.get("commit")
    if not isinstance(commit, str) or _COMMIT.fullmatch(commit) is None:
        raise ProtocolError("audit record commit must be a full lowercase object id")
    content_hash = record.get("content_sha256")
    if not isinstance(content_hash, str) or _SHA256.fullmatch(content_hash) is None:
        raise ProtocolError("audit record content_sha256 is malformed")
    if record.get("status") not in STATUSES:
        raise ProtocolError("audit record status is unsupported")
    audit = record.get("audit", {})
    if not isinstance(audit, dict):
        raise ProtocolError("audit record audit must be an object")
    validate_signature(record.get("sig"))
    endorsements = record.get("endorsements", [])
    if not isinstance(endorsements, list):
        raise ProtocolError("audit record endorsements must be an array")
    for endorsement in endorsements:
        if not isinstance(endorsement, dict) or set(endorsement) != {"endorser", "sig"}:
            raise ProtocolError("audit record endorsement is malformed")
        if not isinstance(endorsement.get("endorser"), str) or not endorsement["endorser"]:
            raise ProtocolError("audit record endorsement requires an endorser")
        validate_signature(endorsement.get("sig"))
    canonical_document_bytes(record)
    return record


def validate_signature(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {"algorithm", "key_id", "signature"}:
        raise ProtocolError("signature envelope is malformed")
    if value.get("algorithm") != "ed25519":
        raise ProtocolError("signature algorithm must be ed25519")
    key_id = value.get("key_id")
    signature = value.get("signature")
    if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
        raise ProtocolError("signature key_id is malformed")
    if not isinstance(signature, str):
        raise ProtocolError("signature value is malformed")


def validate_snapshot(snapshot: Any) -> dict[str, Any]:
    if not isinstance(snapshot, dict):
        raise ProtocolError("snapshot must be an object")
    required = {"schema_version", "merkle_root", "log_size", "head", "version", "created_at", "sig"}
    if set(snapshot) != required or snapshot.get("schema_version") != 1:
        raise ProtocolError("snapshot fields are malformed")
    if any(
        not isinstance(snapshot.get(field), str) or _HEX256.fullmatch(snapshot[field]) is None
        for field in ("merkle_root", "head")
    ):
        raise ProtocolError("snapshot hashes are malformed")
    log_size = snapshot.get("log_size")
    version = snapshot.get("version")
    if (
        not isinstance(log_size, int)
        or isinstance(log_size, bool)
        or not isinstance(version, int)
        or isinstance(version, bool)
        or not 0 <= log_size <= version <= MAX_SAFE_INTEGER
    ):
        raise ProtocolError("snapshot sizes are malformed")
    created_at = snapshot.get("created_at")
    if not isinstance(created_at, str) or _TIMESTAMP.fullmatch(created_at) is None:
        raise ProtocolError("snapshot timestamp is malformed")
    validate_signature(snapshot.get("sig"))
    canonical_document_bytes(snapshot)
    return snapshot


def portable_path(value: str) -> bool:
    if not value or len(value) > 4096 or value.startswith("/") or "\\" in value:
        return False
    return all(_portable_component(component) for component in value.split("/"))


def validate_source_identity(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 4096:
        raise ProtocolError("source_identity must be canonical")
    host, separator, path = value.partition("/")
    if not separator or _HOST.fullmatch(host) is None or not portable_path(path):
        raise ProtocolError("source_identity must be canonical")
    return value


def _portable_component(value: str) -> bool:
    if not value or value in {".", ".."} or value.endswith((" ", ".")) or ":" in value:
        return False
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        return False
    return value.split(".", 1)[0].casefold() not in _WINDOWS_RESERVED
