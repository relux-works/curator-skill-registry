from __future__ import annotations

import base64
import binascii
import json
import re
import unicodedata
from typing import Any

from .errors import ProtocolError as ProtocolError
from .signing import (
    MAX_JSON_DEPTH,
    MAX_SAFE_INTEGER,
    CanonicalDepthError,
    canonical_document_bytes,
)


STATUSES = {"audited", "revoked", "deprecated", "pending"}
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_HOST = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
_COMMIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX256 = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^[0-9a-f]{16}$")
_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_WINDOWS_RESERVED = {"con", "prn", "aux", "nul"} | {
    f"{prefix}{number}" for prefix in ("com", "lpt") for number in range(1, 10)
}


class JSONDepthError(ProtocolError):
    """Protocol JSON nested deeper than ``MAX_JSON_DEPTH``."""

    pass


def _check_json_depth(raw: bytes | str) -> None:
    """Reject JSON text nested deeper than ``MAX_JSON_DEPTH`` without parsing.

    An iterative bracket scan outside strings, so pathological depth fails
    before ``json.loads`` can recurse into the interpreter limit. Malformed
    text is left for the parser to reject; only the depth bound is enforced.
    """
    depth = 0
    in_string = False
    escaped = False

    def bump(opening: bool) -> None:
        nonlocal depth
        if opening:
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise JSONDepthError(
                    f"JSON nesting exceeds maximum depth of {MAX_JSON_DEPTH}"
                )
        else:
            depth = max(0, depth - 1)

    if isinstance(raw, bytes):
        for byte in raw:
            if in_string:
                if escaped:
                    escaped = False
                elif byte == 0x5C:  # backslash
                    escaped = True
                elif byte == 0x22:  # quote
                    in_string = False
            elif byte == 0x22:
                in_string = True
            elif byte == 0x7B or byte == 0x5B:  # { [
                bump(True)
            elif byte == 0x7D or byte == 0x5D:  # } ]
                bump(False)
    else:
        for character in raw:
            if in_string:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    in_string = False
            elif character == '"':
                in_string = True
            elif character == "{" or character == "[":
                bump(True)
            elif character == "}" or character == "]":
                bump(False)


def load_json(raw: bytes | str) -> Any:
    """Parse protocol JSON, rejecting over-deep documents.

    Documents nested deeper than ``MAX_JSON_DEPTH`` (100 levels of
    objects/arrays) raise :class:`JSONDepthError`, a ``ProtocolError``;
    ``RecursionError`` from the parser or canonicalization is mapped to
    the same error so callers only handle ``ProtocolError``.
    """
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
        if text == "-0" or not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ProtocolError(f"JSON integer is not shortest-form or safe: {text}")
        return value

    def reject_number(text: str) -> None:
        raise ProtocolError(f"registry JSON does not allow non-integer number {text!r}")

    try:
        _check_json_depth(raw)
        value = json.loads(
            raw,
            object_pairs_hook=object_pairs,
            parse_int=parse_integer,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
        canonical_document_bytes(value)
        return value
    except JSONDepthError:
        raise
    except CanonicalDepthError as exc:
        raise JSONDepthError(str(exc)) from exc
    except ProtocolError:
        raise
    except RecursionError as exc:
        raise JSONDepthError(
            f"JSON nesting exceeds maximum depth of {MAX_JSON_DEPTH}"
        ) from exc
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProtocolError(f"invalid protocol JSON: {exc}") from exc


def _canonicalize_validated(value: Any) -> None:
    """Canonicalize a validated object, mapping depth failures to ``ProtocolError``.

    Only depth violations are converted; other CCJ errors keep their
    existing ``CanonicalError`` behaviour.
    """
    try:
        canonical_document_bytes(value)
    except CanonicalDepthError as exc:
        raise JSONDepthError(str(exc)) from exc
    except RecursionError as exc:
        raise JSONDepthError(
            f"JSON nesting exceeds maximum depth of {MAX_JSON_DEPTH}"
        ) from exc


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
        if (
            not isinstance(endorsement.get("endorser"), str)
            or not endorsement["endorser"]
            or len(endorsement["endorser"]) > 8192
        ):
            raise ProtocolError("audit record endorsement requires an endorser")
        validate_signature(endorsement.get("sig"))
    _canonicalize_validated(record)
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
    try:
        raw = base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ProtocolError("signature value is malformed") from exc
    if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != signature:
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
    _canonicalize_validated(snapshot)
    return snapshot


def portable_path(value: str) -> bool:
    if not value or len(value) > 4096 or value.startswith("/") or "\\" in value:
        return False
    return all(_portable_component(component) for component in value.split("/"))


def validate_source_identity(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 4096:
        raise ProtocolError("source_identity must be canonical")
    host, separator, path = value.partition("/")
    if (
        not separator
        or _HOST.fullmatch(host) is None
        or not portable_path(path)
        or any(character.isspace() or character in "%?#" for character in path)
    ):
        raise ProtocolError("source_identity must be canonical")
    return value


def _portable_component(value: str) -> bool:
    if (
        not value
        or value in {".", ".."}
        or value.endswith((" ", "."))
        or any(separator in value for separator in (":", "/", "\\"))
    ):
        return False
    if any(unicodedata.category(character) == "Cc" for character in value):
        return False
    return value.split(".", 1)[0].casefold() not in _WINDOWS_RESERVED
