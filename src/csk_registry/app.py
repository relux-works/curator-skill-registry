from __future__ import annotations

import base64
import hashlib
import os
import re
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__
from .auth import AuditorTokens
from .clock import utc_now
from .protocol import ProtocolError, load_json, validate_record, validate_source_identity
from .signing import (
    SigningKey,
    canonical_document_bytes,
    load_key,
    verify,
    verify_signed,
)
from .snapshot import build_snapshot
from .store import IdempotencyConflict, Store


MAX_PAGE_SIZE = 1000
MAX_BODY_BYTES = 16 * 1024 * 1024
CURSOR_TTL_SECONDS = 3600
IDEMPOTENCY_TTL_SECONDS = 24 * 3600


class APIError(Exception):
    def __init__(self, status: int, code: str, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details or {}


def create_app(
    *,
    store: Store,
    signing_key: SigningKey,
    tokens: AuditorTokens,
    registry_name: str = "curator-registry",
) -> FastAPI:
    app = FastAPI(title="Curator Audit Registry", version=__version__)

    def snapshot_version() -> int:
        size, _ = store.head()
        return size

    @app.exception_handler(APIError)
    async def api_error(request: Request, exc: APIError) -> JSONResponse:
        return _error_response(exc.status, exc.code, exc.message, exc.details)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return _error_response(400, "invalid_request", "request parameters are malformed")

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = "not_found" if exc.status_code == 404 else "method_not_allowed"
        return _error_response(exc.status_code, code, "requested registry resource is unavailable")

    @app.exception_handler(Exception)
    async def internal_error(request: Request, exc: Exception) -> JSONResponse:
        return _error_response(500, "internal_error", "the registry could not complete the request")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/meta")
    def meta() -> dict[str, Any]:
        return {
            "name": registry_name,
            "version": __version__,
            "public_keys": [signing_key.public_pinned],
            "record_schema_versions": [1],
            "policy": "append-only signed records with deny-wins revocation",
            "limits": {"max_page_size": MAX_PAGE_SIZE, "max_body_bytes": MAX_BODY_BYTES},
        }

    @app.get("/v1/records")
    def records(
        source_identity: str = Query(default=""),
        commit: str = Query(default=""),
        content_sha256: str = Query(default=""),
        limit: int = Query(default=100, ge=1, le=MAX_PAGE_SIZE),
        cursor: str = Query(default=""),
    ) -> dict[str, Any]:
        if not ((source_identity and commit) or content_sha256):
            raise APIError(400, "invalid_query", "identity plus commit or a content hash is required")
        if source_identity:
            try:
                validate_source_identity(source_identity)
            except ProtocolError as exc:
                raise APIError(400, "invalid_query", str(exc)) from exc
        if commit and re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", commit) is None:
            raise APIError(400, "invalid_query", "commit must be a full lowercase object id")
        if content_sha256 and re.fullmatch(r"sha256:[0-9a-f]{64}", content_sha256) is None:
            raise APIError(400, "invalid_query", "content_sha256 is malformed")
        query = {
            "source_identity": source_identity,
            "commit": commit,
            "content_sha256": content_sha256,
            "limit": limit,
        }
        offset = _cursor_offset(signing_key, cursor, endpoint="records", query=query) if cursor else 0
        found, more = store.records_page(
            source_identity=source_identity,
            commit=commit,
            content_sha256=content_sha256,
            limit=limit,
            offset=offset,
        )
        next_cursor = (
            _encode_cursor(signing_key, endpoint="records", query=query, offset=offset + len(found))
            if more
            else None
        )
        return {"records": found, "next_cursor": next_cursor}

    @app.get("/v1/snapshot")
    def snapshot() -> dict[str, Any]:
        return build_snapshot(store, signing_key, created_at=utc_now(), version=snapshot_version())

    @app.get("/v1/log")
    def log(
        since: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=MAX_PAGE_SIZE),
        cursor: str = Query(default=""),
    ) -> dict[str, Any]:
        query = {"since": since, "limit": limit}
        offset = _cursor_offset(signing_key, cursor, endpoint="log", query=query) if cursor else 0
        entries, more = store.log_page(since=since, limit=limit, offset=offset)
        encoded = [
            {"seq": entry.seq, "entry_hash": entry.entry_hash, "prev_hash": entry.prev_hash, "record": entry.record}
            for entry in entries
        ]
        next_cursor = (
            _encode_cursor(signing_key, endpoint="log", query=query, offset=offset + len(entries))
            if more
            else None
        )
        return {"entries": encoded, "next_cursor": next_cursor}

    @app.post("/v1/records")
    async def submit(
        request: Request,
        authorization: str = Header(default=""),
        idempotency_key: str = Header(default=""),
    ) -> JSONResponse:
        media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            raise APIError(415, "unsupported_media_type", "Content-Type must be application/json")
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
            raise APIError(413, "request_too_large", "record body exceeds 16 MiB")
        body = await request.body()
        if len(body) > MAX_BODY_BYTES:
            raise APIError(413, "request_too_large", "record body exceeds 16 MiB")
        if not authorization.startswith("Bearer "):
            raise APIError(401, "invalid_token", "a valid auditor bearer token is required")
        token = authorization[len("Bearer ") :].strip()
        auditor = tokens.resolve(token)
        if auditor is None:
            raise APIError(401, "invalid_token", "a valid auditor bearer token is required")
        try:
            record = validate_record(load_json(body))
        except ProtocolError as exc:
            raise APIError(400, "invalid_record", str(exc)) from exc
        if not verify_signed(auditor.public_pinned, record):
            raise APIError(400, "invalid_signature", "record signature does not verify for this auditor")
        countersigned = _countersign(record, signing_key, endorser=auditor.auditor_id)
        if idempotency_key:
            if len(idempotency_key) > 256 or any(ord(character) < 0x21 for character in idempotency_key):
                raise APIError(400, "invalid_idempotency_key", "Idempotency-Key is malformed")
            body_sha256 = hashlib.sha256(canonical_document_bytes(record)).hexdigest()
            try:
                response, replayed = store.append_idempotent(
                    countersigned,
                    key=idempotency_key,
                    body_sha256=body_sha256,
                    created_at=utc_now(),
                    now=int(time.time()),
                    ttl_seconds=IDEMPOTENCY_TTL_SECONDS,
                )
            except IdempotencyConflict as exc:
                raise APIError(409, "idempotency_conflict", str(exc)) from exc
            return JSONResponse(response, status_code=200 if replayed else 201)
        try:
            entry = store.append(countersigned, created_at=utc_now())
        except ValueError as exc:
            raise APIError(409, "non_appendable", str(exc)) from exc
        return JSONResponse({"seq": entry.seq, "entry_hash": entry.entry_hash}, status_code=201)

    return app


def _countersign(record: dict[str, Any], signing_key: SigningKey, *, endorser: str) -> dict[str, Any]:
    endorsement = {"endorser": endorser, "sig": record.get("sig")}
    body = {key: value for key, value in record.items() if key != "sig"}
    body["schema_version"] = 1
    existing = body.get("endorsements")
    body["endorsements"] = ([*existing, endorsement] if isinstance(existing, list) else [endorsement])
    return signing_key.sign_record(body)


def _query_digest(endpoint: str, query: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_document_bytes({"endpoint": endpoint, "query": query})).hexdigest()


def _encode_cursor(signing_key: SigningKey, *, endpoint: str, query: dict[str, Any], offset: int) -> str:
    payload = canonical_document_bytes(
        {
            "query": _query_digest(endpoint, query),
            "offset": offset,
            "expires_at": int(time.time()) + CURSOR_TTL_SECONDS,
        }
    )
    signature = base64.b64decode(signing_key.sign(payload))
    return f"{_url64(payload)}.{_url64(signature)}"


def _cursor_offset(signing_key: SigningKey, cursor: str, *, endpoint: str, query: dict[str, Any]) -> int:
    try:
        payload_text, signature_text = cursor.split(".", 1)
        payload = _unurl64(payload_text)
        signature = base64.b64encode(_unurl64(signature_text)).decode("ascii")
        if not verify(signing_key.public_pinned, payload, signature):
            raise ValueError("signature")
        decoded = load_json(payload)
        if not isinstance(decoded, dict) or set(decoded) != {"query", "offset", "expires_at"}:
            raise ValueError("shape")
        if decoded.get("query") != _query_digest(endpoint, query):
            raise ValueError("query")
        offset = decoded.get("offset")
        expires_at = decoded.get("expires_at")
        if (
            not isinstance(offset, int)
            or isinstance(offset, bool)
            or offset < 0
            or not isinstance(expires_at, int)
            or isinstance(expires_at, bool)
            or expires_at < int(time.time())
        ):
            raise ValueError("value")
        return offset
    except (ValueError, ProtocolError) as exc:
        raise APIError(404, "invalid_cursor", "pagination cursor is invalid or expired") from exc


def _url64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unurl64(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def _error_response(status: int, code: str, message: str, details: dict[str, Any] | None = None) -> JSONResponse:
    error: dict[str, Any] = {"code": code, "message": message}
    if details:
        error["details"] = details
    return JSONResponse({"error": error}, status_code=status)


def app_from_env() -> FastAPI:
    home = Path(os.environ.get("CSK_REGISTRY_HOME", "./data")).expanduser()
    home.mkdir(parents=True, exist_ok=True)
    key_path = home / "signing-key.pem"
    if not key_path.exists():
        raise RuntimeError(f"signing key not found at {key_path}; run 'csk-registry genkey' first")
    signing_key = load_key(key_path.read_bytes())
    store = Store(home / "registry.db")
    tokens = AuditorTokens.from_file(home / "auditors.json")
    return create_app(store=store, signing_key=signing_key, tokens=tokens)
