from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import math
import os
import re
import sqlite3
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Awaitable, Callable

from fastapi import FastAPI, Header, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import CHECKPOINT_ENV, COMMAND_NAME, HEALTH_VERIFY_INTERVAL_ENV, __version__, home_from_env
from .auth import AuditorTokens
from .checkpoint import (
    CHECKPOINT_NOT_CONFIGURED,
    CHECKPOINT_SIGNATURE_INVALID,
    CheckpointView,
)
from .clock import utc_now
from .keys import load_active_key, public_keys
from .limits import FixedWindowLimiter
from .permissions import protect_private_directory
from .protocol import (
    ProtocolError,
    load_json,
    validate_record,
    validate_snapshot,
    validate_source_identity,
)
from .signing import (
    SigningKey,
    canonical_bytes,
    canonical_document_bytes,
    verify,
    verify_signed,
)
from .snapshot import build_snapshot
from .store import (
    DEFAULT_HEALTH_VERIFY_INTERVAL_SECONDS,
    CursorBoundaryMismatch,
    IdempotencyConflict,
    SnapshotBoundary,
    Store,
    StoreIntegrityError,
)


MAX_PAGE_SIZE = 1000
MAX_BODY_BYTES = 16 * 1024 * 1024
CURSOR_TTL_SECONDS = 3600
IDEMPOTENCY_TTL_SECONDS = 24 * 3600
DEFAULT_MAX_CONCURRENT_REQUESTS = 128
DEFAULT_NETWORK_REQUESTS_PER_MINUTE = 600
DEFAULT_AUDITOR_SUBMISSIONS_PER_MINUTE = 120
REQUEST_BODY_DEADLINE_SECONDS = 15

_AUDIT_LOG = logging.getLogger("csk_registry.audit")


class APIError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details or {}
        self.headers = headers or {}


def create_app(
    *,
    store: Store,
    signing_key: SigningKey,
    tokens: AuditorTokens,
    registry_name: str = "curator-skill-registry",
    verification_keys: tuple[str, ...] = (),
    max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS,
    network_requests_per_minute: int = DEFAULT_NETWORK_REQUESTS_PER_MINUTE,
    auditor_submissions_per_minute: int = DEFAULT_AUDITOR_SUBMISSIONS_PER_MINUTE,
) -> FastAPI:
    if max_concurrent_requests < 1:
        raise ValueError("max_concurrent_requests must be positive")

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        store.start_health_verifier()
        try:
            yield
        finally:
            store.stop_health_verifier()

    app = FastAPI(title="Curator Skill Registry", version=__version__, lifespan=lifespan)
    accepted_signing_keys = tuple(dict.fromkeys((signing_key.public_pinned, *verification_keys)))
    concurrency = asyncio.Semaphore(max_concurrent_requests)
    network_limiter = FixedWindowLimiter(requests=network_requests_per_minute)
    auditor_limiter = FixedWindowLimiter(requests=auditor_submissions_per_minute)

    @app.middleware("http")
    async def resource_controls(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        started = time.monotonic()
        client_host = request.client.host if request.client is not None else "unknown"
        network_decision = network_limiter.allow(f"network:{client_host}")
        if not network_decision.allowed:
            limited_response = _error_response(
                429,
                "rate_limited",
                "network request rate limit exceeded",
                headers={"Retry-After": str(network_decision.retry_after)},
            )
            _audit_request(
                request,
                limited_response.status_code,
                started,
                client_host,
                "rate_limited",
            )
            return limited_response
        try:
            await asyncio.wait_for(concurrency.acquire(), timeout=0.1)
        except TimeoutError:
            overloaded_response = _error_response(
                503,
                "overloaded",
                "registry concurrent request limit exceeded",
                headers={"Retry-After": "1"},
            )
            _audit_request(
                request,
                overloaded_response.status_code,
                started,
                client_host,
                "overloaded",
            )
            return overloaded_response
        try:
            routed_response = await call_next(request)
            _audit_request(
                request,
                routed_response.status_code,
                started,
                client_host,
                getattr(request.state, "error_code", ""),
            )
            return routed_response
        finally:
            concurrency.release()

    @app.exception_handler(APIError)
    async def api_error(request: Request, exc: APIError) -> JSONResponse:
        request.state.error_code = exc.code
        return _error_response(exc.status, exc.code, exc.message, exc.details, exc.headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        code = (
            "invalid_query"
            if request.method == "GET" and request.url.path in {"/v1/records", "/v1/log"}
            else "invalid_request"
        )
        request.state.error_code = code
        return _error_response(400, code, "request parameters are malformed")

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = "not_found" if exc.status_code == 404 else "method_not_allowed"
        request.state.error_code = code
        return _error_response(exc.status_code, code, "requested registry resource is unavailable")

    @app.exception_handler(Exception)
    async def internal_error(request: Request, exc: Exception) -> JSONResponse:
        request.state.error_code = "internal_error"
        return _error_response(500, "internal_error", "the registry could not complete the request")

    @app.exception_handler(StoreIntegrityError)
    async def store_integrity_error(request: Request, exc: StoreIntegrityError) -> JSONResponse:
        request.state.error_code = "storage_unavailable"
        return _error_response(503, "storage_unavailable", "registry durable state is unavailable")

    @app.exception_handler(sqlite3.Error)
    async def sqlite_error(request: Request, exc: sqlite3.Error) -> JSONResponse:
        request.state.error_code = "storage_unavailable"
        return _error_response(503, "storage_unavailable", "registry storage operation failed")

    @app.get("/health")
    def health() -> dict[str, str]:
        # Cached verdict: no chain walk, no hashing, no I/O per probe. The
        # background verifier refreshes it; a failed or stale verdict is
        # non-ready, exactly like a startup §5 mismatch. A §6 startup
        # checkpoint refusal reports its diagnostic as the error code.
        verdict = store.health_verdict()
        if not verdict.ready:
            if verdict.code == "not_ready":
                raise APIError(
                    503, "not_ready", "registry durable state failed integrity verification"
                )
            raise APIError(
                503,
                verdict.code,
                f"registry startup checkpoint comparison refused: {verdict.code}",
            )
        return {"status": "ok"}

    @app.get("/v1/meta")
    def meta(response: Response) -> dict[str, Any]:
        response.headers["Cache-Control"] = f"public, max-age={CURSOR_TTL_SECONDS}"
        return {
            "name": registry_name,
            "version": __version__,
            "public_keys": list(accepted_signing_keys),
            "record_schema_versions": [1],
            "policy": "append-only signed records with deny-wins revocation",
            "limits": {"max_page_size": MAX_PAGE_SIZE, "max_body_bytes": MAX_BODY_BYTES},
        }

    @app.get("/v1/records")
    def records(
        request: Request,
        response: Response,
        source_identity: str = Query(default=""),
        commit: str = Query(default=""),
        content_sha256: str = Query(default=""),
        limit: int = Query(default=100, ge=1, le=MAX_PAGE_SIZE),
        cursor: str = Query(default=""),
    ) -> dict[str, Any]:
        _validate_query_parameters(
            request,
            {"source_identity", "commit", "content_sha256", "limit", "cursor"},
        )
        if bool(source_identity) != bool(commit):
            raise APIError(400, "invalid_query", "source_identity and commit must appear together")
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
        if cursor:
            offset, boundary, boundary_snapshot = _cursor_state(
                store,
                cursor,
                endpoint="records",
                query=query,
                verification_keys=accepted_signing_keys,
            )
            try:
                found, more = store.records_page(
                    source_identity=source_identity,
                    commit=commit,
                    content_sha256=content_sha256,
                    limit=limit,
                    offset=offset,
                    boundary=boundary,
                )
            except CursorBoundaryMismatch as exc:
                raise APIError(
                    404, "invalid_cursor", "pagination cursor is invalid or expired"
                ) from exc
        else:
            offset = 0
            boundary = store.snapshot_boundary()
            boundary_snapshot = build_snapshot(store, signing_key, boundary=boundary)
            found, more = store.records_page(
                source_identity=source_identity,
                commit=commit,
                content_sha256=content_sha256,
                limit=limit,
                offset=offset,
                max_seq=boundary.log_size,
            )
        next_cursor = (
            _encode_cursor(
                signing_key,
                endpoint="records",
                query=query,
                boundary_snapshot=boundary_snapshot,
                offset=offset + len(found),
            )
            if more
            else None
        )
        response.headers["Cache-Control"] = f"public, max-age={CURSOR_TTL_SECONDS}"
        return {"records": found, "next_cursor": next_cursor, "boundary": boundary_snapshot}

    @app.get("/v1/snapshot")
    def snapshot(response: Response) -> dict[str, Any]:
        response.headers["Cache-Control"] = f"public, max-age={CURSOR_TTL_SECONDS}"
        return build_snapshot(store, signing_key)

    @app.get("/v1/log")
    def log(
        request: Request,
        response: Response,
        since: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=MAX_PAGE_SIZE),
        cursor: str = Query(default=""),
    ) -> dict[str, Any]:
        _validate_query_parameters(request, {"since", "limit", "cursor"})
        query = {"since": since, "limit": limit}
        if cursor:
            offset, boundary, boundary_snapshot = _cursor_state(
                store,
                cursor,
                endpoint="log",
                query=query,
                verification_keys=accepted_signing_keys,
            )
            try:
                entries, more = store.log_page(
                    since=since,
                    limit=limit,
                    offset=offset,
                    boundary=boundary,
                )
            except CursorBoundaryMismatch as exc:
                raise APIError(
                    404, "invalid_cursor", "pagination cursor is invalid or expired"
                ) from exc
        else:
            offset = 0
            boundary = store.snapshot_boundary()
            boundary_snapshot = build_snapshot(store, signing_key, boundary=boundary)
            entries, more = store.log_page(
                since=since,
                limit=limit,
                offset=offset,
                max_seq=boundary.log_size,
            )
        encoded = [
            {"seq": entry.seq, "entry_hash": entry.entry_hash, "prev_hash": entry.prev_hash, "record": entry.record}
            for entry in entries
        ]
        next_cursor = (
            _encode_cursor(
                signing_key,
                endpoint="log",
                query=query,
                boundary_snapshot=boundary_snapshot,
                offset=offset + len(entries),
            )
            if more
            else None
        )
        response.headers["Cache-Control"] = f"public, max-age={CURSOR_TTL_SECONDS}"
        return {"entries": encoded, "next_cursor": next_cursor, "boundary": boundary_snapshot}

    @app.post("/v1/records")
    async def submit(
        request: Request,
        authorization: str = Header(default=""),
        idempotency_key: str = Header(default=""),
    ) -> JSONResponse:
        request.state.authentication_outcome = "rejected"
        request.state.idempotency_outcome = "not_requested"
        if not _is_utf8_json(request.headers.get("content-type", "")):
            raise APIError(415, "unsupported_media_type", "Content-Type must be application/json")
        content_encoding = request.headers.get("content-encoding", "identity").strip().lower()
        if content_encoding not in {"", "identity"}:
            raise APIError(415, "unsupported_media_type", "Content-Encoding must be identity")
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
            raise APIError(413, "request_too_large", "record body exceeds 16 MiB")
        body = await _read_request_body(request, MAX_BODY_BYTES)
        if not authorization.startswith("Bearer "):
            raise APIError(401, "invalid_token", "a valid auditor bearer token is required")
        token = authorization[len("Bearer ") :].strip()
        auditor = tokens.resolve(token)
        if auditor is None:
            raise APIError(401, "invalid_token", "a valid auditor bearer token is required")
        request.state.authentication_outcome = "accepted"
        request.state.auditor_id = auditor.auditor_id
        auditor_decision = auditor_limiter.allow(f"auditor:{auditor.auditor_id}")
        if not auditor_decision.allowed:
            raise APIError(
                429,
                "rate_limited",
                "auditor submission rate limit exceeded",
                headers={"Retry-After": str(auditor_decision.retry_after)},
            )
        try:
            record = validate_record(load_json(body))
        except ProtocolError as exc:
            raise APIError(400, "invalid_record", str(exc)) from exc
        if not verify_signed(auditor.public_pinned, record):
            raise APIError(400, "invalid_signature", "record signature does not verify for this auditor")
        countersigned = _countersign(record, signing_key, endorser=auditor.auditor_id)
        if idempotency_key:
            if not 1 <= len(idempotency_key) <= 256 or any(
                not 0x21 <= ord(character) <= 0x7E for character in idempotency_key
            ):
                raise APIError(400, "invalid_idempotency_key", "Idempotency-Key is malformed")
            body_sha256 = hashlib.sha256(canonical_bytes(record)).hexdigest()
            try:
                response, replayed = store.append_idempotent(
                    countersigned,
                    auditor_id=auditor.auditor_id,
                    key=idempotency_key,
                    body_sha256=body_sha256,
                    created_at=utc_now(),
                    now=int(time.time()),
                    ttl_seconds=IDEMPOTENCY_TTL_SECONDS,
                )
            except IdempotencyConflict as exc:
                request.state.idempotency_outcome = "conflict"
                raise APIError(409, "idempotency_conflict", str(exc)) from exc
            request.state.idempotency_outcome = "replay" if replayed else "committed"
            request.state.sequence = response["seq"]
            return _success_response(response, status_code=200 if replayed else 201)
        try:
            entry = store.append(countersigned, created_at=utc_now())
        except ValueError as exc:
            raise APIError(409, "non_appendable", str(exc)) from exc
        request.state.sequence = entry.seq
        return _success_response({"seq": entry.seq, "entry_hash": entry.entry_hash}, status_code=201)

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


def _encode_cursor(
    signing_key: SigningKey,
    *,
    endpoint: str,
    query: dict[str, Any],
    boundary_snapshot: dict[str, Any],
    offset: int,
) -> str:
    """Encode a cursor carrying the complete signed chain boundary.

    The ``snapshot`` member is the full ``registry-snapshot-v1`` object
    (including ``sig``) served as the page ``boundary``. Cursor pages echo it
    verbatim instead of re-signing, so a chain spanning a staged key rotation
    keeps one byte-identical ``boundary`` (registry §9.3). The cursor envelope
    itself is signed with the active key; only the carried boundary is pinned.
    """
    payload = canonical_document_bytes(
        {
            "query": _query_digest(endpoint, query),
            "snapshot": boundary_snapshot,
            "offset": offset,
            "expires_at": int(time.time()) + CURSOR_TTL_SECONDS,
        }
    )
    signature = base64.b64decode(signing_key.sign(payload))
    return f"{_url64(payload)}.{_url64(signature)}"


def _cursor_state(
    store: Store,
    cursor: str,
    *,
    endpoint: str,
    query: dict[str, Any],
    verification_keys: tuple[str, ...],
) -> tuple[int, SnapshotBoundary, dict[str, Any]]:
    """Decode a cursor into offset, boundary body, and carried snapshot.

    The carried snapshot is the exact signed ``boundary`` the chain was issued
    with; callers echo it verbatim. It must verify against the accepted key
    set, so a cursor stays usable across a staged rotation only inside the
    promised overlap and is refused (never re-signed) once its key retires.
    Cursors issued before the carried snapshot existed fail shape validation.

    The carried boundary body is verified against the store here (a
    signed-but-inconsistent object, an unavailable size, or a pruned prefix is
    ``invalid_cursor``), and callers additionally pass it to the store paging
    call, which re-verifies it structurally under the paging lock. A cursor
    page is therefore served only at the cursor's carried boundary — never
    re-evaluated at a newer one.
    """
    try:
        if len(cursor) > 4096:
            raise ValueError("length")
        payload_text, signature_text = cursor.split(".", 1)
        payload = _unurl64(payload_text)
        signature = base64.b64encode(_unurl64(signature_text)).decode("ascii")
        if not any(verify(public_key, payload, signature) for public_key in verification_keys):
            raise ValueError("signature")
        decoded = load_json(payload)
        if not isinstance(decoded, dict) or set(decoded) != {
            "query",
            "snapshot",
            "offset",
            "expires_at",
        }:
            raise ValueError("shape")
        if decoded.get("query") != _query_digest(endpoint, query):
            raise ValueError("query")
        snapshot = validate_snapshot(decoded.get("snapshot"))
        if not any(verify_signed(public_key, snapshot) for public_key in verification_keys):
            raise ValueError("snapshot signature")
        boundary = SnapshotBoundary.from_dict(
            {
                field: snapshot[field]
                for field in ("version", "log_size", "head", "merkle_root", "created_at")
            }
        )
        if not store.boundary_available(boundary):
            raise ValueError("snapshot")
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
        return offset, boundary, snapshot
    except (ValueError, ProtocolError) as exc:
        raise APIError(404, "invalid_cursor", "pagination cursor is invalid or expired") from exc


def _validate_query_parameters(request: Request, allowed: set[str]) -> None:
    seen: set[str] = set()
    for key, value in request.query_params.multi_items():
        if key not in allowed or key in seen or value == "":
            raise APIError(400, "invalid_query", "query parameters are unknown, repeated, or empty")
        seen.add(key)


def _is_utf8_json(content_type: str) -> bool:
    parts = [part.strip() for part in content_type.split(";")]
    if not parts or parts[0].lower() != "application/json":
        return False
    for parameter in parts[1:]:
        if not parameter:
            continue
        name, separator, value = parameter.partition("=")
        if separator != "=" or name.strip().lower() != "charset":
            return False
        if value.strip().strip('"').lower() not in {"utf-8", "utf8"}:
            return False
    return True


async def _read_request_body(request: Request, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    try:
        async with asyncio.timeout(REQUEST_BODY_DEADLINE_SECONDS):
            async for chunk in request.stream():
                size += len(chunk)
                if size > limit:
                    raise APIError(413, "request_too_large", "record body exceeds 16 MiB")
                chunks.append(chunk)
    except TimeoutError as exc:
        raise APIError(503, "request_timeout", "record body deadline exceeded") from exc
    return b"".join(chunks)


def _audit_request(
    request: Request,
    status: int,
    started: float,
    network_source: str,
    error_code: str,
) -> None:
    event = {
        "event": "registry_request",
        "method": request.method,
        "path": request.url.path,
        "status": status,
        "latency_ms": round((time.monotonic() - started) * 1000, 3),
        "network_source": network_source,
        "authentication": getattr(request.state, "authentication_outcome", "not_applicable"),
        "auditor_id": getattr(request.state, "auditor_id", None),
        "idempotency": getattr(request.state, "idempotency_outcome", "not_applicable"),
        "sequence": getattr(request.state, "sequence", None),
        "error_code": error_code or None,
    }
    _AUDIT_LOG.info("%s", json.dumps(event, sort_keys=True, separators=(",", ":")))


def _url64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unurl64(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def _error_response(
    status: int,
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    error: dict[str, Any] = {"code": code, "message": message}
    if details:
        error["details"] = details
    return JSONResponse(
        {"error": error},
        status_code=status,
        headers={"Cache-Control": "no-store", **(headers or {})},
    )


def _success_response(payload: dict[str, Any], *, status_code: int) -> JSONResponse:
    return JSONResponse(
        payload,
        status_code=status_code,
        headers={"Cache-Control": "no-store"},
    )


def ensure_startup_audit_sink() -> None:
    """Attach the structured audit sink before the §6 startup enforcement runs.

    ``serve`` constructs the app — running the startup checkpoint comparison —
    before Uvicorn configures logging, so without this the INFO
    ``startup_checkpoint`` posture/success events are dropped (the audit
    logger inherits WARNING with no handler). This attaches a stderr sink at
    INFO exactly once; refusal events keep their WARNING level and shape.
    Idempotent: repeated calls add no further handlers and never raise.
    """
    if _AUDIT_LOG.level == logging.NOTSET or _AUDIT_LOG.level > logging.INFO:
        _AUDIT_LOG.setLevel(logging.INFO)
    if not _AUDIT_LOG.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter("%(message)s"))
        _AUDIT_LOG.addHandler(handler)


def _enforce_startup_checkpoint(store: Store, accepted_keys: tuple[str, ...]) -> None:
    """Run the §6 startup checkpoint comparison (or record its absence).

    Called after the §5 store verification and before the app is returned,
    hence before the listener binds or ``/health`` can report ready. A
    missing or empty ``CURATOR_SKILL_REGISTRY_CHECKPOINT`` starts the
    service unchanged and records the ``checkpoint_not_configured``
    posture. An unreadable or malformed checkpoint file is an operator
    configuration error and fails startup. A well-formed checkpoint is
    signature-checked first against the accepted (staged-rotation) keys,
    then compared; either refusal latches non-ready plus writes-disabled
    through the common integrity path while the process stays up.
    """
    configured = os.environ.get(CHECKPOINT_ENV)
    if not configured:
        _log_startup_checkpoint(
            {"configured": False, "posture": CHECKPOINT_NOT_CONFIGURED}, refused=False
        )
        return
    path = Path(configured).expanduser()
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"startup checkpoint is unreadable: {exc}") from exc
    try:
        snapshot = validate_snapshot(load_json(raw))
        checkpoint = CheckpointView.from_snapshot(snapshot)
    except ProtocolError as exc:
        raise RuntimeError(
            f"startup checkpoint is not a signed registry-snapshot-v1 object: {exc}"
        ) from exc
    live = store.snapshot_boundary()
    compared: dict[str, Any] = {
        "checkpoint": {
            "version": checkpoint.version,
            "log_size": checkpoint.log_size,
            "head": checkpoint.head,
        },
        "live": {
            "version": live.version,
            "log_size": live.log_size,
            "head": live.head,
        },
    }
    if not any(verify_signed(key, snapshot) for key in accepted_keys):
        diagnostic = CHECKPOINT_SIGNATURE_INVALID
        store.refuse_startup_checkpoint(
            diagnostic, f"startup checkpoint comparison refused: {diagnostic}"
        )
        _log_startup_checkpoint(
            {"configured": True, "result": "refused", "diagnostic": diagnostic, **compared},
            refused=True,
        )
        return
    refused = store.apply_startup_checkpoint(checkpoint)
    if refused is None:
        _log_startup_checkpoint(
            {"configured": True, "result": "ok", **compared}, refused=False
        )
    else:
        _log_startup_checkpoint(
            {"configured": True, "result": "refused", "diagnostic": refused, **compared},
            refused=True,
        )


def _log_startup_checkpoint(fields: dict[str, Any], *, refused: bool) -> None:
    event = {"event": "startup_checkpoint", **fields}
    message = json.dumps(event, sort_keys=True, separators=(",", ":"))
    if refused:
        _AUDIT_LOG.warning("%s", message)
    else:
        _AUDIT_LOG.info("%s", message)


def app_from_env() -> FastAPI:
    home = Path(home_from_env()).expanduser()
    home.mkdir(parents=True, exist_ok=True)
    protect_private_directory(home)
    key_path = home / "signing-key.pem"
    if not key_path.exists():
        raise RuntimeError(f"signing key not found at {key_path}; run '{COMMAND_NAME} genkey' first")
    signing_key = load_active_key(home)
    store = Store(
        home / "registry.db",
        health_verify_interval=_positive_float_env(
            HEALTH_VERIFY_INTERVAL_ENV, DEFAULT_HEALTH_VERIFY_INTERVAL_SECONDS
        ),
    )
    tokens = AuditorTokens.from_file(home / "auditors.json")
    verification_keys = public_keys(home, signing_key)
    _enforce_startup_checkpoint(store, verification_keys)
    return create_app(
        store=store,
        signing_key=signing_key,
        tokens=tokens,
        verification_keys=verification_keys,
        max_concurrent_requests=_positive_env(
            "CURATOR_SKILL_REGISTRY_MAX_CONCURRENT_REQUESTS",
            DEFAULT_MAX_CONCURRENT_REQUESTS,
        ),
        network_requests_per_minute=_positive_env(
            "CURATOR_SKILL_REGISTRY_NETWORK_REQUESTS_PER_MINUTE",
            DEFAULT_NETWORK_REQUESTS_PER_MINUTE,
        ),
        auditor_submissions_per_minute=_positive_env(
            "CURATOR_SKILL_REGISTRY_AUDITOR_SUBMISSIONS_PER_MINUTE",
            DEFAULT_AUDITOR_SUBMISSIONS_PER_MINUTE,
        ),
    )


def _positive_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a positive integer") from exc
    if value < 1:
        raise RuntimeError(f"{name} must be a positive integer")
    return value


def _positive_float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a positive number of seconds") from exc
    if not math.isfinite(value) or value <= 0:
        raise RuntimeError(f"{name} must be a positive number of seconds")
    return value
