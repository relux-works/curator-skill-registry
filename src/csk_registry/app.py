from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query

from . import __version__
from .auth import AuditorTokens
from .clock import utc_now
from .signing import SigningKey, canonical_bytes, load_key, verify
from .snapshot import build_snapshot
from .store import Store


def create_app(
    *,
    store: Store,
    signing_key: SigningKey,
    tokens: AuditorTokens,
    registry_name: str = "cocoaskills-registry",
) -> FastAPI:
    app = FastAPI(title="CocoaSkills Audit Registry", version=__version__)

    def snapshot_version() -> int:
        # Version tracks the log size; every append advances it monotonically.
        size, _ = store.head()
        return size

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
            "policy": "records are signed; a revocation supersedes an earlier audit",
        }

    @app.get("/v1/records")
    def records(
        source_identity: str = Query(default=""),
        commit: str = Query(default=""),
        content_sha256: str = Query(default=""),
    ) -> dict[str, Any]:
        found = store.records_for(
            source_identity=source_identity, commit=commit, content_sha256=content_sha256
        )
        return {"records": found}

    @app.get("/v1/snapshot")
    def snapshot() -> dict[str, Any]:
        return build_snapshot(store, signing_key, created_at=utc_now(), version=snapshot_version())

    @app.get("/v1/log")
    def log(since: int = Query(default=0, ge=0)) -> dict[str, Any]:
        entries = store.log_entries(since=since)
        return {
            "entries": [
                {"seq": e.seq, "entry_hash": e.entry_hash, "prev_hash": e.prev_hash, "record": e.record}
                for e in entries
            ]
        }

    @app.post("/v1/records")
    def submit(record: dict[str, Any], authorization: str = Header(default="")) -> dict[str, Any]:
        token = authorization.removeprefix("Bearer ").strip()
        auditor = tokens.resolve(token)
        if auditor is None:
            raise HTTPException(status_code=401, detail="invalid auditor token")
        sig = record.get("sig")
        if not isinstance(sig, dict) or not isinstance(sig.get("signature"), str):
            raise HTTPException(status_code=400, detail="record must carry a signature")
        if not verify(auditor.public_pinned, canonical_bytes(record), sig["signature"]):
            raise HTTPException(status_code=400, detail="record signature does not verify for this auditor")
        # The registry countersigns what it serves so clients verify against the
        # registry key alone; the auditor signature is kept as an endorsement
        # for provenance.
        countersigned = _countersign(record, signing_key, endorser=auditor.auditor_id)
        try:
            entry = store.append(countersigned, created_at=utc_now())
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"seq": entry.seq, "entry_hash": entry.entry_hash}

    return app


def _countersign(record: dict[str, Any], signing_key: SigningKey, *, endorser: str) -> dict[str, Any]:
    endorsement = {"endorser": endorser, "sig": record.get("sig")}
    body = {key: value for key, value in record.items() if key != "sig"}
    existing = body.get("endorsements")
    body["endorsements"] = ([*existing, endorsement] if isinstance(existing, list) else [endorsement])
    return signing_key.sign_record(body)


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
