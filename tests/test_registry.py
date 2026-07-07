from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from csk_registry import signing
from csk_registry.app import create_app
from csk_registry.auth import Auditor, AuditorTokens
from csk_registry.snapshot import build_snapshot
from csk_registry.store import Store


def _body(status: str = "audited", **overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": 1,
        "name": "skill-tracker",
        "source_identity": "gitlab.example.com/skills/skill-tracker",
        "commit": "8c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d",
        "content_sha256": "sha256:1f2e3d",
        "status": status,
        "audit": {"ruleset_version": "csk-audit/1"},
    }
    body.update(overrides)
    return body


def test_signing_matches_client_canonical_form():
    # The compact-sorted-JSON canonical form must be stable and reproducible.
    key = signing.generate_key()
    record = key.sign_record(_body())
    expected = json.dumps(
        {k: v for k, v in record.items() if k != "sig"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    assert signing.canonical_bytes(record) == expected
    assert signing.verify(key.public_pinned, expected, record["sig"]["signature"])


def test_store_append_and_lookup(tmp_path: Path):
    store = Store(tmp_path / "r.db")
    key = signing.generate_key()
    store.append(key.sign_record(_body("audited")), created_at="2026-07-07T00:00:00Z")
    found = store.records_for(
        source_identity="gitlab.example.com/skills/skill-tracker",
        commit="8c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d",
    )
    assert len(found) == 1
    assert found[0]["status"] == "audited"
    by_hash = store.records_for(content_sha256="sha256:1f2e3d")
    assert len(by_hash) == 1


def test_revocation_supersedes_audit(tmp_path: Path):
    store = Store(tmp_path / "r.db")
    key = signing.generate_key()
    store.append(key.sign_record(_body("audited")), created_at="2026-07-07T00:00:00Z")
    store.append(key.sign_record(_body("revoked")), created_at="2026-07-07T01:00:00Z")
    found = store.records_for(content_sha256="sha256:1f2e3d")
    assert len(found) == 1
    assert found[0]["status"] == "revoked"


def test_hash_chain_and_verify(tmp_path: Path):
    store = Store(tmp_path / "r.db")
    key = signing.generate_key()
    for i in range(5):
        store.append(key.sign_record(_body("audited", commit=f"{i:040d}")), created_at="2026-07-07T00:00:00Z")
    entries = store.log_entries()
    assert len(entries) == 5
    for prev, entry in zip(entries, entries[1:]):
        assert entry.prev_hash == prev.entry_hash
    assert store.verify_chain()


def test_snapshot_is_signed_and_monotonic(tmp_path: Path):
    store = Store(tmp_path / "r.db")
    key = signing.generate_key()
    snap0 = build_snapshot(store, key, created_at="2026-07-07T00:00:00Z", version=0)
    assert signing.verify(key.public_pinned, signing.canonical_bytes(snap0), snap0["sig"]["signature"])
    store.append(key.sign_record(_body()), created_at="2026-07-07T00:00:00Z")
    snap1 = build_snapshot(store, key, created_at="2026-07-07T00:01:00Z", version=store.head()[0])
    assert snap1["version"] > snap0["version"]
    assert snap1["log_size"] == 1


def _client(tmp_path: Path) -> tuple[TestClient, signing.SigningKey, str]:
    store = Store(tmp_path / "r.db")
    key = signing.generate_key()
    auditor_key = signing.generate_key()
    token = "secret-token"
    tokens = AuditorTokens(
        [
            Auditor(
                auditor_id="a1",
                org="Example",
                public_pinned=auditor_key.public_pinned,
                token_sha256=hashlib.sha256(token.encode()).hexdigest(),
            )
        ]
    )
    app = create_app(store=store, signing_key=key, tokens=tokens)
    # Return the auditor key so tests can sign submissions.
    app.state.auditor_key = auditor_key  # type: ignore[attr-defined]
    return TestClient(app), key, token


def test_endpoints_health_and_meta(tmp_path: Path):
    client, key, _ = _client(tmp_path)
    assert client.get("/health").json() == {"status": "ok"}
    meta = client.get("/v1/meta").json()
    assert key.public_pinned in meta["public_keys"]


def test_submit_requires_valid_token_and_signature(tmp_path: Path):
    client, _, token = _client(tmp_path)
    auditor_key = client.app.state.auditor_key  # type: ignore[attr-defined]
    record = auditor_key.sign_record(_body("audited"))

    # No token.
    assert client.post("/v1/records", json=record).status_code == 401
    # Valid token and signature.
    resp = client.post("/v1/records", json=record, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["seq"] == 1
    # Now retrievable.
    got = client.get(
        "/v1/records",
        params={"content_sha256": "sha256:1f2e3d"},
    ).json()
    assert got["records"][0]["status"] == "audited"


def test_submit_rejects_wrong_signature(tmp_path: Path):
    client, _, token = _client(tmp_path)
    other = signing.generate_key()
    record = other.sign_record(_body("audited"))
    resp = client.post("/v1/records", json=record, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 400


def test_log_endpoint_returns_chain(tmp_path: Path):
    client, _, token = _client(tmp_path)
    auditor_key = client.app.state.auditor_key  # type: ignore[attr-defined]
    for i in range(3):
        client.post(
            "/v1/records",
            json=auditor_key.sign_record(_body("audited", commit=f"{i:040d}")),
            headers={"Authorization": f"Bearer {token}"},
        )
    entries = client.get("/v1/log").json()["entries"]
    assert len(entries) == 3
    assert entries[0]["prev_hash"] == "0" * 64
