from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import sys
import time
import tomllib
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from csk_registry import (
    CHECKPOINT_ENV,
    COMMAND_NAME,
    HOME_ENV,
    LEGACY_COMMAND_NAME,
    LEGACY_HOME_ENV,
    home_from_env,
    signing,
)
from csk_registry.app import _encode_cursor, _url64, app_from_env, create_app
from csk_registry.auth import Auditor, AuditorTokens
from csk_registry.checkpoint import CheckpointView, compare_checkpoint
from csk_registry.cli import build_parser, main
from csk_registry.keys import initialize_key, load_active_key, public_keys, write_private_json
from csk_registry.permissions import (
    private_directory_permissions_enforced,
    private_file_permissions_enforced,
    protect_private_directory,
    protect_private_file,
)
from csk_registry.protocol import (
    JSONDepthError,
    ProtocolError,
    load_json,
    portable_path,
    validate_record,
    validate_source_identity,
)
from csk_registry.snapshot import build_snapshot
from csk_registry.store import (
    CursorBoundaryMismatch,
    SnapshotBoundary,
    Store,
    StoreIntegrityError,
)


def test_public_project_and_cli_identity(monkeypatch: pytest.MonkeyPatch):
    project_root = Path(__file__).parents[1]
    project = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["name"] == COMMAND_NAME
    assert project["scripts"][COMMAND_NAME] == "csk_registry.cli:main"
    assert project["scripts"][LEGACY_COMMAND_NAME] == "csk_registry.cli:main"
    assert project["urls"]["Repository"] == "https://github.com/relux-works/curator-skill-registry"

    monkeypatch.delenv(HOME_ENV, raising=False)
    monkeypatch.delenv(LEGACY_HOME_ENV, raising=False)
    assert build_parser().prog == COMMAND_NAME
    assert build_parser().parse_args(["genkey"]).home == "./data"

    monkeypatch.setenv(LEGACY_HOME_ENV, "/legacy")
    assert home_from_env() == "/legacy"
    monkeypatch.setenv(HOME_ENV, "/current")
    assert home_from_env() == "/current"


def test_auditor_credentials_are_replaced_atomically_with_private_permissions(tmp_path: Path):
    home = tmp_path / "home"
    auditor_key = signing.generate_key()
    assert main(
        [
            "--home",
            str(home),
            "issue-token",
            "auditor-a",
            "--public-key",
            auditor_key.public_pinned,
        ]
    ) == 0
    auditors = home / "auditors.json"
    assert private_directory_permissions_enforced(home)
    assert private_file_permissions_enforced(auditors)
    assert not list(home.glob(".auditors.json-*"))


def test_private_registry_state_uses_platform_access_controls(tmp_path: Path):
    home = tmp_path / "home"
    assert main(["--home", str(home), "genkey"]) == 0
    store = Store(home / "registry.db")
    store.close()

    assert private_directory_permissions_enforced(home)
    assert private_file_permissions_enforced(home / "signing-key.pem")
    assert private_file_permissions_enforced(home / "signing-keyring.json")
    assert private_file_permissions_enforced(home / "registry.db")


def test_private_key_load_fails_closed_for_broad_access(tmp_path: Path):
    home = tmp_path / "home"
    assert main(["--home", str(home), "genkey"]) == 0
    key_path = home / "signing-key.pem"
    if os.name == "nt":
        subprocess.run(
            ["icacls", str(key_path), "/grant", "*S-1-1-0:(R)"],
            check=True,
            capture_output=True,
            text=True,
        )
    else:
        key_path.chmod(0o644)

    with pytest.raises(ValueError, match="unavailable"):
        load_active_key(home)


def _body(status: str = "audited", **overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": 1,
        "name": "skill-tracker",
        "source_identity": "gitlab.example.com/skills/skill-tracker",
        "commit": "8c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d",
        "content_sha256": "sha256:" + "1f" * 32,
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


@pytest.mark.parametrize(
    "source_identity",
    [
        "GitLab.example.com/skills/a",
        "gitlab.example.com/skills/a b",
        "gitlab.example.com/skills/a#fragment",
    ],
)
def test_record_rejects_noncanonical_source_identity(source_identity: str):
    key = signing.generate_key()
    with pytest.raises(ProtocolError, match="source_identity"):
        validate_record(key.sign_record(_body(source_identity=source_identity)))


def test_source_identity_and_portable_path_boundaries():
    assert validate_source_identity("gitlab.example.com/skills/文書") == "gitlab.example.com/skills/文書"
    assert portable_path("directory with space/file name.md")
    for value in ("scripts/", "a//b", "control\u0085name", "stream:name"):
        assert not portable_path(value)


def test_record_rejects_malformed_signature_envelope():
    key = signing.generate_key()
    record = key.sign_record(_body())
    record["sig"]["signature"] = "not-base64"
    with pytest.raises(ProtocolError, match="signature"):
        validate_record(record)


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
    by_hash = store.records_for(content_sha256="sha256:" + "1f" * 32)
    assert len(by_hash) == 1


def test_revocation_supersedes_audit(tmp_path: Path):
    store = Store(tmp_path / "r.db")
    key = signing.generate_key()
    store.append(key.sign_record(_body("audited")), created_at="2026-07-07T00:00:00Z")
    store.append(key.sign_record(_body("revoked")), created_at="2026-07-07T01:00:00Z")
    found = store.records_for(content_sha256="sha256:" + "1f" * 32)
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
    snap0 = build_snapshot(store, key)
    assert signing.verify(key.public_pinned, signing.canonical_bytes(snap0), snap0["sig"]["signature"])
    store.append(key.sign_record(_body()), created_at="2026-07-07T00:00:00Z")
    snap1 = build_snapshot(store, key)
    assert snap1["version"] > snap0["version"]
    assert snap1["log_size"] == 1
    assert snap1["created_at"] == "2026-07-07T00:00:00Z"
    assert build_snapshot(store, key) == snap1
    with pytest.raises(ValueError, match="created_at"):
        build_snapshot(store, key, created_at="2026-07-07T00:01:00Z")


def _client(tmp_path: Path) -> tuple[TestClient, signing.SigningKey, str]:
    store = Store(tmp_path / "r.db")
    key = signing.generate_key()
    auditor_key = signing.generate_key()
    token = "test-token-with-at-least-128-bit-capacity"
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
    assert client.app.title == "Curator Skill Registry"  # type: ignore[attr-defined]
    assert client.get("/health").json() == {"status": "ok"}
    meta = client.get("/v1/meta").json()
    assert meta["name"] == COMMAND_NAME
    assert key.public_pinned in meta["public_keys"]


def test_submit_requires_valid_token_and_signature(tmp_path: Path):
    client, _, token = _client(tmp_path)
    auditor_key = client.app.state.auditor_key  # type: ignore[attr-defined]
    record = auditor_key.sign_record(_body("audited"))

    # No token.
    assert client.post("/v1/records", json=record).status_code == 401
    # Valid token and signature.
    resp = client.post("/v1/records", json=record, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 201
    assert resp.json()["seq"] == 1
    # Now retrievable.
    got = client.get(
        "/v1/records",
        params={"content_sha256": "sha256:" + "1f" * 32},
    ).json()
    assert got["records"][0]["status"] == "audited"
    assert got["next_cursor"] is None


def test_submit_rejects_wrong_signature(tmp_path: Path):
    client, _, token = _client(tmp_path)
    other = signing.generate_key()
    record = other.sign_record(_body("audited"))
    resp = client.post("/v1/records", json=record, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 400


def _nested_list(depth: int) -> list[Any]:
    value: list[Any] = []
    for _ in range(depth - 1):
        value = [value]
    return value


def test_load_json_rejects_over_deep_nesting():
    bound = signing.MAX_JSON_DEPTH
    assert isinstance(load_json("[" * bound + "]" * bound), list)
    assert isinstance(load_json('{"a":' * bound + "1" + "}" * bound), dict)
    for raw in (
        "[" * (bound + 1) + "]" * (bound + 1),
        ('{"a":' * (bound + 1) + "1" + "}" * (bound + 1)).encode("utf-8"),
        "[" * 5000 + "]" * 5000,
    ):
        with pytest.raises(JSONDepthError) as excinfo:
            load_json(raw)
        assert str(bound) in str(excinfo.value)
        with pytest.raises(ProtocolError):
            load_json(raw)
    # Brackets inside strings do not count toward the bound.
    load_json('{"k": "' + "[" * (bound + 10) + '"}')
    load_json(b'{"k": "' + b"[" * (bound + 10) + b'"}')


def test_load_json_maps_recursion_error_to_depth_error(monkeypatch: pytest.MonkeyPatch):
    def boom(value: object) -> bytes:
        raise RecursionError("boom")

    monkeypatch.setattr("csk_registry.protocol.canonical_document_bytes", boom)
    with pytest.raises(JSONDepthError, match="maximum depth"):
        load_json('{"a": 1}')


def test_canonicalization_rejects_over_deep_nesting():
    bound = signing.MAX_JSON_DEPTH
    signing.canonical_document_bytes(_nested_list(bound))
    with pytest.raises(signing.CanonicalDepthError) as excinfo:
        signing.canonical_document_bytes(_nested_list(bound + 1))
    assert str(bound) in str(excinfo.value)
    with pytest.raises(signing.CanonicalDepthError, match="maximum depth"):
        signing.canonical_bytes({"k": _nested_list(bound + 1)})
    assert signing.verify_signed("ed25519:" + "A" * 43 + "=", {"k": _nested_list(bound + 1)}) is False
    # Depth failures honor the protocol contract while keeping
    # CanonicalError/ValueError compatibility for existing handlers.
    assert issubclass(signing.CanonicalDepthError, ProtocolError)
    assert issubclass(signing.CanonicalDepthError, signing.CanonicalError)
    with pytest.raises(ProtocolError, match="maximum depth"):
        signing.canonical_document_bytes(_nested_list(bound + 1))
    with pytest.raises(ProtocolError, match="maximum depth"):
        signing.canonical_bytes({"k": _nested_list(bound + 1)})


@pytest.mark.parametrize("entry_point", ["canonical_bytes", "canonical_document_bytes"])
@pytest.mark.parametrize("fault", ["validate_ccj", "json_dumps"])
def test_canonicalization_maps_recursion_error_to_protocol_error(
    monkeypatch: pytest.MonkeyPatch, entry_point: str, fault: str
):
    if fault == "validate_ccj":
        # RecursionError raised from the CCJ validation path.
        def boom_validate(value: object, depth: int = 0) -> None:
            raise RecursionError("boom")

        monkeypatch.setattr("csk_registry.signing._validate_ccj", boom_validate)
    else:
        # RecursionError raised from JSON serialization.
        def boom_dumps(*args: Any, **kwargs: Any) -> str:
            raise RecursionError("boom")

        monkeypatch.setattr("csk_registry.signing.json.dumps", boom_dumps)
    call = getattr(signing, entry_point)
    with pytest.raises(signing.CanonicalDepthError, match="maximum depth"):
        call({"a": 1})
    with pytest.raises(ProtocolError, match="maximum depth"):
        call({"a": 1})


def test_submit_rejects_deeply_nested_json_with_invalid_json(tmp_path: Path):
    client, _, token = _client(tmp_path)
    bound = signing.MAX_JSON_DEPTH
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    # Just over the explicit bound (far below the interpreter limit).
    over = "[" * (bound + 1) + "]" * (bound + 1)
    resp = client.post("/v1/records", content=over, headers=headers)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "invalid_json"
    # Pathological depth that previously raised RecursionError -> 500.
    pathological = "[" * 5000 + "]" * 5000
    resp = client.post("/v1/records", content=pathological, headers=headers)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "invalid_json"
    # Same verdict on the idempotent-submit path.
    resp = client.post(
        "/v1/records",
        content=pathological,
        headers={**headers, "Idempotency-Key": "deep-key"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "invalid_json"
    # Non-depth errors keep their existing mapping.
    resp = client.post("/v1/records", content="{bad json", headers=headers)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "invalid_record"


def test_deeply_nested_cursor_is_invalid_cursor_not_500(tmp_path: Path):
    client, key, _ = _client(tmp_path)
    payload = ("[" * 1200 + "]" * 1200).encode("utf-8")
    signature = base64.b64decode(key.sign(payload))
    cursor = f"{_url64(payload)}.{_url64(signature)}"
    assert len(cursor) <= 4096
    resp = client.get("/v1/log", params={"since": 0, "limit": 1, "cursor": cursor})
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "invalid_cursor"


def test_submission_audit_log_is_structured_and_omits_bearer_token(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
):
    client, _, token = _client(tmp_path)
    with caplog.at_level(logging.INFO, logger="csk_registry.audit"):
        response = client.post(
            "/v1/records",
            json={},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 400
    event = json.loads(caplog.records[-1].message)
    assert event["event"] == "registry_request"
    assert event["authentication"] == "accepted"
    assert event["auditor_id"] == "a1"
    assert event["error_code"] == "invalid_record"
    assert token not in caplog.text


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


def test_post_countersigns_with_registry_key(tmp_path: Path):
    client, registry_key, token = _client(tmp_path)
    auditor_key = client.app.state.auditor_key  # type: ignore[attr-defined]
    record = auditor_key.sign_record(_body("audited"))
    resp = client.post("/v1/records", json=record, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 201
    served = client.get("/v1/records", params={"content_sha256": "sha256:" + "1f" * 32}).json()["records"][0]
    # The served record verifies against the registry key, not the auditor key.
    assert signing.verify(registry_key.public_pinned, signing.canonical_bytes(served), served["sig"]["signature"])
    assert not signing.verify(auditor_key.public_pinned, signing.canonical_bytes(served), served["sig"]["signature"])
    # The auditor signature is retained as an endorsement.
    assert served["endorsements"][0]["endorser"] == "a1"


def test_export_and_import_bundle_roundtrip(tmp_path: Path):
    from csk_registry.bundle import export_bundle, import_bundle

    upstream = Store(tmp_path / "up.db")
    up_key = signing.generate_key()
    up_key.sign_record(_body("audited"))
    upstream.append(up_key.sign_record(_body("audited")), created_at="2026-07-07T00:00:00Z")
    upstream.append(up_key.sign_record(_body("revoked", commit="1" * 40)), created_at="2026-07-07T01:00:00Z")
    bundle = export_bundle(upstream, up_key)
    assert len(bundle["records"]) == 2

    downstream = Store(tmp_path / "down.db")
    down_key = signing.generate_key()
    count = import_bundle(downstream, down_key, bundle, upstream_public_key=up_key.public_pinned)
    assert count == 2
    # Imported records are countersigned by the downstream key.
    served = downstream.records_for(content_sha256="sha256:" + "1f" * 32)[0]
    assert signing.verify(down_key.public_pinned, signing.canonical_bytes(served), served["sig"]["signature"])
    assert served["endorsements"][0]["endorser"] == "upstream-import"


def test_import_bundle_rejects_wrong_upstream_key(tmp_path: Path):
    from csk_registry.bundle import export_bundle, import_bundle

    upstream = Store(tmp_path / "up.db")
    up_key = signing.generate_key()
    upstream.append(up_key.sign_record(_body("audited")), created_at="2026-07-07T00:00:00Z")
    bundle = export_bundle(upstream, up_key)

    downstream = Store(tmp_path / "down.db")
    down_key = signing.generate_key()
    wrong_key = signing.generate_key()
    import pytest

    with pytest.raises(ValueError, match="does not verify"):
        import_bundle(downstream, down_key, bundle, upstream_public_key=wrong_key.public_pinned)


def test_records_pagination_cursor_is_query_bound(tmp_path: Path):
    client, _, token = _client(tmp_path)
    auditor_key = client.app.state.auditor_key  # type: ignore[attr-defined]
    content_hash = "sha256:" + "1f" * 32
    for index in range(3):
        record = auditor_key.sign_record(_body(name=f"skill-{index}"))
        assert client.post(
            "/v1/records", json=record, headers={"Authorization": f"Bearer {token}"}
        ).status_code == 201
    first = client.get("/v1/records", params={"content_sha256": content_hash, "limit": 1})
    assert first.status_code == 200
    first_body = first.json()
    assert [record["name"] for record in first_body["records"]] == ["skill-0"]
    cursor = first_body["next_cursor"]
    replacement = auditor_key.sign_record(_body("revoked", name="skill-0"))
    assert client.post(
        "/v1/records",
        json=replacement,
        headers={"Authorization": f"Bearer {token}"},
    ).status_code == 201
    second = client.get(
        "/v1/records",
        params={"content_sha256": content_hash, "limit": 1, "cursor": cursor},
    )
    assert [record["name"] for record in second.json()["records"]] == ["skill-1"]
    new_first = client.get(
        "/v1/records",
        params={"content_sha256": content_hash, "limit": 1},
    ).json()
    assert new_first["records"][0]["status"] == "revoked"
    rebound = client.get(
        "/v1/records",
        params={"content_sha256": "sha256:" + "2f" * 32, "limit": 1, "cursor": cursor},
    )
    assert rebound.status_code == 404
    assert rebound.json()["error"]["code"] == "invalid_cursor"


def test_store_uses_exact_artifact_key_and_conjunctive_filters(tmp_path: Path):
    store = Store(tmp_path / "r.db")
    key = signing.generate_key()
    source = "gitlab.example.com/skills/skill-tracker"
    commit = "8c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d"
    hash_a = "sha256:" + "1f" * 32
    hash_b = "sha256:" + "2f" * 32
    store.append(
        key.sign_record(_body("audited", content_sha256=hash_a)),
        created_at="2026-07-07T00:00:00Z",
    )
    store.append(
        key.sign_record(_body("pending", content_sha256=hash_b)),
        created_at="2026-07-07T00:01:00Z",
    )
    store.append(
        key.sign_record(_body("revoked", content_sha256=hash_a)),
        created_at="2026-07-07T00:02:00Z",
    )

    by_identity = store.records_for(source_identity=source, commit=commit)
    assert [(record["content_sha256"], record["status"]) for record in by_identity] == [
        (hash_a, "revoked"),
        (hash_b, "pending"),
    ]
    assert store.records_for(
        source_identity=source,
        commit=commit,
        content_sha256=hash_b,
    )[0]["status"] == "pending"
    assert store.records_for(
        source_identity=source,
        commit=commit,
        content_sha256="sha256:" + "3f" * 32,
    ) == []


def test_query_parameters_reject_ambiguity(tmp_path: Path):
    client, _, _ = _client(tmp_path)
    source = "gitlab.example.com/skills/skill-tracker"
    commit = "8c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d"
    for query in (
        f"source_identity={source}",
        f"commit={commit}",
        "content_sha256=",
        "content_sha256=sha256%3A" + "1f" * 32 + "&limit=1&limit=2",
        "content_sha256=sha256%3A" + "1f" * 32 + "&unknown=true",
    ):
        response = client.get(f"/v1/records?{query}")
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "invalid_query"


def test_idempotency_is_scoped_by_auditor(tmp_path: Path):
    store = Store(tmp_path / "r.db")
    key = signing.generate_key()
    first = key.sign_record(_body("audited"))
    second = key.sign_record(_body("pending", content_sha256="sha256:" + "2f" * 32))
    for auditor, record, digest in (
        ("auditor-a", first, "a" * 64),
        ("auditor-b", second, "b" * 64),
    ):
        response, replayed = store.append_idempotent(
            record,
            auditor_id=auditor,
            key="shared-key",
            body_sha256=digest,
            created_at="2026-07-07T00:00:00Z",
            now=1,
            ttl_seconds=86400,
        )
        assert response["seq"] in {1, 2}
        assert not replayed
    assert store.head()[0] == 2


def test_unscoped_legacy_idempotency_requires_expiry_before_migration(tmp_path: Path):
    path = tmp_path / "legacy.db"
    store = Store(path)
    entry = store.append(
        signing.generate_key().sign_record(_body()),
        created_at="2026-07-07T00:00:00Z",
    )
    store.close()
    connection = sqlite3.connect(path)
    connection.execute("DROP TABLE idempotency")
    connection.execute(
        "CREATE TABLE idempotency ("
        "key TEXT PRIMARY KEY, body_sha256 TEXT NOT NULL, "
        "response_json TEXT NOT NULL, expires_at INTEGER NOT NULL)"
    )
    response = json.dumps({"seq": entry.seq, "entry_hash": entry.entry_hash})
    connection.execute(
        "INSERT INTO idempotency VALUES (?, ?, ?, ?)",
        ("legacy-key", "a" * 64, response, int(time.time()) + 3600),
    )
    connection.execute("DELETE FROM metadata WHERE key = 'schema_version'")
    connection.execute("PRAGMA user_version=0")
    connection.commit()
    connection.close()
    with pytest.raises(StoreIntegrityError, match="no auditor scope"):
        Store(path)

    connection = sqlite3.connect(path)
    connection.execute("UPDATE idempotency SET expires_at = 0")
    connection.commit()
    connection.close()
    migrated = Store(path)
    assert migrated._conn.execute("SELECT COUNT(*) FROM idempotency").fetchone()[0] == 0  # type: ignore[attr-defined]


def test_idempotent_append_rolls_back_if_ledger_write_fails(tmp_path: Path):
    store = Store(tmp_path / "r.db")
    store._conn.execute(  # type: ignore[attr-defined]
        "CREATE TRIGGER fail_idempotency BEFORE INSERT ON idempotency "
        "BEGIN SELECT RAISE(ABORT, 'injected failure'); END"
    )
    with pytest.raises(sqlite3.IntegrityError, match="injected failure"):
        store.append_idempotent(
            signing.generate_key().sign_record(_body()),
            auditor_id="auditor-a",
            key="request",
            body_sha256="a" * 64,
            created_at="2026-07-07T00:00:00Z",
            now=1,
            ttl_seconds=86400,
        )
    assert store.head()[0] == 0


def test_bundle_import_is_one_transaction(tmp_path: Path):
    store = Store(tmp_path / "r.db")
    key = signing.generate_key()
    valid = key.sign_record(_body())
    invalid = key.sign_record(_body())
    del invalid["name"]
    with pytest.raises(ValueError, match="name"):
        store.append_imports(
            [("a" * 64, valid), ("b" * 64, invalid)],
            created_at="2026-07-07T00:00:00Z",
        )
    assert store.head()[0] == 0


def test_concurrent_store_instances_serialize_writers(tmp_path: Path):
    path = tmp_path / "r.db"
    Store(path).close()
    key = signing.generate_key()
    records = [
        key.sign_record(_body(name=f"skill-{index}", commit=f"{index:040d}"))
        for index in range(32)
    ]

    def append(index: int) -> int:
        store = Store(path)
        try:
            return store.append(
                records[index],
                created_at="2026-07-07T00:00:00Z",
            ).seq
        finally:
            store.close()

    with ThreadPoolExecutor(max_workers=8) as executor:
        sequences = list(executor.map(append, range(len(records))))
    assert sorted(sequences) == list(range(1, 33))
    reopened = Store(path)
    assert reopened.verify_chain()
    assert reopened.head()[0] == 32


def test_recovery_refuses_corrupt_authoritative_log(tmp_path: Path):
    path = tmp_path / "r.db"
    store = Store(path)
    store.append(
        signing.generate_key().sign_record(_body()),
        created_at="2026-07-07T00:00:00Z",
    )
    store.close()
    connection = sqlite3.connect(path)
    connection.execute("UPDATE log SET prev_hash = ?", ("f" * 64,))
    connection.commit()
    connection.close()
    with pytest.raises(StoreIntegrityError, match="previous hash"):
        Store(path)


def test_backup_and_external_checkpoint_preserve_boundary(tmp_path: Path):
    store = Store(tmp_path / "r.db")
    key = signing.generate_key()
    store.append(key.sign_record(_body()), created_at="2026-07-07T00:00:00Z")
    checkpoint = store.snapshot_boundary()
    backup_boundary = store.backup_to(tmp_path / "backup.db")
    assert backup_boundary == checkpoint
    store.append(
        key.sign_record(_body("revoked")),
        created_at="2026-07-07T01:00:00Z",
    )
    assert store.checkpoint_matches(checkpoint)
    ahead = SnapshotBoundary(
        version=3,
        log_size=3,
        head="f" * 64,
        merkle_root="f" * 64,
        created_at="2026-07-07T02:00:00Z",
    )
    assert not store.checkpoint_matches(ahead)


def test_backup_cli_emits_and_verifies_signed_checkpoint(tmp_path: Path):
    home = tmp_path / "home"
    home.mkdir()
    protect_private_directory(home)
    key = signing.generate_key()
    key_path = home / "signing-key.pem"
    key_path.write_bytes(signing.export_key_pem(key))
    protect_private_file(key_path)
    store = Store(home / "registry.db")
    store.append(key.sign_record(_body()), created_at="2026-07-07T00:00:00Z")
    store.close()

    backup = tmp_path / "backup.db"
    checkpoint = tmp_path / "checkpoint.json"
    assert main(
        [
            "--home",
            str(home),
            "backup",
            "--out",
            str(backup),
            "--checkpoint-out",
            str(checkpoint),
        ]
    ) == 0
    assert main(
        [
            "--home",
            str(home),
            "verify-backup",
            str(backup),
            "--checkpoint",
            str(checkpoint),
        ]
    ) == 0

    live = Store(home / "registry.db")
    live.append(key.sign_record(_body("revoked")), created_at="2026-07-07T01:00:00Z")
    newer_checkpoint = tmp_path / "newer-checkpoint.json"
    newer_checkpoint.write_text(
        json.dumps(build_snapshot(live, key)),
        encoding="utf-8",
    )
    live.close()
    assert main(
        [
            "--home",
            str(home),
            "verify-backup",
            str(backup),
            "--checkpoint",
            str(newer_checkpoint),
        ]
    ) == 2


def test_verify_backup_without_public_key_warns_on_stderr_and_in_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    protect_private_directory(home)
    key = signing.generate_key()
    key_path = home / "signing-key.pem"
    key_path.write_bytes(signing.export_key_pem(key))
    protect_private_file(key_path)
    store = Store(home / "registry.db")
    store.append(key.sign_record(_body()), created_at="2026-07-07T00:00:00Z")
    store.close()

    backup = tmp_path / "backup.db"
    checkpoint = tmp_path / "checkpoint.json"
    assert main(
        [
            "--home",
            str(home),
            "backup",
            "--out",
            str(backup),
            "--checkpoint-out",
            str(checkpoint),
        ]
    ) == 0
    capsys.readouterr()

    assert main(
        [
            "--home",
            str(home),
            "verify-backup",
            str(backup),
            "--checkpoint",
            str(checkpoint),
        ]
    ) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["backup_valid"] is True
    assert str(home) in payload["warning"]
    assert "--public-key" in payload["warning"]
    assert "out-of-band" in payload["warning"]
    assert "WARNING" in captured.err
    assert str(home) in captured.err
    assert "--public-key" in captured.err

    live = Store(home / "registry.db")
    live.append(key.sign_record(_body("revoked")), created_at="2026-07-07T01:00:00Z")
    newer_checkpoint = tmp_path / "newer-checkpoint.json"
    newer_checkpoint.write_text(
        json.dumps(build_snapshot(live, key)),
        encoding="utf-8",
    )
    live.close()
    assert main(
        [
            "--home",
            str(home),
            "verify-backup",
            str(backup),
            "--checkpoint",
            str(newer_checkpoint),
        ]
    ) == 2
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["backup_valid"] is False
    assert "error" in payload
    assert str(home) in payload["warning"]
    assert "--public-key" in payload["warning"]
    assert "WARNING" in captured.err
    assert str(home) in captured.err


def test_verify_backup_with_explicit_public_key_is_quiet(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    protect_private_directory(home)
    key = signing.generate_key()
    key_path = home / "signing-key.pem"
    key_path.write_bytes(signing.export_key_pem(key))
    protect_private_file(key_path)
    store = Store(home / "registry.db")
    store.append(key.sign_record(_body()), created_at="2026-07-07T00:00:00Z")
    store.close()

    backup = tmp_path / "backup.db"
    checkpoint = tmp_path / "checkpoint.json"
    assert main(
        [
            "--home",
            str(home),
            "backup",
            "--out",
            str(backup),
            "--checkpoint-out",
            str(checkpoint),
        ]
    ) == 0
    capsys.readouterr()

    assert main(
        [
            "--home",
            str(home),
            "verify-backup",
            str(backup),
            "--checkpoint",
            str(checkpoint),
            "--public-key",
            key.public_pinned,
        ]
    ) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert set(payload) == {"backup_valid", "log_size", "head"}
    assert payload["backup_valid"] is True
    assert "live home" not in captured.err
    assert "out-of-band" not in captured.err

    live = Store(home / "registry.db")
    live.append(key.sign_record(_body("revoked")), created_at="2026-07-07T01:00:00Z")
    newer_checkpoint = tmp_path / "newer-checkpoint.json"
    newer_checkpoint.write_text(
        json.dumps(build_snapshot(live, key)),
        encoding="utf-8",
    )
    live.close()
    assert main(
        [
            "--home",
            str(home),
            "verify-backup",
            str(backup),
            "--checkpoint",
            str(newer_checkpoint),
            "--public-key",
            key.public_pinned,
        ]
    ) == 2
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert set(payload) == {"backup_valid", "error"}
    assert payload["backup_valid"] is False
    assert "live home" not in captured.err
    assert "out-of-band" not in captured.err


def _startup_home(home: Path, *, records: int) -> tuple[signing.SigningKey, str]:
    """Create a serve-ready home with a key, one auditor, and a live log."""
    home.mkdir(parents=True, exist_ok=True)
    key = initialize_key(home)
    auditor_key = signing.generate_key()
    token = "startup-checkpoint-unit-test-token"
    write_private_json(
        home / "auditors.json",
        {
            "auditors": [
                {
                    "auditor_id": "a1",
                    "org": "Example",
                    "public_key": auditor_key.public_pinned,
                    "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                }
            ]
        },
    )
    store = Store(home / "registry.db")
    for index in range(records):
        store.append(
            key.sign_record(
                _body(
                    "audited",
                    name=f"skill-checkpoint-{index}",
                    commit=f"{index:040d}",
                    content_sha256="sha256:" + f"{index:064x}",
                )
            ),
            created_at=f"2026-07-13T00:00:{index:02d}Z",
        )
    store.close()
    return auditor_key, token


def test_serve_checkpoint_flag_sets_env_and_defers_to_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    assert build_parser().parse_args(["serve"]).checkpoint is None
    assert (
        build_parser()
        .parse_args(["serve", "--checkpoint", "/secure/checkpoint.json"])
        .checkpoint
        == "/secure/checkpoint.json"
    )

    seen: dict[str, object] = {}

    def fake_run(app: object, **kwargs: object) -> None:
        seen["app"] = app
        seen["kwargs"] = kwargs

    monkeypatch.setattr("uvicorn.run", fake_run)
    monkeypatch.setattr("csk_registry.app.app_from_env", lambda: "app-sentinel")
    home = tmp_path / "home"
    old_home = os.environ.get(HOME_ENV)
    old_checkpoint = os.environ.get(CHECKPOINT_ENV)
    try:
        # The flag wins over the environment.
        monkeypatch.setenv(CHECKPOINT_ENV, "/from/env.json")
        assert (
            main(["--home", str(home), "serve", "--checkpoint", "/from/flag.json"]) == 0
        )
        assert os.environ[HOME_ENV] == str(home)
        assert os.environ[CHECKPOINT_ENV] == "/from/flag.json"
        assert seen["app"] == "app-sentinel"
        # Without the flag the environment value passes through untouched.
        monkeypatch.setenv(CHECKPOINT_ENV, "/from/env.json")
        assert main(["--home", str(home), "serve"]) == 0
        assert os.environ[CHECKPOINT_ENV] == "/from/env.json"
    finally:
        if old_home is None:
            os.environ.pop(HOME_ENV, None)
        else:
            os.environ[HOME_ENV] = old_home
        if old_checkpoint is None:
            os.environ.pop(CHECKPOINT_ENV, None)
        else:
            os.environ[CHECKPOINT_ENV] = old_checkpoint


_SERVE_SUBPROCESS_TIMEOUT_SECONDS = 10.0


def _serve_console_command(home: Path, extra: list[str]) -> list[str]:
    """Resolve the real console entry point for a serve subprocess probe."""
    script = shutil.which(COMMAND_NAME)
    if script is None:
        # Editable installs always provide the script; fall back to the
        # module entry through this interpreter if PATH lacks it.
        return [
            sys.executable,
            "-c",
            "import sys; from csk_registry.cli import main; sys.exit(main(sys.argv[1:]))",
            "--home",
            str(home),
            "serve",
            "--port",
            "0",
            *extra,
        ]
    return [script, "--home", str(home), "serve", "--port", "0", *extra]


def _run_serve_until_terminated(home: Path, extra: list[str], env: dict[str, str]) -> str:
    """Run the real console entry in a fresh process; capture startup output.

    The server is expected to stay up on an ephemeral port; the probe
    terminates it once the startup output is produced and returns the combined
    output. Fails loudly when the process exits early instead of serving.
    """
    child_env = dict(env)
    src_dir = str(Path(__file__).parents[1] / "src")
    child_env["PYTHONPATH"] = (
        src_dir + os.pathsep + child_env["PYTHONPATH"]
        if child_env.get("PYTHONPATH")
        else src_dir
    )
    proc = subprocess.Popen(
        _serve_console_command(home, extra),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=child_env,
    )
    try:
        output, _ = proc.communicate(timeout=_SERVE_SUBPROCESS_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            output, _ = proc.communicate(timeout=_SERVE_SUBPROCESS_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            proc.kill()
            output, _ = proc.communicate()
    else:
        raise AssertionError(f"serve exited early (code {proc.returncode}):\n{output}")
    return output


def _startup_checkpoint_events(output: str) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for line in output.splitlines():
        if "startup_checkpoint" not in line:
            continue
        try:
            payload = json.loads(line)
        except ValueError:
            continue
        if isinstance(payload, dict) and payload.get("event") == "startup_checkpoint":
            events.append(payload)
    return events


def test_serve_subprocess_records_no_checkpoint_posture_on_stderr(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _startup_home(home, records=2)
    env = dict(os.environ)
    env.pop(CHECKPOINT_ENV, None)
    output = _run_serve_until_terminated(home, [], env)
    assert "Application startup complete." in output
    events = _startup_checkpoint_events(output)
    assert len(events) == 1
    assert events[0]["configured"] is False
    assert events[0]["posture"] == "checkpoint_not_configured"


def test_serve_subprocess_records_successful_comparison_on_stderr(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _startup_home(home, records=3)
    key = load_active_key(home)
    store = Store(home / "registry.db")
    checkpoint_snapshot = build_snapshot(store, key)
    store.close()
    checkpoint_path = tmp_path / "checkpoint.json"
    checkpoint_path.write_text(json.dumps(checkpoint_snapshot), encoding="utf-8")
    env = dict(os.environ)
    env.pop(CHECKPOINT_ENV, None)
    output = _run_serve_until_terminated(home, ["--checkpoint", str(checkpoint_path)], env)
    assert "Application startup complete." in output
    events = _startup_checkpoint_events(output)
    assert len(events) == 1
    assert events[0]["configured"] is True
    assert events[0]["result"] == "ok"
    assert events[0]["checkpoint"] == {
        "version": 3,
        "log_size": 3,
        "head": checkpoint_snapshot["head"],
    }
    assert events[0]["live"] == {
        "version": 3,
        "log_size": 3,
        "head": checkpoint_snapshot["head"],
    }


def test_serve_refuses_restored_older_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    home = tmp_path / "home"
    auditor_key, token = _startup_home(home, records=7)
    key = load_active_key(home)
    store = Store(home / "registry.db")
    older_backup = tmp_path / "older.db"
    store.backup_to(older_backup)
    for index in range(7, 10):
        store.append(
            key.sign_record(
                _body(
                    "audited",
                    name=f"skill-checkpoint-{index}",
                    commit=f"{index:040d}",
                    content_sha256="sha256:" + f"{index:064x}",
                )
            ),
            created_at=f"2026-07-13T00:00:{index:02d}Z",
        )
    checkpoint_path = tmp_path / "checkpoint.json"
    checkpoint_snapshot = build_snapshot(store, key)
    checkpoint_path.write_text(json.dumps(checkpoint_snapshot), encoding="utf-8")
    store.close()
    probe = Store(older_backup)
    older_boundary = probe.snapshot_boundary()
    probe.close()
    # Silently restore the older database over the live one.
    (home / "registry.db").write_bytes(older_backup.read_bytes())
    for sidecar in ("-wal", "-shm"):
        (home / f"registry.db{sidecar}").unlink(missing_ok=True)

    monkeypatch.setenv(HOME_ENV, str(home))
    monkeypatch.setenv(CHECKPOINT_ENV, str(checkpoint_path))
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="csk_registry.audit"):
        client = TestClient(app_from_env())

    refused = client.get("/health")
    assert refused.status_code == 503
    assert refused.json()["error"]["code"] == "restore_below_checkpoint"
    write = client.post(
        "/v1/records",
        json=auditor_key.sign_record(_body("audited", name="skill-late-write")),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert write.status_code == 503
    assert write.json()["error"]["code"] == "storage_unavailable"
    # Reads still serve, exactly like a §5 latch: only readiness and writes refuse.
    assert client.get("/v1/snapshot").status_code == 200

    events = []
    for record in caplog.records:
        try:
            payload = json.loads(record.getMessage())
        except (TypeError, ValueError):
            continue
        if isinstance(payload, dict) and payload.get("event") == "startup_checkpoint":
            events.append(payload)
    assert len(events) == 1
    assert events[0]["result"] == "refused"
    assert events[0]["diagnostic"] == "restore_below_checkpoint"
    assert events[0]["checkpoint"] == {
        "version": 10,
        "log_size": 10,
        "head": checkpoint_snapshot["head"],
    }
    assert events[0]["live"] == {
        "version": 7,
        "log_size": 7,
        "head": older_boundary.head,
    }

    # The refusal repaired nothing: the restored database is byte-identical.
    assert (home / "registry.db").read_bytes() == older_backup.read_bytes()
    reopened = Store(home / "registry.db")
    try:
        assert reopened.head()[0] == 7
        assert reopened.health_verdict().ready
    finally:
        reopened.close()


def test_serve_cli_entry_refuses_restored_older_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    auditor_key, token = _startup_home(home, records=7)
    key = load_active_key(home)
    store = Store(home / "registry.db")
    older_backup = tmp_path / "older.db"
    store.backup_to(older_backup)
    for index in range(7, 10):
        store.append(
            key.sign_record(
                _body(
                    "audited",
                    name=f"skill-checkpoint-{index}",
                    commit=f"{index:040d}",
                    content_sha256="sha256:" + f"{index:064x}",
                )
            ),
            created_at=f"2026-07-13T00:00:{index:02d}Z",
        )
    checkpoint_path = tmp_path / "checkpoint.json"
    checkpoint_path.write_text(
        json.dumps(build_snapshot(store, key)), encoding="utf-8"
    )
    store.close()
    # Silently restore the older database over the live one.
    (home / "registry.db").write_bytes(older_backup.read_bytes())
    for sidecar in ("-wal", "-shm"):
        (home / f"registry.db{sidecar}").unlink(missing_ok=True)

    # Drive the real CLI entry with the factory and enforcement real; only
    # Uvicorn's final run boundary is intercepted to inspect the app.
    captured: dict[str, object] = {}

    def fake_run(app: object, **kwargs: object) -> None:
        captured["app"] = app
        captured["kwargs"] = kwargs

    monkeypatch.setattr("uvicorn.run", fake_run)
    old_home = os.environ.get(HOME_ENV)
    old_checkpoint = os.environ.get(CHECKPOINT_ENV)
    os.environ.pop(CHECKPOINT_ENV, None)
    try:
        assert (
            main(["--home", str(home), "serve", "--checkpoint", str(checkpoint_path)])
            == 0
        )
        assert os.environ[HOME_ENV] == str(home)
        assert os.environ[CHECKPOINT_ENV] == str(checkpoint_path)
        app = captured["app"]
        assert isinstance(app, FastAPI)
        client = TestClient(app)
        refused = client.get("/health")
        assert refused.status_code == 503
        assert refused.json()["error"]["code"] == "restore_below_checkpoint"
        write = client.post(
            "/v1/records",
            json=auditor_key.sign_record(_body("audited", name="skill-late-write")),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert write.status_code == 503
        assert write.json()["error"]["code"] == "storage_unavailable"
        assert client.get("/v1/snapshot").status_code == 200
        assert (home / "registry.db").read_bytes() == older_backup.read_bytes()
        reopened = Store(home / "registry.db")
        try:
            assert reopened.head()[0] == 7
            assert reopened.health_verdict().ready
        finally:
            reopened.close()
    finally:
        if old_home is None:
            os.environ.pop(HOME_ENV, None)
        else:
            os.environ[HOME_ENV] = old_home
        if old_checkpoint is None:
            os.environ.pop(CHECKPOINT_ENV, None)
        else:
            os.environ[CHECKPOINT_ENV] = old_checkpoint


def test_startup_checkpoint_unreadable_or_malformed_fails_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    home = tmp_path / "home"
    _startup_home(home, records=1)
    monkeypatch.setenv(HOME_ENV, str(home))
    monkeypatch.setenv(CHECKPOINT_ENV, str(home / "missing.json"))
    with pytest.raises(RuntimeError, match="startup checkpoint is unreadable"):
        app_from_env()
    (home / "bad.json").write_text("not json{", encoding="utf-8")
    monkeypatch.setenv(CHECKPOINT_ENV, str(home / "bad.json"))
    with pytest.raises(RuntimeError, match="not a signed registry-snapshot-v1 object"):
        app_from_env()
    (home / "shape.json").write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
    monkeypatch.setenv(CHECKPOINT_ENV, str(home / "shape.json"))
    with pytest.raises(RuntimeError, match="not a signed registry-snapshot-v1 object"):
        app_from_env()


def test_compare_checkpoint_closed_diagnostics() -> None:
    live = SnapshotBoundary(
        version=8,
        log_size=8,
        head="a" * 64,
        merkle_root="b" * 64,
        created_at="2026-07-13T00:00:07Z",
    )
    same = CheckpointView(
        version=8,
        log_size=8,
        head="a" * 64,
        merkle_root="b" * 64,
        created_at="2026-07-13T00:00:07Z",
    )
    assert compare_checkpoint(live, same, live) is None
    above = SnapshotBoundary(
        version=10,
        log_size=10,
        head="c" * 64,
        merkle_root="d" * 64,
        created_at="2026-07-13T00:00:09Z",
    )
    assert compare_checkpoint(above, same, live) is None
    assert (
        compare_checkpoint(
            live,
            CheckpointView(
                version=9,
                log_size=9,
                head="f" * 64,
                merkle_root="f" * 64,
                created_at="2026-07-13T00:00:08Z",
            ),
            None,
        )
        == "restore_below_checkpoint"
    )
    for field, value in (
        ("head", "0" * 64),
        ("merkle_root", "0" * 64),
        ("log_size", 7),
    ):
        mutated = CheckpointView(
            version=same.version,
            log_size=same.log_size if field != "log_size" else int(value),
            head=same.head if field != "head" else str(value),
            merkle_root=same.merkle_root if field != "merkle_root" else str(value),
            created_at=same.created_at,
        )
        assert (
            compare_checkpoint(live, mutated, live)
            == "restore_inconsistent_with_checkpoint"
        )
    assert (
        compare_checkpoint(above, same, None) == "restore_inconsistent_with_checkpoint"
    )
    diverged = SnapshotBoundary(
        version=8,
        log_size=8,
        head="e" * 64,
        merkle_root="b" * 64,
        created_at="2026-07-13T00:00:07Z",
    )
    assert (
        compare_checkpoint(above, same, diverged)
        == "restore_inconsistent_with_checkpoint"
    )
    root_diverged = SnapshotBoundary(
        version=8,
        log_size=8,
        head="a" * 64,
        merkle_root="0" * 64,
        created_at="2026-07-13T00:00:07Z",
    )
    assert (
        compare_checkpoint(above, same, root_diverged)
        == "restore_inconsistent_with_checkpoint"
    )


def test_startup_checkpoint_above_with_root_only_mismatch_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    auditor_key, token = _startup_home(home, records=10)
    key = load_active_key(home)
    store = Store(home / "registry.db")
    prefix = store.snapshot_boundary(8)
    tampered_root = "0" * 64 if prefix.merkle_root != "0" * 64 else "f" * 64
    checkpoint_snapshot = key.sign_record(
        {
            "schema_version": 1,
            "version": 8,
            "log_size": 8,
            "head": prefix.head,
            "merkle_root": tampered_root,
            "created_at": prefix.created_at,
        }
    )
    assert signing.verify_signed(key.public_pinned, checkpoint_snapshot)
    checkpoint_path = tmp_path / "checkpoint.json"
    checkpoint_path.write_text(json.dumps(checkpoint_snapshot), encoding="utf-8")
    store.close()
    monkeypatch.setenv(HOME_ENV, str(home))
    monkeypatch.setenv(CHECKPOINT_ENV, str(checkpoint_path))
    client = TestClient(app_from_env())
    refused = client.get("/health")
    assert refused.status_code == 503
    assert refused.json()["error"]["code"] == "restore_inconsistent_with_checkpoint"
    write = client.post(
        "/v1/records",
        json=auditor_key.sign_record(_body("audited", name="skill-late-write")),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert write.status_code == 503
    assert write.json()["error"]["code"] == "storage_unavailable"
    reopened = Store(home / "registry.db")
    try:
        assert reopened.head()[0] == 10
        assert reopened.health_verdict().ready
    finally:
        reopened.close()


def test_checkpoint_refusal_latches_and_survives_verifier(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _startup_home(home, records=2)
    store = Store(home / "registry.db")
    ahead = CheckpointView(
        version=5,
        log_size=5,
        head="f" * 64,
        merkle_root="f" * 64,
        created_at="2026-07-13T00:00:04Z",
    )
    assert store.apply_startup_checkpoint(ahead) == "restore_below_checkpoint"
    verdict = store.health_verdict()
    assert not verdict.ready
    assert verdict.code == "restore_below_checkpoint"
    with pytest.raises(StoreIntegrityError):
        store.append(
            load_active_key(home).sign_record(_body()),
            created_at="2026-07-13T00:00:02Z",
        )
    refreshed = store.refresh_health_verdict()
    assert not refreshed.ready
    assert refreshed.code == "restore_below_checkpoint"
    store.close()

    passing = Store(tmp_path / "passing.db")
    boundary = passing.snapshot_boundary()
    assert (
        passing.apply_startup_checkpoint(
            CheckpointView(
                version=boundary.version,
                log_size=boundary.log_size,
                head=boundary.head,
                merkle_root=boundary.merkle_root,
                created_at=boundary.created_at,
            )
        )
        is None
    )
    assert passing.health_verdict().ready
    with pytest.raises(ValueError, match="unknown startup-checkpoint diagnostic"):
        passing.refuse_startup_checkpoint("bogus_code", "detail")
    passing.close()


def test_staged_key_rotation_preserves_snapshot_body_and_live_cursors(tmp_path: Path):
    home = tmp_path / "home"
    assert main(["--home", str(home), "genkey"]) == 0
    old_key = load_active_key(home)
    store = Store(home / "registry.db")
    content_hash = "sha256:" + "1f" * 32
    for index in range(2):
        store.append(
            old_key.sign_record(_body(name=f"skill-{index}")),
            created_at=f"2026-07-13T00:00:0{index}Z",
        )
    before = TestClient(
        create_app(
            store=store,
            signing_key=old_key,
            tokens=AuditorTokens([]),
            verification_keys=public_keys(home, old_key),
        )
    )
    first = before.get(
        "/v1/records",
        params={"content_sha256": content_hash, "limit": 1},
    )
    assert first.status_code == 200
    cursor = first.json()["next_cursor"]
    assert isinstance(cursor, str) and 1 <= len(cursor) <= 4096
    first_boundary = first.json()["boundary"]
    old_snapshot = before.get("/v1/snapshot").json()

    assert main(["--home", str(home), "genkey", "--force"]) == 1
    assert main(["--home", str(home), "prepare-key-rotation"]) == 0
    assert len(public_keys(home, old_key)) == 2
    assert main(["--home", str(home), "activate-key-rotation"]) == 1
    assert main(
        ["--home", str(home), "activate-key-rotation", "--confirm-pins-deployed"]
    ) == 0

    new_key = load_active_key(home)
    retained = public_keys(home, new_key)
    assert new_key.key_id != old_key.key_id
    assert {old_key.public_pinned, new_key.public_pinned} == set(retained)
    after = TestClient(
        create_app(
            store=store,
            signing_key=new_key,
            tokens=AuditorTokens([]),
            verification_keys=retained,
        )
    )
    new_snapshot = after.get("/v1/snapshot").json()
    assert {field: value for field, value in old_snapshot.items() if field != "sig"} == {
        field: value for field, value in new_snapshot.items() if field != "sig"
    }
    continued = after.get(
        "/v1/records",
        params={"content_sha256": content_hash, "limit": 1, "cursor": cursor},
    )
    assert continued.status_code == 200
    assert [record["name"] for record in continued.json()["records"]] == ["skill-1"]
    assert continued.json()["boundary"] == first_boundary
    assert signing.verify_signed(old_key.public_pinned, continued.json()["boundary"])

    assert main(["--home", str(home), "retire-key", old_key.key_id]) == 1
    assert main(
        [
            "--home",
            str(home),
            "retire-key",
            old_key.key_id,
            "--confirm-overlap-elapsed",
        ]
    ) == 0
    assert public_keys(home, new_key) == (new_key.public_pinned,)


def test_rotation_overlap_keeps_chain_boundary_on_both_endpoints(tmp_path: Path):
    home = tmp_path / "home"
    assert main(["--home", str(home), "genkey"]) == 0
    old_key = load_active_key(home)
    store = Store(home / "registry.db")
    content_hash = "sha256:" + "1f" * 32
    for index in range(3):
        store.append(
            old_key.sign_record(_body(name=f"skill-{index}", commit=f"{index:040d}")),
            created_at=f"2026-07-13T00:00:0{index}Z",
        )
    before = TestClient(
        create_app(
            store=store,
            signing_key=old_key,
            tokens=AuditorTokens([]),
            verification_keys=public_keys(home, old_key),
        )
    )
    records_first = before.get(
        "/v1/records", params={"content_sha256": content_hash, "limit": 1}
    ).json()
    log_first = before.get("/v1/log", params={"since": 0, "limit": 1}).json()
    records_cursor = records_first["next_cursor"]
    log_cursor = log_first["next_cursor"]
    assert isinstance(records_cursor, str) and 1 <= len(records_cursor) <= 4096
    assert isinstance(log_cursor, str) and 1 <= len(log_cursor) <= 4096
    records_chain = signing.canonical_document_bytes(records_first["boundary"])
    log_chain = signing.canonical_document_bytes(log_first["boundary"])

    assert main(["--home", str(home), "prepare-key-rotation"]) == 0
    assert main(
        ["--home", str(home), "activate-key-rotation", "--confirm-pins-deployed"]
    ) == 0
    new_key = load_active_key(home)
    retained = public_keys(home, new_key)
    assert {old_key.public_pinned, new_key.public_pinned} == set(retained)
    during = TestClient(
        create_app(
            store=store,
            signing_key=new_key,
            tokens=AuditorTokens([]),
            verification_keys=retained,
        )
    )
    # Snapshot reads move to the new signer while cursor chains stay pinned.
    assert during.get("/v1/snapshot").json()["sig"]["key_id"] == new_key.key_id

    chains = [
        ("/v1/records", {"content_sha256": content_hash, "limit": 1}, records_cursor, records_chain),
        ("/v1/log", {"since": 0, "limit": 1}, log_cursor, log_chain),
    ]
    overlap_issued: list[tuple[str, dict[str, object], str]] = []
    for endpoint, params, first_cursor, chain in chains:
        cursor = first_cursor
        pages = 0
        while cursor is not None:
            response = during.get(endpoint, params={**params, "cursor": cursor})
            assert response.status_code == 200
            body = response.json()
            assert signing.canonical_document_bytes(body["boundary"]) == chain
            assert signing.verify_signed(old_key.public_pinned, body["boundary"])
            assert not signing.verify_signed(new_key.public_pinned, body["boundary"])
            cursor = body["next_cursor"]
            if cursor is not None:
                overlap_issued.append((endpoint, params, cursor))
            pages += 1
        assert pages == 2

    assert main(
        [
            "--home",
            str(home),
            "retire-key",
            old_key.key_id,
            "--confirm-overlap-elapsed",
        ]
    ) == 0
    assert public_keys(home, new_key) == (new_key.public_pinned,)
    retired = TestClient(
        create_app(
            store=store,
            signing_key=new_key,
            tokens=AuditorTokens([]),
            verification_keys=public_keys(home, new_key),
        )
    )
    # Pre-rotation cursors and overlap-issued continuations are refused once the
    # carried boundary's key retires; the service never re-signs the chain.
    stale = [(endpoint, params, first_cursor) for endpoint, params, first_cursor, _ in chains]
    for endpoint, params, cursor in [*stale, *overlap_issued]:
        refused = retired.get(endpoint, params={**params, "cursor": cursor})
        assert refused.status_code == 404
        assert refused.json()["error"]["code"] == "invalid_cursor"
    fresh = retired.get(
        "/v1/records", params={"content_sha256": content_hash, "limit": 1}
    ).json()
    assert signing.verify_signed(new_key.public_pinned, fresh["boundary"])


def test_serve_refuses_insecure_or_ambiguous_transport(tmp_path: Path):
    home = tmp_path / "home"
    assert main(["--home", str(home), "serve", "--host", "0.0.0.0"]) == 1
    assert main(
        [
            "--home",
            str(home),
            "serve",
            "--host",
            "0.0.0.0",
            "--behind-https-proxy",
        ]
    ) == 1
    assert main(
        ["--home", str(home), "serve", "--ssl-certfile", "certificate.pem"]
    ) == 1


def test_submission_idempotency_replays_and_conflicts(tmp_path: Path):
    client, _, token = _client(tmp_path)
    auditor_key = client.app.state.auditor_key  # type: ignore[attr-defined]
    first_record = auditor_key.sign_record(_body("audited"))
    headers = {"Authorization": f"Bearer {token}", "Idempotency-Key": "request-1"}
    first = client.post("/v1/records", json=first_record, headers=headers)
    replay = client.post("/v1/records", json=first_record, headers=headers)
    assert first.status_code == 201
    assert replay.status_code == 200
    assert replay.json() == first.json()
    changed = auditor_key.sign_record(_body("revoked"))
    conflict = client.post("/v1/records", json=changed, headers=headers)
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "idempotency_conflict"
    assert len(client.get("/v1/log").json()["entries"]) == 1


class _ManualAppClock:
    """Injectable ``time`` replacement for deterministic idempotency TTL tests."""

    def __init__(self, now: float) -> None:
        self.now = now

    def time(self) -> float:
        return self.now

    def monotonic(self) -> float:
        return self.now


def test_idempotency_retry_within_slack_window_is_deduplicated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import csk_registry.app as app_module

    assert app_module.IDEMPOTENCY_TTL_SECONDS == 26 * 3600
    client, _, token = _client(tmp_path)
    auditor_key = client.app.state.auditor_key  # type: ignore[attr-defined]
    clock = _ManualAppClock(1_800_000_000.0)
    monkeypatch.setattr(app_module, "time", clock)
    headers = {"Authorization": f"Bearer {token}", "Idempotency-Key": "slack-key"}
    record = auditor_key.sign_record(_body("audited"))
    first = client.post("/v1/records", json=record, headers=headers)
    assert first.status_code == 201
    # A retry at 25 h — past the 24 h contract minimum but inside the 26 h
    # retention — replays the original response without a second append.
    clock.now += 25 * 3600
    replay = client.post("/v1/records", json=record, headers=headers)
    assert replay.status_code == 200
    assert replay.json() == first.json()
    assert len(client.get("/v1/log").json()["entries"]) == 1


def test_idempotency_retry_past_retention_expires(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import csk_registry.app as app_module

    client, _, token = _client(tmp_path)
    auditor_key = client.app.state.auditor_key  # type: ignore[attr-defined]
    clock = _ManualAppClock(1_800_000_000.0)
    monkeypatch.setattr(app_module, "time", clock)
    headers = {"Authorization": f"Bearer {token}", "Idempotency-Key": "expiry-key"}
    record = auditor_key.sign_record(_body("audited"))
    first = client.post("/v1/records", json=record, headers=headers)
    assert first.status_code == 201
    # A retry past the 26 h retention is a new submission, not a replay.
    clock.now += 26 * 3600 + 1
    second = client.post("/v1/records", json=record, headers=headers)
    assert second.status_code == 201
    assert second.json()["seq"] == first.json()["seq"] + 1
    assert len(client.get("/v1/log").json()["entries"]) == 2


@pytest.mark.parametrize(
    ("method", "path", "expected_status"),
    [("get", "/v1/records", 400), ("get", "/missing", 404), ("post", "/v1/records", 401)],
)
def test_errors_use_stable_protocol_envelope(tmp_path: Path, method: str, path: str, expected_status: int):
    client, _, _ = _client(tmp_path)
    response = client.post(path, json={}) if method == "post" else client.get(path)
    assert response.status_code == expected_status
    error = response.json()["error"]
    assert set(error) >= {"code", "message"}


def test_records_pages_carry_byte_identical_boundary(tmp_path: Path):
    client, registry_key, token = _client(tmp_path)
    auditor_key = client.app.state.auditor_key  # type: ignore[attr-defined]
    content_hash = "sha256:" + "1f" * 32
    for index in range(3):
        record = auditor_key.sign_record(_body(name=f"skill-{index}"))
        assert client.post(
            "/v1/records", json=record, headers={"Authorization": f"Bearer {token}"}
        ).status_code == 201
    snapshot = client.get("/v1/snapshot").json()
    first = client.get(
        "/v1/records", params={"content_sha256": content_hash, "limit": 1}
    ).json()
    assert set(first) == {"records", "next_cursor", "boundary"}
    assert first["boundary"] == snapshot
    assert signing.verify_signed(registry_key.public_pinned, first["boundary"])
    # An append after the first page must not move the chain's boundary.
    replacement = auditor_key.sign_record(_body("revoked", name="skill-0"))
    assert client.post(
        "/v1/records", json=replacement, headers={"Authorization": f"Bearer {token}"}
    ).status_code == 201
    chain = signing.canonical_document_bytes(first["boundary"])
    body = first
    names = [record["name"] for record in body["records"]]
    while body["next_cursor"] is not None:
        body = client.get(
            "/v1/records",
            params={"content_sha256": content_hash, "limit": 1, "cursor": body["next_cursor"]},
        ).json()
        assert set(body) == {"records", "next_cursor", "boundary"}
        assert signing.verify_signed(registry_key.public_pinned, body["boundary"])
        assert signing.canonical_document_bytes(body["boundary"]) == chain
        names.extend(record["name"] for record in body["records"])
    assert names == ["skill-0", "skill-1", "skill-2"]
    assert body["boundary"]["created_at"] == snapshot["created_at"]
    assert client.get("/v1/snapshot").json()["log_size"] == snapshot["log_size"] + 1


def test_log_pages_carry_byte_identical_boundary(tmp_path: Path):
    client, registry_key, token = _client(tmp_path)
    auditor_key = client.app.state.auditor_key  # type: ignore[attr-defined]
    for index in range(3):
        record = auditor_key.sign_record(_body("audited", commit=f"{index:040d}"))
        assert client.post(
            "/v1/records", json=record, headers={"Authorization": f"Bearer {token}"}
        ).status_code == 201
    snapshot = client.get("/v1/snapshot").json()
    first = client.get("/v1/log", params={"limit": 1}).json()
    assert set(first) == {"entries", "next_cursor", "boundary"}
    assert first["boundary"] == snapshot
    assert signing.verify_signed(registry_key.public_pinned, first["boundary"])
    late = auditor_key.sign_record(_body("audited", commit=f"{3:040d}"))
    assert client.post(
        "/v1/records", json=late, headers={"Authorization": f"Bearer {token}"}
    ).status_code == 201
    chain = signing.canonical_document_bytes(first["boundary"])
    body = first
    sequences = [entry["seq"] for entry in body["entries"]]
    while body["next_cursor"] is not None:
        body = client.get(
            "/v1/log",
            params={"limit": 1, "cursor": body["next_cursor"]},
        ).json()
        assert set(body) == {"entries", "next_cursor", "boundary"}
        assert signing.verify_signed(registry_key.public_pinned, body["boundary"])
        assert signing.canonical_document_bytes(body["boundary"]) == chain
        sequences.extend(entry["seq"] for entry in body["entries"])
    assert sequences == [1, 2, 3]
    assert body["boundary"]["log_size"] == snapshot["log_size"]
    assert client.get("/v1/snapshot").json()["log_size"] == snapshot["log_size"] + 1


def _flip_hex(value: str) -> str:
    return "00" * 32 if value != "00" * 32 else "ff" * 32


def test_cursor_carried_boundary_disagreement_refused_on_both_endpoints(tmp_path: Path):
    client, registry_key, token = _client(tmp_path)
    auditor_key = client.app.state.auditor_key  # type: ignore[attr-defined]
    content_hash = "sha256:" + "1f" * 32
    for index in range(3):
        record = auditor_key.sign_record(_body(name=f"skill-{index}"))
        assert client.post(
            "/v1/records", json=record, headers={"Authorization": f"Bearer {token}"}
        ).status_code == 201
    records_first = client.get(
        "/v1/records", params={"content_sha256": content_hash, "limit": 1}
    ).json()
    log_first = client.get("/v1/log", params={"since": 0, "limit": 1}).json()
    assert records_first["next_cursor"] and log_first["next_cursor"]
    # Control: the genuine cursors continue the chain at the original boundary.
    genuine_records = client.get(
        "/v1/records",
        params={
            "content_sha256": content_hash,
            "limit": 1,
            "cursor": records_first["next_cursor"],
        },
    )
    assert genuine_records.status_code == 200
    assert genuine_records.json()["boundary"] == records_first["boundary"]

    cases = [
        (
            "/v1/records",
            "records",
            {"source_identity": "", "commit": "", "content_sha256": content_hash, "limit": 1},
            {"content_sha256": content_hash, "limit": 1},
            records_first["boundary"],
        ),
        (
            "/v1/log",
            "log",
            {"since": 0, "limit": 1},
            {"since": 0, "limit": 1},
            log_first["boundary"],
        ),
    ]
    for endpoint, name, query, params, boundary in cases:
        for field in ("head", "merkle_root"):
            forged = dict(boundary)
            forged[field] = _flip_hex(forged[field])
            # The forged body is genuinely re-signed with a key the service
            # accepts, so only the store comparison can refuse it.
            signed = registry_key.sign_record(forged)
            assert signing.verify_signed(registry_key.public_pinned, signed)
            forged_cursor = _encode_cursor(
                registry_key,
                endpoint=name,
                query=query,
                boundary_snapshot=signed,
                offset=1,
            )
            refused = client.get(endpoint, params={**params, "cursor": forged_cursor})
            assert refused.status_code == 404, (endpoint, field)
            assert refused.json()["error"]["code"] == "invalid_cursor", (endpoint, field)


def test_cursor_disagreement_refused_for_overlap_key_signature(tmp_path: Path):
    old_key = signing.generate_key()
    new_key = signing.generate_key()
    store = Store(tmp_path / "overlap-disagreement.db")
    content_hash = "sha256:" + "1f" * 32
    for index in range(2):
        store.append(
            new_key.sign_record(_body(name=f"skill-{index}")),
            created_at=f"2026-07-13T00:00:0{index}Z",
        )
    client = TestClient(
        create_app(
            store=store,
            signing_key=new_key,
            tokens=AuditorTokens([]),
            verification_keys=(old_key.public_pinned,),
        )
    )
    records_first = client.get(
        "/v1/records", params={"content_sha256": content_hash, "limit": 1}
    ).json()
    log_first = client.get("/v1/log", params={"since": 0, "limit": 1}).json()
    cases = [
        (
            "/v1/records",
            "records",
            {"source_identity": "", "commit": "", "content_sha256": content_hash, "limit": 1},
            {"content_sha256": content_hash, "limit": 1},
            records_first["boundary"],
        ),
        (
            "/v1/log",
            "log",
            {"since": 0, "limit": 1},
            {"since": 0, "limit": 1},
            log_first["boundary"],
        ),
    ]
    for endpoint, name, query, params, boundary in cases:
        forged = dict(boundary)
        forged["head"] = _flip_hex(forged["head"])
        # Re-signed with the retained overlap key: the signature verifies, but
        # the body disagrees with the store, so the page must be refused.
        signed = old_key.sign_record(forged)
        assert signing.verify_signed(old_key.public_pinned, signed)
        forged_cursor = _encode_cursor(
            new_key,
            endpoint=name,
            query=query,
            boundary_snapshot=signed,
            offset=1,
        )
        refused = client.get(endpoint, params={**params, "cursor": forged_cursor})
        assert refused.status_code == 404, endpoint
        assert refused.json()["error"]["code"] == "invalid_cursor", endpoint


def test_cursor_unavailable_boundary_refused_on_both_endpoints(tmp_path: Path):
    client, registry_key, token = _client(tmp_path / "future")
    auditor_key = client.app.state.auditor_key  # type: ignore[attr-defined]
    content_hash = "sha256:" + "1f" * 32
    for index in range(2):
        record = auditor_key.sign_record(_body(name=f"skill-{index}"))
        assert client.post(
            "/v1/records", json=record, headers={"Authorization": f"Bearer {token}"}
        ).status_code == 201
    records_first = client.get(
        "/v1/records", params={"content_sha256": content_hash, "limit": 1}
    ).json()
    log_first = client.get("/v1/log", params={"since": 0, "limit": 1}).json()
    cases = [
        (
            "/v1/records",
            "records",
            {"source_identity": "", "commit": "", "content_sha256": content_hash, "limit": 1},
            {"content_sha256": content_hash, "limit": 1},
            records_first["boundary"],
        ),
        (
            "/v1/log",
            "log",
            {"since": 0, "limit": 1},
            {"since": 0, "limit": 1},
            log_first["boundary"],
        ),
    ]
    # A carried boundary past the committed head is unavailable: 404, never a
    # re-evaluation at the newer (or any other) boundary.
    for endpoint, name, query, params, boundary in cases:
        future = dict(boundary)
        future["version"] = future["log_size"] = boundary["log_size"] + 3
        signed = registry_key.sign_record(future)
        assert signing.verify_signed(registry_key.public_pinned, signed)
        forged_cursor = _encode_cursor(
            registry_key,
            endpoint=name,
            query=query,
            boundary_snapshot=signed,
            offset=1,
        )
        refused = client.get(endpoint, params={**params, "cursor": forged_cursor})
        assert refused.status_code == 404, endpoint
        assert refused.json()["error"]["code"] == "invalid_cursor", endpoint


def test_cursor_pruned_prefix_refused_on_both_endpoints(tmp_path: Path):
    client, _, token = _client(tmp_path / "pruned")
    auditor_key = client.app.state.auditor_key  # type: ignore[attr-defined]
    content_hash = "sha256:" + "1f" * 32
    for index in range(3):
        record = auditor_key.sign_record(_body(name=f"skill-{index}"))
        assert client.post(
            "/v1/records", json=record, headers={"Authorization": f"Bearer {token}"}
        ).status_code == 201
    records_first = client.get(
        "/v1/records", params={"content_sha256": content_hash, "limit": 1}
    ).json()
    log_first = client.get("/v1/log", params={"since": 0, "limit": 1}).json()
    records_cursor = records_first["next_cursor"]
    log_cursor = log_first["next_cursor"]
    assert records_cursor and log_cursor
    # Control: both cursors work before the prefix is pruned.
    assert (
        client.get(
            "/v1/records",
            params={
                "content_sha256": content_hash,
                "limit": 1,
                "cursor": records_cursor,
            },
        ).status_code
        == 200
    )
    assert (
        client.get(
            "/v1/log", params={"since": 0, "limit": 1, "cursor": log_cursor}
        ).status_code
        == 200
    )
    # Prune the earliest log row behind the store: the carried log_size prefix
    # no longer exists, so the cursors must be refused, not re-evaluated.
    pruned = sqlite3.connect(tmp_path / "pruned" / "r.db")
    try:
        pruned.execute("DELETE FROM log WHERE seq = 1")
        pruned.commit()
    finally:
        pruned.close()
    for endpoint, params in (
        (
            "/v1/records",
            {"content_sha256": content_hash, "limit": 1, "cursor": records_cursor},
        ),
        ("/v1/log", {"since": 0, "limit": 1, "cursor": log_cursor}),
    ):
        refused = client.get(endpoint, params=params)
        assert refused.status_code == 404, endpoint
        assert refused.json()["error"]["code"] == "invalid_cursor", endpoint


def test_store_page_calls_verify_carried_boundary(tmp_path: Path):
    store = Store(tmp_path / "r.db")
    key = signing.generate_key()
    content_hash = "sha256:" + "1f" * 32
    for index in range(2):
        store.append(
            key.sign_record(_body(name=f"skill-{index}")),
            created_at=f"2026-07-13T00:00:0{index}Z",
        )
    boundary = store.snapshot_boundary()
    # The committed boundary pages exactly like the equivalent max_seq cap.
    via_boundary, more_boundary = store.records_page(
        content_sha256=content_hash, limit=10, offset=0, boundary=boundary
    )
    via_cap, more_cap = store.records_page(
        content_sha256=content_hash, limit=10, offset=0, max_seq=boundary.log_size
    )
    assert (via_boundary, more_boundary) == (via_cap, more_cap)
    log_via_boundary, _ = store.log_page(since=0, limit=10, offset=0, boundary=boundary)
    log_via_cap, _ = store.log_page(
        since=0, limit=10, offset=0, max_seq=boundary.log_size
    )
    assert [entry.seq for entry in log_via_boundary] == [
        entry.seq for entry in log_via_cap
    ]
    # A boundary whose body disagrees with the store is a mismatch.
    tampered = SnapshotBoundary(
        version=boundary.version,
        log_size=boundary.log_size,
        head=_flip_hex(boundary.head),
        merkle_root=boundary.merkle_root,
        created_at=boundary.created_at,
    )
    with pytest.raises(CursorBoundaryMismatch):
        store.records_page(
            content_sha256=content_hash, limit=10, offset=0, boundary=tampered
        )
    with pytest.raises(CursorBoundaryMismatch):
        store.log_page(since=0, limit=10, offset=0, boundary=tampered)
    # An unavailable size and an explicit double cap are rejected too.
    future = SnapshotBoundary(
        version=boundary.version + 5,
        log_size=boundary.log_size + 5,
        head=boundary.head,
        merkle_root=boundary.merkle_root,
        created_at=boundary.created_at,
    )
    with pytest.raises(CursorBoundaryMismatch):
        store.records_page(
            content_sha256=content_hash, limit=10, offset=0, boundary=future
        )
    with pytest.raises(CursorBoundaryMismatch):
        store.log_page(since=0, limit=10, offset=0, boundary=future)
    with pytest.raises(ValueError, match="mutually exclusive"):
        store.records_page(
            content_sha256=content_hash,
            limit=10,
            offset=0,
            max_seq=boundary.log_size,
            boundary=boundary,
        )


def _counting_merkle_hasher(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    import csk_registry.store as store_module

    calls: list[int] = [0]
    real = store_module._merkle_pair_hash

    def counting(left: bytes, right: bytes) -> bytes:
        calls[0] += 1
        return real(left, right)

    monkeypatch.setattr(store_module, "_merkle_pair_hash", counting)
    return calls


def _seed_paginated_store(store: Store, key: signing.SigningKey, count: int) -> str:
    content_hash = "sha256:" + "1f" * 32
    for index in range(count):
        store.append(
            key.sign_record(_body(name=f"skill-{index:03d}")),
            created_at=f"2026-07-13T00:{index // 60:02d}:{index % 60:02d}Z",
        )
    return content_hash


def test_merkle_frontier_matches_naive_root() -> None:
    import csk_registry.store as store_module

    leaves = [hashlib.sha256(f"leaf-{index}".encode()).hexdigest() for index in range(100)]
    frontier: list[store_module._FrontierLevel] = []
    for index, leaf in enumerate(leaves):
        root = store_module._frontier_append(frontier, bytes.fromhex(leaf)).hex()
        assert root == store_module._merkle_root(leaves[: index + 1])


def test_boundary_reads_perform_zero_merkle_hashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import csk_registry.store as store_module

    path = tmp_path / "memo.db"
    store = Store(path)
    registry_key = signing.generate_key()
    content_hash = _seed_paginated_store(store, registry_key, 32)
    # The one append after which every read must be hash-free.
    store.append(
        registry_key.sign_record(_body(name="skill-trigger")),
        created_at="2026-07-13T01:00:00Z",
    )
    # Correctness oracle captured before the hasher is instrumented.
    entry_hashes = [
        str(row["entry_hash"])
        for row in store._conn.execute(  # type: ignore[attr-defined]
            "SELECT entry_hash FROM log ORDER BY seq"
        )
    ]
    expected_roots = {
        size: store_module._merkle_root(entry_hashes[:size]) for size in (1, 7, 33)
    }
    for size, root in expected_roots.items():
        assert store.snapshot_boundary(size).merkle_root == root

    client = TestClient(
        create_app(store=store, signing_key=registry_key, tokens=AuditorTokens([]))
    )
    calls = _counting_merkle_hasher(monkeypatch)
    boundary = store.snapshot_boundary()
    assert store.boundary_available(boundary)

    def _read_everything() -> None:
        first_records = client.get(
            "/v1/records", params={"content_sha256": content_hash, "limit": 1}
        )
        assert first_records.status_code == 200
        records_cursor = first_records.json()["next_cursor"]
        assert records_cursor
        continued_records = client.get(
            "/v1/records",
            params={"content_sha256": content_hash, "limit": 1, "cursor": records_cursor},
        )
        assert continued_records.status_code == 200
        first_log = client.get("/v1/log", params={"since": 0, "limit": 1})
        assert first_log.status_code == 200
        log_cursor = first_log.json()["next_cursor"]
        assert log_cursor
        continued_log = client.get(
            "/v1/log", params={"since": 0, "limit": 1, "cursor": log_cursor}
        )
        assert continued_log.status_code == 200
        assert client.get("/v1/snapshot").status_code == 200
        assert store.snapshot_boundary().merkle_root == expected_roots[33]
        assert store.snapshot_boundary(7).merkle_root == expected_roots[7]
        assert store.boundary_available(boundary)
        assert store.merkle_root() == expected_roots[33]
        assert store.head()[0] == 33
        assert store.checkpoint_matches(boundary)
        found, _ = store.records_page(
            content_sha256=content_hash, limit=5, offset=0, boundary=boundary
        )
        assert found
        entries, _ = store.log_page(since=0, limit=5, offset=0, boundary=boundary)
        assert entries

    for _ in range(3):
        _read_everything()
    assert calls[0] == 0, f"reads recomputed the Merkle tree ({calls[0]} hashes)"

    # Durability: the same zero-hash reads hold after a restart, which
    # revalidates the cache against the log once before serving.
    monkeypatch.undo()
    store.close()
    reopened = Store(path)
    reopened_client = TestClient(
        create_app(store=reopened, signing_key=registry_key, tokens=AuditorTokens([]))
    )
    calls_after_restart = _counting_merkle_hasher(monkeypatch)
    for _ in range(2):
        assert reopened_client.get("/v1/snapshot").status_code == 200
        assert reopened.snapshot_boundary().merkle_root == expected_roots[33]
        assert reopened.boundary_available(boundary)
    assert calls_after_restart[0] == 0


def test_boundary_append_cost_is_logarithmic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import csk_registry.store as store_module

    store = Store(tmp_path / "append.db")
    key = signing.generate_key()
    _seed_paginated_store(store, key, 64)
    calls = _counting_merkle_hasher(monkeypatch)
    entry = store.append(
        key.sign_record(_body(name="skill-065")),
        created_at="2026-07-13T02:00:00Z",
    )
    assert entry.seq == 65
    # One pair-hash per tree level: ~log2(n), far below the naive O(n).
    assert 1 <= calls[0] <= 16, f"append used {calls[0]} Merkle hashes for 65 leaves"
    monkeypatch.undo()
    entry_hashes = [
        str(row["entry_hash"])
        for row in store._conn.execute(  # type: ignore[attr-defined]
            "SELECT entry_hash FROM log ORDER BY seq"
        )
    ]
    assert store.snapshot_boundary().merkle_root == store_module._merkle_root(entry_hashes)


def test_boundary_cache_disagreement_fails_startup_but_missing_row_backfills(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cache.db"
    store = Store(path)
    key = signing.generate_key()
    for index in range(3):
        store.append(
            key.sign_record(_body(name=f"skill-{index}")),
            created_at=f"2026-07-13T00:00:0{index}Z",
        )
    genuine = store.snapshot_boundary()
    store.close()

    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE boundaries SET merkle_root = ? WHERE log_size = 3", ("ff" * 32,)
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(StoreIntegrityError, match="disagrees with the committed log"):
        Store(path)

    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE boundaries SET merkle_root = ? WHERE log_size = 3",
            (genuine.merkle_root,),
        )
        connection.execute("DELETE FROM boundaries WHERE log_size = 2")
        connection.execute("DELETE FROM merkle_frontier")
        connection.commit()
    finally:
        connection.close()
    healed = Store(path)
    try:
        assert healed.snapshot_boundary() == genuine
        assert healed.snapshot_boundary(2).head == store_module_head(healed, 2)
    finally:
        healed.close()


def store_module_head(store: Store, seq: int) -> str:
    row = store._conn.execute(  # type: ignore[attr-defined]
        "SELECT entry_hash FROM log WHERE seq = ?", (seq,)
    ).fetchone()
    assert row is not None
    return str(row["entry_hash"])


def test_v2_database_migrates_and_backfills_boundaries(tmp_path: Path) -> None:
    import csk_registry.store as store_module

    path = tmp_path / "v2.db"
    store = Store(path)
    key = signing.generate_key()
    for index in range(5):
        store.append(
            key.sign_record(_body(name=f"skill-{index}")),
            created_at=f"2026-07-13T00:00:0{index}Z",
        )
    entry_hashes = [
        str(row["entry_hash"])
        for row in store._conn.execute(  # type: ignore[attr-defined]
            "SELECT entry_hash FROM log ORDER BY seq"
        )
    ]
    expected = [store_module._merkle_root(entry_hashes[: size]) for size in range(1, 6)]
    store.close()

    # Downgrade the file to the pre-R2 v2 shape: no cache tables, v2 markers.
    connection = sqlite3.connect(path)
    try:
        connection.execute("DROP TABLE boundaries")
        connection.execute("DROP TABLE merkle_frontier")
        connection.execute("DROP TABLE upstream_high_water")
        connection.execute("UPDATE metadata SET value = '2' WHERE key = 'schema_version'")
        connection.execute("PRAGMA user_version=2")
        connection.commit()
    finally:
        connection.close()

    upgraded = Store(path)
    try:
        marker = upgraded._conn.execute(  # type: ignore[attr-defined]
            "SELECT value FROM metadata WHERE key = 'schema_version'"
        ).fetchone()
        assert marker["value"] == "4"
        version = upgraded._conn.execute("PRAGMA user_version").fetchone()[0]  # type: ignore[attr-defined]
        assert int(version) == 4
        for size, root in enumerate(expected, start=1):
            assert upgraded.snapshot_boundary(size).merkle_root == root
        upgraded.append(
            key.sign_record(_body(name="skill-5")),
            created_at="2026-07-13T00:00:05Z",
        )
        assert upgraded.head()[0] == 6
    finally:
        upgraded.close()


def _counting_store_sha256(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Count ``hashlib.sha256`` calls made through the store module only."""
    import csk_registry.store as store_module

    calls: list[int] = [0]
    real_sha256 = hashlib.sha256

    class _Hashlib:
        @staticmethod
        def sha256(*args: object, **kwargs: object) -> object:
            calls[0] += 1
            return real_sha256(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(store_module, "hashlib", _Hashlib)
    return calls


def _counting_store_canonical_bytes(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    import csk_registry.store as store_module

    calls: list[int] = [0]
    real = store_module.canonical_bytes

    def counting(record: object) -> bytes:
        calls[0] += 1
        return real(record)  # type: ignore[arg-type]

    monkeypatch.setattr(store_module, "canonical_bytes", counting)
    return calls


def _health_client(
    tmp_path: Path, *, health_verify_interval: float | None = None
) -> tuple[TestClient, Store, signing.SigningKey, signing.SigningKey, str]:
    kwargs: dict[str, object] = (
        {} if health_verify_interval is None else {"health_verify_interval": health_verify_interval}
    )
    store = Store(tmp_path / "r.db", **kwargs)  # type: ignore[arg-type]
    key = signing.generate_key()
    auditor_key = signing.generate_key()
    token = "health-token-with-at-least-128-bit-capacity"
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
    return TestClient(create_app(store=store, signing_key=key, tokens=tokens)), store, key, auditor_key, token


def _tamper_log_entry_hash(path: Path, seq: int, entry_hash: str) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("UPDATE log SET entry_hash = ? WHERE seq = ?", (entry_hash, seq))
        connection.commit()
    finally:
        connection.close()


def test_health_probes_perform_zero_hash_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = Store(tmp_path / "health.db")
    key = signing.generate_key()
    _seed_paginated_store(store, key, 8)
    client = TestClient(
        create_app(store=store, signing_key=key, tokens=AuditorTokens([]))
    )
    assert client.get("/health").json() == {"status": "ok"}

    sha_calls = _counting_store_sha256(monkeypatch)
    ccj_calls = _counting_store_canonical_bytes(monkeypatch)
    merkle_calls = _counting_merkle_hasher(monkeypatch)
    for _ in range(5):
        assert client.get("/health").json() == {"status": "ok"}
    assert sha_calls[0] == 0, f"probes hashed {sha_calls[0]} times"
    assert ccj_calls[0] == 0, f"probes canonicalized {ccj_calls[0]} records"
    assert merkle_calls[0] == 0

    # Appends advance the cached head incrementally; later probes stay hash-free.
    store.append(
        key.sign_record(_body(name="skill-008")),
        created_at="2026-07-13T01:00:00Z",
    )
    store.append(
        key.sign_record(_body(name="skill-009")),
        created_at="2026-07-13T01:01:00Z",
    )
    sha_calls[0] = ccj_calls[0] = merkle_calls[0] = 0
    for _ in range(5):
        assert client.get("/health").json() == {"status": "ok"}
    assert sha_calls[0] == 0, f"probes after appends hashed {sha_calls[0]} times"
    assert ccj_calls[0] == 0
    assert merkle_calls[0] == 0
    verdict = store.health_verdict()
    assert verdict.ready and verdict.error is None
    assert (verdict.verified_log_size, verdict.verified_head) == store.head()
    assert verdict.verified_log_size == 10


def test_health_first_verdict_is_startup_verification(tmp_path: Path) -> None:
    path = tmp_path / "first.db"
    store = Store(path)
    key = signing.generate_key()
    for index in range(3):
        store.append(
            key.sign_record(_body(name=f"skill-{index}")),
            created_at=f"2026-07-13T00:00:0{index}Z",
        )
    size, head = store.head()
    store.close()

    # No refresh driven, no verifier thread: readiness comes from startup §5.
    reopened = Store(path)
    try:
        assert not reopened.health_verifier_running()
        client = TestClient(
            create_app(store=reopened, signing_key=key, tokens=AuditorTokens([]))
        )
        assert client.get("/health").json() == {"status": "ok"}
        verdict = reopened.health_verdict()
        assert verdict.ready and verdict.error is None
        assert verdict.verified_head == head
        assert verdict.verified_log_size == size == 3
        assert verdict.verified_at
    finally:
        reopened.close()


def test_health_corruption_detected_at_next_refresh_disables_writes(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    client, store, key, auditor_key, token = _health_client(tmp_path)
    headers = {"Authorization": f"Bearer {token}"}
    assert (
        client.post("/v1/records", json=auditor_key.sign_record(_body("audited")), headers=headers).status_code
        == 201
    )
    assert client.get("/health").status_code == 200

    _tamper_log_entry_hash(tmp_path / "r.db", 1, "ff" * 32)
    # Cached verdict: still green until the next refresh (driven explicitly,
    # no sleeps, no background thread in this test).
    assert client.get("/health").status_code == 200

    caplog.set_level(logging.INFO, logger="csk_registry.audit")
    caplog.clear()
    verdict = store.refresh_health_verdict()
    assert not verdict.ready
    assert verdict.error

    failed = client.get("/health")
    assert failed.status_code == 503
    assert failed.json()["error"]["code"] == "not_ready"
    refused = client.post(
        "/v1/records", json=auditor_key.sign_record(_body("revoked")), headers=headers
    )
    assert refused.status_code == 503
    assert refused.json()["error"]["code"] == "storage_unavailable"
    with pytest.raises(StoreIntegrityError, match="restart to re-verify"):
        store.append(
            key.sign_record(_body(name="skill-blocked")),
            created_at="2026-07-13T02:00:00Z",
        )
    # Latched: a second pass stays failed without a restart.
    assert not store.refresh_health_verdict().ready

    refresh_events = []
    for record in caplog.records:
        if record.name != "csk_registry.audit":
            continue
        try:
            payload = json.loads(record.getMessage())
        except ValueError:
            continue
        if payload.get("event") == "health_refresh":
            refresh_events.append(payload)
    assert [event["result"] for event in refresh_events] == [
        "integrity_failed",
        "integrity_failed_latched",
    ]
    assert refresh_events[0]["log_size"] == 1
    assert refresh_events[0]["duration_ms"] >= 0
    assert refresh_events[0]["error_count"] >= 1
    assert refresh_events[0]["error"]


#: Fixed manual-clock epoch for the exact-boundary staleness test. Anchoring
#: the manual clock to the raw ``time.monotonic()`` value is host-dependent:
#: when ``base + 20.0`` crosses a binary binade boundary (host uptime within
#: 20 s below a power of two) the sum can round up by ~1 ulp, so the
#: exact-bound step reads stale and the test flakes lane-dependently. Both
#: exact-bound additions from this epoch (``+ 20.0`` twice, 40 s apart) stay
#: inside the ``[8192, 16384)`` binade, where a sum of exactly representable
#: addends is exact and the age subtraction is exact by Sterbenz — the
#: boundary reads exactly ``20.0`` on every host.
_MANUAL_CLOCK_EPOCH = 10000.0


class _ManualStoreClock:
    """Injectable ``time`` replacement for deterministic staleness tests."""

    def __init__(self, now: float) -> None:
        self.now = now

    def monotonic(self) -> float:
        return self.now


def test_manual_clock_epoch_keeps_exact_bound_additions_exact() -> None:
    # Premise lock for _MANUAL_CLOCK_EPOCH: both exact-bound additions in
    # test_health_stale_verifier_fails_closed_and_refresh_recovers must read
    # exactly 20.0, else the boundary is off by ~1 ulp on every host.
    first = _MANUAL_CLOCK_EPOCH + 20.0
    assert first - _MANUAL_CLOCK_EPOCH == 20.0
    renewed = _MANUAL_CLOCK_EPOCH + 20.001
    second = renewed + 20.0
    assert second - renewed == 20.0


def test_health_stale_verifier_fails_closed_and_refresh_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import csk_registry.store as store_module

    client, store, key, auditor_key, token = _health_client(
        tmp_path, health_verify_interval=10.0
    )
    headers = {"Authorization": f"Bearer {token}"}
    assert (
        client.post("/v1/records", json=auditor_key.sign_record(_body("audited")), headers=headers).status_code
        == 201
    )
    assert client.get("/health").status_code == 200

    # Deterministic clock: the stale bound is 2 × 10 = 20 s. No sleeps.
    # Only the explicit refresh_health_verdict() calls below may advance the
    # verdict under the manual clock: the verifier only runs under the serving
    # lifespan (this bare TestClient never starts it — locked by the assert),
    # and the stop is the ordered guard before the clock install.
    assert not store.health_verifier_running()
    store.stop_health_verifier()
    clock = _ManualStoreClock(_MANUAL_CLOCK_EPOCH)
    monkeypatch.setattr(store_module, "time", clock)
    # Re-anchor last_refresh to the fixed epoch through the production refresh
    # entry point, then read the base AFTER the pause/clock install.
    assert store.refresh_health_verdict().ready
    base = store._health_last_refresh_monotonic
    assert base == _MANUAL_CLOCK_EPOCH

    # (a) Exact boundary: age == bound is still fresh; age > bound is stale.
    clock.now = base + 20.0
    assert client.get("/health").status_code == 200
    store.append(
        key.sign_record(_body(name="skill-at-bound")),
        created_at="2026-07-13T02:00:00Z",
    )
    clock.now = base + 20.001
    stale = client.get("/health")
    assert stale.status_code == 503
    assert stale.json()["error"]["code"] == "not_ready"
    with pytest.raises(StoreIntegrityError, match="stale"):
        store.append(
            key.sign_record(_body(name="skill-stale")),
            created_at="2026-07-13T02:00:01Z",
        )

    # (b) Late completion of the stalled verifier restores readiness without
    # a restart (staleness is transient; only failure/corruption latches).
    assert store.refresh_health_verdict().ready
    assert client.get("/health").status_code == 200
    assert (
        client.post("/v1/records", json=auditor_key.sign_record(_body("revoked")), headers=headers).status_code
        == 201
    )
    # Still fresh just inside the new bound, stale again past it.
    renewed = store._health_last_refresh_monotonic
    clock.now = renewed + 20.0
    assert client.get("/health").status_code == 200
    clock.now = renewed + 20.001
    assert client.get("/health").status_code == 503


def test_health_stalled_verifier_failure_stays_latched_until_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import csk_registry.store as store_module

    path = tmp_path / "r.db"
    client, store, key, _, _ = _health_client(tmp_path, health_verify_interval=10.0)
    store.append(
        key.sign_record(_body(name="skill-0")),
        created_at="2026-07-13T00:00:00Z",
    )
    genuine = store_module_head(store, 1)
    assert client.get("/health").status_code == 200

    # Stall past the bound, then corrupt: the completion FAILS.
    base = store._health_last_refresh_monotonic
    clock = _ManualStoreClock(base + 20.001)
    monkeypatch.setattr(store_module, "time", clock)
    assert client.get("/health").status_code == 503
    _tamper_log_entry_hash(path, 1, "ff" * 32)
    failed = store.refresh_health_verdict()
    assert not failed.ready
    assert "hash" in (failed.error or "")

    # (c) A failed completion latches: restoring a fresh clock does not
    # recover, and neither does repairing + refreshing without a restart.
    monkeypatch.undo()
    assert client.get("/health").status_code == 503
    with pytest.raises(StoreIntegrityError, match="restart to re-verify"):
        store.append(
            key.sign_record(_body(name="skill-blocked")),
            created_at="2026-07-13T02:00:00Z",
        )
    _tamper_log_entry_hash(path, 1, genuine)
    assert not store.refresh_health_verdict().ready
    assert client.get("/health").status_code == 503
    store.close()

    healed = Store(path)
    try:
        assert healed.health_verdict().ready
        assert healed.head()[0] == 1
    finally:
        healed.close()


def test_health_refresh_sees_concurrent_append_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Correction 1: a valid append committing between the verifier's chain
    # walk and its frontier load must not false-positive as corruption. The
    # whole pass reads under one WAL snapshot; the interleaved append stays
    # invisible to it and is trusted transitively via its anchor checks.
    client, store, key, _, _ = _health_client(tmp_path)
    record = key.sign_record(_body())
    store.append(record, created_at="2026-07-13T02:00:00Z")
    original = store._load_frontier
    injected: list[bool] = [False]

    def interleaved(conn: object = None) -> object:
        if conn is not None and not injected[0]:
            injected[0] = True
            store.append(record, created_at="2026-07-13T02:00:01Z")
        return original(conn)  # type: ignore[arg-type]

    monkeypatch.setattr(store, "_load_frontier", interleaved)
    verdict = store.refresh_health_verdict()
    assert injected[0]
    assert store.integrity_errors() == []
    assert verdict.ready, verdict.error
    assert verdict.verified_log_size == 2
    assert client.get("/health").status_code == 200


def test_health_append_refuses_corrupted_frontier_and_latches(
    tmp_path: Path,
) -> None:
    # Correction 2: length-preserving level-0 tail tampering after three
    # entries must refuse the fourth append through the production entry,
    # flip /health to 503, and leave the committed boundary intact (no wrong
    # immutable root, no green attestation). No full-chain hashing per
    # request: the anchors are O(1) rows + O(log n) hashes.
    import csk_registry.store as store_module

    path = tmp_path / "r.db"
    client, store, key, _, _ = _health_client(tmp_path)
    record = key.sign_record(_body())
    for _ in range(3):
        store.append(record, created_at="2026-07-13T02:00:00Z")
    assert client.get("/health").status_code == 200
    good_root = store.snapshot_boundary().merkle_root
    good_head = store.head()

    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE merkle_frontier SET tail = ? WHERE level = 0",
            ('["' + "f" * 64 + '","' + "e" * 64 + '"]',),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(StoreIntegrityError, match="frontier"):
        store.append(record, created_at="2026-07-13T02:00:01Z")
    failed = client.get("/health")
    assert failed.status_code == 503
    assert failed.json()["error"]["code"] == "not_ready"
    # Nothing committed: head still 3 and the boundary root is the genuine one.
    assert store.head() == good_head
    assert store.snapshot_boundary().merkle_root == good_root
    expected = store_module._merkle_root(
        [entry.entry_hash for entry in store.log_entries()]
    )
    assert good_root == expected
    # Latched: stays non-ready until a restart re-verifies.
    assert not store.refresh_health_verdict().ready


def test_health_rollback_does_not_advance_cached_verdict(tmp_path: Path) -> None:
    # Correction 3: the cached head advances only after COMMIT. A BEFORE
    # INSERT trigger that ABORTs the import-ledger write rolls the whole
    # transaction back; the durable head stays 0 and the verdict must agree.
    client, store, key, _, _ = _health_client(tmp_path)
    record = key.sign_record(_body())
    connection = sqlite3.connect(store.path)
    try:
        connection.execute(
            "CREATE TRIGGER refuse_import BEFORE INSERT ON imported_records "
            "BEGIN SELECT RAISE(ABORT, 'injected write failure'); END"
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(sqlite3.IntegrityError, match="injected write failure"):
        store.append_imports([("fingerprint", record)], created_at="2026-07-13T02:00:00Z")
    assert store.head()[0] == 0
    verdict = store.health_verdict()
    assert verdict.ready
    assert verdict.verified_log_size == 0, f"rolled back store reports {verdict}"
    assert client.get("/health").status_code == 200


def test_health_idempotent_rollback_does_not_advance_cached_verdict(
    tmp_path: Path,
) -> None:
    # Correction 3 via the idempotent entry: the ledger INSERT fails after
    # the log INSERT, the transaction rolls back, and the verdict stays put.
    client, store, key, _, _ = _health_client(tmp_path)
    record = key.sign_record(_body())
    connection = sqlite3.connect(store.path)
    try:
        connection.execute(
            "CREATE TRIGGER refuse_idempotency BEFORE INSERT ON idempotency "
            "BEGIN SELECT RAISE(ABORT, 'injected idempotency failure'); END"
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(sqlite3.IntegrityError, match="injected idempotency failure"):
        store.append_idempotent(
            record,
            auditor_id="a1",
            key="k1",
            body_sha256="ab" * 32,
            created_at="2026-07-13T02:00:00Z",
            now=1_800_000_000,
            ttl_seconds=24 * 3600,
        )
    assert store.head()[0] == 0
    verdict = store.health_verdict()
    assert verdict.ready
    assert verdict.verified_log_size == 0, f"rolled back store reports {verdict}"
    assert client.get("/health").status_code == 200


def test_health_restart_after_repair_returns_ready(tmp_path: Path) -> None:
    path = tmp_path / "repair.db"
    store = Store(path)
    key = signing.generate_key()
    for index in range(2):
        store.append(
            key.sign_record(_body(name=f"skill-{index}")),
            created_at=f"2026-07-13T00:00:0{index}Z",
        )
    genuine = store_module_head(store, 1)
    _tamper_log_entry_hash(path, 1, "ff" * 32)
    assert not store.refresh_health_verdict().ready

    # Repair behind the back: without a restart the latch holds.
    _tamper_log_entry_hash(path, 1, genuine)
    assert not store.refresh_health_verdict().ready
    store.close()

    healed = Store(path)
    try:
        assert healed.health_verdict().ready
        client = TestClient(
            create_app(store=healed, signing_key=key, tokens=AuditorTokens([]))
        )
        assert client.get("/health").status_code == 200
        entry = healed.append(
            key.sign_record(_body(name="skill-2")),
            created_at="2026-07-13T00:00:02Z",
        )
        assert entry.seq == 3
    finally:
        healed.close()


def test_health_append_advances_verified_head_without_full_refresh(tmp_path: Path) -> None:
    store = Store(tmp_path / "incremental.db")
    key = signing.generate_key()
    store.append(key.sign_record(_body(name="skill-0")), created_at="2026-07-13T00:00:00Z")
    before = store.health_verdict()
    assert before.ready and before.verified_log_size == 1

    entry = store.append(
        key.sign_record(_body(name="skill-1")), created_at="2026-07-13T00:00:01Z"
    )
    after = store.health_verdict()
    assert after.ready and after.error is None
    assert after.verified_head == entry.entry_hash == store.head()[1]
    assert after.verified_log_size == 2
    # The incremental advance moves the head only; the staleness clock still
    # requires a periodic full pass to catch interior tampering of old rows.
    assert after.verified_at == before.verified_at


def test_health_verifier_lifecycle_and_lifespan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = Store(tmp_path / "thread.db", health_verify_interval=3600.0)
    try:
        assert not store.health_verifier_running()
        store.start_health_verifier()
        assert store.health_verifier_running()
        store.start_health_verifier()
        assert store.health_verifier_running()
        store.stop_health_verifier()
        assert not store.health_verifier_running()
        store.stop_health_verifier()
        assert not store.health_verifier_running()
    finally:
        store.close()

    # A short interval actually fires the background pass on a quiet store.
    background = Store(tmp_path / "thread2.db", health_verify_interval=0.05)
    try:
        calls: list[int] = [0]
        real_refresh = background.refresh_health_verdict

        def counting() -> object:
            calls[0] += 1
            return real_refresh()

        monkeypatch.setattr(background, "refresh_health_verdict", counting)
        background.start_health_verifier()
        try:
            deadline = time.monotonic() + 10.0
            while not calls and time.monotonic() < deadline:
                time.sleep(0.05)
            assert calls, "background verifier never fired"
            assert background.health_verdict().ready
        finally:
            background.stop_health_verifier()
    finally:
        background.close()

    # Serving lifespan starts the verifier on entry and stops it on exit.
    served = Store(tmp_path / "life.db", health_verify_interval=3600.0)
    try:
        app = create_app(
            store=served, signing_key=signing.generate_key(), tokens=AuditorTokens([])
        )
        with TestClient(app) as client:
            assert served.health_verifier_running()
            assert client.get("/health").status_code == 200
        assert not served.health_verifier_running()
    finally:
        served.close()


def test_health_refresh_detects_boundary_cache_tampering(tmp_path: Path) -> None:
    path = tmp_path / "cache-tamper.db"
    store = Store(path)
    key = signing.generate_key()
    for index in range(3):
        store.append(
            key.sign_record(_body(name=f"skill-{index}")),
            created_at=f"2026-07-13T00:00:0{index}Z",
        )
    assert store.refresh_health_verdict().ready

    # Tamper only the memoized Merkle root: the O(1) live anchors check
    # head/timestamp, so reads keep serving it — only the refresh catches it.
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE boundaries SET merkle_root = ? WHERE log_size = 3", ("ee" * 32,)
        )
        connection.commit()
    finally:
        connection.close()
    assert store.snapshot_boundary().merkle_root == "ee" * 32
    verdict = store.refresh_health_verdict()
    assert not verdict.ready
    assert "boundary cache" in (verdict.error or "")


def test_health_refresh_detects_frontier_tampering(tmp_path: Path) -> None:
    path = tmp_path / "frontier-tamper.db"
    store = Store(path)
    key = signing.generate_key()
    for index in range(3):
        store.append(
            key.sign_record(_body(name=f"skill-{index}")),
            created_at=f"2026-07-13T00:00:0{index}Z",
        )
    assert store.refresh_health_verdict().ready

    connection = sqlite3.connect(path)
    try:
        row = connection.execute(
            "SELECT tail FROM merkle_frontier WHERE level = 0"
        ).fetchone()
        assert row is not None
        tail = json.loads(row[0])
        tail[0] = "ff" * 32
        connection.execute(
            "UPDATE merkle_frontier SET tail = ? WHERE level = 0", (json.dumps(tail),)
        )
        connection.commit()
    finally:
        connection.close()
    verdict = store.refresh_health_verdict()
    assert not verdict.ready
    assert "frontier" in (verdict.error or "")


def test_boundary_cache_comparison_branches() -> None:
    import csk_registry.store as store_module

    leaves = [
        (
            hashlib.sha256(f"leaf-{index}".encode()).hexdigest(),
            f"2026-07-13T00:00:0{index}Z",
        )
        for index in range(3)
    ]
    expected, frontier = store_module._recompute_prefix(leaves)
    stored = {size: boundary for size, boundary in enumerate(expected, start=1)}

    def _tails(levels: list[store_module._FrontierLevel]) -> list[store_module._FrontierLevel]:
        return [
            store_module._FrontierLevel(length=level.length, tail=list(level.tail))
            for level in levels
        ]

    base = {
        "expected": expected,
        "stored": dict(stored),
        "walked_size": 3,
        "live_size": 3,
        "frontier_length": 3,
        "stored_frontier": _tails(frontier),
        "recomputed_frontier": frontier,
    }
    assert store_module._boundary_cache_errors(**base) == []

    missing = dict(base, stored={size: row for size, row in stored.items() if size != 2})
    assert any(
        "missing log size 2" in error
        for error in store_module._boundary_cache_errors(**missing)
    )

    disagreed = dict(stored)
    disagreed[3] = ("00" * 32, disagreed[3][1], disagreed[3][2])
    assert any(
        "disagrees with the committed log" in error
        for error in store_module._boundary_cache_errors(**dict(base, stored=disagreed))
    )

    # A row committed after the chain statement started is a legitimate
    # concurrent append: ignored, and the frontier tails are skipped while
    # the (race-free) length check still holds.
    concurrent = dict(
        base,
        expected=expected[:2],
        walked_size=2,
        stored_frontier=[],
    )
    assert store_module._boundary_cache_errors(**concurrent) == []

    beyond = dict(stored)
    beyond[4] = ("ab" * 32, "cd" * 32, "2026-07-13T00:00:03Z")
    assert any(
        "uncommitted log size 4" in error
        for error in store_module._boundary_cache_errors(**dict(base, stored=beyond))
    )

    invalid = dict(stored)
    invalid[0] = stored[1]
    assert any(
        "invalid log size 0" in error
        for error in store_module._boundary_cache_errors(**dict(base, stored=invalid))
    )

    assert any(
        "does not match the log head" in error
        for error in store_module._boundary_cache_errors(**dict(base, frontier_length=2))
    )

    wrong_tails = [
        store_module._FrontierLevel(length=level.length, tail=[b"\x00" * 32 for _ in level.tail])
        for level in frontier
    ]
    assert any(
        "frontier disagrees" in error
        for error in store_module._boundary_cache_errors(
            **dict(base, stored_frontier=wrong_tails)
        )
    )

    empty_expected, empty_frontier = store_module._recompute_prefix([])
    assert (
        store_module._boundary_cache_errors(
            expected=empty_expected,
            stored={},
            walked_size=0,
            live_size=0,
            frontier_length=None,
            stored_frontier=[],
            recomputed_frontier=empty_frontier,
        )
        == []
    )


def test_serve_health_verify_interval_flag_and_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from csk_registry import HEALTH_VERIFY_INTERVAL_ENV
    from csk_registry.app import _positive_float_env

    parser = build_parser()
    assert parser.parse_args(["serve"]).health_verify_interval is None
    assert (
        parser.parse_args(["serve", "--health-verify-interval", "60"]).health_verify_interval
        == 60.0
    )
    # Invalid values are rejected before the server boots.
    assert main(["--home", str(tmp_path), "serve", "--health-verify-interval", "0"]) == 1
    assert main(["--home", str(tmp_path), "serve", "--health-verify-interval", "-5"]) == 1
    assert main(["--home", str(tmp_path), "serve", "--health-verify-interval", "nan"]) == 1

    monkeypatch.delenv(HEALTH_VERIFY_INTERVAL_ENV, raising=False)
    assert _positive_float_env(HEALTH_VERIFY_INTERVAL_ENV, 300.0) == 300.0
    monkeypatch.setenv(HEALTH_VERIFY_INTERVAL_ENV, "45")
    assert _positive_float_env(HEALTH_VERIFY_INTERVAL_ENV, 300.0) == 45.0
    monkeypatch.setenv(HEALTH_VERIFY_INTERVAL_ENV, "bogus")
    with pytest.raises(RuntimeError, match="positive number"):
        _positive_float_env(HEALTH_VERIFY_INTERVAL_ENV, 300.0)
    monkeypatch.setenv(HEALTH_VERIFY_INTERVAL_ENV, "inf")
    with pytest.raises(RuntimeError, match="positive number"):
        _positive_float_env(HEALTH_VERIFY_INTERVAL_ENV, 300.0)

    with pytest.raises(ValueError, match="health_verify_interval"):
        Store(tmp_path / "bad.db", health_verify_interval=0)


def test_frontier_tampering_rebuilds_and_next_append_stays_correct(
    tmp_path: Path,
) -> None:
    import csk_registry.store as store_module

    path = tmp_path / "frontier.db"
    store = Store(path)
    key = signing.generate_key()
    for index in range(4):
        store.append(
            key.sign_record(_body(name=f"skill-{index}")),
            created_at=f"2026-07-13T00:00:0{index}Z",
        )
    store.close()
    connection = sqlite3.connect(path)
    try:
        connection.execute("UPDATE merkle_frontier SET tail = ?", (json.dumps(["ff" * 32]),))
        connection.commit()
    finally:
        connection.close()
    reopened = Store(path)
    try:
        reopened.append(
            key.sign_record(_body(name="skill-4")),
            created_at="2026-07-13T00:00:04Z",
        )
        entry_hashes = [
            str(row["entry_hash"])
            for row in reopened._conn.execute(  # type: ignore[attr-defined]
                "SELECT entry_hash FROM log ORDER BY seq"
            )
        ]
        assert reopened.snapshot_boundary().merkle_root == store_module._merkle_root(
            entry_hashes
        )
    finally:
        reopened.close()


# Upstream high-water (P4): per-upstream rollback refusal for import-bundle.


def _upstream_pair(tmp_path: Path) -> tuple[object, object, dict, dict]:
    """Build one upstream history and return (up_key, down_key, v1, v2)."""
    from csk_registry.bundle import export_bundle

    upstream = Store(tmp_path / "up.db")
    up_key = signing.generate_key()
    upstream.append(
        up_key.sign_record(_body("audited", name="skill-a")),
        created_at="2026-07-07T00:00:00Z",
    )
    bundle_v1 = export_bundle(upstream, up_key)
    upstream.append(
        up_key.sign_record(
            _body("audited", name="skill-b", commit="1" * 40, content_sha256="sha256:" + "2f" * 32)
        ),
        created_at="2026-07-07T01:00:00Z",
    )
    bundle_v2 = export_bundle(upstream, up_key)
    upstream.close()
    return up_key, signing.generate_key(), bundle_v1, bundle_v2  # type: ignore[return-value]


def test_first_import_establishes_upstream_high_water(tmp_path: Path) -> None:
    from csk_registry.bundle import import_bundle

    up_key, down_key, bundle_v1, _ = _upstream_pair(tmp_path)
    downstream = Store(tmp_path / "down.db")
    assert downstream.get_upstream_high_water(up_key.key_id) is None  # type: ignore[attr-defined,union-attr]
    assert (
        import_bundle(downstream, down_key, bundle_v1, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
        == 1
    )
    high_water = downstream.get_upstream_high_water(up_key.key_id)  # type: ignore[union-attr]
    assert high_water is not None
    assert high_water.version == bundle_v1["snapshot"]["version"] == 1
    assert high_water.log_size == bundle_v1["snapshot"]["log_size"] == 1
    assert high_water.head == bundle_v1["snapshot"]["head"]
    assert high_water.merkle_root == bundle_v1["snapshot"]["merkle_root"]


def test_import_rollback_bundle_refused(tmp_path: Path) -> None:
    from csk_registry.bundle import import_bundle

    up_key, down_key, bundle_v1, bundle_v2 = _upstream_pair(tmp_path)
    downstream = Store(tmp_path / "down.db")
    assert (
        import_bundle(downstream, down_key, bundle_v2, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
        == 2
    )
    before = downstream.head()[0]
    with pytest.raises(ValueError, match="import_upstream_rollback"):
        import_bundle(downstream, down_key, bundle_v1, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
    try:
        import_bundle(downstream, down_key, bundle_v1, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
    except ValueError as exc:
        message = str(exc)
        assert "import_upstream_rollback" in message
        assert up_key.key_id in message  # type: ignore[union-attr]
        assert bundle_v1["snapshot"]["head"] in message
        assert bundle_v2["snapshot"]["head"] in message
    else:  # pragma: no cover
        raise AssertionError("rollback bundle was accepted")
    high_water = downstream.get_upstream_high_water(up_key.key_id)  # type: ignore[union-attr]
    assert high_water is not None and high_water.version == 2
    assert downstream.head()[0] == before


def test_import_inconsistent_bundle_refused_even_with_flag(tmp_path: Path) -> None:
    from csk_registry.bundle import export_bundle, import_bundle

    upstream = Store(tmp_path / "up.db")
    up_key = signing.generate_key()
    upstream.append(
        up_key.sign_record(_body("audited", name="skill-a")),
        created_at="2026-07-07T00:00:00Z",
    )
    bundle_a = export_bundle(upstream, up_key)
    upstream.close()
    fork = Store(tmp_path / "fork.db")
    fork.append(
        up_key.sign_record(
            _body("audited", name="skill-fork", commit="2" * 40, content_sha256="sha256:" + "3f" * 32)
        ),
        created_at="2026-07-07T00:00:00Z",
    )
    bundle_fork = export_bundle(fork, up_key)
    fork.close()
    assert bundle_a["snapshot"]["version"] == bundle_fork["snapshot"]["version"] == 1
    assert bundle_a["snapshot"]["head"] != bundle_fork["snapshot"]["head"]

    downstream = Store(tmp_path / "down.db")
    down_key = signing.generate_key()
    assert import_bundle(downstream, down_key, bundle_a, upstream_public_key=up_key.public_pinned) == 1
    for accept_older in (False, True):
        with pytest.raises(ValueError, match="import_upstream_inconsistent"):
            import_bundle(
                downstream,
                down_key,
                bundle_fork,
                upstream_public_key=up_key.public_pinned,
                accept_older_upstream=accept_older,
            )
    high_water = downstream.get_upstream_high_water(up_key.key_id)
    assert high_water is not None and high_water.head == bundle_a["snapshot"]["head"]
    assert downstream.head()[0] == 1


def test_identical_reimport_is_noop(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    from csk_registry import bundle as bundle_module
    from csk_registry.bundle import import_bundle

    up_key, down_key, _, bundle_v2 = _upstream_pair(tmp_path)
    downstream = Store(tmp_path / "down.db")
    assert (
        import_bundle(downstream, down_key, bundle_v2, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
        == 2
    )
    before = downstream.get_upstream_high_water(up_key.key_id)  # type: ignore[union-attr]
    # Freeze a distinct re-import timestamp: a rewrite of the high-water row
    # would stamp it, so row equality below proves nothing was persisted
    # (utc_now has one-second resolution and same-second imports would
    # otherwise collide).
    monkeypatch.setattr(bundle_module, "utc_now", lambda: "2030-01-01T00:00:00Z")
    with caplog.at_level(logging.INFO, logger="csk_registry.audit"):
        assert (
            import_bundle(downstream, down_key, bundle_v2, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
            == 0
        )
    after = downstream.get_upstream_high_water(up_key.key_id)  # type: ignore[union-attr]
    assert before == after
    assert downstream.head()[0] == 2
    events = [
        json.loads(record.message)
        for record in caplog.records
        if "import_bundle" in record.message
    ]
    assert events and events[-1]["result"] == "noop"
    assert events[-1]["offered"]["version"] == 2
    assert events[-1]["persisted"]["version"] == 2


def test_newer_bundle_advances_high_water(tmp_path: Path) -> None:
    from csk_registry.bundle import import_bundle

    up_key, down_key, bundle_v1, bundle_v2 = _upstream_pair(tmp_path)
    downstream = Store(tmp_path / "down.db")
    assert (
        import_bundle(downstream, down_key, bundle_v1, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
        == 1
    )
    assert downstream.get_upstream_high_water(up_key.key_id).version == 1  # type: ignore[union-attr]
    assert (
        import_bundle(downstream, down_key, bundle_v2, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
        == 1
    )
    high_water = downstream.get_upstream_high_water(up_key.key_id)  # type: ignore[union-attr]
    assert high_water is not None and high_water.version == 2
    assert high_water.head == bundle_v2["snapshot"]["head"]
    assert downstream.head()[0] == 2


def test_accept_older_upstream_imports_without_lowering(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    from csk_registry.bundle import export_bundle, import_bundle

    up_key, down_key, _, bundle_v2 = _upstream_pair(tmp_path)
    fork = Store(tmp_path / "fork.db")
    fork.append(
        up_key.sign_record(  # type: ignore[union-attr]
            _body("audited", name="skill-fork", commit="9" * 40, content_sha256="sha256:" + "9f" * 32)
        ),
        created_at="2026-07-07T00:00:00Z",
    )
    bundle_old_fork = export_bundle(fork, up_key)  # type: ignore[arg-type]
    fork.close()
    assert bundle_old_fork["snapshot"]["version"] == 1

    downstream = Store(tmp_path / "down.db")
    assert (
        import_bundle(downstream, down_key, bundle_v2, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
        == 2
    )
    with caplog.at_level(logging.INFO, logger="csk_registry.audit"):
        count = import_bundle(
            downstream,
            down_key,  # type: ignore[arg-type]
            bundle_old_fork,
            upstream_public_key=up_key.public_pinned,  # type: ignore[union-attr]
            accept_older_upstream=True,
        )
    assert count == 1
    high_water = downstream.get_upstream_high_water(up_key.key_id)  # type: ignore[union-attr]
    assert high_water is not None and high_water.version == 2
    assert high_water.head == bundle_v2["snapshot"]["head"]
    events = [
        json.loads(record.message)
        for record in caplog.records
        if "import_bundle" in record.message
    ]
    assert events and events[-1]["warning"] == "import_upstream_rollback"
    assert events[-1]["accepted_older"] is True
    assert events[-1]["persisted"]["version"] == 2
    assert events[-1]["offered"]["version"] == 1


def test_failed_import_leaves_high_water_untouched(tmp_path: Path) -> None:
    import copy

    from csk_registry.bundle import import_bundle

    up_key, down_key, bundle_v1, bundle_v2 = _upstream_pair(tmp_path)
    downstream = Store(tmp_path / "down.db")
    assert (
        import_bundle(downstream, down_key, bundle_v1, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
        == 1
    )
    # Chain break: swap the two records so per-record signatures still verify
    # but the head no longer matches the snapshot.
    tampered = copy.deepcopy(bundle_v2)
    tampered["records"] = [tampered["records"][1], tampered["records"][0]]
    with pytest.raises(ValueError, match="head or size|Merkle"):
        import_bundle(downstream, down_key, tampered, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
    high_water = downstream.get_upstream_high_water(up_key.key_id)  # type: ignore[union-attr]
    assert high_water is not None and high_water.version == 1
    assert downstream.head()[0] == 1
    # The untampered newer bundle still imports and advances afterwards.
    assert (
        import_bundle(downstream, down_key, bundle_v2, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
        == 1
    )
    assert downstream.get_upstream_high_water(up_key.key_id).version == 2  # type: ignore[union-attr]


def test_failed_append_rolls_back_high_water_advance(tmp_path: Path) -> None:
    from csk_registry.bundle import import_bundle

    up_key, down_key, bundle_v1, bundle_v2 = _upstream_pair(tmp_path)
    downstream = Store(tmp_path / "down.db")
    assert (
        import_bundle(downstream, down_key, bundle_v1, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
        == 1
    )
    downstream._conn.execute(  # type: ignore[attr-defined]
        "CREATE TRIGGER fail_import BEFORE INSERT ON log "
        "BEGIN SELECT RAISE(ABORT, 'injected failure'); END"
    )
    with pytest.raises(Exception, match="injected failure"):
        import_bundle(downstream, down_key, bundle_v2, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
    high_water = downstream.get_upstream_high_water(up_key.key_id)  # type: ignore[union-attr]
    assert high_water is not None and high_water.version == 1
    assert downstream.head()[0] == 1
    downstream._conn.execute("DROP TRIGGER fail_import")  # type: ignore[attr-defined]
    assert (
        import_bundle(downstream, down_key, bundle_v2, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
        == 1
    )
    assert downstream.get_upstream_high_water(up_key.key_id).version == 2  # type: ignore[union-attr]


def test_upstream_high_water_is_per_key(tmp_path: Path) -> None:
    from csk_registry.bundle import export_bundle, import_bundle

    upstream_a = Store(tmp_path / "a.db")
    key_a = signing.generate_key()
    upstream_a.append(
        key_a.sign_record(_body("audited", name="skill-a")),
        created_at="2026-07-07T00:00:00Z",
    )
    upstream_a.append(
        key_a.sign_record(
            _body("audited", name="skill-a2", commit="1" * 40, content_sha256="sha256:" + "2f" * 32)
        ),
        created_at="2026-07-07T01:00:00Z",
    )
    bundle_a2 = export_bundle(upstream_a, key_a)
    upstream_a.close()
    upstream_b = Store(tmp_path / "b.db")
    key_b = signing.generate_key()
    upstream_b.append(
        key_b.sign_record(_body("audited", name="skill-b")),
        created_at="2026-07-07T00:00:00Z",
    )
    bundle_b1 = export_bundle(upstream_b, key_b)
    upstream_b.close()

    downstream = Store(tmp_path / "down.db")
    down_key = signing.generate_key()
    assert import_bundle(downstream, down_key, bundle_a2, upstream_public_key=key_a.public_pinned) == 2
    # An older version from another upstream is a first import, not a rollback.
    assert import_bundle(downstream, down_key, bundle_b1, upstream_public_key=key_b.public_pinned) == 1
    assert downstream.get_upstream_high_water(key_a.key_id) is not None
    assert downstream.get_upstream_high_water(key_a.key_id).version == 2  # type: ignore[union-attr]
    assert downstream.get_upstream_high_water(key_b.key_id) is not None
    assert downstream.get_upstream_high_water(key_b.key_id).version == 1  # type: ignore[union-attr]


def test_import_bundle_cli_flag_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    up_key, _, bundle_v1, bundle_v2 = _upstream_pair(tmp_path)
    home = tmp_path / "home"
    assert main(["--home", str(home), "genkey"]) == 0
    newer_path = tmp_path / "newer.json"
    older_path = tmp_path / "older.json"
    newer_path.write_text(json.dumps(bundle_v2), encoding="utf-8")
    older_path.write_text(json.dumps(bundle_v1), encoding="utf-8")
    assert (
        main(
            ["--home", str(home), "import-bundle", str(newer_path), "--upstream-key", up_key.public_pinned]  # type: ignore[union-attr]
        )
        == 0
    )
    capsys.readouterr()
    assert (
        main(
            ["--home", str(home), "import-bundle", str(older_path), "--upstream-key", up_key.public_pinned]  # type: ignore[union-attr]
        )
        == 1
    )
    _, err = capsys.readouterr()
    assert "import_upstream_rollback" in err
    assert up_key.key_id in err  # type: ignore[union-attr]
    assert (
        main(
            [
                "--home",
                str(home),
                "import-bundle",
                str(older_path),
                "--upstream-key",
                up_key.public_pinned,  # type: ignore[union-attr]
                "--accept-older-upstream",
            ]
        )
        == 0
    )
    _, err_flag = capsys.readouterr()
    assert "warning" in err_flag.lower()
    assert "import_upstream_rollback" in err_flag
    downstream = Store(home / "registry.db")
    try:
        assert downstream.get_upstream_high_water(up_key.key_id).version == 2  # type: ignore[union-attr]
    finally:
        downstream.close()


def test_v3_database_migrates_to_v4_preserving_log(tmp_path: Path) -> None:
    path = tmp_path / "v3.db"
    store = Store(path)
    key = signing.generate_key()
    store.append(
        key.sign_record(_body(name="skill-0")),
        created_at="2026-07-13T00:00:00Z",
    )
    store.close()
    connection = sqlite3.connect(path)
    try:
        connection.execute("DROP TABLE upstream_high_water")
        connection.execute("UPDATE metadata SET value = '3' WHERE key = 'schema_version'")
        connection.execute("PRAGMA user_version=3")
        connection.commit()
    finally:
        connection.close()
    upgraded = Store(path)
    try:
        marker = upgraded._conn.execute(  # type: ignore[attr-defined]
            "SELECT value FROM metadata WHERE key = 'schema_version'"
        ).fetchone()
        assert marker["value"] == "4"
        assert int(upgraded._conn.execute("PRAGMA user_version").fetchone()[0]) == 4  # type: ignore[attr-defined]
        assert upgraded.head()[0] == 1
        assert upgraded.get_upstream_high_water("0" * 16) is None
        upgraded.append(
            key.sign_record(_body(name="skill-1")),
            created_at="2026-07-13T00:00:01Z",
        )
        assert upgraded.head()[0] == 2
    finally:
        upgraded.close()


def test_backup_preserves_upstream_high_water(tmp_path: Path) -> None:
    from csk_registry.bundle import import_bundle

    up_key, down_key, _, bundle_v2 = _upstream_pair(tmp_path)
    downstream = Store(tmp_path / "down.db")
    assert (
        import_bundle(downstream, down_key, bundle_v2, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
        == 2
    )
    downstream.backup_to(tmp_path / "backup.db")
    downstream.close()
    backup = Store(tmp_path / "backup.db")
    try:
        high_water = backup.get_upstream_high_water(up_key.key_id)  # type: ignore[union-attr]
        assert high_water is not None and high_water.version == 2
        assert high_water.head == bundle_v2["snapshot"]["head"]
    finally:
        backup.close()


# Competing-writer high-water races (P4 revision 2): the authoritative
# comparison inside the serialized write transaction must carry the closed
# diagnostics, the override policy and the audit event.


def _upstream_triple(tmp_path: Path) -> tuple[object, object, dict, dict, dict]:
    """Build one upstream history and return (up_key, down_key, v1, v2, v3)."""
    from csk_registry.bundle import export_bundle

    upstream = Store(tmp_path / "up3.db")
    up_key = signing.generate_key()
    upstream.append(
        up_key.sign_record(_body("audited", name="skill-a")),
        created_at="2026-07-07T00:00:00Z",
    )
    bundle_v1 = export_bundle(upstream, up_key)
    upstream.append(
        up_key.sign_record(
            _body("audited", name="skill-b", commit="1" * 40, content_sha256="sha256:" + "2f" * 32)
        ),
        created_at="2026-07-07T01:00:00Z",
    )
    bundle_v2 = export_bundle(upstream, up_key)
    upstream.append(
        up_key.sign_record(
            _body("audited", name="skill-c", commit="3" * 40, content_sha256="sha256:" + "4f" * 32)
        ),
        created_at="2026-07-07T02:00:00Z",
    )
    bundle_v3 = export_bundle(upstream, up_key)
    upstream.close()
    return up_key, signing.generate_key(), bundle_v1, bundle_v2, bundle_v3  # type: ignore[return-value]


def _pause_outer_import_at_write(
    monkeypatch: pytest.MonkeyPatch,
    outer: Store,
    competitor_thunk: Callable[[], object],
) -> None:
    """Model the legal interleaving where a competitor commits first.

    The outer import runs its real verification path, then pauses at its
    serialized write: the competitor thunk (a real second ``Store``
    connection importing through the real ``import_bundle`` entry point)
    commits fully, and only then does the outer write run unchanged. The
    authoritative comparison inside the transaction therefore decides against
    the competitor's committed state. Deterministic: no threads, no sleeps.
    """
    original = outer.append_upstream_import

    def raced(*args: object, **kwargs: object) -> object:
        competitor_thunk()
        return original(*args, **kwargs)  # type: ignore[arg-type,misc]

    monkeypatch.setattr(outer, "append_upstream_import", raced)


def _import_events(caplog: pytest.LogCaptureFixture) -> list[dict]:
    return [
        json.loads(record.message)
        for record in caplog.records
        if "import_bundle" in record.message
    ]


def test_concurrent_newer_first_refuses_outer_with_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from csk_registry.bundle import import_bundle

    up_key, down_key, bundle_v1, bundle_v2, bundle_v3 = _upstream_triple(tmp_path)
    downstream = Store(tmp_path / "down.db")
    competitor = Store(tmp_path / "down.db")
    try:
        assert (
            import_bundle(downstream, down_key, bundle_v1, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
            == 1
        )
        competitor_state: dict[str, object] = {}

        def commit_v3_first() -> None:
            assert (
                import_bundle(competitor, down_key, bundle_v3, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
                == 2
            )
            competitor_state["high_water"] = competitor.get_upstream_high_water(up_key.key_id)  # type: ignore[union-attr]
            competitor_state["head"] = competitor.head()

        _pause_outer_import_at_write(monkeypatch, downstream, commit_v3_first)
        with caplog.at_level(logging.INFO, logger="csk_registry.audit"):
            with pytest.raises(ValueError, match="import_upstream_rollback") as exc_info:
                import_bundle(downstream, down_key, bundle_v2, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
        message = str(exc_info.value)
        assert up_key.key_id in message  # type: ignore[union-attr]
        assert bundle_v3["snapshot"]["head"] in message  # persisted (competitor's v3)
        assert bundle_v2["snapshot"]["head"] in message  # offered (outer v2)
        events = _import_events(caplog)
        assert events and events[-1]["result"] == "refused"
        assert events[-1]["diagnostic"] == "import_upstream_rollback"
        assert events[-1]["persisted"]["version"] == 3
        assert events[-1]["offered"]["version"] == 2
        assert events[-1]["persisted"]["head"] == bundle_v3["snapshot"]["head"]
        # The refused outer import persisted nothing at all.
        assert downstream.get_upstream_high_water(up_key.key_id) == competitor_state["high_water"]  # type: ignore[union-attr]
        assert downstream.head() == competitor_state["head"]
    finally:
        downstream.close()
        competitor.close()


def test_concurrent_older_with_flag_warns_without_lowering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from csk_registry.bundle import import_bundle

    up_key, down_key, bundle_v1, bundle_v2, bundle_v3 = _upstream_triple(tmp_path)
    downstream = Store(tmp_path / "down.db")
    competitor = Store(tmp_path / "down.db")
    try:
        assert (
            import_bundle(downstream, down_key, bundle_v1, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
            == 1
        )

        def commit_v3_first() -> None:
            assert (
                import_bundle(competitor, down_key, bundle_v3, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
                == 2
            )

        _pause_outer_import_at_write(monkeypatch, downstream, commit_v3_first)
        with caplog.at_level(logging.INFO, logger="csk_registry.audit"):
            count = import_bundle(
                downstream,
                down_key,  # type: ignore[arg-type]
                bundle_v2,
                upstream_public_key=up_key.public_pinned,  # type: ignore[union-attr]
                accept_older_upstream=True,
            )
        # Accepted under override; v2's records were already imported as part
        # of v3, so fingerprint dedup yields zero new rows.
        assert count == 0
        high_water = downstream.get_upstream_high_water(up_key.key_id)  # type: ignore[union-attr]
        assert high_water is not None and high_water.version == 3
        assert high_water.head == bundle_v3["snapshot"]["head"]
        assert downstream.head()[0] == 3
        events = _import_events(caplog)
        assert events and events[-1]["result"] == "ok"
        assert events[-1]["warning"] == "import_upstream_rollback"
        assert events[-1]["accepted_older"] is True
        assert events[-1]["persisted"]["version"] == 3
        assert events[-1]["offered"]["version"] == 2
    finally:
        downstream.close()
        competitor.close()


@pytest.mark.parametrize("accept_older", [False, True])
def test_concurrent_first_imports_with_different_bodies_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    accept_older: bool,
) -> None:
    from csk_registry.bundle import export_bundle, import_bundle

    upstream = Store(tmp_path / "up.db")
    up_key = signing.generate_key()
    upstream.append(
        up_key.sign_record(_body("audited", name="skill-a")),
        created_at="2026-07-07T00:00:00Z",
    )
    bundle_a = export_bundle(upstream, up_key)
    upstream.close()
    fork = Store(tmp_path / "fork.db")
    fork.append(
        up_key.sign_record(
            _body("audited", name="skill-fork", commit="2" * 40, content_sha256="sha256:" + "3f" * 32)
        ),
        created_at="2026-07-07T00:00:00Z",
    )
    bundle_fork = export_bundle(fork, up_key)
    fork.close()
    assert bundle_a["snapshot"]["version"] == bundle_fork["snapshot"]["version"] == 1
    assert bundle_a["snapshot"]["head"] != bundle_fork["snapshot"]["head"]

    downstream = Store(tmp_path / "down.db")
    competitor = Store(tmp_path / "down.db")
    try:
        down_key = signing.generate_key()
        competitor_state: dict[str, object] = {}

        def commit_fork_first() -> None:
            assert import_bundle(competitor, down_key, bundle_fork, upstream_public_key=up_key.public_pinned) == 1
            competitor_state["high_water"] = competitor.get_upstream_high_water(up_key.key_id)
            competitor_state["head"] = competitor.head()

        _pause_outer_import_at_write(monkeypatch, downstream, commit_fork_first)
        with caplog.at_level(logging.INFO, logger="csk_registry.audit"):
            with pytest.raises(ValueError, match="import_upstream_inconsistent") as exc_info:
                import_bundle(
                    downstream,
                    down_key,
                    bundle_a,
                    upstream_public_key=up_key.public_pinned,
                    accept_older_upstream=accept_older,
                )
        message = str(exc_info.value)
        assert up_key.key_id in message
        assert bundle_fork["snapshot"]["head"] in message  # persisted (competitor's v1)
        assert bundle_a["snapshot"]["head"] in message  # offered (outer v1)
        events = _import_events(caplog)
        assert events and events[-1]["result"] == "refused"
        assert events[-1]["diagnostic"] == "import_upstream_inconsistent"
        assert events[-1]["persisted"]["head"] == bundle_fork["snapshot"]["head"]
        assert events[-1]["offered"]["head"] == bundle_a["snapshot"]["head"]
        # Never overridable: the competitor's committed first import stands,
        # byte-identical, and the outer import persisted nothing.
        assert downstream.get_upstream_high_water(up_key.key_id) == competitor_state["high_water"]
        assert downstream.head() == competitor_state["head"]
    finally:
        downstream.close()
        competitor.close()


def test_concurrent_identical_import_is_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from csk_registry import bundle as bundle_module
    from csk_registry.bundle import import_bundle

    up_key, down_key, bundle_v1, bundle_v2, _ = _upstream_triple(tmp_path)
    # Distinct import timestamps: the competitor's committed row carries the
    # second stamp, so any rewrite by the outer import (third stamp) would
    # show up in the row comparison below.
    stamps = iter(
        [
            "2026-07-07T10:00:00Z",  # outer v1 import
            "2026-07-07T11:00:00Z",  # competitor v2 import
            "2026-07-07T12:00:00Z",  # outer v2 import
        ]
    )
    monkeypatch.setattr(bundle_module, "utc_now", lambda: next(stamps))
    downstream = Store(tmp_path / "down.db")
    competitor = Store(tmp_path / "down.db")
    try:
        assert (
            import_bundle(downstream, down_key, bundle_v1, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
            == 1
        )
        competitor_state: dict[str, object] = {}

        def commit_v2_first() -> None:
            assert (
                import_bundle(competitor, down_key, bundle_v2, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
                == 1
            )
            competitor_state["high_water"] = competitor.get_upstream_high_water(up_key.key_id)  # type: ignore[union-attr]
            competitor_state["head"] = competitor.head()

        _pause_outer_import_at_write(monkeypatch, downstream, commit_v2_first)
        with caplog.at_level(logging.INFO, logger="csk_registry.audit"):
            assert (
                import_bundle(downstream, down_key, bundle_v2, upstream_public_key=up_key.public_pinned)  # type: ignore[arg-type,union-attr]
                == 0
            )
        # No-op under competition: the high-water row (including updated_at)
        # and the log are exactly the competitor's committed state.
        assert downstream.get_upstream_high_water(up_key.key_id) == competitor_state["high_water"]  # type: ignore[union-attr]
        assert downstream.head() == competitor_state["head"]
        events = _import_events(caplog)
        assert events and events[-1]["result"] == "noop"
        assert events[-1]["persisted"]["version"] == 2
        assert events[-1]["offered"]["version"] == 2
    finally:
        downstream.close()
        competitor.close()
