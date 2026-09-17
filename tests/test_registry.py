from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import sqlite3
import subprocess
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from csk_registry import (
    COMMAND_NAME,
    HOME_ENV,
    LEGACY_COMMAND_NAME,
    LEGACY_HOME_ENV,
    home_from_env,
    signing,
)
from csk_registry.app import _encode_cursor, create_app
from csk_registry.auth import Auditor, AuditorTokens
from csk_registry.cli import build_parser, main
from csk_registry.keys import load_active_key, public_keys
from csk_registry.permissions import (
    private_directory_permissions_enforced,
    private_file_permissions_enforced,
    protect_private_directory,
    protect_private_file,
)
from csk_registry.protocol import ProtocolError, portable_path, validate_record, validate_source_identity
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
