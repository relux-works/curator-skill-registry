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
from csk_registry.app import create_app
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
from csk_registry.store import SnapshotBoundary, Store, StoreIntegrityError


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
