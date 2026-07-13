from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from csk_registry import signing
from csk_registry.app import create_app
from csk_registry.auth import Auditor, AuditorTokens
from csk_registry.bundle import import_bundle
from csk_registry.protocol import (
    ProtocolError,
    load_json,
    portable_path,
    validate_record,
    validate_snapshot,
    validate_source_identity,
)
from csk_registry.snapshot import build_snapshot
from csk_registry.store import (
    IdempotencyConflict,
    Store,
    StoreIntegrityError,
)


ROOT_TEXT = os.environ.get("CURATOR_CONFORMANCE_ROOT")
pytestmark = pytest.mark.skipif(not ROOT_TEXT, reason="CURATOR_CONFORMANCE_ROOT is not set")


def _root() -> Path:
    assert ROOT_TEXT is not None
    root = Path(ROOT_TEXT)
    assert (root / "manifest.json").is_file()
    return root


def _json(relative: str) -> Any:
    return json.loads((_root() / relative).read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", _json("vectors/canonical-valid.json") if ROOT_TEXT else [])
def test_ccj_positive_vectors(case: dict[str, Any]) -> None:
    assert signing.canonical_bytes(case["input"]).decode("utf-8") == case["canonical_utf8"]


@pytest.mark.parametrize("case", _json("vectors/canonical-invalid.json") if ROOT_TEXT else [])
def test_ccj_rejection_vectors(case: dict[str, str]) -> None:
    with pytest.raises(ProtocolError):
        load_json(case["input_text"])


@pytest.mark.parametrize("case", _json("vectors/portable-paths.json") if ROOT_TEXT else [])
def test_portable_path_vectors(case: dict[str, Any]) -> None:
    assert portable_path(case["input"]) is case["valid"]


@pytest.mark.parametrize("case", _json("vectors/source-identities.json") if ROOT_TEXT else [])
def test_source_identity_output_vectors(case: dict[str, Any]) -> None:
    identity = case.get("identity")
    if identity is not None:
        assert validate_source_identity(identity) == identity


@pytest.mark.parametrize("case", _json("vectors/identifiers.json") if ROOT_TEXT else [])
def test_identifier_vectors(case: dict[str, Any]) -> None:
    record = dict(_json("expected/registry/record_audited.json"))
    record["name"] = case["input"]
    if case["valid"]:
        assert validate_record(record)["name"] == case["input"]
    else:
        with pytest.raises(ProtocolError):
            validate_record(record)


def test_shared_signed_objects() -> None:
    pinned = (_root() / "expected" / "registry" / "pinned_key.txt").read_text(encoding="utf-8").strip()
    audited = validate_record(_json("expected/registry/record_audited.json"))
    revoked = validate_record(_json("expected/registry/record_revoked.json"))
    forged = validate_record(_json("expected/registry/record_forged.json"))
    wrong_key = validate_record(_json("expected/registry/record_wrong_key_id.json"))
    snapshot = validate_snapshot(_json("expected/registry/snapshot.json"))
    assert signing.verify_signed(pinned, audited)
    assert signing.verify_signed(pinned, revoked)
    assert not signing.verify_signed(pinned, forged)
    assert not signing.verify_signed(pinned, wrong_key)
    assert signing.verify_signed(pinned, snapshot)


def test_shared_bundle_authentication_and_idempotent_import(tmp_path: Path) -> None:
    bundle = _json("expected/registry/bundle.json")
    pinned = (_root() / "expected" / "registry" / "pinned_key.txt").read_text(encoding="utf-8").strip()
    store = Store(tmp_path / "registry.db")
    local_key = signing.generate_key()
    assert import_bundle(store, local_key, bundle, upstream_public_key=pinned) == 2
    assert import_bundle(store, local_key, bundle, upstream_public_key=pinned) == 0
    assert store.verify_chain()


def test_shared_bundle_rejects_tampering_before_mutation(tmp_path: Path) -> None:
    bundle = _json("expected/registry/bundle.json")
    bundle["records"][1]["status"] = "audited"
    pinned = (_root() / "expected" / "registry" / "pinned_key.txt").read_text(encoding="utf-8").strip()
    store = Store(tmp_path / "registry.db")
    with pytest.raises(ValueError):
        import_bundle(store, signing.generate_key(), bundle, upstream_public_key=pinned)
    assert store.head()[0] == 0


def _service_records() -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    vectors = _json("vectors/registry-service.json")
    records = {item["id"]: item["record"] for item in vectors["records"]}
    appended = vectors["pagination"]["append_after_first_page"]
    records[appended["id"]] = appended["record"]
    return records, vectors


def test_shared_service_query_and_artifact_identity_vectors(tmp_path: Path) -> None:
    records, vectors = _service_records()
    store = Store(tmp_path / "registry.db")
    for item in vectors["records"]:
        store.append(item["record"], created_at="2026-07-13T00:00:00Z")

    for case in vectors["query_cases"]:
        query = case["query"]
        if "error" in case:
            with pytest.raises(ValueError):
                store.records_for(**query)
            continue
        found = store.records_for(**query)
        assert [record["audit"]["case"] for record in found] == case["expected_ids"]


def test_shared_service_snapshot_bound_pagination_vector(tmp_path: Path) -> None:
    _, vectors = _service_records()
    store = Store(tmp_path / "registry.db")
    for item in vectors["records"]:
        store.append(item["record"], created_at="2026-07-13T00:00:00Z")
    case = vectors["pagination"]
    boundary = store.snapshot_boundary()
    query = dict(case["query"])
    limit = query.pop("limit")
    first, more = store.records_page(**query, limit=limit, offset=0, max_seq=boundary.log_size)
    assert more
    assert [record["audit"]["case"] for record in first] == case["expected_pages"][0]

    appended = case["append_after_first_page"]
    store.append(appended["record"], created_at="2026-07-13T00:01:00Z")
    remaining, more = store.records_page(
        **query,
        limit=limit,
        offset=len(first),
        max_seq=boundary.log_size,
    )
    assert not more
    assert [record["audit"]["case"] for record in remaining] == case[
        "expected_original_cursor_ids"
    ]
    current = store.records_for(**query)
    assert [record["audit"]["case"] for record in current] == case["expected_new_query_ids"]


@pytest.mark.parametrize(
    "case",
    _json("vectors/registry-service.json")["idempotency_cases"] if ROOT_TEXT else [],
)
def test_shared_service_idempotency_vectors(case: dict[str, Any], tmp_path: Path) -> None:
    records, _ = _service_records()
    store = Store(tmp_path / "registry.db")
    statuses: list[int] = []
    for auditor, body_id in zip(case["auditors"], case["body_ids"], strict=True):
        record = records[body_id]
        digest = hashlib.sha256(signing.canonical_bytes(record)).hexdigest()
        try:
            _, replayed = store.append_idempotent(
                record,
                auditor_id=auditor,
                key=case["key"],
                body_sha256=digest,
                created_at="2026-07-13T00:00:00Z",
                now=1,
                ttl_seconds=86400,
            )
            statuses.append(200 if replayed else 201)
        except IdempotencyConflict:
            statuses.append(409)
    assert statuses == case["statuses"]
    assert store.head()[0] == case["appends"]


def test_shared_service_concurrent_writer_vector(tmp_path: Path) -> None:
    case = next(
        item
        for item in _json("vectors/registry-service.json")["transaction_cases"]
        if item["name"] == "concurrent-writers"
    )
    path = tmp_path / "registry.db"
    Store(path).close()
    key = signing.generate_key()
    count = case["writers"]
    records = [
        key.sign_record(
            {
                "schema_version": 1,
                "name": f"skill-{index}",
                "source_identity": "git.example.com/skills/concurrent",
                "commit": f"{index:040d}",
                "content_sha256": "sha256:" + f"{index:064x}",
                "status": "audited",
                "audit": {},
            }
        )
        for index in range(count)
    ]

    def append(index: int) -> int:
        store = Store(path)
        try:
            return store.append(records[index], created_at="2026-07-13T00:00:00Z").seq
        finally:
            store.close()

    with ThreadPoolExecutor(max_workers=8) as executor:
        sequences = sorted(executor.map(append, range(count)))
    assert sequences == list(range(case["expected_first_seq"], case["expected_last_seq"] + 1))


@pytest.mark.parametrize(
    "case",
    _json("vectors/registry-service.json")["recovery_cases"] if ROOT_TEXT else [],
)
def test_shared_service_recovery_vectors(case: dict[str, Any], tmp_path: Path) -> None:
    path = tmp_path / "registry.db"
    store = Store(path)
    record = _json("expected/registry/record_audited.json")
    store.append(record, created_at="2026-07-13T00:00:00Z")
    store.close()
    mutation = case["mutation"]
    if mutation != "none":
        connection = sqlite3.connect(path)
        connection.execute("PRAGMA foreign_keys=OFF")
        if mutation == "prev_hash":
            connection.execute("UPDATE log SET prev_hash = ?", ("f" * 64,))
        elif mutation == "entry_hash":
            connection.execute("UPDATE log SET entry_hash = ?", ("f" * 64,))
        elif mutation == "sequence_gap":
            connection.execute("UPDATE log SET seq = 2")
        elif mutation == "idempotency_seq":
            connection.execute(
                "INSERT INTO idempotency "
                "(auditor_id, key, body_sha256, response_json, seq, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("auditor", "key", "a" * 64, '{"seq":2,"entry_hash":"' + "f" * 64 + '"}', 2, 999999),
            )
        elif mutation == "import_seq":
            connection.execute(
                "INSERT INTO imported_records (fingerprint, imported_at, seq) VALUES (?, ?, ?)",
                ("a" * 64, "2026-07-13T00:00:00Z", 2),
            )
        elif mutation == "metadata":
            connection.execute("DELETE FROM metadata WHERE key = 'created_at'")
        elif mutation == "schema_table":
            connection.execute("DROP TABLE imported_records")
        connection.commit()
        connection.close()
    if case["ready"]:
        Store(path).close()
    else:
        with pytest.raises(StoreIntegrityError):
            Store(path)


def test_shared_service_snapshot_and_restore_vectors(tmp_path: Path) -> None:
    vectors = _json("vectors/registry-service.json")
    path = tmp_path / "registry.db"
    store = Store(path)
    key = signing.generate_key()
    records = [
        key.sign_record(
            {
                "schema_version": 1,
                "name": f"skill-{index}",
                "source_identity": "git.example.com/skills/restore",
                "commit": f"{index:040d}",
                "content_sha256": "sha256:" + f"{index:064x}",
                "status": "audited",
                "audit": {},
            }
        )
        for index in range(8)
    ]
    for index, record in enumerate(records):
        store.append(record, created_at=f"2026-07-13T00:00:0{index}Z")
    snapshot = build_snapshot(store, key)
    assert snapshot["version"] == snapshot["log_size"]
    assert build_snapshot(store, key) == snapshot
    rotated = build_snapshot(store, signing.generate_key())
    assert {key: value for key, value in snapshot.items() if key != "sig"} == {
        key: value for key, value in rotated.items() if key != "sig"
    }

    checkpoint = store.snapshot_boundary()
    for case in vectors["restore_cases"]:
        candidate_store = Store(tmp_path / f"{case['name']}.db")
        candidate_records = list(records[: case["restored_version"]])
        if case["name"] == "checkpoint-equivocation":
            changed = dict(candidate_records[-1])
            changed["status"] = "revoked"
            candidate_records[-1] = key.sign_record(
                {field: value for field, value in changed.items() if field != "sig"}
            )
        for index, record in enumerate(candidate_records):
            candidate_store.append(record, created_at=f"2026-07-13T00:00:0{index}Z")
        candidate_boundary = candidate_store.snapshot_boundary()
        assert candidate_boundary.version == case["restored_version"]
        assert checkpoint.version == case["checkpoint_version"]
        assert (candidate_boundary.head == checkpoint.head) is case["matching_head"]
        assert candidate_store.checkpoint_matches(checkpoint) is case["ready"]


def _service_http_client(
    tmp_path: Path,
    *,
    network_requests: int = 600,
    auditor_submissions: int = 120,
) -> tuple[TestClient, signing.SigningKey, str]:
    registry_key = signing.generate_key()
    auditor_key = signing.generate_key()
    token = "conformance-token-with-at-least-128-bits"
    auditors = AuditorTokens(
        [
            Auditor(
                auditor_id="conformance-auditor",
                org="Conformance",
                public_pinned=auditor_key.public_pinned,
                token_sha256=hashlib.sha256(token.encode()).hexdigest(),
            )
        ]
    )
    return (
        TestClient(
            create_app(
                store=Store(tmp_path / "http-registry.db"),
                signing_key=registry_key,
                tokens=auditors,
                network_requests_per_minute=network_requests,
                auditor_submissions_per_minute=auditor_submissions,
            )
        ),
        auditor_key,
        token,
    )


def _service_http_record(key: signing.SigningKey) -> dict[str, Any]:
    return key.sign_record(
        {
            "schema_version": 1,
            "name": "transport-case",
            "source_identity": "git.example.com/skills/transport-case",
            "commit": "a" * 40,
            "content_sha256": "sha256:" + "b" * 64,
            "status": "audited",
            "audit": {},
        }
    )


@pytest.mark.parametrize(
    "case",
    _json("vectors/registry-service.json")["transport_cases"] if ROOT_TEXT else [],
)
def test_shared_service_transport_limit_vectors(case: dict[str, Any], tmp_path: Path) -> None:
    client, auditor_key, token = _service_http_client(
        tmp_path,
        network_requests=case.get("configured_requests", 600),
        auditor_submissions=case.get("configured_submissions", 120),
    )
    content_hash = "sha256:" + "b" * 64
    if case["name"] == "network-rate-limit":
        assert client.get("/v1/snapshot").status_code == 200
        response = client.get("/v1/snapshot")
    elif case["name"] == "auditor-rate-limit":
        headers = {"Authorization": f"Bearer {token}"}
        assert client.post(
            "/v1/records", json=_service_http_record(auditor_key), headers=headers
        ).status_code == 201
        response = client.post(
            "/v1/records", json=_service_http_record(auditor_key), headers=headers
        )
    elif "query_limit" in case:
        response = client.get(
            "/v1/records",
            params={"content_sha256": content_hash, "limit": case["query_limit"]},
        )
    elif "cursor_characters" in case:
        response = client.get(
            "/v1/records",
            params={
                "content_sha256": content_hash,
                "cursor": "x" * case["cursor_characters"],
            },
        )
    elif "body_bytes" in case:
        response = client.post(
            "/v1/records",
            content=b"x" * case["body_bytes"],
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
    elif "content_encoding" in case:
        response = client.post(
            "/v1/records",
            content=b"{}",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Content-Encoding": case["content_encoding"],
            },
        )
    else:
        idempotency_key = case.get("idempotency_key") or "x" * case["idempotency_key_characters"]
        response = client.post(
            "/v1/records",
            json=_service_http_record(auditor_key),
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": idempotency_key,
            },
        )
    assert response.status_code == case["status"]
    if "error" in case:
        assert response.json()["error"]["code"] == case["error"]
    if case.get("retry_after"):
        assert int(response.headers["Retry-After"]) >= 1


@pytest.mark.parametrize(
    "case",
    _json("vectors/registry-service.json")["cache_cases"] if ROOT_TEXT else [],
)
def test_shared_service_cache_control_vectors(case: dict[str, Any], tmp_path: Path) -> None:
    client, auditor_key, token = _service_http_client(tmp_path)
    if case["name"] == "public-read":
        response = client.get("/v1/snapshot")
    elif case["name"] == "authenticated-write":
        response = client.post(
            "/v1/records",
            json=_service_http_record(auditor_key),
            headers={"Authorization": f"Bearer {token}"},
        )
    else:
        response = client.get("/v1/records")
    cache_control = response.headers.get("Cache-Control", "")
    assert case["cache_control"] in cache_control
