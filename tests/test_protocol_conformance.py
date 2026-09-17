from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry
from referencing.jsonschema import DRAFT202012

from csk_registry import CHECKPOINT_ENV, HOME_ENV, signing
from csk_registry.app import _encode_cursor, app_from_env, create_app
from csk_registry.auth import Auditor, AuditorTokens
from csk_registry.bundle import import_bundle
from csk_registry.keys import initialize_key, write_private_json
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


def _schema_dir() -> Path:
    path = _root().parent.parent / "schemas" / "v1"
    assert path.is_dir(), f"spec schema dir not found: {path}"
    return path


def _envelope_validator(schema_name: str) -> Draft202012Validator:
    """Draft 2020-12 validator for a v2 envelope with local $ref resolution."""
    schema = json.loads((_schema_dir() / schema_name).read_text(encoding="utf-8"))
    assert schema.get("additionalProperties") is False
    resources = []
    for schema_path in sorted(_schema_dir().glob("*.schema.json")):
        candidate = json.loads(schema_path.read_text(encoding="utf-8"))
        resources.append((candidate["$id"], DRAFT202012.create_resource(candidate)))
    return Draft202012Validator(schema, registry=Registry().with_resources(resources))


def _assert_valid_envelope(schema_name: str, envelope: Any) -> None:
    _envelope_validator(schema_name).validate(envelope)


def _assert_invalid_envelope(schema_name: str, envelope: Any) -> None:
    with pytest.raises(ValidationError):
        _envelope_validator(schema_name).validate(envelope)


@pytest.mark.parametrize(
    "schema_name",
    [
        "records-response-v2.schema.json",
        "log-response-v2.schema.json",
    ],
)
def test_shared_service_page_envelope_schema_cases(schema_name: str) -> None:
    validator = _envelope_validator(schema_name)
    index = json.loads((_root() / "schema-cases" / "index.json").read_text(encoding="utf-8"))
    cases = [entry for entry in index if entry["schema"] == schema_name]
    assert cases, f"no schema-cases registered for {schema_name}"
    for entry in cases:
        instance = json.loads(
            (_root() / "schema-cases" / entry["instance"]).read_text(encoding="utf-8")
        )
        if entry["valid"]:
            validator.validate(instance)
        else:
            with pytest.raises(ValidationError):
                validator.validate(instance)


def test_shared_service_log_harness_rejects_malformed_entry_hash(tmp_path: Path) -> None:
    """A served log envelope with a non-hex entry_hash fails the real schema."""
    registry_key = signing.generate_key()
    store = Store(tmp_path / "bad-hash-registry.db")
    store.append(
        registry_key.sign_record(
            {
                "schema_version": 1,
                "name": "hash-case",
                "source_identity": "git.example.com/skills/hash-case",
                "commit": "c" * 40,
                "content_sha256": "sha256:" + "d" * 64,
                "status": "audited",
                "audit": {},
            }
        ),
        created_at="2026-07-13T00:00:00Z",
    )
    client = TestClient(
        create_app(store=store, signing_key=registry_key, tokens=AuditorTokens([]))
    )
    served = client.get("/v1/log", params={"since": 0, "limit": 100}).json()
    _assert_valid_envelope("log-response-v2.schema.json", served)
    mutated = json.loads(json.dumps(served))
    mutated["entries"][0]["entry_hash"] = "invalid"
    _assert_invalid_envelope("log-response-v2.schema.json", mutated)


def test_shared_service_page_boundary_vectors(tmp_path: Path) -> None:
    vectors = _json("vectors/registry-service.json")
    pagination = vectors["pagination"]
    assert pagination["boundary_emitted_on_every_page"] is True
    assert pagination["chain_boundary_byte_identical"] is True
    records_schema = "records-response-v2.schema.json"
    log_schema = "log-response-v2.schema.json"

    registry_key = signing.generate_key()
    store = Store(tmp_path / "boundary-registry.db")
    # Sign the shared vector bodies so served log entries validate as
    # audit-record-v1; the audit case markers the vectors assert on survive.
    for item in vectors["records"]:
        store.append(
            registry_key.sign_record(dict(item["record"])),
            created_at="2026-07-13T00:00:00Z",
        )
    client = TestClient(
        create_app(store=store, signing_key=registry_key, tokens=AuditorTokens([]))
    )

    query = dict(pagination["query"])
    first_response = client.get("/v1/records", params=query)
    assert first_response.status_code == 200
    first = first_response.json()
    _assert_valid_envelope(records_schema, first)
    assert [record["audit"]["case"] for record in first["records"]] == pagination[
        "expected_pages"
    ][0]
    assert first["boundary"]["log_size"] == pagination["boundary_log_size"]
    assert signing.verify_signed(registry_key.public_pinned, first["boundary"])
    assert first["boundary"] == client.get("/v1/snapshot").json()
    chain_boundary = signing.canonical_document_bytes(first["boundary"])

    appended = pagination["append_after_first_page"]
    store.append(
        registry_key.sign_record(dict(appended["record"])),
        created_at="2026-07-13T00:01:00Z",
    )

    assert isinstance(first["next_cursor"], str) and first["next_cursor"]
    second_response = client.get(
        "/v1/records", params={**query, "cursor": first["next_cursor"]}
    )
    assert second_response.status_code == 200
    second = second_response.json()
    _assert_valid_envelope(records_schema, second)
    assert [record["audit"]["case"] for record in second["records"]] == pagination[
        "expected_original_cursor_ids"
    ]
    assert second["next_cursor"] is None
    assert signing.verify_signed(registry_key.public_pinned, second["boundary"])
    assert signing.canonical_document_bytes(second["boundary"]) == chain_boundary

    fresh = client.get(
        "/v1/records",
        params={"content_sha256": query["content_sha256"], "limit": 100},
    ).json()
    _assert_valid_envelope(records_schema, fresh)
    assert [record["audit"]["case"] for record in fresh["records"]] == pagination[
        "expected_new_query_ids"
    ]
    assert fresh["next_cursor"] is None
    assert signing.verify_signed(registry_key.public_pinned, fresh["boundary"])
    assert fresh["boundary"] == client.get("/v1/snapshot").json()
    assert signing.canonical_document_bytes(fresh["boundary"]) != chain_boundary

    log_first = client.get("/v1/log", params={"since": 0, "limit": 2}).json()
    _assert_valid_envelope(log_schema, log_first)
    assert signing.verify_signed(registry_key.public_pinned, log_first["boundary"])
    assert log_first["boundary"] == client.get("/v1/snapshot").json()
    log_chain = signing.canonical_document_bytes(log_first["boundary"])
    entries = list(log_first["entries"])
    body = log_first
    while body["next_cursor"] is not None:
        body = client.get(
            "/v1/log",
            params={"since": 0, "limit": 2, "cursor": body["next_cursor"]},
        ).json()
        _assert_valid_envelope(log_schema, body)
        assert signing.verify_signed(registry_key.public_pinned, body["boundary"])
        assert signing.canonical_document_bytes(body["boundary"]) == log_chain
        entries.extend(body["entries"])
    assert [entry["seq"] for entry in entries] == [1, 2, 3, 4, 5]


def _resign_cursor_envelope(
    key: signing.SigningKey, cursor: str, **overrides: Any
) -> str:
    """Re-sign a cursor envelope after tweaking its payload (test forgery).

    The envelope signature is genuine, so a refusal proves the service
    rejected the tampered payload itself (here: the expiry).
    """
    payload_text = cursor.split(".", 1)[0]
    payload = json.loads(
        base64.urlsafe_b64decode(payload_text + "=" * (-len(payload_text) % 4))
    )
    payload.update(overrides)
    raw = signing.canonical_document_bytes(payload)

    def _url64(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    return f"{_url64(raw)}.{_url64(base64.b64decode(key.sign(raw)))}"


def _flip_boundary_hex(value: str) -> str:
    return "00" * 32 if value != "00" * 32 else "ff" * 32


def test_shared_service_cursor_boundary_cases(tmp_path: Path) -> None:
    vectors = _json("vectors/registry-service.json")
    pagination = vectors["pagination"]
    assert pagination["cursor_boundary_cases"], "no cursor_boundary_cases vectors"

    registry_key = signing.generate_key()
    store = Store(tmp_path / "cursor-boundary-registry.db")
    for item in vectors["records"]:
        store.append(
            registry_key.sign_record(dict(item["record"])),
            created_at="2026-07-13T00:00:00Z",
        )
    client = TestClient(
        create_app(store=store, signing_key=registry_key, tokens=AuditorTokens([]))
    )

    query = dict(pagination["query"])
    first = client.get("/v1/records", params=query)
    assert first.status_code == 200
    first_body = first.json()
    assert isinstance(first_body["next_cursor"], str) and first_body["next_cursor"]
    chain = signing.canonical_document_bytes(first_body["boundary"])
    records_query = {
        "source_identity": "",
        "commit": "",
        "content_sha256": query["content_sha256"],
        "limit": query["limit"],
    }

    # The chain is not re-evaluated after an append: reuse the shared
    # append_after_first_page flow as the control for every boundary case.
    appended = pagination["append_after_first_page"]
    store.append(
        registry_key.sign_record(dict(appended["record"])),
        created_at="2026-07-13T00:01:00Z",
    )
    assert client.get("/v1/snapshot").json()["log_size"] == (
        first_body["boundary"]["log_size"] + 1
    )

    for case in pagination["cursor_boundary_cases"]:
        assert case["name"] == "cursor-boundary-disagreement"
        assert case["reevaluate_at_newer_boundary"] is False
        # Control: the original cursor still serves the ORIGINAL boundary.
        continued = client.get(
            "/v1/records", params={**query, "cursor": first_body["next_cursor"]}
        )
        assert continued.status_code == 200
        assert [record["audit"]["case"] for record in continued.json()["records"]] == (
            pagination["expected_original_cursor_ids"]
        )
        assert signing.canonical_document_bytes(continued.json()["boundary"]) == chain
        # Disagreement: a carried boundary whose body differs from the store,
        # genuinely re-signed with the service key, is refused on /v1/records.
        forged = dict(first_body["boundary"])
        forged["head"] = _flip_boundary_hex(forged["head"])
        signed_forged = registry_key.sign_record(forged)
        assert signing.verify_signed(registry_key.public_pinned, signed_forged)
        bad_cursor = _encode_cursor(
            registry_key,
            endpoint="records",
            query=records_query,
            boundary_snapshot=signed_forged,
            offset=1,
        )
        refused = client.get("/v1/records", params={**query, "cursor": bad_cursor})
        assert refused.status_code == case["status"] == 404
        assert refused.json()["error"]["code"] == case["error"] == "invalid_cursor"
        # Same refusal on /v1/log, via the Merkle root this time.
        log_first = client.get("/v1/log", params={"since": 0, "limit": 2}).json()
        forged_log = dict(log_first["boundary"])
        forged_log["merkle_root"] = _flip_boundary_hex(forged_log["merkle_root"])
        signed_log = registry_key.sign_record(forged_log)
        assert signing.verify_signed(registry_key.public_pinned, signed_log)
        bad_log = _encode_cursor(
            registry_key,
            endpoint="log",
            query={"since": 0, "limit": 2},
            boundary_snapshot=signed_log,
            offset=1,
        )
        refused_log = client.get(
            "/v1/log", params={"since": 0, "limit": 2, "cursor": bad_log}
        )
        assert refused_log.status_code == case["status"] == 404
        assert refused_log.json()["error"]["code"] == case["error"] == "invalid_cursor"


def test_shared_service_cursor_rejections(tmp_path: Path) -> None:
    vectors = _json("vectors/registry-service.json")
    pagination = vectors["pagination"]
    assert set(pagination["cursor_rejections"]) == {
        "changed_query",
        "changed_limit",
        "wrong_endpoint",
        "expired",
        "unavailable_snapshot",
    }
    assert pagination["invalid_cursor_status"] == 404

    registry_key = signing.generate_key()
    store = Store(tmp_path / "cursor-rejections-registry.db")
    for item in vectors["records"]:
        store.append(
            registry_key.sign_record(dict(item["record"])),
            created_at="2026-07-13T00:00:00Z",
        )
    client = TestClient(
        create_app(store=store, signing_key=registry_key, tokens=AuditorTokens([]))
    )
    query = dict(pagination["query"])
    records_first = client.get("/v1/records", params=query).json()
    log_first = client.get("/v1/log", params={"since": 0, "limit": 2}).json()
    records_cursor = records_first["next_cursor"]
    log_cursor = log_first["next_cursor"]
    assert isinstance(records_cursor, str) and records_cursor
    assert isinstance(log_cursor, str) and log_cursor

    def _refused(response: Any) -> None:
        assert response.status_code == pagination["invalid_cursor_status"]
        assert response.json()["error"]["code"] == "invalid_cursor"

    # changed_query: the same cursor under different filters.
    _refused(
        client.get(
            "/v1/records",
            params={
                "content_sha256": "sha256:" + "00" * 32,
                "limit": query["limit"],
                "cursor": records_cursor,
            },
        )
    )
    _refused(
        client.get(
            "/v1/log", params={"since": 1, "limit": 2, "cursor": log_cursor}
        )
    )
    # changed_limit: the same cursor under a different page size.
    _refused(
        client.get(
            "/v1/records",
            params={**query, "limit": query["limit"] + 1, "cursor": records_cursor},
        )
    )
    _refused(
        client.get(
            "/v1/log", params={"since": 0, "limit": 3, "cursor": log_cursor}
        )
    )
    # wrong_endpoint: cursors do not cross endpoints.
    _refused(
        client.get(
            "/v1/log", params={"since": 0, "limit": 2, "cursor": records_cursor}
        )
    )
    _refused(client.get("/v1/records", params={**query, "cursor": log_cursor}))
    # expired: genuinely re-signed envelope with a past expiry.
    _refused(
        client.get(
            "/v1/records",
            params={
                **query,
                "cursor": _resign_cursor_envelope(
                    registry_key, records_cursor, expires_at=1
                ),
            },
        )
    )
    _refused(
        client.get(
            "/v1/log",
            params={
                "since": 0,
                "limit": 2,
                "cursor": _resign_cursor_envelope(registry_key, log_cursor, expires_at=1),
            },
        )
    )
    # unavailable_snapshot: a carried boundary past the committed head.
    future = dict(records_first["boundary"])
    future["version"] = future["log_size"] = future["log_size"] + 5
    signed_future = registry_key.sign_record(future)
    assert signing.verify_signed(registry_key.public_pinned, signed_future)
    _refused(
        client.get(
            "/v1/records",
            params={
                **query,
                "cursor": _encode_cursor(
                    registry_key,
                    endpoint="records",
                    query={
                        "source_identity": "",
                        "commit": "",
                        "content_sha256": query["content_sha256"],
                        "limit": query["limit"],
                    },
                    boundary_snapshot=signed_future,
                    offset=1,
                ),
            },
        )
    )
    log_future = dict(log_first["boundary"])
    log_future["version"] = log_future["log_size"] = log_future["log_size"] + 5
    signed_log_future = registry_key.sign_record(log_future)
    assert signing.verify_signed(registry_key.public_pinned, signed_log_future)
    _refused(
        client.get(
            "/v1/log",
            params={
                "since": 0,
                "limit": 2,
                "cursor": _encode_cursor(
                    registry_key,
                    endpoint="log",
                    query={"since": 0, "limit": 2},
                    boundary_snapshot=signed_log_future,
                    offset=1,
                ),
            },
        )
    )


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


def _checkpoint_record(key: signing.SigningKey, lineage: str, index: int) -> dict[str, Any]:
    return key.sign_record(
        {
            "schema_version": 1,
            "name": f"skill-{lineage}-{index}",
            "source_identity": "git.example.com/skills/checkpoint",
            "commit": f"{index:040d}",
            "content_sha256": "sha256:" + f"{index:064x}",
            "status": "audited",
            "audit": {"lineage": lineage},
        }
    )


def _append_checkpoint_record(store: Store, key: signing.SigningKey, lineage: str, index: int) -> None:
    store.append(
        _checkpoint_record(key, lineage, index),
        created_at=f"2026-07-13T00:00:{index:02d}Z",
    )


def _run_startup_checkpoint_case(
    workdir: Path,
    case: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Drive one ``checkpoint_cases`` vector through the real startup path."""
    name = case["name"]
    live_version = case["live_version"]
    checkpoint_version = case["checkpoint_version"]
    home = workdir / "home"
    home.mkdir(parents=True, exist_ok=True)
    registry_key = initialize_key(home)
    auditor_key = signing.generate_key()
    token = "startup-checkpoint-conformance-token"
    write_private_json(
        home / "auditors.json",
        {
            "auditors": [
                {
                    "auditor_id": "checkpoint-auditor",
                    "org": "Conformance",
                    "public_key": auditor_key.public_pinned,
                    "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                }
            ]
        },
    )
    live = Store(home / "registry.db")
    scratch = Store(workdir / "scratch.db")
    checkpoint_snapshot: dict[str, Any] | None = None
    if name == "checkpoint-below-live-consistent":
        for index in range(checkpoint_version):
            _append_checkpoint_record(live, registry_key, "A", index)
        checkpoint_snapshot = build_snapshot(live, registry_key)
        for index in range(checkpoint_version, live_version):
            _append_checkpoint_record(live, registry_key, "A", index)
    elif name == "checkpoint-equal-consistent":
        for index in range(live_version):
            _append_checkpoint_record(live, registry_key, "A", index)
        checkpoint_snapshot = build_snapshot(live, registry_key)
    elif name == "checkpoint-equal-inconsistent":
        for index in range(live_version):
            _append_checkpoint_record(live, registry_key, "A", index)
        for index in range(checkpoint_version):
            _append_checkpoint_record(scratch, registry_key, "B", index)
        checkpoint_snapshot = build_snapshot(scratch, registry_key)
    elif name == "live-below-checkpoint":
        for index in range(checkpoint_version):
            _append_checkpoint_record(scratch, registry_key, "A", index)
        checkpoint_snapshot = build_snapshot(scratch, registry_key)
        for index in range(live_version):
            _append_checkpoint_record(live, registry_key, "A", index)
    elif name == "live-above-prefix-mismatch":
        for index in range(checkpoint_version):
            _append_checkpoint_record(scratch, registry_key, "B", index)
        checkpoint_snapshot = build_snapshot(scratch, registry_key)
        for index in range(live_version):
            _append_checkpoint_record(live, registry_key, "A", index)
    elif name == "checkpoint-signature-invalid":
        for index in range(live_version):
            _append_checkpoint_record(live, registry_key, "A", index)
        checkpoint_snapshot = build_snapshot(live, signing.generate_key())
    elif name == "checkpoint-not-configured":
        for index in range(live_version):
            _append_checkpoint_record(live, registry_key, "A", index)
    else:
        raise AssertionError(f"unknown checkpoint case {name!r}")

    # The constructed inputs reproduce the vector's discriminating predicates.
    assert live.head()[0] == live_version
    live_boundary = live.snapshot_boundary()
    if checkpoint_snapshot is not None:
        assert checkpoint_snapshot["version"] == checkpoint_version
        assert checkpoint_snapshot["log_size"] == checkpoint_version
        assert (
            signing.verify_signed(registry_key.public_pinned, checkpoint_snapshot)
            is case["signature_valid"]
        )
        if live_version == checkpoint_version:
            same_body = (
                live_boundary.head == checkpoint_snapshot["head"]
                and live_boundary.merkle_root == checkpoint_snapshot["merkle_root"]
                and live_boundary.log_size == checkpoint_snapshot["log_size"]
            )
            assert same_body is case["same_boundary_body"]
        if live_version > checkpoint_version:
            prefix = live.snapshot_boundary(checkpoint_version)
            reproduced = (
                prefix.head == checkpoint_snapshot["head"]
                and prefix.merkle_root == checkpoint_snapshot["merkle_root"]
            )
            assert reproduced is case["prefix_reproduced"]

    checkpoint_path = workdir / "checkpoint.json"
    if case["checkpoint_configured"]:
        assert checkpoint_snapshot is not None
        checkpoint_path.write_text(json.dumps(checkpoint_snapshot), encoding="utf-8")
    live.close()
    scratch.close()

    monkeypatch.setenv(HOME_ENV, str(home))
    if case["checkpoint_configured"]:
        monkeypatch.setenv(CHECKPOINT_ENV, str(checkpoint_path))
    else:
        monkeypatch.delenv(CHECKPOINT_ENV, raising=False)
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="csk_registry.audit"):
        app = app_from_env()
    client = TestClient(app)

    health = client.get("/health")
    if case["ready"]:
        assert health.status_code == 200
        assert health.json() == {"status": "ok"}
    else:
        assert health.status_code == 503
        assert health.json()["error"]["code"] == case["diagnostic"]

    # Writes follow readiness through the common integrity path.
    submission = auditor_key.sign_record(
        {
            "schema_version": 1,
            "name": "skill-submit-0",
            "source_identity": "git.example.com/skills/checkpoint",
            "commit": f"{99:040d}",
            "content_sha256": "sha256:" + f"{99:064x}",
            "status": "audited",
            "audit": {},
        }
    )
    posted = client.post(
        "/v1/records", json=submission, headers={"Authorization": f"Bearer {token}"}
    )
    if case["ready"]:
        assert posted.status_code == 201
    else:
        assert posted.status_code == 503
        assert posted.json()["error"]["code"] == "storage_unavailable"

    startup_events = []
    for record in caplog.records:
        try:
            payload = json.loads(record.getMessage())
        except (TypeError, ValueError):
            continue
        if isinstance(payload, dict) and payload.get("event") == "startup_checkpoint":
            startup_events.append(payload)
    assert len(startup_events) == 1
    event = startup_events[0]
    if not case["checkpoint_configured"]:
        assert event["configured"] is False
        assert event["posture"] == case["posture"] == "checkpoint_not_configured"
    else:
        assert checkpoint_snapshot is not None
        assert event["configured"] is True
        assert event["checkpoint"]["version"] == checkpoint_version
        assert event["checkpoint"]["log_size"] == checkpoint_version
        assert event["checkpoint"]["head"] == checkpoint_snapshot["head"]
        assert event["live"]["version"] == live_version
        assert event["live"]["log_size"] == live_version
        assert event["live"]["head"] == live_boundary.head
        if case["ready"]:
            assert event["result"] == "ok"
            assert "diagnostic" not in event
        else:
            assert event["result"] == "refused"
            assert event["diagnostic"] == case["diagnostic"]

    if not case["ready"]:
        # A refusal never truncates or repairs history: the store alone
        # still verifies and reports ready without the checkpoint.
        reopened = Store(home / "registry.db")
        try:
            assert reopened.head()[0] == live_version
            assert reopened.health_verdict().ready
        finally:
            reopened.close()


def test_shared_service_startup_checkpoint_cases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    cases = _json("vectors/registry-service.json")["checkpoint_cases"]
    assert {case["name"] for case in cases} == {
        "checkpoint-below-live-consistent",
        "checkpoint-equal-consistent",
        "checkpoint-equal-inconsistent",
        "live-below-checkpoint",
        "live-above-prefix-mismatch",
        "checkpoint-signature-invalid",
        "checkpoint-not-configured",
    }
    for case in cases:
        _run_startup_checkpoint_case(tmp_path / case["name"], case, monkeypatch, caplog)


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
