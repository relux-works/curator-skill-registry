from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

from .signing import canonical_bytes


_SCHEMA = """
CREATE TABLE IF NOT EXISTS log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_hash TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    source_identity TEXT NOT NULL,
    commit_hash TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    status TEXT NOT NULL,
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_log_identity ON log (source_identity, commit_hash);
CREATE INDEX IF NOT EXISTS idx_log_content ON log (content_sha256);
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS imported_records (
    fingerprint TEXT PRIMARY KEY,
    imported_at TEXT NOT NULL,
    seq INTEGER REFERENCES log(seq) ON DELETE RESTRICT
);
"""

_IDEMPOTENCY_SCHEMA = """
CREATE TABLE idempotency (
    auditor_id TEXT NOT NULL,
    key TEXT NOT NULL,
    body_sha256 TEXT NOT NULL,
    response_json TEXT NOT NULL,
    seq INTEGER NOT NULL REFERENCES log(seq) ON DELETE RESTRICT,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (auditor_id, key)
);
CREATE INDEX idx_idempotency_expiry ON idempotency (expires_at);
"""

_GENESIS = "0" * 64
_SCHEMA_VERSION = 2
_OPERATION_DEADLINE_SECONDS = 30.0


@dataclass(frozen=True)
class LogEntry:
    seq: int
    entry_hash: str
    prev_hash: str
    record: dict[str, Any]


@dataclass(frozen=True)
class SnapshotBoundary:
    version: int
    log_size: int
    head: str
    merkle_root: str
    created_at: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "log_size": self.log_size,
            "head": self.head,
            "merkle_root": self.merkle_root,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, value: Any) -> SnapshotBoundary:
        if not isinstance(value, dict) or set(value) != {
            "version",
            "log_size",
            "head",
            "merkle_root",
            "created_at",
        }:
            raise ValueError("snapshot boundary is malformed")
        version = value["version"]
        log_size = value["log_size"]
        head = value["head"]
        merkle_root = value["merkle_root"]
        created_at = value["created_at"]
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or not isinstance(log_size, int)
            or isinstance(log_size, bool)
            or version != log_size
            or version < 0
            or not isinstance(head, str)
            or not _hex256(head)
            or not isinstance(merkle_root, str)
            or not _hex256(merkle_root)
            or not isinstance(created_at, str)
            or not created_at
        ):
            raise ValueError("snapshot boundary is malformed")
        return cls(version, log_size, head, merkle_root, created_at)


class IdempotencyConflict(ValueError):
    pass


class StoreIntegrityError(RuntimeError):
    pass


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        database_existed = path.exists() and path.stat().st_size > 0
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(path),
            check_same_thread=False,
            isolation_level=None,
            timeout=5.0,
        )
        path.chmod(0o600)
        self._conn.row_factory = sqlite3.Row
        try:
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            if not database_existed:
                self._conn.executescript(_SCHEMA)
                self._initialize_creation_metadata()
                self._migrate_imported_records()
                self._migrate_idempotency()
                self._mark_current_schema()
            else:
                user_version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
                if user_version == 0:
                    self._require_legacy_schema()
                    self._conn.executescript(_SCHEMA)
                    self._initialize_creation_metadata()
                    self._migrate_imported_records()
                    self._migrate_idempotency()
                    self._mark_current_schema()
                elif user_version == _SCHEMA_VERSION:
                    self._require_current_schema()
                else:
                    raise StoreIntegrityError(
                        f"unsupported database schema version {user_version}"
                    )
            errors = self.integrity_errors()
        except sqlite3.DatabaseError as exc:
            self.close()
            raise StoreIntegrityError(f"SQLite integrity verification failed: {exc}") from exc
        except StoreIntegrityError:
            self.close()
            raise
        if errors:
            self.close()
            raise StoreIntegrityError("; ".join(errors))

    def _initialize_creation_metadata(self) -> None:
        created = self._conn.execute(
            "SELECT value FROM metadata WHERE key = 'created_at'"
        ).fetchone()
        if created is None:
            first = self._conn.execute(
                "SELECT created_at FROM log ORDER BY seq LIMIT 1"
            ).fetchone()
            created_at = str(first["created_at"]) if first is not None else _utc_now()
        else:
            created_at = str(created["value"])
        with self._write_transaction():
            self._conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES ('created_at', ?)",
                (created_at,),
            )

    def _mark_current_schema(self) -> None:
        with self._write_transaction():
            self._conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', ?)",
                (str(_SCHEMA_VERSION),),
            )
            self._conn.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
            errors = self.integrity_errors()
            if errors:
                raise StoreIntegrityError("; ".join(errors))

    def _require_legacy_schema(self) -> None:
        tables = {
            str(row["name"])
            for row in self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        missing = {"log", "idempotency", "imported_records"} - tables
        if missing:
            raise StoreIntegrityError(
                "legacy database schema is incomplete: missing " + ", ".join(sorted(missing))
            )
        expected_log = {
            "seq",
            "entry_hash",
            "prev_hash",
            "name",
            "source_identity",
            "commit_hash",
            "content_sha256",
            "status",
            "record_json",
            "created_at",
        }
        if self._table_columns("log") != expected_log:
            raise StoreIntegrityError("legacy database schema for log is unsupported")
        if self._table_columns("imported_records") not in {
            frozenset({"fingerprint", "imported_at"}),
            frozenset({"fingerprint", "imported_at", "seq"}),
        }:
            raise StoreIntegrityError(
                "legacy database schema for imported_records is unsupported"
            )
        if self._table_columns("idempotency") not in {
            frozenset({"key", "body_sha256", "response_json", "expires_at"}),
            frozenset(
                {"auditor_id", "key", "body_sha256", "response_json", "expires_at"}
            ),
            frozenset(
                {
                    "auditor_id",
                    "key",
                    "body_sha256",
                    "response_json",
                    "seq",
                    "expires_at",
                }
            ),
        }:
            raise StoreIntegrityError("legacy database schema for idempotency is unsupported")
        if "metadata" in tables:
            if self._table_columns("metadata") != {"key", "value"}:
                raise StoreIntegrityError("legacy database metadata schema is unsupported")
            marker = self._conn.execute(
                "SELECT value FROM metadata WHERE key = 'schema_version'"
            ).fetchone()
            if marker is not None:
                raise StoreIntegrityError(
                    "database schema version markers disagree; restore a verified backup"
                )

    def _require_current_schema(self) -> None:
        required = {
            "log": {
                "seq",
                "entry_hash",
                "prev_hash",
                "name",
                "source_identity",
                "commit_hash",
                "content_sha256",
                "status",
                "record_json",
                "created_at",
            },
            "metadata": {"key", "value"},
            "imported_records": {"fingerprint", "imported_at", "seq"},
            "idempotency": {
                "auditor_id",
                "key",
                "body_sha256",
                "response_json",
                "seq",
                "expires_at",
            },
        }
        for table, expected_columns in required.items():
            if self._table_columns(table) != expected_columns:
                raise StoreIntegrityError(f"database schema for {table} is unsupported")
        for table, expected_primary_key in {
            "log": ["seq"],
            "metadata": ["key"],
            "imported_records": ["fingerprint"],
            "idempotency": ["auditor_id", "key"],
        }.items():
            actual_primary_key = [
                str(row["name"])
                for row in sorted(
                    self._conn.execute(f"PRAGMA table_info({table})"),
                    key=lambda row: int(row["pk"]) if row["pk"] else 1_000_000,
                )
                if row["pk"]
            ]
            if actual_primary_key != expected_primary_key:
                raise StoreIntegrityError(f"database primary key for {table} is malformed")
        for index, expected_index_columns in {
            "idx_log_identity": ["source_identity", "commit_hash"],
            "idx_log_content": ["content_sha256"],
            "idx_idempotency_expiry": ["expires_at"],
        }.items():
            actual = [
                str(row["name"])
                for row in self._conn.execute(f"PRAGMA index_info({index})")
            ]
            if actual != expected_index_columns:
                raise StoreIntegrityError(f"database index {index} is missing or malformed")
        for table in ("imported_records", "idempotency"):
            foreign_keys = {
                (str(row["from"]), str(row["table"]), str(row["to"]), str(row["on_delete"]))
                for row in self._conn.execute(f"PRAGMA foreign_key_list({table})")
            }
            if ("seq", "log", "seq", "RESTRICT") not in foreign_keys:
                raise StoreIntegrityError(f"database foreign key for {table}.seq is missing")
        marker = self._conn.execute(
            "SELECT value FROM metadata WHERE key = 'schema_version'"
        ).fetchone()
        if marker is None or marker["value"] != str(_SCHEMA_VERSION):
            raise StoreIntegrityError("database schema version markers disagree")

    def _table_columns(self, table: str) -> frozenset[str]:
        return frozenset(
            str(row["name"])
            for row in self._conn.execute(f"PRAGMA table_info({table})")
        )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def _write_transaction(self) -> Iterator[None]:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        else:
            self._conn.execute("COMMIT")

    @contextmanager
    def _operation_deadline(self) -> Iterator[None]:
        deadline = time.monotonic() + _OPERATION_DEADLINE_SECONDS

        def interrupted() -> int:
            return int(time.monotonic() >= deadline)

        self._conn.set_progress_handler(interrupted, 1000)
        try:
            yield
        except sqlite3.OperationalError as exc:
            if time.monotonic() >= deadline and "interrupt" in str(exc).lower():
                raise StoreIntegrityError("database operation deadline exceeded") from exc
            raise
        finally:
            self._conn.set_progress_handler(None, 0)

    def _migrate_imported_records(self) -> None:
        columns = {str(row["name"]) for row in self._conn.execute("PRAGMA table_info(imported_records)")}
        if "seq" not in columns:
            self._conn.execute(
                "ALTER TABLE imported_records ADD COLUMN seq INTEGER REFERENCES log(seq) ON DELETE RESTRICT"
            )
        unresolved = self._conn.execute(
            "SELECT fingerprint FROM imported_records WHERE seq IS NULL"
        ).fetchall()
        if not unresolved:
            return
        by_fingerprint: dict[str, int] = {}
        for row in self._conn.execute("SELECT seq, record_json FROM log ORDER BY seq"):
            try:
                record = json.loads(row["record_json"])
            except json.JSONDecodeError as exc:
                raise StoreIntegrityError(
                    f"cannot migrate imported records: log sequence {row['seq']} is invalid"
                ) from exc
            fingerprint = _import_fingerprint(record)
            if fingerprint is not None:
                by_fingerprint[fingerprint] = int(row["seq"])
        with self._write_transaction():
            for row in unresolved:
                fingerprint = str(row["fingerprint"])
                seq = by_fingerprint.get(fingerprint)
                if seq is not None:
                    self._conn.execute(
                        "UPDATE imported_records SET seq = ? WHERE fingerprint = ?",
                        (seq, fingerprint),
                    )

    def _migrate_idempotency(self) -> None:
        table = self._conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'idempotency'"
        ).fetchone()
        if table is None:
            self._conn.executescript(_IDEMPOTENCY_SCHEMA)
            return
        columns = {str(row["name"]) for row in self._conn.execute("PRAGMA table_info(idempotency)")}
        if {"auditor_id", "seq"}.issubset(columns):
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_idempotency_expiry ON idempotency (expires_at)"
            )
            return
        now = int(datetime.now(UTC).timestamp())
        select_columns = "auditor_id, " if "auditor_id" in columns else ""
        legacy = self._conn.execute(
            f"SELECT {select_columns}key, body_sha256, response_json, expires_at "
            "FROM idempotency WHERE expires_at > ?",
            (now,),
        ).fetchall()
        if legacy and "auditor_id" not in columns:
            raise StoreIntegrityError(
                "unexpired legacy idempotency entries have no auditor scope; "
                "stop submissions until they expire before upgrading"
            )
        with self._write_transaction():
            self._conn.execute("ALTER TABLE idempotency RENAME TO idempotency_legacy")
            self._conn.execute(
                "CREATE TABLE idempotency ("
                "auditor_id TEXT NOT NULL, key TEXT NOT NULL, body_sha256 TEXT NOT NULL, "
                "response_json TEXT NOT NULL, "
                "seq INTEGER NOT NULL REFERENCES log(seq) ON DELETE RESTRICT, "
                "expires_at INTEGER NOT NULL, PRIMARY KEY (auditor_id, key))"
            )
            self._conn.execute(
                "CREATE INDEX idx_idempotency_expiry ON idempotency (expires_at)"
            )
            for row in legacy:
                try:
                    response = json.loads(row["response_json"])
                except json.JSONDecodeError as exc:
                    raise StoreIntegrityError(
                        "legacy idempotency response is invalid"
                    ) from exc
                seq = response.get("seq") if isinstance(response, dict) else None
                if not isinstance(seq, int) or isinstance(seq, bool):
                    raise StoreIntegrityError("legacy idempotency response has no sequence")
                self._conn.execute(
                    "INSERT INTO idempotency "
                    "(auditor_id, key, body_sha256, response_json, seq, expires_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        row["auditor_id"],
                        row["key"],
                        row["body_sha256"],
                        row["response_json"],
                        seq,
                        row["expires_at"],
                    ),
                )
            self._conn.execute("DROP TABLE idempotency_legacy")

    def append(self, record: dict[str, Any], *, created_at: str) -> LogEntry:
        with self._lock, self._operation_deadline(), self._write_transaction():
            return self._append_locked(record, created_at=created_at)

    def _append_locked(self, record: dict[str, Any], *, created_at: str) -> LogEntry:
        for key in ("name", "source_identity", "commit", "content_sha256", "status"):
            if not isinstance(record.get(key), str) or not record[key]:
                raise ValueError(f"record requires a non-empty string {key!r}")
        record_bytes = canonical_bytes(record)
        row = self._conn.execute(
            "SELECT seq, entry_hash FROM log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        previous_seq = int(row["seq"]) if row else 0
        prev_hash = str(row["entry_hash"]) if row else _GENESIS
        entry_hash = hashlib.sha256(prev_hash.encode("ascii") + record_bytes).hexdigest()
        cursor = self._conn.execute(
            "INSERT INTO log (entry_hash, prev_hash, name, source_identity, commit_hash, "
            "content_sha256, status, record_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                entry_hash,
                prev_hash,
                record["name"],
                record["source_identity"],
                record["commit"],
                record["content_sha256"],
                record["status"],
                json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                created_at,
            ),
        )
        seq = int(cursor.lastrowid or 0)
        if seq != previous_seq + 1:
            raise StoreIntegrityError("log sequence is not contiguous")
        return LogEntry(seq=seq, entry_hash=entry_hash, prev_hash=prev_hash, record=record)

    def append_idempotent(
        self,
        record: dict[str, Any],
        *,
        auditor_id: str,
        key: str,
        body_sha256: str,
        created_at: str,
        now: int,
        ttl_seconds: int,
    ) -> tuple[dict[str, Any], bool]:
        if not auditor_id:
            raise ValueError("auditor_id must be non-empty")
        if not 1 <= len(key) <= 256 or any(not 0x21 <= ord(character) <= 0x7E for character in key):
            raise ValueError("idempotency key is malformed")
        if not _hex256(body_sha256):
            raise ValueError("idempotency body digest is malformed")
        if ttl_seconds < 24 * 3600:
            raise ValueError("idempotency retention must be at least 24 hours")
        with self._lock, self._operation_deadline(), self._write_transaction():
            self._conn.execute("DELETE FROM idempotency WHERE expires_at <= ?", (now,))
            existing = self._conn.execute(
                "SELECT body_sha256, response_json FROM idempotency "
                "WHERE auditor_id = ? AND key = ?",
                (auditor_id, key),
            ).fetchone()
            if existing is not None:
                if existing["body_sha256"] != body_sha256:
                    raise IdempotencyConflict(
                        "idempotency key was already used for a different body"
                    )
                response = json.loads(existing["response_json"])
                if not isinstance(response, dict):
                    raise StoreIntegrityError("stored idempotency response is invalid")
                return response, True
            entry = self._append_locked(record, created_at=created_at)
            response = {"seq": entry.seq, "entry_hash": entry.entry_hash}
            self._conn.execute(
                "INSERT INTO idempotency "
                "(auditor_id, key, body_sha256, response_json, seq, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    auditor_id,
                    key,
                    body_sha256,
                    json.dumps(response, separators=(",", ":")),
                    entry.seq,
                    now + ttl_seconds,
                ),
            )
            return response, False

    def records_for(
        self,
        *,
        source_identity: str = "",
        commit: str = "",
        content_sha256: str = "",
    ) -> list[dict[str, Any]]:
        records, _ = self.records_page(
            source_identity=source_identity,
            commit=commit,
            content_sha256=content_sha256,
            limit=10_000,
            offset=0,
        )
        return records

    def records_page(
        self,
        *,
        source_identity: str = "",
        commit: str = "",
        content_sha256: str = "",
        limit: int,
        offset: int,
        max_seq: int | None = None,
    ) -> tuple[list[dict[str, Any]], bool]:
        if bool(source_identity) != bool(commit):
            raise ValueError("source_identity and commit must appear together")
        if not ((source_identity and commit) or content_sha256):
            return [], False
        with self._lock, self._operation_deadline():
            boundary = self._snapshot_boundary_locked(max_seq).log_size
            clauses = ["seq <= ?"]
            params: list[Any] = [boundary]
            if source_identity:
                clauses.extend(["source_identity = ?", "commit_hash = ?"])
                params.extend([source_identity, commit])
            if content_sha256:
                clauses.append("content_sha256 = ?")
                params.append(content_sha256)
            query = (
                "SELECT record_json FROM ("
                "SELECT record_json, name, source_identity, commit_hash, content_sha256, seq, "
                "ROW_NUMBER() OVER ("
                "PARTITION BY name, source_identity, commit_hash, content_sha256 "
                "ORDER BY seq DESC"
                ") AS rank FROM log WHERE "
                + " AND ".join(clauses)
                + ") WHERE rank = 1 "
                "ORDER BY name, source_identity, commit_hash, content_sha256 "
                "LIMIT ? OFFSET ?"
            )
            rows = self._conn.execute(query, [*params, limit + 1, offset]).fetchall()
            records = [json.loads(row["record_json"]) for row in rows[:limit]]
            return records, len(rows) > limit

    def log_entries(self, *, since: int = 0, max_seq: int | None = None) -> list[LogEntry]:
        with self._lock, self._operation_deadline():
            boundary = self._snapshot_boundary_locked(max_seq).log_size
            rows = self._conn.execute(
                "SELECT seq, entry_hash, prev_hash, record_json FROM log "
                "WHERE seq > ? AND seq <= ? ORDER BY seq ASC",
                (since, boundary),
            ).fetchall()
            return [_entry_from_row(row) for row in rows]

    def log_page(
        self,
        *,
        since: int,
        limit: int,
        offset: int,
        max_seq: int | None = None,
    ) -> tuple[list[LogEntry], bool]:
        with self._lock, self._operation_deadline():
            boundary = self._snapshot_boundary_locked(max_seq).log_size
            rows = self._conn.execute(
                "SELECT seq, entry_hash, prev_hash, record_json FROM log "
                "WHERE seq > ? AND seq <= ? ORDER BY seq ASC LIMIT ? OFFSET ?",
                (since, boundary, limit + 1, offset),
            ).fetchall()
            return [_entry_from_row(row) for row in rows[:limit]], len(rows) > limit

    def append_imports(
        self, records: list[tuple[str, dict[str, Any]]], *, created_at: str
    ) -> int:
        imported = 0
        with self._lock, self._operation_deadline(), self._write_transaction():
            for fingerprint, record in records:
                exists = self._conn.execute(
                    "SELECT 1 FROM imported_records WHERE fingerprint = ?",
                    (fingerprint,),
                ).fetchone()
                if exists is not None:
                    continue
                entry = self._append_locked(record, created_at=created_at)
                self._conn.execute(
                    "INSERT INTO imported_records (fingerprint, imported_at, seq) "
                    "VALUES (?, ?, ?)",
                    (fingerprint, created_at, entry.seq),
                )
                imported += 1
        return imported

    def head(self) -> tuple[int, str]:
        boundary = self.snapshot_boundary()
        return boundary.log_size, boundary.head

    def snapshot_boundary(self, max_seq: int | None = None) -> SnapshotBoundary:
        with self._lock, self._operation_deadline():
            return self._snapshot_boundary_locked(max_seq)

    def _snapshot_boundary_locked(self, max_seq: int | None) -> SnapshotBoundary:
        head_row = self._conn.execute(
            "SELECT seq FROM log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        current = int(head_row["seq"]) if head_row else 0
        boundary = current if max_seq is None else max_seq
        if boundary < 0 or boundary > current:
            raise ValueError("snapshot boundary is unavailable")
        rows = self._conn.execute(
            "SELECT seq, entry_hash, created_at FROM log WHERE seq <= ? ORDER BY seq",
            (boundary,),
        ).fetchall()
        if len(rows) != boundary or any(
            int(row["seq"]) != index for index, row in enumerate(rows, start=1)
        ):
            raise StoreIntegrityError("log sequence is not contiguous")
        if rows:
            head = str(rows[-1]["entry_hash"])
            created_at = str(rows[-1]["created_at"])
        else:
            head = _GENESIS
            metadata = self._conn.execute(
                "SELECT value FROM metadata WHERE key = 'created_at'"
            ).fetchone()
            if metadata is None:
                raise StoreIntegrityError("service creation metadata is missing")
            created_at = str(metadata["value"])
        merkle_root = _merkle_root([str(row["entry_hash"]) for row in rows])
        return SnapshotBoundary(
            version=boundary,
            log_size=boundary,
            head=head,
            merkle_root=merkle_root,
            created_at=created_at,
        )

    def boundary_available(self, expected: SnapshotBoundary) -> bool:
        try:
            actual = self.snapshot_boundary(expected.log_size)
        except (ValueError, StoreIntegrityError):
            return False
        return actual == expected

    def merkle_root(self, max_seq: int | None = None) -> str:
        return self.snapshot_boundary(max_seq).merkle_root

    def verify_chain(self) -> bool:
        return not self.integrity_errors()

    def integrity_errors(self) -> list[str]:
        with self._lock, self._operation_deadline():
            errors: list[str] = []
            database_integrity = [str(row[0]) for row in self._conn.execute("PRAGMA integrity_check")]
            if database_integrity != ["ok"]:
                errors.extend(f"SQLite integrity check: {message}" for message in database_integrity)
            for row in self._conn.execute("PRAGMA foreign_key_check"):
                errors.append(
                    f"foreign key violation in {row[0]} row {row[1]} referencing {row[2]}"
                )
            metadata = self._conn.execute(
                "SELECT value FROM metadata WHERE key = 'created_at'"
            ).fetchone()
            if metadata is None or not _timestamp(str(metadata["value"])):
                errors.append("service creation metadata is missing or malformed")
            schema_version = self._conn.execute(
                "SELECT value FROM metadata WHERE key = 'schema_version'"
            ).fetchone()
            if schema_version is None or schema_version["value"] != "2":
                errors.append("database schema metadata is missing or malformed")
            previous = _GENESIS
            expected_seq = 1
            log_hashes: dict[int, str] = {}
            for row in self._conn.execute(
                "SELECT seq, entry_hash, prev_hash, name, source_identity, commit_hash, "
                "content_sha256, status, record_json, created_at FROM log ORDER BY seq"
            ):
                seq = int(row["seq"])
                if seq != expected_seq:
                    errors.append(f"log sequence {seq} follows {expected_seq - 1}")
                    expected_seq = seq
                try:
                    record = json.loads(row["record_json"])
                    if not isinstance(record, dict):
                        raise ValueError("record is not an object")
                    encoded = canonical_bytes(record)
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    errors.append(f"log sequence {seq} has invalid record JSON: {exc}")
                    encoded = b""
                    record = {}
                expected_hash = hashlib.sha256(previous.encode("ascii") + encoded).hexdigest()
                if row["prev_hash"] != previous:
                    errors.append(f"log sequence {seq} has wrong previous hash")
                if row["entry_hash"] != expected_hash:
                    errors.append(f"log sequence {seq} has wrong entry hash")
                if not _timestamp(str(row["created_at"])):
                    errors.append(f"log sequence {seq} has malformed creation time")
                for column, field in (
                    ("name", "name"),
                    ("source_identity", "source_identity"),
                    ("commit_hash", "commit"),
                    ("content_sha256", "content_sha256"),
                    ("status", "status"),
                ):
                    if row[column] != record.get(field):
                        errors.append(f"log sequence {seq} has inconsistent {column}")
                previous = str(row["entry_hash"])
                log_hashes[seq] = str(row["entry_hash"])
                expected_seq += 1

            for row in self._conn.execute(
                "SELECT auditor_id, key, body_sha256, response_json, seq, expires_at "
                "FROM idempotency"
            ):
                seq = int(row["seq"])
                try:
                    response = json.loads(row["response_json"])
                except json.JSONDecodeError:
                    response = None
                if (
                    not isinstance(response, dict)
                    or not row["auditor_id"]
                    or not 1 <= len(str(row["key"])) <= 256
                    or any(
                        not 0x21 <= ord(character) <= 0x7E
                        for character in str(row["key"])
                    )
                    or set(response) != {"seq", "entry_hash"}
                    or response.get("seq") != seq
                    or response.get("entry_hash") != log_hashes.get(seq)
                    or not _hex256(str(row["body_sha256"]))
                    or not isinstance(row["expires_at"], int)
                ):
                    errors.append(
                        f"idempotency entry {row['auditor_id']!r}/{row['key']!r} is inconsistent"
                    )

            for row in self._conn.execute(
                "SELECT fingerprint, seq FROM imported_records"
            ):
                if row["seq"] is None:
                    errors.append(f"import fingerprint {row['fingerprint']!r} has no log sequence")
                    continue
                seq = int(row["seq"])
                record_row = self._conn.execute(
                    "SELECT record_json FROM log WHERE seq = ?", (seq,)
                ).fetchone()
                if record_row is None:
                    errors.append(f"import fingerprint {row['fingerprint']!r} is orphaned")
                    continue
                try:
                    record = json.loads(record_row["record_json"])
                except json.JSONDecodeError:
                    record = None
                if _import_fingerprint(record) != row["fingerprint"]:
                    errors.append(f"import fingerprint {row['fingerprint']!r} is inconsistent")
            return errors

    def checkpoint_matches(self, checkpoint: SnapshotBoundary) -> bool:
        try:
            prefix = self.snapshot_boundary(checkpoint.log_size)
        except (ValueError, StoreIntegrityError):
            return False
        return prefix == checkpoint

    def backup_to(self, destination: Path) -> SnapshotBoundary:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise FileExistsError(destination)
        with self._lock:
            target = sqlite3.connect(str(destination))
            try:
                self._conn.backup(target)
            finally:
                target.close()
        backup = Store(destination)
        try:
            return backup.snapshot_boundary()
        finally:
            backup.close()


def _entry_from_row(row: sqlite3.Row) -> LogEntry:
    record = json.loads(row["record_json"])
    if not isinstance(record, dict):
        raise StoreIntegrityError("stored record is not an object")
    return LogEntry(
        seq=int(row["seq"]),
        entry_hash=str(row["entry_hash"]),
        prev_hash=str(row["prev_hash"]),
        record=record,
    )


def _merkle_root(entry_hashes: list[str]) -> str:
    if not entry_hashes:
        return _GENESIS
    level = [bytes.fromhex(value) for value in entry_hashes]
    while len(level) > 1:
        next_level: list[bytes] = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            next_level.append(hashlib.sha256(left + right).digest())
        level = next_level
    return level[0].hex()


def _import_fingerprint(record: Any) -> str | None:
    if not isinstance(record, dict):
        return None
    endorsements = record.get("endorsements")
    if not isinstance(endorsements, list):
        return None
    signature: str | None = None
    for endorsement in endorsements:
        if not isinstance(endorsement, dict) or endorsement.get("endorser") != "upstream-import":
            continue
        envelope = endorsement.get("sig")
        if isinstance(envelope, dict) and isinstance(envelope.get("signature"), str):
            signature = envelope["signature"]
            break
    fields = [
        record.get("source_identity"),
        record.get("commit"),
        record.get("content_sha256"),
        record.get("status"),
        signature,
    ]
    if any(not isinstance(value, str) or not value for value in fields):
        return None
    payload = json.dumps(fields, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _hex256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _timestamp(value: str) -> bool:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return False
    return parsed.isoformat().replace("+00:00", "Z") == value


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
