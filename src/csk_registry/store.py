from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator, NoReturn

from .checkpoint import REFUSAL_DIAGNOSTICS, CheckpointView, compare_checkpoint
from .permissions import protect_private_file
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
CREATE TABLE IF NOT EXISTS boundaries (
    log_size INTEGER PRIMARY KEY,
    head TEXT NOT NULL,
    merkle_root TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS merkle_frontier (
    level INTEGER PRIMARY KEY,
    len INTEGER NOT NULL,
    tail TEXT NOT NULL
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
_SCHEMA_VERSION = 3
_SCHEMA_VERSION_V2 = 2
_OPERATION_DEADLINE_SECONDS = 30.0

#: Default seconds between background full-verification passes. Probes served
#: from the cached verdict stay cheap no matter how large the log grows.
DEFAULT_HEALTH_VERIFY_INTERVAL_SECONDS = 300.0
#: A cached verdict goes stale (non-ready) when no verification pass has
#: completed within this multiple of the verify interval, so a hung verifier
#: can never leave a green verdict forever.
HEALTH_STALENESS_MULTIPLIER = 2.0
_VERIFIER_JOIN_TIMEOUT_SECONDS = 10.0
_HEALTH_LOG_ERROR_PREVIEW_CHARS = 500

_AUDIT_LOG = logging.getLogger("csk_registry.audit")


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


@dataclass(frozen=True)
class HealthVerdict:
    """Cached integrity verdict served by ``GET /health``.

    The verdict is established by the startup §5 verification, refreshed by
    the background full verifier, and advanced incrementally by appends. It
    performs no hashing or I/O to read: ``ready`` is a pure function of the
    stored fields plus the staleness bound evaluated at read time.
    ``code`` is the ``503`` error code served while non-ready: ``not_ready``
    for integrity failures, or the §6 refusal diagnostic when a startup
    checkpoint comparison refused.
    """

    ready: bool
    verified_head: str
    verified_log_size: int
    verified_at: str
    error: str | None
    code: str = "not_ready"


@dataclass(frozen=True)
class _WalkedLeaf:
    seq: int
    entry_hash: str
    created_at: str


class IdempotencyConflict(ValueError):
    pass


class CursorBoundaryMismatch(ValueError):
    """A page was requested at a boundary the store disagrees with."""


class StoreIntegrityError(RuntimeError):
    pass


class Store:
    def __init__(self, path: Path, *, health_verify_interval: float = DEFAULT_HEALTH_VERIFY_INTERVAL_SECONDS) -> None:
        if (
            isinstance(health_verify_interval, bool)
            or not isinstance(health_verify_interval, (int, float))
            or not math.isfinite(float(health_verify_interval))
            or float(health_verify_interval) <= 0
        ):
            raise ValueError("health_verify_interval must be a positive finite number of seconds")
        self.path = path
        self._health_verify_interval = float(health_verify_interval)
        # Fail-closed defaults: the verdict becomes ready only after the
        # startup §5 verification below passes. Initialized first so the
        # ``close()`` calls on the failure paths always find them.
        self._health_ready = False
        self._health_verified_head = _GENESIS
        self._health_verified_log_size = 0
        self._health_verified_at = ""
        self._health_error: str | None = "startup verification has not completed"
        self._health_code = "not_ready"
        self._health_last_refresh_monotonic = time.monotonic()
        self._integrity_failed = False
        self._verifier_lock = threading.Lock()
        self._verifier_thread: threading.Thread | None = None
        self._verifier_stop = threading.Event()
        path.parent.mkdir(parents=True, exist_ok=True)
        database_existed = path.exists() and path.stat().st_size > 0
        _prepare_private_database_file(path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(path),
            check_same_thread=False,
            isolation_level=None,
            timeout=5.0,
        )
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
                elif user_version == _SCHEMA_VERSION_V2:
                    self._require_v2_schema()
                    self._migrate_v2_to_v3()
                    self._require_current_schema()
                else:
                    raise StoreIntegrityError(
                        f"unsupported database schema version {user_version}"
                    )
            _protect_sqlite_sidecars(path)
            errors = self.integrity_errors()
            if not errors:
                self._ensure_boundaries()
        except sqlite3.DatabaseError as exc:
            self.close()
            raise StoreIntegrityError(f"SQLite integrity verification failed: {exc}") from exc
        except (OSError, ValueError):
            self.close()
            raise
        except StoreIntegrityError:
            self.close()
            raise
        if errors:
            self.close()
            raise StoreIntegrityError("; ".join(errors))
        # The first cached verdict is the startup verification result, so a
        # freshly started service is ready immediately after §5 passes. The
        # O(1) memoized boundary read performs no chain walk.
        try:
            log_size, head = self.head()
        except Exception:
            self.close()
            raise
        with self._lock:
            self._health_ready = True
            self._health_verified_head = head
            self._health_verified_log_size = log_size
            self._health_verified_at = _utc_now()
            self._health_error = None
            self._health_last_refresh_monotonic = time.monotonic()

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
            "boundaries": {"log_size", "head", "merkle_root", "created_at"},
            "merkle_frontier": {"level", "len", "tail"},
        }
        for table, expected_columns in required.items():
            if self._table_columns(table) != expected_columns:
                raise StoreIntegrityError(f"database schema for {table} is unsupported")
        for table, expected_primary_key in {
            "log": ["seq"],
            "metadata": ["key"],
            "imported_records": ["fingerprint"],
            "idempotency": ["auditor_id", "key"],
            "boundaries": ["log_size"],
            "merkle_frontier": ["level"],
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

    def _require_v2_schema(self) -> None:
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
        marker = self._conn.execute(
            "SELECT value FROM metadata WHERE key = 'schema_version'"
        ).fetchone()
        if marker is None or marker["value"] != str(_SCHEMA_VERSION_V2):
            raise StoreIntegrityError("database schema version markers disagree")

    def _migrate_v2_to_v3(self) -> None:
        with self._write_transaction():
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS boundaries ("
                "log_size INTEGER PRIMARY KEY, head TEXT NOT NULL, "
                "merkle_root TEXT NOT NULL, created_at TEXT NOT NULL)"
            )
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS merkle_frontier ("
                "level INTEGER PRIMARY KEY, len INTEGER NOT NULL, tail TEXT NOT NULL)"
            )
            self._conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', ?)",
                (str(_SCHEMA_VERSION),),
            )
            self._conn.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")

    def _table_columns(self, table: str) -> frozenset[str]:
        return frozenset(
            str(row["name"])
            for row in self._conn.execute(f"PRAGMA table_info({table})")
        )

    def close(self) -> None:
        # Stop the verifier before closing the connection, and never while
        # holding ``self._lock``: an in-flight refresh publishes under that
        # lock, so joining under it could deadlock until the join times out.
        self.stop_health_verifier()
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

    def _require_writes_allowed(self) -> None:
        """Refuse writes when the cached verdict is failed or stale.

        This is the runtime half of the §5 rule ("a mismatch in authoritative
        state fails readiness and disables writes"): the same
        :class:`StoreIntegrityError` the startup mismatch raises, so the app
        layer maps it to ``503`` exactly like a startup failure. The check is
        O(1) — field reads plus one clock call, no hashing or I/O.
        """
        with self._lock:
            if self._integrity_failed or not self._health_ready:
                raise StoreIntegrityError(
                    "registry integrity verification failed; restart to re-verify"
                )
            if self._health_stale_locked(time.monotonic()):
                raise StoreIntegrityError("registry integrity verification is stale")

    def _latch_integrity_failure_locked(self, error: str) -> None:
        """Latch non-ready + writes-disabled (call with ``self._lock`` held).

        Common integrity-failure path for append-time anchor mismatches: flips
        ``/health`` to ``503``, refuses further writes via
        :meth:`_require_writes_allowed`, and emits a ``health_refresh`` audit
        event with ``result="integrity_failed"``. Only a restart (which
        re-verifies from scratch) clears it. Idempotent: the first error wins.
        """
        if self._integrity_failed:
            return
        self._integrity_failed = True
        self._health_ready = False
        self._health_error = error
        self._health_last_refresh_monotonic = time.monotonic()
        self._log_health_refresh(
            result="integrity_failed",
            duration_ms=0.0,
            log_size=self._health_verified_log_size,
            errors=[error],
        )

    def _fail_append_locked(self, error: str) -> NoReturn:
        """Latch an append-time integrity mismatch and refuse the write."""
        self._latch_integrity_failure_locked(error)
        raise StoreIntegrityError(error)

    def append(self, record: dict[str, Any], *, created_at: str) -> LogEntry:
        with self._lock, self._operation_deadline():
            with self._write_transaction():
                self._require_writes_allowed()
                entry = self._append_locked(record, created_at=created_at)
            # Publish the incremental advancement only after COMMIT: a later
            # failure (ledger INSERT, COMMIT itself) rolls the DB back, and
            # the cached verdict must stay on the last durable prefix.
            self._health_verified_head = entry.entry_hash
            self._health_verified_log_size = entry.seq
            return entry

    def _append_locked(self, record: dict[str, Any], *, created_at: str) -> LogEntry:
        """Append one log entry inside the caller's write transaction.

        The caller owns the transaction and publishes the cached-verdict
        advancement only after COMMIT (see :meth:`append`). This helper never
        touches the verdict on success; on any integrity mismatch it latches
        via :meth:`_fail_append_locked` (non-ready + writes disabled until a
        restart re-verifies) instead of appending. ``ValueError`` for a
        malformed record is a client error and does not latch.
        """
        for key in ("name", "source_identity", "commit", "content_sha256", "status"):
            if not isinstance(record.get(key), str) or not record[key]:
                raise ValueError(f"record requires a non-empty string {key!r}")
        record_bytes = canonical_bytes(record)
        row = self._conn.execute(
            "SELECT seq, entry_hash FROM log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        previous_seq = int(row["seq"]) if row else 0
        prev_hash = str(row["entry_hash"]) if row else _GENESIS
        try:
            frontier = self._load_frontier()
        except StoreIntegrityError as exc:
            self._fail_append_locked(str(exc))
        self._validate_append_anchors_locked(
            previous_seq=previous_seq, prev_hash=prev_hash, frontier=frontier
        )
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
            self._fail_append_locked("log sequence is not contiguous")
        try:
            new_root = _frontier_append(frontier, bytes.fromhex(entry_hash)).hex()
        except StoreIntegrityError as exc:
            self._fail_append_locked(str(exc))
        self._save_frontier(frontier)
        try:
            self._conn.execute(
                "INSERT INTO boundaries (log_size, head, merkle_root, created_at) "
                "VALUES (?, ?, ?, ?)",
                (seq, entry_hash, new_root, created_at),
            )
        except sqlite3.IntegrityError as exc:
            self._fail_append_locked("snapshot boundary cache is inconsistent")
        return LogEntry(seq=seq, entry_hash=entry_hash, prev_hash=prev_hash, record=record)

    def _validate_append_anchors_locked(
        self,
        *,
        previous_seq: int,
        prev_hash: str,
        frontier: list[_FrontierLevel],
    ) -> None:
        """Validate the frontier/head anchors before trusting them for an append.

        Cheap: two O(1) row reads (last boundary, last 1–2 leaves) plus one
        hash per tree level for the inter-level consistency walk — no chain
        scan. Any mismatch latches through :meth:`_fail_append_locked`
        (``/health`` 503, writes disabled until a restart re-verifies)
        instead of attesting corrupted state as verified.
        """
        if (frontier[0].length if frontier else 0) != previous_seq:
            self._fail_append_locked("merkle frontier does not match the log head")
        if previous_seq == 0:
            if frontier:
                self._fail_append_locked("merkle frontier does not match the log head")
            return
        boundary = self._conn.execute(
            "SELECT head, merkle_root FROM boundaries WHERE log_size = ?",
            (previous_seq,),
        ).fetchone()
        if boundary is None:
            self._fail_append_locked(
                f"snapshot boundary cache is missing log size {previous_seq}"
            )
        if str(boundary["head"]) != prev_hash:
            self._fail_append_locked("log head does not match the snapshot boundary")
        # Level-0 tails must be the last one (size 1) or two (size >= 2)
        # committed leaves; a length-preserving tail swap is otherwise
        # invisible to the length check yet poisons the next root.
        level_zero = frontier[0].tail
        if previous_seq == 1:
            if len(level_zero) != 1 or level_zero[0] != bytes.fromhex(prev_hash):
                self._fail_append_locked("merkle frontier disagrees with the committed log")
        else:
            second = self._conn.execute(
                "SELECT entry_hash FROM log WHERE seq = ?", (previous_seq - 1,)
            ).fetchone()
            if second is None:
                self._fail_append_locked("log sequence is not contiguous")
            want = [bytes.fromhex(str(second["entry_hash"])), bytes.fromhex(prev_hash)]
            if level_zero != want:
                self._fail_append_locked("merkle frontier disagrees with the committed log")
        # Each upper level's last node is the hash of the lower level's last
        # one (odd length, duplicated) or two (even length) nodes. A tampered
        # tail at any level breaks this link for the level above it.
        for lower, upper in zip(frontier, frontier[1:]):
            if lower.length >= 2 and len(lower.tail) < 2:
                self._fail_append_locked("merkle frontier tail is incomplete")
            if lower.length % 2 == 1:
                want_last = _merkle_pair_hash(lower.tail[-1], lower.tail[-1])
            else:
                want_last = _merkle_pair_hash(lower.tail[-2], lower.tail[-1])
            if upper.tail[-1] != want_last:
                self._fail_append_locked("merkle frontier disagrees with the committed log")
        if _frontier_root(frontier).hex() != str(boundary["merkle_root"]):
            self._fail_append_locked("merkle frontier disagrees with the committed log")

    def _load_frontier(self, conn: sqlite3.Connection | None = None) -> list[_FrontierLevel]:
        db = conn if conn is not None else self._conn
        rows = db.execute(
            "SELECT level, len, tail FROM merkle_frontier ORDER BY level"
        ).fetchall()
        frontier: list[_FrontierLevel] = []
        for index, row in enumerate(rows):
            if int(row["level"]) != index:
                raise StoreIntegrityError("merkle frontier levels are not contiguous")
            try:
                tail_hex = json.loads(str(row["tail"]))
            except json.JSONDecodeError as exc:
                raise StoreIntegrityError("merkle frontier encoding is invalid") from exc
            if (
                not isinstance(tail_hex, list)
                or not 1 <= len(tail_hex) <= 2
                or any(not isinstance(item, str) or not _hex256(item) for item in tail_hex)
            ):
                raise StoreIntegrityError("merkle frontier encoding is invalid")
            length = int(row["len"])
            if length < 1 or len(tail_hex) > length:
                raise StoreIntegrityError("merkle frontier length is invalid")
            frontier.append(
                _FrontierLevel(length=length, tail=[bytes.fromhex(item) for item in tail_hex])
            )
        return frontier

    def _save_frontier(self, frontier: list[_FrontierLevel]) -> None:
        self._conn.execute("DELETE FROM merkle_frontier")
        for level, entry in enumerate(frontier):
            self._conn.execute(
                "INSERT INTO merkle_frontier (level, len, tail) VALUES (?, ?, ?)",
                (
                    level,
                    entry.length,
                    json.dumps([item.hex() for item in entry.tail], separators=(",", ":")),
                ),
            )

    def _ensure_boundaries(self) -> None:
        """Validate the memoized boundary cache against the log at startup.

        Recomputes every prefix boundary incrementally from the log leaves
        and compares it to the stored ``boundaries`` row: a missing row is
        backfilled (first upgrade, or rows committed by a writer that did
        not maintain the cache), but a stored row that disagrees with the
        recomputed chain fails readiness like any other §5 mismatch — the
        cache is never trusted over the log. The Merkle frontier is a pure
        append accelerator, so a stale frontier is rebuilt without failing;
        the length check in :meth:`_append_locked` keeps appends fail-closed
        until the rebuild lands.
        """
        for _ in range(4):
            leaves = self._conn.execute(
                "SELECT seq, entry_hash, created_at FROM log ORDER BY seq"
            ).fetchall()
            size = len(leaves)
            if any(int(row["seq"]) != index for index, row in enumerate(leaves, start=1)):
                raise StoreIntegrityError("log sequence is not contiguous")
            expected, frontier = _recompute_prefix(
                [(str(row["entry_hash"]), str(row["created_at"])) for row in leaves]
            )
            stored = {
                int(row["log_size"]): (
                    str(row["head"]),
                    str(row["merkle_root"]),
                    str(row["created_at"]),
                )
                for row in self._conn.execute(
                    "SELECT log_size, head, merkle_root, created_at FROM boundaries"
                ).fetchall()
            }
            if any(log_size < 1 or log_size > size for log_size in stored):
                head_now = self._conn.execute(
                    "SELECT seq FROM log ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                if (int(head_now["seq"]) if head_now else 0) != size:
                    continue
                raise StoreIntegrityError("snapshot boundary cache is inconsistent")
            for index, boundary in enumerate(expected, start=1):
                cached = stored.get(index)
                if cached is None:
                    continue
                if cached != boundary:
                    raise StoreIntegrityError(
                        "snapshot boundary cache disagrees with the committed log"
                    )
            missing = [index for index in range(1, size + 1) if index not in stored]
            try:
                stored_frontier = self._load_frontier()
            except StoreIntegrityError:
                stored_frontier = []
                frontier_matches = False
            else:
                frontier_matches = len(stored_frontier) == len(frontier) and all(
                    actual.length == want.length and actual.tail == want.tail
                    for actual, want in zip(stored_frontier, frontier)
                )
            if not missing and frontier_matches:
                return
            with self._write_transaction():
                head_now = self._conn.execute(
                    "SELECT seq FROM log ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                if (int(head_now["seq"]) if head_now else 0) != size:
                    continue
                for index in missing:
                    head, root, created_at = expected[index - 1]
                    self._conn.execute(
                        "INSERT OR IGNORE INTO boundaries "
                        "(log_size, head, merkle_root, created_at) VALUES (?, ?, ?, ?)",
                        (index, head, root, created_at),
                    )
                self._save_frontier(frontier)
            return
        raise StoreIntegrityError("log changed during startup boundary verification")

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
        with self._lock, self._operation_deadline():
            with self._write_transaction():
                self._require_writes_allowed()
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
            # Publish only after COMMIT (see :meth:`append`).
            self._health_verified_head = entry.entry_hash
            self._health_verified_log_size = entry.seq
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
        boundary: SnapshotBoundary | None = None,
    ) -> tuple[list[dict[str, Any]], bool]:
        if bool(source_identity) != bool(commit):
            raise ValueError("source_identity and commit must appear together")
        if not ((source_identity and commit) or content_sha256):
            return [], False
        with self._lock, self._operation_deadline():
            cap = self._page_boundary_locked(boundary, max_seq).log_size
            clauses = ["seq <= ?"]
            params: list[Any] = [cap]
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
        boundary: SnapshotBoundary | None = None,
    ) -> tuple[list[LogEntry], bool]:
        with self._lock, self._operation_deadline():
            cap = self._page_boundary_locked(boundary, max_seq).log_size
            rows = self._conn.execute(
                "SELECT seq, entry_hash, prev_hash, record_json FROM log "
                "WHERE seq > ? AND seq <= ? ORDER BY seq ASC LIMIT ? OFFSET ?",
                (since, cap, limit + 1, offset),
            ).fetchall()
            return [_entry_from_row(row) for row in rows[:limit]], len(rows) > limit

    def append_imports(
        self, records: list[tuple[str, dict[str, Any]]], *, created_at: str
    ) -> int:
        imported = 0
        last_entry: LogEntry | None = None
        with self._lock, self._operation_deadline():
            with self._write_transaction():
                self._require_writes_allowed()
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
                    last_entry = entry
            # Publish only after COMMIT: the whole batch is atomic, so the
            # verdict jumps to the last durable entry or stays put (see
            # :meth:`append`). A mid-batch failure rolls everything back and
            # leaves the previous verdict untouched.
            if last_entry is not None:
                self._health_verified_head = last_entry.entry_hash
                self._health_verified_log_size = last_entry.seq
        return imported

    def head(self) -> tuple[int, str]:
        boundary = self.snapshot_boundary()
        return boundary.log_size, boundary.head

    def snapshot_boundary(self, max_seq: int | None = None) -> SnapshotBoundary:
        with self._lock, self._operation_deadline():
            return self._snapshot_boundary_locked(max_seq)

    def _page_boundary_locked(
        self,
        boundary: SnapshotBoundary | None,
        max_seq: int | None,
    ) -> SnapshotBoundary:
        """Resolve the boundary a page is evaluated at.

        Cursor pages pass the cursor's carried boundary: it is verified
        structurally against the store (head, Merkle root, size, timestamp at
        that log size) under the paging lock, and any disagreement — a forged
        body, an unavailable size, or a pruned prefix — is
        :class:`CursorBoundaryMismatch`, never a silent re-evaluation at a
        newer boundary.
        """
        if boundary is not None and max_seq is not None:
            raise ValueError("page boundary and max_seq are mutually exclusive")
        if boundary is None:
            return self._snapshot_boundary_locked(max_seq)
        try:
            actual = self._snapshot_boundary_locked(boundary.log_size)
        except (ValueError, StoreIntegrityError) as exc:
            raise CursorBoundaryMismatch(
                "cursor boundary is not available in this store"
            ) from exc
        if actual != boundary:
            raise CursorBoundaryMismatch(
                "cursor boundary disagrees with the committed log prefix"
            )
        return actual

    def _snapshot_boundary_locked(self, max_seq: int | None) -> SnapshotBoundary:
        """Read one memoized boundary row (O(1), no Merkle recomputation).

        The ``boundaries`` row for a committed size is written in the same
        transaction as the log append that created it, so a single-row lookup
        is the committed boundary. Two O(1) structural anchors keep live
        reads fail-closed without rescanning: the log row at the boundary
        must still carry the memoized head/timestamp, and the genesis row
        must still exist (prefix pruning is refused instead of served from
        the cache). The full hash-chain and Merkle proof runs once at
        startup in :meth:`_ensure_boundaries`, never per request.
        """
        head_row = self._conn.execute(
            "SELECT seq FROM log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        current = int(head_row["seq"]) if head_row else 0
        boundary = current if max_seq is None else max_seq
        if boundary < 0 or boundary > current:
            raise ValueError("snapshot boundary is unavailable")
        if boundary == 0:
            metadata = self._conn.execute(
                "SELECT value FROM metadata WHERE key = 'created_at'"
            ).fetchone()
            if metadata is None:
                raise StoreIntegrityError("service creation metadata is missing")
            return SnapshotBoundary(
                version=0,
                log_size=0,
                head=_GENESIS,
                merkle_root=_GENESIS,
                created_at=str(metadata["value"]),
            )
        cached = self._conn.execute(
            "SELECT head, merkle_root, created_at FROM boundaries WHERE log_size = ?",
            (boundary,),
        ).fetchone()
        if cached is None:
            raise StoreIntegrityError("snapshot boundary cache is missing; restart to rebuild")
        anchor = self._conn.execute(
            "SELECT entry_hash, created_at FROM log WHERE seq = ?",
            (boundary,),
        ).fetchone()
        if (
            anchor is None
            or str(anchor["entry_hash"]) != str(cached["head"])
            or str(anchor["created_at"]) != str(cached["created_at"])
        ):
            raise StoreIntegrityError("log head does not match the snapshot boundary")
        genesis = self._conn.execute("SELECT 1 FROM log WHERE seq = 1").fetchone()
        if genesis is None:
            raise StoreIntegrityError("log sequence is not contiguous")
        return SnapshotBoundary(
            version=boundary,
            log_size=boundary,
            head=str(cached["head"]),
            merkle_root=str(cached["merkle_root"]),
            created_at=str(cached["created_at"]),
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
            errors, _ = self._integrity_errors_on(self._conn)
            return errors

    def _integrity_errors_on(
        self, conn: sqlite3.Connection
    ) -> tuple[list[str], list[_WalkedLeaf]]:
        """Run the full chain-plus-ledgers verification on one connection.

        Shared choke point for the startup §5 check (on the store connection,
        under the store lock with the operation deadline) and the background
        refresh (on its own read-only connection, holding no store lock,
        inside the single ``BEGIN`` snapshot :meth:`refresh_health_verdict`
        opens). Returns the error list plus the walked leaves for the
        boundary-cache comparison. At startup each ``SELECT`` sees its own
        statement snapshot (no concurrent writers exist yet); at refresh all
        ``SELECT`` statements share the pass snapshot, so a concurrent append
        stays invisible to the whole pass instead of straddling two reads.
        """
        errors: list[str] = []
        database_integrity = [str(row[0]) for row in conn.execute("PRAGMA integrity_check")]
        if database_integrity != ["ok"]:
            errors.extend(f"SQLite integrity check: {message}" for message in database_integrity)
        for row in conn.execute("PRAGMA foreign_key_check"):
            errors.append(
                f"foreign key violation in {row[0]} row {row[1]} referencing {row[2]}"
            )
        metadata = conn.execute(
            "SELECT value FROM metadata WHERE key = 'created_at'"
        ).fetchone()
        if metadata is None or not _timestamp(str(metadata["value"])):
            errors.append("service creation metadata is missing or malformed")
        schema_version = conn.execute(
            "SELECT value FROM metadata WHERE key = 'schema_version'"
        ).fetchone()
        if schema_version is None or schema_version["value"] != str(_SCHEMA_VERSION):
            errors.append("database schema metadata is missing or malformed")
        previous = _GENESIS
        expected_seq = 1
        log_hashes: dict[int, str] = {}
        leaves: list[_WalkedLeaf] = []
        for row in conn.execute(
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
            leaves.append(
                _WalkedLeaf(seq=seq, entry_hash=str(row["entry_hash"]), created_at=str(row["created_at"]))
            )
            expected_seq += 1

        for row in conn.execute(
            "SELECT auditor_id, key, body_sha256, response_json, seq, expires_at "
            "FROM idempotency"
        ):
            seq = int(row["seq"])
            try:
                response = json.loads(row["response_json"])
            except json.JSONDecodeError:
                response = None
            expected_entry_hash = log_hashes.get(seq)
            if expected_entry_hash is None:
                # Either a genuine orphan (a gap the chain walk already
                # reported) or a row committed after the chain statement
                # started; a live single-row lookup distinguishes them.
                live = conn.execute(
                    "SELECT entry_hash FROM log WHERE seq = ?", (seq,)
                ).fetchone()
                expected_entry_hash = str(live["entry_hash"]) if live is not None else None
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
                or response.get("entry_hash") != expected_entry_hash
                or not _hex256(str(row["body_sha256"]))
                or not isinstance(row["expires_at"], int)
            ):
                errors.append(
                    f"idempotency entry {row['auditor_id']!r}/{row['key']!r} is inconsistent"
                )

        for row in conn.execute(
            "SELECT fingerprint, seq FROM imported_records"
        ):
            if row["seq"] is None:
                errors.append(f"import fingerprint {row['fingerprint']!r} has no log sequence")
                continue
            seq = int(row["seq"])
            record_row = conn.execute(
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
        return errors, leaves

    def _health_stale_locked(self, now: float) -> bool:
        return (now - self._health_last_refresh_monotonic) > (
            self._health_verify_interval * HEALTH_STALENESS_MULTIPLIER
        )

    def health_verdict(self) -> HealthVerdict:
        """Return the cached integrity verdict (no hashing, no I/O).

        Staleness is evaluated at read time: a verdict whose last completed
        refresh is older than twice the verify interval reads as non-ready,
        so a hung verifier can never serve green health forever.
        """
        with self._lock:
            now = time.monotonic()
            if not self._health_ready:
                return HealthVerdict(
                    ready=False,
                    verified_head=self._health_verified_head,
                    verified_log_size=self._health_verified_log_size,
                    verified_at=self._health_verified_at,
                    error=self._health_error,
                    code=self._health_code,
                )
            if self._health_stale_locked(now):
                return HealthVerdict(
                    ready=False,
                    verified_head=self._health_verified_head,
                    verified_log_size=self._health_verified_log_size,
                    verified_at=self._health_verified_at,
                    error="registry integrity verification is stale",
                )
            return HealthVerdict(
                ready=True,
                verified_head=self._health_verified_head,
                verified_log_size=self._health_verified_log_size,
                verified_at=self._health_verified_at,
                error=None,
            )

    def _verify_boundary_cache_on(
        self, conn: sqlite3.Connection, leaves: list[_WalkedLeaf]
    ) -> list[str]:
        """Compare the memoized boundary cache against the walked log prefix.

        Read-only counterpart of the startup :meth:`_ensure_boundaries`: a
        missing or disagreeing row is corruption (never backfilled at
        runtime). The caller holds ``conn`` in one ``BEGIN``-to-``ROLLBACK``
        read snapshot (see :meth:`refresh_health_verdict`), so the boundary
        rows, the frontier length/live head, and the frontier tails below all
        observe the same committed state even when appends land mid-pass.
        Rows for sizes beyond the snapshot head are still tolerated by the
        pure comparator as a defence-in-depth branch (live appends that
        committed before the snapshot opened but after the chain statement
        started cannot occur under one snapshot, yet the comparator keeps the
        explicit ``walked_size``/``live_size`` branch unit-testable).
        """
        expected, recomputed = _recompute_prefix(
            [(leaf.entry_hash, leaf.created_at) for leaf in leaves]
        )
        stored = {
            int(row["log_size"]): (
                str(row["head"]),
                str(row["merkle_root"]),
                str(row["created_at"]),
            )
            for row in conn.execute(
                "SELECT log_size, head, merkle_root, created_at FROM boundaries"
            ).fetchall()
        }
        # One statement, one snapshot: the frontier length and the live head
        # advance in the same append transaction, so comparing them from a
        # single statement is race-free.
        sizes = conn.execute(
            "SELECT (SELECT len FROM merkle_frontier WHERE level = 0) AS frontier_len,"
            " (SELECT MAX(seq) FROM log) AS live_head"
        ).fetchone()
        frontier_length = sizes["frontier_len"]
        live_head = sizes["live_head"]
        try:
            stored_frontier = self._load_frontier(conn)
        except StoreIntegrityError as exc:
            return [f"merkle frontier encoding is invalid: {exc}"]
        return _boundary_cache_errors(
            expected=expected,
            stored=stored,
            walked_size=len(leaves),
            live_size=int(live_head) if live_head is not None else 0,
            frontier_length=int(frontier_length) if frontier_length is not None else None,
            stored_frontier=stored_frontier,
            recomputed_frontier=recomputed,
        )

    def refresh_health_verdict(self) -> HealthVerdict:
        """Run one full verification pass and publish the cached verdict.

        Lock discipline: the walk holds NO store lock — it reads through its
        own short-lived read-only connection (``PRAGMA query_only``), so a
        minutes-long walk on a large log never blocks appends. Only verdict
        publication takes ``self._lock``, briefly. There is deliberately no
        operation deadline on the walk: its duration scales with log size,
        and the staleness bound (twice the verify interval) is the backstop —
        a hung pass simply stops completing and the verdict goes stale.

        Snapshot discipline: the chain walk, the boundary rows, and the
        frontier are all read under ONE ``BEGIN``-to-``ROLLBACK`` DEFERRED
        read transaction on that connection. WAL snapshot isolation keeps the
        pass consistent (a valid append committing mid-pass stays invisible
        to it instead of producing a mixed old-chain/new-frontier view that
        would false-positive as corruption) while preserving append
        concurrency — WAL readers never block writers; the pass only pins the
        snapshot until it ends. Publication afterwards reads the live head
        under ``self._lock`` and trusts only transitively-verified appends
        (each passed the cheap anchor checks in :meth:`_append_locked`).

        Fail-closed: ANY failed pass — corruption found or the walk itself
        raising — latches integrity failure, flips readiness, and disables
        writes exactly like the startup §5 mismatch. Only a restart (which
        re-verifies from scratch) clears it. This method is total: it returns
        a verdict, never raises.
        """
        started = time.monotonic()
        with self._lock:
            if self._integrity_failed:
                verdict = HealthVerdict(
                    ready=False,
                    verified_head=self._health_verified_head,
                    verified_log_size=self._health_verified_log_size,
                    verified_at=self._health_verified_at,
                    error=self._health_error,
                    code=self._health_code,
                )
                self._log_health_refresh(
                    result="integrity_failed_latched",
                    duration_ms=(time.monotonic() - started) * 1000,
                    log_size=self._health_verified_log_size,
                    errors=(),
                )
                return verdict
        walked_size: int | None = None
        try:
            conn = sqlite3.connect(str(self.path), timeout=5.0, isolation_level=None)
            try:
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA busy_timeout=5000")
                conn.execute("PRAGMA query_only=ON")
                # One DEFERRED read snapshot for the whole pass (WAL keeps
                # writers unblocked). Every SELECT below — chain, ledgers,
                # boundaries, frontier — observes the same committed state.
                conn.execute("BEGIN")
                try:
                    errors, leaves = self._integrity_errors_on(conn)
                    walked_size = len(leaves)
                    if not errors:
                        errors = self._verify_boundary_cache_on(conn, leaves)
                finally:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
            finally:
                conn.close()
        except Exception as exc:
            errors = [f"health verification failed: {exc}"]
        duration_ms = (time.monotonic() - started) * 1000
        with self._lock:
            if self._integrity_failed:
                # Lost a race with a concurrent failed pass; stay latched.
                return HealthVerdict(
                    ready=False,
                    verified_head=self._health_verified_head,
                    verified_log_size=self._health_verified_log_size,
                    verified_at=self._health_verified_at,
                    error=self._health_error,
                    code=self._health_code,
                )
            boundary: SnapshotBoundary | None = None
            if not errors:
                try:
                    boundary = self._snapshot_boundary_locked(None)
                except (ValueError, StoreIntegrityError) as exc:
                    # The walk was clean but the live boundary disagrees
                    # (tampering inside the refresh race window): fail closed.
                    errors = [f"snapshot boundary is unavailable: {exc}"]
            if errors or boundary is None:
                if not errors:
                    errors = ["snapshot boundary is unavailable"]
                self._integrity_failed = True
                self._health_ready = False
                self._health_error = "; ".join(errors)
                self._health_last_refresh_monotonic = time.monotonic()
                self._log_health_refresh(
                    result="integrity_failed",
                    duration_ms=duration_ms,
                    log_size=walked_size
                    if walked_size is not None
                    else self._health_verified_log_size,
                    errors=errors,
                )
                return HealthVerdict(
                    ready=False,
                    verified_head=self._health_verified_head,
                    verified_log_size=self._health_verified_log_size,
                    verified_at=self._health_verified_at,
                    error=self._health_error,
                    code=self._health_code,
                )
            # The walked prefix is verified and every newer append passed its
            # incremental check, so the live head is verified transitively.
            self._health_ready = True
            self._health_verified_head = boundary.head
            self._health_verified_log_size = boundary.log_size
            self._health_verified_at = _utc_now()
            self._health_error = None
            self._health_last_refresh_monotonic = time.monotonic()
            self._log_health_refresh(
                result="ok",
                duration_ms=duration_ms,
                log_size=walked_size if walked_size is not None else boundary.log_size,
                errors=(),
            )
            return HealthVerdict(
                ready=True,
                verified_head=boundary.head,
                verified_log_size=boundary.log_size,
                verified_at=self._health_verified_at,
                error=None,
            )

    def _log_health_refresh(
        self,
        *,
        result: str,
        duration_ms: float,
        log_size: int,
        errors: tuple[str, ...] | list[str],
    ) -> None:
        event: dict[str, object] = {
            "event": "health_refresh",
            "result": result,
            "duration_ms": round(duration_ms, 3),
            "log_size": log_size,
        }
        if errors:
            event["error_count"] = len(errors)
            event["error"] = errors[0][:_HEALTH_LOG_ERROR_PREVIEW_CHARS]
        _AUDIT_LOG.info("%s", json.dumps(event, sort_keys=True, separators=(",", ":")))

    def start_health_verifier(self) -> None:
        """Start the background full verifier (idempotent).

        The daemon thread runs :meth:`refresh_health_verdict` every
        ``health_verify_interval`` seconds. A previous thread that already
        finished is reaped; a call racing a still-draining stop is a no-op —
        call again once the drain completes.
        """
        with self._verifier_lock:
            thread = self._verifier_thread
            if thread is not None:
                if thread.is_alive():
                    return
                self._verifier_thread = None
            self._verifier_stop.clear()
            fresh = threading.Thread(
                target=self._health_verifier_loop,
                name="csk-health-verifier",
                daemon=True,
            )
            self._verifier_thread = fresh
            fresh.start()

    def stop_health_verifier(self) -> None:
        """Stop the background verifier (idempotent).

        Waits boundedly for an in-flight pass; a thread that outlives the
        wait is a daemon and dies with the process. Never call while holding
        ``self._lock`` (see :meth:`close`).
        """
        with self._verifier_lock:
            thread = self._verifier_thread
            if thread is None:
                return
            self._verifier_stop.set()
        thread.join(timeout=_VERIFIER_JOIN_TIMEOUT_SECONDS)
        with self._verifier_lock:
            if not thread.is_alive() and self._verifier_thread is thread:
                self._verifier_thread = None

    def health_verifier_running(self) -> bool:
        """Whether the background verifier is currently active."""
        with self._verifier_lock:
            thread = self._verifier_thread
            return (
                thread is not None
                and thread.is_alive()
                and not self._verifier_stop.is_set()
            )

    def _health_verifier_loop(self) -> None:
        while not self._verifier_stop.wait(self._health_verify_interval):
            try:
                self.refresh_health_verdict()
            except Exception as exc:
                # Unreachable in practice (refresh is total); never let the
                # loop die silently, and never log a traceback with paths.
                _AUDIT_LOG.error(
                    "%s",
                    json.dumps(
                        {"event": "health_refresh", "result": "loop_error",
                         "error": type(exc).__name__},
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                )

    def checkpoint_matches(self, checkpoint: SnapshotBoundary) -> bool:
        try:
            prefix = self.snapshot_boundary(checkpoint.log_size)
        except (ValueError, StoreIntegrityError):
            return False
        return prefix == checkpoint

    def refuse_startup_checkpoint(self, diagnostic: str, detail: str) -> None:
        """Latch a §6 startup-checkpoint refusal without comparison.

        Used when the checkpoint itself is unusable (its signature fails
        against the accepted keys): the service stays up non-ready with
        writes disabled through the common integrity-failure path, exactly
        like a failed comparison. Only the closed §6 refusal diagnostics
        are accepted; only a restart clears the latch. History is untouched.
        """
        if diagnostic not in REFUSAL_DIAGNOSTICS:
            raise ValueError(f"unknown startup-checkpoint diagnostic: {diagnostic}")
        with self._lock:
            if not self._integrity_failed:
                self._health_code = diagnostic
            self._latch_integrity_failure_locked(detail)

    def apply_startup_checkpoint(self, checkpoint: CheckpointView) -> str | None:
        """Compare the verified live boundary against a §6 startup checkpoint.

        Runs once at startup, after the §5 verification and before the
        service reports ready. Returns ``None`` when the comparison passes.
        On refusal, latches non-ready plus writes-disabled through the
        common integrity-failure path (``/health`` 503 with the refusal
        diagnostic, writes 503) and returns that diagnostic. Only a restart
        clears it; history is never truncated or repaired.
        """
        with self._lock, self._operation_deadline():
            live = self._snapshot_boundary_locked(None)
            prefix: SnapshotBoundary | None = None
            if live.version > checkpoint.version:
                try:
                    prefix = self._snapshot_boundary_locked(checkpoint.log_size)
                except (ValueError, StoreIntegrityError):
                    prefix = None
            diagnostic = compare_checkpoint(live, checkpoint, prefix)
            if diagnostic is None:
                return None
            self.refuse_startup_checkpoint(
                diagnostic,
                f"startup checkpoint comparison refused: {diagnostic} "
                f"(live version {live.version}, checkpoint version {checkpoint.version})",
            )
            return diagnostic

    def backup_to(self, destination: Path) -> SnapshotBoundary:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise FileExistsError(destination)
        _prepare_private_database_file(destination)
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


def _prepare_private_database_file(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    except FileExistsError:
        pass
    else:
        os.close(descriptor)
    protect_private_file(path)


def _protect_sqlite_sidecars(path: Path) -> None:
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if sidecar.exists():
            protect_private_file(sidecar)


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


def _merkle_pair_hash(left: bytes, right: bytes) -> bytes:
    """Hash one Merkle tree pair.

    Every Merkle-tree hash in this module goes through this function so the
    operation-count test can observe (via monkeypatch) exactly how many tree
    hashes a read or an append performs. Entry-hash computation uses
    ``hashlib.sha256`` directly and is never counted as Merkle work.
    """
    return hashlib.sha256(left + right).digest()


def _merkle_root(entry_hashes: list[str]) -> str:
    if not entry_hashes:
        return _GENESIS
    level = [bytes.fromhex(value) for value in entry_hashes]
    while len(level) > 1:
        next_level: list[bytes] = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            next_level.append(_merkle_pair_hash(left, right))
        level = next_level
    return level[0].hex()


@dataclass
class _FrontierLevel:
    length: int
    tail: list[bytes]


def _frontier_append(frontier: list[_FrontierLevel], leaf: bytes) -> bytes:
    """Append one leaf to an incremental Merkle frontier.

    The frontier holds, per tree level, the level length and its last two
    node hashes. Updating it touches one node per level, so an append costs
    O(log n) hashes and the returned root is byte-identical to
    :func:`_merkle_root` over the full prefix.
    """
    if not frontier:
        frontier.append(_FrontierLevel(length=1, tail=[leaf]))
        return leaf
    first = frontier[0]
    if first.length == 1:
        lower_new_tail = [first.tail[0], leaf]
    else:
        lower_new_tail = [first.tail[-1], leaf]
    first.length += 1
    first.tail = lower_new_tail
    lower_new_length = first.length
    level_index = 1
    while True:
        if lower_new_length <= 1:
            del frontier[level_index:]
            break
        upper_new_length = (lower_new_length + 1) // 2
        if lower_new_length % 2 == 1:
            new_last = _merkle_pair_hash(lower_new_tail[-1], lower_new_tail[-1])
        else:
            new_last = _merkle_pair_hash(lower_new_tail[-2], lower_new_tail[-1])
        if level_index >= len(frontier):
            if upper_new_length != 1:
                raise StoreIntegrityError("merkle frontier is inconsistent")
            frontier.append(_FrontierLevel(length=1, tail=[new_last]))
            break
        upper_old = frontier[level_index]
        if upper_old.length >= 2 and len(upper_old.tail) != 2:
            raise StoreIntegrityError("merkle frontier tail is incomplete")
        if upper_new_length == upper_old.length:
            if upper_old.length == 1:
                new_tail = [new_last]
            else:
                new_tail = [upper_old.tail[-2], new_last]
        elif upper_new_length == upper_old.length + 1:
            if upper_new_length == 1:
                new_tail = [new_last]
            else:
                new_tail = [upper_old.tail[-1], new_last][-2:]
        else:
            raise StoreIntegrityError("merkle frontier is inconsistent")
        upper_old.length = upper_new_length
        upper_old.tail = new_tail
        if upper_new_length == 1:
            del frontier[level_index + 1 :]
            break
        lower_new_tail = new_tail
        lower_new_length = upper_new_length
        level_index += 1
        if level_index > 64:
            raise StoreIntegrityError("merkle frontier exceeds maximum depth")
    return frontier[-1].tail[-1]


def _frontier_root(frontier: list[_FrontierLevel]) -> bytes:
    if not frontier:
        return bytes.fromhex(_GENESIS)
    return frontier[-1].tail[-1]


def _recompute_prefix(
    leaves: list[tuple[str, str]],
) -> tuple[list[tuple[str, str, str]], list[_FrontierLevel]]:
    """Recompute every prefix boundary and the Merkle frontier from leaves.

    Shared choke point for the startup cache rebuild (:meth:`Store._ensure_boundaries`)
    and the background refresh comparison, so both derive the same expected
    values from the committed log. ``leaves`` is ``(entry_hash, created_at)``
    per sequence starting at 1.
    """
    expected: list[tuple[str, str, str]] = []
    frontier: list[_FrontierLevel] = []
    for entry_hash, created_at in leaves:
        root = _frontier_append(frontier, bytes.fromhex(entry_hash)).hex()
        expected.append((entry_hash, root, created_at))
    return expected, frontier


def _boundary_cache_errors(
    *,
    expected: list[tuple[str, str, str]],
    stored: dict[int, tuple[str, str, str]],
    walked_size: int,
    live_size: int,
    frontier_length: int | None,
    stored_frontier: list[_FrontierLevel],
    recomputed_frontier: list[_FrontierLevel],
) -> list[str]:
    """Compare the memoized cache tables against the verified log prefix.

    Pure comparison (no I/O) shared by reasoning, so the concurrent-append
    race branches are unit-testable: ``walked_size`` is the prefix the chain
    walk verified, ``live_size`` the head observed afterwards. Stored rows
    strictly between the two are legitimate concurrent appends and are
    ignored this round; everything else must agree exactly.
    """
    errors: list[str] = []
    for size, boundary in enumerate(expected, start=1):
        cached = stored.get(size)
        if cached is None:
            errors.append(f"snapshot boundary cache is missing log size {size}")
        elif cached != boundary:
            errors.append("snapshot boundary cache disagrees with the committed log")
    for size in stored:
        if size < 1:
            errors.append(f"snapshot boundary cache references invalid log size {size}")
        elif size > live_size:
            errors.append(
                f"snapshot boundary cache references uncommitted log size {size}"
            )
    length_matches = (frontier_length == live_size) or (
        frontier_length is None and live_size == 0
    )
    if not length_matches:
        errors.append("merkle frontier does not match the log head")
    elif live_size == walked_size:
        # Quiescent: no append landed during the walk, so the stored tails
        # must equal the recomputed ones exactly.
        tails_match = len(stored_frontier) == len(recomputed_frontier) and all(
            actual.length == want.length and actual.tail == want.tail
            for actual, want in zip(stored_frontier, recomputed_frontier)
        )
        if not tails_match:
            errors.append("merkle frontier disagrees with the committed log")
    # Else: appends landed during the walk. The frontier length already
    # matches the live head (checked above, race-free), and the tails are a
    # pure append accelerator rechecked on the next quiescent pass.
    return errors


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
