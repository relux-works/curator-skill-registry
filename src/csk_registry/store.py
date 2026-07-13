from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .signing import canonical_bytes


# A record store backed by SQLite in WAL mode. Every accepted record appends to
# a hash-chained transparency log: entry N commits to the previous entry hash
# and the canonical record bytes. The current record for an artifact is the
# latest log entry that names it, so a revocation supersedes an earlier audit.

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
CREATE TABLE IF NOT EXISTS idempotency (
    key TEXT PRIMARY KEY,
    body_sha256 TEXT NOT NULL,
    response_json TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS imported_records (
    fingerprint TEXT PRIMARY KEY,
    imported_at TEXT NOT NULL
);
"""

_GENESIS = "0" * 64


@dataclass(frozen=True)
class LogEntry:
    seq: int
    entry_hash: str
    prev_hash: str
    record: dict[str, Any]


class IdempotencyConflict(ValueError):
    pass


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        # The service runs sync endpoints in a thread pool, so the connection is
        # shared across threads; writes are serialized with a lock.
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def append(self, record: dict[str, Any], *, created_at: str) -> LogEntry:
        with self._lock, self._conn:
            return self._append_locked(record, created_at=created_at)

    def _append_locked(self, record: dict[str, Any], *, created_at: str) -> LogEntry:
        for key in ("name", "source_identity", "commit", "content_sha256", "status"):
            if not isinstance(record.get(key), str) or not record[key]:
                raise ValueError(f"record requires a non-empty string {key!r}")
        record_bytes = canonical_bytes(record)
        row = self._conn.execute("SELECT entry_hash FROM log ORDER BY seq DESC LIMIT 1").fetchone()
        prev_hash = row["entry_hash"] if row else _GENESIS
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
        return LogEntry(seq=seq, entry_hash=entry_hash, prev_hash=prev_hash, record=record)

    def append_idempotent(
        self,
        record: dict[str, Any],
        *,
        key: str,
        body_sha256: str,
        created_at: str,
        now: int,
        ttl_seconds: int,
    ) -> tuple[dict[str, Any], bool]:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM idempotency WHERE expires_at <= ?", (now,))
            existing = self._conn.execute(
                "SELECT body_sha256, response_json FROM idempotency WHERE key = ?", (key,)
            ).fetchone()
            if existing is not None:
                if existing["body_sha256"] != body_sha256:
                    raise IdempotencyConflict("idempotency key was already used for a different body")
                response = json.loads(existing["response_json"])
                if not isinstance(response, dict):
                    raise ValueError("stored idempotency response is invalid")
                return response, True
            entry = self._append_locked(record, created_at=created_at)
            response = {"seq": entry.seq, "entry_hash": entry.entry_hash}
            self._conn.execute(
                "INSERT INTO idempotency (key, body_sha256, response_json, expires_at) VALUES (?, ?, ?, ?)",
                (key, body_sha256, json.dumps(response, separators=(",", ":")), now + ttl_seconds),
            )
            return response, False

    def records_for(self, *, source_identity: str = "", commit: str = "", content_sha256: str = "") -> list[dict[str, Any]]:
        """Latest record per artifact matching identity+commit or content hash."""
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
    ) -> tuple[list[dict[str, Any]], bool]:
        clauses = []
        params: list[Any] = []
        if source_identity and commit:
            clauses.append("(source_identity = ? AND commit_hash = ?)")
            params.extend([source_identity, commit])
        if content_sha256:
            clauses.append("content_sha256 = ?")
            params.append(content_sha256)
        if not clauses:
            return [], False
        query = (
            "SELECT record_json FROM (SELECT record_json, name, source_identity, commit_hash, seq, "
            "ROW_NUMBER() OVER (PARTITION BY name, source_identity, commit_hash ORDER BY seq DESC) AS rank "
            "FROM log WHERE "
            + " OR ".join(clauses)
            + ") WHERE rank = 1 ORDER BY name, source_identity, commit_hash LIMIT ? OFFSET ?"
        )
        rows = self._conn.execute(query, [*params, limit + 1, offset]).fetchall()
        records = [json.loads(row["record_json"]) for row in rows[:limit]]
        return records, len(rows) > limit

    def log_entries(self, *, since: int = 0) -> list[LogEntry]:
        entries, _ = self.log_page(since=since, limit=10_000, offset=0)
        return entries

    def log_page(self, *, since: int, limit: int, offset: int) -> tuple[list[LogEntry], bool]:
        rows = self._conn.execute(
            "SELECT seq, entry_hash, prev_hash, record_json FROM log WHERE seq > ? "
            "ORDER BY seq ASC LIMIT ? OFFSET ?",
            (since, limit + 1, offset),
        ).fetchall()
        entries = [
            LogEntry(
                seq=row["seq"],
                entry_hash=row["entry_hash"],
                prev_hash=row["prev_hash"],
                record=json.loads(row["record_json"]),
            )
            for row in rows[:limit]
        ]
        return entries, len(rows) > limit

    def append_imports(
        self, records: list[tuple[str, dict[str, Any]]], *, created_at: str
    ) -> int:
        imported = 0
        with self._lock, self._conn:
            for fingerprint, record in records:
                exists = self._conn.execute(
                    "SELECT 1 FROM imported_records WHERE fingerprint = ?", (fingerprint,)
                ).fetchone()
                if exists is not None:
                    continue
                self._append_locked(record, created_at=created_at)
                self._conn.execute(
                    "INSERT INTO imported_records (fingerprint, imported_at) VALUES (?, ?)",
                    (fingerprint, created_at),
                )
                imported += 1
        return imported

    def head(self) -> tuple[int, str]:
        row = self._conn.execute("SELECT seq, entry_hash FROM log ORDER BY seq DESC LIMIT 1").fetchone()
        if row is None:
            return 0, _GENESIS
        return int(row["seq"]), row["entry_hash"]

    def merkle_root(self) -> str:
        """A simple ordered Merkle root over all entry hashes."""
        rows = self._conn.execute("SELECT entry_hash FROM log ORDER BY seq ASC").fetchall()
        leaves = [bytes.fromhex(row["entry_hash"]) for row in rows]
        if not leaves:
            return _GENESIS
        level = leaves
        while len(level) > 1:
            nxt: list[bytes] = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                nxt.append(hashlib.sha256(left + right).digest())
            level = nxt
        return level[0].hex()

    def verify_chain(self) -> bool:
        prev = _GENESIS
        for entry in self.log_entries():
            expected = hashlib.sha256(prev.encode("ascii") + canonical_bytes(entry.record)).hexdigest()
            if expected != entry.entry_hash or entry.prev_hash != prev:
                return False
            prev = entry.entry_hash
        return True
