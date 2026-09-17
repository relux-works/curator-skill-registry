# Changelog

## Unreleased

### Added

- Added snapshot-bound signed pagination, exact artifact identity, conjunctive
  filters, and explicit ambiguity rejection.
- Added serialized durable append, auditor-scoped idempotency, startup recovery
  verification, consistent backup, signed external checkpoints, and rollback
  refusal.
- Added staged signing-key rotation that retains overlap keys for live cursors,
  plus safe cancellation and retirement commands.
- Added bounded request streaming, concurrent-work limits, network and auditor
  rate limits, `Retry-After`, cache controls, and secure transport guards.
- Added finite body and database deadlines plus structured redacted audit
  events for authentication, idempotency, errors, and committed sequences.
- Added executable Curator Protocol registry-service vectors for concurrency,
  transaction rollback, crash recovery, restore, key rotation, transport
  limits, and caching.

### Changed

- Renamed the distribution, primary command, environment variable, metadata,
  and documentation to Curator Skill Registry. The former command and home
  variable remain temporary compatibility aliases.
- Changed latest-record identity to the exact tuple of name, source identity,
  commit, and content hash. Existing wire objects and endpoint shapes are
  unchanged.
- Legacy idempotency rows without auditor identity now require a 24-hour
  submission drain before upgrade. Startup refuses ambiguous unexpired rows;
  expired rows migrate without changing the log.

### Security

- R2: snapshot-boundary lookups no longer rescan the log or rebuild the
  Merkle tree per request. Each append now memoizes its boundary tuple
  `(log_size, head, merkle_root, created_at)` in a durable `boundaries`
  row in the same transaction (schema version 3, backfilled once at
  startup), and `snapshot_boundary(max_seq)`, `boundary_available()`, and
  the cursor carried-boundary check read one row (O(1)) with O(1)
  structural anchors instead of recomputing. Appends maintain an
  incremental Merkle frontier (O(log n) hashes, byte-identical roots).
  The memoized rows are revalidated against the recomputed chain at every
  startup, and a disagreement fails readiness like any other §5 mismatch;
  the cache is never trusted over the log. `GET /health` no longer
  re-verifies the chain per probe either: it serves a cached integrity
  verdict refreshed by a background full verifier (chain, ledgers, and
  boundary-cache agreement) every `--health-verify-interval` seconds
  (default 300, `CURATOR_SKILL_REGISTRY_HEALTH_VERIFY_INTERVAL`), while
  each append advances the verified head incrementally (after COMMIT, and
  only after the cheap frontier/head anchors validate). A failed refresh
  latches non-ready and disables writes like a startup §5 mismatch until
  a restart re-verifies; a pass that has not completed within twice the
  interval also reports `503 not_ready` (fail closed on a hung verifier)
  but recovers on the next successful pass without a restart. The success
  envelope is unchanged (`health-response-v1`) (curator-spec `dced9b8`).
- R1: `GET /v1/records` and `GET /v1/log` page envelopes now carry the
  REQUIRED `boundary` member: the complete signed snapshot object
  (`registry-snapshot-v1`, all fields including `sig`) at which the page was
  evaluated, byte-identical across one cursor chain. Envelopes validate
  against `records-response-v2` / `log-response-v2` (curator-spec `dced9b8`).
  Cursors carry that complete signed boundary, so a chain stays byte-identical
  across a staged key rotation; cursors whose boundary key has retired are
  refused with `404 invalid_cursor`. P1: a cursor page is served only at the
  cursor's carried boundary — the carried `head`/`merkle_root`/`log_size` are
  verified against the store before serving, and any disagreement, unavailable
  size, or pruned prefix is `404 invalid_cursor` with no re-evaluation at a
  newer boundary, on both endpoints (curator-spec `dced9b8`,
  `pagination.cursor_boundary_cases`).
- `genkey --force` now refuses to replace the signer of a non-empty registry.
- Corrupt log, projection, snapshot, idempotency, or import-ledger state fails
  readiness instead of truncating or repairing authoritative history.
- Private signing keys are loaded only from regular, service-private files;
  credential documents are strictly validated and atomically replaced.
- Private state now uses verified `0700`/`0600` modes on POSIX and protected
  current-service-identity DACLs on Windows; unsafe credentials fail closed.
