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

- `genkey --force` now refuses to replace the signer of a non-empty registry.
- Corrupt log, projection, snapshot, idempotency, or import-ledger state fails
  readiness instead of truncating or repairing authoritative history.
- Private signing keys are loaded only from regular, service-private files;
  credential documents are strictly validated and atomically replaced.
