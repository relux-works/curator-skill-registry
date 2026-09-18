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

- R4: documented the reverse-proxy deployment the rate-limit and body bounds
  assume (docs only, no wire-schema change, curator-spec `47c3c8c`).
  `README.md` § Production transport and limits now states the rate-limit
  model (network limiter on client host, 600/minute; concurrency semaphore,
  128 slots with 0.1 s acquire; auditor limiter on auditor id,
  120/minute), that a proxy without trusted forwarded headers collapses all
  clients into one shared network bucket, and the recommended configuration
  (`serve --behind-https-proxy --trusted-proxy <proxy IPs>`, forwarded
  headers from other sources ignored) with a worked nginx snippet. The same
  section states the body-before-auth squatting bounds (16 MiB, 15 s
  deadline, `503 overloaded` semantics), the proxy-side mitigations (body,
  connection, and timeout caps), and an operator checklist. `SECURITY.md`
  points at that section from the threat model.
- P4: `import-bundle` now persists a per-upstream high-water (`version`,
  `log_size`, `head`, `merkle_root` per upstream `key_id`) in a new
  `upstream_high_water` table (schema version 4, migrated once at startup)
  and compares every verified bundle against it under the client §5
  rollback rules. A version below refuses with `import_upstream_rollback`;
  an equal version with a different `head`/`merkle_root`/`log_size` refuses
  with `import_upstream_inconsistent`; an equal identical boundary is an
  accepted no-op; a higher version imports and advances the stored boundary
  in the same transaction as the imported records. Refusals exit non-zero
  naming the upstream `key_id` and both boundaries, and the `import_bundle`
  audit event records the compared boundaries and the outcome.
  `--accept-older-upstream` imports an older bundle with a warning without
  lowering the high-water; the inconsistent case is never overridable. No
  protocol or wire change; the table ships inside `registry.db` (so
  `backup` copies it) and is not compared by `verify-backup` (curator-spec
  `dced9b8`, implementation detail).
- R6: optional passphrase-protected signing key via `CSK_REGISTRY_KEY_PASSPHRASE`
  (environment only, never a CLI flag). When set, `genkey`, rotation
  staging, and rotation activation write encrypted PKCS8 PEM
  (`BestAvailableEncryption`) and every key load decrypts with it; when
  unset, behaviour is unchanged. An encrypted key with the variable missing
  or wrong fails closed with a single diagnostic naming the variable (no
  traceback, no partial start); a plain key with the variable set loads
  with an unencrypted-key warning; a present-but-empty variable is rejected
  with a single diagnostic before any key write or load. Key loading and storing
  funnel through the `csk_registry.keys.KeyProvider` seam (`FileKeyProvider`
  default, `default_key_provider()` factory), documented in `SECURITY.md` as
  the KMS hook point; no external provider is implemented. No protocol,
  envelope, or key-material change (curator-spec `dced9b8`).
- R7: `verify-backup` without `--public-key` now warns prominently instead of
  silently trusting the live home's keyring: it prints `WARNING: keys
  resolved from the live home <path>; supply --public-key from an out-of-band
  copy for an independent check` on stderr and records the same text in the
  `warning` member of the JSON result on both the `backup_valid: true` and
  `backup_valid: false` envelopes. The verdict and exit codes are unchanged
  (still `0`/`2`), and the `--public-key` path emits no warning and keeps its
  exact previous envelopes. Operators should pass the registry's pinned
  public key from an out-of-band copy kept with the checkpoint outside the
  primary store. No wire-schema change (curator-spec `47c3c8c`).
- R8: idempotency retention raised from 24 h to 26 h
  (`IDEMPOTENCY_TTL_SECONDS`): the registry-service profile §4 minimum is
  "at least 24 hours from the first successful commit", and the two extra
  hours of slack keep a client retry at the 24 h contract boundary, plus
  network delay, deduplicated instead of double-appending. The store still
  refuses any retention below the 24 h profile minimum, and the success,
  replay (`200`), and conflict (`409`) envelopes are unchanged (curator-spec
  `dced9b8`).
- R5: JSON nested deeper than 100 levels is rejected with `400 invalid_json`
  instead of `500 internal_error`. `protocol.load_json` enforces the bound
  with an iterative pre-parse scan and maps `RecursionError` to the new
  `JSONDepthError` (`ProtocolError`); the CCJ canonicalization entry points
  enforce the same bound and map `RecursionError` to `CanonicalDepthError`.
  `POST /v1/records` reports depth violations as `invalid_json` while other
  record errors keep `invalid_record`, and over-deep cursors keep
  `404 invalid_cursor`. No wire-schema change (curator-spec `47c3c8c`).
- R3/P2: `serve --checkpoint <signed snapshot>`
  (`CURATOR_SKILL_REGISTRY_CHECKPOINT`) compares the live boundary against
  the operator checkpoint at startup, after the §5 integrity verification
  and before the listener binds or `/health` can report ready. The
  checkpoint signature is verified first against the accepted
  (staged-rotation) keys; a live version below the checkpoint refuses with
  `restore_below_checkpoint`, an equal version with a different `head`,
  `merkle_root`, or `log_size` — or a live state above the checkpoint whose
  log does not reproduce the checkpoint boundary at its `log_size` — refuses
  with `restore_inconsistent_with_checkpoint`, and a bad signature refuses
  with `checkpoint_signature_invalid`. A refusal stays up non-ready
  (`/health` 503 carrying the diagnostic code, writes 503) without
  truncating or repairing history; without a checkpoint the
  `startup_checkpoint` audit event (stderr, structured) records
  `checkpoint_not_configured`, otherwise the compared checkpoint/live
  boundaries (`version`, `log_size`, `head`) and the outcome. `verify-backup`
  stays as the offline vetting
  procedure; the startup comparison is the normative readiness gate. The
  `health-response-v1` success envelope is unchanged (curator-spec
  `47c3c8c`).
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
