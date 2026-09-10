# Architectural Security Audit — Curator Skill Registry Service, 2026-09-10

**Scope.** This audit covers the `curator-skill-registry` service
(FastAPI/Python, `src/csk_registry`) against the
[registry-service profile](https://github.com/relux-works/curator-spec/blob/main/profiles/registry-service.md)
and the [registry wire protocol](https://github.com/relux-works/curator-spec/blob/main/protocol/registry.md).
It is an **architectural** audit: trust boundaries, transactional semantics,
concurrency, deployment posture. A line-by-line pass follows per finding.

**Method.** The profile and wire protocol were read in full. The service was
reviewed file-by-file: `app.py`, `store.py`, `auth.py`, `keys.py`,
`signing.py`, `protocol.py`, `bundle.py`, `snapshot.py`, `limits.py`,
`permissions.py`, `cli.py`, plus `Dockerfile`/`compose.yaml` and the test
suite (unit + shared conformance vectors).

**Companion documents.** Manager-side and specification-side findings live in
`relux-works/curator/docs/security-audit-2026-09.md` and
`relux-works/curator-spec/docs/security-audit-2026-09.md`. Finding IDs are
shared.

**Remediation tracking.** Board decomposition: epic
**`EPIC-260910-16qce1` — security-audit-remediation-registry-service** on
the shared Curator board (this repository has no board of its own). The audit
document is attached to the epic as a resource. Details in
[Appendix A](#appendix-a-remediation-decomposition).

## 1. Executive summary

This is a faithful, honest implementation of the profile: signed cursors
bound to snapshot boundaries, append + idempotency committed in one
transaction, fail-closed store verification at startup, staged key rotation
with overlap, tokens stored only as digests, and platform-correct private
permissions. The principal risks are:

1. **The cross-repo composition gap (R1)**: record pages carry no boundary,
   so transparency holds only for clients that replay the log — and the
   shipped Curator client does not. The service can close its half by
   publishing the boundary it evaluated a page at.
2. **O(n) verification on every request** (R2): every records/log/snapshot
   request, every cursor validation, and every `/health` probe recomputes the
   full boundary and Merkle root; reads serialize on one lock. The service
   self-degrades as the log grows.
3. **Restore discipline is procedural** (R3): serve never refuses a
   restored-but-older database because nothing compares live state against the
   external high-water checkpoint at startup.

## 2. Confirmed strengths

- **CCJ-1 parity with the Go client** (`signing.py`): sorted keys,
  compact separators, `ensure_ascii=False`, safe-integer range, lone
  surrogate rejection, canonical base64; cross-checked by shared
  conformance vectors and a dedicated client-parity test.
- **Untrusted JSON discipline** (`protocol.py`): duplicate keys, BOM,
  floats, `NaN`/`Infinity`, `-0`, out-of-safe-range integers all rejected at
  parse time; record validation is stricter than the wire minimum.
- **Cursors** (`app.py`): signed with the active key, verified against the
  full accepted key set; bound to a digest of endpoint + query, the exact
  snapshot boundary (including `created_at`), the offset, and an expiry;
  `boundary_available` recomputes the prefix so forged/expired/foreign
  cursors fail closed as `404 invalid_cursor`.
- **Store** (`store.py`): append-only hash chain with contiguity assertion
  (`seq != previous_seq + 1`), `BEGIN IMMEDIATE` + `synchronous=FULL` +
  WAL, idempotency row + log append + response in one transaction, full
  `integrity_errors()` at startup, fail-closed legacy migrations.
- **Idempotency**: scoped by `(auditor_id, key)`, digest over
  pre-countersigned CCJ-1 bytes — exactly the client's formula; conflict →
  `409`; replay → `200` with the original response.
- **Auth** (`auth.py`): tokens stored as SHA-256 only,
  `hmac.compare_digest`, ≥22 characters (≥128 bits); submissions must also
  verify against the auditor's public key, so a leaked token without the
  private key is inert.
- **Permissions** (`permissions.py`): home/keys/keyring/auditors/DB/
  sidecars at 0600/0700 (POSIX) and verified protected DACLs (Windows,
  ctypes, verify-after-set); fail-closed when controls cannot be
  established.
- **Transport** (`cli.py`/`app.py`): plain HTTP refused off loopback,
  `--behind-https-proxy` requires `--trusted-proxy`, content-type/encoding/
  size/deadline enforcement before parsing, bounded request-body streaming.
- **Bundles** (`bundle.py`): full verification (per-record upstream
  signatures, chain, head, size, Merkle) before mutation; one-transaction
  import; fingerprint idempotence.

## 3. Findings

### R1 (service half). Records pages carry no boundary (High, cross-repo)

`records_page`/`log_page` evaluate at a committed boundary; cursors bind it;
but the response envelope never states which boundary was served. A key-holding
registry can therefore serve an honest, advancing `/v1/snapshot` while
answering `/v1/records` at an older boundary — hiding an appended `revoked`
record from clients that do not replay `/v1/log` (the shipped Curator client
does not). The protocol currently defines no boundary field; this is a joint
spec + service + client fix.

*Fix:* include the committed boundary in records/log page envelopes (per the
spec revision, task `TASK-260910-1b1ens`), and assert cursor state against
the response boundary. Tracked as `STORY-260910-3rvvxh`.

### R2. O(n) boundary recomputation on every request and health probe (Medium)

`_snapshot_boundary_locked` scans the full log prefix and rebuilds the
Merkle root for every `/v1/records` page, `/v1/log` page, `/v1/snapshot`
fetch, and every cursor validation; `integrity_errors()` re-verifies the
entire chain and canonical bytes on **every** `/health` call; all reads
serialize through one `threading.RLock`. With 10⁵–10⁶ entries the service
approaches self-inflicted DoS (compose probes `/health` every 30 s).

*Fix:* memoize `SnapshotBoundary` per `log_size` (recompute only when the
head advances); serve `/health` from a cached verdict refreshed by a
background verifier. Tracked as `STORY-260910-1py4f3`.

### R3 + P2. No serve-time comparison against the external checkpoint (Medium)

`Store.__init__` verifies internal integrity, and `verify-backup` compares a
candidate backup against a signed checkpoint — but `serve` never compares
live state against the operator's out-of-band checkpoint, so a silently
restored older database passes startup and serves stale state (clients
detect it via their own rollback state; the service does not refuse). The
profile leaves the enforcement point ambiguous (P2).

*Fix:* profile clarification (task `TASK-260910-33j1hu`) plus
`serve --checkpoint <signed snapshot>` with fail-closed comparison
(`TASK-260910-1ny7yl`). Tracked as `STORY-260910-35tbgb`.

### R4. Body read before authentication; shared proxy rate-limit bucket (Low)

`submit` streams up to 16 MiB (15 s deadline) before token verification;
the concurrency semaphore (128, 0.1 s acquire) can be occupied by
unauthenticated slow streams, producing `503 overloaded`. Bounded, but
behind a reverse proxy without trusted forwarded headers the network limiter
keys on the proxy IP, so one noisy client throttles everyone. Document the
deployment requirement (or key on forwarded client identity from trusted
proxies). Tracked with `STORY-260910-2xe3n2`.

### R5. Pathological JSON produces `500` instead of `400` (Low)

`load_json`/`_validate_ccj` are recursive; a deeply nested document raises
`RecursionError`, which the generic handler reports as
`500 internal_error` rather than `400 invalid_json`. Wrap `RecursionError`
as a `ProtocolError`. Tracked as `TASK-260910-28kmef`.

### R6. Signing key is unencrypted PEM beside the database (Low, operational)

`keys.py` stores plain PKCS8 next to `registry.db`; profile §7 permits an
external key provider but none is supported. Volume leak = key + history
together. Add optional passphrase-protected loading (secret via
environment) and document the KMS hook point. Tracked as
`STORY-260910-9484i4`.

### R7. `verify-backup` defaults to keys from the live home (Low)

When `--public-key` is omitted, verification uses the registry's own keyring
under `--home`; if the live home is compromised, so is the backup check.
Require or loudly warn on implicit key resolution. Tracked as
`TASK-260910-3u9t1e`.

### R8. Idempotency retention is exactly the 24 h minimum (Info)

`IDEMPOTENCY_TTL_SECONDS = 24*3600` meets the profile minimum ("at least 24
hours") with zero slack; a client retry at the boundary plus network delay can
double-append. Use 26 h. Tracked as `TASK-260910-2rsajv`.

### P4. Import does not compare upstream high-water (Low)

`import_bundle` verifies signatures, chain, head, size, and Merkle root, but
never compares the upstream snapshot against a persisted high-water for that
upstream key — an old but validly signed bundle imports as new. Persist a
per-upstream high-water and reject (or warn under a flag) rollback bundles.
Tracked as `STORY-260910-stz5f0`.

### Informational observations

- `AuditorTokens.resolve` is a linear constant-time scan; timing leaks only
  the auditor count.
- `records_page` uses `OFFSET` pagination on a fixed boundary (deterministic
  and correct); large offsets cost O(offset) — secondary to R2.
- SQLite creates WAL sidecars with the main file's permissions and the store
  re-protects them at init; tests confirm.
- `genkey --force` correctly refuses to replace a key for a non-empty
  registry.
- The compose healthcheck is loopback-bound; production deployments must
  terminate TLS themselves or in front of the service (CLI enforces this).

## 4. Priority summary

| # | Finding | Severity | Story / task |
|---|---|---|---|
| R1 | Records pages carry no boundary | High | `STORY-260910-3rvvxh` |
| R2 | O(n) verification per request/health | Medium | `STORY-260910-1py4f3` |
| R3+P2 | No serve-time checkpoint gate | Medium | `STORY-260910-35tbgb` |
| P4 | Import upstream high-water | Low | `STORY-260910-stz5f0` |
| R4 | Body-before-auth; proxy bucketing | Low | `STORY-260910-2xe3n2` |
| R5 | RecursionError → 500 | Low | `TASK-260910-28kmef` |
| R6 | Unencrypted key PEM | Low | `STORY-260910-9484i4` |
| R7 | verify-backup key default | Low | `TASK-260910-3u9t1e` |
| R8 | TTL without slack | Info | `TASK-260910-2rsajv` |

## 5. Code-level follow-up plan

Per accepted finding: `store.py` transactional/TOCTOU pass and the R2
memoization; `app.py` cursor and pagination edge cases; differential fuzzing
of `protocol.load_json`/`signing.canonical_bytes` against the Go
`internal/protocoljson`; deployment documentation.

---

## Appendix A. Remediation decomposition

Epic **`EPIC-260910-16qce1` — security-audit-remediation-registry-service**
on the shared Curator board (this repository shares the manager board).

| Story | Finding(s) | Tasks |
|---|---|---|
| `STORY-260910-3rvvxh` records-boundary-in-response | R1 (High) | `TASK-260910-14dnb7` service-boundary-response-fields · `TASK-260910-27yepb` service-cursor-boundary-echo |
| `STORY-260910-1py4f3` boundary-verification-performance | R2 (Medium) | `TASK-260910-35279p` service-boundary-memoization · `TASK-260910-3p2rbh` service-health-cached-verdict |
| `STORY-260910-35tbgb` serve-time-checkpoint-gate | R3+P2 (Medium) | `TASK-260910-33j1hu` spec-restore-enforcement-point · `TASK-260910-1ny7yl` service-serve-checkpoint-flag |
| `STORY-260910-2xe3n2` registry-robustness-hardening | R4, R5, R7, R8 | `TASK-260910-28kmef` service-recursionerror-400 · `TASK-260910-2rsajv` service-idempotency-ttl-slack · `TASK-260910-3u9t1e` service-verify-backup-explicit-key · `TASK-260910-2c7s0u` service-deployment-rate-limit-docs |
| `STORY-260910-9484i4` registry-key-management | R6 | `TASK-260910-s9jz1g` service-key-passphrase-support |
| `STORY-260910-stz5f0` import-upstream-high-water | P4 | `TASK-260910-2g5v17` service-import-high-water |

The client and specification halves of R1 are tracked in epic
`EPIC-260910-2hw1xb` (stories `STORY-260910-25yc0h` and
`STORY-260910-2awkzu` et al.; see the manager audit document).
