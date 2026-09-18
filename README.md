# Curator Skill Registry

An implementation of the open
[Curator Protocol registry profile](https://github.com/relux-works/curator-spec/blob/main/profiles/registry-service.md).
It serves signed statements that a skill at a specific commit and content hash
was audited or revoked, and maintains an append-only transparency log with a
signed snapshot.

Anyone can deploy it on a public or closed network. A conforming Curator client
pins the registries it trusts and verifies every record against out-of-band
Ed25519 keys before trusting it.

## Model

- A record names an artifact (`name`, `source_identity`, `commit`,
  `content_sha256`), a status (`audited`, `revoked`, `deprecated`, `pending`),
  audit metadata, and an Ed25519 signature.
- Records append to a hash-chained log. Artifact identity includes name, source,
  commit, and content hash, so conflicting content remains visible.
- A signed snapshot commits to the log head with a monotonic version, so a
  client detects a rolled-back or withheld view.
- Submission requires an auditor token bound to a registered key, and the record
  must verify against that key.
- Signed pagination cursors bind the query to one immutable snapshot boundary;
  concurrent appends cannot duplicate, omit, replace, or reorder later pages.
  Every records and log page states that boundary in its signed `boundary`
  member, byte-identical across one cursor chain. A cursor page is served only
  at its carried boundary: a carried boundary that disagrees with the store or
  is no longer available is refused with `404 invalid_cursor`, never
  re-evaluated at a newer boundary.
- Log append, snapshot state, and auditor-scoped idempotency commit in one
  serialized durable transaction. Startup fails closed on chain or ledger
  corruption.
- Offline bundles are accepted only after signatures, log chain, head, size,
  and Merkle root all match the pinned upstream snapshot.

## Run

```bash
pip install curator-skill-registry

# One-time: generate the signing key and register an auditor.
curator-skill-registry --home ./data genkey
curator-skill-registry --home ./data issue-token acme-security \
  --org "Acme Security" --public-key ed25519:<auditor-public-key>

# Serve.
curator-skill-registry --home ./data serve --host 127.0.0.1 --port 8082
```

Or with Docker:

```bash
docker compose up -d
docker compose exec registry curator-skill-registry --home /data genkey
```

## Endpoints

- `GET /health`
- `GET /v1/meta` registry name, public keys, schema versions, policy
- `GET /v1/records?source_identity=&commit=` or `?content_sha256=` with
  `limit`, `cursor`, and `next_cursor`; every page carries the signed
  `boundary` snapshot it was evaluated at
- `GET /v1/snapshot` signed Merkle root, size, version, timestamp
- `GET /v1/log?since=` paginated transparency log entries, each page carrying
  its signed `boundary`
- `POST /v1/records` submit a signed record (auditor token required;
  `Idempotency-Key` supported)

Every error uses the stable Curator error envelope. Production instances use
HTTPS; plain HTTP is reserved for explicitly configured loopback deployments.

## Admin CLI

```bash
curator-skill-registry --home ./data genkey            # generate the signing key
curator-skill-registry --home ./data issue-token <id>  # issue an auditor token
curator-skill-registry --home ./data prepare-key-rotation
curator-skill-registry --home ./data activate-key-rotation --confirm-pins-deployed
curator-skill-registry --home ./data retire-key <old-key-id> --confirm-overlap-elapsed
curator-skill-registry --home ./data sign-record       # sign a record body from stdin
curator-skill-registry --home ./data export-snapshot   # print a signed snapshot
curator-skill-registry --home ./data export-bundle     # export a signed bundle of all records
curator-skill-registry --home ./data import-bundle <f> --upstream-key <k>  # import a bundle
curator-skill-registry --home ./data verify-chain      # verify the log hash chain
curator-skill-registry --home ./data backup \
  --out /backups/registry.db --checkpoint-out /backups/registry-snapshot.json
curator-skill-registry --home ./data verify-backup /backups/registry.db \
  --checkpoint /secure-high-water/registry-snapshot.json
```

`backup` uses SQLite's consistent backup API and emits a signed snapshot
checkpoint. Keep the latest checkpoint outside the primary store. Before
restoring, run `verify-backup` against that external high-water checkpoint; an
older or equivocal database is refused. Stop all writers before replacing the
live database. Signing keys and `auditors.json` are backed up separately using
encrypted, access-controlled secret storage.

### Startup checkpoint gate

`verify-backup` is the offline procedure for vetting a backup before a
restore. The normative enforcement of "before the service becomes ready" is
the startup checkpoint comparison: pass the operator checkpoint to `serve`
and the service compares live state against it after integrity verification
and before the listener binds or `/health` can report ready.

```bash
curator-skill-registry --home ./data serve --checkpoint /secure-high-water/registry-snapshot.json
# or: CURATOR_SKILL_REGISTRY_CHECKPOINT=/secure-high-water/registry-snapshot.json
```

The file is a signed `registry-snapshot-v1` object, verified against the
accepted signing keys (the staged-rotation set). Produce it with
`backup --checkpoint-out` alongside a consistent database backup, or with
`export-snapshot` for the live boundary; keep it outside the primary store,
encrypted and access controlled. To rotate it, write the new checkpoint and
restart `serve` against it — the comparison runs once at startup. Re-issue
the checkpoint (re-export the live boundary) before retiring an old signing
key, otherwise a checkpoint signed by the retired key refuses with
`checkpoint_signature_invalid`.

A live version below the checkpoint refuses with
`restore_below_checkpoint`; an equal version with a different `head`,
`merkle_root`, or `log_size`, or a live state above the checkpoint whose log
does not reproduce the checkpoint boundary at its `log_size`, refuses with
`restore_inconsistent_with_checkpoint`. A refusal stays up non-ready:
`/health` reports `503` with the diagnostic code, writes report `503`, and
history is never truncated or repaired — recover the missing verified suffix
or remain unavailable. Without `--checkpoint` the service starts as before
and records `checkpoint_not_configured` in the `startup_checkpoint` audit
event; with one, that event carries the compared checkpoint/live boundaries
(`version`, `log_size`, `head`) and the outcome. The event is emitted to
stderr as structured JSON (refusals at WARNING, posture and success at INFO)
before the server configures logging, so it is visible in production output.

### Signing-key rotation

Rotation is staged so clients never see an unannounced signer and live cursors
survive the change:

1. Run `prepare-key-rotation`. The service keeps signing with the old key and
   publishes the old and staged public keys.
2. Distribute that expanded pin set out of band and verify client rollout.
3. Run `activate-key-rotation --confirm-pins-deployed`. New records and
   snapshots use the new key; the old public key remains available for overlap
   verification and existing cursors.
4. After the client overlap and one-hour cursor-retention window, run
   `retire-key <old-key-id> --confirm-overlap-elapsed`. Use `--compromised`
   instead when incident response requires immediate removal.

`cancel-key-rotation --confirm` discards a staged key before activation.
`genkey --force` refuses to replace the signer of a non-empty registry.

### Passphrase-protected signing key

The signing key can be stored as passphrase-encrypted PKCS8 instead of plain
PEM. Set the passphrase before generating the key:

```bash
export CSK_REGISTRY_KEY_PASSPHRASE='<secret>'
curator-skill-registry --home ./data genkey
```

When the variable is set, `genkey`, rotation staging, and rotation
activation write encrypted PEM (`BestAvailableEncryption`), and every command
plus `serve` decrypts with it. There is deliberately no `--passphrase` flag:
process arguments are world-readable on most systems.

- Encrypted key with the variable missing or wrong: the command (or `serve`
  startup) fails closed with a single diagnostic naming the variable;
  nothing starts.
- Plain key with the variable set: still loads, so an existing deployment
  keeps working while it migrates, but logs a warning that the key is
  unencrypted.
- Variable set but empty: rejected with a single diagnostic naming the
  variable before any key is written or loaded; unset it for plain PEM or
  set a non-empty value.
- Variable unset: behaviour is exactly as before (plain PEM written and read).

Encrypt an existing plain key in place (same key material; the file keeps its
`0600` mode):

```bash
export CSK_REGISTRY_KEY_PASSPHRASE='<secret>'
python - <<'EOF'
import os
from pathlib import Path
from csk_registry import signing
path = Path("./data/signing-key.pem")
key = signing.load_key(path.read_bytes())
path.write_bytes(signing.export_key_pem(key, os.environ["CSK_REGISTRY_KEY_PASSPHRASE"].encode()))
print("encrypted:", key.key_id)
EOF
```

Rotate the passphrase by re-encrypting with the new value (same key material,
new secret):

```bash
export OLD_PASSPHRASE='<old secret>' CSK_REGISTRY_KEY_PASSPHRASE='<new secret>'
python - <<'EOF'
import os
from pathlib import Path
from csk_registry import signing
path = Path("./data/signing-key.pem")
key = signing.load_key(path.read_bytes(), passphrase=os.environ["OLD_PASSPHRASE"].encode())
path.write_bytes(signing.export_key_pem(key, os.environ["CSK_REGISTRY_KEY_PASSPHRASE"].encode()))
print("re-encrypted:", key.key_id)
EOF
```

After either operation, re-run any key command (for example
`export-snapshot`) to confirm the new secret decrypts, and if a rotation is
staged, re-encrypt `next-signing-key.pem` the same way. See `compose.yaml`
for wiring the secret without baking it into the image, and [SECURITY.md](SECURITY.md)
for what the passphrase does and does not protect.

### Production transport and limits

Plain HTTP is accepted only on a loopback bind. For direct TLS, pass
`--ssl-certfile` and `--ssl-keyfile`. A non-loopback service behind an HTTPS
reverse proxy requires `--behind-https-proxy --trusted-proxy <ip-list>`;
forwarded headers from other sources are ignored.

The process caps concurrent work, network-source request rate, auditor
submission rate, page size, cursor size, and request bodies. `429` and overload
`503` responses include `Retry-After`. The following settings accept positive
integers:

```text
CURATOR_SKILL_REGISTRY_MAX_CONCURRENT_REQUESTS
CURATOR_SKILL_REGISTRY_NETWORK_REQUESTS_PER_MINUTE
CURATOR_SKILL_REGISTRY_AUDITOR_SUBMISSIONS_PER_MINUTE
```

Run one writable service process per database on local durable storage. SQLite
uses WAL, `synchronous=FULL`, a five-second lock deadline, serialized append
transactions, a 30-second operation deadline, and startup integrity
verification. Request-body streaming has a 15-second deadline. Do not place the
database on a network filesystem or run writable replicas without an external
single-copy serialization layer. Put reverse-proxy request deadlines and
connection limits in front of the finite application and database limits.

The `csk_registry.audit` logger emits one bounded JSON event per request with
status, stable error code, latency, authentication outcome, auditor identity,
idempotency outcome, and committed sequence. It never records bearer tokens,
authorization headers, submitted records, or query values. Route this logger to
access-controlled retention appropriate for your deployment.

`CURATOR_SKILL_REGISTRY_HOME` sets the default data directory. During the 0.x
migration, the former `csk-registry` command and `CSK_REGISTRY_HOME` variable
remain supported as compatibility aliases; the new names take precedence.

Before upgrading a database created by a release that stored idempotency keys
without auditor identity, stop submissions for the prior 24-hour retention
window. Startup refuses unexpired unscoped entries because assigning them to an
auditor would be ambiguous. Expired entries are discarded while the schema is
migrated; log history is unchanged.

Schema version 3 adds two cache tables, `boundaries` (one memoized
`(log_size, head, merkle_root, created_at)` row per committed prefix) and
`merkle_frontier` (the O(log n) incremental-tree state for appends). The first
startup on an older database creates both tables and backfills them from the
log in one idempotent pass as part of startup verification; the memoized rows
are revalidated against the recomputed chain on every startup, and any
disagreement fails readiness. Reopening the database retries an interrupted
migration without changing log history. Expect the first post-upgrade startup
to take longer on large logs (one chain walk plus incremental Merkle work);
steady-state startups revalidate without rewriting, and per-request reads are
single-row lookups.

`GET /health` serves a cached integrity verdict, so probes stay cheap no
matter how large the log grows. A background verifier re-verifies the full
chain, the idempotency/import ledgers, and the boundary-cache agreement every
`--health-verify-interval` seconds (default 300;
`CURATOR_SKILL_REGISTRY_HEALTH_VERIFY_INTERVAL` when the flag is absent),
reading through its own connection so a pass never blocks appends; each
append advances the verified head incrementally. Size the interval
comfortably above the full-walk duration of your log — time
`curator-skill-registry --home <dir> verify-chain` as a proxy for one pass.
A pass that has not completed within twice the interval makes `/health`
report `503 not_ready`, so a hung verifier can never leave a green verdict
forever. Staleness is transient: the next successful pass restores readiness
and writes automatically (check the `health_refresh` audit events for
outcome, duration, and log size; raise the interval if passes routinely
overrun it). A `503 not_ready` caused by corruption or a failed pass latches
instead — readiness and writes stay disabled until a restart re-verifies;
repair the store offline first, since history is never truncated or
rewritten automatically. Writes refused while non-ready report `503
storage_unavailable`.

Private state is fail-closed. On POSIX, the data home is `0700` and private
files are `0600`. On Windows, the service replaces inherited permissions with
a protected DACL that grants full access only to the current service identity;
child state inherits that identity-only policy. Signing keys and auditor files
are rejected if their type or access controls are unsafe, and every write is
verified after replacement. The database and its SQLite sidecars are likewise
created private. Use local durable storage whose filesystem supports native
POSIX modes or Windows ACLs; do not place the data home on a filesystem that
cannot preserve and enforce them.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest
mypy
```

CI checks out the authoritative specification suite and verifies CCJ-1 bytes,
signed objects, stable pagination, concurrent append, scoped idempotency,
recovery, restore checkpoints, the startup checkpoint comparison, key
rotation, resource controls, chain/Merkle commitments, and authenticated
bundle imports on Linux, macOS, and Windows.

See [SECURITY.md](SECURITY.md) for private reporting and incident boundaries,
and [CHANGELOG.md](CHANGELOG.md) for behavior and compatibility changes.

## License

Apache-2.0.
