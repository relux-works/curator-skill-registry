# Curator Skill Registry

An implementation of the open
[Curator Protocol registry profile](https://github.com/relux-works/curator-spec/blob/main/protocol/registry.md).
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
- Records append to a hash-chained log. The latest record for an artifact wins,
  so a revocation supersedes an earlier audit.
- A signed snapshot commits to the log head with a monotonic version, so a
  client detects a rolled-back or withheld view.
- Submission requires an auditor token bound to a registered key, and the record
  must verify against that key.
- Signed pagination cursors are query-bound; repeated submissions are
  transactionally idempotent for at least 24 hours.
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
  `limit`, `cursor`, and `next_cursor`
- `GET /v1/snapshot` signed Merkle root, size, version, timestamp
- `GET /v1/log?since=` paginated transparency log entries
- `POST /v1/records` submit a signed record (auditor token required;
  `Idempotency-Key` supported)

Every error uses the stable Curator error envelope. Production instances use
HTTPS; plain HTTP is reserved for explicitly configured loopback deployments.

## Admin CLI

```bash
curator-skill-registry --home ./data genkey            # generate the signing key
curator-skill-registry --home ./data issue-token <id>  # issue an auditor token
curator-skill-registry --home ./data sign-record       # sign a record body from stdin
curator-skill-registry --home ./data export-snapshot   # print a signed snapshot
curator-skill-registry --home ./data export-bundle     # export a signed bundle of all records
curator-skill-registry --home ./data import-bundle <f> --upstream-key <k>  # import a bundle
curator-skill-registry --home ./data verify-chain      # verify the log hash chain
```

`CURATOR_SKILL_REGISTRY_HOME` sets the default data directory. During the 0.x
migration, the former `csk-registry` command and `CSK_REGISTRY_HOME` variable
remain supported as compatibility aliases; the new names take precedence.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest
mypy
```

CI checks out the authoritative specification suite and verifies CCJ-1 bytes,
signed objects, chain/Merkle commitments, and authenticated bundle imports on
Linux, macOS, and Windows.

## License

Apache-2.0.
