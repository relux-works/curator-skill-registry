# CocoaSkills Audit Registry

An audit registry service for the [CocoaSkills](https://cocoaskills.org) skill
supply chain. It serves signed statements that a skill, at a specific commit and
content hash, was audited or revoked, and it maintains an append-only
transparency log with a signed snapshot. The protocol is
[RFC 0008](https://cocoaskills.org/v0.11-design.md).

This repository is the reference implementation. Anyone can deploy it: the
public central registry runs it, and an organization runs its own instance for
a closed network. A CocoaSkills client pins the registries it trusts and
verifies every record against pinned Ed25519 keys before trusting it.

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

## Run

```bash
pip install cocoaskills-registry

# One-time: generate the signing key and register an auditor.
csk-registry --home ./data genkey
csk-registry --home ./data issue-token acme-security \
  --org "Acme Security" --public-key ed25519:<auditor-public-key>

# Serve.
csk-registry --home ./data serve --host 127.0.0.1 --port 8082
```

Or with Docker:

```bash
docker compose up -d
docker compose exec registry csk-registry --home /data genkey
```

## Endpoints

- `GET /health`
- `GET /v1/meta` registry name, public keys, schema versions, policy
- `GET /v1/records?source_identity=&commit=` or `?content_sha256=`
- `GET /v1/snapshot` signed Merkle root, size, version, timestamp
- `GET /v1/log?since=` transparency log entries
- `POST /v1/records` submit a signed record (auditor token required)

## Admin CLI

```bash
csk-registry --home ./data genkey            # generate the signing key
csk-registry --home ./data issue-token <id>  # issue an auditor token
csk-registry --home ./data sign-record       # sign a record body from stdin
csk-registry --home ./data export-snapshot   # print a signed snapshot
csk-registry --home ./data export-bundle     # export a signed bundle of all records
csk-registry --home ./data import-bundle <f> --upstream-key <k>  # import an upstream bundle
csk-registry --home ./data verify-chain      # verify the log hash chain
```

## Development

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest
mypy
```

The signing canonicalization must stay byte-identical to the CocoaSkills client
(`csk.audit_registry.canonical_bytes`): compact sorted JSON of every field
except `sig`. A cross-project test confirms the client verifies signatures this
service produces.

## License

Apache-2.0.
