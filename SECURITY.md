# Security policy

Report suspected vulnerabilities privately to `ivan@relux.works`. Include a
minimal reproducer, affected command or endpoint, and impact. Do not attach
production tokens, private signing keys, or private registry records.

The service treats HTTP bytes, auditor records, cursors, bundles, databases,
and backup checkpoints as untrusted until their applicable validation and
cryptographic checks pass. Auditor bearer tokens are stored only as SHA-256
digests and compared in constant time. The data home, signing keys, keyring,
auditor file, database, and SQLite sidecars are created with owner-only access:
`0700`/`0600` modes on POSIX and a protected, current-service-identity DACL on
Windows. State creation and private-file loading fail closed when those access
controls cannot be established or verified.

A registry signing-key compromise can authorize false records. Stop writes,
stage and distribute a new trust anchor through an independent channel,
activate it, retire the compromised key with `retire-key --compromised`, and
publish corrective records through an unaffected auditor. History is not
rewritten. An auditor compromise disables that auditor credential and uses a
different authorized auditor for corrective records.

The signing key can additionally be stored as passphrase-encrypted PKCS8
(`CSK_REGISTRY_KEY_PASSPHRASE`, see README). The passphrase protects the key
at rest against an offline copy of the volume or key file made without the
secret — a disk image, a backup, or the PEM file sitting beside
`registry.db`: without the passphrase the PEM does not decrypt, so a bare
volume leak no longer yields key and history together. It does not protect
against a live process compromise (the running service necessarily holds both
the key and the secret), nor against a deployment environment that leaks the
variable itself, and it is no substitute for the owner-only file permissions
above. The passphrase travels exclusively through the environment, never
through argv. A present-but-empty value is rejected; only true absence
selects plain PEM.

All key loads and stores funnel through the `KeyProvider` seam in
`src/csk_registry/keys.py`: the `KeyProvider` Protocol, the `FileKeyProvider`
default, and the `default_key_provider()` factory that reads the variable.
That seam is the hook point for an external key provider (KMS/HSM, profile
§7): such a provider implements the Protocol and is passed to the key
functions without touching call sites. No external provider is implemented.

Restore is fail-closed: `serve --checkpoint` (or
`CURATOR_SKILL_REGISTRY_CHECKPOINT`) compares live state against the signed
external high-water checkpoint after integrity verification and before the
service becomes ready, and a live state below or inconsistent with it stays
up non-ready with writes disabled instead of serving stale state. This
startup comparison is the normative "before the service becomes ready" gate;
`verify-backup` stays as the offline operator procedure for vetting a
candidate backup before a restore. Keep checkpoints and secret backups
outside the primary store, encrypted and access controlled. Cursor and
response data never bootstrap trust; clients pin registry keys out of band.
Pagination is fail-closed too: a cursor page is served only at the cursor's
carried boundary, and a carried boundary that disagrees with the committed
log or is no longer available is refused with `404 invalid_cursor` rather
than re-evaluated at a newer boundary.

Upstream import is fail-closed against rollback: `import-bundle` persists a
per-upstream high-water (the highest accepted upstream `version`, with
`log_size`, `head`, and `merkle_root`) in `registry.db` and refuses an old
but validly signed bundle as `import_upstream_rollback`, or an equal version
with a different body as `import_upstream_inconsistent`, instead of
re-importing it as new. Only an explicit `--accept-older-upstream` imports
an older bundle, with a warning and without lowering the stored high-water;
the inconsistent case is never overridable. Without this, an attacker
replaying a stale upstream bundle could resurrect revoked or superseded
records as fresh imports.

Health is fail-closed too: `GET /health` serves a cached integrity verdict
that a background full verifier refreshes on a bounded interval, and any
failed pass (corruption found or the walk itself failing) latches non-ready
and disables writes until a restart re-verifies — corruption found between
restarts is never served as healthy once the next pass completes. A verifier
that stops completing trips the staleness bound (twice the interval) into a
non-ready state that is transient instead of latched: the next successful
pass restores readiness automatically, while a failed pass still latches
until restart.

The complete normative threat model and deployment requirements are in the
[Curator registry-service profile](https://github.com/relux-works/curator-spec/blob/main/profiles/registry-service.md).
