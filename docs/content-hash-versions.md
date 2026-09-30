# Content-hash framing versions

Existing deployments retain their original signed v1 records and log bytes.
No history rewrite or database migration is required: absent `hash_version`
means framing version 1. The store reads the version from authoritative record
JSON, and latest-record projection includes it in the artifact key.

Version-2 records appear when Curator publishes `schema_version: 2` with
`hash_version: 2`. Both versions use `sha256:<64 lowercase hex digits>`;
the registry cannot infer framing from digest bytes or recompute a tree it
does not possess. It refuses inconsistent schema/framing declarations with
HTTP 400 `invalid_record` and the diagnostic `hash_version_mismatch`.
Frozen v1 records must not include a `hash_version` field, even with value 1.

Content queries default to version 1. Send `hash_version=2` together with
`content_sha256` to query version 2. Version filtering applies even when
source identity and commit are also supplied. Source-only queries discover
both versions; clients must check equal framing versions before matching a
record to an artifact. Supplying a version without a content hash is invalid.

Logs preserve the versioned records using `registry-log-entry-v2` and
`log-response-v3` shapes. Exports containing v2 records use bundle schema 2;
v1-only exports retain schema 1. Imports validate record declarations and
reject v2 records inside a frozen schema-1 bundle. Existing signature,
chain, Merkle, and upstream high-water checks remain in force. Upgrade
consumers to understand the new shapes before publishing v2 records.

The normative spec at `b1a2efb6fa28d014968a2a8fd7641823b5f3cf28` keeps
`registry-snapshot-v1` unchanged. Snapshots commit the versioned log through
the head and Merkle root; they do not add a top-level `hash_version`, since
a single log may contain both framing versions. Existing signed checkpoints
and pagination boundaries therefore retain their wire shape.
