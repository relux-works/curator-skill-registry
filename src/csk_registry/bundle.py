from __future__ import annotations

import hashlib
import json
from typing import Any

from .clock import utc_now
from .protocol import validate_record, validate_snapshot
from .signing import SigningKey, canonical_bytes, parse_public_key, verify_signed
from .snapshot import build_snapshot
from .store import Store


# Air-gapped federation. A registry exports a signed bundle of every record it
# serves, together with its signed snapshot. An offline registry imports the
# bundle, verifies it against the upstream registry's pinned key, then
# countersigns each record with its own key so its own clients verify against
# its own key.


def export_bundle(store: Store, signing_key: SigningKey) -> dict[str, Any]:
    entries = store.log_entries()
    records = [entry.record for entry in entries]
    snapshot = build_snapshot(store, signing_key, created_at=utc_now(), version=store.head()[0])
    return {
        "schema_version": 1,
        "records": records,
        "snapshot": snapshot,
        "public_key": signing_key.public_pinned,
    }


def import_bundle(
    store: Store,
    signing_key: SigningKey,
    bundle: dict[str, Any],
    *,
    upstream_public_key: str,
) -> int:
    """Verify an upstream bundle and countersign its records locally.

    The snapshot must verify against the upstream key, and every record must
    verify against that same key. Each imported record is countersigned with
    the local key so local clients verify against the local registry.
    Returns the number of records imported.
    """
    if not isinstance(bundle, dict) or set(bundle) - {"schema_version", "records", "snapshot", "public_key"}:
        raise ValueError("bundle contains unsupported fields")
    if bundle.get("schema_version") != 1:
        raise ValueError("bundle schema_version must be 1")
    snapshot = validate_snapshot(bundle.get("snapshot"))
    if not verify_signed(upstream_public_key, snapshot):
        raise ValueError("bundle snapshot does not verify against the upstream key")
    embedded_key = bundle.get("public_key")
    if embedded_key is not None:
        if not isinstance(embedded_key, str) or parse_public_key(embedded_key) != parse_public_key(upstream_public_key):
            raise ValueError("bundle public_key does not match the pinned upstream key")
    records = bundle.get("records")
    if not isinstance(records, list):
        raise ValueError("bundle is missing records")
    verified: list[dict[str, Any]] = []
    entry_hashes: list[bytes] = []
    previous = "0" * 64
    for record in records:
        checked = validate_record(record)
        if not verify_signed(upstream_public_key, checked):
            raise ValueError(f"bundle record for {record.get('name')!r} does not verify against the upstream key")
        entry_hash = hashlib.sha256(previous.encode("ascii") + canonical_bytes(checked)).hexdigest()
        previous = entry_hash
        entry_hashes.append(bytes.fromhex(entry_hash))
        verified.append(checked)
    if snapshot["log_size"] != len(verified) or snapshot["head"] != previous:
        raise ValueError("bundle records do not match the snapshot log head or size")
    if snapshot["merkle_root"] != _merkle_root(entry_hashes):
        raise ValueError("bundle records do not match the snapshot Merkle root")

    imports: list[tuple[str, dict[str, Any]]] = []
    for record in verified:
        endorsement = {"endorser": "upstream-import", "sig": record.get("sig")}
        body = {key: value for key, value in record.items() if key != "sig"}
        existing = body.get("endorsements")
        body["endorsements"] = ([*existing, endorsement] if isinstance(existing, list) else [endorsement])
        signature = record["sig"]["signature"]
        fingerprint_body = [
            record["source_identity"],
            record["commit"],
            record["content_sha256"],
            record["status"],
            signature,
        ]
        fingerprint = hashlib.sha256(
            json.dumps(fingerprint_body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        imports.append((fingerprint, signing_key.sign_record(body)))
    return store.append_imports(imports, created_at=utc_now())


def _merkle_root(leaves: list[bytes]) -> str:
    if not leaves:
        return "0" * 64
    level = leaves
    while len(level) > 1:
        next_level: list[bytes] = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            next_level.append(hashlib.sha256(left + right).digest())
        level = next_level
    return level[0].hex()
