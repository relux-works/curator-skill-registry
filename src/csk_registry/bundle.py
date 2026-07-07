from __future__ import annotations

from typing import Any

from .clock import utc_now
from .signing import SigningKey, canonical_bytes, verify
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
    snapshot = bundle.get("snapshot")
    if not isinstance(snapshot, dict):
        raise ValueError("bundle is missing a snapshot")
    if not verify(upstream_public_key, canonical_bytes(snapshot), _sig(snapshot)):
        raise ValueError("bundle snapshot does not verify against the upstream key")
    records = bundle.get("records")
    if not isinstance(records, list):
        raise ValueError("bundle is missing records")
    imported = 0
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("bundle record must be an object")
        if not verify(upstream_public_key, canonical_bytes(record), _sig(record)):
            raise ValueError(f"bundle record for {record.get('name')!r} does not verify against the upstream key")
        endorsement = {"endorser": "upstream-import", "sig": record.get("sig")}
        body = {key: value for key, value in record.items() if key != "sig"}
        existing = body.get("endorsements")
        body["endorsements"] = ([*existing, endorsement] if isinstance(existing, list) else [endorsement])
        store.append(signing_key.sign_record(body), created_at=utc_now())
        imported += 1
    return imported


def _sig(obj: dict[str, Any]) -> str:
    sig = obj.get("sig")
    if not isinstance(sig, dict):
        raise ValueError("object is not signed")
    signature = sig.get("signature")
    if not isinstance(signature, str):
        raise ValueError("object is not signed")
    return signature
