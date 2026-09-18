from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from .clock import utc_now
from .protocol import validate_record, validate_snapshot
from .signing import SigningKey, canonical_bytes, parse_public_key, verify_signed
from .snapshot import build_snapshot
from .store import (
    IMPORT_UPSTREAM_INCONSISTENT,
    IMPORT_UPSTREAM_ROLLBACK,
    Store,
    UpstreamHighWater,
    UpstreamHighWaterConflict,
)


# Air-gapped federation. A registry exports a signed bundle of every record it
# serves, together with its signed snapshot. An offline registry imports the
# bundle, verifies it against the upstream registry's pinned key, then
# countersigns each record with its own key so its own clients verify against
# its own key.
#
# The closed import diagnostics live in the store module (re-exported here),
# because the store performs the authoritative high-water comparison inside
# its serialized write transaction.

__all__ = [
    "IMPORT_UPSTREAM_INCONSISTENT",
    "IMPORT_UPSTREAM_ROLLBACK",
    "UpstreamInconsistentError",
    "UpstreamRollbackError",
    "export_bundle",
    "import_bundle",
]

_AUDIT_LOG = logging.getLogger("csk_registry.audit")


class UpstreamRollbackError(ValueError):
    """An upstream bundle is below the persisted high-water for its key."""

    def __init__(
        self,
        key_id: str,
        persisted: UpstreamHighWater,
        offered: dict[str, Any],
    ) -> None:
        self.diagnostic = IMPORT_UPSTREAM_ROLLBACK
        self.key_id = key_id
        self.persisted = persisted
        self.offered = offered
        super().__init__(
            f"{IMPORT_UPSTREAM_ROLLBACK}: upstream {key_id} offered version "
            f"{offered['version']} below persisted version {persisted.version} "
            f"(persisted version={persisted.version} log_size={persisted.log_size} "
            f"head={persisted.head} merkle_root={persisted.merkle_root}; "
            f"offered version={offered['version']} log_size={offered['log_size']} "
            f"head={offered['head']} merkle_root={offered['merkle_root']})"
        )


class UpstreamInconsistentError(ValueError):
    """An upstream bundle matches the high-water version with another body."""

    def __init__(
        self,
        key_id: str,
        persisted: UpstreamHighWater,
        offered: dict[str, Any],
    ) -> None:
        self.diagnostic = IMPORT_UPSTREAM_INCONSISTENT
        self.key_id = key_id
        self.persisted = persisted
        self.offered = offered
        super().__init__(
            f"{IMPORT_UPSTREAM_INCONSISTENT}: upstream {key_id} offered version "
            f"{offered['version']} with a different body than persisted "
            f"(persisted version={persisted.version} log_size={persisted.log_size} "
            f"head={persisted.head} merkle_root={persisted.merkle_root}; "
            f"offered version={offered['version']} log_size={offered['log_size']} "
            f"head={offered['head']} merkle_root={offered['merkle_root']})"
        )


def export_bundle(store: Store, signing_key: SigningKey) -> dict[str, Any]:
    entries = store.log_entries()
    records = [entry.record for entry in entries]
    snapshot = build_snapshot(store, signing_key)
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
    accept_older_upstream: bool = False,
) -> int:
    """Verify an upstream bundle and countersign its records locally.

    The snapshot must verify against the upstream key, and every record must
    verify against that same key. Each imported record is countersigned with
    the local key so local clients verify against the local registry.
    Returns the number of records imported.

    After bundle verification, the offered upstream snapshot is compared
    against the persisted per-upstream high-water for the upstream ``key_id``
    under the client §5 rollback rules: a version below refuses with
    ``import_upstream_rollback`` (or imports with a warning under
    ``accept_older_upstream`` without lowering the high-water); an equal
    version with a different ``head``/``merkle_root``/``log_size`` refuses
    with ``import_upstream_inconsistent`` and is never overridable; an equal
    identical boundary is a no-op; a higher version imports and advances the
    high-water in the same transaction as the imported records. The comparison
    is authoritative: it runs inside the store's serialized write transaction
    against the latest committed high-water, so a concurrent import that
    commits first decides the outcome with the same diagnostics, override
    policy and audit event as the ordinary path.
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

    key_id = _upstream_key_id(upstream_public_key)
    offered = {
        "version": snapshot["version"],
        "log_size": snapshot["log_size"],
        "head": snapshot["head"],
        "merkle_root": snapshot["merkle_root"],
    }
    imports = _countersign_imports(signing_key, verified)
    now = utc_now()
    advance = UpstreamHighWater(
        key_id=key_id,
        version=int(offered["version"]),
        log_size=int(offered["log_size"]),
        head=str(offered["head"]),
        merkle_root=str(offered["merkle_root"]),
        updated_at=now,
    )
    try:
        result = store.append_upstream_import(
            imports,
            created_at=now,
            offered=advance,
            accept_older_upstream=accept_older_upstream,
        )
    except UpstreamHighWaterConflict as exc:
        _log_import_refused(key_id, exc.persisted, offered, exc.diagnostic)
        if exc.diagnostic == IMPORT_UPSTREAM_INCONSISTENT:
            raise UpstreamInconsistentError(key_id, exc.persisted, offered) from exc
        raise UpstreamRollbackError(key_id, exc.persisted, offered) from exc
    if result.outcome == "accepted_older":
        # Explicit operator override: import without lowering the high-water.
        _log_import_outcome(
            key_id,
            result.persisted,
            offered,
            result="ok",
            imported=result.imported,
            refused=False,
            warning=IMPORT_UPSTREAM_ROLLBACK,
            accepted_older=True,
        )
    elif result.outcome == "noop":
        # Identical re-import: accepted with nothing persisted.
        _log_import_outcome(
            key_id,
            result.persisted,
            offered,
            result="noop",
            imported=result.imported,
            refused=False,
        )
    else:
        _log_import_outcome(
            key_id, result.persisted, offered, result="ok", imported=result.imported, refused=False
        )
    return result.imported


def _countersign_imports(
    signing_key: SigningKey, verified: list[dict[str, Any]]
) -> list[tuple[str, dict[str, Any]]]:
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
    return imports


def _upstream_key_id(upstream_public_key: str) -> str:
    return hashlib.sha256(parse_public_key(upstream_public_key)).hexdigest()[:16]


def _persisted_summary(persisted: UpstreamHighWater | None) -> dict[str, Any] | None:
    if persisted is None:
        return None
    return {
        "version": persisted.version,
        "log_size": persisted.log_size,
        "head": persisted.head,
        "merkle_root": persisted.merkle_root,
    }


def _log_import_refused(
    key_id: str,
    persisted: UpstreamHighWater,
    offered: dict[str, Any],
    diagnostic: str,
) -> None:
    event = {
        "event": "import_bundle",
        "key_id": key_id,
        "persisted": _persisted_summary(persisted),
        "offered": dict(offered),
        "result": "refused",
        "diagnostic": diagnostic,
    }
    _AUDIT_LOG.warning("%s", json.dumps(event, sort_keys=True, separators=(",", ":")))


def _log_import_outcome(
    key_id: str,
    persisted: UpstreamHighWater | None,
    offered: dict[str, Any],
    *,
    result: str,
    imported: int,
    refused: bool,
    warning: str | None = None,
    accepted_older: bool = False,
) -> None:
    event: dict[str, Any] = {
        "event": "import_bundle",
        "key_id": key_id,
        "persisted": _persisted_summary(persisted),
        "offered": dict(offered),
        "result": result,
        "imported": imported,
    }
    if warning is not None:
        event["warning"] = warning
    if accepted_older:
        event["accepted_older"] = True
    message = json.dumps(event, sort_keys=True, separators=(",", ":"))
    if refused or warning is not None:
        _AUDIT_LOG.warning("%s", message)
    else:
        _AUDIT_LOG.info("%s", message)


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
