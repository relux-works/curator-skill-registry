from __future__ import annotations

from typing import Any

from .signing import SigningKey
from .store import SnapshotBoundary, Store


def build_snapshot(
    store: Store,
    signing_key: SigningKey,
    *,
    boundary: SnapshotBoundary | None = None,
    created_at: str | None = None,
    version: int | None = None,
) -> dict[str, Any]:
    """Sign one immutable committed log boundary.

    The compatibility arguments are accepted only when they agree with the
    store boundary. Callers cannot refresh an old boundary's timestamp.
    """
    selected = boundary or store.snapshot_boundary()
    if created_at is not None and created_at != selected.created_at:
        raise ValueError("snapshot created_at must equal the committed boundary")
    if version is not None and version != selected.version:
        raise ValueError("snapshot version must equal the committed log size")
    body = {
        "schema_version": 1,
        "merkle_root": selected.merkle_root,
        "log_size": selected.log_size,
        "head": selected.head,
        "version": selected.version,
        "created_at": selected.created_at,
    }
    return signing_key.sign_record(body)
