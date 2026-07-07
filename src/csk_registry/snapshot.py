from __future__ import annotations

from typing import Any

from .signing import SigningKey
from .store import Store


def build_snapshot(store: Store, signing_key: SigningKey, *, created_at: str, version: int) -> dict[str, Any]:
    """A signed commitment to the log head: Merkle root, size, version, time.

    The version is monotonic; a client refuses a snapshot whose version moved
    backward, which detects a rolled-back view.
    """
    size, head = store.head()
    body = {
        "schema_version": 1,
        "merkle_root": store.merkle_root(),
        "log_size": size,
        "head": head,
        "version": version,
        "created_at": created_at,
    }
    return signing_key.sign_record(body)
