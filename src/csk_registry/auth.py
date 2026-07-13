from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path

from .signing import parse_public_key


# Auditor submission is gated by a token bound to a registered signing key. A
# token is an opaque secret; the store keeps only its SHA-256, so the file at
# rest never carries a usable credential. The record itself must also verify
# against the auditor's public key, so a leaked token alone cannot forge a
# record without the auditor private key.
@dataclass(frozen=True)
class Auditor:
    auditor_id: str
    org: str
    public_pinned: str
    token_sha256: str


class AuditorTokens:
    def __init__(self, auditors: list[Auditor]) -> None:
        for auditor in auditors:
            parse_public_key(auditor.public_pinned)
            if len(auditor.token_sha256) != 64 or any(
                character not in "0123456789abcdef" for character in auditor.token_sha256
            ):
                raise ValueError(f"auditor {auditor.auditor_id!r} has an invalid token digest")
        self._by_hash = {auditor.token_sha256: auditor for auditor in auditors}

    @classmethod
    def from_file(cls, path: Path) -> "AuditorTokens":
        if not path.exists():
            return cls([])
        data = json.loads(path.read_text(encoding="utf-8"))
        auditors = [
            Auditor(
                auditor_id=item["auditor_id"],
                org=item.get("org", ""),
                public_pinned=item["public_key"],
                token_sha256=item["token_sha256"],
            )
            for item in data.get("auditors", [])
        ]
        return cls(auditors)

    def resolve(self, token: str) -> Auditor | None:
        if len(token) < 22:
            return None
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        for candidate_hash, auditor in self._by_hash.items():
            if hmac.compare_digest(candidate_hash, digest):
                return auditor
        return None
