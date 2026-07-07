from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


# The canonical signing form must match the CocoaSkills client
# (audit_registry.canonical_bytes): compact sorted JSON of every field except
# 'sig', encoded as UTF-8. Keep these byte-identical across the two projects.
def canonical_bytes(record: dict[str, Any]) -> bytes:
    body = {key: value for key, value in record.items() if key != "sig"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class SigningKey:
    private: Ed25519PrivateKey

    @property
    def public_bytes(self) -> bytes:
        return self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def public_pinned(self) -> str:
        return "ed25519:" + base64.b64encode(self.public_bytes).decode("ascii")

    @property
    def key_id(self) -> str:
        return hashlib.sha256(self.public_bytes).hexdigest()[:16]

    def sign(self, message: bytes) -> str:
        return base64.b64encode(self.private.sign(message)).decode("ascii")

    def sign_record(self, body: dict[str, Any]) -> dict[str, Any]:
        record = {key: value for key, value in body.items() if key != "sig"}
        record["sig"] = {
            "key_id": self.key_id,
            "algorithm": "ed25519",
            "signature": self.sign(canonical_bytes(record)),
        }
        return record


def generate_key() -> SigningKey:
    return SigningKey(Ed25519PrivateKey.generate())


def load_key(pem: bytes) -> SigningKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("private key is not an Ed25519 key")
    return SigningKey(key)


def export_key_pem(key: SigningKey) -> bytes:
    return key.private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def verify(public_pinned: str, message: bytes, signature_b64: str) -> bool:
    raw = public_pinned.split(":", 1)[1] if public_pinned.startswith("ed25519:") else public_pinned
    public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(raw))
    try:
        public_key.verify(base64.b64decode(signature_b64), message)
        return True
    except Exception:
        return False
