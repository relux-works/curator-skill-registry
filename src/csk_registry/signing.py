from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


MAX_SAFE_INTEGER = 9_007_199_254_740_991


class CanonicalError(ValueError):
    pass


def canonical_bytes(record: dict[str, Any]) -> bytes:
    """Return Curator Canonical JSON 1 bytes for a signed object."""
    body = {key: value for key, value in record.items() if key != "sig"}
    return _canonical_document(body)


def canonical_document_bytes(value: Any) -> bytes:
    """Canonicalize a complete JSON value without stripping a signature."""
    return _canonical_document(value)


def _canonical_document(value: Any) -> bytes:
    _validate_ccj(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _validate_ccj(value: Any) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise CanonicalError(f"CCJ-1 integer outside safe range: {value}")
        return
    if isinstance(value, float):
        raise CanonicalError("CCJ-1 numbers must be integers")
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise CanonicalError("CCJ-1 strings must not contain lone surrogates")
        return
    if isinstance(value, list):
        for item in value:
            _validate_ccj(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError("CCJ-1 object keys must be strings")
            _validate_ccj(key)
            _validate_ccj(item)
        return
    raise CanonicalError(f"CCJ-1 does not support {type(value).__name__}")


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
    try:
        public_key = Ed25519PublicKey.from_public_bytes(parse_public_key(public_pinned))
        signature = base64.b64decode(signature_b64, validate=True)
        if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != signature_b64:
            return False
        public_key.verify(signature, message)
        return True
    except (ValueError, binascii.Error, InvalidSignature):
        return False


def parse_public_key(value: str) -> bytes:
    encoded = value.removeprefix("ed25519:")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid Ed25519 public key encoding") from exc
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != encoded:
        raise ValueError("Ed25519 public key must be canonical padded base64 for 32 bytes")
    return raw


def verify_signed(public_pinned: str, obj: dict[str, Any]) -> bool:
    sig = obj.get("sig")
    if not isinstance(sig, dict) or set(sig) != {"algorithm", "key_id", "signature"}:
        return False
    try:
        public = parse_public_key(public_pinned)
        canonical = canonical_bytes(obj)
    except (ValueError, CanonicalError):
        return False
    if sig.get("algorithm") != "ed25519":
        return False
    if sig.get("key_id") != hashlib.sha256(public).hexdigest()[:16]:
        return False
    signature = sig.get("signature")
    return isinstance(signature, str) and verify(public_pinned, canonical, signature)
