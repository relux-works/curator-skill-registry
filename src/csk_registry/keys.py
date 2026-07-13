from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path

from .signing import (
    SigningKey,
    export_key_pem,
    generate_key,
    load_key,
    parse_public_key,
)


ACTIVE_KEY_NAME = "signing-key.pem"
NEXT_KEY_NAME = "next-signing-key.pem"
KEYRING_NAME = "signing-keyring.json"


def active_key_path(home: Path) -> Path:
    return home / ACTIVE_KEY_NAME


def next_key_path(home: Path) -> Path:
    return home / NEXT_KEY_NAME


def load_active_key(home: Path) -> SigningKey:
    return load_key(_read_private_key(active_key_path(home)))


def initialize_key(home: Path, *, replace: bool = False) -> SigningKey:
    path = active_key_path(home)
    if path.exists() and not replace:
        raise ValueError(f"signing key already exists at {path}")
    if next_key_path(home).exists():
        raise ValueError("a signing-key rotation is already staged")
    key = generate_key()
    _atomic_write(path, export_key_pem(key), 0o600)
    _write_public_keys(home, (key.public_pinned,))
    return key


def public_keys(home: Path, active: SigningKey | None = None) -> tuple[str, ...]:
    current = active or load_active_key(home)
    values: list[str] = [current.public_pinned]
    path = home / KEYRING_NAME
    if path.is_file():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or set(payload) != {
                "schema_version",
                "public_keys",
            }:
                raise ValueError("keyring must contain schema_version and public_keys")
            if payload["schema_version"] != 1:
                raise ValueError("unsupported keyring schema_version")
            configured = payload["public_keys"]
            if not isinstance(configured, list):
                raise ValueError("public_keys must be an array")
            for value in configured:
                if not isinstance(value, str):
                    raise ValueError("public key must be a string")
                parse_public_key(value)
                if value not in values:
                    values.append(value)
        except (KeyError, OSError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"signing keyring is malformed: {exc}") from exc
    staged = next_key_path(home)
    if staged.is_file():
        staged_public = load_key(_read_private_key(staged)).public_pinned
        if staged_public not in values:
            values.append(staged_public)
    return tuple(values)


def prepare_rotation(home: Path) -> tuple[SigningKey, SigningKey]:
    active = load_active_key(home)
    staged_path = next_key_path(home)
    if staged_path.exists():
        raise ValueError("a signing-key rotation is already staged")
    staged = generate_key()
    _atomic_write(staged_path, export_key_pem(staged), 0o600)
    try:
        _write_public_keys(home, (*public_keys(home, active), staged.public_pinned))
    except (OSError, ValueError):
        staged_path.unlink(missing_ok=True)
        raise
    return active, staged


def activate_rotation(home: Path) -> tuple[SigningKey, SigningKey]:
    active = load_active_key(home)
    staged_path = next_key_path(home)
    if not staged_path.is_file():
        raise ValueError("no signing-key rotation is staged")
    staged = load_key(_read_private_key(staged_path))
    _write_public_keys(home, (*public_keys(home, active), staged.public_pinned))
    os.replace(staged_path, active_key_path(home))
    active_key_path(home).chmod(0o600)
    _sync_directory(home)
    return active, staged


def cancel_rotation(home: Path) -> SigningKey:
    active = load_active_key(home)
    staged_path = next_key_path(home)
    if not staged_path.is_file():
        raise ValueError("no signing-key rotation is staged")
    staged = load_key(_read_private_key(staged_path))
    retained = tuple(
        value for value in public_keys(home, active) if value != staged.public_pinned
    )
    _write_public_keys(home, retained)
    staged_path.unlink()
    _sync_directory(home)
    return staged


def retire_public_key(home: Path, key_id: str) -> str:
    active = load_active_key(home)
    staged_path = next_key_path(home)
    staged = load_key(_read_private_key(staged_path)) if staged_path.is_file() else None
    if key_id == active.key_id or (staged is not None and key_id == staged.key_id):
        raise ValueError("the active or staged signing key cannot be retired")
    values = list(public_keys(home, active))
    matches = [value for value in values if _key_id(value) == key_id]
    if len(matches) != 1:
        raise ValueError(f"retained signing key {key_id!r} was not found")
    values.remove(matches[0])
    _write_public_keys(home, tuple(values))
    return matches[0]


def _key_id(public_pinned: str) -> str:
    return hashlib.sha256(parse_public_key(public_pinned)).hexdigest()[:16]


def _write_public_keys(home: Path, values: tuple[str, ...]) -> None:
    unique: list[str] = []
    for value in values:
        parse_public_key(value)
        if value not in unique:
            unique.append(value)
    payload = json.dumps({"schema_version": 1, "public_keys": unique}, indent=2).encode("utf-8") + b"\n"
    _atomic_write(home / KEYRING_NAME, payload, 0o600)


def write_private_json(path: Path, value: object) -> None:
    payload = json.dumps(value, indent=2).encode("utf-8") + b"\n"
    _atomic_write(path, payload, 0o600)


def _atomic_write(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(mode)
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _sync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_private_key(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"signing key {path} is unavailable: {exc}") from exc
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"signing key {path} is not a regular file")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError(f"signing key {path} permissions are too broad")
    return path.read_bytes()
