from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from . import KEY_PASSPHRASE_ENV
from .permissions import (
    protect_private_directory,
    protect_private_file,
    require_private_file,
)
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

_LOG = logging.getLogger(__name__)

_EMPTY_PASSPHRASE_MESSAGE = (
    f"{KEY_PASSPHRASE_ENV} is set but empty; "
    "unset it for a plain key or set a non-empty passphrase"
)


class KeyPassphraseError(ValueError):
    """An encrypted signing key cannot be decrypted with the configured secret.

    Subclasses ``ValueError`` so every existing command handler reports the
    single diagnostic naming ``KEY_PASSPHRASE_ENV`` without a traceback.
    """


class KeyProvider(Protocol):
    """Seam for signing-key storage; the KMS hook point (see SECURITY.md).

    Every key load and store in this module funnels through a provider. The
    default is :class:`FileKeyProvider` (PEM files under the data home with
    an optional passphrase). An external KMS/HSM integration implements this
    Protocol and passes it to the functions below; call sites stay unchanged.
    """

    @property
    def passphrase(self) -> bytes | None:
        """Passphrase for encrypted PEM, or None for plain PEM."""
        ...

    def load(self, path: Path) -> SigningKey:
        """Load and decrypt the private key stored at ``path``."""
        ...

    def store(self, path: Path, key: SigningKey) -> None:
        """Atomically store ``key`` at ``path``, encrypted when set."""
        ...


@dataclass(frozen=True)
class FileKeyProvider:
    """File-backed PEM provider with an optional passphrase."""

    passphrase: bytes | None = None

    def load(self, path: Path) -> SigningKey:
        if self.passphrase == b"":
            raise KeyPassphraseError(_EMPTY_PASSPHRASE_MESSAGE)
        pem = _read_private_key(path)
        if b"ENCRYPTED PRIVATE KEY" in pem:
            if self.passphrase is None:
                raise KeyPassphraseError(
                    f"signing key {path} is encrypted but {KEY_PASSPHRASE_ENV} is not set"
                )
            try:
                return load_key(pem, passphrase=self.passphrase)
            except (TypeError, ValueError) as exc:
                raise KeyPassphraseError(
                    f"could not decrypt signing key {path} with {KEY_PASSPHRASE_ENV}"
                    " (wrong passphrase?)"
                ) from exc
        if self.passphrase is not None:
            _LOG.warning(
                "signing key %s is not encrypted although %s is set; "
                "encrypt it at rest (see README) or unset the variable",
                path,
                KEY_PASSPHRASE_ENV,
            )
        return load_key(pem)

    def store(self, path: Path, key: SigningKey) -> None:
        if self.passphrase == b"":
            raise KeyPassphraseError(_EMPTY_PASSPHRASE_MESSAGE)
        _atomic_write(path, export_key_pem(key, passphrase=self.passphrase), 0o600)


def key_passphrase_from_env() -> bytes | None:
    """Return the key passphrase from the environment, or None when unset.

    Set means encrypted and unset means plain; a present-but-empty value is
    rejected because PKCS8 encryption requires a non-empty password.
    """
    if KEY_PASSPHRASE_ENV not in os.environ:
        return None
    raw = os.environ[KEY_PASSPHRASE_ENV]
    if raw == "":
        raise KeyPassphraseError(_EMPTY_PASSPHRASE_MESSAGE)
    return raw.encode("utf-8")


def default_key_provider() -> FileKeyProvider:
    """Return the default file-backed provider honouring the environment."""
    return FileKeyProvider(passphrase=key_passphrase_from_env())


def _resolve_provider(provider: KeyProvider | None) -> KeyProvider:
    return provider if provider is not None else default_key_provider()


def active_key_path(home: Path) -> Path:
    return home / ACTIVE_KEY_NAME


def next_key_path(home: Path) -> Path:
    return home / NEXT_KEY_NAME


def load_active_key(home: Path, *, provider: KeyProvider | None = None) -> SigningKey:
    return _resolve_provider(provider).load(active_key_path(home))


def initialize_key(
    home: Path, *, replace: bool = False, provider: KeyProvider | None = None
) -> SigningKey:
    path = active_key_path(home)
    if path.exists() and not replace:
        raise ValueError(f"signing key already exists at {path}")
    if next_key_path(home).exists():
        raise ValueError("a signing-key rotation is already staged")
    key = generate_key()
    _resolve_provider(provider).store(path, key)
    _write_public_keys(home, (key.public_pinned,))
    return key


def public_keys(
    home: Path, active: SigningKey | None = None, *, provider: KeyProvider | None = None
) -> tuple[str, ...]:
    resolved = _resolve_provider(provider)
    current = active or resolved.load(active_key_path(home))
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
        staged_public = resolved.load(staged).public_pinned
        if staged_public not in values:
            values.append(staged_public)
    return tuple(values)


def prepare_rotation(
    home: Path, *, provider: KeyProvider | None = None
) -> tuple[SigningKey, SigningKey]:
    resolved = _resolve_provider(provider)
    active = resolved.load(active_key_path(home))
    staged_path = next_key_path(home)
    if staged_path.exists():
        raise ValueError("a signing-key rotation is already staged")
    staged = generate_key()
    resolved.store(staged_path, staged)
    try:
        _write_public_keys(home, (*public_keys(home, active, provider=resolved), staged.public_pinned))
    except (OSError, ValueError):
        staged_path.unlink(missing_ok=True)
        raise
    return active, staged


def activate_rotation(
    home: Path, *, provider: KeyProvider | None = None
) -> tuple[SigningKey, SigningKey]:
    resolved = _resolve_provider(provider)
    active = resolved.load(active_key_path(home))
    staged_path = next_key_path(home)
    if not staged_path.is_file():
        raise ValueError("no signing-key rotation is staged")
    staged = resolved.load(staged_path)
    _write_public_keys(home, (*public_keys(home, active, provider=resolved), staged.public_pinned))
    # Re-export through the provider so the configured encryption applies to
    # the activated key (a plain staged key becomes encrypted when the
    # variable is set); the staged key material and public pins are unchanged.
    resolved.store(active_key_path(home), staged)
    staged_path.unlink()
    _sync_directory(home)
    return active, staged


def cancel_rotation(home: Path, *, provider: KeyProvider | None = None) -> SigningKey:
    resolved = _resolve_provider(provider)
    active = resolved.load(active_key_path(home))
    staged_path = next_key_path(home)
    if not staged_path.is_file():
        raise ValueError("no signing-key rotation is staged")
    staged = resolved.load(staged_path)
    retained = tuple(
        value for value in public_keys(home, active, provider=resolved) if value != staged.public_pinned
    )
    _write_public_keys(home, retained)
    staged_path.unlink()
    _sync_directory(home)
    return staged


def retire_public_key(home: Path, key_id: str, *, provider: KeyProvider | None = None) -> str:
    resolved = _resolve_provider(provider)
    active = resolved.load(active_key_path(home))
    staged_path = next_key_path(home)
    staged = resolved.load(staged_path) if staged_path.is_file() else None
    if key_id == active.key_id or (staged is not None and key_id == staged.key_id):
        raise ValueError("the active or staged signing key cannot be retired")
    values = list(public_keys(home, active, provider=resolved))
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
    protect_private_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.close(descriptor)
        temporary.chmod(mode)
        protect_private_file(temporary)
        with temporary.open("wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        protect_private_file(temporary)
        os.replace(temporary, path)
        protect_private_file(path)
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
        require_private_file(path)
    except (OSError, ValueError) as exc:
        raise ValueError(f"signing key {path} is unavailable: {exc}") from exc
    return path.read_bytes()
