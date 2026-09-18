from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from csk_registry import CHECKPOINT_ENV, HOME_ENV, KEY_PASSPHRASE_ENV, signing
from csk_registry.app import app_from_env
from csk_registry.cli import main
from csk_registry.keys import (
    FileKeyProvider,
    KeyPassphraseError,
    default_key_provider,
    initialize_key,
    key_passphrase_from_env,
    load_active_key,
    public_keys,
    write_private_json,
)
from csk_registry.store import Store

ENCRYPTED_HEADER = b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
PLAIN_HEADER = b"-----BEGIN PRIVATE KEY-----"


def test_encrypted_pem_round_trip_preserves_public_key() -> None:
    key = signing.generate_key()
    pem = signing.export_key_pem(key, passphrase=b"s3cret")
    assert pem.startswith(ENCRYPTED_HEADER)
    loaded = signing.load_key(pem, passphrase=b"s3cret")
    assert loaded.public_pinned == key.public_pinned
    assert loaded.key_id == key.key_id


def test_export_without_passphrase_stays_plain() -> None:
    key = signing.generate_key()
    pem = signing.export_key_pem(key)
    assert pem.startswith(PLAIN_HEADER)
    assert b"ENCRYPTED" not in pem
    assert signing.load_key(pem).public_pinned == key.public_pinned


def test_passphrase_from_env_shapes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(KEY_PASSPHRASE_ENV, raising=False)
    assert key_passphrase_from_env() is None
    assert default_key_provider().passphrase is None
    monkeypatch.setenv(KEY_PASSPHRASE_ENV, "s3cret")
    assert key_passphrase_from_env() == b"s3cret"
    assert default_key_provider().passphrase == b"s3cret"


def test_empty_passphrase_rejected_before_any_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(KEY_PASSPHRASE_ENV, "")
    with pytest.raises(KeyPassphraseError, match="CSK_REGISTRY_KEY_PASSPHRASE"):
        key_passphrase_from_env()
    with pytest.raises(KeyPassphraseError, match="empty"):
        default_key_provider()
    home = tmp_path / "home"
    with pytest.raises(KeyPassphraseError, match="CSK_REGISTRY_KEY_PASSPHRASE"):
        initialize_key(home)
    assert not (home / "signing-key.pem").exists()
    capsys.readouterr()
    assert main(["--home", str(home), "genkey"]) == 1
    err = capsys.readouterr().err
    assert err.count(KEY_PASSPHRASE_ENV) == 1
    assert "empty" in err
    assert "Traceback" not in err
    assert not (home / "signing-key.pem").exists()


def test_empty_passphrase_at_load_time_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_PASSPHRASE_ENV, raising=False)
    home = tmp_path / "home"
    key = initialize_key(home)
    assert load_active_key(home).public_pinned == key.public_pinned
    monkeypatch.setenv(KEY_PASSPHRASE_ENV, "")
    with pytest.raises(KeyPassphraseError, match="CSK_REGISTRY_KEY_PASSPHRASE"):
        load_active_key(home)
    with pytest.raises(KeyPassphraseError, match="empty"):
        load_active_key(home, provider=FileKeyProvider(passphrase=b""))


def test_missing_passphrase_fails_closed_naming_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_PASSPHRASE_ENV, "correct-horse")
    home = tmp_path / "home"
    initialize_key(home)
    assert (home / "signing-key.pem").read_bytes().startswith(ENCRYPTED_HEADER)
    monkeypatch.delenv(KEY_PASSPHRASE_ENV)
    with pytest.raises(KeyPassphraseError, match="CSK_REGISTRY_KEY_PASSPHRASE"):
        load_active_key(home)
    with pytest.raises(KeyPassphraseError, match="not set"):
        load_active_key(home, provider=FileKeyProvider(passphrase=None))


def test_wrong_passphrase_fails_closed_naming_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_PASSPHRASE_ENV, "right")
    home = tmp_path / "home"
    initialize_key(home)
    monkeypatch.setenv(KEY_PASSPHRASE_ENV, "wrong")
    with pytest.raises(KeyPassphraseError, match="CSK_REGISTRY_KEY_PASSPHRASE"):
        load_active_key(home)
    with pytest.raises(KeyPassphraseError, match="wrong passphrase"):
        load_active_key(home, provider=FileKeyProvider(passphrase=b"wrong"))


def test_plain_pem_loads_with_warning_while_variable_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv(KEY_PASSPHRASE_ENV, raising=False)
    home = tmp_path / "home"
    key = initialize_key(home)
    with caplog.at_level(logging.WARNING, logger="csk_registry.keys"):
        caplog.clear()
        assert load_active_key(home).public_pinned == key.public_pinned
    assert "not encrypted" not in caplog.text
    monkeypatch.setenv(KEY_PASSPHRASE_ENV, "new-secret")
    with caplog.at_level(logging.WARNING, logger="csk_registry.keys"):
        caplog.clear()
        assert load_active_key(home).public_pinned == key.public_pinned
    assert "CSK_REGISTRY_KEY_PASSPHRASE" in caplog.text
    assert "not encrypted" in caplog.text


def test_genkey_honours_variable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    monkeypatch.delenv(KEY_PASSPHRASE_ENV, raising=False)
    assert main(["--home", str(home), "genkey"]) == 0
    assert b"ENCRYPTED" not in (home / "signing-key.pem").read_bytes()
    monkeypatch.setenv(KEY_PASSPHRASE_ENV, "s3cret")
    assert main(["--home", str(home), "genkey", "--force"]) == 0
    assert (home / "signing-key.pem").read_bytes().startswith(ENCRYPTED_HEADER)
    assert public_keys(home) == (load_active_key(home).public_pinned,)


def test_rotation_with_encrypted_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(KEY_PASSPHRASE_ENV, "rotation-secret")
    home = tmp_path / "home"
    assert main(["--home", str(home), "genkey"]) == 0
    old = load_active_key(home)
    assert main(["--home", str(home), "prepare-key-rotation"]) == 0
    assert (home / "next-signing-key.pem").read_bytes().startswith(ENCRYPTED_HEADER)
    assert len(public_keys(home)) == 2
    assert (
        main(["--home", str(home), "activate-key-rotation", "--confirm-pins-deployed"])
        == 0
    )
    assert not (home / "next-signing-key.pem").exists()
    new = load_active_key(home)
    assert new.key_id != old.key_id
    assert (home / "signing-key.pem").read_bytes().startswith(ENCRYPTED_HEADER)
    assert set(public_keys(home)) == {old.public_pinned, new.public_pinned}


def test_rotation_migrates_plain_key_to_encrypted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_PASSPHRASE_ENV, raising=False)
    home = tmp_path / "home"
    assert main(["--home", str(home), "genkey"]) == 0
    old_public = load_active_key(home).public_pinned
    monkeypatch.setenv(KEY_PASSPHRASE_ENV, "adopted")
    assert main(["--home", str(home), "prepare-key-rotation"]) == 0
    assert b"ENCRYPTED" not in (home / "signing-key.pem").read_bytes()
    assert (home / "next-signing-key.pem").read_bytes().startswith(ENCRYPTED_HEADER)
    assert (
        main(["--home", str(home), "activate-key-rotation", "--confirm-pins-deployed"])
        == 0
    )
    assert (home / "signing-key.pem").read_bytes().startswith(ENCRYPTED_HEADER)
    assert set(public_keys(home)) == {old_public, load_active_key(home).public_pinned}


def test_activation_encrypts_plain_staged_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Staged while unset, activated while set: the active key is encrypted."""
    monkeypatch.delenv(KEY_PASSPHRASE_ENV, raising=False)
    home = tmp_path / "home"
    assert main(["--home", str(home), "genkey"]) == 0
    old = load_active_key(home)
    assert main(["--home", str(home), "prepare-key-rotation"]) == 0
    assert b"ENCRYPTED" not in (home / "next-signing-key.pem").read_bytes()
    staged_public = public_keys(home)[1]
    monkeypatch.setenv(KEY_PASSPHRASE_ENV, "late-secret")
    assert (
        main(["--home", str(home), "activate-key-rotation", "--confirm-pins-deployed"])
        == 0
    )
    assert not (home / "next-signing-key.pem").exists()
    assert (home / "signing-key.pem").read_bytes().startswith(ENCRYPTED_HEADER)
    new = load_active_key(home)
    assert new.key_id != old.key_id
    assert new.public_pinned == staged_public
    assert set(public_keys(home)) == {old.public_pinned, new.public_pinned}


def test_activation_keeps_encrypted_staged_key_loadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Encrypted staged key activated under the same passphrase stays loadable."""
    monkeypatch.setenv(KEY_PASSPHRASE_ENV, "same-secret")
    home = tmp_path / "home"
    assert main(["--home", str(home), "genkey"]) == 0
    assert main(["--home", str(home), "prepare-key-rotation"]) == 0
    staged_pem = (home / "next-signing-key.pem").read_bytes()
    assert staged_pem.startswith(ENCRYPTED_HEADER)
    assert (
        main(["--home", str(home), "activate-key-rotation", "--confirm-pins-deployed"])
        == 0
    )
    active_pem = (home / "signing-key.pem").read_bytes()
    assert active_pem.startswith(ENCRYPTED_HEADER)
    assert load_active_key(home).public_pinned in set(public_keys(home))


@pytest.mark.parametrize("command", [["prepare-key-rotation"], ["sign-record"]])
def test_commands_fail_closed_with_single_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: list[str],
) -> None:
    monkeypatch.setenv(KEY_PASSPHRASE_ENV, "sealed")
    home = tmp_path / "home"
    assert main(["--home", str(home), "genkey"]) == 0
    monkeypatch.delenv(KEY_PASSPHRASE_ENV)
    argv = ["--home", str(home), *command]
    if command == ["sign-record"]:
        record = tmp_path / "record.json"
        record.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
        argv += ["--record", str(record)]
    capsys.readouterr()
    assert main(argv) == 1
    captured = capsys.readouterr()
    assert captured.err.count(KEY_PASSPHRASE_ENV) == 1
    assert "Traceback" not in captured.err
    assert "Traceback" not in captured.out


def test_command_with_wrong_passphrase_names_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(KEY_PASSPHRASE_ENV, "right")
    home = tmp_path / "home"
    assert main(["--home", str(home), "genkey"]) == 0
    monkeypatch.setenv(KEY_PASSPHRASE_ENV, "wrong")
    capsys.readouterr()
    assert main(["--home", str(home), "prepare-key-rotation"]) == 1
    err = capsys.readouterr().err
    assert err.count(KEY_PASSPHRASE_ENV) == 1
    assert "wrong passphrase" in err
    assert "Traceback" not in err


def test_explicit_provider_overrides_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_PASSPHRASE_ENV, raising=False)
    home = tmp_path / "home"
    provider = FileKeyProvider(passphrase=b"explicit-secret")
    key = initialize_key(home, provider=provider)
    assert (home / "signing-key.pem").read_bytes().startswith(ENCRYPTED_HEADER)
    assert load_active_key(home, provider=provider).public_pinned == key.public_pinned
    with pytest.raises(KeyPassphraseError, match="CSK_REGISTRY_KEY_PASSPHRASE"):
        load_active_key(home)


def test_key_operations_funnel_through_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A custom KeyProvider sees every load/store (the KMS hook shape)."""

    monkeypatch.delenv(KEY_PASSPHRASE_ENV, raising=False)
    home = tmp_path / "home"
    inner = FileKeyProvider()
    calls: list[tuple[str, str]] = []

    class RecordingProvider:
        @property
        def passphrase(self) -> bytes | None:
            return inner.passphrase

        def load(self, path: Path) -> signing.SigningKey:
            calls.append(("load", path.name))
            return inner.load(path)

        def store(self, path: Path, key: signing.SigningKey) -> None:
            calls.append(("store", path.name))
            inner.store(path, key)

    provider = RecordingProvider()
    initialize_key(home, provider=provider)  # type: ignore[arg-type]
    load_active_key(home, provider=provider)  # type: ignore[arg-type]
    assert ("store", "signing-key.pem") in calls
    assert ("load", "signing-key.pem") in calls


def _serve_ready_encrypted_home(home: Path, *, records: int) -> signing.SigningKey:
    """Create a serve-ready home; the caller must preset the passphrase env."""
    home.mkdir(parents=True, exist_ok=True)
    key = initialize_key(home)
    token = "passphrase-startup-unit-test-token"
    write_private_json(
        home / "auditors.json",
        {
            "auditors": [
                {
                    "auditor_id": "a1",
                    "org": "Example",
                    "public_key": signing.generate_key().public_pinned,
                    "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                }
            ]
        },
    )
    store = Store(home / "registry.db")
    for index in range(records):
        store.append(
            key.sign_record(
                {
                    "schema_version": 1,
                    "name": f"skill-passphrase-{index}",
                    "source_identity": "gitlab.example.com/skills/skill-passphrase",
                    "commit": f"{index:040d}",
                    "content_sha256": "sha256:" + f"{index:064x}",
                    "status": "audited",
                    "audit": {"ruleset_version": "csk-audit/1"},
                }
            ),
            created_at=f"2026-07-13T00:00:{index:02d}Z",
        )
    store.close()
    return key


def test_serve_startup_with_encrypted_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_PASSPHRASE_ENV, "serve-secret")
    home = tmp_path / "home"
    key = _serve_ready_encrypted_home(home, records=2)
    assert (home / "signing-key.pem").read_bytes().startswith(ENCRYPTED_HEADER)
    monkeypatch.setenv(HOME_ENV, str(home))
    monkeypatch.delenv(CHECKPOINT_ENV, raising=False)
    client = TestClient(app_from_env())
    assert client.get("/health").status_code == 200
    snapshot = client.get("/v1/snapshot").json()
    assert signing.verify_signed(key.public_pinned, snapshot)


def test_serve_startup_without_passphrase_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_PASSPHRASE_ENV, "serve-secret")
    home = tmp_path / "home"
    _serve_ready_encrypted_home(home, records=1)
    monkeypatch.setenv(HOME_ENV, str(home))
    monkeypatch.delenv(CHECKPOINT_ENV, raising=False)
    monkeypatch.delenv(KEY_PASSPHRASE_ENV)
    with pytest.raises(KeyPassphraseError, match="CSK_REGISTRY_KEY_PASSPHRASE"):
        app_from_env()


def test_serve_command_with_encrypted_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_PASSPHRASE_ENV, "serve-secret")
    home = tmp_path / "home"
    _serve_ready_encrypted_home(home, records=1)
    monkeypatch.setenv(HOME_ENV, str(home))
    monkeypatch.delenv(CHECKPOINT_ENV, raising=False)
    calls: list[object] = []
    monkeypatch.setattr("uvicorn.run", lambda app, **kwargs: calls.append(app))
    assert main(["--home", str(home), "serve"]) == 0
    assert len(calls) == 1


def test_serve_command_without_passphrase_has_no_partial_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(KEY_PASSPHRASE_ENV, "serve-secret")
    home = tmp_path / "home"
    _serve_ready_encrypted_home(home, records=1)
    monkeypatch.setenv(HOME_ENV, str(home))
    monkeypatch.delenv(CHECKPOINT_ENV, raising=False)
    monkeypatch.delenv(KEY_PASSPHRASE_ENV)

    def _must_not_run(app: object, **kwargs: object) -> None:
        raise AssertionError("uvicorn.run must not run without the passphrase")

    monkeypatch.setattr("uvicorn.run", _must_not_run)
    capsys.readouterr()
    assert main(["--home", str(home), "serve"]) == 1
    captured = capsys.readouterr()
    assert captured.err.count(KEY_PASSPHRASE_ENV) == 1
    assert "Traceback" not in captured.err


def test_serve_command_with_empty_passphrase_has_no_partial_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv(KEY_PASSPHRASE_ENV, raising=False)
    home = tmp_path / "home"
    _serve_ready_encrypted_home(home, records=1)
    monkeypatch.setenv(HOME_ENV, str(home))
    monkeypatch.delenv(CHECKPOINT_ENV, raising=False)
    monkeypatch.setenv(KEY_PASSPHRASE_ENV, "")

    def _must_not_run(app: object, **kwargs: object) -> None:
        raise AssertionError("uvicorn.run must not run with an empty passphrase")

    monkeypatch.setattr("uvicorn.run", _must_not_run)
    capsys.readouterr()
    assert main(["--home", str(home), "serve"]) == 1
    captured = capsys.readouterr()
    assert captured.err.count(KEY_PASSPHRASE_ENV) == 1
    assert "empty" in captured.err
    assert "Traceback" not in captured.err
