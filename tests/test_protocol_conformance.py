from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from csk_registry import signing
from csk_registry.bundle import import_bundle
from csk_registry.protocol import ProtocolError, load_json, validate_record, validate_snapshot
from csk_registry.store import Store


ROOT_TEXT = os.environ.get("CURATOR_CONFORMANCE_ROOT")
pytestmark = pytest.mark.skipif(not ROOT_TEXT, reason="CURATOR_CONFORMANCE_ROOT is not set")


def _root() -> Path:
    assert ROOT_TEXT is not None
    root = Path(ROOT_TEXT)
    assert (root / "manifest.json").is_file()
    return root


def _json(relative: str) -> Any:
    return json.loads((_root() / relative).read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", _json("vectors/canonical-valid.json") if ROOT_TEXT else [])
def test_ccj_positive_vectors(case: dict[str, Any]) -> None:
    assert signing.canonical_bytes(case["input"]).decode("utf-8") == case["canonical_utf8"]


@pytest.mark.parametrize("case", _json("vectors/canonical-invalid.json") if ROOT_TEXT else [])
def test_ccj_rejection_vectors(case: dict[str, str]) -> None:
    with pytest.raises(ProtocolError):
        load_json(case["input_text"])


def test_shared_signed_objects() -> None:
    pinned = (_root() / "expected" / "registry" / "pinned_key.txt").read_text(encoding="utf-8").strip()
    audited = validate_record(_json("expected/registry/record_audited.json"))
    revoked = validate_record(_json("expected/registry/record_revoked.json"))
    forged = validate_record(_json("expected/registry/record_forged.json"))
    wrong_key = validate_record(_json("expected/registry/record_wrong_key_id.json"))
    snapshot = validate_snapshot(_json("expected/registry/snapshot.json"))
    assert signing.verify_signed(pinned, audited)
    assert signing.verify_signed(pinned, revoked)
    assert not signing.verify_signed(pinned, forged)
    assert not signing.verify_signed(pinned, wrong_key)
    assert signing.verify_signed(pinned, snapshot)


def test_shared_bundle_authentication_and_idempotent_import(tmp_path: Path) -> None:
    bundle = _json("expected/registry/bundle.json")
    pinned = (_root() / "expected" / "registry" / "pinned_key.txt").read_text(encoding="utf-8").strip()
    store = Store(tmp_path / "registry.db")
    local_key = signing.generate_key()
    assert import_bundle(store, local_key, bundle, upstream_public_key=pinned) == 2
    assert import_bundle(store, local_key, bundle, upstream_public_key=pinned) == 0
    assert store.verify_chain()


def test_shared_bundle_rejects_tampering_before_mutation(tmp_path: Path) -> None:
    bundle = _json("expected/registry/bundle.json")
    bundle["records"][1]["status"] = "audited"
    pinned = (_root() / "expected" / "registry" / "pinned_key.txt").read_text(encoding="utf-8").strip()
    store = Store(tmp_path / "registry.db")
    with pytest.raises(ValueError):
        import_bundle(store, signing.generate_key(), bundle, upstream_public_key=pinned)
    assert store.head()[0] == 0
