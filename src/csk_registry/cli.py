from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path

from . import COMMAND_NAME, HOME_ENV, home_from_env
from .bundle import export_bundle, import_bundle
from .clock import utc_now
from .protocol import load_json, validate_record
from .signing import export_key_pem, generate_key, load_key
from .snapshot import build_snapshot
from .store import Store


def _home(args: argparse.Namespace) -> Path:
    home = Path(args.home).expanduser()
    home.mkdir(parents=True, exist_ok=True)
    return home


def _cmd_genkey(args: argparse.Namespace) -> int:
    home = _home(args)
    key_path = home / "signing-key.pem"
    if key_path.exists() and not args.force:
        print(f"signing key already exists at {key_path} (use --force to overwrite)", file=sys.stderr)
        return 1
    key = generate_key()
    key_path.write_bytes(export_key_pem(key))
    key_path.chmod(0o600)
    print(json.dumps({"key_id": key.key_id, "public_key": key.public_pinned, "path": str(key_path)}, indent=2))
    return 0


def _cmd_issue_token(args: argparse.Namespace) -> int:
    home = _home(args)
    auditors_path = home / "auditors.json"
    data = json.loads(auditors_path.read_text(encoding="utf-8")) if auditors_path.exists() else {"auditors": []}
    token = secrets.token_urlsafe(32)
    data["auditors"] = [a for a in data.get("auditors", []) if a.get("auditor_id") != args.auditor_id]
    data["auditors"].append(
        {
            "auditor_id": args.auditor_id,
            "org": args.org,
            "public_key": args.public_key,
            "token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
        }
    )
    auditors_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"auditor_id": args.auditor_id, "token": token}, indent=2))
    print("Store this token now; only its hash is kept on the server.", file=sys.stderr)
    return 0


def _cmd_sign_record(args: argparse.Namespace) -> int:
    home = _home(args)
    key = load_key((home / "signing-key.pem").read_bytes())
    body = load_json(Path(args.record).read_bytes() if args.record else sys.stdin.buffer.read())
    if not isinstance(body, dict):
        raise ValueError("record body must be a JSON object")
    body.setdefault("schema_version", 1)
    record = key.sign_record(body)
    validate_record(record)
    print(json.dumps(record, indent=2, ensure_ascii=False))
    return 0


def _cmd_export_snapshot(args: argparse.Namespace) -> int:
    home = _home(args)
    key = load_key((home / "signing-key.pem").read_bytes())
    store = Store(home / "registry.db")
    size, _ = store.head()
    print(json.dumps(build_snapshot(store, key, created_at=utc_now(), version=size), indent=2))
    return 0


def _cmd_export_bundle(args: argparse.Namespace) -> int:
    home = _home(args)
    key = load_key((home / "signing-key.pem").read_bytes())
    store = Store(home / "registry.db")
    bundle = export_bundle(store, key)
    text = json.dumps(bundle, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(json.dumps({"records": len(bundle["records"]), "path": args.out}, indent=2))
    else:
        print(text)
    return 0


def _cmd_import_bundle(args: argparse.Namespace) -> int:
    home = _home(args)
    key = load_key((home / "signing-key.pem").read_bytes())
    store = Store(home / "registry.db")
    bundle = load_json(Path(args.bundle).read_bytes())
    if not isinstance(bundle, dict):
        print("import failed: bundle must be a JSON object", file=sys.stderr)
        return 1
    try:
        count = import_bundle(store, key, bundle, upstream_public_key=args.upstream_key)
    except ValueError as exc:
        print(f"import failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"imported": count}, indent=2))
    return 0


def _cmd_verify_chain(args: argparse.Namespace) -> int:
    home = _home(args)
    store = Store(home / "registry.db")
    ok = store.verify_chain()
    print(json.dumps({"chain_valid": ok, "log_size": store.head()[0]}, indent=2))
    return 0 if ok else 2


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .app import app_from_env

    os.environ[HOME_ENV] = args.home
    uvicorn.run(app_from_env(), host=args.host, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=COMMAND_NAME, description="Curator Skill Registry administration tool")
    parser.add_argument("--home", default=home_from_env(), help="registry data directory")
    sub = parser.add_subparsers(dest="command", required=True)

    genkey = sub.add_parser("genkey", help="generate the registry signing key")
    genkey.add_argument("--force", action="store_true")
    genkey.set_defaults(func=_cmd_genkey)

    issue = sub.add_parser("issue-token", help="issue an auditor submission token")
    issue.add_argument("auditor_id")
    issue.add_argument("--org", default="")
    issue.add_argument("--public-key", required=True, help="auditor ed25519 public key (ed25519:base64)")
    issue.set_defaults(func=_cmd_issue_token)

    sign = sub.add_parser("sign-record", help="sign a record body read from a file or stdin")
    sign.add_argument("--record", help="path to record JSON (default: stdin)")
    sign.set_defaults(func=_cmd_sign_record)

    snap = sub.add_parser("export-snapshot", help="print a signed snapshot")
    snap.set_defaults(func=_cmd_export_snapshot)

    export_b = sub.add_parser("export-bundle", help="export a signed bundle of all records")
    export_b.add_argument("--out", help="write the bundle to a file (default: stdout)")
    export_b.set_defaults(func=_cmd_export_bundle)

    import_b = sub.add_parser("import-bundle", help="import and countersign an upstream bundle")
    import_b.add_argument("bundle", help="path to the exported bundle JSON")
    import_b.add_argument("--upstream-key", required=True, help="upstream registry public key (ed25519:base64)")
    import_b.set_defaults(func=_cmd_import_bundle)

    verify_chain = sub.add_parser("verify-chain", help="verify the transparency log hash chain")
    verify_chain.set_defaults(func=_cmd_verify_chain)

    serve = sub.add_parser("serve", help="run the HTTP service")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8082)
    serve.set_defaults(func=_cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = args.func
    result = func(args)
    return int(result)


if __name__ == "__main__":
    raise SystemExit(main())
