from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
from pathlib import Path

from .clock import utc_now
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
    body = json.loads(Path(args.record).read_text(encoding="utf-8") if args.record else sys.stdin.read())
    print(json.dumps(key.sign_record(body), indent=2))
    return 0


def _cmd_export_snapshot(args: argparse.Namespace) -> int:
    home = _home(args)
    key = load_key((home / "signing-key.pem").read_bytes())
    store = Store(home / "registry.db")
    size, _ = store.head()
    print(json.dumps(build_snapshot(store, key, created_at=utc_now(), version=size), indent=2))
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

    import os

    os.environ.setdefault("CSK_REGISTRY_HOME", args.home)
    uvicorn.run(app_from_env(), host=args.host, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="csk-registry", description="CocoaSkills audit registry admin tool")
    parser.add_argument("--home", default="./data", help="registry data directory")
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
