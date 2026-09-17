from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import secrets
import sys
from pathlib import Path

from . import COMMAND_NAME, HEALTH_VERIFY_INTERVAL_ENV, HOME_ENV, home_from_env
from .auth import Auditor, AuditorTokens
from .bundle import export_bundle, import_bundle
from .clock import utc_now
from .keys import (
    active_key_path,
    activate_rotation,
    cancel_rotation,
    initialize_key,
    load_active_key,
    prepare_rotation,
    public_keys,
    retire_public_key,
    write_private_json,
)
from .permissions import protect_private_directory
from .protocol import load_json, validate_record, validate_snapshot
from .signing import verify_signed
from .snapshot import build_snapshot
from .store import (
    DEFAULT_HEALTH_VERIFY_INTERVAL_SECONDS,
    SnapshotBoundary,
    Store,
    StoreIntegrityError,
)


def _home(args: argparse.Namespace) -> Path:
    home = Path(args.home).expanduser()
    home.mkdir(parents=True, exist_ok=True)
    protect_private_directory(home)
    return home


def _cmd_genkey(args: argparse.Namespace) -> int:
    home = _home(args)
    key_path = active_key_path(home)
    if key_path.exists() and not args.force:
        print(f"signing key already exists at {key_path} (use --force to overwrite)", file=sys.stderr)
        return 1
    if key_path.exists() and args.force and (home / "registry.db").exists():
        try:
            store = Store(home / "registry.db")
            log_size = store.head()[0]
            store.close()
        except StoreIntegrityError as exc:
            print(f"refusing to replace a key for an invalid registry: {exc}", file=sys.stderr)
            return 2
        if log_size > 0:
            print("refusing to replace the signing key for a non-empty registry; use staged rotation", file=sys.stderr)
            return 1
    try:
        key = initialize_key(home, replace=args.force)
    except (OSError, ValueError) as exc:
        print(f"could not generate signing key: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"key_id": key.key_id, "public_key": key.public_pinned, "path": str(key_path)}, indent=2))
    return 0


def _cmd_prepare_key_rotation(args: argparse.Namespace) -> int:
    home = _home(args)
    try:
        active, staged = prepare_rotation(home)
    except (OSError, ValueError) as exc:
        print(f"could not prepare signing-key rotation: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "active_key_id": active.key_id,
                "active_public_key": active.public_pinned,
                "next_key_id": staged.key_id,
                "next_public_key": staged.public_pinned,
                "next_step": "deploy the expanded out-of-band pin set, then run activate-key-rotation",
            },
            indent=2,
        )
    )
    return 0


def _cmd_activate_key_rotation(args: argparse.Namespace) -> int:
    if not args.confirm_pins_deployed:
        print("activation requires --confirm-pins-deployed", file=sys.stderr)
        return 1
    home = _home(args)
    try:
        previous, active = activate_rotation(home)
    except (OSError, ValueError) as exc:
        print(f"could not activate signing-key rotation: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "active_key_id": active.key_id,
                "active_public_key": active.public_pinned,
                "retained_key_id": previous.key_id,
                "next_step": "wait through the overlap and cursor-retention window before retire-key",
            },
            indent=2,
        )
    )
    return 0


def _cmd_cancel_key_rotation(args: argparse.Namespace) -> int:
    if not args.confirm:
        print("cancellation requires --confirm", file=sys.stderr)
        return 1
    home = _home(args)
    try:
        staged = cancel_rotation(home)
    except (OSError, ValueError) as exc:
        print(f"could not cancel signing-key rotation: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"cancelled_key_id": staged.key_id}, indent=2))
    return 0


def _cmd_retire_key(args: argparse.Namespace) -> int:
    if not args.confirm_overlap_elapsed and not args.compromised:
        print("retirement requires --confirm-overlap-elapsed or --compromised", file=sys.stderr)
        return 1
    home = _home(args)
    try:
        retired = retire_public_key(home, args.key_id)
    except (OSError, ValueError) as exc:
        print(f"could not retire signing key: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "retired_key_id": args.key_id,
                "retired_public_key": retired,
                "reason": "compromised" if args.compromised else "overlap elapsed",
            },
            indent=2,
        )
    )
    return 0


def _cmd_issue_token(args: argparse.Namespace) -> int:
    home = _home(args)
    auditors_path = home / "auditors.json"
    try:
        if auditors_path.exists():
            AuditorTokens.from_file(auditors_path)
            data = load_json(auditors_path.read_bytes())
            if not isinstance(data, dict):
                raise ValueError("auditors file must be an object")
        else:
            data = {"auditors": []}
        token = secrets.token_urlsafe(32)
        token_sha256 = hashlib.sha256(token.encode("utf-8")).hexdigest()
        AuditorTokens(
            [
                Auditor(
                    auditor_id=args.auditor_id,
                    org=args.org,
                    public_pinned=args.public_key,
                    token_sha256=token_sha256,
                )
            ]
        )
        data["auditors"] = [
            auditor
            for auditor in data.get("auditors", [])
            if auditor.get("auditor_id") != args.auditor_id
        ]
        data["auditors"].append(
            {
                "auditor_id": args.auditor_id,
                "org": args.org,
                "public_key": args.public_key,
                "token_sha256": token_sha256,
            }
        )
        write_private_json(auditors_path, data)
    except (OSError, TypeError, ValueError) as exc:
        print(f"could not issue auditor token: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"auditor_id": args.auditor_id, "token": token}, indent=2))
    print("Store this token now; only its hash is kept on the server.", file=sys.stderr)
    return 0


def _cmd_sign_record(args: argparse.Namespace) -> int:
    home = _home(args)
    key = load_active_key(home)
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
    key = load_active_key(home)
    store = Store(home / "registry.db")
    print(json.dumps(build_snapshot(store, key), indent=2))
    return 0


def _cmd_export_bundle(args: argparse.Namespace) -> int:
    home = _home(args)
    key = load_active_key(home)
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
    key = load_active_key(home)
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
    try:
        store = Store(home / "registry.db")
    except StoreIntegrityError as exc:
        print(json.dumps({"state_valid": False, "error": str(exc)}, indent=2))
        return 2
    print(json.dumps({"state_valid": True, "log_size": store.head()[0]}, indent=2))
    return 0


def _cmd_backup(args: argparse.Namespace) -> int:
    home = _home(args)
    key = load_active_key(home)
    store = Store(home / "registry.db")
    database_path = Path(args.out).expanduser()
    checkpoint_path = Path(args.checkpoint_out).expanduser()
    if database_path.exists() or checkpoint_path.exists():
        print("backup output already exists", file=sys.stderr)
        return 1
    boundary = store.backup_to(database_path)
    checkpoint = build_snapshot(store, key, boundary=boundary)
    checkpoint_path.write_text(
        json.dumps(checkpoint, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "database": str(database_path),
                "checkpoint": str(checkpoint_path),
                "log_size": boundary.log_size,
                "head": boundary.head,
            },
            indent=2,
        )
    )
    return 0


def _cmd_verify_backup(args: argparse.Namespace) -> int:
    home = _home(args)
    try:
        store = Store(Path(args.database).expanduser())
        checkpoint_value = load_json(Path(args.checkpoint).expanduser().read_bytes())
        checkpoint = validate_snapshot(checkpoint_value)
        checkpoint_keys = (args.public_key,) if args.public_key else public_keys(home)
        if not any(verify_signed(public_key, checkpoint) for public_key in checkpoint_keys):
            raise ValueError("checkpoint signature does not verify")
        boundary = SnapshotBoundary(
            version=checkpoint["version"],
            log_size=checkpoint["log_size"],
            head=checkpoint["head"],
            merkle_root=checkpoint["merkle_root"],
            created_at=checkpoint["created_at"],
        )
        if not store.checkpoint_matches(boundary):
            raise ValueError("backup is below or inconsistent with the checkpoint")
    except (OSError, ValueError, StoreIntegrityError) as exc:
        print(json.dumps({"backup_valid": False, "error": str(exc)}, indent=2))
        return 2
    print(
        json.dumps(
            {
                "backup_valid": True,
                "log_size": boundary.log_size,
                "head": boundary.head,
            },
            indent=2,
        )
    )
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    if bool(args.ssl_certfile) != bool(args.ssl_keyfile):
        print("serve requires both --ssl-certfile and --ssl-keyfile", file=sys.stderr)
        return 1
    if args.behind_https_proxy and not args.trusted_proxy:
        print("--behind-https-proxy requires --trusted-proxy", file=sys.stderr)
        return 1
    if not _loopback_host(args.host) and not args.ssl_certfile and not args.behind_https_proxy:
        print(
            "refusing plain HTTP on a non-loopback host; configure TLS or an explicitly trusted HTTPS proxy",
            file=sys.stderr,
        )
        return 1
    if args.health_verify_interval is not None and (
        not math.isfinite(args.health_verify_interval) or args.health_verify_interval <= 0
    ):
        print("serve requires --health-verify-interval to be a positive number of seconds", file=sys.stderr)
        return 1
    import uvicorn

    from .app import app_from_env

    os.environ[HOME_ENV] = args.home
    if args.health_verify_interval is not None:
        os.environ[HEALTH_VERIFY_INTERVAL_ENV] = str(args.health_verify_interval)
    uvicorn.run(
        app_from_env(),
        host=args.host,
        port=args.port,
        ssl_certfile=args.ssl_certfile,
        ssl_keyfile=args.ssl_keyfile,
        proxy_headers=args.behind_https_proxy,
        forwarded_allow_ips=args.trusted_proxy or "",
    )
    return 0


def _loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=COMMAND_NAME, description="Curator Skill Registry administration tool")
    parser.add_argument("--home", default=home_from_env(), help="registry data directory")
    sub = parser.add_subparsers(dest="command", required=True)

    genkey = sub.add_parser("genkey", help="generate the registry signing key")
    genkey.add_argument("--force", action="store_true")
    genkey.set_defaults(func=_cmd_genkey)

    prepare_key = sub.add_parser(
        "prepare-key-rotation",
        help="stage a new signer and publish an overlap key set",
    )
    prepare_key.set_defaults(func=_cmd_prepare_key_rotation)

    activate_key = sub.add_parser(
        "activate-key-rotation",
        help="activate the staged signer after clients receive both pins",
    )
    activate_key.add_argument("--confirm-pins-deployed", action="store_true")
    activate_key.set_defaults(func=_cmd_activate_key_rotation)

    cancel_key = sub.add_parser(
        "cancel-key-rotation",
        help="remove a staged signer before activation",
    )
    cancel_key.add_argument("--confirm", action="store_true")
    cancel_key.set_defaults(func=_cmd_cancel_key_rotation)

    retire_key = sub.add_parser(
        "retire-key",
        help="remove an inactive public key after overlap or compromise",
    )
    retire_key.add_argument("key_id")
    retirement = retire_key.add_mutually_exclusive_group()
    retirement.add_argument("--confirm-overlap-elapsed", action="store_true")
    retirement.add_argument("--compromised", action="store_true")
    retire_key.set_defaults(func=_cmd_retire_key)

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

    backup = sub.add_parser("backup", help="create a consistent database backup and signed checkpoint")
    backup.add_argument("--out", required=True, help="new backup database path")
    backup.add_argument("--checkpoint-out", required=True, help="new signed checkpoint path")
    backup.set_defaults(func=_cmd_backup)

    verify_backup = sub.add_parser(
        "verify-backup",
        help="verify a candidate backup against a signed high-water checkpoint",
    )
    verify_backup.add_argument("database", help="candidate backup database path")
    verify_backup.add_argument("--checkpoint", required=True, help="signed checkpoint JSON")
    verify_backup.add_argument(
        "--public-key",
        help="checkpoint signing key (default: registry key under --home)",
    )
    verify_backup.set_defaults(func=_cmd_verify_backup)

    serve = sub.add_parser("serve", help="run the HTTP service")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8082)
    serve.add_argument("--ssl-certfile", help="TLS certificate chain for direct HTTPS")
    serve.add_argument("--ssl-keyfile", help="TLS private key for direct HTTPS")
    serve.add_argument(
        "--behind-https-proxy",
        action="store_true",
        help="confirm that a trusted reverse proxy terminates HTTPS",
    )
    serve.add_argument(
        "--trusted-proxy",
        help="comma-separated proxy IPs allowed to supply forwarded headers",
    )
    serve.add_argument(
        "--health-verify-interval",
        type=float,
        default=None,
        metavar="SECONDS",
        help=(
            "seconds between background full-integrity passes refreshing the "
            "cached /health verdict "
            f"(default: {DEFAULT_HEALTH_VERIFY_INTERVAL_SECONDS:g}; "
            f"{HEALTH_VERIFY_INTERVAL_ENV} when the flag is absent)"
        ),
    )
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
