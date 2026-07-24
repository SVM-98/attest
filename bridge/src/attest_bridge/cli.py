"""attest-bridge CLI: `serve`, `check-config`, `retry-failed` (task-8-brief.md).

`check-config` deliberately stops at config + issuer + catalog validation —
it never touches the Ledger (no sqlite file is created just to validate a
config) and never contacts a platform. `serve`/`retry-failed` need the full
runtime (Ledger, Delivery, IssuingCore, the platform adapters), assembled by
`_build_deps`.
"""

from __future__ import annotations

import argparse
import json
import logging
import socketserver
import sys
from datetime import UTC, datetime
from pathlib import Path
from wsgiref.simple_server import WSGIServer, make_server

from attest_bridge.catalog import ProductCatalog
from attest_bridge.config import load_config
from attest_bridge.core import IssuingCore
from attest_bridge.delivery import Delivery
from attest_bridge.http import BridgeDeps, make_app
from attest_bridge.ledger import Ledger
from attest_bridge.model import ConfigError
from attest_bridge.signing import load_issuer
from attest_bridge.stripe_adapter import StripeAdapter

_RFC3339 = "%Y-%m-%dT%H:%M:%SZ"
_RC_OK = 0
_RC_CONFIG_ERROR = 2


def _now_rfc3339() -> str:
    return datetime.now(UTC).strftime(_RFC3339)


class _ThreadingWSGIServer(socketserver.ThreadingMixIn, WSGIServer):
    """WSGI server that dispatches each request to its own thread.

    Safe by construction: `Ledger` (T4) serializes every access — reads and
    writes alike — under its own connection lock, so no additional locking
    is added here or in `http.py`.
    """

    daemon_threads = True


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="attest-bridge")
    sub = parser.add_subparsers(dest="command", required=True)

    serve_parser = sub.add_parser("serve", help="run the webhook bridge")
    serve_parser.add_argument("--config", required=True)
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8080)

    check_parser = sub.add_parser("check-config", help="validate config, keys, and catalog")
    check_parser.add_argument("--config", required=True)

    retry_parser = sub.add_parser("retry-failed", help="re-drive unresolved dead letters")
    retry_parser.add_argument("--config", required=True)

    return parser


def _build_deps(config_path: Path, *, log: logging.Logger) -> BridgeDeps:
    """Assemble the full runtime: config, issuer, ledger, delivery, core, adapters.

    Raises `ConfigError` fail-fast — never partially wires a bridge with a
    bad key or missing secret.
    """
    config = load_config(config_path)
    issuer = load_issuer(config.issuer)
    catalog = ProductCatalog(config.products)
    ledger = Ledger(config.ledger_path)
    delivery = Delivery(config.delivery)
    core = IssuingCore(
        catalog=catalog,
        issuer=issuer,
        ledger=ledger,
        public_base_url=config.public_base_url,
        delivery=delivery,
    )
    stripe = (
        StripeAdapter(webhook_secret=config.stripe.webhook_secret, api_key=config.stripe.api_key)
        if config.stripe is not None
        else None
    )
    return BridgeDeps(config=config, core=core, ledger=ledger, stripe=stripe, log=log)


def _cmd_serve(args: argparse.Namespace) -> int:
    log = logging.getLogger("attest_bridge")
    logging.basicConfig(level=logging.INFO)
    try:
        deps = _build_deps(Path(args.config), log=log)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return _RC_CONFIG_ERROR

    app = make_app(deps)
    host: str = args.host
    port: int = args.port
    with make_server(host, port, app, server_class=_ThreadingWSGIServer) as httpd:
        log.info("attest-bridge serving on %s:%d", host, port)
        httpd.serve_forever()
    return _RC_OK


def _cmd_check_config(args: argparse.Namespace) -> int:
    try:
        config = load_config(Path(args.config))
        issuer = load_issuer(config.issuer)
        catalog = ProductCatalog(config.products)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return _RC_CONFIG_ERROR

    print(f"issuer: {issuer.issuer_id} (kid={issuer.kid})")
    print(f"public_base_url: {config.public_base_url}")
    print(f"products: {', '.join(catalog.keys()) or '(none)'}")
    print(f"stripe: {'configured' if config.stripe is not None else 'not configured'}")
    print(f"delivery: {'smtp' if config.delivery is not None else 'download-link-only'}")
    return _RC_OK


def _cmd_retry_failed(args: argparse.Namespace) -> int:
    log = logging.getLogger("attest_bridge")
    try:
        deps = _build_deps(Path(args.config), log=log)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return _RC_CONFIG_ERROR

    resolved = 0
    still_failing = 0
    for dead_letter in deps.ledger.unresolved_dead_letters():
        if dead_letter.platform != "stripe" or deps.stripe is None:
            # Only the Stripe adapter is wired up in T8; a dead letter from a
            # platform with no adapter configured is left for a later retry.
            still_failing += 1
            continue
        try:
            event = json.loads(dead_letter.raw_json)
            purchase = deps.stripe.normalize(event)
            deps.core.process(purchase)
        except Exception as exc:  # still bad input, or a transient failure — leave unresolved
            still_failing += 1
            log.warning("retry-failed: dead letter %d still failing: %s", dead_letter.id, exc)
            continue
        deps.ledger.resolve_dead_letter(dead_letter.id, now=_now_rfc3339())
        resolved += 1

    print(f"resolved: {resolved}, still failing: {still_failing}")
    return _RC_OK


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "serve":
        return _cmd_serve(args)
    if args.command == "check-config":
        return _cmd_check_config(args)
    if args.command == "retry-failed":
        return _cmd_retry_failed(args)
    parser.error(
        f"unknown command: {args.command}"
    )  # pragma: no cover - argparse exits before this
    return _RC_CONFIG_ERROR  # pragma: no cover - unreachable, parser.error raises SystemExit
