"""Command line: ``python -m sso_client check | login [--follow]``."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import Callable, Optional, Sequence, TextIO

from .client import Client
from .config import Config
from .errors import APIError, ConfigError, LeavesGatewayError, PolicyError, SSOClientError

DEFAULT_PROVIDER = "auth0"


def run(
    argv: Sequence[str],
    getenv: Callable[[str], Optional[str]] = os.environ.get,
    out: TextIO = sys.stdout,
    err: TextIO = sys.stderr,
) -> int:
    """Run one command and return the process exit code."""
    parser = argparse.ArgumentParser(prog="sso_client", description="Universal SSO gateway client")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("check", help="gateway reachable and provider registered")
    login = sub.add_parser("login", help="start a sign-in")
    login.add_argument("--follow", action="store_true", help="finish without a browser (mock provider only)")
    try:
        args = parser.parse_args(list(argv))
    except SystemExit as e:  # argparse already printed the message
        return int(e.code or 0)
    if not args.command:
        parser.print_usage(err)
        return 2
    try:
        cfg = Config.from_lookup(getenv, DEFAULT_PROVIDER)
    except ConfigError as e:
        print(f"configuration error: {e}", file=err)
        return 2

    level = {"debug": logging.DEBUG, "info": logging.INFO}.get((getenv("SSO_LOG_LEVEL") or "").lower(), logging.WARNING)
    logging.basicConfig(level=level, stream=err, format="%(levelname)s %(name)s: %(message)s")
    client = Client(cfg)
    return _check(client, out, err) if args.command == "check" else _login(client, args.follow, out, err)


def _check(client: Client, out: TextIO, err: TextIO) -> int:
    try:
        client.health()
        ids = client.providers()
    except SSOClientError as e:
        print(f"gateway check failed: {e}", file=err)
        return 1
    print(f"gateway ok, providers: {', '.join(ids)}", file=out)
    if client.cfg.provider not in ids:
        print(f"provider {client.cfg.provider!r} is not registered in the gateway", file=err)
        return 1
    return 0


def _login(client: Client, follow: bool, out: TextIO, err: TextIO) -> int:
    try:
        started = client.start_login()
        if not follow:
            print("Open this URL in a browser to sign in:", file=out)
            print(started.authorize_url, file=out)
            print("The identity provider returns the browser to the gateway callback, which completes the login.", file=out)
            return 0
        profile = client.follow_local(started)
    except APIError as e:
        if e.code == "PROVIDER_NOT_FOUND":
            print(f"the gateway has no such provider ({e.message}). Its adapter may not be implemented yet: see Docs/Architecture.md", file=err)
        else:
            print(f"login failed: {e}", file=err)
        return 1
    except PolicyError as e:
        print(f"refused to continue: {e}", file=err)
        return 1
    except LeavesGatewayError as e:
        print(e, file=err)
        return 1
    except SSOClientError as e:
        print(f"login failed: {e}", file=err)
        return 1
    print(f"signed in via {profile.provider_id} as {profile.user.display_name} ({profile.user.email})", file=out)
    return 0


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))
