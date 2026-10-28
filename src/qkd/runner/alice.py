#!/usr/bin/env python3
"""
Alice: sender in the BB84 QKD file transfer.

Usage:
    qkd-alice <file> [--host H] [--port P]
    qkd-alice <file> --eve-mode           # connect to Eve's proxy port instead of Bob
"""

from __future__ import annotations

import argparse
import sys

from qkd.core.config import ALICE_HOST, BOB_PORT, EVE_PORT
from qkd.services.reporting import ConsoleReporter
from qkd.services.wire import connect_with_retry
from qkd.usecases.send_file import send_file


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send a file to Bob over a BB84-derived AES-256-GCM key.")
    parser.add_argument("file", help="File to send")
    parser.add_argument("--host", default=ALICE_HOST, help=f"Receiver host (default: {ALICE_HOST})")
    parser.add_argument("--port", type=int, help=f"Receiver port (default: {BOB_PORT}, or {EVE_PORT} with --eve-mode)")
    parser.add_argument("--eve-mode", action="store_true", help="Connect to Eve's proxy port")
    args = parser.parse_args(argv)
    if args.port is None:
        args.port = EVE_PORT if args.eve_mode else BOB_PORT
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    reporter = ConsoleReporter()

    if args.eve_mode:
        reporter.warning(f"EVE MODE: Connecting to Eve's proxy at {args.host}:{args.port}")
    else:
        reporter.info(f"Connecting to Bob at {args.host}:{args.port}")
    try:
        sock = connect_with_retry(args.host, args.port)
    except OSError as exc:
        reporter.error(f"Failed to connect to {args.host}:{args.port}: {exc}")
        return 1
    reporter.success(f"Connected to {'Eve (proxy)' if args.eve_mode else 'Bob'}")

    with sock:
        result = send_file(sock, args.file, reporter)
    return 1 if result.aborted else 0


if __name__ == "__main__":
    sys.exit(main())
