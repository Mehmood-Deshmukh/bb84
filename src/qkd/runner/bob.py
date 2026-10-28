#!/usr/bin/env python3
"""
Bob: receiver in the BB84 QKD file transfer.

Usage:
    qkd-bob [--port P] [--output-dir DIR]
"""

from __future__ import annotations

import argparse
import socket
import sys

from qkd.core.config import BOB_PORT, OUTPUT_DIR
from qkd.services.reporting import ConsoleReporter
from qkd.services.wire import listen
from qkd.usecases.receive_file import receive_file


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Receive a file from Alice over a BB84-derived AES-256-GCM key.")
    parser.add_argument("--port", type=int, default=BOB_PORT, help=f"Port to listen on (default: {BOB_PORT}, 0 = any free port)")
    parser.add_argument("--output-dir", default=OUTPUT_DIR, help=f"Directory for received files (default: {OUTPUT_DIR})")
    parser.add_argument("--timeout", type=float, default=60.0, help="Seconds to wait for Alice (default: 60)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    reporter = ConsoleReporter()
    reporter.banner("BB84 QKD Secure File Transfer", "BOB (Receiver)")

    with listen(args.port) as server:
        reporter.info(f"Listening on port {server.getsockname()[1]}...")
        reporter.info(f"Waiting for Alice's connection ({args.timeout:.0f}s timeout)...")
        server.settimeout(args.timeout)
        try:
            conn, addr = server.accept()
        except socket.timeout:
            reporter.error("Timed out waiting for Alice's connection.")
            return 1
        conn.settimeout(None)
        reporter.success(f"Alice connected from {addr}")

        with conn:
            try:
                result = receive_file(conn, args.output_dir, reporter)
            except Exception as exc:
                reporter.error(f"Decryption FAILED: {exc!r}")
                reporter.error("Authentication tag mismatch or connection lost. Partial output removed.")
                return 1
    return 1 if result.key_exchange.aborted else 0


if __name__ == "__main__":
    sys.exit(main())
