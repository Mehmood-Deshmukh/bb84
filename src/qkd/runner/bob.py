#!/usr/bin/env python3
"""
Bob: receiver in the BB84 QKD file transfer.

Usage:
    qkd-bob [--port P] [--output-dir DIR]
    qkd-bob --port 0 --events json        # any free port, JSON events (used by the backend node)
"""

from __future__ import annotations

import argparse
import socket
import sys

from qkd.core.config import BOB_PORT, OUTPUT_DIR
from qkd.services.reporting import (
    OUTCOME_ABORTED_QBER,
    OUTCOME_COMPLETED,
    OUTCOME_FAILED,
    ConsoleReporter,
    JsonEventReporter,
)
from qkd.services.wire import listen
from qkd.usecases.receive_file import receive_file


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Receive a file from Alice over a BB84-derived AES-256-GCM key.")
    parser.add_argument("--port", type=int, default=BOB_PORT, help=f"Port to listen on (default: {BOB_PORT}, 0 = any free port)")
    parser.add_argument("--output-dir", default=OUTPUT_DIR, help=f"Directory for received files (default: {OUTPUT_DIR})")
    parser.add_argument("--timeout", type=float, default=60.0, help="Seconds to wait for Alice (default: 60)")
    parser.add_argument("--events", choices=["text", "json"], default="text", help="Output format (default: text)")
    parser.add_argument("--transfer-id", help="Transfer id to include in JSON events")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.events == "json":
        reporter = JsonEventReporter(args.transfer_id)
    else:
        reporter = ConsoleReporter()
        reporter.banner("BB84 QKD Secure File Transfer", "BOB (Receiver)")

    reporter.stage("connecting")
    with listen(args.port) as server:
        port = server.getsockname()[1]
        reporter.listening(port)
        reporter.info(f"Listening on port {port}...")
        reporter.info(f"Waiting for Alice's connection ({args.timeout:.0f}s timeout)...")
        server.settimeout(args.timeout)
        try:
            conn, addr = server.accept()
        except socket.timeout:
            reporter.error("Timed out waiting for Alice's connection.")
            reporter.result(OUTCOME_FAILED, "timed out waiting for the sender")
            return 1
        conn.settimeout(None)
        reporter.success(f"Alice connected from {addr}")

        with conn:
            try:
                result = receive_file(conn, args.output_dir, reporter)
            except Exception as exc:
                reporter.error(f"Decryption FAILED: {exc!r}")
                reporter.error("Authentication tag mismatch or connection lost. Partial output removed.")
                reporter.result(OUTCOME_FAILED, str(exc) or type(exc).__name__)
                return 1

    kx = result.key_exchange
    if kx.aborted:
        reporter.result(OUTCOME_ABORTED_QBER, f"QBER {kx.qber:.2%} >= threshold {kx.threshold:.0%}")
        return 1
    reporter.metrics(output_path=result.output_path, bytes_written=result.bytes_written)
    reporter.result(OUTCOME_COMPLETED)
    return 0


if __name__ == "__main__":
    sys.exit(main())
