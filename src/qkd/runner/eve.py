#!/usr/bin/env python3
"""
Eve: intercept-resend man-in-the-middle proxy between Alice and Bob.

Usage:
    Terminal 1: qkd-bob
    Terminal 2: qkd-eve
    Terminal 3: qkd-alice <file> --eve-mode
"""

from __future__ import annotations

import argparse
import sys

from qkd.core.config import ALICE_HOST, BOB_PORT, EVE_PORT
from qkd.services.reporting import eve_console
from qkd.services.wire import accept, connect_with_retry, listen
from qkd.usecases.eavesdrop_demo import run_eavesdrop


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Eve's intercept-resend proxy.")
    parser.add_argument("--bob-host", default=ALICE_HOST, help=f"Bob's host (default: {ALICE_HOST})")
    parser.add_argument("--bob-port", type=int, default=BOB_PORT, help=f"Bob's port (default: {BOB_PORT})")
    parser.add_argument("--listen-port", type=int, default=EVE_PORT, help=f"Port Alice connects to (default: {EVE_PORT})")
    parser.add_argument("--fraction", type=float, default=1.0,
                        help="Share of qubits to intercept, between 0 and 1 (default: 1.0, every qubit)")
    args = parser.parse_args(argv)
    if not 0.0 <= args.fraction <= 1.0:
        parser.error("--fraction must be between 0 and 1")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    reporter = eve_console()
    reporter.banner("BB84 QKD - EVE (Eavesdropper / MITM)", "Intercept-Resend Attack")
    reporter.section("Setting up Man-in-the-Middle Proxy")

    reporter.info(f"Connecting to Bob at {args.bob_host}:{args.bob_port}...")
    with connect_with_retry(args.bob_host, args.bob_port, attempts=1) as bob:
        reporter.info("Connected to Bob")
        reporter.info(f"Listening for Alice on port {args.listen_port}...")
        with listen(args.listen_port) as server:
            alice, addr = accept(server)
            with alice:
                reporter.info(f"Alice connected from {addr}")
                run_eavesdrop(alice, bob, reporter, fraction=args.fraction)
    return 0


if __name__ == "__main__":
    sys.exit(main())
