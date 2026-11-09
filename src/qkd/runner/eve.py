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

from qkd.core.config import ALICE_HOST, BOB_PORT, EVE_PORT, ProtocolParams
from qkd.services.reporting import JsonEventReporter, eve_console
from qkd.services.wire import accept, connect_with_retry, listen
from qkd.usecases.eavesdrop_demo import run_eavesdrop
from qkd.usecases.pns_demo import run_pns


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Eve's eavesdropper proxy.")
    parser.add_argument("--bob-host", default=ALICE_HOST, help=f"Bob's host (default: {ALICE_HOST})")
    parser.add_argument("--bob-port", type=int, default=BOB_PORT, help=f"Bob's port (default: {BOB_PORT})")
    parser.add_argument("--listen-port", type=int, default=EVE_PORT, help=f"Port Alice connects to (default: {EVE_PORT})")
    parser.add_argument("--attack", choices=["intercept", "pns"], default="intercept",
                        help="intercept-resend (default) or photon-number-splitting (needs a weak-coherent "
                             "source and Alice in --eve-mode)")
    parser.add_argument("--fraction", type=float, default=1.0,
                        help="intercept: share of qubits Eve intercepts, 0 to 1 (default: 1.0)")
    parser.add_argument("--multi-fraction", type=float, default=None,
                        help="pns: share of multi-photon pulses forwarded (default: tune to the honest gain)")
    parser.add_argument("--forward-fraction", type=float, default=None,
                        help="pns: share of single-photon pulses forwarded (default: tune to the honest gain)")
    parser.add_argument("--events", choices=["text", "json"], default="text",
                        help="Output format (default: text). json emits Eve's metrics as events.")
    args = parser.parse_args(argv)
    if not 0.0 <= args.fraction <= 1.0:
        parser.error("--fraction must be between 0 and 1")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    pns = args.attack == "pns"
    if args.events == "json":
        reporter = JsonEventReporter()
    else:
        reporter = eve_console()
        reporter.banner("BB84 QKD - EVE (Eavesdropper / MITM)",
                        "Photon-Number-Splitting Attack" if pns else "Intercept-Resend Attack")
    reporter.section("Setting up Man-in-the-Middle Proxy")

    reporter.info(f"Connecting to Bob at {args.bob_host}:{args.bob_port}...")
    with connect_with_retry(args.bob_host, args.bob_port, attempts=1) as bob:
        reporter.info("Connected to Bob")
        reporter.info(f"Listening for Alice on port {args.listen_port}...")
        with listen(args.listen_port) as server:
            alice, addr = accept(server)
            with alice:
                reporter.info(f"Alice connected from {addr}")
                if pns:
                    run_pns(alice, bob, reporter, ProtocolParams(),
                            forward_fraction=args.forward_fraction, multi_fraction=args.multi_fraction)
                else:
                    run_eavesdrop(alice, bob, reporter, fraction=args.fraction)
    return 0


if __name__ == "__main__":
    sys.exit(main())
