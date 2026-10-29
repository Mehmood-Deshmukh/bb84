#!/usr/bin/env python3
"""
Mallory: active man-in-the-middle proxy between Alice and Bob.

Unlike Eve (who passively forwards classical messages and only intercepts
qubits), Mallory is an active adversary. She intercepts the classical
channel, establishes separate sessions with Alice and Bob, and decrypts/re-encrypts
file traffic in transit.

Usage:
    Terminal 1: qkd-bob
    Terminal 2: python -m qkd.runner.mallory [--scenario {none,own_identity,relay_hello}]
    Terminal 3: qkd-alice <file> --eve-mode
"""

from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path

from qkd.core.config import ALICE_HOST, AUTH_MODE, BOB_PORT, EVE_PORT, IDENTITY_DIR, ProtocolParams
from qkd.services.reporting import (
    OUTCOME_ABORTED_AUTH,
    OUTCOME_ABORTED_QBER,
    OUTCOME_COMPLETED,
    OUTCOME_FAILED,
    ConsoleReporter,
    JsonEventReporter,
    Reporter,
)
from qkd.services.wire import connect_with_retry, listen
from qkd.usecases.common import PeerAuthError


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Mallory's active MITM proxy.")
    parser.add_argument("--bob-host", default=ALICE_HOST, help=f"Bob's host (default: {ALICE_HOST})")
    parser.add_argument("--bob-port", type=int, default=BOB_PORT, help=f"Bob's port (default: {BOB_PORT})")
    parser.add_argument(
        "--listen-port",
        type=int,
        default=EVE_PORT,
        help=f"Port Alice connects to (default: {EVE_PORT})",
    )
    parser.add_argument(
        "--scenario",
        choices=["none", "own_identity", "relay_hello"],
        default="own_identity",
        help="MITM attack scenario: none (auth off), own_identity (Mallory's key), relay_hello (Bob's hello relayed)",
    )
    parser.add_argument(
        "--strategy",
        choices=["own_key", "relay_hello"],
        default=None,
        help="MITM attack strategy (default: own_key)",
    )
    parser.add_argument(
        "--auth",
        choices=["none", "sign", "hybrid"],
        default=None,
        help=f"Authentication mode (default: {AUTH_MODE})",
    )
    parser.add_argument(
        "--identity",
        default=str(Path(IDENTITY_DIR) / "mallory"),
        help="Mallory's identity directory (default: identity/mallory)",
    )
    parser.add_argument("--events", choices=["text", "json"], default="text", help="Output format (default: text)")
    parser.add_argument("--transfer-id", help="Transfer id to include in JSON events")
    return parser.parse_args(argv)


def make_reporter(args: argparse.Namespace) -> Reporter:
    if args.events == "json":
        return JsonEventReporter(args.transfer_id)
    # Magenta ANSI styling for active attacker
    return ConsoleReporter(accent="\033[95m", info_color="\033[95m")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    reporter = make_reporter(args)

    # Resolve mode and strategy
    if args.scenario is not None:
        if args.scenario == "none":
            mode = "none"
            strategy = "own_key"
        elif args.scenario == "relay_hello":
            mode = args.auth or AUTH_MODE
            strategy = "relay_hello"
        else:  # "own_identity"
            mode = args.auth or AUTH_MODE
            strategy = "own_key"
    else:
        strategy = args.strategy or "own_key"
        mode = args.auth or AUTH_MODE

    if hasattr(reporter, "banner"):
        reporter.banner("BB84 QKD - MALLORY (Active MITM)", f"Mode: {mode}, Strategy: {strategy}")
    reporter.section("Setting up Active MITM Proxy")

    # Connect to Bob
    reporter.info(f"Connecting to Bob at {args.bob_host}:{args.bob_port}...")
    try:
        bob_sock = connect_with_retry(args.bob_host, args.bob_port, attempts=2, delay=0.2)
    except (ConnectionError, OSError) as exc:
        reporter.error(f"Network error: Failed to connect to Bob at {args.bob_host}:{args.bob_port}: {exc}")
        reporter.result(OUTCOME_FAILED, f"Network error: {exc}")
        return 2

    reporter.info("Connected to Bob")

    # Listen for Alice
    reporter.info(f"Listening for Alice on port {args.listen_port}...")
    try:
        server_sock = listen(args.listen_port)
    except (OSError, socket.error) as exc:
        bob_sock.close()
        reporter.error(f"Startup error: Could not listen on port {args.listen_port}: {exc}")
        reporter.result(OUTCOME_FAILED, f"Startup error: {exc}")
        return 2

    try:
        with server_sock, bob_sock:
            alice_sock, addr = server_sock.accept()
            with alice_sock:
                reporter.info(f"Alice connected from {addr}")

                # Call Person A's usecases.mitm_demo workflow
                try:
                    from qkd.usecases.mitm_demo import run_mitm
                except ImportError:
                    reporter.error(
                        "Interface pending: 'qkd.usecases.mitm_demo.run_mitm' has not yet been landed by Person A."
                    )
                    reporter.result(
                        OUTCOME_FAILED,
                        "Pending Person A interface: src/qkd/usecases/mitm_demo.py:run_mitm",
                    )
                    return 3

                identity = None
                if args.identity:
                    id_path = Path(args.identity)
                    if (id_path / "identity.seed").exists() and (id_path / "identity.pub").exists():
                        try:
                            from qkd.services.identity import load_or_create_identity
                            id_obj = load_or_create_identity(id_path)
                            identity = (id_obj.public_key, id_obj.seed)
                        except Exception as e:
                            reporter.warning(f"Could not load identity from {id_path}: {e}")

                try:
                    result = run_mitm(
                        alice_sock=alice_sock,
                        bob_sock=bob_sock,
                        reporter=reporter,
                        params=ProtocolParams(),
                        mode=mode,
                        strategy=strategy,
                        identity=identity,
                    )
                except PeerAuthError as exc:
                    reporter.success(f"Security check passed: Attack BLOCKED by authentication ({exc.reason})")
                    reporter.result(OUTCOME_ABORTED_AUTH, exc.reason)
                    return 0
                except Exception as exc:
                    reporter.error(f"MITM execution error: {exc!r}")
                    reporter.result(OUTCOME_FAILED, str(exc) or type(exc).__name__)
                    return 1

                if result.plaintext_sha256:
                    reporter.warning("VULNERABILITY DEMONSTRATED: Classical channel was unauthenticated!")
                    reporter.info(f"Mallory captured plaintext SHA-256: {result.plaintext_sha256}")
                    reporter.result(OUTCOME_COMPLETED, None)
                    return 0

                if result.alice_error:
                    if "qber" in result.alice_error.lower():
                        reporter.info(f"Attack stopped by QBER threshold: {result.alice_error}")
                        reporter.result(OUTCOME_ABORTED_QBER, result.alice_error)
                        return 1
                    reporter.success(f"Security check passed: Attack BLOCKED by authentication ({result.alice_error})")
                    reporter.result(OUTCOME_ABORTED_AUTH, result.alice_error)
                    return 0

                if result.relayed:
                    reporter.success("Relayed file to Bob undetected")
                    reporter.result(OUTCOME_COMPLETED, None)
                    return 0

                reporter.result(OUTCOME_COMPLETED, None)
                return 0

    except KeyboardInterrupt:
        reporter.info("Mallory stopped by user")
        return 130


if __name__ == "__main__":
    sys.exit(main())
