#!/usr/bin/env python3
"""
Bob: receiver in the BB84 QKD file transfer.

Usage:
    qkd-bob [--port P] [--output-dir DIR]
    qkd-bob --port 0 --events json        # any free port, JSON events (used by the backend node)
    qkd-bob --auth none                   # disable authentication
    qkd-bob --peer-fingerprint FP         # pin a specific peer key
"""

from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path

from qkd.core.config import AUTH_MODE, BOB_PORT, IDENTITY_DIR, KNOWN_PEERS_FILE, OUTPUT_DIR, TOFU
from qkd.services.reporting import (
    OUTCOME_ABORTED_AUTH,
    OUTCOME_ABORTED_QBER,
    OUTCOME_COMPLETED,
    OUTCOME_FAILED,
    ConsoleReporter,
    JsonEventReporter,
)
from qkd.services.wire import accept, listen
from qkd.usecases.common import KeyConfirmationError, PeerAuthError
from qkd.usecases.receive_file import receive_file


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Receive a file from Alice over a BB84-derived AES-256-GCM key.")
    parser.add_argument("--port", type=int, default=BOB_PORT, help=f"Port to listen on (default: {BOB_PORT}, 0 = any free port)")
    parser.add_argument("--output-dir", default=OUTPUT_DIR, help=f"Directory for received files (default: {OUTPUT_DIR})")
    parser.add_argument("--timeout", type=float, default=60.0, help="Seconds to wait for Alice (default: 60)")
    parser.add_argument("--events", choices=["text", "json"], default="text", help="Output format (default: text)")
    parser.add_argument("--transfer-id", help="Transfer id to include in JSON events")
    # Authentication flags
    parser.add_argument("--auth", choices=["none", "sign", "hybrid"], default=AUTH_MODE,
                        help=f"Authentication mode (default: {AUTH_MODE})")
    parser.add_argument("--peer-fingerprint", default=None,
                        help="Pin a specific peer fingerprint (uses PinnedVerifier)")
    parser.add_argument("--identity", default=IDENTITY_DIR,
                        help=f"Identity directory (default: {IDENTITY_DIR})")
    return parser.parse_args(argv)


def build_auth(args: argparse.Namespace):
    """Build an AuthContext from CLI args, or return None for --auth none."""
    if args.auth == "none":
        return None

    from qkd.services.identity import (
        PinnedVerifier,
        TrustStore,
        TrustStoreVerifier,
        load_or_create_identity,
    )
    from qkd.usecases.common import AuthContext

    identity = load_or_create_identity(Path(args.identity))

    if args.peer_fingerprint:
        verifier = PinnedVerifier(args.peer_fingerprint)
    else:
        store = TrustStore(Path(KNOWN_PEERS_FILE))
        verifier = TrustStoreVerifier(store, tofu=bool(TOFU))

    return AuthContext(
        mode=args.auth,
        public_key=identity.public_key,
        seed=identity.seed,
        verifier=verifier,
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.events == "json":
        reporter = JsonEventReporter(args.transfer_id)
    else:
        reporter = ConsoleReporter()
        reporter.banner("BB84 QKD Secure File Transfer", "BOB (Receiver)")

    reporter.stage("connecting")
    # Load the identity before listening, so a broken identity fails before any
    # connection is accepted, and so this setup is not counted in Alice's
    # handshake time (she starts her clock when she sends her hello).
    try:
        auth = build_auth(args)
    except PeerAuthError as exc:
        reporter.error(f"Authentication FAILED: {exc.reason}")
        reporter.result(OUTCOME_ABORTED_AUTH, exc.reason)
        return 1
    except Exception as exc:
        reporter.error(f"Identity/auth setup failed: {exc!r}")
        reporter.result(OUTCOME_FAILED, str(exc) or type(exc).__name__)
        return 1

    with listen(args.port) as server:
        port = server.getsockname()[1]
        reporter.listening(port)
        reporter.info(f"Listening on port {port}...")
        reporter.info(f"Waiting for Alice's connection ({args.timeout:.0f}s timeout)...")
        server.settimeout(args.timeout)
        try:
            conn, addr = accept(server)
        except socket.timeout:
            reporter.error("Timed out waiting for Alice's connection.")
            reporter.result(OUTCOME_FAILED, "timed out waiting for the sender")
            return 1
        conn.settimeout(None)
        reporter.success(f"Alice connected from {addr}")

        with conn:
            try:
                result = receive_file(conn, args.output_dir, reporter, auth=auth)
            except KeyConfirmationError as exc:
                reporter.error(f"Key confirmation FAILED: {exc.reason}")
                reporter.result(OUTCOME_ABORTED_QBER, exc.reason)
                return 1
            except PeerAuthError as exc:
                reporter.error(f"Authentication FAILED: {exc.reason}")
                reporter.result(OUTCOME_ABORTED_AUTH, exc.reason)
                return 1
            except Exception as exc:
                reporter.error(f"Decryption FAILED: {exc!r}")
                reporter.error("Authentication tag mismatch or connection lost. Partial output removed.")
                reporter.result(OUTCOME_FAILED, str(exc) or type(exc).__name__)
                return 1

    kx = result.key_exchange
    if kx.aborted:
        reporter.result(OUTCOME_ABORTED_QBER, kx.abort_reason)
        return 1
    reporter.metrics(output_path=result.output_path, bytes_written=result.bytes_written)
    reporter.result(OUTCOME_COMPLETED)
    return 0


if __name__ == "__main__":
    sys.exit(main())
