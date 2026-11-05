#!/usr/bin/env python3
"""
Alice: sender in the BB84 QKD file transfer.

Usage:
    qkd-alice <file> [--host H] [--port P]
    qkd-alice <file> --eve-mode           # connect to Eve's proxy port instead of Bob
    qkd-alice <file> --events json        # one JSON event per line (used by the backend node)
    qkd-alice <file> --auth none          # disable authentication
    qkd-alice <file> --peer-fingerprint FP  # pin a specific peer key
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from qkd.core.config import RESUME, RESUME_SYNC_CHUNKS, ALICE_HOST, AUTH_MODE, BOB_PORT, EVE_PORT, IDENTITY_DIR, KNOWN_PEERS_FILE, TOFU
from qkd.services.reporting import (
    OUTCOME_ABORTED_AUTH,
    OUTCOME_ABORTED_QBER,
    OUTCOME_COMPLETED,
    OUTCOME_FAILED,
    OUTCOME_INTERRUPTED,
    ConsoleReporter,
    JsonEventReporter,
    Reporter,
)
from qkd.services.wire import connect_with_retry
from qkd.usecases.common import PeerAuthError, TransferInterrupted
from qkd.usecases.resume import ResumeOptions
from qkd.usecases.send_file import send_file


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send a file to Bob over a BB84-derived AES-256-GCM key.")
    parser.add_argument("file", help="File to send")
    parser.add_argument("--host", default=ALICE_HOST, help=f"Receiver host (default: {ALICE_HOST})")
    parser.add_argument("--port", type=int, help=f"Receiver port (default: {BOB_PORT}, or {EVE_PORT} with --eve-mode)")
    parser.add_argument("--eve-mode", action="store_true", help="Connect to Eve's proxy port")
    parser.add_argument("--events", choices=["text", "json"], default="text", help="Output format (default: text)")
    parser.add_argument("--transfer-id", help="Transfer id to include in JSON events")
    # Authentication flags
    parser.add_argument("--auth", choices=["none", "sign", "hybrid"], default=AUTH_MODE,
                        help=f"Authentication mode (default: {AUTH_MODE})")
    parser.add_argument("--peer-fingerprint", default=None,
                        help="Pin a specific peer fingerprint (uses PinnedVerifier)")
    parser.add_argument("--identity", default=IDENTITY_DIR,
                        help=f"Identity directory (default: {IDENTITY_DIR})")
    parser.add_argument("--resume", action="store_true", default=bool(RESUME),
                        help="Make the transfer resumable (needs --transfer-id and auth sign or hybrid; "
                             "default: QKD_RESUME)")
    args = parser.parse_args(argv)
    if args.resume and not args.transfer_id:
        parser.error("--resume needs --transfer-id (it names the interrupted transfer)")
    if args.port is None:
        args.port = EVE_PORT if args.eve_mode else BOB_PORT
    return args


def make_reporter(args: argparse.Namespace) -> Reporter:
    return JsonEventReporter(args.transfer_id) if args.events == "json" else ConsoleReporter()


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


def resume_options(args: argparse.Namespace) -> ResumeOptions | None:
    return ResumeOptions(args.transfer_id, sync_chunks=RESUME_SYNC_CHUNKS) if args.resume else None


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    reporter = make_reporter(args)

    reporter.stage("connecting")
    if args.eve_mode:
        reporter.warning(f"EVE MODE: Connecting to Eve's proxy at {args.host}:{args.port}")
    else:
        reporter.info(f"Connecting to Bob at {args.host}:{args.port}")
    try:
        sock = connect_with_retry(args.host, args.port)
    except OSError as exc:
        reporter.error(f"Failed to connect to {args.host}:{args.port}: {exc}")
        reporter.result(OUTCOME_FAILED, f"could not connect to {args.host}:{args.port}")
        return 1
    reporter.success(f"Connected to {'Eve (proxy)' if args.eve_mode else 'Bob'}")

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

    try:
        with sock:
            result = send_file(sock, args.file, reporter, auth=auth, resume=resume_options(args))
    except PeerAuthError as exc:
        reporter.error(f"Authentication FAILED: {exc.reason}")
        reporter.result(OUTCOME_ABORTED_AUTH, exc.reason)
        return 1
    except TransferInterrupted as exc:
        reporter.warning(f"Transfer interrupted: {exc.reason}. It can be resumed.")
        reporter.result(OUTCOME_INTERRUPTED, exc.reason)
        return 1
    except Exception as exc:
        reporter.error(f"Transfer FAILED: {exc!r}")
        reporter.result(OUTCOME_FAILED, str(exc) or type(exc).__name__)
        return 1
    if result.aborted:
        reporter.result(OUTCOME_ABORTED_QBER, f"QBER {result.qber:.2%} >= threshold {result.threshold:.0%}")
        return 1
    reporter.result(OUTCOME_COMPLETED)
    return 0


if __name__ == "__main__":
    sys.exit(main())
