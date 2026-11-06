"""
E4 — attack matrix on the current protocol, N=8192 (the smallest power of two for which
the finite-key bound gives >= 256 secure bits; see e3_keylen_vs_N.csv), each cell 3 runs.

Columns: outcome (runner name), check (the defense that stopped it), stage, detector side,
bytes_at_bob, attacker_plaintext, alice_reported_success.

Reuses tests/invariants/support.py (proxy, PinnedVerifier, RecordingReporter), the six
tamper functions from tests/invariants/test_tamper.py, qkd.usecases.mitm_demo.run_mitm,
qkd.usecases.eavesdrop_demo.run_eavesdrop, scripts/paper/eve.py (partial-f), and the
file_stream / handshake primitives for the malicious-sender rows. src/ and tests/ are not
edited.

Usage: python scripts/paper/e4_matrix.py [--smoke]
"""

from __future__ import annotations

import argparse
import base64
import csv
import socket
import tempfile

from cryptography.exceptions import InvalidTag

import common
from common import RESULTS, eve_leg, guarded, keypair, loadavg, run_parallel

import eve as eve_mod

from qkd.core.config import ProtocolParams
from qkd.services.file_stream import encrypt_chunk, encrypt_metadata, derive_chunk_nonce, key_schedule
from qkd.services.reporting import NullReporter
from qkd.services.transcript import TranscriptChannel
from qkd.services.wire import send_bytes
from qkd.usecases.common import AuthContext, KeyConfirmationError, KeyExchangeResult, PeerAuthError
from qkd.usecases.eavesdrop_demo import run_eavesdrop
from qkd.usecases.handshake import alice_finished, alice_hello, session_key
from qkd.usecases.mitm_demo import run_mitm
from qkd.usecases.receive_file import ReceiveResult, receive_file
from qkd.usecases.send_file import run_key_exchange as alice_key_exchange, send_file
from tests.invariants.support import PinnedVerifier, RecordingReporter, proxy
from tests.invariants.test_tamper import t_bases, t_matching, t_qber, t_salt, t_sample_bits, t_sample_indices

N = 8192
RUNS = 3
TAMPER_THRESHOLD = 1.01   # disables the QBER check, as in test_tamper.py (isolate the signature)
ALICE_ID = keypair()
BOB_ID = keypair()


def _ctx(role_id, peer_pk, mode):
    return None if mode == "none" else AuthContext(mode, role_id[0], role_id[1], PinnedVerifier(peer_pk))


def _payload(nbytes: int = 1024) -> str:
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".bin"); f.write(b"P" * nbytes); f.close()
    return f.name


def _last_stage(rep):
    return rep.stages[-1] if rep.stages else None


def _check_from(a_res, b_res, a_rep, b_rep):
    """Classify the defense that stopped a run from exceptions, reasons, and stages."""
    reasons = []
    for r in (a_res, b_res):
        if isinstance(r, (PeerAuthError, KeyConfirmationError)):
            reasons.append((r, getattr(r, "reason", "")))
    for r, reason in reasons:
        if isinstance(r, KeyConfirmationError):
            return "tag"
        low = reason.lower()
        if "pinned" in low or "tofu" in low or "unknown peer" in low or "disabled" in low:
            return "trust"
        if "parameter mismatch" in low:
            return "policy"
        if "mode mismatch" in low or "version mismatch" in low:
            return "mode"
        if "signature" in low:
            return "signature"
        return "auth_other"
    # aborts
    for r in (a_res, b_res):
        kx = common._kx_of(r)
        if kx is not None and kx.aborted:
            rr = (kx.abort_reason or "").lower()
            # "finite-key" reason also contains "qber"; test finite-key first.
            if "finite-key" in rr:
                return "finite_key"
            return "threshold" if "qber" in rr else "abort_other"
    if isinstance(b_res, InvalidTag) or isinstance(a_res, InvalidTag):
        return "gcm"
    # metadata rule (MetadataError from file_stream)
    for r in (a_res, b_res):
        if isinstance(r, Exception) and type(r).__name__ == "MetadataError":
            return "metadata_rule"
    completed = isinstance(b_res, ReceiveResult) and b_res.output_path is not None
    if completed:
        return "none"
    if isinstance(a_res, Exception) or isinstance(b_res, Exception):
        return "connection"
    return "none"


def _row(a_res, b_res, a_rep, b_rep, mitm=None):
    check = _check_from(a_res, b_res, a_rep, b_rep)
    a_out, b_out = common.runner_outcome(a_res), common.runner_outcome(b_res)
    completed = isinstance(b_res, ReceiveResult) and b_res.output_path is not None
    # which side detected
    det = []
    if isinstance(a_res, Exception):
        det.append("Alice")
    if isinstance(b_res, Exception):
        det.append("Bob")
    if not det:
        for name, r in (("Alice", a_res), ("Bob", b_res)):
            kx = common._kx_of(r)
            if kx is not None and kx.aborted:
                det.append(name)
    detector = "+".join(det) if det else ("none" if completed else "none")
    stage = _last_stage(a_rep) or _last_stage(b_rep)
    bytes_at_bob = getattr(b_res, "bytes_written", 0) if not isinstance(b_res, Exception) else 0
    attacker_plaintext = int(bool(mitm and mitm.plaintext_sha256))
    alice_passed_4b = "file_transfer" in (a_rep.stages if a_rep else [])
    return {
        "check": check, "outcome_alice": a_out, "outcome_bob": b_out,
        "stage": stage, "detector": detector, "bytes_at_bob": bytes_at_bob,
        "attacker_plaintext": attacker_plaintext,
        "alice_reported_success": int(a_out == "completed"),
        "alice_passed_key_confirmation": int(alice_passed_4b),
    }


# ── cells ────────────────────────────────────────────────────────────────────
def cell_eve(mode: str, f: float, src: str) -> dict:
    params = ProtocolParams(num_qubits=N)
    a_rep, b_rep = RecordingReporter(), RecordingReporter()
    a_end, eve_a = socket.socketpair(); eve_b, b_end = socket.socketpair()
    with tempfile.TemporaryDirectory() as out, a_end, eve_a, eve_b, b_end:
        with eve_mod.install_partial_eve(f):
            a, b, _ = run_parallel(
                guarded(lambda s: send_file(s, src, a_rep, params, _ctx(ALICE_ID, BOB_ID[0], mode)), a_end),
                guarded(lambda s: receive_file(s, out, b_rep, params, _ctx(BOB_ID, ALICE_ID[0], mode)), b_end),
                lambda: eve_leg(lambda: run_eavesdrop(eve_a, eve_b, NullReporter(), threshold=params.qber_threshold), eve_a, eve_b),
            )
        return _row(a, b, a_rep, b_rep)


def cell_mitm(mode: str, strategy: str, src: str, identity=None) -> dict:
    params = ProtocolParams(num_qubits=N)
    a_rep, b_rep = RecordingReporter(), RecordingReporter()
    a_end, mal_a = socket.socketpair(); mal_b, b_end = socket.socketpair()
    with tempfile.TemporaryDirectory() as out, a_end, mal_a, mal_b, b_end:
        a, b, mitm = run_parallel(
            guarded(lambda s: send_file(s, src, a_rep, params, _ctx(ALICE_ID, BOB_ID[0], mode)), a_end),
            guarded(lambda s: receive_file(s, out, b_rep, params, _ctx(BOB_ID, ALICE_ID[0], mode)), b_end),
            lambda: run_mitm(mal_a, mal_b, NullReporter(), params, mode, strategy, identity=identity),
        )
        return _row(a, b, a_rep, b_rep, mitm=mitm)


def cell_tamper(step: str, tamper, stop_after, threshold: float, src: str) -> dict:
    params = ProtocolParams(num_qubits=N, qber_threshold=threshold)
    a_rep, b_rep = RecordingReporter(), RecordingReporter()
    a_end, pa = socket.socketpair(); pb, b_end = socket.socketpair()
    with tempfile.TemporaryDirectory() as out, a_end, pa, pb, b_end:
        a, b, _ = run_parallel(
            guarded(lambda s: send_file(s, src, a_rep, params, _ctx(ALICE_ID, BOB_ID[0], "hybrid")), a_end),
            guarded(lambda s: receive_file(s, out, b_rep, params, _ctx(BOB_ID, ALICE_ID[0], "hybrid")), b_end),
            lambda: proxy(pa, pb, tamper_step=step, tamper=tamper, stop_after=stop_after),
        )
        return _row(a, b, a_rep, b_rep)


def cell_downgrade(alice_mode: str, bob_mode: str, src: str) -> dict:
    params = ProtocolParams(num_qubits=N)
    a_rep, b_rep = RecordingReporter(), RecordingReporter()
    a_end, b_end = socket.socketpair()
    with tempfile.TemporaryDirectory() as out, a_end, b_end:
        a, b = run_parallel(
            guarded(lambda s: send_file(s, src, a_rep, params, _ctx(ALICE_ID, BOB_ID[0], alice_mode)), a_end),
            guarded(lambda s: receive_file(s, out, b_rep, params, _ctx(BOB_ID, ALICE_ID[0], bob_mode)), b_end),
        )
        return _row(a, b, a_rep, b_rep)


def cell_policy_downgrade(src: str) -> dict:
    """Alice runs a weaker policy (smaller l); Bob keeps the default. Policy is in the hello."""
    a_params = ProtocolParams(num_qubits=N, final_key_bits=128)
    b_params = ProtocolParams(num_qubits=N)
    a_rep, b_rep = RecordingReporter(), RecordingReporter()
    a_end, b_end = socket.socketpair()
    with tempfile.TemporaryDirectory() as out, a_end, b_end:
        a, b = run_parallel(
            guarded(lambda s: send_file(s, src, a_rep, a_params, _ctx(ALICE_ID, BOB_ID[0], "hybrid")), a_end),
            guarded(lambda s: receive_file(s, out, b_rep, b_params, _ctx(BOB_ID, ALICE_ID[0], "hybrid")), b_end),
        )
        return _row(a, b, a_rep, b_rep)


def cell_replay(src: str) -> dict:
    """Session 1 taps Bob's finished; session 2 injects it; Alice must reject (fresh nonce/KEM)."""
    params = ProtocolParams(num_qubits=N)
    captured = {}

    def tap(msg):
        captured["fin"] = msg; return msg

    a1, pa1 = socket.socketpair(); pb1, b1 = socket.socketpair()
    with tempfile.TemporaryDirectory() as out1, a1, pa1, pb1, b1:
        run_parallel(
            guarded(lambda s: send_file(s, src, RecordingReporter(), params, _ctx(ALICE_ID, BOB_ID[0], "hybrid")), a1),
            guarded(lambda s: receive_file(s, out1, RecordingReporter(), params, _ctx(BOB_ID, ALICE_ID[0], "hybrid")), b1),
            lambda: proxy(pa1, pb1, tamper_step="4b-bob", tamper=tap, stop_after=None),
        )
    if "fin" not in captured:
        return {"check": "error", "outcome_alice": "failed", "outcome_bob": "failed", "stage": None,
                "detector": "none", "bytes_at_bob": 0, "attacker_plaintext": 0,
                "alice_reported_success": 0, "alice_passed_key_confirmation": 0}

    def inject(_msg):
        return captured["fin"]

    a_rep2, b_rep2 = RecordingReporter(), RecordingReporter()
    a2, pa2 = socket.socketpair(); pb2, b2 = socket.socketpair()
    with tempfile.TemporaryDirectory() as out2, a2, pa2, pb2, b2:
        a, b, _ = run_parallel(
            guarded(lambda s: send_file(s, src, a_rep2, params, _ctx(ALICE_ID, BOB_ID[0], "hybrid")), a2),
            guarded(lambda s: receive_file(s, out2, b_rep2, params, _ctx(BOB_ID, ALICE_ID[0], "hybrid")), b2),
            lambda: proxy(pa2, pb2, tamper_step="4b-bob", tamper=inject, stop_after="4b-bob"),
        )
        return _row(a, b, a_rep2, b_rep2)


def _malicious_alice(sock, src, params, bad):
    """Alice's real flow up to the session key, then a crafted metadata message.

    bad='zero_chunks': metadata num_chunks=0 (chunk-count rule).
    bad='size_mismatch': metadata total_size larger than the bytes actually sent (size rule).
    Reuses real handshake/key-exchange primitives; only the final metadata/chunk is crafted.
    """
    import os
    channel = TranscriptChannel(sock, "alice")
    handshake = alice_hello(channel, _ctx(ALICE_ID, BOB_ID[0], "hybrid"), NullReporter(), params)
    kx = alice_key_exchange(channel, params, NullReporter())
    if kx.aborted:
        return
    t = channel.digest()
    key = session_key(kx.key, handshake, t)
    alice_finished(channel, _ctx(ALICE_ID, BOB_ID[0], "hybrid"), handshake, t, key, NullReporter())
    keys = key_schedule(key)
    base = os.urandom(8)
    if bad == "zero_chunks":
        msg = {"filename": "x.bin", "total_size": 1024, "chunk_size": params.chunk_size,
               "num_chunks": 0, "base_nonce": base.hex()}
        send_bytes(sock, encrypt_metadata(msg, keys.metadata))
    else:  # size_mismatch: announce 4096 bytes but send one 1000-byte chunk
        msg = {"filename": "x.bin", "total_size": 4096, "chunk_size": params.chunk_size,
               "num_chunks": 1, "base_nonce": base.hex()}
        import hashlib, json
        aad = hashlib.sha256(json.dumps(msg, sort_keys=True, separators=(",", ":")).encode()).digest()
        send_bytes(sock, encrypt_metadata(msg, keys.metadata))
        ct, tag = encrypt_chunk(b"Q" * 1000, keys.file, derive_chunk_nonce(base, 0), aad)
        send_bytes(sock, tag + ct)


def cell_malicious_meta(bad: str, src: str) -> dict:
    params = ProtocolParams(num_qubits=N)
    b_rep = RecordingReporter()
    a_end, b_end = socket.socketpair()
    with tempfile.TemporaryDirectory() as out, a_end, b_end:
        a, b = run_parallel(
            guarded(lambda s: _malicious_alice(s, src, params, bad), a_end),
            guarded(lambda s: receive_file(s, out, b_rep, params, _ctx(BOB_ID, ALICE_ID[0], "hybrid")), b_end),
        )
        return _row(a, b, RecordingReporter(), b_rep)


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--smoke", action="store_true")
    args = ap.parse_args()
    runs = 1 if args.smoke else RUNS
    src = _payload()
    print(f"[E4] loadavg start: {loadavg()}", flush=True)

    cells = []
    cells.append(("eve_full_f1.0", "none", lambda: cell_eve("none", 1.0, src)))
    cells.append(("eve_full_f1.0", "hybrid", lambda: cell_eve("hybrid", 1.0, src)))
    cells.append(("eve_partial_f0.1", "none", lambda: cell_eve("none", 0.1, src)))
    cells.append(("eve_partial_f0.1", "hybrid", lambda: cell_eve("hybrid", 0.1, src)))
    for mode in ("none", "sign", "hybrid"):
        cells.append(("mallory_own_key", mode, lambda m=mode: cell_mitm(m, "own_key", src)))
    for mode in ("sign", "hybrid"):
        cells.append(("mallory_relay_ownkey", mode, lambda m=mode: cell_mitm(m, "relay_hello", src)))
    for mode in ("sign", "hybrid"):  # relay CONTROL: Mallory holds Bob's real key
        cells.append(("mallory_relay_BOBKEY_control", mode, lambda m=mode: cell_mitm(m, "relay_hello", src, identity=BOB_ID)))
    tampers = [("2-bases", t_bases), ("2-matching", t_matching), ("3-sample_indices", t_sample_indices),
               ("3-sample_bits", t_sample_bits), ("3-qber", t_qber), ("4-salt", t_salt)]
    for step, fn in tampers:
        cells.append((f"tamper_{step}", "hybrid", lambda s=step, f=fn: cell_tamper(s, f, "4b-bob", TAMPER_THRESHOLD, src)))
    meta_bitflip = lambda raw: raw[:-1] + bytes([raw[-1] ^ 1])  # noqa: E731
    cells.append(("tamper_metadata_bitflip", "hybrid", lambda: cell_tamper("5-meta", meta_bitflip, None, ProtocolParams().qber_threshold, src)))
    cells.append(("malicious_zero_chunks", "hybrid", lambda: cell_malicious_meta("zero_chunks", src)))
    cells.append(("malicious_size_mismatch", "hybrid", lambda: cell_malicious_meta("size_mismatch", src)))
    for am, bm in (("hybrid", "none"), ("none", "hybrid")):
        cells.append((f"downgrade_mode_{am}_vs_{bm}", f"{am}/{bm}", lambda a=am, b=bm: cell_downgrade(a, b, src)))
    cells.append(("downgrade_policy_l128_vs_l256", "hybrid", lambda: cell_policy_downgrade(src)))
    cells.append(("replay_finished", "hybrid", lambda: cell_replay(src)))

    rows = []
    for attacker, mode, fn in cells:
        results = [fn() for _ in range(runs)]
        r0 = results[0]
        stable = all(r["check"] == r0["check"] and r["outcome_bob"] == r0["outcome_bob"] for r in results)
        rows.append({"attacker": attacker, "mode": mode, "runs": runs, "stable": stable, **r0})
        print(f"[E4] {attacker:30s} {mode:12s} -> check={r0['check']:14s} a={r0['outcome_alice']:11s} "
              f"b={r0['outcome_bob']:11s} stage={r0['stage']} det={r0['detector']} "
              f"bob_bytes={r0['bytes_at_bob']} pt={r0['attacker_plaintext']} "
              f"a_ok={r0['alice_reported_success']} passed4b={r0['alice_passed_key_confirmation']} stable={stable}", flush=True)

    with open(RESULTS / "e4_matrix.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    print(f"[E4] loadavg end: {loadavg()}", flush=True)
    import os as _os; _os.unlink(src)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
