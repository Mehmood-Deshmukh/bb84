"""
E2 — all checks enabled at N=8192 (resolves the paper's fig:e2 TODO).

In-process partial-f Eve, N=8192, modes hybrid and none, 30 runs/point,
f in {0.01,0.05,0.1,0.25,0.3,0.35,0.4,0.5}. Per run we record:
  - the in-process stopping check and the stage it stopped at;
  - Alice's runner outcome AND exit code, and Bob's runner outcome;
  - file bytes written at Bob;
  - the Hamming distance between the kept (privacy-amplification input) bits, recorded
    in-process by wrapping privacy_amplification (no src/ edit);
  - whether any file byte left Alice before the abort (Alice completed => whole file sent).
For none-mode runs we flag explicitly whether Alice reported success (completed, exit 0)
while Bob failed -- the gap the key-confirmation tag closes in signed modes.

Usage: python scripts/paper/e2_full.py [--smoke]
"""

from __future__ import annotations

import argparse
import csv
import os
import socket
import tempfile

import common
from common import (RESULTS, eve_leg, guarded, keypair, loadavg, run_parallel, runner_exit,
                    runner_outcome, stopping_check)

from qkd.core.config import ProtocolParams
from qkd.services.reporting import NullReporter
from qkd.usecases import receive_file as rf
from qkd.usecases import send_file as sf
from qkd.usecases.common import AuthContext
from qkd.usecases.eavesdrop_demo import run_eavesdrop
from tests.invariants.support import PinnedVerifier, RecordingReporter

N = 8192
F_LIST = [0.01, 0.05, 0.1, 0.25, 0.3, 0.35, 0.4, 0.5]
MODES = ["hybrid", "none"]
RUNS = 30
PAYLOAD_BYTES = 1024

STAGE = {"threshold": "qber_estimation", "finite_key": "qber_estimation",
         "abort_other": "qber_estimation", "tag": "key_confirmation",
         "signature": "key_confirmation", "gcm": "file_transfer",
         "none": "file_transfer", "error_other": "unknown"}


def _install_recorders():
    a_bits, b_bits = [], []
    orig = sf.privacy_amplification

    def wrap(sink):
        def w(bits, *a, **k):
            sink.append(list(bits)); return orig(bits, *a, **k)
        return w
    sf.privacy_amplification = wrap(a_bits)
    rf.privacy_amplification = wrap(b_bits)

    def restore():
        sf.privacy_amplification = orig
        rf.privacy_amplification = orig
    return a_bits, b_bits, restore


def _hamming(a, b):
    n = min(len(a), len(b))
    return sum(1 for i in range(n) if a[i] != b[i]) + abs(len(a) - len(b)), max(len(a), len(b))


def one_run(mode: str, f: float, payload: str, aid, bid) -> dict:
    params = ProtocolParams(num_qubits=N)
    auth_a = None if mode == "none" else AuthContext(mode, aid[0], aid[1], PinnedVerifier(bid[0]))
    auth_b = None if mode == "none" else AuthContext(mode, bid[0], bid[1], PinnedVerifier(aid[0]))
    a_rep, b_rep = RecordingReporter(), RecordingReporter()
    a_bits, b_bits, restore = _install_recorders()
    with tempfile.TemporaryDirectory() as out_dir:
        a_end, eve_a = socket.socketpair(); eve_b, b_end = socket.socketpair()
        try:
            with a_end, eve_a, eve_b, b_end:
                a_res, b_res, _ = run_parallel(
                    guarded(lambda s: sf.send_file(s, payload, a_rep, params, auth_a), a_end),
                    guarded(lambda s: rf.receive_file(s, out_dir, b_rep, params, auth_b), b_end),
                    lambda: eve_leg(lambda: run_eavesdrop(eve_a, eve_b, NullReporter(), threshold=params.qber_threshold, fraction=f), eve_a, eve_b),
                )
        finally:
            restore()

    am, bm = a_rep.merged(), b_rep.merged()
    def _m(key):
        return am.get(key) if am.get(key) is not None else bm.get(key)
    check = stopping_check(a_res, b_res)
    a_out, b_out = runner_outcome(a_res), runner_outcome(b_res)
    a_exit = runner_exit(a_res)
    alice_completed = (a_out == "completed")
    bob_failed = (b_out != "completed")
    ham = rem_len = None
    if a_bits and b_bits:
        ham, rem_len = _hamming(a_bits[0], b_bits[0])
    return {
        "mode": mode, "f": f, "n": N,
        "sifted": _m("sifted_length"), "sample": _m("sample_size"),
        "qber": _m("qber"), "secure_bits": _m("secure_key_bits"),
        "stopping_check": check, "stage": STAGE.get(check, "unknown"),
        "alice_outcome": a_out, "alice_exit": a_exit, "bob_outcome": b_out,
        "bytes_at_bob": getattr(b_res, "bytes_written", 0) if not isinstance(b_res, Exception) else 0,
        "alice_sent_whole_file": int(alice_completed),
        "file_bytes_left_alice": PAYLOAD_BYTES if alice_completed else 0,
        "alice_success_while_bob_failed": int(alice_completed and bob_failed),
        "remaining_len": rem_len, "remaining_hamming": ham,
        "keys_differ": (None if ham is None else int(ham > 0)),
        "a_exc": type(a_res).__name__ if isinstance(a_res, Exception) else "",
        "b_exc": type(b_res).__name__ if isinstance(b_res, Exception) else "",
    }


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--smoke", action="store_true")
    args = ap.parse_args()
    runs = 2 if args.smoke else RUNS
    f_list = [0.1, 0.5] if args.smoke else F_LIST
    modes = MODES

    aid, bid = keypair(), keypair()
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".bin"); tmp.write(b"A" * PAYLOAD_BYTES); tmp.close()

    print(f"[E2] loadavg start: {loadavg()}", flush=True)
    rows = []
    for mode in modes:
        for f in f_list:
            for _ in range(runs):
                rows.append(one_run(mode, f, tmp.name, aid, bid))
            rs = [r for r in rows if r["mode"] == mode and r["f"] == f]
            brk = {c: sum(1 for r in rs if r["stopping_check"] == c) for c in set(r["stopping_check"] for r in rs)}
            asf = sum(r["alice_success_while_bob_failed"] for r in rs)
            print(f"[E2] mode={mode} f={f}: checks={brk} alice_ok_bob_fail={asf}", flush=True)

    with open(RESULTS / "e2_outcomes.csv", "w", newline="") as fcsv:
        w = csv.DictWriter(fcsv, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)

    checks = ["threshold", "finite_key", "tag", "signature", "gcm", "none", "error_other", "abort_other"]
    with open(RESULTS / "e2_summary.csv", "w", newline="") as fcsv:
        w = csv.writer(fcsv)
        w.writerow(["mode", "f", "runs", "mean_qber", "mean_secure_bits", "mean_hamming",
                    "alice_success_while_bob_failed", "bytes_at_bob_max"] + ["cnt_" + c for c in checks])
        for mode in modes:
            for f in f_list:
                rs = [r for r in rows if r["mode"] == mode and r["f"] == f]
                qbers = [r["qber"] for r in rs if r["qber"] is not None]
                mq = sum(qbers) / len(qbers) if qbers else float("nan")
                sb = [r["secure_bits"] for r in rs if r["secure_bits"] is not None]
                hams = [r["remaining_hamming"] for r in rs if r["remaining_hamming"] is not None]
                w.writerow([mode, f, len(rs), f"{mq:.4f}",
                            f"{sum(sb)/len(sb):.1f}" if sb else "",
                            f"{sum(hams)/len(hams):.2f}" if hams else "",
                            sum(r["alice_success_while_bob_failed"] for r in rs),
                            max(r["bytes_at_bob"] for r in rs)]
                           + [sum(1 for r in rs if r["stopping_check"] == c) for c in checks])
    print(f"[E2] loadavg end: {loadavg()}", flush=True)
    os.unlink(tmp.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
