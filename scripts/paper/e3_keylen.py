"""
E3 — threshold vs finite-key bound.

(a) Tabulate l(n,k,Q) from the code's own secure_key_length:
    - Q in [0, 0.12] step 0.005 at N=8192 and N=4096 (sifted ~ N/2, k = floor(0.15*sifted));
    - l(Q=0) for N in {512,1024,2048,4096,8192,16384}.
(b) At N=8192, sweep Q_max in {0.05,0.08,0.11,0.15} x f in {0.25,0.35,0.5}, 10 runs/cell,
    recording the in-process stopping check (threshold | finite_key | tag | gcm | none).
(c) 20 honest runs (no Eve) at N=8192: honest abort rate and the Q distribution.

Usage: python scripts/paper/e3_keylen.py [--smoke]
"""

from __future__ import annotations

import argparse
import csv
import socket
import tempfile

import common
from common import RESULTS, eve_leg, guarded, keypair, loadavg, run_parallel, stopping_check

from qkd.core.config import ProtocolParams
from qkd.core.finite_key import secure_key_length, deviation
from qkd.services.reporting import NullReporter
from qkd.usecases import receive_file as rf
from qkd.usecases import send_file as sf
from qkd.usecases.common import AuthContext
from qkd.usecases.eavesdrop_demo import run_eavesdrop
from tests.invariants.support import PinnedVerifier

EPS_SEC, EPS_COR = 1e-10, 1e-15
FRACTION = 0.15


def sifted(N): return N // 2
def k_of(ns): return max(1, int(ns * FRACTION))


def table_a() -> None:
    # l(n,k,Q) at N=8192 and N=4096
    with open(RESULTS / "e3_keylen_vs_qber.csv", "w", newline="") as f:
        w = csv.writer(f); w.writerow(["N", "n_kept", "k_sample", "qber", "mu", "secure_bits"])
        for N in (8192, 4096):
            ns = sifted(N); k = k_of(ns); n = ns - k
            q = 0.0
            while q <= 0.1201:
                mu = deviation(n, k, EPS_SEC)
                w.writerow([N, n, k, f"{q:.3f}", f"{mu:.4f}", secure_key_length(n, k, q, EPS_SEC, EPS_COR)])
                q += 0.005
    # l(Q=0) vs N
    with open(RESULTS / "e3_keylen_vs_N.csv", "w", newline="") as f:
        w = csv.writer(f); w.writerow(["N", "sifted", "n_kept", "k_sample", "secure_bits_Q0"])
        for N in (512, 1024, 2048, 4096, 8192, 16384):
            ns = sifted(N); k = k_of(ns); n = ns - k
            w.writerow([N, ns, n, k, secure_key_length(n, k, 0.0, EPS_SEC, EPS_COR)])


def one_run(f: float, qmax: float, payload: str, aid, bid) -> dict:
    params = ProtocolParams(num_qubits=8192, qber_threshold=qmax)
    auth_a = AuthContext("hybrid", aid[0], aid[1], PinnedVerifier(bid[0]))
    auth_b = AuthContext("hybrid", bid[0], bid[1], PinnedVerifier(aid[0]))
    with tempfile.TemporaryDirectory() as out_dir:
        a_end, eve_a = socket.socketpair(); eve_b, b_end = socket.socketpair()
        with a_end, eve_a, eve_b, b_end:
            a_res, b_res, _ = run_parallel(
                guarded(lambda s: sf.send_file(s, payload, NullReporter(), params, auth_a), a_end),
                guarded(lambda s: rf.receive_file(s, out_dir, NullReporter(), params, auth_b), b_end),
                lambda: eve_leg(lambda: run_eavesdrop(eve_a, eve_b, NullReporter(), threshold=qmax, fraction=f), eve_a, eve_b),
            )
    kx = common._kx_of(a_res) or common._kx_of(b_res)
    return {"f": f, "qmax": qmax, "qber": kx.qber if kx else None,
            "sifted": kx.sifted_length if kx else None, "sample": kx.sample_size if kx else None,
            "stopping_check": stopping_check(a_res, b_res)}


def honest_run(payload: str, aid, bid) -> dict:
    params = ProtocolParams(num_qubits=8192)
    auth_a = AuthContext("hybrid", aid[0], aid[1], PinnedVerifier(bid[0]))
    auth_b = AuthContext("hybrid", bid[0], bid[1], PinnedVerifier(aid[0]))
    with tempfile.TemporaryDirectory() as out_dir:
        a, b = socket.socketpair()
        with a, b:
            a_res, b_res = run_parallel(
                guarded(lambda s: sf.send_file(s, payload, NullReporter(), params, auth_a), a),
                guarded(lambda s: rf.receive_file(s, out_dir, NullReporter(), params, auth_b), b),
            )
    kx = common._kx_of(a_res) or common._kx_of(b_res)
    return {"qber": kx.qber if kx else None, "stopping_check": stopping_check(a_res, b_res),
            "aborted": int(stopping_check(a_res, b_res) != "none")}


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--smoke", action="store_true")
    args = ap.parse_args()
    runs = 2 if args.smoke else 10
    honest_runs = 3 if args.smoke else 20
    qmaxes = [0.11] if args.smoke else [0.05, 0.08, 0.11, 0.15]
    fs = [0.35] if args.smoke else [0.25, 0.35, 0.5]

    print(f"[E3] loadavg start: {loadavg()}", flush=True)
    table_a()
    print("[E3a] wrote finite-key tables (vs QBER, vs N)", flush=True)

    aid, bid = keypair(), keypair()
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".bin"); tmp.write(b"A" * 1024); tmp.close()

    rows = []
    for qmax in qmaxes:
        for f in fs:
            for _ in range(runs):
                rows.append(one_run(f, qmax, tmp.name, aid, bid))
            rs = [r for r in rows if r["qmax"] == qmax and r["f"] == f]
            brk = {c: sum(1 for r in rs if r["stopping_check"] == c) for c in set(r["stopping_check"] for r in rs)}
            print(f"[E3b] Qmax={qmax} f={f}: {brk}", flush=True)
    with open(RESULTS / "e3_qmax_sweep.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)

    hon = [honest_run(tmp.name, aid, bid) for _ in range(honest_runs)]
    with open(RESULTS / "e3_honest.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(hon[0])); w.writeheader(); w.writerows(hon)
    aborted = sum(r["aborted"] for r in hon)
    qmax_q = max(r["qber"] for r in hon); qmin_q = min(r["qber"] for r in hon)
    print(f"[E3c] honest: {honest_runs} runs, aborts={aborted}, QBER in [{qmin_q:.4f},{qmax_q:.4f}]", flush=True)
    print(f"[E3] loadavg end: {loadavg()}", flush=True)
    import os as _os; _os.unlink(tmp.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
