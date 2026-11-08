"""
E1 — Eve detection vs qubit count N and attack fraction f (current protocol).

In-process honest hybrid flow with a partial-f intercept-resend Eve between Alice and Bob;
Eve attacks a fraction f of the qubits via run_eavesdrop(..., fraction=f) (native in
quantum_channel.eve_intercept_resend as of origin/main). Full protocol with the finite-key
gate ON. Per run we record the sifted count n, the sample size k, the observed QBER Q, the
finite-key secure length l, and WHICH check stopped the run
(threshold | finite_key | tag | signature | gcm | none), detected in-process. The runner
collapses threshold/finite_key/tag into 'aborted_qber'.

Before E1 it runs two sanity checks on the native partial-f Eve (channel level):
  (a) f=1.0: the sifted error rate is ~25% (full intercept-resend), 30 rounds at N=2048;
  (b) f=0.0: the sifted error rate is exactly 0.

Usage: python scripts/paper/e1_detection.py [--smoke]
"""

from __future__ import annotations

import argparse
import csv
import socket
import tempfile
from math import ceil, exp, lgamma, log, sqrt

import common
from common import (RESULTS, eve_leg, guarded, keypair, loadavg, run_parallel, runner_outcome,
                    runner_exit, stopping_check, wilson)

from qkd.core.config import ProtocolParams
from qkd.core.finite_key import secure_key_length
from qkd.core.bb84_protocol import generate_random_bases, generate_random_bits
from qkd.core.quantum_channel import eve_intercept_resend, measure_qubits, prepare_qubits
from qkd.services.reporting import NullReporter
from qkd.usecases import receive_file as rf
from qkd.usecases import send_file as sf
from qkd.usecases.common import AuthContext
from qkd.usecases.eavesdrop_demo import run_eavesdrop
from tests.invariants.support import PinnedVerifier, RecordingReporter

N_LIST = [512, 1024, 2048, 4096, 8192]
F_LIST = [0.1, 0.25, 0.5, 1.0]
RUNS = 30
FRACTION = 0.15
THRESHOLD = 0.11
EPS_SEC, EPS_COR = 1e-10, 1e-15


# ── threshold-detection model (mirrors the code), per-bit error p = f/4 ──────
def sample_size(m: int, fraction: float = FRACTION) -> int:
    return min(max(1, int(m * fraction)), m)


def min_errors_to_detect(s: int, t: float = THRESHOLD) -> int:
    return ceil(t * s - 1e-9)


def _log_binom_pmf(n: int, k: int, p: float) -> float:
    """log P(Binomial(n,p) = k), computed with lgamma to avoid overflow at large n."""
    if k < 0 or k > n:
        return float("-inf")
    if p <= 0.0:
        return 0.0 if k == 0 else float("-inf")
    if p >= 1.0:
        return 0.0 if k == n else float("-inf")
    return (lgamma(n + 1) - lgamma(k + 1) - lgamma(n - k + 1)
            + k * log(p) + (n - k) * log(1 - p))


def _binom_sf(n: int, kmin: int, p: float) -> float:
    """P(Binomial(n,p) >= kmin)."""
    if kmin <= 0:
        return 1.0
    if kmin > n:
        return 0.0
    return sum(exp(_log_binom_pmf(n, k, p)) for k in range(kmin, n + 1))


def p_detect_given_sample(s: int, p: float, t: float = THRESHOLD) -> float:
    if s == 0:
        return 0.0
    return _binom_sf(s, min_errors_to_detect(s, t), p)


def theoretical_threshold_detection(n: int, f: float) -> float:
    """E over m ~ Bin(n,1/2) of P(Bin(sample_size(m), f/4) >= ceil(0.11*sample)).

    The sifted count m ~ Bin(n,1/2) concentrates; the outer sum is restricted to
    mean +/- 12 standard deviations and computed in log space (exact otherwise).
    """
    p = f / 4.0
    mean, std = n / 2.0, sqrt(n) / 2.0
    lo, hi = max(0, int(mean - 12 * std)), min(n, int(mean + 12 * std))
    total = 0.0
    for m in range(lo, hi + 1):
        total += exp(_log_binom_pmf(n, m, 0.5)) * p_detect_given_sample(sample_size(m), p)
    return total


# ── privacy_amplification recorder for the kept-bit Hamming distance ─────────
def _install_recorders():
    a_bits, b_bits = [], []
    orig = sf.privacy_amplification

    def wrap(sink):
        def w(bits, *a, **k):
            sink.append(list(bits))
            return orig(bits, *a, **k)
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


def one_run(n: int, f: float, payload: str, aid, bid) -> dict:
    params = ProtocolParams(num_qubits=n)
    auth_a = AuthContext("hybrid", aid[0], aid[1], PinnedVerifier(bid[0]))
    auth_b = AuthContext("hybrid", bid[0], bid[1], PinnedVerifier(aid[0]))
    a_rep, b_rep = RecordingReporter(), RecordingReporter()
    a_bits, b_bits, restore = _install_recorders()
    with tempfile.TemporaryDirectory() as out_dir:
        a_end, eve_a = socket.socketpair()
        eve_b, b_end = socket.socketpair()
        try:
            with a_end, eve_a, eve_b, b_end:
                a_res, b_res, _ = run_parallel(
                    guarded(lambda s: sf.send_file(s, payload, a_rep, params, auth_a), a_end),
                    guarded(lambda s: rf.receive_file(s, out_dir, b_rep, params, auth_b), b_end),
                    lambda: eve_leg(lambda: run_eavesdrop(eve_a, eve_b, NullReporter(), threshold=params.qber_threshold, fraction=f), eve_a, eve_b),
                )
        finally:
            restore()

    # Metrics are emitted (RecordingReporter) before any abort, so they survive even when
    # both sides raise (e.g. the tag path); fall back across sides.
    am, bm = a_rep.merged(), b_rep.merged()
    def _m(key):
        return am.get(key) if am.get(key) is not None else bm.get(key)
    sifted = _m("sifted_length")
    sample = _m("sample_size")
    qber = _m("qber")
    secure = None
    if sifted is not None and sample is not None and qber is not None:
        secure = secure_key_length(sifted - sample, sample, qber, EPS_SEC, EPS_COR)
    check = stopping_check(a_res, b_res)
    ham = rem_len = None
    if a_bits and b_bits:
        ham, rem_len = _hamming(a_bits[0], b_bits[0])
    return {
        "n": n, "f": f, "sifted": sifted, "sample": sample, "qber": qber,
        "secure_bits": secure, "secure_bits_code": _m("secure_key_bits"),
        "stopping_check": check,
        "alice_outcome": runner_outcome(a_res), "bob_outcome": runner_outcome(b_res),
        "alice_exit": runner_exit(a_res),
        "detected_threshold": int(check == "threshold"),
        "detected_any": int(check != "none"),
        "bytes_at_bob": getattr(b_res, "bytes_written", 0) if not isinstance(b_res, Exception) else 0,
        "remaining_len": rem_len, "remaining_hamming": ham,
        "a_exc": type(a_res).__name__ if isinstance(a_res, Exception) else "",
        "b_exc": type(b_res).__name__ if isinstance(b_res, Exception) else "",
    }


# ── sanity checks (channel level, native eve_intercept_resend) ───────────────
def _sifted_error_counts(fraction: float, n: int) -> tuple[int, int]:
    """One Alice->Eve->Bob round with the native partial-f Eve; (sifted_errors, sifted)."""
    a_bits = generate_random_bits(n)
    a_bases = generate_random_bases(n)
    qubits = prepare_qubits(a_bits, a_bases)
    mod_qasm, _, _ = eve_intercept_resend(qubits, fraction)
    b_bases = generate_random_bases(n)
    b_bits = measure_qubits(mod_qasm, b_bases)
    matching = [i for i in range(n) if a_bases[i] == b_bases[i]]
    errors = sum(1 for i in matching if a_bits[i] != b_bits[i])
    return errors, len(matching)


def sanity(rounds: int = 30, n: int = 2048) -> dict:
    agg = {}
    for name, fraction in (("f1", 1.0), ("f0", 0.0)):
        e = s = 0
        for _ in range(rounds):
            ee, ss = _sifted_error_counts(fraction, n)
            e += ee; s += ss
        p, lo, hi = wilson(e, s)
        agg[name] = {"errors": e, "sifted": s, "rate": p, "lo": lo, "hi": hi}
    # Full intercept-resend disturbs ~25% of sifted bits; f=0 disturbs none.
    agg["f1_near_quarter"] = (agg["f1"]["lo"] <= 0.25 <= agg["f1"]["hi"])
    agg["f0_is_zero"] = (agg["f0"]["errors"] == 0)
    return agg


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--smoke", action="store_true")
    args = ap.parse_args()
    runs = 3 if args.smoke else RUNS
    n_list = [512, 8192] if args.smoke else N_LIST
    f_list = [0.25, 1.0] if args.smoke else F_LIST

    aid, bid = keypair(), keypair()
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".bin"); tmp.write(b"A" * 1024); tmp.close()

    print(f"[E1] loadavg start: {loadavg()}", flush=True)
    sc = sanity(3 if args.smoke else 30, 2048)
    with open(RESULTS / "e1_eve_sanity.csv", "w", newline="") as fcsv:
        w = csv.writer(fcsv); w.writerow(["case", "errors", "sifted", "rate", "wilson_lo", "wilson_hi"])
        for name in ("f1", "f0"):
            d = sc[name]; w.writerow([name, d["errors"], d["sifted"], f"{d['rate']:.4f}", f"{d['lo']:.4f}", f"{d['hi']:.4f}"])
    print(f"[E1] SANITY (a) f=1.0 sifted error ~25%: {sc['f1']['rate']:.4f}"
          f"[{sc['f1']['lo']:.4f},{sc['f1']['hi']:.4f}] -> contains 0.25: {sc['f1_near_quarter']}", flush=True)
    print(f"[E1] SANITY (b) f=0 error rate exactly 0: {sc['f0_is_zero']} (errors={sc['f0']['errors']})", flush=True)

    rows = []
    for n in n_list:
        for f in f_list:
            for i in range(runs):
                row = one_run(n, f, tmp.name, aid, bid)
                rows.append(row)
            rs = [r for r in rows if r["n"] == n and r["f"] == f]
            print(f"[E1] N={n} f={f}: thr={sum(r['detected_threshold'] for r in rs)}/{len(rs)} "
                  f"checks={ {c: sum(1 for r in rs if r['stopping_check']==c) for c in set(r['stopping_check'] for r in rs)} }", flush=True)

    with open(RESULTS / "e1_detection.csv", "w", newline="") as fcsv:
        w = csv.DictWriter(fcsv, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)

    # summary per (N,f): threshold rate + Wilson vs model, and the full check breakdown
    checks = ["threshold", "finite_key", "tag", "signature", "gcm", "none", "error_other", "abort_other"]
    with open(RESULTS / "e1_summary.csv", "w", newline="") as fcsv:
        w = csv.writer(fcsv)
        w.writerow(["n", "f", "runs", "thr_detected", "thr_rate", "thr_wilson_lo", "thr_wilson_hi",
                    "thr_model", "mean_sifted", "mean_sample", "mean_qber", "mean_secure_bits"] + ["cnt_" + c for c in checks])
        for n in n_list:
            for f in f_list:
                rs = [r for r in rows if r["n"] == n and r["f"] == f]
                det = sum(r["detected_threshold"] for r in rs)
                p, lo, hi = wilson(det, len(rs))
                model = theoretical_threshold_detection(n, f)
                msift = sum(r["sifted"] for r in rs) / len(rs)
                msamp = sum(r["sample"] for r in rs) / len(rs)
                mq = sum(r["qber"] for r in rs) / len(rs)
                msec = sum(r["secure_bits"] for r in rs) / len(rs)
                cnts = [sum(1 for r in rs if r["stopping_check"] == c) for c in checks]
                w.writerow([n, f, len(rs), det, f"{p:.4f}", f"{lo:.4f}", f"{hi:.4f}", f"{model:.4f}",
                            f"{msift:.1f}", f"{msamp:.1f}", f"{mq:.4f}", f"{msec:.1f}"] + cnts)
    print(f"[E1] loadavg end: {loadavg()}", flush=True)
    import os as _os; _os.unlink(tmp.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
