"""
E6 — handshake overhead and primitive microbenchmarks (current protocol).

(1) Framed bytes per hello and finished message per mode, measured on the wire, plus the
    auth_overhead_bytes metric; and the QASM qubit payload size at each N.
(2) handshake_ms over the real CLI (10 runs/mode, cold process, both sides) and in-process
    warm. The CLI runs use N=512 with the finite-key gate OFF so the run reaches step 4b
    and emits handshake_ms (the handshake cost is N-independent; the gate would otherwise
    abort a small-N run before the finished exchange). Nagle is ENABLED (no TCP_NODELAY).
(3) Microbenchmarks (>=1000 calls, median us): sig_keygen, sign, verify, kem_keygen,
    kem_encaps, kem_decaps, HMAC confirmation_tag, derive_session_key, key_schedule
    (subkey derivation), one transcript update, Toeplitz privacy_amplification at N=8192,
    and the finite-key secure_key_length.

Run on an idle machine.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import timeit
from pathlib import Path

import common
from common import RESULTS, loadavg, median_iqr, run_parallel, guarded, keypair

from qkd.core import pqc
from qkd.core.config import ProtocolParams
from qkd.core.crypto_utils import derive_session_key, key_schedule
from qkd.core.finite_key import secure_key_length
from qkd.core.bb84_protocol import generate_random_bases, generate_random_bits, privacy_amplification
from qkd.core.quantum_channel import prepare_qubits
from qkd.services import wire
from qkd.services.reporting import NullReporter
from qkd.services.transcript import TranscriptChannel
from qkd.usecases import handshake as hs
from qkd.usecases.common import AuthContext
from qkd.usecases.receive_file import receive_file
from qkd.usecases.send_file import send_file
from tests.invariants.support import PinnedVerifier, RecordingReporter

ROOT = common.ROOT


# ── (1) wire sizes ───────────────────────────────────────────────────────────
class _RecSock:
    def __init__(self, sock): self._s = sock; self.sent = []
    def sendall(self, data): self.sent.append(len(data)); self._s.sendall(data)
    def __getattr__(self, n): return getattr(self._s, n)


def message_bytes(mode, aid, bid):
    a_raw, b_raw = socket.socketpair()
    a_sock, b_sock = _RecSock(a_raw), _RecSock(b_raw)
    policy = ProtocolParams().security_policy()
    auth_a = AuthContext(mode, aid[0], aid[1], PinnedVerifier(bid[0]))
    auth_b = AuthContext(mode, bid[0], bid[1], PinnedVerifier(aid[0]))
    ca, cb = TranscriptChannel(a_sock, "alice"), TranscriptChannel(b_sock, "bob")
    run_parallel(lambda: hs.alice_hello(ca, auth_a, NullReporter(), ProtocolParams()),
                 lambda: hs.bob_hello(cb, auth_b, NullReporter(), ProtocolParams()))
    hello_a, hello_b = a_sock.sent[0], b_sock.sent[0]
    t = ca.digest(); assert t == cb.digest()
    key = os.urandom(32)
    before_a, before_b = len(a_sock.sent), len(b_sock.sent)
    state_a = hs.HandshakeState(mode, peer_id_pk=bid[0])
    state_b = hs.HandshakeState(mode, peer_id_pk=aid[0])
    run_parallel(lambda: hs.alice_finished(ca, auth_a, state_a, t, key, NullReporter()),
                 lambda: hs.bob_finished(cb, auth_b, state_b, t, key, NullReporter()))
    fin_a, fin_b = a_sock.sent[before_a], b_sock.sent[before_b]
    a_raw.close(); b_raw.close()
    return {"mode": mode, "hello_A": hello_a, "hello_B": hello_b, "finished_B": fin_b, "finished_A": fin_a,
            "total_bytes": hello_a + hello_b + fin_a + fin_b}


def none_hello_bytes(aid, bid):
    a_raw, b_raw = socket.socketpair(); a_sock, b_sock = _RecSock(a_raw), _RecSock(b_raw)
    ca, cb = TranscriptChannel(a_sock, "alice"), TranscriptChannel(b_sock, "bob")
    run_parallel(lambda: hs.alice_hello(ca, None, NullReporter(), ProtocolParams()),
                 lambda: hs.bob_hello(cb, None, NullReporter(), ProtocolParams()))
    r = {"mode": "none", "hello_A": a_sock.sent[0], "hello_B": b_sock.sent[0],
         "finished_B": 0, "finished_A": 0, "total_bytes": a_sock.sent[0] + b_sock.sent[0]}
    a_raw.close(); b_raw.close(); return r


def qasm_sizes():
    rows = []
    for n in (512, 1024, 2048, 4096, 8192):
        payload = wire.encode_json(prepare_qubits(generate_random_bits(n), generate_random_bases(n)))
        rows.append({"qubits": n, "framed_bytes": len(payload) + 4, "bytes_per_qubit": round((len(payload) + 4) / n, 2)})
    return rows


# ── (2) handshake_ms in-process warm + auth_overhead_bytes ───────────────────
def handshake_inproc(mode, runs, aid, bid):
    params = ProtocolParams(num_qubits=512, enforce_finite_key=False)
    auth_a = None if mode == "none" else AuthContext(mode, aid[0], aid[1], PinnedVerifier(bid[0]))
    auth_b = None if mode == "none" else AuthContext(mode, bid[0], bid[1], PinnedVerifier(aid[0]))
    ms, overhead = [], None
    with tempfile.NamedTemporaryFile(suffix=".bin") as tf:
        tf.write(b"X" * 1024); tf.flush()
        for _ in range(runs):
            a_rep, b_rep = RecordingReporter(), RecordingReporter()
            with tempfile.TemporaryDirectory() as out:
                a, b = socket.socketpair()
                with a, b:
                    run_parallel(lambda: _leg(send_file, a, tf.name, a_rep, params, auth_a),
                                 lambda: _leg(receive_file, b, out, b_rep, params, auth_b))
            am = a_rep.merged()
            if am.get("handshake_ms") is not None:
                ms.append(am["handshake_ms"]); overhead = am.get("auth_overhead_bytes")
    return ms, overhead


def _leg(fn, sock, arg2, rep, params, auth):
    try:
        return fn(sock, arg2, rep, params, auth)
    except Exception as e:
        return e
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


# CLI cold handshake
def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); return s.getsockname()[1]


def handshake_cli(mode, runs, base):
    adir, bdir = base / f"a-{mode}", base / f"b-{mode}"
    for d in (adir, bdir):
        (d / "id").mkdir(parents=True, exist_ok=True)
    payload = base / "hs.bin"
    if not payload.exists():
        payload.write_bytes(os.urandom(1024))
    a_ms, b_ms = [], []
    for _ in range(runs):
        port = _free_port()
        env = {**os.environ, "QKD_NUM_QUBITS": "512", "QKD_ENFORCE_FINITE_KEY": "0",
               "QKD_KNOWN_PEERS_FILE": str(bdir / "known.json"), "QKD_TOFU": "1"}
        env_a = {**env, "QKD_KNOWN_PEERS_FILE": str(adir / "known.json")}
        bob = subprocess.Popen([sys.executable, "-m", "qkd.runner.bob", "--port", str(port), "--events", "json",
                                "--auth", mode, "--identity", str(bdir / "id"), "--output-dir", str(bdir / "recv")],
                               cwd=str(bdir), env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        ok = False; t0 = time.time()
        while time.time() - t0 < 30:
            ln = bob.stdout.readline()
            if not ln:
                break
            try:
                if json.loads(ln).get("type") == "listening":
                    ok = True; break
            except json.JSONDecodeError:
                continue
        if not ok:
            bob.kill(); continue
        al = subprocess.run([sys.executable, "-m", "qkd.runner.alice", str(payload), "--host", "127.0.0.1",
                             "--port", str(port), "--events", "json", "--auth", mode, "--identity", str(adir / "id")],
                            cwd=str(adir), env=env_a, capture_output=True, text=True, timeout=120)
        rest = bob.stdout.read(); bob.wait(timeout=30)

        def _hs(stdout):
            v = None
            for ln in stdout.splitlines():
                try:
                    e = json.loads(ln)
                except json.JSONDecodeError:
                    continue
                if e.get("type") == "metrics" and "handshake_ms" in (e.get("payload") or {}):
                    v = e["payload"]["handshake_ms"]
            return v
        va, vb = _hs(al.stdout), _hs(rest)
        if va is not None:
            a_ms.append(va)
        if vb is not None:
            b_ms.append(vb)
    return a_ms, b_ms


# ── (3) microbenchmarks ───────────────────────────────────────────────────────
def micro(fn, iters=2000):
    samples = []
    for _ in range(iters):
        t0 = time.perf_counter_ns(); fn(); samples.append((time.perf_counter_ns() - t0) / 1000.0)
    return statistics.median(samples)


def primitives():
    pk, seed = pqc.sig_keygen(); msg = b"benchmark" * 4; sig = pqc.sign(seed, msg)
    kpk, ksk = pqc.kem_keygen(); ss, ct = pqc.kem_encaps(kpk)
    key = b"\x01" * 32; t = b"\x02" * 32
    # Toeplitz PA at N=8192: kept ~ 3482 bits -> 256
    kept = [i & 1 for i in range(3482)]
    salt, _ = privacy_amplification(kept, 256)
    ops = {
        "sig_keygen": lambda: pqc.sig_keygen(),
        "sign": lambda: pqc.sign(seed, msg),
        "verify": lambda: pqc.verify(pk, msg, sig),
        "kem_keygen": lambda: pqc.kem_keygen(),
        "kem_encaps": lambda: pqc.kem_encaps(kpk),
        "kem_decaps": lambda: pqc.kem_decaps(ksk, ct),
        "confirmation_tag_hmac": lambda: hs.confirmation_tag(key, b"bob", t),
        "derive_session_key_hybrid": lambda: derive_session_key(key, ss, t, "hybrid"),
        "key_schedule_subkeys": lambda: key_schedule(key),
        "secure_key_length": lambda: secure_key_length(3482, 614, 0.0, 1e-10, 1e-15),
    }
    rows = [{"op": n, "median_us": round(micro(f), 4), "iters": 2000} for n, f in ops.items()]
    rows.append({"op": "toeplitz_pa_8192", "median_us": round(micro(lambda: privacy_amplification(kept, 256, salt=salt), 200), 4), "iters": 200})
    # transcript update (one tracked small message)
    small = {"sample_indices": [1, 2, 3, 4, 5]}

    def tracked():
        h = hashlib.sha256()
        p = json.dumps(small, sort_keys=True, separators=(",", ":")).encode()
        h.update(b"\x00" + wire._LENGTH.pack(len(p)) + p); h.digest()
    rows.append({"op": "transcript_update", "median_us": round(micro(tracked), 4), "iters": 2000})
    return rows


def main():
    import argparse
    ap = argparse.ArgumentParser(); ap.add_argument("--smoke", action="store_true")
    args = ap.parse_args()
    cli_runs = 2 if args.smoke else 10
    inproc_runs = 3 if args.smoke else 10
    print(f"[E6] loadavg start: {loadavg()}", flush=True)
    aid, bid = keypair(), keypair()

    # (1)
    mb = [none_hello_bytes(aid, bid)] + [message_bytes(m, aid, bid) for m in ("sign", "hybrid")]
    with open(RESULTS / "e6_message_bytes.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(mb[0])); w.writeheader(); w.writerows(mb)
    for r in mb:
        print(f"[E6.1] {r['mode']}: helloA={r['hello_A']} helloB={r['hello_B']} finB={r['finished_B']} finA={r['finished_A']} total={r['total_bytes']}", flush=True)
    q = qasm_sizes()
    with open(RESULTS / "e6_qasm_sizes.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(q[0])); w.writeheader(); w.writerows(q)

    # (2)
    base = Path(tempfile.mkdtemp(prefix="e6v2-"))
    hs_rows = []
    for mode in ("none", "sign", "hybrid"):
        ms_in, overhead = handshake_inproc(mode, inproc_runs, aid, bid)
        a_cli, b_cli = handshake_cli(mode, cli_runs, base)
        med_in = median_iqr(ms_in)
        med_a = median_iqr(a_cli); med_b = median_iqr(b_cli)
        hs_rows.append({"mode": mode, "auth_overhead_bytes": overhead,
                        "inproc_warm_ms_median": round(med_in[0], 3), "inproc_warm_ms_iqr": round(med_in[3], 3),
                        "cli_alice_ms_median": round(med_a[0], 3) if a_cli else None, "cli_alice_ms_iqr": round(med_a[3], 3) if a_cli else None,
                        "cli_bob_ms_median": round(med_b[0], 3) if b_cli else None, "cli_bob_ms_iqr": round(med_b[3], 3) if b_cli else None,
                        "cli_runs_alice": len(a_cli), "cli_runs_bob": len(b_cli)})
        print(f"[E6.2] {mode}: overhead={overhead} inproc_warm={med_in[0]:.3f}ms "
              f"cli_alice={med_a[0] if a_cli else None} cli_bob={med_b[0] if b_cli else None}", flush=True)
    with open(RESULTS / "e6_handshake_ms.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(hs_rows[0])); w.writeheader(); w.writerows(hs_rows)

    # (3)
    p = primitives()
    with open(RESULTS / "e6_primitives.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(p[0])); w.writeheader(); w.writerows(p)
    for r in p:
        print(f"[E6.3] {r['op']}: {r['median_us']} us", flush=True)
    print(f"[E6] loadavg end: {loadavg()}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
