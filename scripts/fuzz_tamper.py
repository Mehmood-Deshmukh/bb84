#!/usr/bin/env python3
"""
E7: tamper fuzzing. Change one wire message at random and record what catches it.

    python scripts/fuzz_tamper.py experiments/configs/e7_fuzz.yaml [--repeats N] [--seed S]

Each trial runs the real Alice (send_file) and Bob (receive_file) in threads over
socket pairs, with a proxy between them that forwards every message unchanged except
one: the target step, which it mutates. Steps are the wire order in
tests/invariants/support.py (WIRE_STEPS) plus the file chunks (5-chunk-<i>).

Mutations:
  semantic  the message still parses and only its meaning changes: one JSON leaf is
            changed to another valid value (a bit or index +-1, a hex or base64
            character, a basis '+' <-> 'x', a number nudged); for the qubit stream,
            one qubit's encoded bit is flipped (what channel noise on one qubit does)
  bitflip   one random bit of the raw message bytes is flipped (often no longer valid
            JSON, so this tests input validation as much as cryptography)
Binary steps (encrypted metadata and chunks) only get bitflip.

Outcomes (first that applies):
  delivered_corrupt   Bob accepted a file that differs from Alice's   <- must never happen
  delivered_intact    Bob got the exact file; the change had no effect on it
  key_confirmation    signatures fine, key tags differ (KeyConfirmationError)
  signature           a finished signature failed (transcript changed)
  handshake_reject    hello rejected (malformed, version/mode/parameter mismatch, trust)
  aead_tag            AES-GCM tag failed (metadata or a chunk)
  metadata_reject     metadata decrypted but failed its checks (MetadataError)
  qber_or_finite_key  a side aborted on the QBER check or the finite-key bound
  malformed_reject    any other error while parsing or using the message
  connection_only     only connection errors (one side gave up without saying why)

Results follow the benchmark convention (see experiments/ignore-INSIGHTS.md):
experiments/results/e7_fuzz/<run id>/ with runs.csv, summary.csv, meta.json, log.txt.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
import random
import secrets
import socket
import string
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

HEX = set(string.hexdigits)
B64 = string.ascii_letters + string.digits + "+/"
BINARY_PREFIX = "5-"  # 5-meta and 5-chunk-<i> are raw ciphertext


def _load_benchmark():
    spec = importlib.util.spec_from_file_location("benchmark", ROOT / "scripts" / "benchmark.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ── mutations (pure functions of the raw message and an RNG) ────────────────

def bitflip(raw: bytes, rng: random.Random) -> bytes:
    """Flip one random bit of the raw message."""
    if not raw:
        return b"\x01"
    pos = rng.randrange(len(raw) * 8)
    out = bytearray(raw)
    out[pos // 8] ^= 1 << (pos % 8)
    return bytes(out)


def _leaves(node: Any, path: tuple = ()) -> list[tuple]:
    """Paths to every scalar (non-container) value in a JSON document."""
    if isinstance(node, dict):
        return [p for k in node for p in _leaves(node[k], path + (k,))]
    if isinstance(node, list):
        return [p for i, v in enumerate(node) for p in _leaves(v, path + (i,))]
    return [path]


def _get(node: Any, path: tuple) -> Any:
    for key in path:
        node = node[key]
    return node


def _set(node: Any, path: tuple, value: Any) -> Any:
    if not path:
        return value
    _get(node, path[:-1])[path[-1]] = value
    return node


def _change_string(value: str, rng: random.Random) -> str:
    if value in ("+", "x"):
        return "x" if value == "+" else "+"
    if value and set(value) <= HEX:
        alphabet = string.hexdigits.lower() if value == value.lower() else string.hexdigits.upper()
        alphabet = "".join(sorted(set(alphabet)))
    elif value and len(value) % 4 == 0 and all(c in B64 + "=" for c in value):
        alphabet = B64
    else:
        alphabet = string.ascii_lowercase
    body = value.rstrip("=")
    if not body:
        return value + "a"
    # Avoid the last base64 character, whose low bits may be padding and decode the same
    i = rng.randrange(max(1, len(body) - 1)) if alphabet == B64 else rng.randrange(len(body))
    choices = [c for c in alphabet if c != body[i]]
    return value[:i] + rng.choice(choices) + value[i + 1:]


def _change_number(value: Any, in_list: bool, rng: random.Random) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        if in_list and value in (0, 1):
            return 1 - value  # a bit
        return value + 1 if value == 0 or rng.random() < 0.5 else value - 1
    if isinstance(value, float):
        return round(value + 0.01, 6)
    return value


def flip_one_qubit(qubits: list[str], rng: random.Random) -> list[str]:
    """
    Flip the encoded bit of one random qubit: an X right after the register
    declaration, before any existing gates, flips the bit in either basis. (A qubit
    for bit 0 in the + basis has no gates, so its string ends at `qreg q[1];` with no
    newline; matching the declaration alone handles that case.)
    """
    out = list(qubits)
    i = rng.randrange(len(out))
    out[i] = out[i].replace("qreg q[1];", "qreg q[1];\nx q[0];", 1)
    return out


def semantic(raw: bytes, step: str, rng: random.Random) -> bytes:
    """Change one value so the message still parses; see the module docstring."""
    doc = json.loads(raw)
    if step == "1":
        return json.dumps(flip_one_qubit(doc, rng)).encode()
    paths = [p for p in _leaves(doc) if _get(doc, p) is not None]
    path = rng.choice(paths)
    old = _get(doc, path)
    if isinstance(old, str):
        new = _change_string(old, rng)
    else:
        in_list = bool(path) and isinstance(_get(doc, path[:-1]), list)
        new = _change_number(old, in_list, rng)
    doc = _set(doc, path, new)
    return json.dumps(doc).encode()


def mutate(raw: bytes, step: str, kind: str, rng: random.Random) -> tuple[bytes, str]:
    """
    The changed message and the mutation actually applied. If a semantic change
    would leave the bytes identical, a bitflip is used instead and reported as such,
    so an unchanged message is never counted as a tamper.
    """
    out = bitflip(raw, rng) if kind == "bitflip" else semantic(raw, step, rng)
    if out == raw:
        return bitflip(raw, rng), "bitflip_fallback"
    return out, kind


# ── one trial ───────────────────────────────────────────────────────────────

def fuzz_proxy(a: socket.socket, b: socket.socket, steps: list[tuple[str, str]], target: str,
               num_chunks: int, change: Callable[[bytes, str], bytes], seen: dict) -> None:
    """Forward the wire in order, changing only the target step; then relay to EOF."""
    from qkd.services import wire
    from tests.invariants.support import A2B

    try:
        order = list(steps) + [(f"5-chunk-{i}", A2B) for i in range(num_chunks)]
        for step_id, direction in order:
            src, dst = (a, b) if direction == A2B else (b, a)
            raw = wire.recv_bytes(src)
            if step_id == target:
                raw, seen["applied"] = change(raw, step_id)
                seen["mutated"] = True
            wire.send_bytes(dst, raw)
        while True:
            wire.forward_message(a, b)
    except (ConnectionError, OSError, ValueError):
        return
    finally:
        for sock in (a, b):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def classify(alice_res: Any, bob_res: Any, src: bytes) -> tuple[str, str]:
    """(outcome, detail) for one trial; see the module docstring for the order."""
    from cryptography.exceptions import InvalidTag

    from qkd.services.file_stream import MetadataError
    from qkd.usecases.common import KeyConfirmationError, KeyExchangeResult, PeerAuthError
    from qkd.usecases.receive_file import ReceiveResult

    if isinstance(bob_res, ReceiveResult) and bob_res.output_path:
        same = Path(bob_res.output_path).read_bytes() == src
        return ("delivered_intact" if same else "delivered_corrupt"), ""
    errors = [r for r in (alice_res, bob_res) if isinstance(r, BaseException)]

    def detail(e: BaseException) -> str:
        return f"{type(e).__name__}: {getattr(e, 'reason', None) or e}"[:200]

    for name, test in (
        ("key_confirmation", lambda e: isinstance(e, KeyConfirmationError)),
        ("signature", lambda e: isinstance(e, PeerAuthError) and "signature" in e.reason),
        ("handshake_reject", lambda e: isinstance(e, PeerAuthError)),
        ("aead_tag", lambda e: isinstance(e, InvalidTag)),
        ("metadata_reject", lambda e: isinstance(e, MetadataError)),
    ):
        for e in errors:
            if test(e):
                return name, detail(e)
    kx = [r.key_exchange if isinstance(r, ReceiveResult) else r for r in (alice_res, bob_res)]
    aborted = [r for r in kx if isinstance(r, KeyExchangeResult) and r.aborted]
    if aborted:
        return "qber_or_finite_key", aborted[0].abort_reason or ""
    for e in errors:
        if not isinstance(e, (ConnectionError, OSError, TimeoutError)):
            return "malformed_reject", detail(e)
    if errors:
        return "connection_only", detail(errors[0])
    return "other", f"alice={alice_res!r} bob={bob_res!r}"[:200]


def run_trial(mode: str, step: str, kind: str, seed: int, keys: dict, params, src_path: Path,
              src: bytes, num_chunks: int, work: Path) -> dict:
    from qkd.usecases.receive_file import receive_file
    from qkd.usecases.send_file import send_file
    from tests.invariants.support import WIRE_STEPS, RecordingReporter, context, guarded

    steps = [s for s in WIRE_STEPS if mode != "none" or not s[0].startswith("4b")]
    rng = random.Random(seed)
    out_dir = work / f"recv-{seed}"
    alice_rep, bob_rep = RecordingReporter(), RecordingReporter()
    seen: dict = {}
    results: list[Any] = [None, None]

    alice_end, proxy_a = socket.socketpair()
    proxy_b, bob_end = socket.socketpair()
    for sock in (alice_end, proxy_a, proxy_b, bob_end):
        sock.settimeout(60)  # a stuck trial fails instead of hanging the run
    with alice_end, proxy_a, proxy_b, bob_end:
        def alice() -> None:
            results[0] = guarded(lambda s: send_file(s, str(src_path), alice_rep, params,
                                                     context(keys, "alice", mode)))(alice_end)

        def bob() -> None:
            results[1] = guarded(lambda s: receive_file(s, str(out_dir), bob_rep, params,
                                                        context(keys, "bob", mode)))(bob_end)

        threads = [threading.Thread(target=alice), threading.Thread(target=bob),
                   threading.Thread(target=fuzz_proxy, args=(proxy_a, proxy_b, steps, step, num_chunks,
                                                             lambda raw, s: mutate(raw, s, kind, rng), seen))]
        for t in threads:
            t.start()
        for t in threads:
            t.join(120)

    outcome, detail = classify(results[0], results[1], src)
    leftovers = [p.name for p in out_dir.glob("*")] if out_dir.exists() else []
    # A file left behind is only acceptable when it was delivered intact
    leftover_bad = bool(leftovers) and outcome != "delivered_intact"
    return {
        "mode": mode, "step": step, "mutation": kind, "seed": seed,
        "mutated": int(bool(seen.get("mutated"))),
        "applied": seen.get("applied", ""),
        "outcome": outcome, "detail": detail,
        "alice_last_stage": alice_rep.stages[-1] if alice_rep.stages else "",
        "bob_last_stage": bob_rep.stages[-1] if bob_rep.stages else "",
        "partial_file_left": int(leftover_bad),
    }


# ── main ────────────────────────────────────────────────────────────────────

OUTCOMES = ["delivered_corrupt", "delivered_intact", "key_confirmation", "signature", "handshake_reject",
            "aead_tag", "metadata_reject", "qber_or_finite_key", "malformed_reject", "connection_only", "other"]


def combos(cfg: dict) -> list[tuple[str, str, str]]:
    """Every (mode, step, mutation) to try."""
    from tests.invariants.support import WIRE_STEPS

    out = []
    for mode in cfg["modes"]:
        steps = [s for s, _ in WIRE_STEPS if mode != "none" or not s.startswith("4b")]
        steps += [f"5-chunk-{i}" for i in range(cfg["num_chunks"])]
        for step in steps:
            for kind in cfg["mutations"]:
                if step.startswith(BINARY_PREFIX) and kind == "semantic":
                    continue
                out.append((mode, step, kind))
    return out


def summarize(rows: list[dict]) -> list[dict]:
    bench = _load_benchmark()
    groups: dict[tuple, list[dict]] = {}
    for r in rows:
        groups.setdefault((r["mode"], r["step"], r["mutation"]), []).append(r)
    out = []
    for (mode, step, kind), group in groups.items():
        n = len(group)
        row: dict[str, Any] = {"mode": mode, "step": step, "mutation": kind, "n": n}
        for o in OUTCOMES:
            row[f"n_{o}"] = sum(r["outcome"] == o for r in group)
        caught = n - row["n_delivered_intact"] - row["n_delivered_corrupt"]
        lo, hi = bench.wilson(caught, n)
        row.update(rate_caught=round(caught / n, 5), rate_caught_lo=round(lo, 5), rate_caught_hi=round(hi, 5),
                   n_partial_file_left=sum(int(r["partial_file_left"]) for r in group),
                   n_not_mutated=sum(1 - int(r["mutated"]) for r in group),
                   n_fallback=sum(r["applied"] == "bitflip_fallback" for r in group))
        out.append(row)
    return out


def main() -> int:
    import yaml

    from qkd.core import pqc
    from qkd.core.config import ProtocolParams

    bench = _load_benchmark()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("config", type=Path)
    parser.add_argument("--repeats", type=int, help="Trials per (mode, step, mutation); marks the run -scratch")
    parser.add_argument("--seed", type=int)
    args = parser.parse_args()

    cfg = yaml.safe_load(args.config.read_text())
    repeats = args.repeats or cfg.get("repeats", 30)
    seed = args.seed if args.seed is not None else cfg.get("seed", secrets.randbits(32))
    meta = bench.environment(cfg)
    meta.update(repeats=repeats, run_order_seed=seed, status="running")
    started = datetime.fromisoformat(meta["started"])
    run_dir = bench.RESULTS / cfg["name"] / bench.run_id(started, meta["git_commit"], meta["git_dirty"],
                                                         repeats != cfg.get("repeats", 30))
    run_dir.mkdir(parents=True, exist_ok=False)
    meta["run_id"] = run_dir.name
    (run_dir / "meta.json").write_text(json.dumps(meta, indent=2, default=str))
    log = open(run_dir / "log.txt", "a")

    def say(line: str) -> None:
        print(line, flush=True)
        log.write(line + "\n")
        log.flush()

    from qkd.services.file_stream import expected_chunks

    if expected_chunks(cfg["payload_bytes"], cfg["chunk_size"]) != cfg["num_chunks"]:
        parser.error("num_chunks does not match payload_bytes / chunk_size in the config")
    params = ProtocolParams(num_qubits=cfg["num_qubits"], chunk_size=cfg["chunk_size"],
                            enforce_finite_key=cfg.get("enforce_finite_key", False))
    keys = {"alice": pqc.sig_keygen(), "bob": pqc.sig_keygen()}
    plan = [(c, r) for c in combos(cfg) for r in range(repeats)]
    random.Random(seed).shuffle(plan)
    rows_log = bench.RowLog(run_dir / "runs.csv")
    say(f"run id {run_dir.name}: {len(plan)} trials, seed {seed}")

    with tempfile.TemporaryDirectory(prefix="qkd-fuzz-") as tmp:
        work = Path(tmp)
        src_path = work / "payload.bin"
        src_path.write_bytes(os.urandom(cfg["payload_bytes"]))
        src = src_path.read_bytes()
        for n, ((mode, step, kind), repeat) in enumerate(plan, start=1):
            trial_seed = random.Random(f"{seed}-{mode}-{step}-{kind}-{repeat}").randrange(1 << 31)
            row = {"order": n - 1, "repeat": repeat,
                   **run_trial(mode, step, kind, trial_seed, keys, params, src_path, src, cfg["num_chunks"], work)}
            rows_log.append(row)
            flag = "  <-- CORRUPT FILE ACCEPTED" if row["outcome"] == "delivered_corrupt" else ""
            say(f"[{n}/{len(plan)}] {mode} {step} {kind}: {row['outcome']}{flag}")

    bench.write_csv(run_dir / "summary.csv", summarize(bench.read_csv(run_dir / "runs.csv")))
    meta.update(status="complete", finished=datetime.now(timezone.utc).isoformat())
    (run_dir / "meta.json").write_text(json.dumps(meta, indent=2, default=str))
    if bench.paper_grade(meta):
        bench.update_latest(run_dir.parent, run_dir)
        say(f"complete; {run_dir.parent.name}/latest -> {run_dir.name}")
    else:
        say("complete; not paper grade (scratch or dirty tree), so latest was not moved")
    log.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
