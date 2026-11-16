# Evaluation report — BB84 with an authenticated classical channel (paper-eval v2, origin/main)

**Commit:** `c8f8601` (origin/main; merged into `exp/paper-eval-v2` at `29090bf`). Every
result below was produced by a script in `scripts/paper/` run on this commit; the source
CSV is named with each table. **Channel preset: `ideal`** (lossless, no dark counts, no
misalignment). **Reconciliation: `none`** (Cascade off). All other defaults: N=8192,
sample fraction 0.15, Q_max=0.11, ℓ=256, ε_sec=1e-10, ε_cor=1e-15, auth mode hybrid,
finite-key gate on unless a sub-experiment states otherwise.

**TCP_NODELAY is set on every protocol socket** (`wire.no_delay`, wire.py:121, applied by
`wire.accept` at bob.py:121 and `wire.connect_with_retry` at alice.py:109), so the E5/E6
CLI timings below have **Nagle disabled** — the ~40 ms delayed-ACK stall that the previous
run (commit 3c2f5f9) measured is gone (see "Changes vs previous run").

Companion file: `implementation.md` (1A facts, from 3c2f5f9 — wire sizes there are the v2
protocol; see E6 here for the v3 values).

## Environment

- AMD Ryzen 5 5600H, 12 logical CPUs, 15 GiB RAM, Linux (Ubuntu 24.04).
- Python 3.12.3; qiskit 2.6.1, qiskit-aer 0.18.2, cryptography 50.0.2, numpy 2.5.4.
- **`pytest -q` → 802 passed, 1 skipped, 3 warnings, 122.8 s, exit 0** (`pytest_full.log`).

## Method

- **In-process harnesses (E1–E4)** drive the real `send_file`/`receive_file`/`run_eavesdrop`/
  `run_mitm` over `socket.socketpair()`. **CLI harnesses (E5, E6 handshake)** spawn real
  `qkd-alice`/`qkd-bob` subprocesses (`--events json`, localhost TCP, TCP_NODELAY set).
- **Partial-f Eve is now native** (`quantum_channel.eve_intercept_resend(qasm, fraction)`;
  `run_eavesdrop(..., fraction=f)`), so the harnesses call it directly (the old
  monkeypatch and `scripts/paper/eve.py` are gone). **Sanity (`e1_eve_sanity.csv`):** at
  f=1.0 the sifted error rate is **0.2492 [0.2444, 0.2558]** (contains 0.25, full
  intercept-resend); at f=0.0 it is **exactly 0** (0 errors), 30 rounds each at N=2048.
- **Stopping check recorded in-process** — `threshold | finite_key | tag | signature |
  gcm | none` — because the runner maps QBER-threshold, finite-key, and
  `KeyConfirmationError` **all to `aborted_qber`**; the classifier tests "finite-key"
  before "qber" (the finite-key reason string also contains "QBER"). `PeerAuthError` →
  `aborted_auth`, `InvalidTag`/other → `failed`.

---

## E1 — Detection vs N and f (`e1_detection.csv`, `e1_summary.csv`, fig `e1_detection.pdf/png`)

In-process partial-f Eve, hybrid, finite-key gate ON, 30 runs per (N, f). Threshold rate
with 95% Wilson vs the binomial model (p = f/4), and the stopping-check breakdown.

| N | f | thr rate | 95% Wilson | model | mean QBER | mean ℓ | thr / fin / tag |
|---|---|---|---|---|---|---|---|
| 512 | 0.1 | 0.000 | [0.00, 0.11] | 0.004 | 0.0217 | 0 | 0 / 30 / 0 |
| 512 | 0.25 | 0.100 | [0.03, 0.26] | 0.108 | 0.0560 | 0 | 3 / 27 / 0 |
| 512 | 0.5 | 0.667 | [0.49, 0.81] | 0.562 | 0.1357 | 0 | 20 / 10 / 0 |
| 512 | 1.0 | 1.000 | [0.89, 1.00] | 0.980 | 0.2667 | 0 | 30 / 0 / 0 |
| 1024 | 0.25 | 0.033 | [0.01, 0.17] | 0.051 | 0.0625 | 0 | 1 / 29 / 0 |
| 2048 | 0.25 | 0.033 | [0.01, 0.17] | 0.013 | 0.0658 | 0 | 1 / 29 / 0 |
| 4096 | 0.25 | 0.000 | [0.00, 0.11] | 0.001 | 0.0652 | 0 | 0 / 30 / 0 |
| 4096 | 0.5 | 0.833 | [0.66, 0.93] | 0.786 | 0.1267 | 0 | 25 / 5 / 0 |
| 8192 | 0.1 | 0.000 | [0.00, 0.11] | 0.000 | 0.0246 | 556 | 0 / 0 / 30 |
| 8192 | 0.25 | 0.000 | [0.00, 0.11] | 0.000 | 0.0641 | 346 | 0 / 0 / 30 |
| 8192 | 0.5 | 0.900 | [0.74, 0.97] | 0.871 | 0.1269 | 94 | 27 / 3 / 0 |
| 8192 | 1.0 | 1.000 | [0.89, 1.00] | 1.000 | 0.2509 | 0 | 30 / 0 / 0 |

(Full 20-row table in the CSV.) **The model is inside the 95% Wilson interval for all 20
points.** f=0.1 is never caught by the threshold at any N (0/30 each). The stopping-check
column shows the structure: at N ≤ 4096 the finite-key bound (ℓ=0 below 4096, 34 at 4096)
stops every run the threshold misses; **at N=8192 with f ∈ {0.1, 0.25} all 30 runs reach
and are stopped by the key-confirmation tag.**

## E2 — All checks at N=8192 (`e2_outcomes.csv`, `e2_summary.csv`, fig `e2_stopping_check.pdf/png`)

Partial-f Eve, N=8192, 30 runs per (mode, f).

| mode | f | tag | finite_key | threshold | gcm | mean QBER | mean ℓ | mean Hamming | Alice-ok-while-Bob-failed |
|---|---|---|---|---|---|---|---|---|---|
| hybrid | 0.01 | 30 | 0 | 0 | 0 | 0.0024 | 698 | 8.8 | 0 |
| hybrid | 0.05 | 30 | 0 | 0 | 0 | 0.0126 | 631 | 43.5 | 0 |
| hybrid | 0.10 | 30 | 0 | 0 | 0 | 0.0238 | 561 | 89.0 | 0 |
| hybrid | 0.25 | 30 | 0 | 0 | 0 | 0.0642 | 349 | 212.6 | 0 |
| hybrid | 0.30 | 22 | 7 | 1 | 0 | 0.0756 | 296 | 259.2 | 0 |
| hybrid | 0.35 | 14 | 16 | 0 | 0 | 0.0890 | 241 | 301.0 | 0 |
| hybrid | 0.40 | 2 | 21 | 7 | 0 | 0.1003 | 209 | 361.0 | 0 |
| hybrid | 0.50 | 0 | 5 | 25 | 0 | 0.1258 | 159 | — | 0 |
| none | 0.01 | 0 | 0 | 0 | 30 | 0.0017 | 697 | 8.6 | 30 |
| none | 0.10 | 0 | 0 | 0 | 30 | 0.0272 | 537 | 85.1 | 30 |
| none | 0.25 | 0 | 2 | 0 | 28 | 0.0654 | 344 | 215.1 | 28 |
| none | 0.35 | 0 | 17 | 0 | 13 | 0.0869 | 246 | 307.9 | 13 |
| none | 0.50 | 0 | 5 | 25 | 0 | 0.1246 | 184 | — | 0 |

(Full 16-row table in the CSV.) **In hybrid mode every run with 0.01 ≤ f ≤ 0.25 (120/120)
is stopped by the key-confirmation tag, 0 bytes at Bob, Alice never reports success.** In
none mode the same runs fail only at Bob's first GCM tag (the metadata) **while Alice's
runner reports `completed`, exit 0: 118 of 120 runs at f ≤ 0.25** (the other 2, at f=0.25,
hit the finite-key bound first; 160 none-mode runs across all f end with Alice-success
while Bob fails). The kept-bit Hamming distance grows with f (≈9 at f=0.01 to ≈213 at
f=0.25), so the keys genuinely differ — key confirmation turns that silent difference into
an abort both parties see. Above f≈0.3 the finite-key bound and then the threshold take
over.

## E3 — Threshold vs finite-key bound (`e3_keylen_vs_qber.csv`, `e3_keylen_vs_N.csv`, `e3_qmax_sweep.csv`, `e3_honest.csv`; fig `e3_keylen_vs_qber.pdf/png`)

**(a) ℓ(Q=0) vs N:** 512→0, 1024→0, 2048→0, **4096→34, 8192→709**, 16384→2535.
**(ℓ vs Q at N=8192, μ=0.2133):** Q=0.080→274, Q=0.085→252 — the bound drops below 256 at
**Q ≈ 0.082–0.084**. **(b) Q_max sweep, 10 runs/cell:** at Q_max=0.05 every f is caught by
the low threshold; at Q_max=0.11, f=0.35 → 7 finite_key + 3 tag; at Q_max=0.15, f=0.5 →
**10/10 finite_key** (threshold raised away, so the finite-key bound is the active gate).
**(c) 20 honest runs: 0 aborts, QBER exactly 0.0** on every run.

## E4 — Attack matrix at N=8192, 3 runs/cell (`e4_matrix.csv`)

All 24 cells `stable=True`. `check` = the defense that fired.

| attacker | mode | check | stage | attacker plaintext | Alice success |
|---|---|---|---|---|---|
| eve full (f=1) | none / hybrid | threshold | qber_estimation | no | no |
| eve partial f=0.1 | none | **gcm** | file_transfer | no | **yes** |
| eve partial f=0.1 | hybrid | **tag** | key_confirmation | no | no |
| mallory own-key | none | **none (succeeds)** | file_transfer | **yes (1024 B)** | yes |
| mallory own-key | sign / hybrid | trust | authentication | no | no |
| mallory relay (own key) | sign / hybrid | signature | key_confirmation | no | no |
| mallory relay (Bob's real key) | sign | **passes 4b** (control) | file_transfer | no | passed 4b |
| mallory relay (Bob's real key) | hybrid | **tag** | key_confirmation | no | no |
| tamper ×6 (bases…salt) | hybrid | signature | key_confirmation | no | no |
| tamper metadata (bitflip) | hybrid | gcm | file_transfer | no | yes* |
| malicious zero chunks | hybrid | metadata_rule | file_transfer | no | yes* |
| malicious size mismatch | hybrid | metadata_rule | file_transfer | no | yes* |
| downgrade mode | hybrid/none | mode | authentication | no | no |
| downgrade policy (ℓ 128 vs 256) | hybrid | policy | authentication | no | no |
| replay finished | hybrid | signature | key_confirmation | no | no |

\* Alice completed streaming; Bob rejected the bytes, so no plaintext reached Bob. The
**only** cell where an attacker obtains plaintext is **Mallory own-key in `none` mode**
(1024 bytes). The relay-with-Bob's-real-key control reproduces the paper: in **sign**
Mallory passes key confirmation (she can recompute K from the BB84 key + T), in **hybrid**
she is stopped at the **tag** (she cannot compute the KEM secret).

## E5 — Transfer time over the real CLI (`e5_transfer_time.csv`, `e5_summary_*.csv`; fig `e5_stage_bars.pdf/png`)

5 runs each, median (IQR), Bob stage breakdown. **TCP_NODELAY set (Nagle off).**

**(a) N sweep, 1 MB, hybrid (finite-key gate OFF so N<8192 completes):** total wall
0.87→3.12 s, almost all Bob's single measurement job (`quantum_transmission`): N=512→0.37 s,
2048→0.79 s, 4096→1.37 s, **8192→2.60 s** (≈ linear, ~0.32 ms/qubit). **(b) file size at
N=8192, hybrid, gate ON:** wall is flat at **~3.12 s for 1 KB … 10 MB**; **100 MB adds only
0.15 s** of file_transfer (total 3.20 s). **(c) modes at N=8192, 1 MB:** none 3.09 s, sign
3.10 s, hybrid 3.10 s — within noise; the key_confirmation stage is now ~3–11 ms (Nagle's
~40 ms gone). **Where the time goes: ~83% is Bob's one Aer measurement job (2.60 s of
3.12 s); privacy amplification (Toeplitz) ~0.013 s; handshake a few ms; file transfer
negligible.**

## E6 — Handshake overhead and microbenchmarks (`e6_message_bytes.csv`, `e6_handshake_ms.csv`, `e6_qasm_sizes.csv`, `e6_primitives.csv`; fig `e6_byte_breakdown.pdf/png`)

**Wire bytes (framed, per message):** none hello 188/188; sign hello 2862/2862, finished
4491 each; hybrid hello 4458/4330, finished 4491 each. **`auth_overhead_bytes`
(sent+received): none 378, sign 14708, hybrid 17770.** (Each hello is +26 B over 3c2f5f9:
the new `reconciliation` field in the policy Π.) **Qubit message (as actually sent,
`encode_pulses`): ≈63 B/qubit; N=8192 → 517 083 B.**

**handshake_ms (`e6_handshake_ms.csv`, TCP_NODELAY set):** in-process warm — none 0.37,
sign 1.78, hybrid 2.53 ms. Real CLI, cold process (10 runs/mode, N=512, gate off) —
**Alice sign 11.96 / hybrid 14.62 ms, Bob sign 14.18 / hybrid 16.28 ms**. (With Nagle off
these are ~4× lower than 3c2f5f9's ~53/55 ms Alice; the residual is cold ML-KEM/ML-DSA
provider init in a fresh process.)

**Microbenchmarks (median of 2000 calls, µs):** sig_keygen 167, sign 846, verify 167,
kem_keygen 97, kem_encaps 35, kem_decaps 100, HMAC confirmation_tag 11, derive_session_key
5.2, key_schedule (3 subkeys) 9.0, secure_key_length 2.4, transcript_update 4.8;
**Toeplitz privacy_amplification at N=8192 = 6490 µs (6.5 ms, median of 200).**

---

## Values for the paper

Draft *experimental* numbers (Section 6.4, fig:e1/e2) are PLACEHOLDERS. §6.3 key-length
numbers are derivations, reproduced by calling `finite_key.secure_key_length`.

### Section 6.3 — key length (CONFIRMED, `e3_keylen_vs_*.csv`)

| Quantity | Draft | Measured | Verdict |
|---|---|---|---|
| fixed penalty | ≈168 bits | 168.1 | ✓ |
| N=8192: k, n, μ, ℓ(Q=0) | 614, 3482, 0.213, ≈709 | 614, 3482, 0.2133, **709** | ✓ |
| N=4096: ℓ(Q=0) | ≈34 | 34 | ✓ |
| ≤ N=2048 | none | 0 | ✓ |
| smallest power of two for 256 bits | 8192 | 8192 (4096→34) | ✓ |
| bound < 256 for Q ≳ | 8.4% | 8.2–8.4% (Q=0.080→274, 0.085→252) | ✓ |

### Section 6.4 — detection model and rates (PLACEHOLDERS → measured)

| Draft statement | Draft | Measured | Source | Verdict |
|---|---|---|---|---|
| per-bit error p = f/4 | f/4 | f=1 → sifted error 0.2492 [0.2444, 0.2558] | `e1_eve_sanity.csv` | ✓ |
| finite-key bound stops f in | ≈0.34–0.44 | finite_key dominant at f=0.35 (16/30) and 0.40 (21/30); band ≈0.30–0.44 | `e2_summary.csv`, `e3_qmax_sweep.csv` | ✓ (from ~0.30) |
| fig:e1 f=0.1 caught by threshold | none | **0/30 at every N** | `e1_summary.csv` | ✓ |
| fig:e1 f=0.25 catch rate | 0.13 @512 → 0 from N=2048 | **0.100 @512**, 0.033 @1024, 0.033 @2048, **0 @4096+** | `e1_summary.csv` | ≈ (0.10 not 0.13; 0 from 4096) |
| fig:e1 f=0.5 catch rate | 0.50 → 0.87 | **0.667 @512 → 0.900 @8192** | `e1_summary.csv` | ✗ value (higher; shape ✓) |
| fig:e1 all rates within 95% Wilson of model | all | **all 20 inside** | `e1_summary.csv` | ✓ |
| fig:e2 hybrid stops every 0.01≤f≤0.25 at key confirmation, before any byte | all | **120/120 at the tag, 0 bytes at Bob, Alice never completes** | `e2_summary.csv` | ✓ |
| fig:e2 none fails at Bob's GCM, Alice reports completed | "in all 150 runs" | **118/120 at f≤0.25 (160 across all f); Alice outcome=completed, exit 0, Bob fails** | `e2_outcomes.csv` | ✓ (count 118/120, not 150) |
| fig:e2 run counts | N=8192, hybrid+none, (none 150) | N=8192, both modes, **30/point**, 8 f-values | `e2_outcomes.csv` | resolves the TODO |

### Table "attackers" — "stopped by / stops at" (CONFIRMED, `e4_matrix.csv`)

Every row reproduced at N=8192: eve full → threshold (step 3); eve partial f=0.1 → tag
(4b, hybrid) / GCM (5, none); mallory own-key → trust (0); relay → signature (4b);
classical tamper ×6 → signature (4b); metadata tamper → GCM (5); replay → signature (4b);
downgrade → mode (0). New rows: relay with Bob's real key → passes 4b in sign, **tag** in
hybrid; policy downgrade (ℓ) → parameter mismatch at step 0; zero-chunks and size-mismatch
(malicious sender) → `MetadataError`.

## Changes vs previous run (3c2f5f9 → c8f8601)

The default protocol (ideal channel, reconciliation none) is unchanged in substance, so
E1–E4 values moved only within sampling noise. The real moves are in **E5/E6 (TCP_NODELAY
+ the new policy field + a more faithful qubit-byte measurement)** and the test suite.

| Quantity | Previous (3c2f5f9) | New (c8f8601) | Note |
|---|---|---|---|
| pytest | 536 passed, 57.4 s | **802 passed, 1 skipped, 122.8 s** | cascade + channel + resume tests added |
| **E6 CLI handshake_ms, Alice sign** | 53.4 ms | **11.96 ms** | TCP_NODELAY removes the ~40 ms Nagle stall |
| **E6 CLI handshake_ms, Alice hybrid** | 55.0 ms | **14.62 ms** | same |
| E6 CLI handshake_ms, Bob sign / hybrid | 11.3 / 13.0 ms | 14.18 / 16.28 ms | within a few ms |
| E6 in-process warm handshake_ms (none/sign/hybrid) | 0.41 / 2.63 / 3.45 | 0.37 / 1.78 / 2.53 | socketpair; Nagle N/A; ~noise |
| **E6 auth_overhead_bytes (none/sign/hybrid)** | 326 / 14656 / 17720 | **378 / 14708 / 17772** | +52 each: new `reconciliation` field in Π (+26 per hello) |
| E6 hello bytes (none / sign / hybrid A/B) | 162 / 2836 / 4432,4304 | 188 / 2862 / 4458,4330 | +26 per hello |
| E6 finished bytes | 4491 | 4491 | unchanged |
| **E6 qubit message** | 54 B/qubit (442 372 @8192) | **63 B/qubit (517 083 @8192)** | now measured via `encode_pulses` (dict framing) with random bits/bases; old used minimal all-\|0⟩/+ qubits — a measurement correction, not a protocol change |
| E6 primitives (sign / Toeplitz PA) | 842 / 6408 µs | 846 / 6490 µs | noise |
| E5 wall @N=8192 1MB hybrid | 3.08 s | 3.12 s | noise; `quantum_transmission` 2.52→2.60 s (channel-sim overhead) |
| E5 key_confirmation stage | included ~40 ms Nagle stall | ~3–11 ms | TCP_NODELAY |
| E5 modes (none/sign/hybrid wall) | 2.96 / 3.05 / 3.10 s | 3.09 / 3.10 / 3.10 s | within noise |
| E1 threshold rate f=0.5 @8192 | 0.933 | 0.900 | within Wilson (sampling) |
| E1 model-in-Wilson | 19/20 | **20/20** | sampling |
| E2 hybrid f≤0.25 → tag | 120/120 | 120/120 | unchanged |
| E2 none Alice-success f≤0.25 | 120/120 | 118/120 | 2 runs hit finite_key first (sampling) |
| **Design fact: "Nagle disabled"** | **WRONG** (no TCP_NODELAY) | **now correct** (`wire.no_delay` sets TCP_NODELAY) | fixed in `dcbcad1` |

The previous run's only WRONG design fact ("Nagle disabled") is **now correct** on
origin/main: `wire.no_delay` sets `TCP_NODELAY` (wire.py:121), used by `wire.accept`
(bob.py:121) and `wire.connect_with_retry` (alice.py:109).

## Figures

`e1_detection.pdf/png`, `e2_stopping_check.pdf/png` (new: hybrid/none stacked stopping-check
bars per f), `e3_keylen_vs_qber.pdf/png`, `e5_stage_bars.pdf/png`, `e6_byte_breakdown.pdf/png`.
All vector PDF + PNG.

## Raw data files

`e1_detection.csv`, `e1_summary.csv`, `e1_eve_sanity.csv`; `e2_outcomes.csv`,
`e2_summary.csv`; `e3_keylen_vs_qber.csv`, `e3_keylen_vs_N.csv`, `e3_qmax_sweep.csv`,
`e3_honest.csv`; `e4_matrix.csv`; `e5_transfer_time.csv` + `e5_summary_{qubits,sizes,modes}.csv`;
`e6_message_bytes.csv`, `e6_handshake_ms.csv`, `e6_qasm_sizes.csv`, `e6_primitives.csv`;
`pytest_full.log`; per-experiment logs `e1.log`…`e6.log`.
