# 1C — Existing data, and 1D — Measurement plan (paper-eval v2)

## 1C. Existing scripts and data: what can be reused

**Searched:** `git branch -a`, `git log --all -- experiments/ scripts/paper/`,
`git ls-tree -r` on all branches, the on-disk `experiments/results/`, and `~/bench_data*`.

**Findings — nothing can be reused for the paper's fig:e1 / fig:e2.**

- The only paper harnesses in version control are the ones on `exp/paper-eval`
  (`e1_e2_eve.py`, `e2_topup.py`, `e3_threshold.py`, `e4_matrix.py`, `e5_transfer_time.py`,
  `e6_overhead.py`, `e7_cli_handshake.py`, `plot.py`, `common.py`). No raw data is in git
  (`experiments/results/` is gitignored).
- `exp/paper-eval:scripts/paper/e1_e2_eve.py` uses **full** intercept-resend
  (`PERR = 0.25`, every qubit, i.e. f = 1.0) at **N ∈ {32,64,128,256,512}**. It has **no
  partial-fraction-f Eve** and does not go to N=8192.
- That harness ran on the **old protocol** (commit `7afd1a9`/`d346ba4`): default
  N=128, **SHA-256 privacy amplification (not Toeplitz), no finite-key gate, no key
  confirmation tag, no encrypted metadata, PROTOCOL_VERSION=1 (no policy Π in the
  hello)**. Its on-disk results in `experiments/results/paper/` are therefore **not valid
  for the current code** and cannot be reused.
- `~/bench_data`, `~/bench_data_final` contain `review_key.csv` / `review_blind.csv` /
  `summary.csv` — an unrelated project, not QKD. `origin/decoy_state` has an old `eve.py`
  (decoy-state code, removed on purpose per CLAUDE.md). Neither is relevant.
- The paper's cited fig:e1/e2 numbers (e.g. "0.13 at N=512", "150 none-mode runs") have
  **no committed script or data** I can find, and fig:e2 is marked `TODO` in the tex. I
  treat them as provisional and will regenerate everything on the current code.

**Consequence:** every experiment below runs fresh on commit `3c2f5f9`. A **partial-f
Eve** must be written (adapting `eve_intercept_resend`, which does all qubits): attack a
random f·N subset of the qubits — measure+re-prepare those, pass the rest through —
without editing `src/`. I will reuse the structure of `exp/paper-eval`'s in-process
harness (`common.py`, the socketpair + `privacy_amplification`-recorder trick for Hamming
distance) and `e5`/`e7`'s CLI subprocess harness.

## Timing anchors (measured now, commit 3c2f5f9, this machine)

| Quantity | Measured |
|---|---|
| QRNG `generate_random_bits`+`generate_random_bases` at N=8192 (2 batches) | 0.147 s |
| `prepare_qubits(8192)` | 0.230 s |
| `measure_qubits(8192)` — **single Aer job** | **2.195 s** |
| full `eve_intercept_resend(8192)` (measure all + re-prepare) | 2.458 s |
| **in-process honest hybrid, N=8192, 1 MB (Alice+Bob, socketpair)** | **2.42 s/run** |

Measurement dominates and is ~linear in N (≈0.27 ms/qubit): per-run in-process honest
time ≈ N/8192 × 2.4 s (≈0.15/0.30/0.60/1.2/2.4 s at N=512/1024/2048/4096/8192). A partial-f
Eve adds ≈ f × 2.4 s at N=8192 (she measures+re-prepares f·N qubits). CLI runs add
~0.8–1.5 s of process start-up + cold PQC per run on top of the in-process time.

## 1D. Plan (prefer existing harnesses; outputs → `experiments/results/paper-v2/`)

Scripts go in `scripts/paper/` and are the only things committed. In-process harnesses
amortise one Aer warm-up and give exact in-run facts (stopping check, Hamming distance);
CLI harnesses (E5, E6 handshake) exercise the real runner path.

### E1 — Detection vs N and f  → `e1_detection.py`, `e1_detection.csv`, `e1_summary.csv`
- **Method:** in-process, partial-f Eve between Alice and Bob; full protocol
  (finite-key gate ON). Per run record: sifted n, sample k, Q, computed ℓ
  (`secure_key_length`), and **which check stopped it** — one of
  {`threshold`, `finite_key`, `tag` (τ), `gcm` (chunk 0), `none`} — detected in-process,
  since all three aborts share the `aborted_qber` outcome name (see implementation.md).
- **Params:** N ∈ {512,1024,2048,4096,8192}, f ∈ {0.1, 0.25, 0.5, 1.0}, 30 runs/point.
  Mode hybrid (so τ is available). Compare each check's rate to the §6.4 binomial model
  with 95 % Wilson intervals.
- **Runs / time:** 5×4×30 = 600 runs. Est. per-run ≈ (N/8192)·2.4·(1+f); dominated by
  N=8192 (120 runs × ~3.5 s ≈ 7 min) + N=4096 (~3.5 min) + smaller. **≈ 15–20 min.**
- Note: at N=512–2048 the finite-key bound gives ℓ=0, so with the gate ON **every** run
  there aborts at `finite_key` before PA. That is itself a finding (the bound, not the
  threshold, is the active gate at small N); the threshold/τ/gcm rates are only observable
  at N=8192 (and partly N=4096). I will record all checks at all N and report this
  explicitly rather than forcing the gate off.

### E2 — All checks at N=8192 (resolves the fig:e2 TODO)  → `e2_full.py`, `e2_outcomes.csv`
- **Method:** in-process, partial-f Eve, N=8192, modes **hybrid and none**, 30 runs each.
  Per run: stopping check + stage; Alice's outcome; Bob's outcome; file bytes written at
  Bob; **Hamming distance between the kept bits** (recorded in-process via the
  `privacy_amplification` monkeypatch from `exp/paper-eval`, no `src/` edit); whether any
  file byte left Alice before the abort.
- **Params:** f ∈ {0.01, 0.05, 0.1, 0.25, 0.3, 0.35, 0.4, 0.5}. 8×2×30 = **480 runs** at
  N=8192.
- **Time:** per run ≈ 2.5 + f·2.4 s (mean f≈0.25 ⇒ ~3.1 s). **≈ 25 min. ⚠ FLAG: longest
  single experiment, near the 30-min line.** Mitigation: run in the background; or drop to
  20 runs/point (≈17 min) if you prefer. I will keep 30 unless told otherwise.

### E3 — Threshold vs finite-key bound  → `e3_keylen.py` + `e3_*.csv`
- **(a)** Tabulate ℓ(n,k,Q) from `secure_key_length` for Q ∈ [0, 0.12] (step 0.005) at
  N=8192 and N=4096, and ℓ(Q=0) for N ∈ {512,…,16384}. **No runs — instant.**
- **(b)** N=8192, sweep Q_max ∈ {0.05,0.08,0.11,0.15} × f ∈ {0.25,0.35,0.5}, record the
  stopping check per run. Proposed **10 runs/cell** (the brief gives no count): 4×3×10 =
  120 runs × ~3.4 s ≈ **7 min**. (Q_max is a per-run `ProtocolParams.qber_threshold`
  override; it is bound in Π, so both peers use the same value.)
- **(c)** 20 honest runs (no Eve) at N=8192: honest abort rate + Q distribution. 20 × 2.4 s
  ≈ **1 min.**
- **Total ≈ 8–9 min.**

### E4 — Attack matrix on current code  → `e4_matrix.py`, `e4_matrix.csv`
- **N = 8192** (the smallest power of two with ℓ ≥ 256; stated in E3a). Each cell 3 runs.
  Columns: outcome name, stopping check, stage, which side detected, bytes at Bob, whether
  the attacker obtained plaintext, whether Alice reported success.
- **Rows:** Eve full (f=1); Mallory own-key; Mallory relay; six classical tampers (bases,
  matching, sample_indices, sample_bits, Q, salt) with Q_max > 1; metadata tamper; replay;
  mode downgrade — **plus new rows:** partial Eve f=0.1; **policy downgrade** (tamper Π in
  the hello: smaller ℓ or looser ε); **chunk-count tamper (zero chunks)**; **size
  mismatch**; **relay control with Bob's real key in BOTH sign and hybrid** (paper says
  hybrid then fails at the tag). Adapt `exp/paper-eval/e4_matrix.py` + `tamper` proxy from
  `tests/invariants/support.py`.
- **Time:** ~18 rows, most abort early; a few do full BB84 at 8192 (~2.5–5 s). ~3 runs each
  ≈ **6–9 min.**

### E5 — Transfer time over the real CLI  → `e5_transfer.py` + `e5_*.csv` (adapt e5)
- qkd-alice/qkd-bob, `--events json`, localhost TCP, 5 runs each, median + IQR, stage
  breakdown from both sides' event timestamps:
  - N ∈ {512,1024,2048,4096,8192} at 1 MB hybrid (25 runs);
  - sizes {1 KB, 1 MB, 10 MB, 100 MB} at N=8192 hybrid (20 runs);
  - modes {none,sign,hybrid} at N=8192, 1 MB (15 runs).
- **Time:** CLI run ≈ in-process + ~1 s start-up. The 100 MB × 5 and 8192 × many are the
  heavy parts. **≈ 10–12 min.** Report where time goes now that measurement is one job
  (expect the single 2.2 s measurement job to dominate small files, and GCM/IO to
  dominate at 100 MB).

### E6 — Handshake overhead + microbenchmarks  → `e6_overhead.py` + `e6_*.csv` (adapt e6/e7)
- Framed bytes per hello/finished per mode on the wire + the `auth_overhead_bytes` metric
  (preview from implementation.md: none 324, sign 14654, hybrid 17718); QASM payload per N
  (54 B/qubit; 8192→442372 B). **Instant.**
- `handshake_ms` over the real CLI (10 runs/mode, cold process, both sides) + in-process
  warm. CLI runs at a **small N** (e.g. N=512) to isolate the handshake from the 2.2 s
  measurement; 30 CLI runs ≈ **3–4 min.**
- Microbenchmarks (≥1000 calls, median): `sig_keygen`, `sign`, `verify`, `kem_keygen`,
  `kem_encaps`, `kem_decaps`, HMAC `confirmation_tag`, `derive_session_key`, `key_schedule`
  (subkey derivation), one transcript update, **Toeplitz `privacy_amplification` at
  N=8192**, and **`secure_key_length`**. All fast. **≈ 2–3 min.**
- **Total ≈ 6–8 min.**

## Totals and flags

| Exp | Runs | Est. time |
|---|---|---|
| E1 | 600 (in-proc) | 15–20 min |
| E2 | 480 (in-proc) | **~25 min ⚠** |
| E3 | 140 (+ instant tables) | 8–9 min |
| E4 | ~54 (in-proc) | 6–9 min |
| E5 | 60 (CLI) | 10–12 min |
| E6 | 30 CLI + micro | 6–8 min |
| **Total** | | **~70–85 min** |

- **Only E2 approaches 30 min.** Nothing else is close. I'd run E1–E4 (in-process) first,
  then E5/E6 (CLI, needs an idle machine), recording load averages, as in v1.
- **One code gap to flag:** the partial-f Eve does not exist in `src/`; I will implement it
  only in `scripts/paper/` (no `src/` edit), matching the §6.4 model (attack a random f·N
  subset). I'll sanity-check it at f=1.0 against the existing full `eve_intercept_resend`
  (same QBER distribution) before trusting E1/E2.
- **Reporting caveat:** because QBER-threshold, finite-key, and key-confirmation aborts all
  surface as the single `aborted_qber` outcome, every harness records the stopping check
  in-process (or from the abort-reason text), not from the outcome name.
