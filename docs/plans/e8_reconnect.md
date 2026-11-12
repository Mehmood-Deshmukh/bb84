# Plan: E8, re-connection overhead after an interruption

Question: when a transfer is interrupted halfway, what does it cost to get going again as a function of
the raw qubit count N, for **resume** (continue from Bob's verified chunks) versus **restart** (send the
whole file again)? A resume is a new session (hello, full BB84 at N, key confirmation 4b, sealed
negotiation 4c/4d, the missing chunks, receipt 6); no key is reused, so the BB84 cost is paid on every
reconnect.

## 1. Findings (what exists, what is added)

Already recorded by `scripts/benchmark.py`: per-stage durations for Alice and Bob (`alice_<stage>_s`,
including `key_confirmation` and `file_transfer`), `protocol_s`, `end_to_end_s`, `sim_s`,
`protocol_minus_sim_s`, and the metrics `channel_bytes`, `qubit_bytes`, `auth_overhead_bytes`,
`file_wire_bytes`, `bb84_classical_bytes`, `detected`, ... all emitted by the runners.
The runners already emit `resumed_from_bytes` and `bytes_total` (resume only), and `progress` events
(`chunks_done`, `num_chunks`, `bytes_done`), one per whole percent.

Not available: a way to interrupt a run, a second session, and any of the columns below. The resume
negotiation runs inside the `key_confirmation` stage and has no stage or metric of its own (adding one
would be an API change), so it is **not separable from events**; its cost is estimated by comparing
`alice_key_confirmation_s` of resume against restart.

Added (nothing in protocol, runners or resume code changes):

- grid parameters `strategy` (`resume` | `restart`) and `kill_fraction` in `SPECIAL`/`DEFAULTS`
- `run_interrupted` (session 1 to the kill, session 2 measured), helpers `kill_chunk`, `stage_ts`,
  `last_progress_bytes`, `kept_bytes`, `reconnect_columns`; `run_once` dispatches to it when `strategy` is set,
  and its row building moved unchanged into `build_row`
- columns `RECONNECT_COLUMNS`, all in `NUMERIC_SUMMARY` except `s1_bob_outcome`

## 2. Definitions (second session)

| Column | Meaning |
|---|---|
| `reconnect_s` | Alice's `authentication` stage to her `file_transfer` stage: hello + BB84 + key confirmation + (resume) 4c/4d. Event timestamps |
| `reconnect_minus_sim_s` | `reconnect_s` minus `sim_s` (Alice + Bob simulator time) |
| `completion_s` | Alice's `authentication` stage to her result: Bob's receipt (resume) or end of streaming (restart has no receipt) |
| `resumed_from_bytes`, `bytes_total` | existing metrics; for restart 0 and the payload size |
| `resent_bytes` | `file_wire_bytes` of the session (metadata + chunks, length prefixes included) |
| `lost_bytes` | Alice's last progress `bytes_done` before the kill minus the bytes in Bob's sidecar (`kept_bytes`), floored at 0. Includes chunks still in flight at the kill |
| `reconnect_bytes` | `channel_bytes`: everything through the transcript channel before the first chunk (qubits, BB84, hello/finished, 4c/4d) |
| `sent_before_kill_bytes`, `kept_bytes`, `s1_bob_outcome` | the inputs of `lost_bytes` and a check that session 1 ended `interrupted` |

## 3. Harness design

Session 1 (both strategies): Bob and Alice with `--resume --transfer-id <e8-random>`. Alice's progress events
are watched; at `ceil(kill_fraction * num_chunks)` chunks sent she is SIGKILLed (as in
`tests/invariants/test_resume_kill.py`) and Bob must exit with outcome `interrupted`; otherwise the row is
`stopped_at = other` with the reason in `bob_error` (reported, not dropped).
Session 2: resume = same id and output dir with `--resume`; restart = no `--resume`, fresh id, clean output dir.
Intact = SHA-256 of the received file equals the source. Each run has its own work dir (removed at the end),
own ports and the shared per-experiment identities; ordering, run folders and `latest` rules are unchanged.
Not allowed with strategy: mode `none`, Eve, latency proxy.

Grid (`experiments/configs/e8_reconnect.yaml`): N in {1024..16384} x mode {sign, hybrid} x strategy
{resume, restart}, 24 repeats = 480 runs, 8 MiB payload (128 chunks), kill_fraction 0.5,
`QKD_ENFORCE_FINITE_KEY=0` (not provably secure below N=8192; fine for timing).
Figures: `e8_reconnect` (reconnect_s, resume only, per mode) and `e8_completion` (completion_s, per mode and
strategy). `plot_figures.py` gained `where` and list-valued `series`; colours untouched.

## 4. Files touched

`scripts/benchmark.py`, `scripts/plot_figures.py`, `experiments/configs/e8_reconnect.yaml`,
`experiments/figures.yaml`, `tests/scripts/test_benchmark.py`, this plan.

## 5. Verification

Unit tests in `tests/scripts/test_benchmark.py`; whole pytest suite; smoke run with `--repeats 2`
(results in the final report). The full 480-run experiment is launched by hand.
