# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

BB84 quantum key distribution (simulated with Qiskit Aer) used to derive an AES-256-GCM key for peer-to-peer file transfer. The package lives in `src/qkd` (src layout, installed with `pip install -e`):

- `core/`: protocol steps (`bb84_protocol.py`), simulated channel and Eve's attack (`quantum_channel.py`), AES-GCM/HKDF and the session key schedule (`crypto_utils.py`), the finite-key bound (`finite_key.py`), and `config.py`. **core must not import from services, usecases, or runner** (enforced by `tests/test_setup.py`).
- `services/`: wire framing (`wire.py`), transcript hashing over the wire (`transcript.py`), chunked file streaming (`file_stream.py`), reporters and JSON events (`reporting.py`), and the backend pieces: `node.py` (NodeService, the transfer orchestration), `transfer_store.py` (state machine + repository), `events.py` (EventBus), `discovery.py` (mDNS), `peer_client.py`, `process_runner.py`, `history.py`, and `api/` (FastAPI factory, routes, Pydantic models, error handlers).
- `usecases/`: `send_file` (Alice), `receive_file` (Bob), `eavesdrop_demo` (Eve), `mitm_demo` (Mallory, the man-in-the-middle demo), and `handshake` (the signed hello/finished helpers they share). These are workflows combining core and services.
- `runner/`: thin argparse CLIs `alice`, `bob`, `eve`, `node` (console scripts `qkd-alice`, `qkd-bob`, `qkd-eve`, `qkd-node`).
- `app/frontend/`: React 19 + Vite 8 + Tailwind v4 UI.

## Commands

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[backend,dev]"          # extras: backend, dev, experiments, hardware

pytest                                    # whole suite (557 tests, ~45 s; includes 100 MB transfers)
pytest tests/services/test_api.py -k cancel
pytest tests/invariants                   # real Alice/Bob runs on the Aer simulator

qkd-bob                                   # CLI receiver, port 65432, writes ./received/
qkd-alice FILE [--host H] [--port P]      # CLI sender
qkd-bob; qkd-eve [--fraction F]; qkd-alice FILE --eve-mode   # eavesdropper demo (Eve on 65433)

qkd-node [--port 8000] [--reload]         # backend node; docs at /docs
cd app/frontend && npm install && npm run dev   # also: npm run lint, npm run build

python scripts/benchmark.py experiments/configs/e4_overhead.yaml     # needs [experiments]; --repeats 2 for a quick check
python scripts/plot_figures.py                                        # PNG + PDF into experiments/figures/
```

Running two nodes on one machine works: give each its own `--port`, `QKD_NODE_NAME`, and working directory (history.json and received/ are cwd-relative). Point a second Vite dev server at it with `VITE_API_BASE_URL=http://127.0.0.1:8001`.

## Architecture notes

### Wire protocol (send_file / receive_file / eavesdrop_demo)
Single TCP connection. Every message is a 4-byte big-endian length prefix plus JSON or raw bytes, and goes through `qkd.services.wire` only. Protocol sockets must come from `wire.connect_with_retry` or `wire.accept`, which set `TCP_NODELAY`; with Nagle on, two messages in a row from one side (Alice's qber then salt) stall about 40 ms on the peer's delayed ACK. The message order is fixed and must change in lockstep in **usecases/send_file.py, receive_file.py, handshake.py, eavesdrop_demo.py, and mitm_demo.py** (Eve forwards the hellos, parses the next messages, then blindly forwards the rest; Mallory's relay strategy runs Bob's side against Alice; the invariants tests share one ordered step list, `WIRE_STEPS` in **tests/invariants/support.py**, that drives a generic tamper/relay proxy). Steps 0 to 4 go through a `TranscriptChannel`; "tracked" messages are hashed into the transcript, untracked ones are not:

0. Alice → `{"hello"}`; Bob → `{"hello"}` (tracked). Protocol version `v` is 2. Fields per mode (binary values base64): none `{v, mode, params}`; sign adds `id_pk`, `nonce` (32 B); hybrid adds Alice's `kem_pk` and Bob's `kem_ct`. `params` is `ProtocolParams.security_policy()` (`final_key_bits`, `eps_sec`, `eps_cor`, `qber_threshold`, `enforce_finite_key`) and must equal the receiver's. Each side runs `auth.verifier.check(peer id_pk)` on arrival; Alice sends no qubits unless it passed. On a version, mode, or parameter mismatch Bob still replies with `{v, mode, params}`, and both raise `PeerAuthError` (no fallback)
1. Alice → qubits as a list of QASM2 strings (untracked)
2. Bob → bases; Alice → matching indices
3. Alice → `{"sample_indices"}`; Bob → `{"sample_bits"}`; Alice → `{"qber"}`. Both abort if `qber >= QBER_THRESHOLD`, then both compute the finite-key secure length (`core/finite_key.py`, from kept bits, distinct sample size, and the announced QBER) and abort, without sending anything, if it is below `final_key_bits` (unless `enforce_finite_key` is off)
4. Alice → `{"salt"}`, a fresh Toeplitz seed of n + m - 1 bits (hex); qkd_key = Toeplitz hash of the kept sifted bits down to `final_key_bits`. Both sides then take T = transcript digest and the session key K
4b. Sign and hybrid only (untracked): Bob → `{"finished", "confirm"}`: `confirm` = HMAC-SHA256 under `key_schedule(K).confirm` over `qkd-confirm-v1|bob|` + T, `finished` = ML-DSA over `qkd-finished-v1|bob|` + T + tag. Alice checks the signature (`PeerAuthError`), then the tag (`KeyConfirmationError`, reported as `aborted_qber`), then sends hers with role `alice`; Bob checks both before reading any file data
5. Alice → metadata as `tag(16B) + ciphertext` under `key_schedule(K).metadata` (zero nonce, AAD `qkd-file-meta-v1`), then one `tag(16B) + ciphertext` message per chunk under `key_schedule(K).file` (nonce = 8-byte base || 4-byte counter; AAD = SHA-256 of the canonical metadata JSON). There is always at least one chunk (an empty file is one empty chunk), and Bob rejects metadata whose `num_chunks` does not match `total_size`/`chunk_size` (`MetadataError`)

The session key K is `derive_session_key(qkd_key, kem_ss, T, mode)`; in none mode (`auth=None`) that is `derive_aes_key(qkd_key)`. `crypto_utils.key_schedule(K)` expands it with HKDF-Expand into independent `file`, `metadata`, and `confirm` subkeys. Peers running protocol version 1 cannot talk to current ones, even in none mode.

`services/wire.py`, `file_stream.py`, and `reporting.py` must not import qiskit (tested). Bob writes `received_<basename>` into `OUTPUT_DIR` and deletes the partial file on any tag failure.

### Scope of the protocol
The channel is noiseless; there is no reconciliation and no decoy-state code (removed on purpose). If you add channel noise you must also add an interactive reconciliation step over the wire (and charge its leakage in `finite_key.py`), or key confirmation will fail. The default N = 8192 is the smallest power of two for which the finite-key bound gives 256 secure bits with the default eps values; at the old 128 it gives 0. Tests that study authentication or tampering rather than key length run small N with `enforce_finite_key=False`. `measure_qubits` submits all one-qubit circuits as one Aer job without transpiling (they use only native gates); do not go back to one job per qubit (about 250x slower). The QRNG is the Aer simulator (`_quantum_random_bits`), so importing `bb84_protocol` or `quantum_channel` pulls in qiskit.

### Reporters and events
Workflows never print. They call a `Reporter` (`section/info/success/warning/error` for humans; `stage/metrics/progress/listening/result` for structure). `ConsoleReporter` prints the human lines; `JsonEventReporter` (`--events json`) writes one JSON object per line: `{"type", "transfer_id", "stage", "payload", "ts"}`. The node and `scripts/benchmark.py` consume these, so **renaming a stage, metric key, or event type is an API change**: update `node.py` (`STAGE_STATUS`, `METRIC_FIELDS`), `api/models.py` (`TransferEvent.type`), and `app/frontend/src/api/types.js`. Log text is display-only; nothing parses it. The handshake adds stages `authentication` (before step 0) and `key_confirmation` (before 4b, signed modes only) and the metrics `auth_mode`, `peer_fingerprint`, `peer_trust`, `handshake_ms`, `auth_overhead_bytes`; the key exchange adds `secure_key_bits` (finite-key bound). The node, API models, and frontend do not map these yet. Abort messages come from `KeyExchangeResult.abort_reason`.

### Backend node
`create_app(service)` builds the FastAPI app around a `NodeService`; `default_service()` wires the real pieces (Zeroconf discovery, httpx peer client, subprocess launcher). Tests inject `StaticPeerDirectory`, fakes from `tests/services/fakes.py`, and drive it with `TestClient`.

- REST resources under `/api/v1`: `node`, `peers`, `transfers` (+ `/incoming` for node-to-node offers, `/{id}/events` SSE), `history`. Errors are always `{"error": {"code", "message"}}`; domain exceptions map to status codes in `api/errors.py`.
- Both nodes store a transfer with the **same id**. Sender: POST `/transfers` → POSTs `/transfers/incoming` to the peer. Receiver: PATCH accepted → launches bob with `--port 0`, waits for its `listening` event, then PATCHes the sender with `receiver_port` → sender launches alice.
- State machine in `transfer_store.py`. API-driven moves must be valid single transitions (else 409); event-driven moves use `path_to` and may step through intermediate statuses. Use `NodeService._fail` (not `_move(..., failed)`) for failures after async work, because the runner may already have finished the transfer.
- Runners are spawned as `sys.executable -m qkd.runner.<role> --events json`, inheriting the node's environment (so `QKD_*` overrides apply to them).
- Transfers live in memory; finished ones are appended to `HISTORY_FILE` (gitignored). Uploads go to a temp dir and are deleted when the transfer finishes.
- Peers are contacted on the port they advertise over mDNS (TXT record carries the node id).

### Frontend
`src/api/client.js` is the only module that calls the backend (JSDoc-typed against `src/api/types.js`); components get data through `src/hooks/` (polling + `useTransferEvents` for SSE). Base URL from `VITE_API_BASE_URL` (default `http://127.0.0.1:8000`). Components are in `src/components/`; `ProtocolView` renders the stage sequence, key funnel, QBER scale, and chunk progress from the transfer resource. Theme tokens (palette, type scale) are in `src/index.css` (`@theme`); fonts are bundled with `@fontsource`.

## Configuration
Every tunable is in `src/qkd/core/config.py` and can be overridden with `QKD_<NAME>` (read once at import; tests check this in subprocesses): `NUM_QUBITS`, `QBER_SAMPLE_FRACTION`, `QBER_THRESHOLD`, `FINAL_KEY_BITS`, `EPS_SEC`, `EPS_COR`, `ENFORCE_FINITE_KEY`, `CHUNK_SIZE`, `ALICE_HOST`, `BOB_PORT`, `EVE_PORT`, `BUFFER_SIZE`, `OUTPUT_DIR`, `HISTORY_FILE`, `NODE_PORT` (falls back to `PORT`), `NODE_NAME`, `NODE_HOST`, `AUTH_MODE`, `IDENTITY_DIR`, `KNOWN_PEERS_FILE`, `TOFU`. `ProtocolParams` bundles the per-run protocol values and is what the use cases take.

## Experiments
`scripts/benchmark.py` runs a grid from `experiments/configs/e*.yaml` (E1 detection, E2 where runs stop, E3 secure length, E4 overhead; E5 wire bytes is drawn from E4) with real runner processes. Timing comes from the runners' event timestamps, not process wall time; `sim_ms` (Alice and Bob) separates simulator cost, and `protocol_minus_sim_s` is the protocol's own time. Each run is labelled by `stopped_at` (`classify`). Outputs per experiment: `<name>.csv` (per run), `<name>_summary.csv` (median/IQR, outcome rates with Wilson 95% intervals), `<name>.meta.json` (git commit, versions, CPU). `scripts/plot_figures.py` reads only the summaries, per `experiments/figures.yaml`; its colors are a validated categorical order and an ordinal blue ramp, keep them.

## Git hygiene
`received/`, `history.json`, `experiments/results/`, and `experiments/figures/` are run outputs and gitignored. `literature/` and `reports/` hold PDFs only.
