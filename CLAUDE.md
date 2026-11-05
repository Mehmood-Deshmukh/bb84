# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

BB84 quantum key distribution (simulated with Qiskit Aer) used to derive an AES-256-GCM key for peer-to-peer file transfer. The package lives in `src/qkd` (src layout, installed with `pip install -e`):

- `core/`: protocol steps (`bb84_protocol.py`), simulated channel and Eve's attack (`quantum_channel.py`), AES-GCM/HKDF (`crypto_utils.py`), and `config.py`. **core must not import from services, usecases, or runner** (enforced by `tests/test_setup.py`).
- `services/`: wire framing (`wire.py`), transcript hashing over the wire (`transcript.py`), chunked file streaming (`file_stream.py`), reporters and JSON events (`reporting.py`), and the backend pieces: `node.py` (NodeService, the transfer orchestration), `transfer_store.py` (state machine + repository), `events.py` (EventBus), `discovery.py` (mDNS), `peer_client.py`, `process_runner.py`, `history.py`, `resume.py` (receiver's `.part` + sidecar for resumable transfers), `interrupted_store.py` (interrupted transfers on disk), and `api/` (FastAPI factory, routes, Pydantic models, error handlers).
- `usecases/`: `send_file` (Alice), `receive_file` (Bob), `eavesdrop_demo` (Eve), `mitm_demo` (Mallory, the man-in-the-middle demo), `handshake` (the signed hello/finished helpers they share), and `resume` (the sealed resume negotiation). These are workflows combining core and services.
- `runner/`: thin argparse CLIs `alice`, `bob`, `eve`, `node` (console scripts `qkd-alice`, `qkd-bob`, `qkd-eve`, `qkd-node`).
- `app/frontend/`: React 19 + Vite 8 + Tailwind v4 UI.

## Commands

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[backend,dev]"          # extras: backend, dev, experiments, hardware

pytest                                    # whole suite (654 tests, ~5 min; includes 100 MB transfers and a SIGKILL-and-resume run)
pytest tests/services/test_api.py -k cancel
pytest tests/invariants                   # real Alice/Bob runs on the Aer simulator

qkd-bob                                   # CLI receiver, port 65432, writes ./received/
qkd-alice FILE [--host H] [--port P]      # CLI sender
qkd-bob; qkd-eve; qkd-alice FILE --eve-mode   # eavesdropper demo (Eve on 65433)
qkd-bob --resume --transfer-id ID; qkd-alice FILE --resume --transfer-id ID   # resumable; rerun both after an interruption

qkd-node [--port 8000] [--reload]         # backend node; docs at /docs
cd app/frontend && npm install && npm run dev   # also: npm run lint, npm run build

python scripts/benchmark.py experiments/configs/qubit_scaling.yaml   # needs [experiments]
python scripts/plot_figures.py
```

Running two nodes on one machine works: give each its own `--port`, `QKD_NODE_NAME`, and working directory (history.json and received/ are cwd-relative). Point a second Vite dev server at it with `VITE_API_BASE_URL=http://127.0.0.1:8001`.

## Architecture notes

### Wire protocol (send_file / receive_file / eavesdrop_demo)
Single TCP connection. Every message is a 4-byte big-endian length prefix plus JSON or raw bytes, and goes through `qkd.services.wire` only. The message order is fixed and must change in lockstep in **usecases/send_file.py, receive_file.py, handshake.py, eavesdrop_demo.py, and mitm_demo.py** (Eve forwards the hellos, parses the next messages, then blindly forwards the rest, relaying 4c/4d and Bob's receipt when both `finished` carry the resume flag; Mallory's relay strategy runs Bob's side against Alice; the invariants tests share one ordered step list, `WIRE_STEPS` in **tests/invariants/support.py**, that drives a generic tamper/relay proxy; `WIRE_STEPS_RESUME` and `RESUME_FINAL_STEPS` add 4c, 4d and 6 for resume runs). Steps 0 to 4 go through a `TranscriptChannel`; "tracked" messages are hashed into the transcript, untracked ones are not:

0. Alice → `{"hello"}`; Bob → `{"hello"}` (tracked). Fields per mode (binary values base64): none `{v, mode}`; sign adds `id_pk`, `nonce` (32 B); hybrid adds Alice's `kem_pk` and Bob's `kem_ct`. Each side runs `auth.verifier.check(peer id_pk)` on arrival; Alice sends no qubits unless it passed. On a mode or version mismatch Bob still replies with `{v, mode}`, and both raise `PeerAuthError` (no fallback)
1. Alice → qubits as a list of QASM2 strings (untracked)
2. Bob → bases; Alice → matching indices
3. Alice → `{"sample_indices"}`; Bob → `{"sample_bits"}`; Alice → `{"qber"}`. Both abort if `qber >= QBER_THRESHOLD`
4. Alice → `{"salt"}`; qkd_key = SHA-256(salt + remaining sifted bits). Both sides then take T = transcript digest
4b. Sign and hybrid only (untracked): Bob → `{"finished"}` = ML-DSA over `qkd-finished-v1|bob|` + T; Alice verifies, then sends hers over `qkd-finished-v1|alice|` + T, and Bob verifies before reading any file data
4c/4d. **Resume only** (untracked): with `resume=ResumeOptions(...)`, auth sign/hybrid, and `"resume": 1` in *both* `finished` messages (unsigned flag; it can only switch resume off or stall it): Bob → `{"resume_request"}`, Alice → `{"resume_grant"}`. Both are AES-GCM under HKDF subkeys of the session key (`derive_resume_key`, never the file key), AAD = T (+ SHA-256 of the request for the grant). Bob says how many chunks he holds and a hash of them; Alice answers the offset, or 0 with a reason if her file changed. A failed tag is `PeerAuthError` before any file data. If a side has resume off the step is skipped and the wire is the plain one
5. Alice → file metadata, then one `tag(16B) + ciphertext` message per chunk (nonce = 8-byte base || 4-byte counter; AAD = SHA-256 of the canonical metadata JSON, so a changed metadata message fails on chunk 0). With resume the metadata also has `sha256` (whole file) and `resume_offset`, and chunks start at the offset (chunk `i` keeps nonce base || i; every session draws a fresh base nonce)
6. **Resume only**: Bob → `{"resume_done"}`, a sealed receipt sent after size and whole-file SHA-256 verified and the file was renamed into place; Alice reports success only after reading it

Without `resume` (the default, and what every pre-existing test uses) none of 4c, 4d, 6 or the metadata fields exist and the wire is byte-for-byte the one above.

The file key is `derive_session_key(qkd_key, kem_ss, T, mode)`; in none mode (`auth=None`) that is `derive_aes_key(qkd_key)`, the pre-handshake key. Peers from before the hello exchange cannot talk to current ones, even in none mode.

`services/wire.py`, `file_stream.py`, and `reporting.py` must not import qiskit (tested). Bob writes `received_<basename>` into `OUTPUT_DIR` and deletes the partial file on any tag failure. With resume he instead keeps `OUTPUT_DIR/.resume/<transfer_id>.part` (only AES-GCM-verified bytes) and `<id>.json` (atomic sidecar: file identity, chunks held, last base nonce, the sender's identity fingerprint), keyed by transfer id because the file name arrives after the negotiation; on a lost connection or bad tag he cuts the `.part` to the last verified chunk and raises `TransferInterrupted`; the final file appears by atomic rename after the hash check. A different authenticated peer identity than the sidecar's is refused before the `.part` is touched.

### Scope of the protocol
The channel is noiseless; there is no reconciliation and no decoy-state code (removed on purpose). If you add channel noise you must also add an interactive reconciliation step over the wire, or GCM decryption will fail. The QRNG is the Aer simulator (`_quantum_random_bits`), so importing `bb84_protocol` or `quantum_channel` pulls in qiskit.

### Reporters and events
Workflows never print. They call a `Reporter` (`section/info/success/warning/error` for humans; `stage/metrics/progress/listening/result` for structure). `ConsoleReporter` prints the human lines; `JsonEventReporter` (`--events json`) writes one JSON object per line: `{"type", "transfer_id", "stage", "payload", "ts"}`. The node and `scripts/benchmark.py` consume these, so **renaming a stage, metric key, or event type is an API change**: update `node.py` (`STAGE_STATUS`, `METRIC_FIELDS`), `api/models.py` (`TransferEvent.type`), and `app/frontend/src/api/types.js`. Log text is display-only; nothing parses it. Resume adds the result outcome `interrupted` and the metrics `resumed_from_bytes`, `bytes_total`, `resume_restart_reason` (mapped in `node.py` `METRIC_FIELDS`, its copy in `events.py`, `api/models.py` `Transfer`/`HistoryEntry`, and `types.js`); it adds no stage (negotiation runs inside `key_confirmation`). The handshake adds stages `authentication` (before step 0) and `key_confirmation` (before 4b, signed modes only) and the metrics `auth_mode`, `peer_fingerprint`, `peer_trust`, `handshake_ms`, `auth_overhead_bytes`; the node, API models, and frontend do not map them yet.

### Backend node
`create_app(service)` builds the FastAPI app around a `NodeService`; `default_service()` wires the real pieces (Zeroconf discovery, httpx peer client, subprocess launcher). Tests inject `StaticPeerDirectory`, fakes from `tests/services/fakes.py`, and drive it with `TestClient`.

- REST resources under `/api/v1`: `node`, `peers`, `transfers` (+ `/incoming` for node-to-node offers, `/{id}/events` SSE), `history`. Errors are always `{"error": {"code", "message"}}`; domain exceptions map to status codes in `api/errors.py`.
- Both nodes store a transfer with the **same id**. Sender: POST `/transfers` → POSTs `/transfers/incoming` to the peer. Receiver: PATCH accepted → launches bob with `--port 0`, waits for its `listening` event, then PATCHes the sender with `receiver_port` → sender launches alice.
- State machine in `transfer_store.py`. API-driven moves must be valid single transitions (else 409); event-driven moves use `path_to` and may step through intermediate statuses. Use `NodeService._fail` (not `_move(..., failed)`) for failures after async work, because the runner may already have finished the transfer.
- Runners are spawned as `sys.executable -m qkd.runner.<role> --events json`, inheriting the node's environment (so `QKD_*` overrides apply to them).
- Transfers live in memory; finished ones are appended to `HISTORY_FILE` (gitignored). Uploads go to a temp dir and are deleted when the transfer finishes.
- Peers are contacted on the port they advertise over mDNS (TXT record carries the node id).
- **Resumable transfers** (`QKD_RESUME=1`; the node then passes `--resume` to its runners). Status `interrupted` is non-terminal: from `transferring` when a runner reports outcome `interrupted`, or dies in a signed mode with verified data. Its edges live in `transfer_store.RESUME_TRANSITIONS`, not `TRANSITIONS`, because `test_transition_table` pins the latter; use `can_move`/`path_to`, not `can_transition`, for them. Exits: `pending` (sender `POST /transfers/{id}/resume`, which re-offers the same id with `resume_transfer_id`; the receiver's interrupted transfer goes back to `pending` and is accepted like any offer), `cancelled`, `failed`. `Transfer.attempt` counts tries. Interrupted transfers are persisted in `QKD_STATE_FILE` (`interrupted_store.py`) and restored at start; the sender's upload is moved next to it while interrupted; finishing, cancelling or declining deletes the receiver's `.resume` state. An interruption also writes a history entry. Node ids are random per start, so resume offers and restarted peers are matched by PQC identity fingerprint (ids only when a fingerprint is missing). The resume route has `include_in_schema=False` because `test_openapi_schema_and_docs` pins the exact documented paths.

### Frontend
`src/api/client.js` is the only module that calls the backend (JSDoc-typed against `src/api/types.js`); components get data through `src/hooks/` (polling + `useTransferEvents` for SSE). Base URL from `VITE_API_BASE_URL` (default `http://127.0.0.1:8000`). Components are in `src/components/`; `ProtocolView` renders the stage sequence, key funnel, QBER scale, and chunk progress from the transfer resource. Theme tokens (palette, type scale) are in `src/index.css` (`@theme`); fonts are bundled with `@fontsource`.

## Configuration
Every tunable is in `src/qkd/core/config.py` and can be overridden with `QKD_<NAME>` (read once at import; tests check this in subprocesses): `NUM_QUBITS`, `QBER_SAMPLE_FRACTION`, `QBER_THRESHOLD`, `FINAL_KEY_BITS`, `CHUNK_SIZE`, `ALICE_HOST`, `BOB_PORT`, `EVE_PORT`, `BUFFER_SIZE`, `OUTPUT_DIR`, `HISTORY_FILE`, `NODE_PORT` (falls back to `PORT`), `NODE_NAME`, `NODE_HOST`, `AUTH_MODE`, `IDENTITY_DIR`, `KNOWN_PEERS_FILE`, `TOFU`, `RESUME`, `RESUME_SYNC_CHUNKS`, `STATE_FILE`. `ProtocolParams` bundles the per-run protocol values and is what the use cases take.

## Git hygiene
`received/` (including `received/.resume/`), `history.json`, `node_state.json`, `node_state-uploads/`, `experiments/results/`, and `experiments/figures/` are run outputs and gitignored. `literature/` and `reports/` hold PDFs only.
