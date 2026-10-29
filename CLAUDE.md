# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

BB84 quantum key distribution (simulated with Qiskit Aer) used to derive an AES-256-GCM key for peer-to-peer file transfer. The package lives in `src/qkd` (src layout, installed with `pip install -e`):

- `core/`: protocol steps (`bb84_protocol.py`), simulated channel and Eve's attack (`quantum_channel.py`), AES-GCM/HKDF (`crypto_utils.py`), and `config.py`. **core must not import from services, usecases, or runner** (enforced by `tests/test_setup.py`).
- `services/`: wire framing (`wire.py`), chunked file streaming (`file_stream.py`), reporters and JSON events (`reporting.py`), and the backend pieces: `node.py` (NodeService, the transfer orchestration), `transfer_store.py` (state machine + repository), `events.py` (EventBus), `discovery.py` (mDNS), `peer_client.py`, `process_runner.py`, `history.py`, and `api/` (FastAPI factory, routes, Pydantic models, error handlers).
- `usecases/`: `send_file` (Alice), `receive_file` (Bob), `eavesdrop_demo` (Eve). These are workflows combining core and services.
- `runner/`: thin argparse CLIs `alice`, `bob`, `eve`, `node` (console scripts `qkd-alice`, `qkd-bob`, `qkd-eve`, `qkd-node`).
- `app/frontend/`: React 19 + Vite 8 + Tailwind v4 UI.

## Commands

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[backend,dev]"          # extras: backend, dev, experiments, hardware

pytest                                    # whole suite (~275 tests, ~35 s; includes 100 MB transfers)
pytest tests/services/test_api.py -k cancel
pytest tests/invariants                   # real Alice/Bob runs on the Aer simulator

qkd-bob                                   # CLI receiver, port 65432, writes ./received/
qkd-alice FILE [--host H] [--port P]      # CLI sender
qkd-bob; qkd-eve; qkd-alice FILE --eve-mode   # eavesdropper demo (Eve on 65433)

qkd-node [--port 8000] [--reload]         # backend node; docs at /docs
cd app/frontend && npm install && npm run dev   # also: npm run lint, npm run build

python scripts/benchmark.py experiments/configs/qubit_scaling.yaml   # needs [experiments]
python scripts/plot_figures.py
```

Running two nodes on one machine works: give each its own `--port`, `QKD_NODE_NAME`, and working directory (history.json and received/ are cwd-relative). Point a second Vite dev server at it with `VITE_API_BASE_URL=http://127.0.0.1:8001`.

## Architecture notes

### Wire protocol (send_file / receive_file / eavesdrop_demo)
Single TCP connection. Every message is a 4-byte big-endian length prefix plus JSON or raw bytes, and goes through `qkd.services.wire` only. The message order is fixed and must change in lockstep in **usecases/send_file.py, receive_file.py, and eavesdrop_demo.py** (Eve parses the first messages, then blindly forwards the rest; the invariants test has its own flipping proxy that also follows the order):

1. Alice → qubits as a list of QASM2 strings
2. Bob → bases; Alice → matching indices
3. Alice → `{"sample_indices"}`; Bob → `{"sample_bits"}`; Alice → `{"qber"}`. Both abort if `qber >= QBER_THRESHOLD`
4. Alice → `{"salt"}`; key = SHA-256(salt + remaining sifted bits)
5. Alice → file metadata, then one `tag(16B) + ciphertext` message per chunk (nonce = 8-byte base || 4-byte counter)

`services/wire.py`, `file_stream.py`, and `reporting.py` must not import qiskit (tested). Bob writes `received_<basename>` into `OUTPUT_DIR` and deletes the partial file on any tag failure.

### Scope of the protocol
The channel is noiseless; there is no reconciliation and no decoy-state code (removed on purpose). If you add channel noise you must also add an interactive reconciliation step over the wire, or GCM decryption will fail. The QRNG is the Aer simulator (`_quantum_random_bits`), so importing `bb84_protocol` or `quantum_channel` pulls in qiskit.

### Reporters and events
Workflows never print. They call a `Reporter` (`section/info/success/warning/error` for humans; `stage/metrics/progress/listening/result` for structure). `ConsoleReporter` prints the human lines; `JsonEventReporter` (`--events json`) writes one JSON object per line: `{"type", "transfer_id", "stage", "payload", "ts"}`. The node and `scripts/benchmark.py` consume these, so **renaming a stage, metric key, or event type is an API change**: update `node.py` (`STAGE_STATUS`, `METRIC_FIELDS`), `api/models.py` (`TransferEvent.type`), and `app/frontend/src/api/types.js`. Log text is display-only; nothing parses it.

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
Every tunable is in `src/qkd/core/config.py` and can be overridden with `QKD_<NAME>` (read once at import; tests check this in subprocesses): `NUM_QUBITS`, `QBER_SAMPLE_FRACTION`, `QBER_THRESHOLD`, `FINAL_KEY_BITS`, `CHUNK_SIZE`, `ALICE_HOST`, `BOB_PORT`, `EVE_PORT`, `BUFFER_SIZE`, `OUTPUT_DIR`, `HISTORY_FILE`, `NODE_PORT` (falls back to `PORT`), `NODE_NAME`, `NODE_HOST`, `AUTH_MODE`, `IDENTITY_DIR`, `KNOWN_PEERS_FILE`, `TOFU`. `ProtocolParams` bundles the per-run protocol values and is what the use cases take.

## Git hygiene
`received/`, `history.json`, `experiments/results/`, and `experiments/figures/` are run outputs and gitignored. `literature/` and `reports/` hold PDFs only.
