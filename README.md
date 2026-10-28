# BB84 QKD file transfer

Two machines agree on a key with the BB84 protocol, then use it to send a file encrypted with AES-256-GCM.
The quantum channel is simulated with Qiskit Aer: each qubit travels over TCP as a one-qubit QASM circuit,
and the receiver measures it on the simulator. A small backend node finds peers on the LAN over mDNS and
exposes a REST API, and a React UI shows each run of the protocol.

What it does not do:

- No quantum hardware in the default flow. `scripts/ibm_hardware_run.py` can run a single circuit on IBM
  Quantum, but it is separate from the transfer.
- The channel is noiseless. There is no information reconciliation and no decoy-state analysis. Both were
  removed because the live flow never called them. Any QBER above zero comes from an eavesdropper.
- The random bits come from measuring `H|0⟩` on the Aer simulator, which is a pseudo-random source.
- The classical channel is not authenticated, and the node API has no authentication or TLS. BB84 assumes an
  authenticated classical channel, so this is a teaching and demo tool, not a secure transport.
- The key is short. With the default 128 qubits, about 64 bits survive sifting and about 55 remain after the
  QBER sample. SHA-256 stretches them to 256 bits, so the AES key carries at most about 55 bits of entropy.

## Install

Python 3.11 or later. Node.js 20.19 or 22.12 and later for the UI (Vite 8).

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .                        # core: qiskit, qiskit-aer, cryptography
pip install -e ".[backend,dev]"         # backend node and tests
```

Optional dependency groups:

| Group | Packages | Needed for |
|---|---|---|
| `backend` | fastapi, uvicorn, zeroconf, python-multipart, httpx | `qkd-node` |
| `dev` | pytest, httpx | the test suite |
| `experiments` | pyyaml, matplotlib | `scripts/benchmark.py`, `scripts/plot_figures.py` |
| `hardware` | qiskit-ibm-runtime | `scripts/ibm_hardware_run.py` |

## Send a file from the command line

```bash
qkd-bob                       # terminal 1: listens on port 65432
qkd-alice notes.txt           # terminal 2: sends to localhost:65432
```

Bob writes the file to `received/received_notes.txt` (change it with `--output-dir` or `QKD_OUTPUT_DIR`).
Use `qkd-alice FILE --host HOST --port PORT` for another machine. Both commands exit with code 1 when the key
exchange aborts.

### Eavesdropper demo

```bash
qkd-bob                           # terminal 1
qkd-eve                           # terminal 2: connects to Bob, listens on 65433
qkd-alice notes.txt --eve-mode    # terminal 3: connects to Eve instead of Bob
```

Eve measures every qubit in a random basis and re-sends what she measured. That puts errors into about 25% of
the sifted bits. Alice and Bob compare a sample of about 9 sifted bits; one wrong bit is already above the 11%
threshold, so both sides abort. Eve escapes the sample in about 7.5% of runs (0.75^9). The keys still differ in
those runs, so Bob's first AES-GCM tag check fails and no plaintext is written.

## Run the backend node and the UI

```bash
qkd-node                          # REST API on :8000, advertises itself over mDNS
cd app/frontend && npm install && npm run dev
```

Open the URL Vite prints. The UI talks to `http://127.0.0.1:8000` unless you set `VITE_API_BASE_URL` (see
`app/frontend/.env.example`). Run `qkd-node` on a second machine on the same network, and each node lists the
other as a peer. To try both nodes on one machine, give each its own port, name, and working directory:

```bash
# terminal 1
mkdir -p /tmp/a && cd /tmp/a && QKD_NODE_NAME=alice qkd-node --port 8000
# terminal 2
mkdir -p /tmp/b && cd /tmp/b && QKD_NODE_NAME=bob qkd-node --port 8001
# terminal 3, in app/frontend: a second UI for the second node
VITE_API_BASE_URL=http://127.0.0.1:8001 npm run dev -- --port 5174
```

The node starts `python -m qkd.runner.alice` or `qkd.runner.bob` as a subprocess for each transfer, with
`--events json`. The runner prints one JSON event per line, and the node turns those events into transfer
state.

## Tests and benchmarks

```bash
pytest                                    # about 275 tests, about 35 s
pytest tests/services/test_api.py -k cancel
cd app/frontend && npm run lint && npm run build
```

- `tests/core`: chunk encryption, nonce layout, HKDF and privacy amplification, protocol helpers, env config.
- `tests/services`: wire framing, file streaming over TCP, the REST API with fake runners (including two
  nodes talking to each other), the state machine, the event bus, and the peer HTTP client.
- `tests/invariants`: full Alice and Bob runs on the simulator. Both sides derive the same key without Eve,
  both abort when QBER reaches the threshold, and a channel that flips every qubit is always caught.
- `tests/test_setup.py`: layering rules (core imports nothing above it, the wire module does not import
  qiskit) and the console entry points.

The benchmarks start real `bob`, `alice`, and optionally `eve` processes on free localhost ports. They read
the QBER and outcome from Alice's JSON events.

```bash
pip install -e ".[experiments]"
python scripts/benchmark.py experiments/configs/qubit_scaling.yaml    # writes experiments/results/qubit_scaling.csv
python scripts/plot_figures.py                                       # writes experiments/figures/*.png
```

| Config | Sweeps |
|---|---|
| `qubit_scaling.yaml` | transfer time against qubit count, 1 MB payload |
| `payload_scaling.yaml` | transfer time against payload size, 128 qubits |
| `eve_detection.yaml` | how often Eve is caught against qubit count |
| `qber_threshold.yaml` | abort rate under Eve against the QBER threshold |

`scripts/ibm_hardware_run.py` runs a bundled circuit on Aer by default. With `--hardware`, it submits to IBM
Quantum using `QISKIT_IBM_TOKEN` and `QISKIT_IBM_INSTANCE`.

## Wire protocol

One TCP connection from Alice to Bob. Every message is a 4-byte big-endian length followed by JSON or raw
bytes (`qkd.services.wire`). The order is fixed, and `alice`, `bob`, and `eve` depend on it:

| # | Direction | Message |
|---|---|---|
| 1 | A to B | list of QASM strings, one per qubit |
| 2 | B to A | Bob's bases, `+` or `x` per qubit |
| 3 | A to B | indices where the bases match (sifting) |
| 4 | A to B | `{"sample_indices": [...]}` |
| 5 | B to A | `{"sample_bits": [...]}` |
| 6 | A to B | `{"qber": q}`. Both sides stop here if `q >= QBER_THRESHOLD` |
| 7 | A to B | `{"salt": hex}`. Key = SHA-256(salt + remaining sifted bits) |
| 8 | A to B | file metadata: name, size, chunk size, chunk count, 8-byte base nonce |
| 9+ | A to B | one message per chunk: GCM tag (16 bytes) + ciphertext |

The AES key is HKDF-SHA256 of the 256-bit key. Chunk `i` uses nonce `base_nonce || i` (4 bytes,
big-endian). Each chunk is authenticated on its own, and Bob deletes the partial file if any tag fails.

## REST API

Every route is under `/api/v1`. The interactive docs are at `http://localhost:8000/docs` and the schema is at
`/openapi.json`. Errors always have the shape `{"error": {"code": "...", "message": "..."}}`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/node` | this node's id, name, address, `idle` or `busy` |
| PATCH | `/node` | rename the node (`{"name": ...}`) |
| GET | `/peers` | peers found over mDNS, with a reachability probe |
| GET | `/peers/{peer_id}` | one peer, 404 if unknown |
| POST | `/transfers` | multipart `file` + `peer_id`. 201 with a `Location` header. The node offers the file to the peer |
| GET | `/transfers` | list, filter with `?direction=` and repeated `?status=` |
| GET | `/transfers/{id}` | status, stage, QBER, sifted length, sample size, key bits, chunk progress, error |
| PATCH | `/transfers/{id}` | `{"status": "accepted"}` (202) or `{"status": "rejected"}` (200) |
| DELETE | `/transfers/{id}` | cancel a pending or running transfer, and tell the peer |
| GET | `/transfers/{id}/events` | server-sent events. Replays history, resumes with `Last-Event-ID` |
| GET | `/history` | finished transfers, newest first |
| POST | `/transfers/incoming` | node to node: the sender offers a transfer to the receiver |

Node to node, both sides keep a transfer with the same id. The sender POSTs `/transfers/incoming` to the
receiver. When the user accepts, the receiver starts Bob on a free port and PATCHes the sender's transfer with
`{"status": "accepted", "receiver_port": N}`. The sender then starts Alice. Because each Bob gets its own port,
several transfers can run at once.

Transfer states:

```
pending -> accepted -> key_exchange -> transferring -> completed
   |          |             |               |
   |          +-------------+---------------+--> failed, cancelled
   |                        +--> aborted_qber
   +--> rejected, failed, cancelled
```

`completed`, `rejected`, `aborted_qber`, `failed`, and `cancelled` are terminal. A request that asks for any
other move returns 409. Event types on the stream are `status`, `stage`, `metrics`, `progress`, `log`,
`listening`, and `result`.

## Project structure

```
src/qkd/
  core/           protocol steps, simulated channel, AES-GCM and HKDF, config (imports nothing above it)
  services/       wire framing, file streaming, reporting, mDNS discovery, transfer store,
                  event bus, history, peer HTTP client, runner launcher, NodeService
    api/          FastAPI app factory, routes, Pydantic models, error handlers
  usecases/       send_file (Alice), receive_file (Bob), eavesdrop_demo (Eve)
  runner/         CLI entry points: alice, bob, eve, node
app/frontend/     React + Vite UI; src/api/client.js is the only module that calls the backend
tests/            core/, services/, invariants/, conftest.py, test_setup.py
scripts/          benchmark.py, plot_figures.py, ibm_hardware_run.py
experiments/      configs/*.yaml for the benchmarks, figures.yaml for plots
literature/       reference papers (PDF)
reports/          project reports (PDF)
```

## Configuration

`src/qkd/core/config.py` holds every tunable. Each one can be overridden with `QKD_<NAME>`. Values are read
once at import, and the node passes its environment on to the alice and bob processes it starts.

| Variable | Default | Meaning |
|---|---|---|
| `QKD_NUM_QUBITS` | 128 | qubits Alice sends per transfer |
| `QKD_QBER_SAMPLE_FRACTION` | 0.15 | share of sifted bits revealed to estimate QBER |
| `QKD_QBER_THRESHOLD` | 0.11 | abort when QBER is at or above this |
| `QKD_FINAL_KEY_BITS` | 256 | bits taken from the SHA-256 digest |
| `QKD_CHUNK_SIZE` | 65536 | plaintext bytes per encrypted chunk |
| `QKD_ALICE_HOST` | localhost | default host for `qkd-alice` and `qkd-eve` |
| `QKD_BOB_PORT` | 65432 | default port for `qkd-bob` |
| `QKD_EVE_PORT` | 65433 | default port Eve listens on |
| `QKD_BUFFER_SIZE` | 1048576 | socket receive size |
| `QKD_OUTPUT_DIR` | received | where Bob writes files (relative to the working directory) |
| `QKD_HISTORY_FILE` | history.json | finished transfers written by the node |
| `QKD_NODE_PORT` | 8000 (or `PORT`) | HTTP port of `qkd-node` |
| `QKD_NODE_NAME` | generated | name advertised over mDNS |
| `QKD_NODE_HOST` | detected | address advertised to peers, if detection picks the wrong interface |

The frontend reads `VITE_API_BASE_URL` at build time.
