# BB84 QKD file transfer

Two machines agree on a key with the BB84 protocol, then use it to send a file encrypted with AES-256-GCM.
The quantum channel is simulated with Qiskit Aer: each qubit travels over TCP as a one-qubit QASM circuit,
and the receiver measures it on the simulator. The classical channel is authenticated against active
man-in-the-middle attacks using post-quantum signatures (ML-DSA-65) and an optional ephemeral post-quantum
key exchange (ML-KEM-768). A small backend node finds peers on the LAN over mDNS and exposes a REST API,
and a React UI shows each run of the protocol.

What it does not do:

- No quantum hardware in the default flow. `scripts/ibm_hardware_run.py` can run a single circuit on IBM
  Quantum, but it is separate from the transfer.
- The channel is noiseless. There is no information reconciliation and no decoy-state analysis. Both were
  removed because the live flow never called them. Any QBER above zero comes from an eavesdropper.
- The random bits come from measuring `H|0⟩` on the Aer simulator, which is a pseudo-random source.
- The classical channel is authenticated against active MITM attacks, but the node API has no authentication
  or TLS, and peer keys are pinned without a PKI. Denial of service and first-contact interception under
  trust-on-first-use remain outside the threat model (see [Security properties and limits](#security-properties-and-limits)).
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

### Man-in-the-middle demo

The man-in-the-middle demo currently runs as the acceptance tests:

```bash
pytest tests/invariants/test_mitm.py -v
```

This exercises Mallory (`src/qkd/usecases/mitm_demo.py`, `run_mitm`) between Alice and Bob:
- **Authentication off (`none`)**: Mallory runs the `own_key` strategy, relaying the file while recovering
  the full plaintext undetected at 0% QBER (the vulnerability of unauthenticated BB84).
- **Authentication on (`sign` / `hybrid`), own key**: Alice checks Mallory's unpinned identity key in the
  hello exchange and aborts at `authentication` before transmitting any qubits.
- **Authentication on, relay hello**: Mallory forwards the authentic hellos to match Alice's transcript `T`,
  but cannot forge Bob's signature over `b"qkd-finished-v1|bob|" + T` at step 4b; Alice aborts at
  `key_confirmation` and no file data is transferred.

CLI flags (`--auth`, `--identity`, `--peer-fingerprint`) and a `qkd-mallory` console script arrive with the
runner work.

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
pytest                                    # 350 tests, about 84 s
pytest tests/services/test_api.py -k cancel
cd app/frontend && npm run lint && npm run build
```

- `tests/core`: chunk encryption, nonce layout, HKDF and privacy amplification, protocol helpers, post-quantum primitives (`pqc.py`), session key derivation (`test_session_key.py`), and env config.
- `tests/services`: wire framing, file streaming over TCP, transcript hashing (`test_transcript.py`), the REST API with fake runners (including two nodes talking to each other), the state machine, the event bus, and the peer HTTP client.
- `tests/invariants`: full Alice and Bob runs on the Aer simulator. Exercises protocol invariants without Eve, QBER threshold aborts, full-channel flipping, signed handshakes (`test_signed_handshake.py`: honest transfers, wrong-pin rejection before qubits, downgrade rejection), man-in-the-middle attacks (`test_mitm.py`: own-key and relay strategies), and classical/metadata message tampering (`test_tamper.py`).
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
bytes (`qkd.services.wire`). The order is fixed, and `send_file`, `receive_file`, `eavesdrop_demo`, and
`mitm_demo` depend on it.

Messages pass through a `TranscriptChannel` (`src/qkd/services/transcript.py`). Tracked classical messages
are folded into a running SHA-256 transcript digest `T` as:
`direction byte (0x00 for Alice, 0x01 for Bob) || length (4 bytes, big-endian) || canonical JSON payload`.
Untracked messages (`qubits` and `finished`) bypass transcript hashing: quantum channel integrity is
evaluated separately by QBER, and `finished` contains the signature over `T` itself.

| Step | Direction | Tracked? | Message |
|---|---|---|---|
| 0a | A to B | Yes | `{"hello": {...}}` (Alice's protocol version, mode, nonces, public keys) |
| 0b | B to A | Yes | `{"hello": {...}}` (Bob's protocol version, mode, nonces, public keys/ciphertext) |
| 1 | A to B | No | list of QASM strings, one per qubit (simulated quantum channel) |
| 2 | B to A | Yes | Bob's bases, `+` or `x` per qubit |
| 2 | A to B | Yes | matching basis indices (sifting) |
| 3 | A to B | Yes | `{"sample_indices": [...]}` |
| 3 | B to A | Yes | `{"sample_bits": [...]}` |
| 3 | A to B | Yes | `{"qber": q}`. Both sides abort if `q >= QBER_THRESHOLD` |
| 4 | A to B | Yes | `{"salt": hex}`. Both compute `qkd_key = SHA-256(salt + remaining sifted bits)` and transcript digest `T` |
| 4b | B to A | No | `{"finished": sig}` (`sign` and `hybrid` only). Bob signs `b"qkd-finished-v1\|bob\|" + T` |
| 4b | A to B | No | `{"finished": sig}` (`sign` and `hybrid` only). Alice signs `b"qkd-finished-v1\|alice\|" + T` |
| 5 | A to B | No | file metadata: name, size, chunk size, chunk count, 8-byte base nonce |
| 5+ | A to B | No | one message per chunk: GCM tag (16 bytes) + ciphertext |

Bob sends `finished` first at step 4b. Alice verifies Bob's signature before deriving the session key or sending
any ciphertext. Bob verifies Alice's signature before reading metadata, creating the output directory, or
decrypting chunks.

Chunk `i` uses nonce `base_nonce || i` (4 bytes, big-endian). The file metadata is bound as AES-GCM
additional authenticated data (AAD = SHA-256 of the canonical metadata JSON) to every chunk, so any altered
metadata message fails on chunk 0. Bob deletes the partial file if any tag fails.

### Authentication modes

The authentication mode is configured per node via `QKD_AUTH_MODE` (default `hybrid`):

| Mode | Hello payload | Finished step (4b)? | Session key derivation (`derive_session_key`) |
|---|---|---|---|
| `none` | `{v, mode}` | No | `derive_aes_key(qkd_key)`: HKDF-SHA256 (`ikm=qkd_key`, `salt=None`, `info=b"bb84-qkd-file-transfer"`) |
| `sign` | `{v, mode, id_pk, nonce}` | Yes (ML-DSA-65) | HKDF-SHA256 (`ikm=qkd_key`, `salt=T`, `info=b"bb84-sign-v1"`) |
| `hybrid` | Alice: `{v, mode, id_pk, nonce, kem_pk}`<br>Bob: `{v, mode, id_pk, nonce, kem_ct}` | Yes (ML-DSA-65) | HKDF-SHA256 (`ikm=qkd_key \|\| kem_ss`, `salt=T`, `info=b"bb84-mlkem768-hybrid-v1"`) |

Binary fields (`id_pk`, `nonce`, `kem_pk`, `kem_ct`, `finished`) are base64-encoded. Each node verifies the
peer's identity public key against its trust policy (`auth.verifier.check`) upon receiving the hello. On any
protocol version or mode mismatch, Bob replies with `{"hello": {"v": 1, "mode": mode}}` so both sides record
the same mismatch reason, and both sides abort with `PeerAuthError` with no fallback or negotiation.

### Security properties and limits

These are informal security arguments under stated assumptions, not formal proofs. For full arguments and
test evidence, see [docs/security-argument.md](docs/security-argument.md).

What the layer stops:

- **Impersonation and MITM**: If an attacker presents their own identity key, Alice rejects it during the hello
  exchange (step 0) before transmitting any qubits. If an attacker relays authentic hellos, they cannot forge
  Bob's signature over `b"qkd-finished-v1|bob|" + T` at step 4b without Bob's private signing seed.
- **Classical tampering**: Any modification, insertion, or reordering of tracked classical messages (bases,
  sifting indices, sample indices, sample bits, QBER, salt) changes transcript digest `T`, causing signature
  verification at step 4b to fail.
- **Metadata tampering via GCM AAD**: File metadata is sent after step 4b and is not in `T`. Instead, its
  canonical JSON SHA-256 digest is bound as AES-256-GCM additional authenticated data (AAD) to each chunk.
  Tampering with the metadata causes chunk 0 to fail tag verification.
- **Replay attacks**: Fresh 32-byte nonces in every hello (and fresh ephemeral ML-KEM-768 keypairs in hybrid mode)
  ensure transcript digest `T` is unique per session with overwhelming probability. A signature captured from
  a previous session will not verify against a new session's `T`.

What it does not stop (limits):

- **Denial of service**: An in-path attacker can drop, corrupt, or truncate the TCP connection at any point.
  The protocol ensures tampering and impersonation are detected, not that delivery is guaranteed.
- **Trust-on-first-use (TOFU) first contact**: Under TOFU (`QKD_TOFU=1`), an attacker present on the very first
  connection can have their key pinned. TOFU only protects subsequent connections. Out-of-band key pinning
  (`QKD_KNOWN_PEERS_FILE`) is required to secure first contact.
- **Qubits over the same TCP socket**: In this simulation, quantum states are serialized QASM circuits sent over
  the same TCP socket as classical data. On physical hardware, quantum and classical channels would be separate.
- **No PKI**: Peer trust is managed per node via pinned keys or TOFU. There is no certificate authority (CA),
  certificate hierarchy, or revocation infrastructure.
- **Noiseless simulation and no reconciliation**: The quantum channel simulation is noiseless, so any non-zero
  QBER aborts the transfer; real-world information reconciliation is not implemented.
- **Unauthenticated REST API**: The `qkd-node` REST API and mDNS discovery are unauthenticated and run over plain HTTP.

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
  usecases/       send_file (Alice), receive_file (Bob), eavesdrop_demo (Eve), mitm_demo (Mallory), handshake
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
| `QKD_AUTH_MODE` | hybrid | authentication mode: `none`, `sign`, or `hybrid` |
| `QKD_IDENTITY_DIR` | identity | directory holding node identity seeds and keys |
| `QKD_KNOWN_PEERS_FILE` | known_peers.json | path to pinned peer public keys |
| `QKD_TOFU` | 1 | trust-on-first-use for unknown peers (1 = enabled, 0 = disabled) |

The frontend reads `VITE_API_BASE_URL` at build time.
