# Authenticated BB84 QKD file transfer

Two machines agree on a key with the BB84 quantum key distribution protocol, then use it to send a file
encrypted with AES-256-GCM. The quantum channel is simulated with Qiskit Aer. The classical channel is
authenticated with post-quantum cryptography (ML-DSA-65 signatures, plus an optional ML-KEM-768 key
exchange), which closes the man-in-the-middle gap that unauthenticated BB84 leaves open.

A backend node finds peers on the LAN over mDNS and exposes a REST API. A React UI shows every stage of
each run: sifting, the QBER check, the key funnel, and chunk progress.

## Features

- **BB84 end to end.** Sifting, QBER estimation and abort, optional Cascade error correction, Toeplitz
  privacy amplification, and a finite-key security bound (Tomamichel et al. 2012) that decides whether
  enough secure bits remain for a 256-bit key.
- **Post-quantum authentication.** Signed handshake with identity pinning, a transcript hash over every
  classical message, and key confirmation before any file data moves. Three modes: `none`, `sign`, `hybrid`.
- **Realistic channel option.** Fibre loss, detector efficiency, dark counts and misalignment
  (Ma, Qi, Zhao, Lo 2005; presets `GYS` and `KTH`). The default is an ideal lossless channel.
- **Decoy states.** Weak coherent source with signal, decoy and vacuum intensities. The security gate is
  either the asymptotic estimate or a composable finite-key bound (Lim et al. 2014).
- **Attack demos.** Eve (intercept-resend, partial or full, and photon-number splitting) and Mallory
  (active man-in-the-middle), each runnable from the command line.
- **Resumable transfers.** After a dropped connection or a killed process, a new authenticated session
  continues from the last chunk the receiver verified.
- **Backend node and UI.** mDNS discovery, REST API, server-sent events, and a React 19 + Vite UI.
- **Reproducible experiments.** A benchmark harness with seeded run order, provenance metadata, and
  plotting scripts.

## Scope and limits

- **Simulation, not hardware.** Qubits travel over TCP as one-qubit circuits on the same socket as the
  classical data. `scripts/ibm_hardware_run.py` can run a single circuit on IBM Quantum, but it is not
  part of the transfer.
- **Pseudo-random QRNG.** Random bits come from measuring `H|0⟩` on the simulator, so they are
  pseudo-random.
- **The node API is not hardened.** The REST API and mDNS run over plain HTTP with no authentication.
  Peer keys are pinned per node or accepted on first use, and there is no PKI. Under trust-on-first-use,
  an attacker's unknown key is accepted too. Only a pinned key stops an active man in the middle.
- **Denial of service is out of scope.** An attacker on the path can always drop the connection. The
  protocol detects tampering but cannot guarantee delivery.

[docs/security-argument.md](docs/security-argument.md) gives the full threat model and security argument.

## Install

Requires Python 3.11 or later. The UI needs Node.js 20.19+ or 22.12+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[backend,dev]"
```

| Extra | Packages | Needed for |
|---|---|---|
| (core) | qiskit, qiskit-aer, cryptography, numpy, scipy | the protocol and CLI |
| `backend` | fastapi, uvicorn, zeroconf, python-multipart, httpx | `qkd-node` |
| `dev` | pytest, httpx | the test suite |
| `experiments` | pyyaml, matplotlib | `scripts/benchmark.py`, `scripts/plot_figures.py` |
| `hardware` | qiskit-ibm-runtime | `scripts/ibm_hardware_run.py` |

## Quick start

### Send a file

```bash
qkd-bob                                # terminal 1: listens on port 65432
qkd-alice examples/hello.txt           # terminal 2: sends to localhost:65432
```

Bob writes the file to `received/received_hello.txt`. Use `--output-dir` or `QKD_OUTPUT_DIR` to change
the folder. To send to another machine, run `qkd-alice FILE --host HOST --port PORT`. Both commands exit
with code 1 if the key exchange aborts.

### Eavesdropper (Eve)

```bash
qkd-bob                                          # terminal 1
qkd-eve                                          # terminal 2: listens on 65433, forwards to Bob
qkd-alice examples/hello.txt --eve-mode          # terminal 3: connects to Eve instead of Bob
```

Eve measures each qubit in a random basis and re-sends the result, which corrupts about 25% of the
sifted bits. With the default 8192 qubits, Alice and Bob compare a sample of several hundred bits, so the
QBER check catches this every time. `--fraction F` attacks only part of the qubits. A light attack can
stay under the 11% threshold, but the keys then differ, so key confirmation stops the run (or, in `none`
mode, the first AES-GCM tag fails). No plaintext is written in either case.
`--attack pns` runs a photon-number-splitting attack against a weak coherent source.

### Man in the middle (Mallory)

Authentication only helps if Alice knows Bob's key. Do one honest transfer first: Alice prints
`Bob's identity <FP> accepted`. Then pin that fingerprint:

```bash
qkd-bob                                                              # terminal 1
python -m qkd.runner.mallory --scenario relay_hello                  # terminal 2: listens on 65433
qkd-alice examples/hello.txt --eve-mode --peer-fingerprint <FP>      # terminal 3
```

| Scenario | Auth | What happens |
|---|---|---|
| `none` | off | Mallory runs separate BB84 sessions with Alice and Bob, reads the whole file, and nobody notices (QBER 0%) |
| `own_identity` | on | Alice rejects Mallory's unpinned identity key at the hello, before she sends any qubits |
| `relay_hello` | on | Mallory relays the real hellos, but cannot forge Bob's signature over the transcript, so Alice aborts at key confirmation |

Trust-on-first-use (`QKD_TOFU=1`, the default) is convenient but does not stop Mallory. Trust is stored per
fingerprint, so an unknown key is accepted as a new peer. Pin keys with `--peer-fingerprint` or
`QKD_KNOWN_PEERS_FILE` with `QKD_TOFU=0` whenever a man in the middle is a concern. The same scenarios run
as tests with `pytest tests/invariants/test_mitm.py -v`.

### Backend node and UI

```bash
qkd-node                                         # REST API on :8000, advertises itself over mDNS
cd app/frontend && npm install && npm run dev
```

Open the URL Vite prints. The UI talks to `http://127.0.0.1:8000` unless `VITE_API_BASE_URL` is set (see
`app/frontend/.env.example`). Start `qkd-node` on a second machine on the same network and each node will
list the other as a peer. To run two nodes on one machine, give each one its own port, name and working
directory:

```bash
mkdir -p /tmp/a && cd /tmp/a && QKD_NODE_NAME=alice qkd-node --port 8000      # terminal 1
mkdir -p /tmp/b && cd /tmp/b && QKD_NODE_NAME=bob qkd-node --port 8001        # terminal 2
VITE_API_BASE_URL=http://127.0.0.1:8001 npm run dev -- --port 5174           # terminal 3, in app/frontend
```

For each transfer the node starts `python -m qkd.runner.alice` or `qkd.runner.bob` with `--events json`. It
reads one JSON event per line and turns those events into the transfer's state.

## How it works

```
 Alice                                                        Bob
   | -- hello (identity key, nonce, [ML-KEM pk], policy) -->   |   0  authenticate, pin identities
   | <-- hello (identity key, nonce, [ML-KEM ct], policy) --   |
   | -- qubits (simulated quantum channel) ---------------->   |   1  BB84 transmission
   | <-- bases / matching indices -------------------------->  |   2  sifting
   | <-- QBER sample, verdict ------------------------------>  |   3  abort if QBER >= 11% or finite-key bound too low
   | <-- Cascade parities (optional) ----------------------->  |   3c error correction
   | -- Toeplitz seed ------------------------------------->   |   4  privacy amplification -> 256-bit QKD key
   | <-- finished: signature + HMAC over transcript T ----->   |   4b key confirmation (sign / hybrid)
   | -- encrypted metadata, then AES-256-GCM chunks ------->   |   5  file transfer
```

The session key mixes the BB84 key, the transcript digest `T` and (in hybrid mode) the ML-KEM shared
secret through HKDF. It is then expanded into independent subkeys for file data, metadata and key
confirmation.

### Wire protocol

All traffic uses one TCP connection with `TCP_NODELAY` set. Each message is a 4-byte big-endian length
followed by JSON or raw bytes (`qkd.services.wire`). Steps 0 to 4 go through a `TranscriptChannel`.
Tracked messages are hashed into `T` as `direction byte || length || canonical JSON`. Qubits are not
hashed, because the QBER check protects them, and neither are the `finished` messages, because they sign
`T` itself.

| Step | Direction | Tracked | Message |
|---|---|---|---|
| 0 | A ↔ B | yes | `{"hello": {v, mode, params, ...}}`. Protocol version 3. `params` is the security policy and must match on both sides. `sign` adds `id_pk` and `nonce`; `hybrid` also adds `kem_pk` (Alice) and `kem_ct` (Bob) |
| 1 | A → B | no | `{"n", "index", "qubits"}`: the pulses that clicked at Bob, one QASM circuit each (integer codes in analytic mode) |
| 2 | B → A, A → B | yes | Bob's bases; the matching indices |
| 2d | A ↔ B | yes | decoy source only: intensity labels and per-intensity gains and QBERs |
| 3 | A ↔ B | yes | `sample_indices`, `sample_bits`, `qber`. Abort if the QBER is too high or the finite-key length is under 256 bits |
| 3c | A ↔ B | yes | Cascade only: seed, then parity rounds. Revealed parities are charged in the finite-key bound |
| 4 | A → B | yes | `{"salt"}`: the Toeplitz seed. Both sides hash the kept bits down to 256 bits |
| 4b | B → A, then A → B | no | `{"finished", "confirm"}` (sign and hybrid): ML-DSA signature and HMAC over `qkd-finished-v1\|role\|` + `T` |
| 4c / 4d | B → A, A → B | no | resume only: sealed `resume_request` and `resume_grant` |
| 5 | A → B | no | metadata (`tag + ciphertext`), then one `tag + ciphertext` message per chunk |
| 6 | B → A | no | resume only: sealed `resume_done` receipt after the whole-file SHA-256 matches |

Chunk `i` uses nonce `base_nonce || i`, where the 8-byte base nonce is fresh in every session. The
SHA-256 of the metadata is the AAD of every chunk, so altering the metadata makes chunk 0 fail. If any tag
fails, Bob deletes the partial file.

### Authentication modes

Set with `QKD_AUTH_MODE` (default `hybrid`) or `--auth`.

| Mode | Hello adds | Key confirmation | Session key |
|---|---|---|---|
| `none` | nothing | no | HKDF(`qkd_key`) |
| `sign` | ML-DSA-65 identity key, 32-byte nonce | yes | HKDF(`qkd_key`, salt = `T`) |
| `hybrid` | the above plus an ephemeral ML-KEM-768 key / ciphertext | yes | HKDF(`qkd_key ‖ kem_ss`, salt = `T`) |

If the version, mode or policy differs, both sides abort with `PeerAuthError`. There is no fallback.
Identity keys are checked against `QKD_KNOWN_PEERS_FILE`, or pinned on first use when `QKD_TOFU=1`.

### Security properties

- **Impersonation and MITM.** An attacker's own identity key is rejected at the hello, before Alice sends
  any qubits. An attacker who relays the real hellos cannot forge the `finished` signature over `T`.
- **Classical tampering.** Changing, inserting or reordering any tracked message changes `T`, so the
  signatures fail at step 4b.
- **Metadata tampering.** The metadata is encrypted and bound as AAD to every chunk.
- **Replay.** Fresh nonces (and, in hybrid mode, a fresh ML-KEM key pair) make `T` unique to each session.
- **Key reuse.** A resume runs a complete new handshake. No key or (key, nonce) pair is ever reused.

`scripts/fuzz_tamper.py` changes one wire message per trial and records which check caught it. The
property it checks is that Bob never accepts a file that differs from Alice's (`delivered_corrupt = 0`).

## Resumable transfers

Resume is off by default and needs auth mode `sign` or `hybrid`.

```bash
qkd-bob --resume --transfer-id job1
qkd-alice big.iso --resume --transfer-id job1     # interrupt it (Ctrl-C, kill, unplug), then run both again
```

When the node runs with `QKD_RESUME=1`, a transfer that stops after key confirmation becomes
`interrupted`. The sender clicks **Resume** (or calls `POST /api/v1/transfers/{id}/resume`), and the
receiver accepts as for any other offer. Interrupted transfers are saved to `QKD_STATE_FILE` and survive a
node restart. Peers are matched by identity fingerprint, because node ids change on every start.

On the wire, a resume is a full new session. After key confirmation, Bob sends a sealed request with the
number of chunks he holds and a hash of them. Alice answers with the offset to continue from, or 0 and a
reason if her file has changed. Bob keeps only AES-GCM-verified bytes in `received/.resume/<id>.part`. The
final file appears through an atomic rename after the whole-file hash matches, and Alice reports success
only once she has Bob's sealed receipt. If that receipt is lost, the next resume finds Bob's delivery
record, sends no file data, and gets the receipt again.

## REST API

All routes are under `/api/v1`. Interactive docs are served at `http://localhost:8000/docs`. Errors
always have the shape `{"error": {"code": "...", "message": "..."}}`.

| Method | Path | Purpose |
|---|---|---|
| GET / PATCH | `/node` | this node's id, name, address and status; rename it |
| GET | `/peers`, `/peers/{peer_id}` | peers found over mDNS, with a reachability probe |
| POST | `/transfers` | multipart `file` + `peer_id`: offer a file to a peer (201) |
| GET | `/transfers`, `/transfers/{id}` | list (`?direction=`, `?status=`) or one transfer with its stage, QBER, key bits and progress |
| PATCH | `/transfers/{id}` | `{"status": "accepted"}` or `{"status": "rejected"}` |
| DELETE | `/transfers/{id}` | cancel and notify the peer |
| POST | `/transfers/{id}/resume` | resume an `interrupted` outgoing transfer |
| GET | `/transfers/{id}/events` | server-sent events (supports `Last-Event-ID`) |
| GET | `/history` | finished transfers, newest first |
| POST | `/transfers/incoming` | node to node: the sender offers a transfer |

```
pending -> accepted -> key_exchange -> transferring -> completed
   |          |             |               |
   |          +-------------+---------------+--> failed, cancelled
   |                        +--> aborted_qber, aborted_auth
   +--> rejected, failed, cancelled

transferring -> interrupted -> pending (resume) -> ...        (QKD_RESUME=1)
```

## Configuration

Every tunable is in [src/qkd/core/config.py](src/qkd/core/config.py) and can be overridden with an
environment variable `QKD_<NAME>`. Values are read once at import, and the node passes its environment on to
the runners it starts.

| Variable | Default | Meaning |
|---|---|---|
| `QKD_NUM_QUBITS` | 8192 | pulses Alice sends per session |
| `QKD_QBER_SAMPLE_FRACTION` | 0.15 | share of sifted bits revealed to estimate the QBER |
| `QKD_QBER_THRESHOLD` | 0.11 | abort when the QBER is at or above this |
| `QKD_FINAL_KEY_BITS` | 256 | length of the QKD key |
| `QKD_EPS_SEC`, `QKD_EPS_COR` | 1e-10, 1e-15 | finite-key security and correctness parameters |
| `QKD_ENFORCE_FINITE_KEY` | 1 | abort when the finite-key bound gives fewer than `FINAL_KEY_BITS` |
| `QKD_RECONCILIATION` | none | `none` or `cascade` |
| `QKD_CHANNEL_PRESET` | ideal | `ideal`, `GYS` or `KTH` |
| `QKD_CHANNEL_LENGTH_KM` | 0 | fibre length; `FIBER_LOSS_DB_PER_KM`, `DETECTOR_EFFICIENCY`, `DARK_COUNT_PROB` and `MISALIGNMENT` override single values |
| `QKD_SOURCE` | single | `single`, `decoy` or `wcp` (`wcp` is a deliberately insecure baseline for the PNS demo) |
| `QKD_DECOY_INTENSITIES`, `QKD_DECOY_PROBS` | 0.48,0.1,0 / 0.7,0.2,0.1 | decoy intensities and sending probabilities |
| `QKD_DECOY_GATE` | asymptotic | `asymptotic` or `composable` |
| `QKD_MEASUREMENT` | aer | `aer` or `analytic` (NumPy, for runs with millions of pulses) |
| `QKD_AUTH_MODE` | hybrid | `none`, `sign` or `hybrid` |
| `QKD_IDENTITY_DIR` | identity | node identity keys |
| `QKD_KNOWN_PEERS_FILE` | known_peers.json | pinned peer public keys |
| `QKD_TOFU` | 1 | trust unknown peers on first use |
| `QKD_CHUNK_SIZE` | 65536 | plaintext bytes per encrypted chunk |
| `QKD_ALICE_HOST`, `QKD_BOB_PORT`, `QKD_EVE_PORT` | localhost, 65432, 65433 | CLI defaults |
| `QKD_OUTPUT_DIR` | received | where Bob writes files |
| `QKD_NODE_PORT`, `QKD_NODE_NAME`, `QKD_NODE_HOST` | 8000, generated, detected | backend node |
| `QKD_HISTORY_FILE`, `QKD_STATE_FILE` | history.json, node_state.json | node history and interrupted transfers |
| `QKD_RESUME` | 0 | make transfers resumable |
| `QKD_RESUME_STALL_TIMEOUT` | 60 | seconds of silence before a resumable transfer reports `interrupted` |
| `QKD_RESUME_SYNC_CHUNKS` | 8 | verified chunks between an fsync and a sidecar update |

## Tests

```bash
pytest                                    # about 1000 tests; includes 100 MB transfers and a kill-and-resume run
pytest tests/invariants                   # full Alice/Bob runs on the Aer simulator
cd app/frontend && npm run lint && npm run build
```

| Folder | Covers |
|---|---|
| `tests/core` | crypto, nonces, HKDF, Toeplitz hashing, finite-key and decoy bounds, Cascade, channel model, PQC primitives |
| `tests/services` | wire framing, transcript hashing, file streaming, REST API (including two nodes talking to each other), state machine, resume storage |
| `tests/invariants` | end-to-end runs: honest transfers, QBER aborts, signed handshakes, MITM, tampering, noisy channels, decoy states, PNS, resume after SIGKILL |
| `tests/usecases`, `tests/runner`, `tests/scripts` | handshake and resume negotiation, CLI arguments, benchmark harness, fuzzer |
| `tests/test_setup.py` | layering rules (`core` imports nothing above it; the wire module does not import qiskit) and console entry points |

## Experiments

```bash
pip install -e ".[experiments]"
python scripts/benchmark.py experiments/configs/e1_detection.yaml
python scripts/plot_figures.py                                       # PNG + PDF into experiments/figures/
```

| Config | Question |
|---|---|
| `e1_detection` / `e1n_detection` | how often the QBER check catches a partial intercept-resend Eve (ideal / 25 km fibre) |
| `e2_outcomes` | which check stops each run under a partial Eve, with and without authentication |
| `e3_secure_length` | finite-key secure length against the number of raw qubits |
| `e4_overhead` | time and bytes per stage by auth mode and payload size |
| `e6_latency` | cost of each auth mode under network latency (`scripts/latency_proxy.py`) |
| `e7_fuzz` | tamper fuzzing (`scripts/fuzz_tamper.py`) |
| `e8_reconnect` | cost of resuming against restarting after an interruption |
| `n0_channel` | measured click rate and QBER against the channel model |
| `d2_decoy_honest` / `d3_pns` | decoy-state transfers, and the PNS attack against weak coherent and decoy sources |

Each run is written to its own folder, `experiments/results/<experiment>/<timestamp>_<commit>/`, with the
raw runs, a median/IQR summary with Wilson intervals, and metadata (commit, versions, CPU, seed). Runs are
executed in a seeded shuffled order. Selected results, including the decoy-state study and
[experiments/results/eval-v2/REPORT.md](experiments/results/eval-v2/REPORT.md), are committed.

## Project layout

```
src/qkd/
  core/        BB84 steps, channel model, Cascade, finite-key and decoy bounds, AES-GCM/HKDF, PQC, config
  services/    wire framing, transcript, file streaming, reporting, node service, transfer store,
               discovery, resume storage, api/ (FastAPI)
  usecases/    send_file (Alice), receive_file (Bob), eavesdrop_demo (Eve), pns_demo, mitm_demo
               (Mallory), handshake, reconcile, decoy_reveal, resume
  runner/      CLIs: qkd-alice, qkd-bob, qkd-eve, qkd-node, and the Mallory runner
app/frontend/  React 19 + Vite + Tailwind UI
tests/         unit, service, and end-to-end tests
scripts/       benchmark harness, plotting, fuzzer, latency proxy, decoy studies, IBM hardware run
experiments/   benchmark configs, figure definitions, committed results
docs/          security argument, project review slides
examples/      a sample file to send
```

## References

- C. H. Bennett and G. Brassard, "Quantum cryptography: Public key distribution and coin tossing", 1984.
- P. W. Shor and J. Preskill, "Simple proof of security of the BB84 quantum key distribution protocol", PRL 85, 441 (2000).
- G. Brassard and L. Salvail, "Secret-key reconciliation by public discussion", EUROCRYPT 1993.
- J. Martinez-Mateo, C. Pacher, M. Peev, A. Ciurana, V. Martin, "Demystifying the information reconciliation protocol Cascade", QIC 15 (2015).
- M. Tomamichel, C. C. W. Lim, N. Gisin, R. Renner, "Tight finite-key analysis for quantum cryptography", Nat. Commun. 3, 634 (2012).
- H.-K. Lo, X. Ma, K. Chen, "Decoy state quantum key distribution", PRL 94, 230504 (2005).
- X. Ma, B. Qi, Y. Zhao, H.-K. Lo, "Practical decoy state for quantum key distribution", PRA 72, 012326 (2005).
- C. C. W. Lim, M. Curty, N. Walenta, F. Xu, H. Zbinden, "Concise security bounds for practical decoy-state QKD", PRA 89, 022307 (2014).
- V. Scarani et al., "The security of practical quantum key distribution", RMP 81, 1301 (2009).
- NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA), 2024.

## Team

Built as a semester major project at COEP Technological University by
[Mehmood Deshmukh](https://github.com/Mehmood-Deshmukh), [Arya Kulkarni](https://github.com/arukaka),
[Chaithanya Hosahudya](https://github.com/hosachaii) and [Yashwant Bhosale](https://github.com/YashwantBhosale),
under the guidance of Dr. Mukta Nivelkar.
