# Implementation facts (paper-eval v2)

All facts below are from the code at the commit named, or from a command whose
output is quoted. Nothing here is estimated.

## Commit, environment, machine

- **Commit:** `3c2f5f9e4de9dae4021d7ca4cfd66628d50cbb4d` (branch `exp/paper-eval-v2`, cut from `main`).
  Message: `feat: finite-key bound, key confirmation, encrypted metadata in protocol`.
- **Python:** 3.12.3 (venv at `/home/hosachai/bb84/.venv`).
- **Libraries** (`pip`/import): qiskit 2.6.1, qiskit-aer 0.18.2, cryptography 50.0.2,
  numpy 2.5.4, fastapi 0.162.0.
- **Machine** (`uname -a`, `lscpu`, `free -h`): Linux `bluewaffle` 7.0.0-38-generic,
  Ubuntu 24.04, x86_64. AMD Ryzen 5 5600H, 12 logical CPUs (6 cores × 2 threads,
  1 socket). 15 GiB RAM.

## Non-blank lines of code (`grep -vcE '^[[:space:]]*$'`)

| Package | Non-blank LOC | Files |
|---|---|---|
| `src/qkd/core` | 724 | 7 |
| `src/qkd/services` | 2032 | 18 |
| &nbsp;&nbsp;of which `services/api` | 412 | — |
| `src/qkd/usecases` | 949 | 7 |
| `src/qkd/runner` | 475 | 6 |
| **`src/qkd` total** | **4182** | — |
| `app/frontend/src` (`.js/.jsx/.css`) | 1663 | — |

## Tests

`pytest --collect-only -q` → **536 tests collected** (0.95 s). I used collection, not a
full run, to avoid a long execution in Phase 1 (the suite includes 100 MB transfers);
say the word to run `pytest -q` for pass/fail. Per-directory collected counts:

| Directory | Tests |
|---|---|
| `tests/core` | 95 |
| `tests/services` | 281 |
| `tests/usecases` | 23 |
| `tests/invariants` | 54 |
| `tests/test_setup.py` | 49 |

(These sum to 502; the remaining 34 are in other `tests/*.py` modules at the tests root.)

## Config defaults (`src/qkd/core/config.py`, each overridable via `QKD_<NAME>`)

| Name | Default | Line | Paper symbol |
|---|---|---|---|
| `NUM_QUBITS` | 8192 | 47 | N |
| `QBER_SAMPLE_FRACTION` | 0.15 | 48 | sample fraction |
| `QBER_THRESHOLD` | 0.11 | 49 | Q_max |
| `FINAL_KEY_BITS` | 256 | 54 | ℓ |
| `EPS_SEC` | 1e-10 | 59 | ε_sec |
| `EPS_COR` | 1e-15 | 60 | ε_cor |
| `CHUNK_SIZE` | 65536 (64 KiB) | 65 | chunk size |
| `ENFORCE_FINITE_KEY` | 1 (True) | 95 | "enforce" in Π |
| `AUTH_MODE` | hybrid | 97 | default mode |
| `TOFU` | 1 | 100 | trust-on-first-use |
| `IDENTITY_DIR` | `identity` | 98 | — |
| `KNOWN_PEERS_FILE` | `known_peers.json` | 99 | — |
| network: `ALICE_HOST`=localhost, `BOB_PORT`=65432, `EVE_PORT`=65433, `BUFFER_SIZE`=1 MiB, `NODE_PORT`=8000 | | 30–38 | — |

`ProtocolParams` (config.py:103) bundles the per-run values; its
`security_policy()` (config.py:116) returns exactly
`{final_key_bits, eps_sec, eps_cor, qber_threshold, enforce_finite_key}` — this dict is
the policy Π placed in every hello.

## Simulator usage

- **QRNG** — `bb84_protocol._quantum_random_bits` (bb84_protocol.py:42): one
  `QuantumCircuit(1,1)` with `h(0); measure`, `transpile`d once, then
  `_qrng_backend.run(compiled, shots=n, memory=True)` — **one batched job of n shots**,
  n bits from `get_memory()`. Used for Alice's raw bits and for both sides' bases.
- **Preparation** — `quantum_channel.prepare_qubit` (quantum_channel.py:36): `X` on
  `|0⟩` iff bit=1, then `H` iff basis is `x`; serialised with `qiskit.qasm2.dumps`.
  Each qubit is one QASM2 circuit string.
- **Measurement** — `quantum_channel.measure_qubits` (quantum_channel.py:125): builds one
  measurement circuit per received qubit and submits **all of them as a single job**,
  `_backend.run(circuits, shots=1, memory=True)` (line 137). **CONFIRMS the paper's
  "Bob measures all circuits as a single simulator job."** The docstring states this is
  ~250× faster than one job per qubit; no transpile step (only x/h/measure).
  Measured cost at N=8192: **2.20 s** for the single measurement job (vs QRNG ~0.15 s
  for two n-bit batches, preparation ~0.23 s).
- **Eve** — `quantum_channel.eve_intercept_resend` (quantum_channel.py:67) measures
  **every** qubit in a random basis and re-prepares from the result (full
  intercept-resend, i.e. the paper's f = 1.0). **There is no partial-fraction-f Eve in
  `src/`.** The paper's partial Eve (attacks a fraction f) must be realised in the
  experiment harness by attacking only a random f·N subset (see the plan, E1/E2).

## Privacy amplification and the finite-key bound

- **Toeplitz PA** — `bb84_protocol.toeplitz_hash` (bb84_protocol.py:128) multiplies the
  n-bit vector by an m×n binary Toeplitz matrix over GF(2) via `np.convolve`; the seed is
  the first **n + m − 1 bits** (`toeplitz_seed_bytes`, line 123). `privacy_amplification`
  (line 148) draws the seed from the OS CSPRNG (`secrets.token_bytes`) when Alice
  generates it; Bob passes the received seed. **CONFIRMS "Toeplitz construction, seed
  length n + ℓ − 1".**
- **Finite key** — `core/finite_key.py`. `deviation(n,k,eps_sec)` = μ (line 39);
  `secure_key_length(n,k,Q,eps_sec,eps_cor)` = ℓ (line 51), floored, ≥ 0, with
  `leak_EC = log2(2/eps_cor)` as the only "disclosed" term (no reconciliation). Matches
  the paper's Eq. (finitekey) exactly.

## Key schedule (`core/crypto_utils.py`)

- **Session key** `derive_session_key` (line 49): HKDF-SHA256, length 32.
  hybrid → ikm = `qkd_key || kem_ss`, salt = T, info = `b"bb84-mlkem768-hybrid-v1"`;
  sign → ikm = `qkd_key`, salt = T, info = `b"bb84-sign-v1"`;
  none → `derive_aes_key(qkd_key)` = HKDF(info=`b"bb84-qkd-file-transfer"`, salt=None).
- **Subkeys** `key_schedule` (line 113): HKDF-Expand of the session key into three 256-bit
  subkeys — `file`=`b"bb84-file-v1"`, `metadata`=`b"bb84-metadata-v1"`,
  `confirm`=`b"bb84-confirm-v1"`.

## Confirmation tag and finished signature (`usecases/handshake.py`)

- `confirmation_tag(key, role, T)` (line 217): `HMAC-SHA256(key_schedule(key).confirm,
  CONFIRM_PREFIX + role + b"|" + T)`, `CONFIRM_PREFIX = b"qkd-confirm-v1|"`, 32-byte tag.
- `finished_message(role, T, tag)` (line 222): the signed bytes =
  `FINISHED_PREFIX + role + b"|" + T + tag`, `FINISHED_PREFIX = b"qkd-finished-v1|"`.
- `_finished` (line 278) sends `{"finished": b64(sig), "confirm": b64(tag)}`.
- `_verify_finished` (line 284): checks the ML-DSA signature first (→ `PeerAuthError`),
  then the tag with `hmac.compare_digest` (→ `KeyConfirmationError`). Bob sends first
  (`bob_finished` line 200), Alice verifies then sends (`alice_finished` line 178). The
  session key is derived just before step 4b (send_file.py:152–157, receive_file.py:142–147).

## Metadata encryption and chunk rules (`services/file_stream.py`)

- Metadata message fields (`FileMeta.to_message`, line 80): `filename, total_size,
  chunk_size, num_chunks, base_nonce` (8-byte, hex).
- `encrypt_metadata` (line 136): AES-256-GCM under `K_meta` with `METADATA_NONCE =
  bytes(12)` (all-zero) and fixed `METADATA_AAD = b"qkd-file-meta-v1"`.
- Chunk nonce `derive_chunk_nonce` (crypto_utils.py:209) = `base(8B) || struct(">I", i)`
  (4B BE); `MAX_CHUNKS = 1<<32`. Chunk AAD = `metadata_aad` = SHA-256 of canonical
  metadata JSON.
- Receiver rules: `expected_chunks = max(1, ceil(size/chunk_size))` (line 49);
  `FileMeta.from_message` rejects `num_chunks != expected_chunks` or `> MAX_CHUNKS`
  (line 107); `receive_encrypted_file` raises `MetadataError` if written bytes ≠
  `total_size` (line 229) and deletes the partial file on any exception (line 231).

## Transcript (`services/transcript.py`)

Running SHA-256 of `dir_byte(1B) || len(4B BE) || canonical-JSON(payload)` per tracked
message; `_DIR_ALICE = b"\x00"`, `_DIR_BOB = b"\x01"` (lines 20–21). Canonical JSON =
`json.dumps(sort_keys=True, separators=(",",":")).encode("utf-8")`. `bytes_sent`/
`bytes_received` count framed bytes of every message (the `auth_overhead_bytes` source).

## Wire message sizes (measured, PROTOCOL_VERSION = 2)

Framed = 4-byte length prefix + `wire.encode_json` payload. Hellos now carry the policy
Π in every mode (`"params"` field), which did not exist at the v1 measurement.

| Message | none | sign | hybrid |
|---|---|---|---|
| hello A→B | 162 | 2836 | 4432 |
| hello B→A | 162 | 2836 | 4304 |
| finished (each role) | — | 4491 | 4491 |

finished = `{"finished": b64(3309-byte ML-DSA sig)=4412, "confirm": b64(32-byte tag)=44}`.
Derived `auth_overhead_bytes` (sent+received hello+finished): none 324, sign 14654,
hybrid 17718 (to be re-measured on the wire in E6).

QASM qubit payload (framed list of N circuits): **54.0 B/qubit** at every N
(512→27652, 1024→55300, 2048→110596, 4096→221188, 8192→442372 bytes).

## Outcome-name mapping (important for E1/E2/E4)

The runners (`runner/alice.py`, `runner/bob.py`) map exceptions to four outcome strings
(`reporting.py:42`): `completed`, `aborted_qber`, `aborted_auth`, `failed`. Note:

- QBER-threshold abort, finite-key-bound abort (`KeyExchangeResult.aborted`), **and**
  `KeyConfirmationError` **all report as `aborted_qber`** (alice.py:119–121, 131–133;
  bob.py:117–119, 132–134). The stopping check is therefore **not** distinguishable from
  the outcome name alone — the harness must read the stage/metrics and the abort reason
  text (or detect the check in-process) to tell QBER vs finite-key vs key-confirmation.
- `PeerAuthError` → `aborted_auth`; `InvalidTag`/other → `failed`.
