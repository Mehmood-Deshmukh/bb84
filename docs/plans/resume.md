# Plan: resumable file transfer (`feature/resume`)

Goal: after a connection drop, a runner kill or a node restart, the sender can resume a transfer
and only the missing part of the file is sent. A resume is a NEW full handshake (hello, BB84,
key confirmation) that continues at a chunk offset. No session key is ever cached or reused.

## 1. Findings (recon, verified against the repo)

Baseline on `new-feature` @ 2a5a63c, before any change:

| Check | Result |
|---|---|
| `pytest` (whole suite) | 482 passed in 2m40s |
| `npm --prefix app/frontend run lint` | exit 0 |
| `npm --prefix app/frontend run build` | exit 0 |

(The brief said about 330 tests; the real number is 482.)

What the code does today:

- **Chunk nonces** (`core/crypto_utils.derive_chunk_nonce`): `base_nonce(8B, os.urandom per
  describe_file) || chunk_index(4B BE)`. Key = `derive_session_key(qkd_key, kem_ss, T, mode)`.
  In sign/hybrid the HKDF salt `T` covers two fresh 32 B nonces and (hybrid) a fresh ML-KEM key, on
  top of fresh BB84 bits, so every session has a fresh key. A fresh `base_nonce` is drawn per session.
- **Stream end**: there is no end marker. The receiver reads exactly `num_chunks` messages, where
  `num_chunks` comes from the metadata message. The metadata is not signed; it is bound as GCM AAD
  (SHA-256 of its canonical JSON), so a changed `num_chunks` fails the tag of chunk 0. A cut stream
  surfaces as `ConnectionError`. Gaps: nothing checks `written == total_size`, and there is no
  whole-file hash. `total_size` is only covered through the AAD.
- **Receiver** (`receive_encrypted_file`): writes straight to `received_<name>`, deletes it on any
  exception. A killed process leaves an unverified-complete-looking partial file behind.
- **Node**: transfers are in memory only. A runner that exits without a `result` event becomes `failed`
  (`NodeService._supervise`). Uploads live in a per-process `mkdtemp` and are deleted in `_finish`.
- **State machine**: `tests/services/test_transfer_store.py::test_transition_table` parametrizes over
  every `(S, S)` pair and asserts `can_transition(a, b) is ((a, b) in ALLOWED)` with a closed `ALLOWED`
  set. Any new status therefore cannot appear in `TRANSITIONS` as a source or target without breaking
  that test (which must stay unmodified). See Decision D5.
- `services/events.py` holds an unused duplicate of `STAGE_STATUS`/`METRIC_FIELDS`; the live ones are in
  `services/node.py`. Both are kept in sync.
- The wire proxy in `tests/invariants/support.py` encodes the wire order in `WIRE_STEPS`. Eve's
  `_forward_rest` and Mallory's relay (`mitm_demo`) also encode it.

## 2. Design

### 2.1 Opt-in, wire unchanged when off
`send_file`/`receive_file` take `resume: ResumeOptions | None = None`. With `None` (the default, and
what every existing test uses) the wire, files and events are byte-for-byte what they are today.
Runners expose `--resume` (config `QKD_RESUME`, default `0`). The node passes `--resume` to the runners
it launches when `QKD_RESUME=1`.

Resume is only available in `sign` and `hybrid` (D2): without an identity there is nothing to bind a
resume to. In `none` mode `--resume` is ignored with a warning and the transfer behaves as today.

### 2.2 Wire flow (resume on, signed modes)
```
4b  Bob  -> {"finished": sig, "resume": 1}      (capability flag, untracked, not part of the signature)
4b  Alice-> {"finished": sig, "resume": 1}
        Both sides enter 4c/4d only if their own resume is on AND the peer's finished carried the flag.
4c  Bob  -> {"resume_request": b64(nonce || AES-GCM_kBob(json request, aad = T | "request"))}
4d  Alice-> {"resume_grant":   b64(nonce || AES-GCM_kAlice(json grant,  aad = T | "grant" | sha256(request)))}
5   Alice-> file metadata (now with resume_offset, sha256), then chunks offset..N-1
6   Bob  -> {"resume_done": b64(nonce || AES-GCM_kBob(receipt, aad = T | "resume-done"))}
```
Step 6 is Bob's receipt, sent after the size and the whole-file SHA-256 verified and the file was
renamed into place. Alice reports success only after reading it. Without it a sender can finish
writing into its socket buffers while the receiver never got the data (TCP gives no end-to-end
confirmation), so the sender would call a transfer complete that the receiver has as interrupted.
- Negotiation is after key confirmation: both `finished` signatures have verified over `T` before 4c.
- `kBob`/`kAlice` = HKDF-SHA256(session_key, info = `bb84-resume-v1|bob` / `|alice`). They are
  separate keys, never the file key, so resume messages cannot collide with chunk nonces. Each key
  encrypts exactly one message; a random 96-bit nonce is used anyway.
- Request (plaintext inside the AEAD): `{transfer_id, meta_digest, chunk_size, next_chunk,
  prefix_sha256, alice_fp}`. `meta_digest` = SHA-256 of canonical JSON of `{filename, total_size}`;
  `prefix_sha256` = SHA-256 of the first `next_chunk * chunk_size` bytes Bob has on disk.
- Alice verifies, before streaming: AEAD tag (else `PeerAuthError`, outcome `aborted_auth`), `transfer_id`
  equals hers, `alice_fp` equals her own fingerprint. Then she decides the offset:
  - `meta_digest` or `chunk_size` differ, or `prefix_sha256` differs from the hash of her file's prefix
    (source changed): grant `offset = 0` with `reason` (`source_changed`/`chunk_size`) and emit an explicit
    warning plus metric `resume_restart_reason`. Bob discards the `.part` and receives the whole file.
  - else grant `offset = next_chunk`.
- Bob checks the (authenticated) grant: `offset in {0, requested}`; the metadata's `resume_offset` must
  equal it and (offset > 0) `meta_digest` must match his sidecar.
- Capability mismatch is safe: if the peer has resume off, Bob (flag absent) skips 4c/4d and gets a plain
  restart; a Bob that sent a request to an Alice that ignores it gets a metadata message where the grant
  should be and falls back to a restart. A network attacker who strips or adds a flag can only cause a
  restart or a stall (bounded by a negotiation timeout); it never causes key or nonce reuse and never
  reveals data (see Risks).

### 2.3 Why a resumed stream cannot reuse a (key, nonce) pair
1. The file key is fresh per session (fresh BB84 bits, plus fresh hello nonces / ML-KEM key in the
   HKDF salt `T`). A resume runs the whole handshake again.
2. Independently, `describe_file` draws a fresh 8-byte `base_nonce` for every session, and the
   receiver refuses a resumed session whose `base_nonce` equals the one recorded in its sidecar.
3. Within one session the counter takes each value in `offset..num_chunks-1` at most once.
   Counters below `offset` are never used. `num_chunks <= 2**32` is enforced when metadata is built/parsed.
4. Resume messages use HKDF subkeys, so they live in a different key space from chunk nonces.

Tests pin 1 to 4 (derived keys differ across two sessions with the same inputs but fresh nonces; fresh
`base_nonce`; equal `base_nonce` refused; recorded (key, nonce) pairs of an original and a resumed
run are disjoint).

### 2.4 Receiver state on disk
Under `OUTPUT_DIR/.resume/`, keyed by transfer id (the filename is only known after the metadata
message, which comes after the resume negotiation, so Bob must find his state by id alone):
- `<transfer_id>.part`: only bytes that passed AES-GCM, written chunk by chunk.
- `<transfer_id>.json`: sidecar written atomically (tmp file, fsync, `os.replace`):
  `{v, transfer_id, filename, total_size, chunk_size, num_chunks, meta_digest, next_chunk, base_nonce,
  peer_fingerprint, auth_mode, updated_at}`.
  Updated every `QKD_RESUME_SYNC_CHUNKS` (default 8) verified chunks and on every error path, after an
  `fsync` of the `.part`. On load the `.part` is truncated to `next_chunk * chunk_size` (bytes beyond
  the sidecar are dropped), and if it is shorter the offset is lowered to the last full chunk it holds.
- On `InvalidTag` or `ConnectionError`: truncate to the last verified chunk boundary, flush the sidecar,
  re-raise. The final path is never created before every chunk verified, `written == total_size` and
  the SHA-256 of the whole `.part` equals the AAD-bound `sha256` from the metadata; then `os.replace`
  `.part` to the final name and delete the sidecar.
- Peer binding: the sidecar stores the authenticated peer fingerprint of the first session. A later
  session with a different fingerprint is refused (`PeerAuthError`) before the `.part` is touched.

### 2.5 Node, API, events
- New status `interrupted`: non-terminal, not ACTIVE. Entered from `transferring` when a runner reports
  outcome `interrupted` or dies after key confirmation with resume on. Exits: `pending` (resume),
  `cancelled`, `failed`. Kept in a separate extension table (D5).
- New runner outcome `interrupted`. New metrics `resumed_from_bytes`, `bytes_total`,
  `resume_restart_reason`: added to `node.py` `METRIC_FIELDS` (+ the copy in `events.py`),
  `api/models.py` (`Transfer`, `HistoryEntry`) and `app/frontend/src/api/types.js` in the same commit.
  No new stage names (negotiation runs inside `key_confirmation`).
- `POST /api/v1/transfers/{id}/resume` on the sender's interrupted outgoing transfer: re-offers it to the
  receiver with `IncomingTransferRequest.resume_transfer_id`; the receiver's interrupted incoming
  transfer goes back to `pending` for the user to accept (same consent step as a new transfer), then the
  normal accept flow launches bob with `--resume`, which PATCHes the sender, which launches alice
  `--resume`. Same transfer id throughout (D4).
- Persistence: interrupted transfers are written to `QKD_STATE_FILE` and reloaded on node start. The
  sender's upload is moved to a persistent directory next to the state file while interrupted.
  The receiver's truth is the sidecar. A history entry is appended when a transfer becomes interrupted.
- Progress starts at the offset: runners report `chunks_done`/`bytes_done` as absolute values.

### 2.6 UI
`interrupted` label, a Resume action in `TransferPanel` (outgoing) and an action in `TransferList`
rows, progress starting at the offset, `resumed_from_bytes` note, `interrupted` in the history table.

## 3. Milestones

| # | Content | Files | New tests | Gate |
|---|---|---|---|---|
| M1 | Crypto and storage primitives: resume subkeys + AEAD helpers, offset-aware `send/receive_encrypted_file`, `services/resume.py` (sidecar, `.part`, prefix hash), optional metadata fields (`sha256`, `resume_offset`), `written == total_size` + whole-file hash | `core/crypto_utils.py`, `core/config.py`, `services/file_stream.py`, `services/resume.py` | nonce disjointness, sidecar atomicity/recovery, drop after k chunks then resume is byte-identical, InvalidTag keeps only verified bytes, truncated stream never completes | full pytest |
| M2 | Protocol: `usecases/resume.py` (sealed request/grant and Bob's receipt), wiring in `send_file`/`receive_file`, the `finished` flag in `handshake.py`, runner `--resume` and the `interrupted` outcome; lockstep in `eavesdrop_demo`, `mitm_demo` (unchanged: it stops at key confirmation, tested), `tests/invariants/support.py` | `usecases/*`, `runner/alice.py`, `runner/bob.py`, `services/reporting.py`, `tests/invariants/support.py` | tampered request/grant/receipt abort before data, wrong identity refused, changed source restarts, one-sided resume, Eve and Mallory with resume on, real-process SIGKILL and resume in hybrid (`NUM_QUBITS=64`) | full pytest |
| M3 | Node/API/CLI: `interrupted` status + extension table, runner flags and outcome, persistence, `POST .../resume`, offer field, metrics, history | `services/node.py`, `transfer_store.py`, `api/*`, `peer_client.py`, `history.py`, `runner/*`, `events.py`, `app/frontend/src/api/types.js` | resume after node restart, interrupted in history, API 409s, offer carries resume id | full pytest |
| M4 | UI | `app/frontend/src/components/*`, `api/client.js` | (lint, build) | full pytest + lint + build |
| M5 | Docs | `README.md`, `CLAUDE.md`, this plan | | full pytest + lint + build |

One commit per milestone on `feature/resume`.

## 4. Decisions

- **D1 Opt-in.** `resume=None` keeps the wire and files identical; `QKD_RESUME` defaults to 0. Existing tests exercise only that path and stay unmodified. Resume-on wire changes are made in lockstep in `send_file`, `receive_file`, `eavesdrop_demo`, `mitm_demo` and the invariants proxy, in the M2 commit.
- **D2 `none` mode: resume disallowed.** There is no identity to bind a resume to, so anyone could continue or overwrite a partial transfer. A `--resume` request in none mode is ignored with a warning; the transfer fails as today.
- **D3 Capability flag in `finished`.** Not in the hello (the brief forbids it). It is unsigned, so it can only turn resume off or stall.
- **D4 Same transfer id for the resumed attempt.** One row per file in the UI; the sidecar's `transfer_id` is the binding. `interrupted -> pending` on the resume offer.
- **D5 Extension transition table.** `TRANSITIONS`/`can_transition` stay as they are (the existing closed-set test must pass unmodified); `TRANSITIONS[interrupted] = frozenset()` so lookups work, and the new edges live in `INTERRUPT_TRANSITIONS`, consulted by new `can_move`/`path_to`. New tests cover the new edges.
- **D6 InvalidTag mid-stream in resume mode becomes `interrupted`**, keeping the verified prefix (a resume uses a new key and re-verifies the prefix hash). Without `--resume` the old behaviour (delete the partial file, `failed`) is unchanged.
- **D7 Changed source: restart from 0 with an explicit warning and metric**, rather than abort. Nothing is lost compared with a fresh transfer and the final SHA-256 still protects the result.
- **D8 State is keyed by transfer id** (`.resume/<id>.part` + `.json`) rather than `<name>.part`: the filename is not known until after the negotiation, and two transfers of the same filename cannot clobber each other's state.
- **D9 Resume messages are AEAD-protected with HKDF subkeys**, not the file key, and bound to `T`.
- **D10 `sha256` goes into the metadata only in resume mode**, so the metadata message (and its AAD) is unchanged otherwise.
- **D11 Tampered resume request or grant is a `PeerAuthError`** (outcome `aborted_auth`).
- **D12 `QKD_RESUME_SYNC_CHUNKS` = 8**: a hard kill re-sends at most 7 verified chunks; the cost is one fsync per 8 chunks.

## 5. Risks

- Unsigned capability flag: a network attacker can force a restart or stall a negotiation (bounded by a timeout). They could already drop the connection. No confidentiality or integrity impact.
- Extra full read of the source file (SHA-256 for the metadata, plus the prefix hash) and of the `.part` at the end: IO cost on very large files.
- fsync cost per sync point; mitigated by `RESUME_SYNC_CHUNKS`.
- Lockstep drift between the use cases, Eve, Mallory and the proxy; mitigated by tests that run resume-on through each.
- The node's persistence file and the persistent upload copy add disk state that must be cleaned on cancel/complete.
- Real-Aer tests are slow; the resume invariants test uses `QKD_NUM_QUBITS=64`.
