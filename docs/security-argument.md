# Security argument: the authenticated classical channel

This note explains why the authentication layer added to this BB84 implementation
stops an active man-in-the-middle, and why the session key is derived the way it is.
It is written for a reviewer who knows BB84 and basic cryptography but not this
codebase. Every claim points at the file, function, or test that backs it. These are
informal arguments under stated assumptions, not formal proofs.

The authentication layer lives in `src/qkd/usecases/handshake.py`; the key combiner
is `derive_session_key` in `src/qkd/core/crypto_utils.py`; the post-quantum
primitives are in `src/qkd/core/pqc.py`; the transcript hash is
`src/qkd/services/transcript.py`. The three authentication modes are `none`, `sign`,
and `hybrid`, selected per node by `QKD_AUTH_MODE` (default `hybrid`,
`src/qkd/core/config.py` `AUTH_MODE`).

## 1. The gap

BB84's security proof assumes the *classical* channel is authenticated: Alice and
Bob can talk, an eavesdropper may listen and even inject, but each side knows that a
classical message claiming to be from the other really is. The quantum channel needs
no such assumption — that is the point of BB84 — but the basis reconciliation and
error-estimation steps that follow are ordinary classical messages, and the proof
leans on their integrity.

Our classical channel was plain TCP with no authentication. That opens a gap that
QBER cannot close. Consider Mallory sitting in the middle, running **two** honest
BB84 sessions: one with Alice (where Mallory plays Bob) and one with Bob (where
Mallory plays Alice). Each session is, on its own, a textbook BB84 run over a
noiseless channel. Mallory prepares and measures real qubits with each partner, so
each session's QBER is exactly 0%. The QBER check — the only eavesdropper detector
BB84 itself provides — therefore passes on both sides. Mallory ends up holding one
key shared with Alice and a different key shared with Bob; she decrypts every file
Alice sends, reads it, and re-encrypts it to Bob, who sees a clean transfer. Nobody's
QBER ever rises.

This is demonstrated directly: `test_mitm_auth_off`
(`tests/invariants/test_mitm.py`) runs Alice, Bob, and Mallory (`run_mitm` in
`src/qkd/usecases/mitm_demo.py`, strategy `own_key`) with authentication off. It
asserts that both legs report `qber == 0.0`, that Mallory's recovered
`plaintext_sha256` equals the SHA-256 of Alice's source file, and that Bob's received
file is byte-identical to the original. QBER is blind to this attack because, from
the quantum channel's point of view, nothing is wrong.

The fix is to authenticate the classical channel so that Mallory cannot
convincingly be Bob to Alice (or Alice to Bob) without a secret she does not have.

## 2. Threat model

| Attacker | Capability | What stops it | Evidence |
|---|---|---|---|
| Eve (intercept-resend on the quantum channel) | Measures and re-sends qubits; relays classical messages | QBER rises ~25%, both sides abort at step 3 before any key use | `test_eve_with_hybrid_aborts_on_qber` |
| Mallory, own key (impersonation at first message) | Full in-path control; presents her own identity key | Pinned peer key does not match hers; the hello is rejected before any qubit is sent | `test_mitm_auth_on_own_key`, `test_wrong_pin_rejected_before_qubits` |
| Mallory, relay (forwards the real hellos) | Relays both hellos, runs BB84 against each side | She cannot sign the transcript as Bob; the `finished` check fails at key confirmation | `test_mitm_auth_on_relay_hello` |
| Tamperer (alters a classical message) | Flips or reorders any tracked message | The two transcripts diverge, so the signature over the transcript fails | `test_classical_tamper_caught_by_signature` |
| Tamperer (alters file metadata) | Changes the metadata message after authentication | Metadata is bound as AES-GCM additional data; chunk 0 fails its tag | `test_metadata_tamper_caught_by_aad` |
| Replayer | Captures a `finished` signature and replays it later | Fresh 32-byte nonces and a fresh ML-KEM key make each transcript unique | `test_finished_replayed_from_previous_session_is_rejected` |
| Store-now-decrypt-later | Records traffic; breaks ML-KEM in the future | The QKD key is an independent secret input to the combiner | argument in §9 |
| Future break of the QKD implementation | Recovers the QKD key (e.g. a weak RNG) | The ML-KEM shared secret is an independent secret input | argument in §9 |

Assumptions throughout:

- Private signing and KEM seeds never leave the node (they live in the node's
  `AuthContext`; `src/qkd/usecases/common.py`).
- First contact is either pinned out of band or accepted under trust-on-first-use
  (`QKD_TOFU`, `src/qkd/core/config.py`). A man-in-the-middle present at the very
  first contact under TOFU is out of scope (see §11).
- ML-DSA-65 (FIPS 204) and ML-KEM-768 (FIPS 203), both NIST security category 3, are
  secure: signatures are unforgeable and the KEM is IND-CCA2. These are provided by
  `cryptography`'s `mldsa`/`mlkem` (`src/qkd/core/pqc.py`); if the installed
  `cryptography` lacks them, import fails with a clear version error.
- SHA-256 is collision-resistant (used for the transcript and the metadata AAD).

## 3. Why signatures, not only a KEM

A natural first instinct is: just do a post-quantum key exchange (ML-KEM) and mix its
shared secret into the key. That stops a *passive* recorder, but not Mallory. An
ephemeral ML-KEM exchange is **unauthenticated**: nothing in an encapsulation ties it
to a particular party. Mallory can run one ML-KEM exchange with Alice and a second,
independent one with Bob, exactly as she runs two BB84 sessions in §1. She would then
know both KEM secrets and both resulting keys. A KEM alone moves the problem without
solving it.

What Mallory cannot do is produce a signature that verifies under a long-term key she
does not hold. So authentication rests on an ML-DSA signature (`pqc.sign`,
`pqc.verify`) made with a per-node identity seed, over a value that captures the whole
session. The KEM is still valuable — it contributes post-quantum secrecy to the key
(§9) — but it is the *signature* that stops impersonation. The hybrid mode uses both;
`sign` mode uses the signature without the KEM.

## 4. The transcript

Both sides maintain a running SHA-256 over the classical messages, in
`TranscriptChannel` (`src/qkd/services/transcript.py`). Each *tracked* message is
folded in as:

```
direction byte (1 byte) || length (4 bytes, big-endian) || canonical JSON payload
```

The direction byte is `0x00` for a message Alice sent and `0x01` for a message Bob
sent (`_DIR_ALICE`, `_DIR_BOB`). The payload is canonical JSON — sorted keys, compact
separators, UTF-8 (`_canonical_json`) — so both sides serialize identically and hash
identical bytes. The final digest is `T = channel.digest()`. Each design choice earns
its place:

- **Direction bytes** make the transcript a record of *who said what*. Without them, a
  message reflected back to its sender, or two messages swapped in direction, could
  hash the same. Tagging each message with its sender prevents reordering and
  reflection from producing a matching transcript.
- **Both hellos are tracked** (steps 0a and 0b; `alice_hello`/`bob_hello` call
  `channel.send_json`/`recv_json`). This binds, into `T`, both identity public keys,
  both 32-byte nonces, the negotiated mode, and — in hybrid — Alice's KEM public key
  and Bob's KEM ciphertext. A signature over `T` therefore vouches for the entire
  negotiated context, not just the later BB84 messages.
- **Qubits are excluded** (step 1 is sent with `send_untracked`/`recv_untracked`).
  The qubit stream is the simulated quantum channel; its integrity is the job of the
  QBER check, not the signature. Leaving qubits out of `T` keeps the division of
  labour clean: an eavesdropper on the quantum channel (Eve) is caught by rising QBER
  at step 3, before the signature step is ever reached (§10), rather than by a
  transcript mismatch.
- **`finished` is excluded** from `T` because it *is* the signature over `T`; a value
  cannot sign itself. The two `finished` messages are sent untracked (`alice_finished`,
  `bob_finished`).
- **Role labels** distinguish the two signatures. Bob signs
  `b"qkd-finished-v1|bob|" + T` and Alice signs `b"qkd-finished-v1|alice|" + T`
  (`FINISHED_PREFIX` and the `b"bob"`/`b"alice"` role in `_finished`). The label stops
  one side's signature from being accepted as the other's: Alice verifies Bob's
  message against the `bob` label and Bob verifies Alice's against the `alice` label
  (`_verify_finished`), so a signature made for one role will not validate for the
  other even though both are over the same `T`.

## 5. Why signing once at the end is enough

The signature is exchanged once, at step 4b, after the salt. That is safe because
**no key is used and no file byte moves before 4b completes**, and each side verifies
the other before doing anything that depends on the peer.

On Alice's side (`send_file`, `src/qkd/usecases/send_file.py`): she runs
`alice_hello`, then the BB84 `run_key_exchange` (which ends by sending the salt), then
computes `T`, then — in sign/hybrid — calls `alice_finished`. `alice_finished`
**receives and verifies Bob's signature first**, and only then sends her own. She
derives the session key and calls `send_encrypted_file` *after* `alice_finished`
returns. So if Bob's signature does not verify, she raises before computing the key or
sending a single ciphertext byte.

On Bob's side (`receive_file`, `src/qkd/usecases/receive_file.py`): he runs
`bob_hello`, then `run_key_exchange` (which receives the salt), then computes `T`,
then calls `bob_finished`. `bob_finished` sends his signature and then **verifies
Alice's**. Only after it returns does Bob call `receive_file_meta`, `os.makedirs`, and
`receive_encrypted_file`. So if Alice's signature does not verify, Bob raises before
reading the metadata, creating the output directory, or opening any file.

Because the signature covers `T`, which already contains the hellos and every tracked
BB84 message, one signature at the end authenticates the whole conversation
retroactively; there is no need to sign each message as it goes.

## 6. Tampering

Suppose an in-path attacker changes one tracked classical message. The sender folds
the original into its transcript (as sent); the receiver folds the altered version
into its transcript (as received). The two transcripts now differ, so the two digests
`T` differ. Bob signs his `T`; Alice verifies that signature against her `T`; because
ML-DSA is unforgeable and SHA-256 is collision-resistant, a signature valid for Bob's
`T` does not validate against Alice's different `T`, and the check fails. The change
is caught no matter which message was touched, as long as it is tracked.

The test design isolates this mechanism deliberately. `tests/invariants/test_tamper.py`
runs honest, mutually pinned Alice and Bob in hybrid mode with a proxy
(`tests/invariants/support.py`, `proxy`) that rewrites exactly one message. Crucially
it sets `qber_threshold` above 1.0 on both sides, so the QBER check can *never* abort
— the signature is then the only thing that can possibly catch the change. Six cases
are covered (`test_classical_tamper_caught_by_signature`, parametrized): the bases, the
matching indices, the sample indices, the sample bits, the QBER value, and the salt.
Each tamper function asserts it actually changed the message (via `_changed`), so a
no-op tamper cannot pass silently. Every case expects Alice to raise a
`PeerAuthError` whose reason contains `"signature"` at the `key_confirmation` stage,
with no `file_transfer` stage and no output directory. A companion control,
`test_untampered_proxy_run_succeeds`, runs the same setup with no tamper and asserts
the transfer completes and the file is byte-identical — proving the proxy and the
disabled threshold do not themselves break anything, so the six failures are caused by
the tampering alone.

The file metadata is a special case because it is sent at step 5, *after* 4b, so it is
not in `T`. Instead it is bound as AES-GCM additional authenticated data: the sender
computes `metadata_aad(msg)` (SHA-256 of the canonical JSON of the metadata message,
`src/qkd/services/file_stream.py`) and passes it as AAD to every chunk; the receiver
recomputes the AAD from the *raw metadata message it received* and uses it to decrypt.
If the metadata was altered in flight, the AAD differs and chunk 0 fails its GCM tag.
`test_metadata_tamper_caught_by_aad` changes the filename and asserts Bob raises
`InvalidTag`, that no chunk was reported written, and that the partial file is removed.

## 7. Impersonation results

Mallory is implemented in `src/qkd/usecases/mitm_demo.py` with two strategies.

**Own key** (`_own_key`). Mallory presents her own identity key to each side. When
Alice is pinned to Bob, Alice's `alice_hello` parses Mallory's hello, reports her
fingerprint, and calls `verifier.check` — which rejects the unexpected key and raises
`PeerAuthError` *before any qubit is sent*. `test_mitm_auth_on_own_key` (sign and
hybrid) asserts Alice's last stage is `authentication`, that she never reached
`quantum_transmission`, that the fingerprint Alice recorded is Mallory's, that Mallory
recovered no plaintext, and that Bob's output directory never appears.
`test_wrong_pin_rejected_before_qubits` makes the same point at the use-case level.

**Relay** (`_relay_hello`). Mallory forwards Alice's and Bob's real hellos unchanged
and runs Bob's side of the key exchange against Alice, hashing the relayed messages
into her own `TranscriptChannel` exactly as Bob would. Her transcript therefore equals
Alice's `T`. But at step 4b she must send `qkd-finished-v1|bob|T` signed with *Bob's*
seed, which she does not have; she signs with her own seed instead. Alice verifies
against Bob's pinned public key and the check fails.
`test_mitm_auth_on_relay_hello` asserts Alice raises with `"signature"` in the reason,
at the `key_confirmation` stage, having never reached `file_transfer`, and that the
fingerprint Alice recorded is **Bob's real** fingerprint (the relay did carry Bob's
key), while Mallory still gets no plaintext.

The relay result has a subtle gap a reviewer should want closed: maybe the relay fails
for some incidental reason — a transcript that silently diverged — rather than because
Mallory lacks Bob's key. `test_relay_control_with_bobs_key_passes_key_confirmation`
closes it. It runs the identical relay but hands Mallory **Bob's real `(pk, seed)`**.
Now the relay passes `key_confirmation` and reaches `file_transfer`. This proves two
things at once: Mallory's relayed transcript is bit-for-bit what Alice computed (or the
signature over it could not have verified), and the only thing standing between the
relay and success was possession of Bob's private key.

## 8. Replay and downgrade

**Replay.** Each hello carries a fresh 32-byte nonce (`os.urandom(NONCE_BYTES)` in
`_hello`), and in hybrid each session also uses a fresh ML-KEM keypair
(`pqc.kem_keygen` in `alice_hello`). Both are tracked, so every session's `T` is
unique with overwhelming probability, and a `finished` signature captured in one
session is a signature over that session's `T` only. Replaying it into a later session
fails, because the later `T` differs.
`test_finished_replayed_from_previous_session_is_rejected`
(`tests/usecases/test_handshake.py`) captures Bob's `finished` from one session and
feeds it into a second; verification raises `PeerAuthError`.

**Downgrade.** An attacker might try to force the weaker `sign` or `none` mode. This
cannot be done silently: every mode — including `none` — sends a hello whose `mode`
field is tracked into `T`, and each side checks the peer's advertised mode against its
own (`_mismatch` in `handshake.py`). On any mismatch both sides raise `PeerAuthError`
("mode mismatch"), and there is no fallback or renegotiation. `test_downgrade_rejected`
runs Alice in hybrid against Bob in none and vice versa, and asserts both sides raise
with "mode mismatch" and no file is written. A node's mode is a fixed policy, not
something negotiated down over the wire.

## 9. The hybrid key

In hybrid mode the session key is

```
K = HKDF-SHA256(ikm = K_QKD || ss_KEM, salt = T, info = "bb84-mlkem768-hybrid-v1")
```

where `K_QKD` is the 32-byte QKD key from privacy amplification, `ss_KEM` is the
32-byte ML-KEM-768 shared secret, and `T` is the transcript digest
(`derive_session_key`, `src/qkd/core/crypto_utils.py`). `test_known_answer_hkdf`
(`tests/core/test_session_key.py`) pins this against an independent HKDF computation.

**Secrecy if either input is secret.** HKDF-Extract is HMAC-SHA256 keyed by the salt,
applied to the input keying material; it is designed to act as a randomness extractor,
producing a pseudorandom key as long as the input keying material has enough secret
entropy. Here the input is the concatenation `K_QKD || ss_KEM`. Informally: if *either*
half is uniform and unknown to the attacker, the concatenation has ~256 bits of secret
entropy from the attacker's view, and the extracted key is pseudorandom to them. So `K`
stays secret unless the attacker learns *both* `K_QKD` and `ss_KEM`. This is an
assumption about HKDF/HMAC as an extractor, stated here explicitly, not a proof.

This yields defence in depth against two future failures:

- **Store-now-decrypt-later.** An attacker records the traffic and, years on, breaks
  ML-KEM and recovers `ss_KEM`. They still lack `K_QKD`: the QKD key never crosses the
  wire — it comes from the sifted quantum bits, and an eavesdropper who measured those
  qubits would have raised QBER and been caught. So `K` remains secret.
- **QKD implementation leak.** Suppose the QKD side is later found weak (for instance
  this project's RNG is the Aer simulator, a pseudo-random source) and `K_QKD` becomes
  predictable. The attacker still lacks `ss_KEM`, which is protected by ML-KEM. So `K`
  remains secret.

Two more details:

- **`salt = T`** binds `K` to this exact session's transcript, so even with identical
  inputs two different negotiations yield different keys, and a key cannot be lifted
  from one session into another.
- **`sign` mode** drops `ss_KEM` (ikm is `K_QKD` alone) and uses a **different** info
  label, `"bb84-sign-v1"`, for explicit domain separation from hybrid, so the two modes
  never derive the same key from the same inputs (`test_known_answer_hkdf_sign`,
  `test_sign_and_hybrid_keys_differ`).
- **`none` mode** returns `derive_aes_key(qkd_key)` — HKDF-SHA256 with
  `info="bb84-qkd-file-transfer"` and no salt — which is exactly the pre-feature key,
  so `none` is directly comparable to the original system
  (`test_none_mode_session_key_is_legacy_key`,
  `test_none_mode_equals_derive_aes_key`).

## 10. Eve is still caught by QBER

Adding authentication does not weaken BB84's own defence against a quantum-channel
eavesdropper. Eve (`src/qkd/usecases/eavesdrop_demo.py`) forwards the hellos unchanged
(`_forward_hellos`), so the hello handshake itself has no reason to reject her. But her
intercept-resend disturbs roughly 25% of the sifted bits, driving QBER over the
threshold, so both sides abort at step 3 — the QBER check — *before* the `finished`
exchange at 4b is ever reached. `test_eve_with_hybrid_aborts_on_qber`
(`tests/invariants/test_signed_handshake.py`) runs Eve between a pinned Alice and Bob
in hybrid mode (sampling every sifted bit, threshold 0.01) and asserts both sides abort
on QBER, that both nonetheless recorded `peer_trust == "pinned"` (the hellos did
authenticate), and that `key_confirmation` never happened. Authentication and QBER are
complementary: the hello/finished layer stops impersonation and tampering of the
classical channel; QBER still stops interference with the quantum channel.

## 11. Limitations

- **Denial of service is out of scope.** An in-path attacker can always cut the
  connection; the goal here is to prevent a *silent* compromise, not to guarantee
  delivery.
- **TOFU first contact.** With trust-on-first-use, a man-in-the-middle present at the
  very first contact can have their key pinned. Out-of-band pinning avoids this; TOFU
  only protects contacts after the first.
- **Qubits share the TCP connection.** The "quantum" channel is a stream of QASM
  circuits over the same TCP socket (a simulation artefact). On real hardware the
  quantum and classical channels would be separate.
- **Noiseless channel, no reconciliation.** The simulated channel has no noise, so
  there is no information reconciliation step; any non-zero QBER is attributed to an
  eavesdropper.
- **Trust is pinned per peer; there is no PKI.** Keys are pinned or accepted under
  TOFU per peer, with no certificate authority or revocation.
- **Error surfaced to the rejecting peer's partner.** When one side rejects the other
  and closes the connection, the partner often observes a plain connection error rather
  than an authentication error (for example Bob sees a closed socket while waiting for
  qubits after Alice rejects his key). The security outcome — nothing is sent or
  written — is unchanged; only the reported reason differs.
- **Key material was removed from logs** in commit `deeddd5` ("fix: stop logging key
  material"); earlier the derived key's hex prefix was logged.

## 12. Evidence summary

| Claim | Test (file::name) | What it asserts |
|---|---|---|
| The gap is real with auth off | `test_mitm.py::test_mitm_auth_off` | Mallory relays the file and recovers the plaintext; both legs' QBER 0 |
| Honest sign/hybrid transfer works | `test_signed_handshake.py::test_honest_transfer` | Byte-identical file, both peers pinned, stages in order |
| Own-key impersonation stopped at hello | `test_mitm.py::test_mitm_auth_on_own_key` | Alice raises at `authentication`; no qubits; Mallory gets nothing |
| Wrong pin stops Alice before qubits | `test_signed_handshake.py::test_wrong_pin_rejected_before_qubits` | `PeerAuthError`; no output dir |
| Relay stopped at key confirmation | `test_mitm.py::test_mitm_auth_on_relay_hello` | Alice raises with "signature" at `key_confirmation`; peer fingerprint is Bob's |
| Relayed transcript is exact | `test_mitm.py::test_relay_control_with_bobs_key_passes_key_confirmation` | With Bob's key, the relay passes `key_confirmation` |
| Classical tamper caught by signature | `test_tamper.py::test_classical_tamper_caught_by_signature` | Six tampers each raise "signature" at `key_confirmation`; no transfer |
| Metadata tamper caught by AAD | `test_tamper.py::test_metadata_tamper_caught_by_aad` | `InvalidTag` on chunk 0; no partial file |
| Untampered control succeeds | `test_tamper.py::test_untampered_proxy_run_succeeds` | Clean transfer with the proxy and disabled threshold |
| Replay rejected | `test_handshake.py::test_finished_replayed_from_previous_session_is_rejected` | Old `finished` fails in a new session |
| Downgrade rejected | `test_signed_handshake.py::test_downgrade_rejected` | Mode mismatch aborts both sides |
| Eve caught by QBER (hybrid) | `test_signed_handshake.py::test_eve_with_hybrid_aborts_on_qber` | Abort at step 3 before 4b; hellos still authenticated |
| Key combiner matches spec | `test_session_key.py::test_known_answer_hkdf`, `::test_known_answer_hkdf_sign` | Independent HKDF reproduces hybrid and sign keys |
| `none` equals the legacy key | `test_session_key.py::test_none_mode_equals_derive_aes_key` | `none` returns `derive_aes_key(qkd_key)` |
| Fingerprint format pinned | `test_pqc.py::test_fingerprint_known_answer` | Fixed 1952-byte key maps to a fixed fingerprint |

The full test suite is **350 tests** (`pytest -q`), of which `tests/invariants/`
exercises the handshake, MITM, and tamper behaviours above against the real Aer
simulator.

## 13. Overhead

*Placeholder for Person B's benchmark numbers.* To be filled in with measured
`handshake_ms`, `auth_overhead_bytes`, and total transfer time for `none`, `sign`, and
`hybrid` at 128 qubits and a 1 MB payload. **No numbers are invented here.**

What can be stated from the code are the per-message sizes that drive the overhead
(`src/qkd/core/pqc.py`, `src/qkd/usecases/handshake.py`):

| Field | Size | Appears in |
|---|---|---|
| Identity public key `id_pk` (ML-DSA-65) | 1952 bytes | hello (sign, hybrid) |
| KEM public key `kem_pk` (ML-KEM-768) | 1184 bytes | Alice's hello (hybrid) |
| KEM ciphertext `kem_ct` (ML-KEM-768) | 1088 bytes | Bob's hello (hybrid) |
| Signature (ML-DSA-65) | 3309 bytes | each `finished` (sign, hybrid) |
| Nonce | 32 bytes | hello (sign, hybrid) |

Binary fields travel base64-encoded inside JSON, so on-wire sizes are about 4/3 of the
raw sizes plus JSON framing. `auth_overhead_bytes` (reported by the handshake,
`_report_cost`) counts the actual framed bytes of the hello and finished messages, sent
plus received, and is the figure Person B's benchmark should report.
