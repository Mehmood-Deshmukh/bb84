# 1B — Paper claims vs. code (`scripts/paper/design_security.tex` @ commit 3c2f5f9)

Every concrete, checkable claim in the Design + Security sections, with its location in
the code and a verdict. **WRONG items are listed first.** Line numbers are from the
current `src/` at commit `3c2f5f9`.

## WRONG

| # | Claim (tex line) | Code location | Correct value / note |
|---|---|---|---|
| W1 | "Alice and Bob share one TCP connection with **Nagle's algorithm disabled**." (tex:91) | `services/wire.py:71–92` (`connect_with_retry`, `listen`) | **WRONG.** No `TCP_NODELAY` is set anywhere in `src/` (`grep -rn TCP_NODELAY src/` → none; the only `setsockopt` is `SO_REUSEADDR`, wire.py:89). Sockets therefore run with Nagle **enabled** (the OS default). Either disable Nagle in `wire.py` or drop the claim. |

## CAN'T VERIFY statically (behavioural — resolved by the planned experiments)

| # | Claim (tex) | Why / where it is tested |
|---|---|---|
| C1 | Partial Eve (f ≲ 0.3): "Keys differ; τ check fails (signed) or the first GCM tag fails (none)", stops at step 4b/5 (tex:261, 350–354, 366–371). | There is **no partial-f Eve in `src/`** (only full intercept-resend, quantum_channel.py:67). The mechanism is consistent with the code (none mode has no tag → InvalidTag at chunk 0; signed modes check τ at 4b), but the *rates* and *who-stops* are an experiment → **E2** (and E1). |
| C2 | fig:e1 measured rates: f=0.1 never caught by threshold; f=0.25 catch 0.13→0 from N=2048; f=0.5 catch 0.50→0.87; "all 20 within 95% Wilson" (tex:359–364). | No script/data exist for this (see 1C). Must be produced → **E1**. |
| C3 | fig:e2: hybrid stops every run 0.01≤f≤0.25 at key confirmation before any file byte; none fails only at Bob's GCM tag, Alice reports completed in all 150 runs (tex:366–371). | Marked by a `TODO` in the tex (tex:365). Must be produced → **E2**. |
| C4 | Each attacker row "backed by an end-to-end test" (tex:248). | Tests exist (`tests/invariants/`), but the paper's table is re-measured on current code → **E4**. |

## CONFIRMED

### Architecture / simulator
- "core imports nothing from the layers above, a test enforces this" — `tests/test_setup.py` (layering test). **CONFIRMED.**
- "Alice encodes each bit as a one-qubit circuit (X for bit 1, then H for the diagonal basis)" — `prepare_qubit` quantum_channel.py:36–55. **CONFIRMED.**
- "Bob measures all circuits as a **single simulator job**" — `measure_qubits` quantum_channel.py:137 (`_backend.run(circuits, shots=1, memory=True)`). **CONFIRMED.**
- "channel is noiseless … no information reconciliation step" — no reconciliation anywhere; bb84_protocol.py:9, receive_file.py:97. **CONFIRMED.**
- Three auth modes none/sign/hybrid; hybrid default; long-term ML-DSA-65 identity; TOFU or pinned — config.py:97, identity.py, handshake.py. **CONFIRMED.**

### Wire protocol / hello / Π
- "4-byte big-endian length prefix + JSON or raw bytes" — wire.py:33–41, `_LENGTH=">I"`. **CONFIRMED.**
- Hello carries v, mode, Π = (ℓ, ε_sec, ε_cor, Q_max, enforce) — `_hello` handshake.py:232 with `params.security_policy()` = `{final_key_bits, eps_sec, eps_cor, qber_threshold, enforce_finite_key}` (config.py:116). **CONFIRMED.**
- "signed modes add pk_id and a 32-byte nonce; hybrid adds pk_KEM (A) / ct_KEM (B)" — `_hello` lines 234–237, `NONCE_BYTES=32`, kem_pk/kem_ct. **CONFIRMED.**
- "receiver aborts on any mismatch in version, mode, or policy, with no fallback" — `_mismatch` handshake.py:247–254 (checks v, mode, params). **CONFIRMED.**
- "each side checks the peer's identity as soon as the hello arrives; Alice sends no qubits and Bob sends no hello until that check passes" — `alice_hello`/`bob_hello` call `verifier.check` before proceeding; Bob sends his hello only after (handshake.py:123–172). **CONFIRMED.**
- "Alice draws a fraction 0.15 of sifted positions from the OS CSPRNG" — `choose_sample_indices` bb84_protocol.py:80–88 (`secrets.SystemRandom().sample`). **CONFIRMED (sampling from OS CSPRNG).**
- "both abort if Q ≥ Q_max = 0.11" — `qber_exceeds_threshold` (`>=`) bb84_protocol.py:107; wired in send/receive via `report_qber_verdict`. **CONFIRMED.**
- "both compute the finite-key length and abort, without sending a message, if below ℓ" — `finite_key_verdict` common.py:92 called before the salt is sent/received (send_file.py:114, receive_file.py:101). **CONFIRMED.**
- "Alice sends a fresh Toeplitz seed (n+ℓ−1 bits)" — `{"salt": salt.hex()}` send_file.py:124, seed length `toeplitz_seed_bytes` = ⌈(n+ℓ−1)/8⌉ bytes. **CONFIRMED.**
- Message sequence Table 1 (0a,0b,1,2,3,4,4b,5; tracked/untracked flags) — matches send_file.py:4–13 / receive_file.py and `TranscriptChannel.send_json`(tracked) vs `send_untracked`(qubits, finished). **CONFIRMED.**

### Transcript, tag, signature
- Eq. (transcript) `T = SHA256(‖ d_i ‖ |c(m_i)|_32 ‖ c(m_i))`, d=0x00 Alice / 0x01 Bob, canonical JSON — transcript.py:52–66, `_DIR_ALICE=0x00`, `_DIR_BOB=0x01`. **CONFIRMED.**
- "qubits and finished are left out of T" — qubits via `send_untracked` (send_file.py:59); finished via `send_untracked` (handshake.py:196,210). **CONFIRMED.**
- Eq. (tag) `τ_R = HMAC_{K_conf}(λ_conf ‖ R ‖ T)`, `λ_conf = qkd-confirm-v1`, `|` separator — `confirmation_tag` handshake.py:217, `CONFIRM_PREFIX=b"qkd-confirm-v1|"`. **CONFIRMED.**
- Eq. (sig) `σ_R = Sign_{sk_R}(λ_fin ‖ R ‖ T ‖ τ_R)`, `λ_fin = qkd-finished-v1` — `finished_message` handshake.py:222 = `FINISHED_PREFIX + role + b"|" + T + tag`. **CONFIRMED** (label/role pipe-separated; T (32B) and τ (32B) fixed-length concatenated with no delimiter — the field boundaries are still unambiguous).
- "role label stops one side's signature being accepted as the other's" — role ∈ {`alice`,`bob`} bound in both τ and σ; `_verify_finished` passes the expected role (handshake.py:194, 212). **CONFIRMED.**
- "Bob sends first; Alice checks σ_B (auth error) then τ_B in constant time (key-confirmation error); only then sends hers; Bob checks Alice's the same way before reading metadata/creating a file" — `bob_finished`/`alice_finished` ordering (handshake.py:178–214), `hmac.compare_digest` (line 294), distinct `PeerAuthError`/`KeyConfirmationError`. **CONFIRMED.**
- "session key derived just before step 4b; nothing else uses it until both checks pass" — send_file.py:152–157, receive_file.py:142–147 (derive, then finished, then file). **CONFIRMED.**

### Session key / subkeys
- Eq. (sessionkey) three HKDF branches with salt = T (hybrid/sign) / ∅ (none) and labels `λ_hyb = bb84-mlkem768-hybrid-v1`, `λ_sig = bb84-sign-v1`, `λ_none = bb84-qkd-file-transfer` — `derive_session_key` crypto_utils.py:49–101. **CONFIRMED.**
- "none branch equals the pre-auth key" — none → `derive_aes_key(qkd_key)` (crypto_utils.py:99, 22). **CONFIRMED.**
- "HKDF-Expand → three 256-bit subkeys K_file/K_meta/K_conf, labels bb84-file-v1 / bb84-metadata-v1 / bb84-confirm-v1" — `key_schedule` crypto_utils.py:113–131. **CONFIRMED.**

### Bulk encryption
- "metadata (name, size, chunk size, chunk count, 8-byte base nonce) encrypted under K_meta, all-zero nonce, fixed AAD; safe because that subkey encrypts one message" — file_stream.py:39–40, 136–139. **CONFIRMED.**
- "chunk i under K_file with nonce b‖[i]_32, up to 2^32 chunks" — `derive_chunk_nonce` crypto_utils.py:209, `MAX_CHUNKS=1<<32`. **CONFIRMED.**
- "chunk AAD = SHA256(c(metadata))" — file_stream.py:181, 186. **CONFIRMED.**
- Receiver's three rules (≥1 chunk; reject chunk-count ≠ max(1,⌈size/chunk⌉); decrypted bytes = size; delete partial on failure) — file_stream.py:49, 107, 229–234. **CONFIRMED.**

### §6.3 key-length numbers — computed by calling `finite_key.secure_key_length` (not reimplemented)
With ε_sec=1e-10, ε_cor=1e-15, sample fraction 0.15, sifted ≈ N/2, k = max(1, ⌊0.15·sifted⌋), n = sifted − k:

| Claim (tex:326–335) | Computed | Verdict |
|---|---|---|
| fixed penalty ≈ 168 bits | leak_EC + log2(2/(ε_sec²ε_cor)) = 50.83 + 117.27 = **168.1** | **CONFIRMED** |
| N=8192: ~4096 survive sifting, k≈614, n≈3482, μ≈0.213, ℓ(Q=0)≈709 | sifted=4096, k=614, n=3482, μ=0.2133, **ℓ=709** | **CONFIRMED** |
| N=4096: ℓ≈34 | ℓ=**34** | **CONFIRMED** |
| N=128: none | ℓ=**0** | **CONFIRMED** |
| "8192 is the smallest power of two that supports 256 bits" | 4096→34, **8192→709**; 2048 and below →0 | **CONFIRMED** |
| bound < 256 for Q ≳ 8.4% | last Q with ℓ≥256 is Q=0.084 (ℓ=256); Q=0.085 → ℓ=252 | **CONFIRMED (≈8.4–8.5%)** |

### §6.4 detection model
- "each sifted bit wrong with probability p = f/4" (tex:342–343) — standard intercept-resend: wrong basis ½, flip ½, so p = f·¼. **CONFIRMED (model).** (Matches the full-Eve code at f=1 → p=0.25.)
- "finite-key bound stops f between about 0.34 and 0.44 at N=8192" (tex:349) — from the ℓ function: ℓ<256 at Q≳0.084 and threshold at Q=0.11; Q≈p=f/4 ⇒ f∈[4·0.084, 4·0.11] = **[0.336, 0.44]**. **CONFIRMED (derivation).**
- Threshold stop prob `P_QBER(f)=Pr[Bin(k,f/4) ≥ ⌈Q_max·k⌉]` (tex:347) — matches `qber_exceeds_threshold` (`>=`) and `choose_sample_indices` sample size. **CONFIRMED (model).**

### Table "attackers" — "stops at" per row (mechanism confirmed in code; rates/E2E are E4)
| Attacker | Claimed stop | Code mechanism | Verdict |
|---|---|---|---|
| Eve full intercept-resend | step 3, QBER ≈25% > Q_max | full `eve_intercept_resend` → high QBER → `report_qber_verdict` abort | **CONFIRMED (mechanism); rate via E4/E1 (f=1)** |
| Eve partial f≲0.3 | step 4b (τ, signed) / step 5 (GCM, none) | see C1 | **CAN'T VERIFY statically → E2/E4** |
| Mallory own key | step 0, trust check | `verifier.check` on hello → `PeerAuthError` | **CONFIRMED (mechanism); E4** |
| Mallory relay | step 4b, cannot produce σ_B | σ verified under pinned Bob key; relay lacks Bob's seed | **CONFIRMED (mechanism); E4** |
| Classical tamperer | step 4b, T differs → σ fails | tracked messages change T; σ over T fails | **CONFIRMED (mechanism); E4 (6 cases)** |
| Metadata tamperer | step 5, GCM tag / chunk-count rule | metadata AAD + `from_message` rule | **CONFIRMED (mechanism); E4** |
| Replayer | step 4b, fresh nonce/KEM makes T unique | 32-byte `os.urandom` nonce in hello, ephemeral KEM | **CONFIRMED (mechanism); E4** |
| Downgrader | step 0, mode+policy in hello, bound into T | `_mismatch` on mode/params | **CONFIRMED (mechanism); E4** |
| Recorder (future KEM break) | n/a; K_QKD independent input | hybrid ikm = qkd_key‖kem_ss | **CONFIRMED (design claim)** |

### §6.4 narrative to be re-measured, not statically checkable
- "In hybrid the same relay still fails, now at the **tag** check, because the KEM secret belongs to Bob" (tex:284–286) — plausible (Mallory's KEM secret differs → different session key → τ mismatch), but this is an E2E behaviour → **E4 new row** (relay control with Bob's real key in BOTH sign and hybrid).
