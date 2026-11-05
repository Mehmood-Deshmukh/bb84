"""
Module 12: Acceptance Test Matrix (Shared Spec Verification).

Coordinates and verifies the full shared acceptance-test matrix from the spec's
"Testing and acceptance" section:
1. Honest hybrid transfer with pinned keys: byte-identical output file, peer_trust: pinned both sides.
2. MITM, auth off: both QBER 0%, Mallory reports correct plaintext SHA-256.
3. MITM, auth on (own identity): aborted_auth at authentication, no qubits/file bytes sent, Bob's received/ empty.
4. MITM, auth on (Bob's real hello relayed): fails at key_confirmation.
5. Eve under hybrid: aborted_qber, not aborted_auth.
6. Tamper, once per classical message (bases, matching indices, sample bits, qber, salt, metadata):
   every case aborts before the first chunk is decrypted.
7. Downgrade: one side hybrid, other none — both abort, neither falls back.
8. Private identity material never leaves the local machine (no seed bytes on the wire, 0600 mode).
9. tests/test_setup.py import-boundary assertions still pass unchanged.
"""

from __future__ import annotations

import os
import socket
import stat
import threading
from pathlib import Path
from typing import Any

import pytest

from qkd.core.config import ProtocolParams
from qkd.services.identity import load_or_create_identity
from qkd.services.reporting import NullReporter
from qkd.usecases.common import AuthContext
from qkd.usecases.receive_file import receive_file
from qkd.usecases.send_file import send_file
import tests.invariants.test_mitm as tm
import tests.invariants.test_signed_handshake as tsh
import tests.invariants.test_tamper as tt
from tests.invariants.support import keys  # noqa: F401 - pytest fixture

PARAMS = ProtocolParams()  # default N with the finite-key gate on


class DummyVerifier:
    def __init__(self, trust_status: str = "pinned") -> None:
        self.trust_status = trust_status

    def check(self, peer_public_key: bytes) -> str:
        return self.trust_status


# ── Item 1: Honest transfer with pinned keys ───────────────────────────────

def test_acceptance_item_1_honest_transfer_byte_identical(parallel, make_file, same_file, tmp_path: Path) -> None:
    """Item 1: Honest transfer produces byte-identical output file on disk."""
    src = make_file("payload.bin", 150_000)
    out_dir = tmp_path / "received"
    alice_id = load_or_create_identity(tmp_path / "id_a")
    bob_id = load_or_create_identity(tmp_path / "id_b")

    auth_a = AuthContext(
        mode="hybrid",
        public_key=alice_id.public_key,
        seed=(tmp_path / "id_a" / "identity.seed").read_bytes(),
        verifier=DummyVerifier("pinned"),
    )
    auth_b = AuthContext(
        mode="hybrid",
        public_key=bob_id.public_key,
        seed=(tmp_path / "id_b" / "identity.seed").read_bytes(),
        verifier=DummyVerifier("pinned"),
    )

    alice_sock, bob_sock = socket.socketpair()
    with alice_sock, bob_sock:
        sent, got = parallel(
            lambda: send_file(alice_sock, str(src), NullReporter(), PARAMS, auth=auth_a),
            lambda: receive_file(bob_sock, str(out_dir), NullReporter(), PARAMS, auth=auth_b),
        )

    assert not sent.aborted, "Alice transfer aborted on honest channel"
    assert not got.key_exchange.aborted, "Bob transfer aborted on honest channel"
    assert got.bytes_written == 150_000
    assert same_file(src, Path(got.output_path)), "Transferred file differs from source"


# ── Item 2: MITM, auth off ──────────────────────────────────────────────────

def test_acceptance_item_2_mitm_auth_off(parallel, make_file, same_file, tmp_path: Path) -> None:
    """Item 2: MITM, auth off: both QBER 0%, Mallory reports correct plaintext SHA-256."""
    tm.test_mitm_auth_off(parallel, make_file, same_file, tmp_path)


# ── Item 3: MITM, auth on (own identity) ────────────────────────────────────

def test_acceptance_item_3_mitm_auth_on_own_identity(keys, parallel, make_file, tmp_path: Path) -> None:
    """Item 3: MITM, auth on (own identity): aborted_auth at authentication, no qubits/file bytes sent."""
    tm.test_mitm_auth_on_own_key("hybrid", keys, parallel, make_file, tmp_path)


# ── Item 4: MITM, auth on (relay hello) ─────────────────────────────────────

def test_acceptance_item_4_mitm_auth_on_relay_hello(keys, parallel, make_file, tmp_path: Path) -> None:
    """Item 4: MITM, auth on (Bob's real hello relayed): fails at key_confirmation."""
    tm.test_mitm_auth_on_relay_hello("hybrid", keys, parallel, make_file, tmp_path)


# ── Item 5: Eve under hybrid triggers aborted_qber, not aborted_auth ─────────

def test_acceptance_item_5_eve_under_hybrid_causes_aborted_qber_not_aborted_auth(keys, parallel, make_file, tmp_path: Path) -> None:
    """Item 5: Eve intercept-resend attack under hybrid mode triggers aborted_qber, not aborted_auth."""
    tsh.test_eve_with_hybrid_aborts_on_qber(keys, parallel, make_file, tmp_path)


# ── Item 6: Classical message tampering ─────────────────────────────────────

@pytest.mark.parametrize(
    "step, tamper",
    [
        ("2-bases", tt.t_bases),
        ("2-matching", tt.t_matching),
        ("3-sample_indices", tt.t_sample_indices),
        ("3-sample_bits", tt.t_sample_bits),
        ("3-qber", tt.t_qber),
        ("4-salt", tt.t_salt),
    ],
)
def test_acceptance_item_6_tamper_classical_messages_aborts(step, tamper, keys, parallel, make_file, tmp_path: Path) -> None:
    """
    Item 6: Tampering with classical messages causes transfer to abort before
    any file chunk is transferred.
    """
    tt.test_classical_tamper_caught_by_signature(step, tamper, keys, parallel, make_file, tmp_path)


def test_acceptance_item_6_metadata_tamper_aborts(keys, parallel, make_file, tmp_path: Path) -> None:
    """Item 6: File metadata tampering is caught by the metadata's own AES-GCM tag."""
    tt.test_metadata_tamper_caught_by_aad(keys, parallel, make_file, tmp_path)


# ── Item 7: Downgrade attack rejection ──────────────────────────────────────

@pytest.mark.parametrize("alice_mode, bob_mode", [("hybrid", "none"), ("none", "hybrid")])
def test_acceptance_item_7_downgrade_hybrid_vs_none_aborts(alice_mode: str, bob_mode: str, keys, connected, make_file, tmp_path: Path) -> None:
    """Item 7: One side hybrid, other none — both abort, neither falls back."""
    tsh.test_downgrade_rejected(alice_mode, bob_mode, keys, connected, make_file, tmp_path)


# ── Item 8: Private identity material never leaves local machine ────────────

def test_acceptance_item_8_private_identity_seed_safety(tmp_path: Path) -> None:
    """
    Item 8: Private identity material never leaves local machine:
    1. identity.seed is stored with mode 0600.
    2. Zero seed bytes or slices ever appear in wire traffic.
    """
    alice_id_dir = tmp_path / "alice_id"
    bob_id_dir = tmp_path / "bob_id"
    alice_id = load_or_create_identity(alice_id_dir)
    bob_id = load_or_create_identity(bob_id_dir)

    alice_seed_path = alice_id_dir / "identity.seed"
    bob_seed_path = bob_id_dir / "identity.seed"

    # Assert 0600 mode permissions
    mode_a = oct(stat.S_IMODE(alice_seed_path.stat().st_mode))
    mode_b = oct(stat.S_IMODE(bob_seed_path.stat().st_mode))
    assert mode_a == "0o600", f"Alice seed permissions must be 0600, got {mode_a}"
    assert mode_b == "0o600", f"Bob seed permissions must be 0600, got {mode_b}"

    alice_seed = alice_seed_path.read_bytes()
    bob_seed = bob_seed_path.read_bytes()
    assert len(alice_seed) == 32
    assert len(bob_seed) == 32

    # Capture all wire traffic during real transfer
    src = tmp_path / "test.bin"
    src.write_bytes(os.urandom(25_000))
    out_dir = tmp_path / "received"

    alice_sock, wire_a = socket.socketpair()
    wire_b, bob_sock = socket.socketpair()

    captured_bytes = bytearray()
    lock = threading.Lock()

    def forward(src_s: socket.socket, dst_s: socket.socket) -> None:
        try:
            while True:
                data = src_s.recv(4096)
                if not data:
                    break
                with lock:
                    captured_bytes.extend(data)
                dst_s.sendall(data)
        except Exception:
            pass
        finally:
            try:
                dst_s.close()
            except Exception:
                pass

    t1 = threading.Thread(target=forward, args=(wire_a, wire_b))
    t2 = threading.Thread(target=forward, args=(wire_b, wire_a))
    t1.start()
    t2.start()

    auth_a = AuthContext(mode="hybrid", public_key=alice_id.public_key, seed=alice_seed, verifier=DummyVerifier())
    auth_b = AuthContext(mode="hybrid", public_key=bob_id.public_key, seed=bob_seed, verifier=DummyVerifier())

    def run_alice() -> None:
        with alice_sock:
            send_file(alice_sock, str(src), NullReporter(), PARAMS, auth=auth_a)

    def run_bob() -> None:
        with bob_sock:
            receive_file(bob_sock, str(out_dir), NullReporter(), PARAMS, auth=auth_b)

    ta = threading.Thread(target=run_alice)
    tb = threading.Thread(target=run_bob)
    ta.start()
    tb.start()

    ta.join(timeout=20)
    tb.join(timeout=20)
    wire_a.close()
    wire_b.close()
    t1.join(timeout=5)
    t2.join(timeout=5)

    assert len(captured_bytes) > 25_000, "Wire capture did not record full file transfer"

    # Assert private seed never appeared in captured wire traffic
    assert alice_seed not in captured_bytes, "SECURITY VIOLATION: Alice seed found in wire traffic!"
    assert bob_seed not in captured_bytes, "SECURITY VIOLATION: Bob seed found in wire traffic!"

    for i in range(len(alice_seed) - 15):
        assert alice_seed[i:i + 16] not in captured_bytes, f"16-byte slice of Alice seed found at offset {i}"
    for i in range(len(bob_seed) - 15):
        assert bob_seed[i:i + 16] not in captured_bytes, f"16-byte slice of Bob seed found at offset {i}"


# ── Item 9: Architectural import boundaries pass unchanged ──────────────────

def test_acceptance_item_9_setup_and_architecture_boundaries_pass() -> None:
    """Item 9: Core must not import from services, usecases, or runner; pure services must not import qiskit."""
    import tests.test_setup as ts
    for p in Path("src/qkd/core").glob("*.py"):
        ts.test_core_does_not_depend_on_outer_layers(p)
    ts.test_wire_and_file_stream_do_not_import_qiskit()
    ts.test_console_entry_points_resolve()
