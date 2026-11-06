"""
Hello and finished exchange (wire steps 0a, 0b, 4b) driven directly over a socket pair.

The BB84 exchange is skipped: a tracked salt message stands in for steps 2 to 4 so
both sides have a transcript to sign. Where a test plays one side by hand it uses
the raw wire or a TranscriptChannel, never the helper under test.
"""

from __future__ import annotations

import base64
import os
import socket
from typing import Any, Callable

import pytest

from qkd.core import pqc
from qkd.core.config import ProtocolParams
from qkd.core.crypto_utils import derive_aes_key
from qkd.services.reporting import NullReporter
from qkd.services.transcript import TranscriptChannel
from qkd.services.wire import recv_json, send_json
from qkd.usecases.common import AuthContext, KeyConfirmationError, PeerAuthError
from qkd.usecases.handshake import (
    PROTOCOL_VERSION,
    HandshakeState,
    alice_finished,
    alice_hello,
    bob_finished,
    bob_hello,
    confirmation_tag,
    finished_message,
    session_key,
)

POLICY = ProtocolParams().security_policy()


class PinnedVerifier:
    """Accepts exactly one public key, like a trust store with a single pin."""

    def __init__(self, expected: bytes) -> None:
        self.expected = expected

    def check(self, peer_public_key: bytes) -> str:
        if peer_public_key != self.expected:
            raise PeerAuthError("peer public key does not match the pinned key")
        return "pinned"


@pytest.fixture(scope="module")
def keys() -> dict[str, tuple[bytes, bytes]]:
    return {"alice": pqc.sig_keygen(), "bob": pqc.sig_keygen()}


def contexts(keys: dict[str, tuple[bytes, bytes]], mode: str) -> tuple[AuthContext, AuthContext]:
    """Alice's and Bob's AuthContext, each pinning the other's identity key."""
    (a_pk, a_seed), (b_pk, b_seed) = keys["alice"], keys["bob"]
    return (
        AuthContext(mode, a_pk, a_seed, PinnedVerifier(b_pk)),
        AuthContext(mode, b_pk, b_seed, PinnedVerifier(a_pk)),
    )


def closing(sock: socket.socket, fn: Callable[[], Any]) -> Callable[[], Any]:
    """Run fn, return its result or exception, then shut sock down as a runner does on exit."""

    def run() -> Any:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - asserted on by the caller
            return exc
        finally:
            sock.shutdown(socket.SHUT_RDWR)

    return run


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


@pytest.mark.parametrize(
    "mode, fields",
    [
        ("none", {"v", "mode", "params"}),
        ("sign", {"v", "mode", "params", "id_pk", "nonce"}),
        ("hybrid", {"v", "mode", "params", "id_pk", "nonce", "kem_pk"}),
    ],
)
def test_alice_hello_contents(mode: str, fields: set[str], keys, parallel) -> None:
    alice_auth = None if mode == "none" else contexts(keys, mode)[0]
    a, b = socket.socketpair()
    with a, b:
        _, msg = parallel(
            closing(a, lambda: alice_hello(TranscriptChannel(a, "alice"), alice_auth, NullReporter())),
            closing(b, lambda: recv_json(b)),
        )
    hello = msg["hello"]
    assert set(hello) == fields
    assert (hello["v"], hello["mode"], hello["params"]) == (PROTOCOL_VERSION, mode, POLICY)
    if mode != "none":
        assert base64.b64decode(hello["id_pk"]) == keys["alice"][0]
        assert len(base64.b64decode(hello["nonce"])) == 32
    if mode == "hybrid":
        assert len(base64.b64decode(hello["kem_pk"])) == 1184


def test_bob_hybrid_hello_carries_kem_ct_for_alice_kem_pk(keys, parallel) -> None:
    _, bob_auth = contexts(keys, "hybrid")
    kem_pk, kem_seed = pqc.kem_keygen()
    alice_hello_msg = {"hello": {"v": PROTOCOL_VERSION, "mode": "hybrid", "params": POLICY,
                                 "id_pk": b64(keys["alice"][0]), "nonce": b64(os.urandom(32)), "kem_pk": b64(kem_pk)}}

    def play_alice() -> Any:
        send_json(a, alice_hello_msg)
        return recv_json(a)

    a, b = socket.socketpair()
    with a, b:
        msg, state = parallel(
            closing(a, play_alice),
            closing(b, lambda: bob_hello(TranscriptChannel(b, "bob"), bob_auth, NullReporter())),
        )
    hello = msg["hello"]
    assert set(hello) == {"v", "mode", "params", "id_pk", "nonce", "kem_ct"}
    assert base64.b64decode(hello["id_pk"]) == keys["bob"][0]
    assert pqc.kem_decaps(kem_seed, base64.b64decode(hello["kem_ct"])) == state.kem_ss
    assert state.peer_trust == "pinned"


@pytest.mark.parametrize(
    "mode, bad_fields",
    [
        ("sign", {"id_pk": None}),
        ("sign", {"id_pk": "not base64!"}),
        ("sign", {"id_pk": b64(b"\x00" * 100)}),
        ("hybrid", {"kem_ct": b64(b"\x00" * 10)}),
    ],
    ids=["missing_id_pk", "bad_base64", "short_id_pk", "short_kem_ct"],
)
def test_malformed_bob_hello_raises_peer_auth_error(mode: str, bad_fields: dict, keys, parallel) -> None:
    alice_auth, _ = contexts(keys, mode)
    fields = {"v": PROTOCOL_VERSION, "mode": mode, "params": POLICY, "id_pk": b64(keys["bob"][0]),
              "nonce": b64(os.urandom(32))}
    if mode == "hybrid":
        fields["kem_ct"] = b64(os.urandom(1088))
    fields.update(bad_fields)
    fields = {k: v for k, v in fields.items() if v is not None}

    def play_bob() -> None:
        recv_json(b)
        send_json(b, {"hello": fields})
        recv_json(b)  # blocks until Alice gives up and her socket shuts down

    a, b = socket.socketpair()
    with a, b:
        err, _ = parallel(
            closing(a, lambda: alice_hello(TranscriptChannel(a, "alice"), alice_auth, NullReporter())),
            closing(b, play_bob),
        )
    assert isinstance(err, PeerAuthError)
    assert "malformed" in err.reason


def test_unknown_local_mode_raises_before_any_message(keys) -> None:
    (a_pk, a_seed), (b_pk, _) = keys["alice"], keys["bob"]
    bogus = AuthContext("bogus", a_pk, a_seed, PinnedVerifier(b_pk))  # type: ignore[arg-type]
    for hello in (alice_hello, bob_hello):
        a, b = socket.socketpair()
        with a, b:
            a.settimeout(2)  # a regression that sends or waits fails fast instead of hanging
            with pytest.raises(ValueError, match="bogus"):
                hello(TranscriptChannel(a, "alice" if hello is alice_hello else "bob"), bogus, NullReporter())
            b.setblocking(False)
            with pytest.raises(BlockingIOError):
                b.recv(1)  # nothing was sent to the peer


def test_alice_peer_closed_during_hello(keys, parallel) -> None:
    alice_auth, _ = contexts(keys, "sign")
    a, b = socket.socketpair()
    with a, b:
        err, _ = parallel(
            closing(a, lambda: alice_hello(TranscriptChannel(a, "alice"), alice_auth, NullReporter())),
            closing(b, lambda: recv_json(b)),  # Bob reads 0a, then closes (e.g. his trust store said no)
        )
    assert isinstance(err, PeerAuthError)
    assert err.reason == "peer closed connection during authentication"


def _run_finished(keys, parallel, alice_key: bytes, bob_key: bytes, mode: str = "sign") -> tuple[Any, Any]:
    """Hellos, a stand-in tracked salt, then the real finished exchange with each side's key."""
    alice_auth, bob_auth = contexts(keys, mode)

    def alice(sock: socket.socket) -> None:
        ch = TranscriptChannel(sock, "alice")
        state = alice_hello(ch, alice_auth, NullReporter())
        ch.send_json({"salt": "00" * 16})
        alice_finished(ch, alice_auth, state, ch.digest(), alice_key, NullReporter())

    def bob(sock: socket.socket) -> None:
        ch = TranscriptChannel(sock, "bob")
        state = bob_hello(ch, bob_auth, NullReporter())
        ch.recv_json()
        bob_finished(ch, bob_auth, state, ch.digest(), bob_key, NullReporter())

    a, b = socket.socketpair()
    with a, b:
        return parallel(closing(a, lambda: alice(a)), closing(b, lambda: bob(b)))


def test_finished_with_same_key_passes(keys, parallel) -> None:
    key = os.urandom(32)
    assert list(_run_finished(keys, parallel, key, key)) == [None, None]


def test_different_keys_fail_key_confirmation_not_authentication(keys, parallel) -> None:
    # Same transcript, valid signatures, different keys: what a missed channel error looks like
    alice_err, _ = _run_finished(keys, parallel, os.urandom(32), os.urandom(32))
    assert isinstance(alice_err, KeyConfirmationError)
    assert not isinstance(alice_err, PeerAuthError)
    assert "key confirmation failed" in alice_err.reason


def test_finished_replayed_from_previous_session_is_rejected(keys, parallel) -> None:
    alice_auth, bob_auth = contexts(keys, "sign")
    salt = {"salt": "00" * 16}
    key = os.urandom(32)

    # Session 1: honest Bob; the test plays Alice after the hellos and captures Bob's finished.
    def alice_capture(sock: socket.socket) -> tuple[bytes, Any]:
        ch = TranscriptChannel(sock, "alice")
        alice_hello(ch, alice_auth, NullReporter())
        ch.send_json(salt)
        return ch.digest(), ch.recv_untracked()

    def honest_bob(sock: socket.socket) -> None:
        ch = TranscriptChannel(sock, "bob")
        state = bob_hello(ch, bob_auth, NullReporter())
        ch.recv_json()
        bob_finished(ch, bob_auth, state, ch.digest(), key, NullReporter())

    a, b = socket.socketpair()
    with a, b:
        (t1, captured), _ = parallel(closing(a, lambda: alice_capture(a)), closing(b, lambda: honest_bob(b)))
    tag = base64.b64decode(captured["confirm"])
    assert tag == confirmation_tag(key, b"bob", t1)
    assert pqc.verify(keys["bob"][0], finished_message(b"bob", t1, tag), base64.b64decode(captured["finished"]))

    # Session 2: honest Alice; Bob runs the real hello (fresh nonces) and replays the old finished.
    def honest_alice(sock: socket.socket) -> None:
        ch = TranscriptChannel(sock, "alice")
        state = alice_hello(ch, alice_auth, NullReporter())
        ch.send_json(salt)
        alice_finished(ch, alice_auth, state, ch.digest(), key, NullReporter())

    def replaying_bob(sock: socket.socket) -> bytes:
        ch = TranscriptChannel(sock, "bob")
        bob_hello(ch, bob_auth, NullReporter())
        ch.recv_json()
        ch.send_untracked(captured)
        return ch.digest()

    a, b = socket.socketpair()
    with a, b:
        err, t2 = parallel(closing(a, lambda: honest_alice(a)), closing(b, lambda: replaying_bob(b)))
    assert t2 != t1
    assert isinstance(err, PeerAuthError)
    assert "signature" in err.reason


def test_signature_covers_the_confirmation_tag(keys, parallel) -> None:
    """A relay that swaps in another tag under Bob's real signature breaks the signature."""
    alice_auth, bob_auth = contexts(keys, "sign")
    key = os.urandom(32)

    def alice(sock: socket.socket) -> None:
        ch = TranscriptChannel(sock, "alice")
        state = alice_hello(ch, alice_auth, NullReporter())
        ch.send_json({"salt": "00" * 16})
        alice_finished(ch, alice_auth, state, ch.digest(), key, NullReporter())

    def bob_with_swapped_tag(sock: socket.socket) -> None:
        ch = TranscriptChannel(sock, "bob")
        bob_hello(ch, bob_auth, NullReporter())
        ch.recv_json()
        t = ch.digest()
        good = confirmation_tag(key, b"bob", t)
        signature = pqc.sign(keys["bob"][1], finished_message(b"bob", t, good))
        ch.send_untracked({"finished": b64(signature), "confirm": b64(os.urandom(32))})
        ch.recv_untracked()

    a, b = socket.socketpair()
    with a, b:
        err, _ = parallel(closing(a, lambda: alice(a)), closing(b, lambda: bob_with_swapped_tag(b)))
    assert isinstance(err, PeerAuthError)
    assert "signature" in err.reason


@pytest.mark.parametrize(
    "bob_params",
    [ProtocolParams(eps_sec=1e-6), ProtocolParams(final_key_bits=128), ProtocolParams(enforce_finite_key=False),
     ProtocolParams(qber_threshold=0.2)],
    ids=["eps_sec", "final_key_bits", "enforce_finite_key", "qber_threshold"],
)
@pytest.mark.parametrize("mode", ["none", "hybrid"])
def test_parameter_mismatch_aborts_both_sides(mode: str, bob_params: ProtocolParams, keys, parallel) -> None:
    alice_auth, bob_auth = (None, None) if mode == "none" else contexts(keys, mode)
    a, b = socket.socketpair()
    with a, b:
        alice_err, bob_err = parallel(
            closing(a, lambda: alice_hello(TranscriptChannel(a, "alice"), alice_auth, NullReporter())),
            closing(b, lambda: bob_hello(TranscriptChannel(b, "bob"), bob_auth, NullReporter(), bob_params)),
        )
    for err in (alice_err, bob_err):
        assert isinstance(err, PeerAuthError)
        assert "parameter mismatch" in err.reason


def test_none_mode_session_key_is_legacy_key() -> None:
    qkd_key = os.urandom(32)
    assert session_key(qkd_key, HandshakeState("none"), os.urandom(32)) == derive_aes_key(qkd_key)
