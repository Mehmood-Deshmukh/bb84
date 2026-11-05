"""
The mutation and classification helpers of scripts/fuzz_tamper.py (E7).

A fuzzer that silently fails to change a message, or mislabels what caught a change,
would make the E7 coverage claim worthless, so these pin both down.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import random
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from qkd.core.quantum_channel import measure_qubits, prepare_qubits
from qkd.services import wire
from qkd.services.file_stream import MetadataError
from qkd.usecases.common import KeyConfirmationError, KeyExchangeResult, PeerAuthError
from qkd.usecases.receive_file import ReceiveResult

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("fuzz_tamper", ROOT / "scripts" / "fuzz_tamper.py")
fz = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fz)

MESSAGES = {
    "2-bases": ["+", "x", "x", "+"],
    "2-matching": [0, 2, 5, 9],
    "3-sample_bits": {"sample_bits": [0, 1, 1, 0]},
    "3-qber": {"qber": 0.0},
    "4-salt": {"salt": "0a1b2c3d4e5f"},
    "4b-bob": {"finished": base64.b64encode(bytes(range(40))).decode(),
               "confirm": base64.b64encode(bytes(32)).decode()},
    "0a": {"hello": {"v": 2, "mode": "hybrid", "params": {"eps_sec": 1e-10, "enforce_finite_key": True}}},
}


def _shape(node):
    if isinstance(node, dict):
        return {k: _shape(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_shape(v) for v in node]
    return type(node).__name__


def test_bitflip_changes_exactly_one_bit() -> None:
    raw = bytes(range(64))
    for seed in range(50):
        out = fz.bitflip(raw, random.Random(seed))
        assert sum(bin(a ^ b).count("1") for a, b in zip(raw, out)) == 1


@pytest.mark.parametrize("step", sorted(MESSAGES))
def test_semantic_change_keeps_valid_json_and_shape(step: str) -> None:
    raw = wire.encode_json(MESSAGES[step])
    for seed in range(50):
        out, applied = fz.mutate(raw, step, "semantic", random.Random(seed))
        assert applied == "semantic"
        doc = json.loads(out)
        assert doc != json.loads(raw)
        assert _shape(doc) == _shape(MESSAGES[step])  # same structure and types, one value changed


def test_semantic_change_keeps_hex_hex_and_base64_decodable() -> None:
    for seed in range(50):
        rng = random.Random(seed)
        h = fz._change_string("0a1b2c3d", rng)
        assert h != "0a1b2c3d" and bytes.fromhex(h)
        b = fz._change_string(MESSAGES["4b-bob"]["confirm"], rng)
        assert b != MESSAGES["4b-bob"]["confirm"] and base64.b64decode(b, validate=True) != bytes(32)


def test_semantic_qubit_change_flips_exactly_one_encoded_bit() -> None:
    # Includes bit 0 in the + basis, whose QASM has no gates and no trailing newline
    bits, bases = [0, 1, 0, 1, 1, 0], ["+", "+", "x", "x", "+", "x"]
    raw = wire.encode_json(prepare_qubits(bits, bases))
    for seed in range(30):
        out, applied = fz.mutate(raw, "1", "semantic", random.Random(seed))
        assert applied == "semantic"
        measured = measure_qubits(json.loads(out), bases)
        assert sum(m != b for m, b in zip(measured, bits)) == 1


def test_unchangeable_semantic_falls_back_and_says_so() -> None:
    # A "qubit" without a register line cannot be flipped, so the semantic change is a
    # no-op; the fallback must still change the bytes and must be labelled as such
    raw = wire.encode_json(["not a circuit"])
    out, applied = fz.mutate(raw, "1", "semantic", random.Random(0))
    assert out != raw
    assert applied == "bitflip_fallback"


def _kx(aborted: bool) -> KeyExchangeResult:
    return KeyExchangeResult(raw_qubits=8, sifted_length=4, sample_size=1, qber=0.0, threshold=0.11,
                             key=None if aborted else b"k" * 32, abort_reason="QBER 25%" if aborted else None)


def test_classify(tmp_path: Path) -> None:
    good, bad = tmp_path / "good", tmp_path / "bad"
    good.write_bytes(b"data")
    bad.write_bytes(b"dbta")
    delivered = lambda p: ReceiveResult(_kx(False), str(p), 4)  # noqa: E731
    assert fz.classify(_kx(False), delivered(good), b"data")[0] == "delivered_intact"
    assert fz.classify(_kx(False), delivered(bad), b"data")[0] == "delivered_corrupt"
    assert fz.classify(KeyConfirmationError("x"), ConnectionError(), b"data")[0] == "key_confirmation"
    assert fz.classify(PeerAuthError("bob finished signature invalid"), ConnectionError(), b"d")[0] == "signature"
    assert fz.classify(PeerAuthError("mode mismatch"), PeerAuthError("mode mismatch"), b"d")[0] == "handshake_reject"
    assert fz.classify(_kx(False), InvalidTag(), b"d")[0] == "aead_tag"
    assert fz.classify(_kx(False), MetadataError("num_chunks"), b"d")[0] == "metadata_reject"
    assert fz.classify(_kx(True), ReceiveResult(_kx(True)), b"d")[0] == "qber_or_finite_key"
    assert fz.classify(ValueError("bad hex"), ConnectionError(), b"d")[0] == "malformed_reject"
    assert fz.classify(ConnectionError(), ConnectionError(), b"d")[0] == "connection_only"
