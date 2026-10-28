"""QKD_<NAME> environment overrides. Config is read at import, so each case runs in a fresh interpreter."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest


def read_config(env: dict[str, str], *names: str) -> dict:
    code = (
        "import json; from qkd.core import config; "
        f"print(json.dumps({{n: getattr(config, n) for n in {list(names)!r}}}))"
    )
    proc = subprocess.run([sys.executable, "-c", code], env={**os.environ, **env}, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr)
    return json.loads(proc.stdout)


def test_defaults() -> None:
    values = read_config({}, "NUM_QUBITS", "QBER_THRESHOLD", "CHUNK_SIZE", "BOB_PORT")
    assert values == {"NUM_QUBITS": 128, "QBER_THRESHOLD": 0.11, "CHUNK_SIZE": 65536, "BOB_PORT": 65432}


def test_env_overrides() -> None:
    env = {
        "QKD_NUM_QUBITS": "256",
        "QKD_QBER_THRESHOLD": "0.05",
        "QKD_CHUNK_SIZE": "1024",
        "QKD_BOB_PORT": "7000",
        "QKD_OUTPUT_DIR": "/tmp/out",
        "QKD_NODE_PORT": "9001",
    }
    values = read_config(env, "NUM_QUBITS", "QBER_THRESHOLD", "CHUNK_SIZE", "BOB_PORT", "OUTPUT_DIR", "NODE_PORT")
    assert values == {"NUM_QUBITS": 256, "QBER_THRESHOLD": 0.05, "CHUNK_SIZE": 1024, "BOB_PORT": 7000,
                      "OUTPUT_DIR": "/tmp/out", "NODE_PORT": 9001}


def test_protocol_params_pick_up_overrides() -> None:
    code = "from qkd.core.config import ProtocolParams; print(ProtocolParams().num_qubits)"
    out = subprocess.run([sys.executable, "-c", code], env={**os.environ, "QKD_NUM_QUBITS": "32"},
                         capture_output=True, text=True, check=True).stdout
    assert out.strip() == "32"


def test_invalid_value_is_rejected() -> None:
    with pytest.raises(RuntimeError, match="QKD_NUM_QUBITS"):
        read_config({"QKD_NUM_QUBITS": "lots"}, "NUM_QUBITS")
