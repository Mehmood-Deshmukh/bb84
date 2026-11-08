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
    assert values == {"NUM_QUBITS": 8192, "QBER_THRESHOLD": 0.11, "CHUNK_SIZE": 65536, "BOB_PORT": 65432}


def test_finite_key_defaults_and_overrides() -> None:
    names = ("EPS_SEC", "EPS_COR", "ENFORCE_FINITE_KEY", "FINAL_KEY_BITS")
    assert read_config({}, *names) == {"EPS_SEC": 1e-10, "EPS_COR": 1e-15, "ENFORCE_FINITE_KEY": True,
                                       "FINAL_KEY_BITS": 256}
    env = {"QKD_EPS_SEC": "1e-6", "QKD_EPS_COR": "1e-9", "QKD_ENFORCE_FINITE_KEY": "false"}
    assert read_config(env, *names[:3]) == {"EPS_SEC": 1e-6, "EPS_COR": 1e-9, "ENFORCE_FINITE_KEY": False}


def test_security_policy_lists_the_values_peers_must_share() -> None:
    from qkd.core.config import ProtocolParams

    policy = ProtocolParams(final_key_bits=128, eps_sec=1e-6, eps_cor=1e-9, qber_threshold=0.05,
                            enforce_finite_key=False).security_policy()
    assert policy == {"final_key_bits": 128, "eps_sec": 1e-6, "eps_cor": 1e-9, "qber_threshold": 0.05,
                      "enforce_finite_key": False, "reconciliation": "none",
                      "source": "single", "intensities": [0.48, 0.1, 0.0], "probs": [0.7, 0.2, 0.1]}


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


def test_auth_defaults() -> None:
    values = read_config({}, "AUTH_MODE", "IDENTITY_DIR", "KNOWN_PEERS_FILE", "TOFU")
    assert values == {
        "AUTH_MODE": "hybrid",
        "IDENTITY_DIR": "identity",
        "KNOWN_PEERS_FILE": "known_peers.json",
        "TOFU": 1,
    }



def test_auth_env_overrides() -> None:
    env = {
        "QKD_AUTH_MODE": "sign",
        "QKD_IDENTITY_DIR": "custom_ident",
        "QKD_KNOWN_PEERS_FILE": "custom_peers.json",
        "QKD_TOFU": "0",
    }
    values = read_config(env, "AUTH_MODE", "IDENTITY_DIR", "KNOWN_PEERS_FILE", "TOFU")
    assert values == {
        "AUTH_MODE": "sign",
        "IDENTITY_DIR": "custom_ident",
        "KNOWN_PEERS_FILE": "custom_peers.json",
        "TOFU": 0,
    }


@pytest.mark.parametrize("mode", ["none", "sign", "hybrid"])
def test_auth_mode_allowed_values(mode: str) -> None:
    values = read_config({"QKD_AUTH_MODE": mode}, "AUTH_MODE")
    assert values["AUTH_MODE"] == mode


def test_auth_mode_invalid_rejected() -> None:
    with pytest.raises(RuntimeError, match="QKD_AUTH_MODE"):
        read_config({"QKD_AUTH_MODE": "invalid_mode"}, "AUTH_MODE")



def test_channel_preset_length_and_overrides() -> None:
    code = ("import json; from qkd.core.config import CHANNEL; from dataclasses import asdict; "
            "print(json.dumps(asdict(CHANNEL)))")
    env = {**os.environ, "QKD_CHANNEL_PRESET": "GYS", "QKD_CHANNEL_LENGTH_KM": "50", "QKD_MISALIGNMENT": "0.01"}
    out = json.loads(subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True,
                                    check=True).stdout)
    assert out == {"length_km": 50.0, "loss_db_per_km": 0.21, "detector_efficiency": 0.045,
                   "dark_count_prob": 1.7e-6, "misalignment": 0.01}
    default = json.loads(subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                                        check=True, env={k: v for k, v in os.environ.items()
                                                         if not k.startswith("QKD_")}).stdout)
    assert default["detector_efficiency"] == 1.0 and default["length_km"] == 0.0  # ideal


def test_unknown_channel_preset_is_rejected() -> None:
    with pytest.raises(RuntimeError, match="QKD_CHANNEL_PRESET"):
        read_config({"QKD_CHANNEL_PRESET": "bogus"}, "CHANNEL")
