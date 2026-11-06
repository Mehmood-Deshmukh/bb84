"""Tests for runner CLI argument parsing and AuthContext construction (Module 4).

Tests cover:
  - Default flags produce mode=hybrid behavior
  - --auth none round-trips
  - --peer-fingerprint produces a PinnedVerifier
  - Missing --peer-fingerprint with TOFU on produces a TrustStoreVerifier
  - Config env-var overrides (subprocess tests matching test_config.py pattern)
  - Old-style invocations (no new flags) behave identically
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Deterministic stubs for pqc — same as test_identity.py
# ---------------------------------------------------------------------------
_STUB_PUBLIC_KEY = b"\x01" * 1952
_STUB_SEED = b"\x02" * 32


def _stub_sig_keygen():
    return _STUB_PUBLIC_KEY, _STUB_SEED


def _stub_fingerprint(public_key: bytes) -> str:
    import hashlib
    digest = hashlib.sha256(public_key).digest()[:16].hex()
    return "-".join(digest[i : i + 4] for i in range(0, 32, 4))


_FP_1 = _stub_fingerprint(_STUB_PUBLIC_KEY)

_KEYGEN_PATCH = "qkd.services.identity.sig_keygen"
_FP_PATCH = "qkd.services.identity._pqc_fingerprint"


@pytest.fixture(autouse=True)
def _patch_pqc():
    with patch(_KEYGEN_PATCH, side_effect=_stub_sig_keygen), \
         patch(_FP_PATCH, side_effect=_stub_fingerprint):
        yield


# ═══════════════════════════════════════════════════════════════════════════
# Alice CLI argument parsing
# ═══════════════════════════════════════════════════════════════════════════

from qkd.runner.alice import parse_args as alice_parse_args
from qkd.runner.alice import build_auth as alice_build_auth
from qkd.runner.bob import parse_args as bob_parse_args
from qkd.runner.bob import build_auth as bob_build_auth


class TestAliceParseArgs:
    def test_defaults(self) -> None:
        args = alice_parse_args(["myfile.txt"])
        assert args.file == "myfile.txt"
        assert args.auth == "hybrid"
        assert args.peer_fingerprint is None
        assert args.identity == "identity"

    def test_auth_none(self) -> None:
        args = alice_parse_args(["myfile.txt", "--auth", "none"])
        assert args.auth == "none"

    def test_auth_sign(self) -> None:
        args = alice_parse_args(["myfile.txt", "--auth", "sign"])
        assert args.auth == "sign"

    def test_peer_fingerprint(self) -> None:
        args = alice_parse_args(["myfile.txt", "--peer-fingerprint", _FP_1])
        assert args.peer_fingerprint == _FP_1

    def test_identity_dir(self) -> None:
        args = alice_parse_args(["myfile.txt", "--identity", "/tmp/myid"])
        assert args.identity == "/tmp/myid"

    def test_old_style_no_new_flags(self) -> None:
        """Old-style invocation still parses correctly."""
        args = alice_parse_args(["myfile.txt", "--host", "10.0.0.1", "--port", "9999"])
        assert args.file == "myfile.txt"
        assert args.host == "10.0.0.1"
        assert args.port == 9999
        assert args.auth == "hybrid"  # default

    def test_eve_mode_port_default(self) -> None:
        """--eve-mode still selects EVE_PORT when --port is not given."""
        args = alice_parse_args(["myfile.txt", "--eve-mode"])
        from qkd.core.config import EVE_PORT
        assert args.port == EVE_PORT


class TestBobParseArgs:
    def test_defaults(self) -> None:
        args = bob_parse_args([])
        assert args.auth == "hybrid"
        assert args.peer_fingerprint is None
        assert args.identity == "identity"

    def test_auth_none(self) -> None:
        args = bob_parse_args(["--auth", "none"])
        assert args.auth == "none"

    def test_peer_fingerprint(self) -> None:
        args = bob_parse_args(["--peer-fingerprint", _FP_1])
        assert args.peer_fingerprint == _FP_1

    def test_identity_dir(self) -> None:
        args = bob_parse_args(["--identity", "/tmp/myid"])
        assert args.identity == "/tmp/myid"

    def test_old_style_no_new_flags(self) -> None:
        args = bob_parse_args(["--port", "7777", "--output-dir", "/tmp/out"])
        assert args.port == 7777
        assert args.output_dir == "/tmp/out"
        assert args.auth == "hybrid"


# ═══════════════════════════════════════════════════════════════════════════
# build_auth — AuthContext construction
# ═══════════════════════════════════════════════════════════════════════════

class TestAliceBuildAuth:
    def test_auth_none_returns_none(self) -> None:
        args = alice_parse_args(["myfile.txt", "--auth", "none"])
        assert alice_build_auth(args) is None

    def test_auth_hybrid_returns_auth_context(self, tmp_path: Path) -> None:
        args = alice_parse_args(["myfile.txt", "--auth", "hybrid", "--identity", str(tmp_path / "id")])
        with patch("qkd.runner.alice.KNOWN_PEERS_FILE", str(tmp_path / "peers.json")):
            ctx = alice_build_auth(args)
        from qkd.usecases.common import AuthContext
        assert isinstance(ctx, AuthContext)
        assert ctx.mode == "hybrid"
        assert ctx.public_key == _STUB_PUBLIC_KEY
        assert ctx.seed == _STUB_SEED

    def test_peer_fingerprint_uses_pinned_verifier(self, tmp_path: Path) -> None:
        args = alice_parse_args([
            "myfile.txt", "--auth", "sign",
            "--peer-fingerprint", _FP_1,
            "--identity", str(tmp_path / "id"),
        ])
        ctx = alice_build_auth(args)
        from qkd.services.identity import PinnedVerifier
        assert isinstance(ctx.verifier, PinnedVerifier)

    def test_no_peer_fingerprint_uses_trust_store_verifier(self, tmp_path: Path) -> None:
        args = alice_parse_args([
            "myfile.txt", "--auth", "hybrid",
            "--identity", str(tmp_path / "id"),
        ])
        with patch("qkd.runner.alice.KNOWN_PEERS_FILE", str(tmp_path / "peers.json")):
            ctx = alice_build_auth(args)
        from qkd.services.identity import TrustStoreVerifier
        assert isinstance(ctx.verifier, TrustStoreVerifier)


class TestBobBuildAuth:
    def test_auth_none_returns_none(self) -> None:
        args = bob_parse_args(["--auth", "none"])
        assert bob_build_auth(args) is None

    def test_auth_hybrid_returns_auth_context(self, tmp_path: Path) -> None:
        args = bob_parse_args(["--auth", "hybrid", "--identity", str(tmp_path / "id")])
        with patch("qkd.runner.bob.KNOWN_PEERS_FILE", str(tmp_path / "peers.json")):
            ctx = bob_build_auth(args)
        from qkd.usecases.common import AuthContext
        assert isinstance(ctx, AuthContext)
        assert ctx.mode == "hybrid"

    def test_peer_fingerprint_uses_pinned_verifier(self, tmp_path: Path) -> None:
        args = bob_parse_args([
            "--auth", "sign",
            "--peer-fingerprint", _FP_1,
            "--identity", str(tmp_path / "id"),
        ])
        ctx = bob_build_auth(args)
        from qkd.services.identity import PinnedVerifier
        assert isinstance(ctx.verifier, PinnedVerifier)

    def test_no_peer_fingerprint_uses_trust_store_verifier(self, tmp_path: Path) -> None:
        args = bob_parse_args([
            "--auth", "hybrid",
            "--identity", str(tmp_path / "id"),
        ])
        with patch("qkd.runner.bob.KNOWN_PEERS_FILE", str(tmp_path / "peers.json")):
            ctx = bob_build_auth(args)
        from qkd.services.identity import TrustStoreVerifier
        assert isinstance(ctx.verifier, TrustStoreVerifier)


# ═══════════════════════════════════════════════════════════════════════════
# Subprocess env-var tests (match test_config.py pattern)
# ═══════════════════════════════════════════════════════════════════════════

def _read_runner_parse(runner_module: str, argv_json: str, env: dict[str, str], *attrs: str) -> dict:
    """Parse args in a subprocess so QKD_* env vars are read fresh."""
    code = (
        f"import json; from qkd.runner.{runner_module} import parse_args; "
        f"args = parse_args(json.loads({argv_json!r})); "
        f"print(json.dumps({{a: getattr(args, a) for a in {list(attrs)!r}}}))"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        env={**os.environ, **env},
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr)
    return json.loads(proc.stdout)


class TestAliceEnvOverrides:
    def test_auth_mode_from_env(self) -> None:
        vals = _read_runner_parse(
            "alice", '["dummy.txt"]',
            {"QKD_AUTH_MODE": "sign"},
            "auth",
        )
        assert vals["auth"] == "sign"

    def test_identity_dir_from_env(self) -> None:
        vals = _read_runner_parse(
            "alice", '["dummy.txt"]',
            {"QKD_IDENTITY_DIR": "/custom/id"},
            "identity",
        )
        assert vals["identity"] == "/custom/id"

    def test_cli_flag_overrides_env(self) -> None:
        vals = _read_runner_parse(
            "alice", '["dummy.txt", "--auth", "none"]',
            {"QKD_AUTH_MODE": "sign"},
            "auth",
        )
        assert vals["auth"] == "none"


class TestBobEnvOverrides:
    def test_auth_mode_from_env(self) -> None:
        vals = _read_runner_parse(
            "bob", '[]',
            {"QKD_AUTH_MODE": "none"},
            "auth",
        )
        assert vals["auth"] == "none"

    def test_identity_dir_from_env(self) -> None:
        vals = _read_runner_parse(
            "bob", '[]',
            {"QKD_IDENTITY_DIR": "/custom/id"},
            "identity",
        )
        assert vals["identity"] == "/custom/id"

    def test_cli_flag_overrides_env(self) -> None:
        vals = _read_runner_parse(
            "bob", '["--auth", "hybrid"]',
            {"QKD_AUTH_MODE": "none"},
            "auth",
        )
        assert vals["auth"] == "hybrid"


# ═══════════════════════════════════════════════════════════════════════════
# Safety: AuthContext construction never imports node.py or api
# ═══════════════════════════════════════════════════════════════════════════

class TestBuildAuthNoForbiddenImports:
    def test_alice_build_auth_no_node_import(self, tmp_path: Path) -> None:
        import qkd.runner.alice as mod
        source = Path(mod.__file__).read_text()
        for forbidden in ("services.node", "services.api", "frontend"):
            assert forbidden not in source, (
                f"runner/alice.py must not import from {forbidden}"
            )

    def test_bob_build_auth_no_node_import(self, tmp_path: Path) -> None:
        import qkd.runner.bob as mod
        source = Path(mod.__file__).read_text()
        for forbidden in ("services.node", "services.api", "frontend"):
            assert forbidden not in source, (
                f"runner/bob.py must not import from {forbidden}"
            )



class TestEveParseArgs:
    def test_fraction_defaults_to_every_qubit(self) -> None:
        from qkd.runner.eve import parse_args as eve_parse_args

        assert eve_parse_args([]).fraction == 1.0
        assert eve_parse_args(["--fraction", "0.25"]).fraction == 0.25

    def test_fraction_out_of_range_is_rejected(self) -> None:
        import pytest

        from qkd.runner.eve import parse_args as eve_parse_args

        for bad in ("-0.1", "1.5"):
            with pytest.raises(SystemExit):
                eve_parse_args(["--fraction", bad])
