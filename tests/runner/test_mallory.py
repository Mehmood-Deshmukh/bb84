"""Tests for Mallory MITM runner (Module 11)."""

from __future__ import annotations

import socket
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from qkd.runner.mallory import main, parse_args
from qkd.services.reporting import (
    OUTCOME_ABORTED_AUTH,
    OUTCOME_ABORTED_QBER,
    OUTCOME_COMPLETED,
    OUTCOME_FAILED,
)
from qkd.usecases.common import PeerAuthError


def test_mallory_arg_defaults():
    args = parse_args([])
    assert args.bob_host == "localhost"
    assert args.bob_port == 65432
    assert args.listen_port == 65433
    assert args.scenario == "own_identity"
    assert "mallory" in args.identity
    assert args.events == "text"


def test_mallory_arg_overrides():
    args = parse_args([
        "--bob-host", "10.0.0.5",
        "--bob-port", "40000",
        "--listen-port", "40001",
        "--scenario", "relay_hello",
        "--identity", "/tmp/mallory_id",
        "--events", "json",
        "--transfer-id", "t-123",
    ])
    assert args.bob_host == "10.0.0.5"
    assert args.bob_port == 40000
    assert args.listen_port == 40001
    assert args.scenario == "relay_hello"
    assert args.identity == "/tmp/mallory_id"
    assert args.events == "json"
    assert args.transfer_id == "t-123"


def test_mallory_network_error_returns_code_2():
    # Connecting to an unused port should return 2 (network error, not auth rejection)
    code = main(["--bob-port", "59998", "--events", "json"])
    assert code == 2


def test_mallory_missing_mitm_demo_returns_code_3():
    # Mock successful sockets to Bob and Alice
    mock_bob = MagicMock(spec=socket.socket)
    mock_server = MagicMock(spec=socket.socket)
    mock_alice = MagicMock(spec=socket.socket)
    mock_server.accept.return_value = (mock_alice, ("127.0.0.1", 50000))

    with patch("qkd.runner.mallory.connect_with_retry", return_value=mock_bob), \
         patch("qkd.runner.mallory.listen", return_value=mock_server):
        # Because mitm_demo.py is not landed by Person A yet, importing it fails
        code = main(["--events", "json"])
        assert code == 3


def test_mallory_security_rejection_auth_error_returns_0():
    mock_bob = MagicMock(spec=socket.socket)
    mock_server = MagicMock(spec=socket.socket)
    mock_alice = MagicMock(spec=socket.socket)
    mock_server.accept.return_value = (mock_alice, ("127.0.0.1", 50000))

    mock_run_mitm = MagicMock(side_effect=PeerAuthError("Fingerprint mismatch"))

    with patch("qkd.runner.mallory.connect_with_retry", return_value=mock_bob), \
         patch("qkd.runner.mallory.listen", return_value=mock_server), \
         patch.dict("sys.modules", {"qkd.usecases.mitm_demo": MagicMock(run_mitm=mock_run_mitm)}):
        code = main(["--scenario", "own_identity"])
        assert code == 0


def test_mallory_successful_attack_none_scenario():
    mock_bob = MagicMock(spec=socket.socket)
    mock_server = MagicMock(spec=socket.socket)
    mock_alice = MagicMock(spec=socket.socket)
    mock_server.accept.return_value = (mock_alice, ("127.0.0.1", 50000))

    mock_result = MagicMock()
    mock_result.aborted = False
    mock_result.plaintext_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    mock_run_mitm = MagicMock(return_value=mock_result)

    with patch("qkd.runner.mallory.connect_with_retry", return_value=mock_bob), \
         patch("qkd.runner.mallory.listen", return_value=mock_server), \
         patch.dict("sys.modules", {"qkd.usecases.mitm_demo": MagicMock(run_mitm=mock_run_mitm)}):
        code = main(["--scenario", "none"])
        assert code == 0

