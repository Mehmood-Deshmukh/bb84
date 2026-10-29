"""Tests for node identity exposure and mDNS discovery (Module 5).

Covers:
  - TXT_VERSION is bumped to "3"
  - GET /api/v1/node includes fingerprint and matches fingerprint(identity.public_key)
  - mDNS advertisement ServiceInfo contains 'fp', 'version': '3', and 'id'
  - Restart stability: starting a node, reading fingerprint, restarting pointed at the
    same directory preserves the identical fingerprint
  - Node API response shape contains only expected fields
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from qkd.core.pqc import fingerprint as pqc_fingerprint
from qkd.services.api.app import create_app
from qkd.services.discovery import (
    SERVICE_TYPE,
    TXT_VERSION,
    NodeIdentity,
    PeerInfo,
    StaticPeerDirectory,
    ZeroconfPeerDirectory,
)
from qkd.services.events import EventBus
from qkd.services.history import HistoryStore
from qkd.services.identity import load_or_create_identity
from qkd.services.node import NodeService
from qkd.services.transfer_store import InMemoryTransferRepository
from tests.services.fakes import FakeLauncher, RecordingPeerClient

_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{4}(-[0-9a-f]{4}){7}$")


def _make_test_service(identity_dir: Path, tmp_path: Path) -> NodeService:
    ident = NodeIdentity(id="test-node-id", name="test-node", host="127.0.0.1", port=8000)
    return NodeService(
        ident,
        repo=InMemoryTransferRepository(),
        bus=EventBus(),
        history=HistoryStore(tmp_path / "history.json"),
        directory=StaticPeerDirectory(),
        peers=RecordingPeerClient(),
        launcher=FakeLauncher(),
        output_dir=str(tmp_path / "received"),
        upload_dir=str(tmp_path / "uploads"),
        version="1.0.0-test",
        listen_timeout=5,
        identity_dir=identity_dir,
    )


class TestDiscoveryModule5:
    def test_txt_version_is_3(self) -> None:
        assert TXT_VERSION == "3"

    def test_get_node_includes_fingerprint_matching_public_key(self, tmp_path: Path) -> None:
        id_dir = tmp_path / "identity"
        service = _make_test_service(id_dir, tmp_path)
        app = create_app(service)

        with TestClient(app) as client:
            resp = client.get("/api/v1/node")
            assert resp.status_code == 200
            data = resp.json()

            assert "fingerprint" in data
            fp = data["fingerprint"]
            assert _FINGERPRINT_RE.match(fp), f"Fingerprint {fp!r} does not match 8-hex-group format"

            expected_fp = pqc_fingerprint(service.pqc_identity.public_key)
            assert fp == expected_fp
            assert fp == service.identity.fingerprint

    def test_node_response_shape_has_no_incidental_changes(self, tmp_path: Path) -> None:
        id_dir = tmp_path / "identity"
        service = _make_test_service(id_dir, tmp_path)
        app = create_app(service)

        with TestClient(app) as client:
            data = client.get("/api/v1/node").json()
            expected_keys = {"id", "name", "host", "port", "status", "version", "fingerprint"}
            assert set(data.keys()) == expected_keys

    def test_restart_stability_check(self, tmp_path: Path) -> None:
        id_dir = tmp_path / "persistent_identity"

        # Start 1: Initial creation and run
        service1 = _make_test_service(id_dir, tmp_path)
        app1 = create_app(service1)
        with TestClient(app1) as client1:
            data1 = client1.get("/api/v1/node").json()
            fp1 = data1["fingerprint"]
            pk1 = service1.pqc_identity.public_key
            seed1 = service1.pqc_identity.seed

        # Start 2: Restart against the same identity directory
        service2 = _make_test_service(id_dir, tmp_path)
        app2 = create_app(service2)
        with TestClient(app2) as client2:
            data2 = client2.get("/api/v1/node").json()
            fp2 = data2["fingerprint"]
            pk2 = service2.pqc_identity.public_key
            seed2 = service2.pqc_identity.seed

        assert fp1 == fp2
        assert pk1 == pk2
        assert seed1 == seed2

    def test_mdns_txt_record_contains_fp(self, tmp_path: Path) -> None:
        async def _test() -> None:
            id_dir = tmp_path / "identity"
            identity = load_or_create_identity(id_dir)
            node_ident = NodeIdentity(
                id="node-xyz",
                name="alice-device",
                host="192.168.1.50",
                port=8000,
                fingerprint=identity.fingerprint,
            )

            zc_dir = ZeroconfPeerDirectory()
            mock_zc = MagicMock()
            mock_zc.async_register_service = AsyncMock()
            mock_zc.async_unregister_service = AsyncMock()
            zc_dir._zc = mock_zc

            await zc_dir.advertise(node_ident)

            assert mock_zc.async_register_service.called
            service_info = mock_zc.async_register_service.call_args[0][0]
            props = service_info.properties
            props_decoded = {
                (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
                for k, v in props.items()
            }

            assert props_decoded.get("version") == "3"
            assert props_decoded.get("id") == "node-xyz"
            assert props_decoded.get("fp") == identity.fingerprint

        asyncio.run(_test())

    def test_mdns_resolve_parses_fp(self) -> None:
        async def _test() -> None:
            zc_dir = ZeroconfPeerDirectory()
            mock_zc = MagicMock()

            mock_info = MagicMock()
            mock_info.addresses = [b"\x7f\x00\x00\x01"]  # 127.0.0.1
            mock_info.port = 8000
            mock_info.properties = {
                b"id": b"node-remote",
                b"version": b"3",
                b"fp": b"1234-5678-90ab-cdef-1234-5678-90ab-cdef",
            }
            mock_info.async_request = AsyncMock(return_value=True)

            with patch("zeroconf.asyncio.AsyncServiceInfo", return_value=mock_info):
                await zc_dir._resolve(mock_zc, SERVICE_TYPE, f"remote-peer.{SERVICE_TYPE}")

            peer = zc_dir._peers.get(f"remote-peer.{SERVICE_TYPE}")
            assert peer is not None
            assert peer.id == "node-remote"
            assert peer.name == "remote-peer"
            assert peer.port == 8000
            assert peer.fingerprint == "1234-5678-90ab-cdef-1234-5678-90ab-cdef"

        asyncio.run(_test())
