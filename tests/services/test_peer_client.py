"""HttpPeerClient builds the right node-to-node requests."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from qkd.services.api.models import IncomingTransferRequest, PeerRef, TransferPatch
from qkd.services.peer_client import HttpPeerClient, PeerError
from qkd.services.process_runner import parse_line


def client_with(handler) -> tuple[HttpPeerClient, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    return HttpPeerClient(transport=httpx.MockTransport(record)), seen


def test_offer_respond_cancel_requests() -> None:
    client, seen = client_with(lambda r: httpx.Response(201 if r.method == "POST" else 200, json={}))
    offer = IncomingTransferRequest(
        id="t1",
        filename="a.bin",
        file_size=3,
        sender=PeerRef(id="n", name="n", host="10.0.0.1", port=8000),
        sender_fingerprint="1234-5678-90ab-cdef-1234-5678-90ab-cdef",
    )

    async def run() -> None:
        await client.offer_transfer("10.0.0.2", 8001, offer)
        await client.respond("10.0.0.1", 8000, "t1", TransferPatch(status="accepted", receiver_port=5000))
        await client.respond("10.0.0.1", 8000, "t1", TransferPatch(status="rejected"))
        await client.cancel("10.0.0.2", 8001, "t1")

    asyncio.run(run())
    assert [(r.method, str(r.url)) for r in seen] == [
        ("POST", "http://10.0.0.2:8001/api/v1/transfers/incoming"),
        ("PATCH", "http://10.0.0.1:8000/api/v1/transfers/t1"),
        ("PATCH", "http://10.0.0.1:8000/api/v1/transfers/t1"),
        ("DELETE", "http://10.0.0.2:8001/api/v1/transfers/t1"),
    ]
    assert json.loads(seen[0].content)["sender"]["port"] == 8000
    assert json.loads(seen[0].content)["sender_fingerprint"] == "1234-5678-90ab-cdef-1234-5678-90ab-cdef"
    assert json.loads(seen[1].content) == {"status": "accepted", "receiver_port": 5000}
    assert json.loads(seen[2].content) == {"status": "rejected"}


def test_error_status_raises_peer_error() -> None:
    client, _ = client_with(lambda r: httpx.Response(409, json={"error": {"code": "invalid_transition"}}))
    with pytest.raises(PeerError, match="409"):
        asyncio.run(client.cancel("10.0.0.2", 8001, "t1"))


def test_probe() -> None:
    up, _ = client_with(lambda r: httpx.Response(200, json={}))
    down, _ = client_with(lambda r: (_ for _ in ()).throw(httpx.ConnectError("refused")))
    assert asyncio.run(up.probe("h", 1)) is True
    assert asyncio.run(down.probe("h", 1)) is False


def test_parse_line_wraps_non_json_output() -> None:
    event = {"type": "stage", "stage": "sifting", "payload": {}, "ts": 1.0}
    assert parse_line(json.dumps(event)) == event
    raw = parse_line("Traceback (most recent call last):")
    assert raw["type"] == "log"
    assert raw["payload"] == {"level": "raw", "message": "Traceback (most recent call last):"}
    assert parse_line("[1, 2]")["type"] == "log"
