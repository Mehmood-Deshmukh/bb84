"""HTTP calls from this node to another node's /api/v1 resources."""

from __future__ import annotations

from typing import Optional, Protocol

import httpx

from qkd.services.api.models import IncomingTransferRequest, TransferPatch


class PeerError(Exception):
    """The peer could not be reached or refused the request."""


class PeerClient(Protocol):
    async def probe(self, host: str, port: int) -> bool: ...
    async def offer_transfer(self, host: str, port: int, request: IncomingTransferRequest) -> None: ...
    async def respond(self, host: str, port: int, transfer_id: str, patch: TransferPatch) -> None: ...
    async def cancel(self, host: str, port: int, transfer_id: str) -> None: ...


class HttpPeerClient:
    def __init__(self, timeout: float = 5.0, probe_timeout: float = 0.5,
                 transport: Optional[httpx.AsyncBaseTransport] = None) -> None:
        self.timeout = timeout
        self.probe_timeout = probe_timeout
        self.transport = transport

    def _client(self, timeout: float) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=timeout, transport=self.transport)

    @staticmethod
    def _url(host: str, port: int, path: str) -> str:
        return f"http://{host}:{port}/api/v1{path}"

    async def _send(self, method: str, url: str, json: Optional[dict] = None) -> None:
        try:
            async with self._client(self.timeout) as client:
                resp = await client.request(method, url, json=json)
        except httpx.HTTPError as exc:
            raise PeerError(f"{method} {url} failed: {exc!r}") from exc
        if resp.status_code >= 400:
            raise PeerError(f"{method} {url} returned {resp.status_code}: {resp.text[:200]}")

    async def probe(self, host: str, port: int) -> bool:
        try:
            async with self._client(self.probe_timeout) as client:
                return (await client.get(self._url(host, port, "/node"))).status_code == 200
        except httpx.HTTPError:
            return False

    async def offer_transfer(self, host: str, port: int, request: IncomingTransferRequest) -> None:
        await self._send("POST", self._url(host, port, "/transfers/incoming"), request.model_dump(mode="json"))

    async def respond(self, host: str, port: int, transfer_id: str, patch: TransferPatch) -> None:
        await self._send("PATCH", self._url(host, port, f"/transfers/{transfer_id}"), patch.model_dump(mode="json", exclude_none=True))

    async def cancel(self, host: str, port: int, transfer_id: str) -> None:
        await self._send("DELETE", self._url(host, port, f"/transfers/{transfer_id}"))
