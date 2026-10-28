"""
Peer discovery over mDNS (zeroconf).

Each node advertises `_qkd._tcp.local.` with its HTTP port and a TXT record
holding its node id, and browses for other nodes of the same type.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass
from typing import Optional, Protocol

log = logging.getLogger(__name__)

SERVICE_TYPE = "_qkd._tcp.local."
TXT_VERSION = "2"


@dataclass
class NodeIdentity:
    id: str
    name: str
    host: str
    port: int


@dataclass(frozen=True)
class PeerInfo:
    id: str
    name: str
    host: str
    port: int


class PeerDirectory(Protocol):
    async def start(self, identity: NodeIdentity) -> None: ...
    async def stop(self) -> None: ...
    async def advertise(self, identity: NodeIdentity) -> None: ...
    def peers(self) -> list[PeerInfo]: ...


def local_ip() -> str:
    """Best guess at this host's LAN address (the interface used for outbound traffic)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


class StaticPeerDirectory:
    """Fixed peer list. Used by tests, and anywhere mDNS is not available."""

    def __init__(self, peers: Optional[list[PeerInfo]] = None) -> None:
        self._peers = list(peers or [])

    async def start(self, identity: NodeIdentity) -> None: ...
    async def stop(self) -> None: ...
    async def advertise(self, identity: NodeIdentity) -> None: ...

    def peers(self) -> list[PeerInfo]:
        return list(self._peers)


class ZeroconfPeerDirectory:
    def __init__(self) -> None:
        self._zc = None
        self._browser = None
        self._info = None
        self._self_id: Optional[str] = None
        self._peers: dict[str, PeerInfo] = {}  # keyed by mDNS service name

    async def start(self, identity: NodeIdentity) -> None:
        from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf

        self._zc = AsyncZeroconf()
        await self.advertise(identity)
        self._browser = AsyncServiceBrowser(self._zc.zeroconf, SERVICE_TYPE, handlers=[self._on_change])

    async def stop(self) -> None:
        if self._browser:
            await self._browser.async_cancel()
        if self._zc:
            if self._info:
                await self._zc.async_unregister_service(self._info)
            await self._zc.async_close()
        log.info("Unregistered mDNS service")

    async def advertise(self, identity: NodeIdentity) -> None:
        from zeroconf import ServiceInfo

        self._self_id = identity.id
        info = ServiceInfo(
            SERVICE_TYPE,
            f"{identity.name}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(identity.host)],
            port=identity.port,
            properties={"id": identity.id, "version": TXT_VERSION},
            server=f"qkd-{identity.id}.local.",
        )
        if self._zc is None:
            return
        if self._info:
            await self._zc.async_unregister_service(self._info)
        await self._zc.async_register_service(info)
        self._info = info
        log.info("Registered mDNS service %s at %s:%s", identity.name, identity.host, identity.port)

    def peers(self) -> list[PeerInfo]:
        return sorted((p for p in self._peers.values() if p.id != self._self_id), key=lambda p: p.name.lower())

    def _on_change(self, zeroconf, service_type: str, name: str, state_change) -> None:
        from zeroconf import ServiceStateChange

        if state_change is ServiceStateChange.Removed:
            self._peers.pop(name, None)
        else:
            asyncio.ensure_future(self._resolve(zeroconf, service_type, name))

    async def _resolve(self, zeroconf, service_type: str, name: str) -> None:
        from zeroconf.asyncio import AsyncServiceInfo

        info = AsyncServiceInfo(service_type, name)
        if not await info.async_request(zeroconf, 3000) or not info.addresses:
            return
        props = {k.decode(): (v.decode() if v else "") for k, v in (info.properties or {}).items()}
        display = name.removesuffix(f".{SERVICE_TYPE}")
        self._peers[name] = PeerInfo(
            id=props.get("id") or display,
            name=display,
            host=socket.inet_ntoa(info.addresses[0]),
            port=info.port,
        )
