"""Test doubles for the node service: scripted runner processes and recording peer clients."""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any, AsyncIterator, Callable, Optional

from qkd.services.api.models import IncomingTransferRequest, TransferPatch
from qkd.services.peer_client import PeerError


def ev(type_: str, stage: Optional[str] = None, **payload: Any) -> dict[str, Any]:
    return {"type": type_, "stage": stage, "payload": payload, "ts": time.time()}


def key_exchange_events(qber: float = 0.0, threshold: float = 0.11) -> list[dict]:
    return [
        ev("stage", "quantum_transmission"),
        ev("log", "quantum_transmission", level="info", message="Sending qubits"),
        ev("stage", "sifting"),
        ev("metrics", "sifting", raw_qubits=128, sifted_length=61),
        ev("stage", "qber_estimation"),
        ev("metrics", "qber_estimation", qber=qber, qber_threshold=threshold, sample_size=9),
    ]


def success_tail(extra_metrics: Optional[dict] = None) -> list[dict]:
    tail = [
        ev("stage", "privacy_amplification"),
        ev("metrics", "privacy_amplification", key_bits=256),
        ev("stage", "file_transfer"),
        ev("progress", "file_transfer", chunks_done=0, num_chunks=2, bytes_done=0, total_bytes=100_000),
        ev("progress", "file_transfer", chunks_done=2, num_chunks=2, bytes_done=100_000, total_bytes=100_000),
    ]
    if extra_metrics:
        tail.append(ev("metrics", "file_transfer", **extra_metrics))
    return tail + [ev("result", "done", outcome="completed", error=None)]


def alice_script(outcome: str = "completed") -> list[dict]:
    events = [ev("stage", "connecting")] + key_exchange_events(qber=0.25 if outcome == "aborted_qber" else 0.0)
    if outcome == "aborted_qber":
        return events + [ev("result", "done", outcome="aborted_qber", error="QBER 25.00% >= threshold 11%")]
    return events + success_tail()


def bob_script(port: int = 40001) -> list[dict]:
    return ([ev("stage", "connecting"), ev("listening", "connecting", port=port)]
            + key_exchange_events() + success_tail({"output_path": "/tmp/received/received_a.bin"}))


class FakeProcess:
    """
    Yields scripted events. With `gate`, pauses before event `gate_at` until the gate opens.
    With `block`, keeps running after the script until terminated.
    """

    def __init__(self, events: list[dict], exit_code: int = 0, gate: Optional[threading.Event] = None,
                 gate_at: int = 0, block: bool = False) -> None:
        self.script = events
        self.exit_code = exit_code
        self.gate = gate
        self.gate_at = gate_at
        self.block = block
        self.terminated = False

    async def events(self) -> AsyncIterator[dict]:
        for i, event in enumerate(self.script):
            if self.gate is not None and i == self.gate_at:
                await asyncio.to_thread(self.gate.wait, 10)
            if self.terminated:
                return
            yield event
            await asyncio.sleep(0)
        while self.block and not self.terminated:
            await asyncio.sleep(0.01)

    async def wait(self) -> int:
        return -15 if self.terminated else self.exit_code

    def terminate(self) -> None:
        self.terminated = True


class FakeLauncher:
    """Hands out FakeProcesses from per-role factories and records every launch."""

    def __init__(self, **factories: Callable[[list[str]], FakeProcess]) -> None:
        self.factories = factories
        self.launches: list[tuple[str, list[str], FakeProcess]] = []
        self.launched = threading.Event()

    async def launch(self, role: str, args: list[str]) -> FakeProcess:
        process = self.factories[role](args)
        self.launches.append((role, args, process))
        self.launched.set()
        return process

    def roles(self) -> list[str]:
        return [role for role, _, _ in self.launches]


class RecordingPeerClient:
    """Records calls to other nodes. Methods named in `failing` raise PeerError."""

    def __init__(self, failing: tuple[str, ...] = ()) -> None:
        self.calls: list[tuple] = []
        self.failing = set(failing)

    def _record(self, name: str, *args: Any) -> None:
        self.calls.append((name, *args))
        if name in self.failing:
            raise PeerError(f"{name} failed (test)")

    def called(self, name: str) -> list[tuple]:
        return [c for c in self.calls if c[0] == name]

    async def probe(self, host: str, port: int) -> bool:
        return "probe" not in self.failing

    async def offer_transfer(self, host: str, port: int, request: IncomingTransferRequest) -> None:
        self._record("offer_transfer", host, port, request)

    async def respond(self, host: str, port: int, transfer_id: str, patch: TransferPatch) -> None:
        self._record("respond", host, port, transfer_id, patch)

    async def cancel(self, host: str, port: int, transfer_id: str) -> None:
        self._record("cancel", host, port, transfer_id)


class RoutedPeerClient:
    """Delivers peer calls to other in-process apps through their TestClients, keyed by (host, port)."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, int], Any] = {}

    async def _call(self, host: str, port: int, method: str, path: str, json: Optional[dict] = None) -> None:
        client = self.routes.get((host, port))
        if client is None:
            raise PeerError(f"no route to {host}:{port}")
        resp = await asyncio.to_thread(client.request, method, f"/api/v1{path}", json=json)
        if resp.status_code >= 400:
            raise PeerError(f"{method} {path} -> {resp.status_code} {resp.text}")

    async def probe(self, host: str, port: int) -> bool:
        return (host, port) in self.routes

    async def offer_transfer(self, host: str, port: int, request: IncomingTransferRequest) -> None:
        await self._call(host, port, "POST", "/transfers/incoming", request.model_dump(mode="json"))

    async def respond(self, host: str, port: int, transfer_id: str, patch: TransferPatch) -> None:
        await self._call(host, port, "PATCH", f"/transfers/{transfer_id}", patch.model_dump(mode="json", exclude_none=True))

    async def cancel(self, host: str, port: int, transfer_id: str) -> None:
        await self._call(host, port, "DELETE", f"/transfers/{transfer_id}")
