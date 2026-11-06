"""
Per-transfer event log with fan-out to any number of subscribers.

Every event gets a sequence number. Subscribers first receive the stored events
after the sequence number they ask for (for SSE reconnects via Last-Event-ID),
then live events, until the transfer's stream is closed.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from typing import Any, AsyncIterator, Optional

from qkd.services.api.models import TransferEvent

MAX_EVENTS_PER_TRANSFER = 5000
_CLOSED = None  # queue sentinel

STAGE_STATUS: dict[str, str] = {
    "authentication": "key_exchange",
    "quantum_transmission": "key_exchange",
    "sifting": "key_exchange",
    "qber_estimation": "key_exchange",
    "privacy_amplification": "key_exchange",
    "key_confirmation": "key_exchange",
    "file_transfer": "transferring",
}

METRIC_FIELDS: tuple[str, ...] = (
    "raw_qubits",
    "sifted_length",
    "sample_size",
    "qber",
    "qber_threshold",
    "key_bits",
    "output_path",
    "auth_mode",
    "peer_fingerprint",
    "peer_trust",
    "handshake_ms",
    "auth_overhead_bytes",
    "resumed_from_bytes",
    "bytes_total",
    "resume_restart_reason",
)


class EventBus:
    def __init__(self, max_events: int = MAX_EVENTS_PER_TRANSFER) -> None:
        self.max_events = max_events
        self._log: dict[str, list[TransferEvent]] = defaultdict(list)
        self._seq: dict[str, int] = defaultdict(int)
        self._subscribers: dict[str, set[asyncio.Queue]] = defaultdict(set)
        self._closed: set[str] = set()

    def publish(self, transfer_id: str, type_: str, stage: Optional[str] = None,
                payload: Optional[dict[str, Any]] = None, ts: Optional[float] = None) -> TransferEvent:
        self._seq[transfer_id] += 1
        event = TransferEvent(seq=self._seq[transfer_id], type=type_, transfer_id=transfer_id,
                              stage=stage, payload=payload or {}, ts=ts or time.time())
        log = self._log[transfer_id]
        log.append(event)
        if len(log) > self.max_events:
            del log[: len(log) - self.max_events]
        for queue in self._subscribers[transfer_id]:
            queue.put_nowait(event)
        return event

    def close(self, transfer_id: str) -> None:
        """Mark the stream finished. Current subscribers drain and stop; new ones get the replay only."""
        self._closed.add(transfer_id)
        for queue in self._subscribers[transfer_id]:
            queue.put_nowait(_CLOSED)

    def history(self, transfer_id: str, after: int = 0) -> list[TransferEvent]:
        return [e for e in self._log.get(transfer_id, []) if e.seq > after]

    def subscriber_count(self, transfer_id: str) -> int:
        return len(self._subscribers.get(transfer_id, ()))

    async def subscribe(self, transfer_id: str, after: int = 0,
                        heartbeat: Optional[float] = None) -> AsyncIterator[Optional[TransferEvent]]:
        """
        Yield stored events after `after`, then live events until the stream is closed.
        With `heartbeat`, yields None after that many idle seconds (for SSE keepalives).
        """
        queue: asyncio.Queue = asyncio.Queue()
        # Register before replaying so nothing published in between is lost.
        self._subscribers[transfer_id].add(queue)
        try:
            last = after
            for event in self.history(transfer_id, after):
                last = event.seq
                yield event
            if transfer_id in self._closed:
                for event in self.history(transfer_id, last):  # published while replaying
                    yield event
                return
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), heartbeat)
                except asyncio.TimeoutError:
                    yield None
                    continue
                if event is _CLOSED:
                    return
                if event.seq > last:
                    last = event.seq
                    yield event
        finally:
            self._subscribers[transfer_id].discard(queue)
