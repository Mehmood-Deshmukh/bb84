"""EventBus: sequence numbers, replay, and fan-out to several subscribers."""

from __future__ import annotations

import asyncio

from qkd.services.events import EventBus


async def collect(bus: EventBus, transfer_id: str, after: int = 0) -> list[int]:
    return [e.seq async for e in bus.subscribe(transfer_id, after) if e is not None]


def test_multiple_subscribers_receive_every_event() -> None:
    async def scenario() -> tuple[list[int], list[int], list[int]]:
        bus = EventBus()
        bus.publish("t", "status", payload={"status": "pending"})
        first = asyncio.create_task(collect(bus, "t"))
        second = asyncio.create_task(collect(bus, "t"))
        await asyncio.sleep(0)
        assert bus.subscriber_count("t") == 2
        for i in range(3):
            bus.publish("t", "log", payload={"message": str(i)})
            await asyncio.sleep(0)
        third = asyncio.create_task(collect(bus, "t", after=2))
        await asyncio.sleep(0)
        bus.publish("t", "status", payload={"status": "completed"})
        bus.close("t")
        results = await asyncio.gather(first, second, third)
        assert bus.subscriber_count("t") == 0
        return results

    first, second, third = asyncio.run(scenario())
    assert first == second == [1, 2, 3, 4, 5]
    assert third == [3, 4, 5]


def test_subscribing_after_close_replays_and_ends() -> None:
    async def scenario() -> list[int]:
        bus = EventBus()
        for _ in range(4):
            bus.publish("t", "log")
        bus.close("t")
        return await collect(bus, "t", after=1)

    assert asyncio.run(scenario()) == [2, 3, 4]


def test_streams_are_per_transfer() -> None:
    bus = EventBus()
    bus.publish("a", "log")
    bus.publish("b", "log")
    bus.publish("a", "log")
    assert [e.seq for e in bus.history("a")] == [1, 2]
    assert [e.seq for e in bus.history("b")] == [1]


def test_heartbeat_yields_none_when_idle() -> None:
    async def scenario() -> list:
        bus = EventBus()
        gen = bus.subscribe("t", heartbeat=0.01)
        first = await gen.__anext__()
        bus.publish("t", "log")
        second = await gen.__anext__()
        await gen.aclose()
        return [first, second.seq]

    assert asyncio.run(scenario()) == [None, 1]


def test_log_is_bounded() -> None:
    bus = EventBus(max_events=3)
    for _ in range(5):
        bus.publish("t", "log")
    assert [e.seq for e in bus.history("t")] == [3, 4, 5]
