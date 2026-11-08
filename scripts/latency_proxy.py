#!/usr/bin/env python3
"""
One-connection TCP proxy that delays everything it forwards by a fixed one-way latency.

    python scripts/latency_proxy.py --target-port 65432 --one-way-ms 25

Used by scripts/benchmark.py for E6 (grid parameter `rtt_ms`): Alice connects to the
proxy, the proxy connects to Bob (or Eve), and every byte is delivered `--one-way-ms`
after it arrived, in both directions, so a request/response pair costs one round trip
of 2 x one-way. Order is preserved; there is no bandwidth limit, loss, or jitter.

It does the same job as `tc qdisc ... netem delay` on the loopback device, but needs
no root, delays only this connection (not every localhost program on the machine), and
can change latency between runs, which keeps the harness's shuffled run order.

Prints `listening <port>` on stdout once it accepts connections (port 0 = any free
port), handles exactly one connection, and exits when both directions are closed.
Imports nothing from qiskit, so it starts in well under a second.
"""

from __future__ import annotations

import argparse
import asyncio
import socket
import sys
from typing import Optional


def _no_delay(writer: asyncio.StreamWriter) -> None:
    sock = writer.get_extra_info("socket")
    if sock is not None:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


async def pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, delay_s: float) -> None:
    """
    Copy reader to writer, delivering each piece delay_s after it was read.

    A reader task stamps each piece with its due time and queues it; a writer task
    sleeps until the due time and sends it. When the source closes, the destination
    gets a half-close (EOF) after the last piece, just as a direct connection would.
    """
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[tuple[float, Optional[bytes]]] = asyncio.Queue()

    async def read_side() -> None:
        try:
            while data := await reader.read(65536):
                await queue.put((loop.time() + delay_s, data))
        except (ConnectionError, OSError):
            pass
        await queue.put((loop.time() + delay_s, None))

    async def write_side() -> None:
        while True:
            due, data = await queue.get()
            wait = due - loop.time()
            if wait > 0:
                await asyncio.sleep(wait)
            try:
                if data is None:
                    if writer.can_write_eof():
                        writer.write_eof()
                    return
                writer.write(data)
                await writer.drain()
            except (ConnectionError, OSError):
                return

    await asyncio.gather(read_side(), write_side())


async def serve(target_host: str, target_port: int, listen_port: int, delay_s: float) -> None:
    done = asyncio.Event()

    async def handle(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        server.close()  # one connection only
        try:
            target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
        except OSError:
            client_writer.close()
            done.set()
            return
        _no_delay(client_writer)
        _no_delay(target_writer)
        await asyncio.gather(
            pump(client_reader, target_writer, delay_s),
            pump(target_reader, client_writer, delay_s),
        )
        for w in (client_writer, target_writer):
            w.close()
        done.set()

    server = await asyncio.start_server(handle, "127.0.0.1", listen_port)
    port = server.sockets[0].getsockname()[1]
    print(f"listening {port}", flush=True)
    await done.wait()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, required=True)
    parser.add_argument("--listen-port", type=int, default=0, help="0 = any free port (printed on stdout)")
    parser.add_argument("--one-way-ms", type=float, required=True, help="Delay added in each direction")
    args = parser.parse_args(argv)
    if args.one_way_ms < 0:
        parser.error("--one-way-ms must not be negative")
    asyncio.run(serve(args.target_host, args.target_port, args.listen_port, args.one_way_ms / 1000))
    return 0


if __name__ == "__main__":
    sys.exit(main())
