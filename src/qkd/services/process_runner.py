"""
Launch qkd.runner.alice / bob as subprocesses and read their JSON events.

The runners are started with `--events json`, so each stdout line is one event.
Lines that are not JSON (tracebacks, warnings) are wrapped as log events, so they
still reach the log view.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from typing import Any, AsyncIterator, Protocol


class RunningProcess(Protocol):
    def events(self) -> AsyncIterator[dict[str, Any]]: ...
    async def wait(self) -> int: ...
    def terminate(self) -> None: ...


class ProtocolLauncher(Protocol):
    async def launch(self, role: str, args: list[str]) -> RunningProcess: ...


def parse_line(line: str) -> dict[str, Any]:
    """Parse one stdout line into an event dict."""
    try:
        event = json.loads(line)
        if isinstance(event, dict) and "type" in event:
            return event
    except json.JSONDecodeError:
        pass
    return {"type": "log", "stage": None, "payload": {"level": "raw", "message": line}, "ts": time.time()}


class _Subprocess:
    def __init__(self, proc: asyncio.subprocess.Process) -> None:
        self._proc = proc

    async def events(self) -> AsyncIterator[dict[str, Any]]:
        assert self._proc.stdout is not None
        async for raw in self._proc.stdout:
            line = raw.decode(errors="replace").rstrip()
            if line:
                yield parse_line(line)

    async def wait(self) -> int:
        return await self._proc.wait()

    def terminate(self) -> None:
        if self._proc.returncode is None:
            self._proc.terminate()


class SubprocessLauncher:
    """Runs `python -m qkd.runner.<role>` with the interpreter that runs the node."""

    async def launch(self, role: str, args: list[str]) -> RunningProcess:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-u", "-m", f"qkd.runner.{role}", "--events", "json", *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            limit=1 << 22,  # max bytes per stdout line
        )
        return _Subprocess(proc)
