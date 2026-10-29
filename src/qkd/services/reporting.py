"""
Progress reporting for the protocol workflows.

Workflows report two kinds of output through a Reporter:
  - human log lines: section/info/success/warning/error
  - structured events: stage changes, metrics, chunk progress, the final result

ConsoleReporter prints the log lines for people. JsonEventReporter writes every
call as one JSON object per line, which the backend node parses:

    {"type": "metrics", "transfer_id": "...", "stage": "qber_estimation",
     "payload": {"qber": 0.0, "qber_threshold": 0.11, "sample_size": 9}, "ts": 1730000000.0}
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any, Optional, Protocol, TextIO

# Protocol stages, in order. The backend maps these onto transfer statuses.
STAGES = (
    "connecting",
    "quantum_transmission",
    "sifting",
    "qber_estimation",
    "privacy_amplification",
    "file_transfer",
    "done",
)

# Event types written by JsonEventReporter
EVENT_LOG = "log"
EVENT_STAGE = "stage"
EVENT_METRICS = "metrics"
EVENT_PROGRESS = "progress"
EVENT_RESULT = "result"
EVENT_LISTENING = "listening"

# Values of the "outcome" field in a result event
OUTCOME_COMPLETED = "completed"
OUTCOME_ABORTED_QBER = "aborted_qber"
OUTCOME_ABORTED_AUTH = "aborted_auth"
OUTCOME_FAILED = "failed"


class Reporter(Protocol):
    def section(self, title: str) -> None: ...
    def info(self, message: str) -> None: ...
    def success(self, message: str) -> None: ...
    def warning(self, message: str) -> None: ...
    def error(self, message: str) -> None: ...
    def stage(self, stage: str) -> None: ...
    def metrics(self, **values: Any) -> None: ...
    def progress(self, chunks_done: int, num_chunks: int, bytes_done: int, total_bytes: int) -> None: ...
    def listening(self, port: int) -> None: ...
    def result(self, outcome: str, error: Optional[str] = None) -> None: ...


class NullReporter:
    """Discards everything. Base class for reporters that only handle part of the interface."""

    def section(self, title: str) -> None: ...
    def info(self, message: str) -> None: ...
    def success(self, message: str) -> None: ...
    def warning(self, message: str) -> None: ...
    def error(self, message: str) -> None: ...
    def stage(self, stage: str) -> None: ...
    def metrics(self, **values: Any) -> None: ...
    def progress(self, chunks_done: int, num_chunks: int, bytes_done: int, total_bytes: int) -> None: ...
    def listening(self, port: int) -> None: ...
    def result(self, outcome: str, error: Optional[str] = None) -> None: ...


class _Ansi:
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    END = "\033[0m"


class ConsoleReporter(NullReporter):
    """Prints `▸ message` style lines. Colour is used only when the stream is a TTY."""

    def __init__(self, stream: TextIO | None = None, accent: str = _Ansi.CYAN, info_color: str = _Ansi.BLUE) -> None:
        self.stream = stream or sys.stdout
        self.color = self.stream.isatty()
        self.accent = accent
        self.info_color = info_color

    def _c(self, code: str, text: str) -> str:
        return f"{code}{text}{_Ansi.END}" if self.color else text

    def _line(self, symbol: str, code: str, message: str) -> None:
        print(f"  {self._c(code, symbol)} {message}", file=self.stream, flush=True)

    def banner(self, title: str, subtitle: str) -> None:
        width = 58
        lines = ["╔" + "═" * width + "╗", f"║{title:^{width}}║", f"║{subtitle:^{width}}║", "╚" + "═" * width + "╝"]
        print("\n" + "\n".join(self._c(_Ansi.BOLD + self.accent, line) for line in lines) + "\n", file=self.stream, flush=True)

    def section(self, title: str) -> None:
        rule = "─" * 58
        print(f"\n{self._c(_Ansi.BOLD + self.accent, rule)}\n  {self._c(_Ansi.BOLD, title)}\n{self._c(self.accent, rule)}",
              file=self.stream, flush=True)

    def info(self, message: str) -> None:
        self._line("▸", self.info_color, message)

    def success(self, message: str) -> None:
        self._line("✓", _Ansi.GREEN, message)

    def warning(self, message: str) -> None:
        self._line("⚠", _Ansi.YELLOW, message)

    def error(self, message: str) -> None:
        self._line("✗", _Ansi.RED, message)


def eve_console() -> ConsoleReporter:
    """Console reporter with Eve's red styling."""
    return ConsoleReporter(accent=_Ansi.RED, info_color=_Ansi.RED)


class JsonEventReporter:
    """Writes every report as one JSON event per line (for the backend node)."""

    def __init__(self, transfer_id: Optional[str] = None, stream: TextIO | None = None) -> None:
        self.transfer_id = transfer_id
        self.stream = stream or sys.stdout
        self.current_stage: Optional[str] = None
        self._last_percent = -1

    def emit(self, type_: str, **payload: Any) -> None:
        event = {"type": type_, "transfer_id": self.transfer_id, "stage": self.current_stage,
                 "payload": payload, "ts": time.time()}
        self.stream.write(json.dumps(event) + "\n")
        self.stream.flush()

    def _log(self, level: str, message: str) -> None:
        self.emit(EVENT_LOG, level=level, message=message)

    def section(self, title: str) -> None:
        self._log("section", title)

    def info(self, message: str) -> None:
        self._log("info", message)

    def success(self, message: str) -> None:
        self._log("success", message)

    def warning(self, message: str) -> None:
        self._log("warning", message)

    def error(self, message: str) -> None:
        self._log("error", message)

    def stage(self, stage: str) -> None:
        self.current_stage = stage
        self.emit(EVENT_STAGE)

    def metrics(self, **values: Any) -> None:
        self.emit(EVENT_METRICS, **values)

    def progress(self, chunks_done: int, num_chunks: int, bytes_done: int, total_bytes: int) -> None:
        # One event per whole percent keeps large files from flooding the stream.
        percent = 100 if num_chunks == 0 else chunks_done * 100 // num_chunks
        if percent == self._last_percent and chunks_done != num_chunks:
            return
        self._last_percent = percent
        self.emit(EVENT_PROGRESS, chunks_done=chunks_done, num_chunks=num_chunks,
                  bytes_done=bytes_done, total_bytes=total_bytes)

    def listening(self, port: int) -> None:
        self.emit(EVENT_LISTENING, port=port)

    def result(self, outcome: str, error: Optional[str] = None) -> None:
        self.current_stage = "done"
        self.emit(EVENT_RESULT, outcome=outcome, error=error)
