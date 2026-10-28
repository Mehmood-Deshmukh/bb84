"""Progress reporting for the protocol workflows (human-readable console output)."""

from __future__ import annotations

import sys
from typing import Protocol, TextIO


class Reporter(Protocol):
    def section(self, title: str) -> None: ...
    def info(self, message: str) -> None: ...
    def success(self, message: str) -> None: ...
    def warning(self, message: str) -> None: ...
    def error(self, message: str) -> None: ...


class _Ansi:
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[35m"
    BOLD = "\033[1m"
    END = "\033[0m"


class ConsoleReporter:
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


class NullReporter:
    """Discards all output. Useful for library callers and tests."""

    def section(self, title: str) -> None: ...
    def info(self, message: str) -> None: ...
    def success(self, message: str) -> None: ...
    def warning(self, message: str) -> None: ...
    def error(self, message: str) -> None: ...
