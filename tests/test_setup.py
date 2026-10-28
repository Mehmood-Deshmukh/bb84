"""Packaging and layering rules for the src/qkd layout."""

from __future__ import annotations

import ast
import importlib
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "qkd"
OLD_MODULES = {"config", "bb84_protocol", "quantum_channel", "crypto_utils", "alice", "bob", "eve", "main"}


def imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def python_files(*parts: str) -> list[Path]:
    return sorted(SRC.joinpath(*parts).rglob("*.py"))


@pytest.mark.parametrize("path", python_files("core"), ids=lambda p: p.name)
def test_core_does_not_depend_on_outer_layers(path: Path) -> None:
    forbidden = ("qkd.services", "qkd.runner", "qkd.usecases")
    assert not [m for m in imported_modules(path) if m.startswith(forbidden)]


@pytest.mark.parametrize("path", python_files(), ids=lambda p: str(p.relative_to(SRC)))
def test_no_bare_sibling_imports(path: Path) -> None:
    assert not imported_modules(path) & OLD_MODULES


def test_wire_and_file_stream_do_not_import_qiskit() -> None:
    code = (
        "import sys, qkd.services.wire, qkd.services.file_stream, qkd.services.reporting; "
        "print(any(m == 'qiskit' or m.startswith('qiskit.') for m in sys.modules))"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout
    assert out.strip() == "False"


def test_console_entry_points_resolve() -> None:
    scripts = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["scripts"]
    assert set(scripts) == {"qkd-alice", "qkd-bob", "qkd-eve", "qkd-node"}
    for target in scripts.values():
        module, func = target.split(":")
        assert callable(getattr(importlib.import_module(module), func))


def test_optional_dependency_groups() -> None:
    extras = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["optional-dependencies"]
    assert {"backend", "hardware", "dev"} <= set(extras)
