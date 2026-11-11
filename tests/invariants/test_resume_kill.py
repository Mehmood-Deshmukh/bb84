"""
Kill and resume with real processes: qkd.runner.alice / qkd.runner.bob as the node launches them
(--events json, --resume, --transfer-id), real BB84 on the Aer simulator with QKD_NUM_QUBITS=64,
hybrid authentication. Alice is SIGKILLed mid-transfer; a second pair of processes then resumes it.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Optional

CHUNK = 4096
CHUNKS = 3000
SIZE = CHUNK * CHUNKS - 77
TID = "killtest1"


class Runner:
    """A runner process whose JSON events are collected on a thread."""

    def __init__(self, role: str, args: list[str], env: dict[str, str], cwd: Path) -> None:
        self.role = role
        self.events: list[dict[str, Any]] = []
        self.cv = threading.Condition()
        self.proc = subprocess.Popen(
            [sys.executable, "-u", "-m", f"qkd.runner.{role}", "--events", "json", *args],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, cwd=cwd,
        )
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            try:
                event = json.loads(line)
            except ValueError:
                event = {"type": "log", "payload": {"message": line.rstrip()}}
            with self.cv:
                self.events.append(event)
                self.cv.notify_all()

    def wait_for(self, predicate, timeout: float = 120.0) -> dict[str, Any]:
        with self.cv:
            if not self.cv.wait_for(lambda: any(predicate(e) for e in self.events), timeout):
                raise AssertionError(f"{self.role}: timed out waiting for an event; last: {self.events[-3:]}")
            return next(e for e in self.events if predicate(e))

    def finish(self, timeout: float = 120.0) -> int:
        code = self.proc.wait(timeout)
        self.reader.join(10)
        return code

    def result(self) -> Optional[dict[str, Any]]:
        return next((e["payload"] for e in reversed(self.events) if e["type"] == "result"), None)

    def metrics(self) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        for e in self.events:
            if e["type"] == "metrics":
                merged.update(e["payload"])
        return merged

    def progress(self) -> list[dict[str, Any]]:
        return [e["payload"] for e in self.events if e["type"] == "progress"]

    def kill(self) -> None:
        self.proc.send_signal(signal.SIGKILL)


def start_pair(src: Path, work: Path, out: Path) -> tuple[Runner, Runner]:
    env = {
        **os.environ,
        "QKD_NUM_QUBITS": "64",
        "QKD_ENFORCE_FINITE_KEY": "false",  # 64 qubits cannot reach the finite-key length
        "QKD_AUTH_MODE": "hybrid",
        "QKD_CHUNK_SIZE": str(CHUNK),
        "QKD_RESUME_SYNC_CHUNKS": "1",  # an fsync per chunk keeps Bob slow enough to be killed mid-stream
    }
    bob = Runner("bob", ["--port", "0", "--output-dir", str(out), "--transfer-id", TID, "--resume",
                         "--identity", str(work / "bob-id")],
                 {**env, "QKD_KNOWN_PEERS_FILE": str(work / "bob-peers.json")}, work)
    port = bob.wait_for(lambda e: e["type"] == "listening")["payload"]["port"]
    alice = Runner("alice", [str(src), "--host", "127.0.0.1", "--port", str(port), "--transfer-id", TID, "--resume",
                             "--identity", str(work / "alice-id")],
                   {**env, "QKD_KNOWN_PEERS_FILE": str(work / "alice-peers.json")}, work)
    return alice, bob


def test_sigkill_the_sender_mid_transfer_then_resume(tmp_path: Path) -> None:
    src = tmp_path / "big.bin"
    src.write_bytes(os.urandom(SIZE))
    out = tmp_path / "received"
    state = out / ".resume"

    # ── first attempt: kill Alice once Bob has verified a few percent ──
    alice, bob = start_pair(src, tmp_path, out)
    try:
        bob.wait_for(lambda e: e["type"] == "progress" and e["payload"]["chunks_done"] >= CHUNKS // 20)
        alice.kill()
        assert bob.finish() == 1
    finally:
        for r in (alice, bob):
            if r.proc.poll() is None:
                r.proc.kill()
    alice.finish()
    assert alice.proc.returncode == -signal.SIGKILL

    assert bob.result()["outcome"] == "interrupted", bob.result()
    assert not (out / "received_big.bin").exists(), "a killed transfer must not leave a final file"
    part = state / f"{TID}.part"
    side = json.loads((state / f"{TID}.json").read_text())
    verified = side["next_chunk"] * CHUNK
    assert 0 < verified < SIZE and part.stat().st_size == verified, "the .part holds exactly the verified chunks"
    assert part.read_bytes() == src.read_bytes()[:verified], "and they are the right bytes"
    assert side["peer_fingerprint"] and side["auth_mode"] == "hybrid"

    # ── second attempt: new processes, a new handshake, a new key ──
    alice2, bob2 = start_pair(src, tmp_path, out)
    assert bob2.finish() == 0, bob2.events[-5:]
    assert alice2.finish() == 0, alice2.events[-5:]

    assert bob2.result()["outcome"] == "completed" and alice2.result()["outcome"] == "completed"
    assert (out / "received_big.bin").read_bytes() == src.read_bytes()
    assert os.listdir(state) == [f"{TID}.done.json"], "the partial state is gone; only the delivery record stays"

    resumed = bob2.metrics()["resumed_from_bytes"]
    assert resumed == verified and alice2.metrics()["resumed_from_bytes"] == resumed
    assert bob2.metrics()["bytes_total"] == SIZE
    # Only the missing part crossed the wire: progress starts at the offset on both sides
    assert alice2.progress()[0]["chunks_done"] == side["next_chunk"] == bob2.progress()[0]["chunks_done"]
    assert alice2.progress()[-1]["chunks_done"] == CHUNKS
    assert bob2.metrics()["auth_mode"] == "hybrid" and bob2.metrics()["peer_trust"] in ("pinned", "new")
