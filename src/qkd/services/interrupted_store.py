"""
Interrupted transfers, kept on disk so they survive a node restart.

One JSON file (QKD_STATE_FILE) holds, per interrupted transfer, its API resource and, for an
outgoing one, where its upload now lives. The sender's upload is moved into a directory next to
the state file for as long as the transfer is interrupted, because the node's normal upload
directory is a per-process temp dir. The receiver needs nothing else: its verified bytes and
sidecar are under <output_dir>/.resume (services/resume.py).
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger(__name__)


class InterruptedStore:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self.uploads_dir = self.path.parent / f"{self.path.stem}-uploads"
        self._lock = threading.Lock()

    def load_all(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._read().values())

    def put(self, transfer_id: str, transfer: dict[str, Any], upload_path: Optional[str]) -> None:
        with self._lock:
            records = self._read()
            records[transfer_id] = {"transfer": transfer, "upload_path": upload_path}
            self._write(records)

    def remove(self, transfer_id: str) -> None:
        with self._lock:
            records = self._read()
            if records.pop(transfer_id, None) is not None:
                self._write(records)

    def _read(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        try:
            raw = json.loads(self.path.read_text())
        except (OSError, ValueError) as exc:
            log.warning("Ignoring unreadable state file %s: %s", self.path, exc)
            return {}
        if not isinstance(raw, dict):
            return {}
        return {k: v for k, v in raw.items() if isinstance(v, dict) and isinstance(v.get("transfer"), dict)}

    def _write(self, records: dict[str, dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        tmp.replace(self.path)
