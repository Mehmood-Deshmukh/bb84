"""Finished transfers, kept in a small JSON file (QKD_HISTORY_FILE, default ./history.json)."""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path

from pydantic import ValidationError

from qkd.services.api.models import HistoryEntry

log = logging.getLogger(__name__)

MAX_ENTRIES = 50


class HistoryStore:
    def __init__(self, path: str | os.PathLike[str], max_entries: int = MAX_ENTRIES) -> None:
        self.path = Path(path)
        self.max_entries = max_entries
        self._lock = threading.Lock()

    def list(self) -> list[HistoryEntry]:
        with self._lock:
            return self._read()

    def append(self, entry: HistoryEntry) -> None:
        with self._lock:
            entries = [entry, *self._read()][: self.max_entries]
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps([e.model_dump(mode="json") for e in entries], indent=2))
            tmp.replace(self.path)

    def _read(self) -> list[HistoryEntry]:
        if not self.path.exists():
            return []
        try:
            raw = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("Ignoring unreadable history file %s: %s", self.path, exc)
            return []
        entries = []
        for item in raw if isinstance(raw, list) else []:
            try:
                entries.append(HistoryEntry.model_validate(item))
            except ValidationError:
                continue  # entries written by older versions use a different shape
        return entries
