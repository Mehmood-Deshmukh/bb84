"""
Transfer state machine and storage.

    pending -> accepted -> key_exchange -> transferring -> completed
       |          |             |               |
       |          +-------------+---------------+--> failed, cancelled
       |                        +--> aborted_qber, aborted_auth
       +--> rejected, failed, cancelled

completed, rejected, aborted_qber, aborted_auth, failed, and cancelled are terminal.

Resumable transfers add one non-terminal status, `interrupted`. It is kept apart from TRANSITIONS
(which only holds the edges above, so `can_transition` never involves it) in RESUME_TRANSITIONS:

    transferring -> interrupted -> pending (the sender resumes) -> accepted -> ... -> completed
                        |
                        +--> cancelled, failed
    pending -> interrupted (a resume offer that the peer did not take)

`can_move` and `path_to` know both tables.
"""

from __future__ import annotations

import threading
from typing import Iterable, Optional, Protocol

from qkd.services.api.models import Direction, Transfer, TransferStatus, utcnow

S = TransferStatus

TERMINAL: frozenset[TransferStatus] = frozenset({S.completed, S.rejected, S.aborted_qber, S.aborted_auth, S.failed, S.cancelled})
ACTIVE: frozenset[TransferStatus] = frozenset({S.accepted, S.key_exchange, S.transferring})

TRANSITIONS: dict[TransferStatus, frozenset[TransferStatus]] = {
    S.pending: frozenset({S.accepted, S.rejected, S.failed, S.cancelled}),
    S.accepted: frozenset({S.key_exchange, S.failed, S.cancelled}),
    S.key_exchange: frozenset({S.transferring, S.aborted_qber, S.aborted_auth, S.failed, S.cancelled}),
    S.transferring: frozenset({S.completed, S.failed, S.cancelled}),
    S.interrupted: frozenset(),  # its exits live in RESUME_TRANSITIONS
    **{s: frozenset() for s in TERMINAL},
}

RESUME_TRANSITIONS: dict[TransferStatus, frozenset[TransferStatus]] = {
    S.transferring: frozenset({S.interrupted}),
    S.interrupted: frozenset({S.pending, S.cancelled, S.failed}),
    S.pending: frozenset({S.interrupted}),
}

# Forward path used when protocol events skip intermediate statuses
_HAPPY_PATH = (S.accepted, S.key_exchange, S.transferring, S.completed)


class InvalidTransition(Exception):
    def __init__(self, current: TransferStatus, target: TransferStatus) -> None:
        super().__init__(f"Cannot move a transfer from '{current.value}' to '{target.value}'")
        self.current = current
        self.target = target


class TransferNotFound(KeyError):
    pass


class TransferExists(Exception):
    pass


def can_transition(current: TransferStatus, target: TransferStatus) -> bool:
    """Whether the base state machine allows current -> target (never involves `interrupted`)."""
    return target in TRANSITIONS[current]


def can_move(current: TransferStatus, target: TransferStatus) -> bool:
    """can_transition, plus the edges of resumable transfers."""
    return can_transition(current, target) or target in RESUME_TRANSITIONS.get(current, frozenset())


def path_to(current: TransferStatus, target: TransferStatus) -> list[TransferStatus]:
    """
    Statuses to step through to reach target. Follows the happy path when target is
    further along it (e.g. accepted -> transferring goes through key_exchange).
    Raises InvalidTransition when target is not reachable.
    """
    if can_move(current, target):
        return [target]
    if current in _HAPPY_PATH:
        steps: list[TransferStatus] = []
        for status in _HAPPY_PATH[_HAPPY_PATH.index(current) + 1:]:
            steps.append(status)
            if can_move(status, target):
                return steps + [target]
    raise InvalidTransition(current, target)


class TransferRepository(Protocol):
    def add(self, transfer: Transfer) -> Transfer: ...
    def get(self, transfer_id: str) -> Transfer: ...
    def list(self, direction: Optional[Direction] = None, statuses: Optional[Iterable[TransferStatus]] = None) -> list[Transfer]: ...
    def save(self, transfer: Transfer) -> Transfer: ...


class InMemoryTransferRepository:
    """Thread-safe dict-backed repository. Transfers are lost on restart; history.json keeps finished ones."""

    def __init__(self) -> None:
        self._items: dict[str, Transfer] = {}
        self._lock = threading.Lock()

    def add(self, transfer: Transfer) -> Transfer:
        with self._lock:
            if transfer.id in self._items:
                raise TransferExists(transfer.id)
            self._items[transfer.id] = transfer.model_copy()
            return transfer

    def get(self, transfer_id: str) -> Transfer:
        with self._lock:
            try:
                return self._items[transfer_id].model_copy()
            except KeyError:
                raise TransferNotFound(transfer_id) from None

    def list(self, direction: Optional[Direction] = None, statuses: Optional[Iterable[TransferStatus]] = None) -> list[Transfer]:
        wanted = set(statuses) if statuses else None
        with self._lock:
            items = [t.model_copy() for t in self._items.values()
                     if (direction is None or t.direction == direction) and (wanted is None or t.status in wanted)]
        return sorted(items, key=lambda t: t.created_at, reverse=True)

    def save(self, transfer: Transfer) -> Transfer:
        with self._lock:
            if transfer.id not in self._items:
                raise TransferNotFound(transfer.id)
            transfer.updated_at = utcnow()
            self._items[transfer.id] = transfer.model_copy()
            return transfer
