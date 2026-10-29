"""Transfer state machine and the in-memory repository."""

from __future__ import annotations

import itertools

import pytest

from qkd.services.api.models import Direction, PeerRef, Transfer, TransferStatus as S
from qkd.services.transfer_store import (
    TERMINAL,
    TRANSITIONS,
    InMemoryTransferRepository,
    InvalidTransition,
    TransferExists,
    TransferNotFound,
    can_transition,
    path_to,
)

ALLOWED = {
    (S.pending, S.accepted), (S.pending, S.rejected), (S.pending, S.failed), (S.pending, S.cancelled),
    (S.accepted, S.key_exchange), (S.accepted, S.failed), (S.accepted, S.cancelled),
    (S.key_exchange, S.transferring), (S.key_exchange, S.aborted_qber), (S.key_exchange, S.aborted_auth),
    (S.key_exchange, S.failed), (S.key_exchange, S.cancelled),
    (S.transferring, S.completed), (S.transferring, S.failed), (S.transferring, S.cancelled),
}


@pytest.mark.parametrize(("current", "target"), list(itertools.product(S, S)), ids=lambda s: s.value)
def test_transition_table(current: S, target: S) -> None:
    assert can_transition(current, target) is ((current, target) in ALLOWED)


def test_terminal_states_have_no_exits() -> None:
    assert TERMINAL == {S.completed, S.rejected, S.aborted_qber, S.aborted_auth, S.failed, S.cancelled}
    assert all(not TRANSITIONS[s] for s in TERMINAL)


@pytest.mark.parametrize(("current", "target", "steps"), [
    (S.accepted, S.transferring, [S.key_exchange, S.transferring]),
    (S.accepted, S.completed, [S.key_exchange, S.transferring, S.completed]),
    (S.accepted, S.aborted_qber, [S.key_exchange, S.aborted_qber]),
    (S.accepted, S.aborted_auth, [S.key_exchange, S.aborted_auth]),
    (S.key_exchange, S.completed, [S.transferring, S.completed]),
    (S.transferring, S.cancelled, [S.cancelled]),
])
def test_path_to_follows_happy_path(current: S, target: S, steps: list[S]) -> None:
    assert path_to(current, target) == steps


@pytest.mark.parametrize(("current", "target"), [
    (S.pending, S.key_exchange), (S.pending, S.completed), (S.transferring, S.aborted_qber),
    (S.transferring, S.aborted_auth),
    (S.completed, S.cancelled), (S.cancelled, S.cancelled), (S.rejected, S.accepted),
])
def test_path_to_rejects_invalid(current: S, target: S) -> None:
    with pytest.raises(InvalidTransition):
        path_to(current, target)


def make(transfer_id: str, direction: Direction = Direction.outgoing, status: S = S.pending) -> Transfer:
    return Transfer(id=transfer_id, direction=direction, status=status, filename="f", file_size=1,
                    peer=PeerRef(id="p", name="p", host="10.0.0.1", port=8000))


def test_repository_crud_and_filters() -> None:
    repo = InMemoryTransferRepository()
    repo.add(make("a"))
    repo.add(make("b", Direction.incoming))
    repo.add(make("c", Direction.incoming, S.completed))
    with pytest.raises(TransferExists):
        repo.add(make("a"))
    with pytest.raises(TransferNotFound):
        repo.get("zzz")

    assert {t.id for t in repo.list()} == {"a", "b", "c"}
    assert {t.id for t in repo.list(Direction.incoming)} == {"b", "c"}
    assert {t.id for t in repo.list(statuses=[S.pending])} == {"a", "b"}

    t = repo.get("a")
    t.status = S.accepted
    repo.save(t)
    assert repo.get("a").status is S.accepted


def test_repository_returns_copies() -> None:
    repo = InMemoryTransferRepository()
    repo.add(make("a"))
    repo.get("a").status = S.failed
    assert repo.get("a").status is S.pending
