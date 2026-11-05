"""
Resumable transfers at the node level: the `interrupted` status, persistence across restarts,
POST /transfers/{id}/resume, resume offers, and the history. Protocol processes are scripted fakes.
"""

from __future__ import annotations

import io
import json
import os
import threading
import time
from pathlib import Path
from typing import Callable, Optional

import pytest
from fastapi.testclient import TestClient

from qkd.services.api.app import create_app
from qkd.services.api.models import TransferStatus as S
from qkd.services.discovery import NodeIdentity, PeerInfo, StaticPeerDirectory
from qkd.services.events import EventBus
from qkd.services.history import HistoryStore
from qkd.services.interrupted_store import InterruptedStore
from qkd.services.node import NodeService
from qkd.services.resume import ResumeStore
from qkd.services.transfer_store import (
    InMemoryTransferRepository,
    InvalidTransition,
    can_move,
    can_transition,
    path_to,
)
from tests.services.fakes import (
    FakeLauncher,
    FakeProcess,
    RecordingPeerClient,
    RoutedPeerClient,
    ev,
    key_exchange_events,
)

PEER = PeerInfo(id="peer-b", name="bob-laptop", host="10.0.0.2", port=8001)
A_ID = NodeIdentity(id="node-a", name="alice-laptop", host="10.0.0.1", port=8000)
B_ID = NodeIdentity(id="node-b", name="bob-laptop", host="10.0.0.2", port=8001)
SENDER = {"id": "node-a", "name": "alice-laptop", "host": "10.0.0.1", "port": 8000}
FP = "1111-2222-3333-4444"
SIZE = 1000


# ── scripted runners ────────────────────────────────────────────


def runner_events(end: str, *, auth_mode: str = "hybrid", resumed_from: Optional[int] = None, listening: Optional[int] = None) -> list[dict]:
    """A runner that gets as far as streaming, then: end = 'completed', 'interrupted' (result event) or 'died' (no result)."""
    events = [ev("stage", "connecting")]
    if listening:
        events.append(ev("listening", "connecting", port=listening))
    events += [ev("stage", "authentication"),
               ev("metrics", "authentication", auth_mode=auth_mode, peer_fingerprint=FP, peer_trust="pinned")]
    events += key_exchange_events()
    events += [ev("stage", "privacy_amplification"), ev("metrics", "privacy_amplification", key_bits=256),
               ev("stage", "key_confirmation"), ev("stage", "file_transfer")]
    if resumed_from is not None:
        events.append(ev("metrics", "file_transfer", resumed_from_bytes=resumed_from, bytes_total=SIZE))
    if end == "completed":
        events += [ev("progress", "file_transfer", chunks_done=10, num_chunks=10, bytes_done=SIZE, total_bytes=SIZE),
                   ev("result", "done", outcome="completed", error=None)]
    else:
        events.append(ev("progress", "file_transfer", chunks_done=4, num_chunks=10, bytes_done=400, total_bytes=SIZE))
        if end == "interrupted":
            events.append(ev("result", "done", outcome="interrupted", error="ConnectionResetError: peer vanished"))
    return events


def make_node(root: Path, launcher: FakeLauncher, peers, identity: NodeIdentity, peer: Optional[PeerInfo] = PEER, *,
              resume: bool = True) -> NodeService:
    return NodeService(
        identity,
        repo=InMemoryTransferRepository(),
        bus=EventBus(),
        history=HistoryStore(root / f"history-{identity.id}.json"),
        directory=StaticPeerDirectory([peer] if peer else []),
        peers=peers,
        launcher=launcher,
        output_dir=str(root / f"received-{identity.id}"),
        upload_dir=str(root / f"uploads-{identity.id}"),
        version="test",
        listen_timeout=5,
        identity_dir=root / f"identity-{identity.id}",
        known_peers_file=root / f"known-peers-{identity.id}.json",
        resume=resume,
        state_file=root / f"state-{identity.id}.json",
    )


def wait_for(client: TestClient, transfer_id: str, *statuses: str, timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    while True:
        body = client.get(f"/api/v1/transfers/{transfer_id}").json()
        if body["status"] in statuses:
            return body
        if time.monotonic() > deadline:
            raise AssertionError(f"transfer stayed {body['status']}, wanted {statuses}: {body}")
        time.sleep(0.02)


def upload(client: TestClient, peer_id: str = PEER.id) -> str:
    resp = client.post("/api/v1/transfers", data={"peer_id": peer_id}, files={"file": ("a.bin", io.BytesIO(b"x" * SIZE))})
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def start_sender(client: TestClient, tid: str, port: int = 40001) -> None:
    assert client.patch(f"/api/v1/transfers/{tid}", json={"status": "accepted", "receiver_port": port}).status_code == 202


def interrupted_sender(root: Path, end: str = "interrupted"):
    """A node whose outgoing transfer was interrupted. Returns (service, client context manager)."""
    launcher = FakeLauncher(alice=lambda args: FakeProcess(runner_events(end), exit_code=1 if end != "completed" else 0))
    service = make_node(root, launcher, RecordingPeerClient(), A_ID)
    return service, launcher


def error_code(resp, status: int) -> str:
    assert resp.status_code == status, resp.text
    return resp.json()["error"]["code"]


# ── state machine ───────────────────────────────────────────────


def test_interrupted_is_only_reachable_through_the_resume_table() -> None:
    assert not any(can_transition(s, S.interrupted) or can_transition(S.interrupted, s) for s in S)
    assert can_move(S.transferring, S.interrupted)
    assert {t for t in S if can_move(S.interrupted, t)} == {S.pending, S.cancelled, S.failed}
    assert {s for s in S if can_move(s, S.interrupted)} == {S.transferring, S.pending}


def test_path_to_interrupted_follows_the_happy_path() -> None:
    assert path_to(S.transferring, S.interrupted) == [S.interrupted]
    assert path_to(S.key_exchange, S.interrupted) == [S.transferring, S.interrupted]
    assert path_to(S.accepted, S.interrupted) == [S.key_exchange, S.transferring, S.interrupted]
    assert path_to(S.interrupted, S.pending) == [S.pending]


@pytest.mark.parametrize("target", [S.completed, S.transferring, S.key_exchange, S.accepted, S.rejected, S.aborted_qber])
def test_an_interrupted_transfer_cannot_jump_ahead(target: S) -> None:
    with pytest.raises(InvalidTransition):
        path_to(S.interrupted, target)


# ── the persistence file ────────────────────────────────────────


def test_store_roundtrip_and_remove(tmp_path: Path) -> None:
    store = InterruptedStore(tmp_path / "state.json")
    assert store.load_all() == []
    store.put("t1", {"id": "t1"}, "/up/a")
    store.put("t2", {"id": "t2"}, None)
    assert {r["transfer"]["id"] for r in store.load_all()} == {"t1", "t2"}
    store.remove("t1")
    store.remove("missing")
    assert [r["transfer"]["id"] for r in InterruptedStore(tmp_path / "state.json").load_all()] == ["t2"]
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize("content", ["not json", "[]", '{"t1": 3}', '{"t1": {"transfer": "x"}}'])
def test_store_ignores_garbage(tmp_path: Path, content: str) -> None:
    path = tmp_path / "state.json"
    path.write_text(content)
    assert InterruptedStore(path).load_all() == []


# ── a transfer that stops becomes interrupted, not failed ───────


@pytest.mark.parametrize("end, exit_code", [("interrupted", 1), ("died", -9)])
def test_a_stopped_runner_leaves_the_transfer_interrupted(tmp_path: Path, end: str, exit_code: int) -> None:
    launcher = FakeLauncher(alice=lambda args: FakeProcess(runner_events(end), exit_code=exit_code))
    service = make_node(tmp_path, launcher, RecordingPeerClient(), A_ID)
    with TestClient(create_app(service)) as c:
        tid = upload(c)
        start_sender(c, tid)
        body = wait_for(c, tid, "interrupted", "failed")
        assert body["status"] == "interrupted", body
        assert body["error"]
        assert c.get("/api/v1/node").json()["status"] == "idle", "an interrupted transfer is not running"
        assert [t["id"] for t in c.get("/api/v1/transfers", params={"status": "interrupted"}).json()["items"]] == [tid]

        history = c.get("/api/v1/history").json()["items"]
        assert [(h["id"], h["status"]) for h in history] == [(tid, "interrupted")], "the interruption is in the history"
        assert history[0]["auth_mode"] == "hybrid" and history[0]["error"]

    record, = InterruptedStore(tmp_path / "state-node-a.json").load_all()
    assert record["transfer"]["id"] == tid and Path(record["upload_path"]).exists()


def test_the_upload_is_kept_for_the_resume_and_leaves_the_temp_dir(tmp_path: Path) -> None:
    service, _ = interrupted_sender(tmp_path)
    with TestClient(create_app(service)) as c:
        tid = upload(c)
        start_sender(c, tid)
        wait_for(c, tid, "interrupted")
        assert not (tmp_path / "uploads-node-a" / tid).exists()
        assert (tmp_path / "state-node-a-uploads" / tid / "a.bin").read_bytes() == b"x" * SIZE


def test_without_resume_the_same_death_is_a_failure(tmp_path: Path) -> None:
    launcher = FakeLauncher(alice=lambda args: FakeProcess(runner_events("died"), exit_code=-9))
    service = make_node(tmp_path, launcher, RecordingPeerClient(), A_ID, resume=False)
    with TestClient(create_app(service)) as c:
        tid = upload(c)
        start_sender(c, tid)
        assert wait_for(c, tid, "interrupted", "failed")["status"] == "failed"
    assert not (tmp_path / "state-node-a.json").exists()


def test_without_authentication_a_dead_runner_is_a_failure(tmp_path: Path) -> None:
    launcher = FakeLauncher(alice=lambda args: FakeProcess(runner_events("died", auth_mode="none"), exit_code=-9))
    service = make_node(tmp_path, launcher, RecordingPeerClient(), A_ID)
    with TestClient(create_app(service)) as c:
        tid = upload(c)
        start_sender(c, tid)
        assert wait_for(c, tid, "interrupted", "failed")["status"] == "failed"


def test_a_runner_dying_during_the_key_exchange_is_a_failure(tmp_path: Path) -> None:
    launcher = FakeLauncher(alice=lambda args: FakeProcess(runner_events("died")[:6], exit_code=-9))
    service = make_node(tmp_path, launcher, RecordingPeerClient(), A_ID)
    with TestClient(create_app(service)) as c:
        tid = upload(c)
        start_sender(c, tid)
        assert wait_for(c, tid, "interrupted", "failed")["status"] == "failed", "no verified data yet: nothing to resume"


def test_runners_get_the_resume_flag_only_when_enabled(tmp_path: Path) -> None:
    for enabled in (True, False):
        launcher = FakeLauncher(alice=lambda args: FakeProcess(runner_events("completed")))
        service = make_node(tmp_path / str(enabled), launcher, RecordingPeerClient(), A_ID, resume=enabled)
        with TestClient(create_app(service)) as c:
            start_sender(c, upload(c))
            (_, args, _), = launcher.launches
            assert ("--resume" in args) is enabled
            assert "--transfer-id" in args


# ── resuming ────────────────────────────────────────────────────


def test_resume_reoffers_the_transfer_with_its_id(tmp_path: Path) -> None:
    service, launcher = interrupted_sender(tmp_path)
    peers = service.peers
    with TestClient(create_app(service)) as c:
        tid = upload(c)
        start_sender(c, tid)
        wait_for(c, tid, "interrupted")
        peers.calls.clear()

        resp = c.post(f"/api/v1/transfers/{tid}/resume")
        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert body["status"] == "pending" and body["id"] == tid and body["error"] is None and body["progress"] is None
        (_, host, port, offer), = peers.called("offer_transfer")
        assert (host, port) == (PEER.host, PEER.port)
        assert offer.id == tid and offer.resume_transfer_id == tid
        assert offer.filename == "a.bin" and offer.file_size == SIZE


@pytest.mark.parametrize("setup, status, code", [
    ("pending", 409, "invalid_transition"),
    ("unknown", 404, "transfer_not_found"),
])
def test_only_an_interrupted_transfer_can_be_resumed(tmp_path: Path, setup: str, status: int, code: str) -> None:
    service, _ = interrupted_sender(tmp_path)
    with TestClient(create_app(service)) as c:
        tid = upload(c) if setup == "pending" else "nope"
        assert error_code(c.post(f"/api/v1/transfers/{tid}/resume"), status) == code


def test_a_completed_transfer_cannot_be_resumed(tmp_path: Path) -> None:
    launcher = FakeLauncher(alice=lambda args: FakeProcess(runner_events("completed")))
    service = make_node(tmp_path, launcher, RecordingPeerClient(), A_ID)
    with TestClient(create_app(service)) as c:
        tid = upload(c)
        start_sender(c, tid)
        wait_for(c, tid, "completed")
        assert error_code(c.post(f"/api/v1/transfers/{tid}/resume"), 409) == "invalid_transition"


def test_only_the_sender_can_resume(tmp_path: Path) -> None:
    service = make_node(tmp_path, FakeLauncher(bob=lambda a: FakeProcess(runner_events("interrupted", listening=40001), exit_code=1)),
                        RecordingPeerClient(), B_ID, peer=PeerInfo("node-a", "alice-laptop", "10.0.0.1", 8000))
    with TestClient(create_app(service)) as c:
        assert c.post("/api/v1/transfers/incoming", json={"id": "t1", "filename": "a.bin", "file_size": SIZE, "sender": SENDER}).status_code == 201
        assert c.patch("/api/v1/transfers/t1", json={"status": "accepted"}).status_code == 202
        wait_for(c, "t1", "interrupted")
        assert error_code(c.post("/api/v1/transfers/t1/resume"), 422) == "invalid_request"


def test_a_receiver_that_refuses_the_offer_leaves_it_resumable(tmp_path: Path) -> None:
    peers = RecordingPeerClient()
    launcher = FakeLauncher(alice=lambda args: FakeProcess(runner_events("interrupted"), exit_code=1))
    service = make_node(tmp_path, launcher, peers, A_ID)
    with TestClient(create_app(service)) as c:
        tid = upload(c)
        start_sender(c, tid)
        wait_for(c, tid, "interrupted")
        peers.failing.add("offer_transfer")
        assert error_code(c.post(f"/api/v1/transfers/{tid}/resume"), 502) == "peer_unreachable"
        body = c.get(f"/api/v1/transfers/{tid}").json()
        assert body["status"] == "interrupted" and "did not take the resume offer" in body["error"]
        assert len(c.get("/api/v1/history").json()["items"]) == 1, "a failed attempt is not logged twice"
        peers.failing.clear()
        assert c.post(f"/api/v1/transfers/{tid}/resume").status_code == 202


def test_cancelling_an_interrupted_transfer_discards_everything(tmp_path: Path) -> None:
    service, _ = interrupted_sender(tmp_path)
    with TestClient(create_app(service)) as c:
        tid = upload(c)
        start_sender(c, tid)
        wait_for(c, tid, "interrupted")
        assert c.delete(f"/api/v1/transfers/{tid}").json()["status"] == "cancelled"
    assert InterruptedStore(tmp_path / "state-node-a.json").load_all() == []
    assert not (tmp_path / "state-node-a-uploads" / tid).exists()


# ── the receiving side ──────────────────────────────────────────


def receiver_with_interrupted(root: Path):
    launcher = FakeLauncher(bob=lambda args: FakeProcess(runner_events("interrupted", listening=40001), exit_code=1))
    service = make_node(root, launcher, RecordingPeerClient(), B_ID, peer=PeerInfo("node-a", "alice-laptop", "10.0.0.1", 8000))
    return service, launcher


def receive_and_interrupt(c: TestClient, tid: str = "t1") -> None:
    assert c.post("/api/v1/transfers/incoming", json={"id": tid, "filename": "a.bin", "file_size": SIZE, "sender": SENDER}).status_code == 201
    assert c.patch(f"/api/v1/transfers/{tid}", json={"status": "accepted"}).status_code == 202
    assert wait_for(c, tid, "interrupted")["status"] == "interrupted"


def offer(c: TestClient, tid: str = "t1", **overrides):
    body = {"id": tid, "filename": "a.bin", "file_size": SIZE, "sender": SENDER, "resume_transfer_id": tid, **overrides}
    return c.post("/api/v1/transfers/incoming", json=body)


def test_a_resume_offer_puts_the_interrupted_transfer_back_to_pending(tmp_path: Path) -> None:
    service, launcher = receiver_with_interrupted(tmp_path)
    with TestClient(create_app(service)) as c:
        receive_and_interrupt(c)
        resp = offer(c, sender={**SENDER, "port": 8123})
        assert resp.status_code == 201 and resp.json()["status"] == "pending" and resp.json()["peer"]["port"] == 8123
        assert len(c.get("/api/v1/transfers").json()["items"]) == 1, "the same transfer, not a second one"
        assert c.patch("/api/v1/transfers/t1", json={"status": "accepted"}).status_code == 202
        args = launcher.launches[1][1]
        assert launcher.roles() == ["bob", "bob"] and "--resume" in args and args[args.index("--transfer-id") + 1] == "t1"


def test_a_resume_offer_for_a_transfer_this_node_does_not_know_is_a_new_offer(tmp_path: Path) -> None:
    service, _ = receiver_with_interrupted(tmp_path)
    with TestClient(create_app(service)) as c:
        resp = offer(c, "never-seen")
        assert resp.status_code == 201 and resp.json()["status"] == "pending"


@pytest.mark.parametrize("overrides", [
    {"filename": "other.bin"},
    {"file_size": SIZE + 1},
    {"sender": {**SENDER, "id": "someone-else"}},
], ids=["filename", "size", "sender"])
def test_a_resume_offer_must_describe_the_same_transfer(tmp_path: Path, overrides: dict) -> None:
    service, _ = receiver_with_interrupted(tmp_path)
    with TestClient(create_app(service)) as c:
        receive_and_interrupt(c)
        assert error_code(offer(c, **overrides), 422) == "invalid_request"
        assert c.get("/api/v1/transfers/t1").json()["status"] == "interrupted"


def test_resume_transfer_id_must_equal_the_id(tmp_path: Path) -> None:
    service, _ = receiver_with_interrupted(tmp_path)
    with TestClient(create_app(service)) as c:
        assert error_code(offer(c, "t1", resume_transfer_id="t2"), 422) == "invalid_request"


def test_a_resume_offer_for_a_transfer_that_is_not_interrupted_conflicts(tmp_path: Path) -> None:
    service, _ = receiver_with_interrupted(tmp_path)
    with TestClient(create_app(service)) as c:
        assert c.post("/api/v1/transfers/incoming", json={"id": "t1", "filename": "a.bin", "file_size": SIZE, "sender": SENDER}).status_code == 201
        assert error_code(offer(c), 409) == "transfer_exists"


def test_rejecting_or_cancelling_drops_the_verified_bytes(tmp_path: Path) -> None:
    service, _ = receiver_with_interrupted(tmp_path)
    store = ResumeStore(service.output_dir, "t1")
    with TestClient(create_app(service)) as c:
        receive_and_interrupt(c)
        os.makedirs(store.dir, exist_ok=True)
        open(store.part_path, "wb").write(b"verified")
        open(store.state_path, "w").write("{}")
        assert c.delete("/api/v1/transfers/t1").json()["status"] == "cancelled"
    assert not os.path.exists(store.part_path) and not os.path.exists(store.state_path)


# ── across restarts ─────────────────────────────────────────────


def test_an_interrupted_transfer_survives_a_node_restart(tmp_path: Path) -> None:
    service, _ = interrupted_sender(tmp_path)
    with TestClient(create_app(service)) as c:
        tid = upload(c)
        start_sender(c, tid)
        wait_for(c, tid, "interrupted")

    peers = RecordingPeerClient()  # a brand new node process: empty repository, same files
    reborn = make_node(tmp_path, FakeLauncher(), peers, A_ID)
    with TestClient(create_app(reborn)) as c:
        body = c.get(f"/api/v1/transfers/{tid}").json()
        assert body["status"] == "interrupted" and body["direction"] == "outgoing" and body["filename"] == "a.bin"
        assert body["auth_mode"] == "hybrid" and body["peer"]["id"] == PEER.id
        assert c.post(f"/api/v1/transfers/{tid}/resume").status_code == 202
        (_, _, _, offer_), = peers.called("offer_transfer")
        assert offer_.resume_transfer_id == tid


def test_a_receiver_restart_keeps_the_interrupted_transfer(tmp_path: Path) -> None:
    service, _ = receiver_with_interrupted(tmp_path)
    with TestClient(create_app(service)) as c:
        receive_and_interrupt(c)
    reborn, launcher = receiver_with_interrupted(tmp_path)
    with TestClient(create_app(reborn)) as c:
        assert c.get("/api/v1/transfers/t1").json()["status"] == "interrupted"
        assert offer(c).json()["status"] == "pending"
        assert c.patch("/api/v1/transfers/t1", json={"status": "accepted"}).status_code == 202
        assert "--resume" in launcher.launches[0][1]


def test_a_restart_without_the_upload_cannot_resume(tmp_path: Path) -> None:
    service, _ = interrupted_sender(tmp_path)
    with TestClient(create_app(service)) as c:
        tid = upload(c)
        start_sender(c, tid)
        wait_for(c, tid, "interrupted")
    for f in (tmp_path / "state-node-a-uploads" / tid).iterdir():
        f.unlink()

    reborn = make_node(tmp_path, FakeLauncher(), RecordingPeerClient(), A_ID)
    with TestClient(create_app(reborn)) as c:
        body = c.get(f"/api/v1/transfers/{tid}").json()
        assert body["status"] == "failed" and "gone" in body["error"]
    assert InterruptedStore(tmp_path / "state-node-a.json").load_all() == []


def test_without_resume_nothing_is_restored(tmp_path: Path) -> None:
    service, _ = interrupted_sender(tmp_path)
    with TestClient(create_app(service)) as c:
        tid = upload(c)
        start_sender(c, tid)
        wait_for(c, tid, "interrupted")
    off = make_node(tmp_path, FakeLauncher(), RecordingPeerClient(), A_ID, resume=False)
    with TestClient(create_app(off)) as c:
        assert c.get("/api/v1/transfers").json()["items"] == []


# ── two nodes: interrupt, resume, complete ──────────────────────


def test_two_nodes_interrupt_resume_and_complete(tmp_path: Path) -> None:
    router = RoutedPeerClient()
    attempt = {"a": 0, "b": 0}
    gates: list[threading.Event] = []

    def alice(args: list[str]) -> FakeProcess:
        attempt["a"] += 1
        gates[-1].set()
        if attempt["a"] == 1:
            return FakeProcess(runner_events("interrupted"), exit_code=1)
        assert "--resume" in args
        return FakeProcess(runner_events("completed", resumed_from=400))

    def bob(args: list[str]) -> FakeProcess:
        attempt["b"] += 1
        gates.append(threading.Event())
        if attempt["b"] == 1:
            return FakeProcess(runner_events("interrupted", listening=45678), exit_code=1, gate=gates[-1], gate_at=2)
        assert "--resume" in args
        return FakeProcess(runner_events("completed", resumed_from=400, listening=45678), gate=gates[-1], gate_at=2)

    a_launcher, b_launcher = FakeLauncher(alice=alice), FakeLauncher(bob=bob)
    node_a = make_node(tmp_path, a_launcher, router, A_ID, PeerInfo(B_ID.id, B_ID.name, B_ID.host, B_ID.port))
    node_b = make_node(tmp_path, b_launcher, router, B_ID, PeerInfo(A_ID.id, A_ID.name, A_ID.host, A_ID.port))

    with TestClient(create_app(node_a)) as a, TestClient(create_app(node_b)) as b:
        router.routes = {("10.0.0.1", 8000): a, ("10.0.0.2", 8001): b}

        tid = upload(a, peer_id="node-b")
        assert b.patch(f"/api/v1/transfers/{tid}", json={"status": "accepted"}).status_code == 202
        wait_for(a, tid, "interrupted")
        wait_for(b, tid, "interrupted")

        # The sender resumes; the receiver is asked again and answers as for any offer
        assert a.post(f"/api/v1/transfers/{tid}/resume").json()["status"] == "pending"
        assert b.get(f"/api/v1/transfers/{tid}").json()["status"] == "pending"
        assert b.patch(f"/api/v1/transfers/{tid}", json={"status": "accepted"}).status_code == 202

        done_a, done_b = wait_for(a, tid, "completed"), wait_for(b, tid, "completed")
        assert done_a["resumed_from_bytes"] == done_b["resumed_from_bytes"] == 400
        assert done_a["bytes_total"] == SIZE
        assert done_a["error"] is None and done_b["error"] is None
        assert attempt == {"a": 2, "b": 2}

        for client in (a, b):
            assert [h["status"] for h in client.get("/api/v1/history").json()["items"]] == ["completed", "interrupted"]
        completed = a.get("/api/v1/history").json()["items"][0]
        assert completed["resumed_from_bytes"] == 400 and completed["bytes_total"] == SIZE

        # Finished: nothing left to restore, and a second resume is a conflict
        assert error_code(a.post(f"/api/v1/transfers/{tid}/resume"), 409) == "invalid_transition"

    assert InterruptedStore(tmp_path / "state-node-a.json").load_all() == []
    assert InterruptedStore(tmp_path / "state-node-b.json").load_all() == []


def test_events_report_the_resume_metrics(tmp_path: Path) -> None:
    launcher = FakeLauncher(alice=lambda args: FakeProcess(runner_events("completed", resumed_from=400)))
    service = make_node(tmp_path, launcher, RecordingPeerClient(), A_ID)
    with TestClient(create_app(service)) as c:
        tid = upload(c)
        start_sender(c, tid)
        body = wait_for(c, tid, "completed")
        assert (body["resumed_from_bytes"], body["bytes_total"]) == (400, SIZE)
        with c.stream("GET", f"/api/v1/transfers/{tid}/events") as resp:
            payloads = [json.loads(line[6:]) for line in resp.iter_lines() if line.startswith("data: ")]
        metrics = [e["payload"] for e in payloads if e["type"] == "metrics" and "resumed_from_bytes" in e["payload"]]
        assert metrics == [{"resumed_from_bytes": 400, "bytes_total": SIZE}]
