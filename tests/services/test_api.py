"""REST API tests: resources, status codes, the transfer state machine, and the error body."""

from __future__ import annotations

import io
import json
import threading
import time
from pathlib import Path
from typing import Iterator

import pytest
from fastapi.testclient import TestClient

from qkd.services.api.app import create_app
from qkd.services.discovery import NodeIdentity, PeerInfo, StaticPeerDirectory
from qkd.services.events import EventBus
from qkd.services.history import HistoryStore
from qkd.services.node import NodeService
from qkd.services.transfer_store import InMemoryTransferRepository
from tests.services.fakes import (
    FakeLauncher,
    FakeProcess,
    RecordingPeerClient,
    RoutedPeerClient,
    alice_script,
    bob_script,
    ev,
)

PEER = PeerInfo(id="peer-b", name="bob-laptop", host="10.0.0.2", port=8001)
SENDER = {"id": "peer-a", "name": "alice-laptop", "host": "10.0.0.1", "port": 8000}


def make_service(tmp_path: Path, launcher: FakeLauncher, peers, directory_peers=(PEER,),
                 identity: NodeIdentity | None = None) -> NodeService:
    identity = identity or NodeIdentity(id="self", name="self-node", host="10.0.0.9", port=8000)
    return NodeService(
        identity,
        repo=InMemoryTransferRepository(),
        bus=EventBus(),
        history=HistoryStore(tmp_path / f"history-{identity.id}.json"),
        directory=StaticPeerDirectory(list(directory_peers)),
        peers=peers,
        launcher=launcher,
        output_dir=str(tmp_path / "received"),
        upload_dir=str(tmp_path / f"uploads-{identity.id}"),
        version="test",
        listen_timeout=5,
        identity_dir=tmp_path / f"identity-{identity.id}",
        known_peers_file=tmp_path / f"known-peers-{identity.id}.json",
    )


@pytest.fixture
def gate() -> threading.Event:
    return threading.Event()


@pytest.fixture
def launcher(gate: threading.Event) -> FakeLauncher:
    return FakeLauncher(
        alice=lambda args: FakeProcess(alice_script()),
        bob=lambda args: FakeProcess(bob_script(), gate=gate, gate_at=2),
    )


@pytest.fixture
def peers() -> RecordingPeerClient:
    return RecordingPeerClient()


@pytest.fixture
def client(tmp_path: Path, launcher: FakeLauncher, peers: RecordingPeerClient) -> Iterator[TestClient]:
    with TestClient(create_app(make_service(tmp_path, launcher, peers))) as c:
        yield c


def wait_for(client: TestClient, transfer_id: str, *statuses: str, timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    while True:
        body = client.get(f"/api/v1/transfers/{transfer_id}").json()
        if body["status"] in statuses:
            return body
        if time.monotonic() > deadline:
            raise AssertionError(f"transfer stayed {body['status']}, wanted {statuses}: {body}")
        time.sleep(0.02)


def create_outgoing(client: TestClient, peer_id: str = PEER.id, content: bytes = b"x" * 1000):
    return client.post("/api/v1/transfers", data={"peer_id": peer_id}, files={"file": ("a.bin", io.BytesIO(content))})


def offer_incoming(client: TestClient, transfer_id: str = "t-incoming-1", **overrides):
    body = {"id": transfer_id, "filename": "a.bin", "file_size": 1000, "sender": SENDER, **overrides}
    return client.post("/api/v1/transfers/incoming", json=body)


def assert_error(resp, status: int, code: str) -> dict:
    assert resp.status_code == status, resp.text
    body = resp.json()
    assert set(body) == {"error"}
    assert body["error"]["code"] == code
    assert body["error"]["message"]
    return body["error"]


# ── node and peers ─────────────────────────────────────────────

def test_get_node(client: TestClient) -> None:
    body = client.get("/api/v1/node").json()
    service = client.app.state.service
    assert body == {
        "id": "self",
        "name": "self-node",
        "host": "10.0.0.9",
        "port": 8000,
        "status": "idle",
        "version": "test",
        "fingerprint": service.pqc_identity.fingerprint,
    }


def test_rename_node(client: TestClient) -> None:
    assert client.patch("/api/v1/node", json={"name": "lab-1"}).json()["name"] == "lab-1"
    assert client.get("/api/v1/node").json()["name"] == "lab-1"


@pytest.mark.parametrize("name", ["", "has.dot", "x" * 64])
def test_rename_node_validation(client: TestClient, name: str) -> None:
    assert_error(client.patch("/api/v1/node", json={"name": name}), 422, "validation_error")


def test_list_and_get_peers(client: TestClient) -> None:
    peer = {
        "id": PEER.id,
        "name": PEER.name,
        "host": PEER.host,
        "port": PEER.port,
        "reachable": True,
        "fingerprint": PEER.fingerprint,
        "trust": "new",
    }
    assert client.get("/api/v1/peers").json() == {"items": [peer]}
    assert client.get(f"/api/v1/peers/{PEER.id}").json() == peer


def test_unknown_peer_is_404(client: TestClient) -> None:
    assert_error(client.get("/api/v1/peers/nope"), 404, "peer_not_found")


def test_peer_trust_put_delete_round_trip(tmp_path: Path, launcher: FakeLauncher) -> None:
    peer_with_fp = PeerInfo(
        id="peer-fp",
        name="charlie-laptop",
        host="10.0.0.3",
        port=8002,
        fingerprint="1234-5678-90ab-cdef-1234-5678-90ab-cdef",
    )
    service = make_service(tmp_path, launcher, RecordingPeerClient(), directory_peers=[peer_with_fp])
    app = create_app(service)

    with TestClient(app) as c:
        # Initially trust is "new"
        initial = c.get(f"/api/v1/peers/{peer_with_fp.id}").json()
        assert initial["trust"] == "new"
        assert initial["fingerprint"] == peer_with_fp.fingerprint

        # PUT marks verified
        put_resp = c.put(f"/api/v1/peers/{peer_with_fp.id}/trust")
        assert put_resp.status_code == 200
        assert put_resp.json()["trust"] == "verified"
        assert put_resp.json()["fingerprint"] == peer_with_fp.fingerprint

        # GET confirms verified
        assert c.get(f"/api/v1/peers/{peer_with_fp.id}").json()["trust"] == "verified"

        # DELETE forgets trust (returns to "new")
        del_resp = c.delete(f"/api/v1/peers/{peer_with_fp.id}/trust")
        assert del_resp.status_code == 200
        assert del_resp.json()["trust"] == "new"

        # GET confirms "new"
        assert c.get(f"/api/v1/peers/{peer_with_fp.id}").json()["trust"] == "new"


def test_peer_trust_unknown_peer_returns_error(client: TestClient) -> None:
    assert_error(client.put("/api/v1/peers/unknown-peer/trust"), 404, "peer_not_found")
    assert_error(client.delete("/api/v1/peers/unknown-peer/trust"), 404, "peer_not_found")


def test_offer_incoming_matching_fingerprint_succeeds(tmp_path: Path, launcher: FakeLauncher) -> None:
    fp = "aaaa-bbbb-cccc-dddd-1111-2222-3333-4444"
    sender_peer = PeerInfo(id="sender-node", name="sender", host="10.0.0.1", port=8000, fingerprint=fp)
    service = make_service(tmp_path, launcher, RecordingPeerClient(), directory_peers=[sender_peer])
    app = create_app(service)

    with TestClient(app) as c:
        resp = offer_incoming(
            c,
            transfer_id="t-matched-1",
            sender={"id": "sender-node", "name": "sender", "host": "10.0.0.1", "port": 8000},
            sender_fingerprint=fp,
        )
        assert resp.status_code == 201


def test_offer_incoming_mismatched_fingerprint_is_409(tmp_path: Path, launcher: FakeLauncher) -> None:
    fp_mdns = "aaaa-bbbb-cccc-dddd-1111-2222-3333-4444"
    sender_peer = PeerInfo(id="sender-node", name="sender", host="10.0.0.1", port=8000, fingerprint=fp_mdns)
    service = make_service(tmp_path, launcher, RecordingPeerClient(), directory_peers=[sender_peer])
    app = create_app(service)

    with TestClient(app) as c:
        resp = offer_incoming(
            c,
            transfer_id="t-mismatched-1",
            sender={"id": "sender-node", "name": "sender", "host": "10.0.0.1", "port": 8000},
            sender_fingerprint="ffff-ffff-ffff-ffff-ffff-ffff-ffff-ffff",
        )
        assert_error(resp, 409, "fingerprint_mismatch")


# ── creating transfers ─────────────────────────────────────────

def test_create_outgoing_transfer(client: TestClient, peers: RecordingPeerClient) -> None:
    resp = create_outgoing(client)
    assert resp.status_code == 201
    body = resp.json()
    assert resp.headers["location"] == f"/api/v1/transfers/{body['id']}"
    assert body["direction"] == "outgoing"
    assert body["status"] == "pending"
    assert body["file_size"] == 1000
    assert body["peer"]["id"] == PEER.id

    (_, host, port, offer), = peers.called("offer_transfer")
    assert (host, port) == (PEER.host, PEER.port)
    assert offer.id == body["id"]
    assert offer.sender.id == "self"
    assert offer.sender_fingerprint == client.app.state.service.pqc_identity.fingerprint


def test_create_outgoing_unknown_peer(client: TestClient) -> None:
    assert_error(create_outgoing(client, peer_id="ghost"), 422, "unknown_peer")


def test_create_outgoing_requires_file(client: TestClient) -> None:
    err = assert_error(client.post("/api/v1/transfers", data={"peer_id": PEER.id}), 422, "validation_error")
    assert any(d["loc"][-1] == "file" for d in err["details"])


def test_create_outgoing_peer_unreachable(tmp_path: Path, launcher: FakeLauncher) -> None:
    with TestClient(create_app(make_service(tmp_path, launcher, RecordingPeerClient(failing=("offer_transfer",))))) as c:
        assert_error(create_outgoing(c), 502, "peer_unreachable")
        (failed,) = c.get("/api/v1/transfers").json()["items"]
        assert failed["status"] == "failed"
        assert "offer" in failed["error"]


def test_offer_incoming(client: TestClient) -> None:
    resp = offer_incoming(client)
    assert resp.status_code == 201
    assert resp.headers["location"] == "/api/v1/transfers/t-incoming-1"
    assert resp.json()["direction"] == "incoming"
    assert resp.json()["status"] == "pending"


def test_offer_incoming_duplicate_id_is_409(client: TestClient) -> None:
    offer_incoming(client)
    assert_error(offer_incoming(client), 409, "transfer_exists")


@pytest.mark.parametrize("override", [{"id": "bad id!"}, {"file_size": -1}, {"sender": {"id": "x"}}, {"filename": ""}])
def test_offer_incoming_validation(client: TestClient, override: dict) -> None:
    assert_error(offer_incoming(client, **override), 422, "validation_error")


def test_offer_incoming_strips_directories(client: TestClient) -> None:
    assert offer_incoming(client, filename="../../etc/passwd").json()["filename"] == "passwd"


# ── reading transfers ──────────────────────────────────────────

def test_get_unknown_transfer_is_404(client: TestClient) -> None:
    assert_error(client.get("/api/v1/transfers/nope"), 404, "transfer_not_found")


def test_list_filters(client: TestClient) -> None:
    out_id = create_outgoing(client).json()["id"]
    offer_incoming(client, "in-1")
    offer_incoming(client, "in-2")
    client.patch("/api/v1/transfers/in-2", json={"status": "rejected"})

    def ids(**params) -> set[str]:
        return {t["id"] for t in client.get("/api/v1/transfers", params=params).json()["items"]}

    assert ids() == {out_id, "in-1", "in-2"}
    assert ids(direction="outgoing") == {out_id}
    assert ids(direction="incoming", status="pending") == {"in-1"}
    assert ids(status=["pending", "rejected"]) == {out_id, "in-1", "in-2"}
    assert ids(status="completed") == set()


def test_list_invalid_filter_is_422(client: TestClient) -> None:
    assert_error(client.get("/api/v1/transfers", params={"status": "done"}), 422, "validation_error")
    assert_error(client.get("/api/v1/transfers", params={"direction": "sideways"}), 422, "validation_error")


# ── state machine: incoming side ───────────────────────────────

def test_accept_incoming_runs_receiver_and_tells_sender(client, launcher, peers, gate) -> None:
    offer_incoming(client)
    resp = client.patch("/api/v1/transfers/t-incoming-1", json={"status": "accepted"})
    assert resp.status_code == 202
    assert resp.json()["status"] in ("accepted", "key_exchange")

    (role, args, _), = launcher.launches
    assert role == "bob"
    assert args[:2] == ["--port", "0"] and "--transfer-id" in args
    (_, host, port, tid, patch), = peers.called("respond")
    assert (host, port, tid) == (SENDER["host"], SENDER["port"], "t-incoming-1")
    assert (patch.status, patch.receiver_port) == ("accepted", 40001)

    gate.set()
    done = wait_for(client, "t-incoming-1", "completed")
    assert done["qber"] == 0.0 and done["key_bits"] == 256 and done["sifted_length"] == 61
    assert done["progress"] == {"chunks_done": 2, "num_chunks": 2, "bytes_done": 100_000, "total_bytes": 100_000}
    assert done["output_path"] == "/tmp/received/received_a.bin"
    assert done["error"] is None

    (entry,) = client.get("/api/v1/history").json()["items"]
    assert (entry["id"], entry["status"], entry["direction"]) == ("t-incoming-1", "completed", "incoming")


def test_reject_incoming(client: TestClient, launcher: FakeLauncher, peers: RecordingPeerClient) -> None:
    offer_incoming(client)
    resp = client.patch("/api/v1/transfers/t-incoming-1", json={"status": "rejected"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "rejected"
    assert launcher.launches == []
    (_, _, _, _, patch), = peers.called("respond")
    assert patch.status == "rejected"


def test_patch_twice_is_409(client: TestClient) -> None:
    offer_incoming(client)
    client.patch("/api/v1/transfers/t-incoming-1", json={"status": "rejected"})
    err = assert_error(client.patch("/api/v1/transfers/t-incoming-1", json={"status": "accepted"}), 409, "invalid_transition")
    assert "rejected" in err["message"]


@pytest.mark.parametrize("body", [{"status": "completed"}, {"status": "cancelled"}, {}, {"status": "accepted", "receiver_port": 0}])
def test_patch_validation(client: TestClient, body: dict) -> None:
    offer_incoming(client)
    assert_error(client.patch("/api/v1/transfers/t-incoming-1", json=body), 422, "validation_error")


def test_patch_unknown_is_404(client: TestClient) -> None:
    assert_error(client.patch("/api/v1/transfers/nope", json={"status": "accepted"}), 404, "transfer_not_found")


def test_receiver_port_not_allowed_on_incoming(client: TestClient) -> None:
    offer_incoming(client)
    assert_error(client.patch("/api/v1/transfers/t-incoming-1", json={"status": "accepted", "receiver_port": 5000}),
                 422, "invalid_request")


def test_accept_incoming_sender_gone(tmp_path: Path, launcher: FakeLauncher) -> None:
    with TestClient(create_app(make_service(tmp_path, launcher, RecordingPeerClient(failing=("respond",))))) as c:
        offer_incoming(c)
        assert_error(c.patch("/api/v1/transfers/t-incoming-1", json={"status": "accepted"}), 502, "peer_unreachable")
        body = c.get("/api/v1/transfers/t-incoming-1").json()
        assert body["status"] == "failed"
        assert launcher.launches[0][2].terminated


def test_receiver_that_never_listens_fails(tmp_path: Path, peers: RecordingPeerClient) -> None:
    launcher = FakeLauncher(bob=lambda args: FakeProcess([ev("log", message="boom")], exit_code=1))
    with TestClient(create_app(make_service(tmp_path, launcher, peers))) as c:
        offer_incoming(c)
        assert_error(c.patch("/api/v1/transfers/t-incoming-1", json={"status": "accepted"}), 500, "launch_failed")
        assert c.get("/api/v1/transfers/t-incoming-1").json()["status"] == "failed"
        assert peers.called("respond") == []


# ── state machine: outgoing side ───────────────────────────────

def test_outgoing_accept_starts_sender(client: TestClient, launcher: FakeLauncher) -> None:
    tid = create_outgoing(client).json()["id"]
    resp = client.patch(f"/api/v1/transfers/{tid}", json={"status": "accepted", "receiver_port": 40001})
    assert resp.status_code == 202

    (role, args, _), = launcher.launches
    assert role == "alice"
    assert args[1:5] == ["--host", PEER.host, "--port", "40001"]
    assert Path(args[0]).name == "a.bin"

    done = wait_for(client, tid, "completed")
    assert done["stage"] == "file_transfer"
    assert not Path(args[0]).exists(), "upload should be deleted once the transfer finishes"


def test_outgoing_accept_requires_receiver_port(client: TestClient) -> None:
    tid = create_outgoing(client).json()["id"]
    assert_error(client.patch(f"/api/v1/transfers/{tid}", json={"status": "accepted"}), 422, "invalid_request")
    assert client.get(f"/api/v1/transfers/{tid}").json()["status"] == "pending"


def test_outgoing_rejected_by_receiver(client: TestClient) -> None:
    tid = create_outgoing(client).json()["id"]
    resp = client.patch(f"/api/v1/transfers/{tid}", json={"status": "rejected"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "rejected"


def test_qber_abort(tmp_path: Path, peers: RecordingPeerClient) -> None:
    launcher = FakeLauncher(alice=lambda args: FakeProcess(alice_script("aborted_qber"), exit_code=1))
    with TestClient(create_app(make_service(tmp_path, launcher, peers))) as c:
        tid = create_outgoing(c).json()["id"]
        c.patch(f"/api/v1/transfers/{tid}", json={"status": "accepted", "receiver_port": 40001})
        body = wait_for(c, tid, "aborted_qber")
        assert body["qber"] == 0.25 and body["qber_threshold"] == 0.11
        assert "QBER" in body["error"]
        assert body["key_bits"] is None


def test_auth_abort(tmp_path: Path, peers: RecordingPeerClient) -> None:
    launcher = FakeLauncher(alice=lambda args: FakeProcess(alice_script("aborted_auth"), exit_code=1))
    with TestClient(create_app(make_service(tmp_path, launcher, peers))) as c:
        tid = create_outgoing(c).json()["id"]
        c.patch(f"/api/v1/transfers/{tid}", json={"status": "accepted", "receiver_port": 40001})
        body = wait_for(c, tid, "aborted_auth")
        assert body["status"] == "aborted_auth"
        assert body["auth_mode"] == "hybrid"
        assert body["peer_fingerprint"] == "1111-2222-3333-4444"
        assert body["peer_trust"] == "new"
        assert body["error"] == "Peer authentication failed: key mismatch"
        assert body["key_bits"] is None

        (entry,) = c.get("/api/v1/history").json()["items"]
        assert entry["id"] == tid
        assert entry["status"] == "aborted_auth"
        assert entry["auth_mode"] == "hybrid"
        assert entry["peer_fingerprint"] == "1111-2222-3333-4444"
        assert entry["peer_trust"] == "new"
        assert entry["error"] == "Peer authentication failed: key mismatch"


def test_process_exit_without_result_is_failed(tmp_path: Path, peers: RecordingPeerClient) -> None:
    launcher = FakeLauncher(alice=lambda args: FakeProcess([ev("stage", "connecting"), ev("log", message="Traceback ...")], exit_code=1))
    with TestClient(create_app(make_service(tmp_path, launcher, peers))) as c:
        tid = create_outgoing(c).json()["id"]
        c.patch(f"/api/v1/transfers/{tid}", json={"status": "accepted", "receiver_port": 40001})
        body = wait_for(c, tid, "failed")
        assert "exited with code 1" in body["error"]


# ── cancellation ───────────────────────────────────────────────

def test_cancel_pending(client: TestClient, peers: RecordingPeerClient) -> None:
    tid = create_outgoing(client).json()["id"]
    resp = client.delete(f"/api/v1/transfers/{tid}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "cancelled"
    assert peers.called("cancel") == [("cancel", PEER.host, PEER.port, tid)]
    assert_error(client.delete(f"/api/v1/transfers/{tid}"), 409, "invalid_transition")
    assert_error(client.patch(f"/api/v1/transfers/{tid}", json={"status": "rejected"}), 409, "invalid_transition")


def test_cancel_running_terminates_process(tmp_path: Path, peers: RecordingPeerClient) -> None:
    launcher = FakeLauncher(alice=lambda args: FakeProcess(alice_script()[:4], block=True))
    with TestClient(create_app(make_service(tmp_path, launcher, peers))) as c:
        tid = create_outgoing(c).json()["id"]
        c.patch(f"/api/v1/transfers/{tid}", json={"status": "accepted", "receiver_port": 40001})
        wait_for(c, tid, "key_exchange")
        assert c.get("/api/v1/node").json()["status"] == "busy"
        assert c.delete(f"/api/v1/transfers/{tid}").json()["status"] == "cancelled"
        assert launcher.launches[0][2].terminated
        time.sleep(0.1)
        assert c.get(f"/api/v1/transfers/{tid}").json()["status"] == "cancelled"
        assert c.get("/api/v1/node").json()["status"] == "idle"


def test_cancel_unknown_is_404(client: TestClient) -> None:
    assert_error(client.delete("/api/v1/transfers/nope"), 404, "transfer_not_found")


# ── events stream ──────────────────────────────────────────────

def read_sse(client: TestClient, path: str, headers: dict | None = None) -> list[dict]:
    events = []
    with client.stream("GET", path, headers=headers or {}) as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        for line in resp.iter_lines():
            if line.startswith("data: "):
                events.append(json.loads(line[6:]))
    return events


def test_event_stream_replays_and_ends(client: TestClient) -> None:
    tid = create_outgoing(client).json()["id"]
    client.patch(f"/api/v1/transfers/{tid}", json={"status": "accepted", "receiver_port": 40001})
    wait_for(client, tid, "completed")

    events = read_sse(client, f"/api/v1/transfers/{tid}/events")
    seqs = [e["seq"] for e in events]
    assert seqs == sorted(seqs) == list(range(1, len(seqs) + 1))
    assert all(e["transfer_id"] == tid for e in events)
    statuses = [e["payload"]["status"] for e in events if e["type"] == "status"]
    assert statuses == ["pending", "accepted", "key_exchange", "transferring", "completed"]
    assert {"log", "stage", "metrics", "progress", "result"} <= {e["type"] for e in events}
    assert events[-1]["type"] == "status" and events[-1]["payload"]["status"] == "completed"

    later = read_sse(client, f"/api/v1/transfers/{tid}/events", headers={"Last-Event-ID": str(seqs[-3])})
    assert [e["seq"] for e in later] == seqs[-2:]
    assert [e["seq"] for e in read_sse(client, f"/api/v1/transfers/{tid}/events?after={seqs[-2]}")] == seqs[-1:]


def test_event_stream_unknown_is_404(client: TestClient) -> None:
    assert_error(client.get("/api/v1/transfers/nope/events"), 404, "transfer_not_found")


# ── history, errors, schema ────────────────────────────────────

def test_history_ignores_legacy_entries(tmp_path: Path, launcher, peers) -> None:
    service = make_service(tmp_path, launcher, peers)
    service.history.path.write_text(json.dumps([{"timestamp": "2026-01-01", "type": "SENT", "filename": "x", "status": "Completed"}]))
    with TestClient(create_app(service)) as c:
        assert c.get("/api/v1/history").json() == {"items": []}


def test_unknown_route_uses_error_body(client: TestClient) -> None:
    assert_error(client.get("/api/v1/nothing-here"), 404, "not_found")
    assert_error(client.put("/api/v1/node", json={}), 405, "method_not_allowed")


def test_openapi_schema_and_docs(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()
    assert spec["openapi"].startswith("3.")
    assert set(spec["paths"]) == {
        "/api/v1/node", "/api/v1/peers", "/api/v1/peers/{peer_id}", "/api/v1/peers/{peer_id}/trust",
        "/api/v1/transfers", "/api/v1/transfers/incoming", "/api/v1/transfers/{transfer_id}",
        "/api/v1/transfers/{transfer_id}/events", "/api/v1/history",
    }
    transfer = spec["paths"]["/api/v1/transfers/{transfer_id}"]
    assert set(transfer) == {"get", "patch", "delete"}
    assert {"202", "404", "409", "422"} <= set(transfer["patch"]["responses"])
    assert "201" in spec["paths"]["/api/v1/transfers"]["post"]["responses"]
    assert "text/event-stream" in spec["paths"]["/api/v1/transfers/{transfer_id}/events"]["get"]["responses"]["200"]["content"]
    for name in ("Transfer", "TransferPatch", "IncomingTransferRequest", "ErrorResponse", "Node", "Peer", "HistoryEntry"):
        assert name in spec["components"]["schemas"]

    docs = client.get("/docs")
    assert docs.status_code == 200
    assert "swagger-ui" in docs.text.lower()


# ── two nodes talking to each other ────────────────────────────

def test_two_nodes_end_to_end(tmp_path: Path) -> None:
    """Sender and receiver apps call each other's REST resources; protocol processes are faked."""
    router = RoutedPeerClient()
    gate = threading.Event()
    a_id = NodeIdentity(id="node-a", name="alice-laptop", host="10.0.0.1", port=8000)
    b_id = NodeIdentity(id="node-b", name="bob-laptop", host="10.0.0.2", port=8001)

    alice_launcher = FakeLauncher(alice=lambda args: (gate.set(), FakeProcess(alice_script()))[1])
    bob_launcher = FakeLauncher(bob=lambda args: FakeProcess(bob_script(port=45678), gate=gate, gate_at=2))
    node_a = make_service(tmp_path, alice_launcher, router, [PeerInfo(b_id.id, b_id.name, b_id.host, b_id.port)], a_id)
    node_b = make_service(tmp_path, bob_launcher, router, [PeerInfo(a_id.id, a_id.name, a_id.host, a_id.port)], b_id)

    with TestClient(create_app(node_a)) as a, TestClient(create_app(node_b)) as b:
        router.routes = {("10.0.0.1", 8000): a, ("10.0.0.2", 8001): b}

        tid = create_outgoing(a, peer_id="node-b").json()["id"]
        incoming = b.get("/api/v1/transfers", params={"direction": "incoming", "status": "pending"}).json()["items"]
        assert [t["id"] for t in incoming] == [tid]
        assert incoming[0]["peer"]["name"] == "alice-laptop"

        assert b.patch(f"/api/v1/transfers/{tid}", json={"status": "accepted"}).status_code == 202
        (_, alice_args, _), = alice_launcher.launches
        assert alice_args[1:5] == ["--host", "10.0.0.2", "--port", "45678"]

        assert wait_for(a, tid, "completed")["direction"] == "outgoing"
        assert wait_for(b, tid, "completed")["direction"] == "incoming"

        # Cancelling a finished transfer is a conflict on both sides
        assert_error(a.delete(f"/api/v1/transfers/{tid}"), 409, "invalid_transition")


def test_two_nodes_cancel_propagates(tmp_path: Path) -> None:
    router = RoutedPeerClient()
    a_id = NodeIdentity(id="node-a", name="a", host="10.0.0.1", port=8000)
    b_id = NodeIdentity(id="node-b", name="b", host="10.0.0.2", port=8001)
    node_a = make_service(tmp_path, FakeLauncher(), router, [PeerInfo(b_id.id, b_id.name, b_id.host, b_id.port)], a_id)
    node_b = make_service(tmp_path, FakeLauncher(), router, [PeerInfo(a_id.id, a_id.name, a_id.host, a_id.port)], b_id)

    with TestClient(create_app(node_a)) as a, TestClient(create_app(node_b)) as b:
        router.routes = {("10.0.0.1", 8000): a, ("10.0.0.2", 8001): b}
        tid = create_outgoing(a, peer_id="node-b").json()["id"]
        assert a.delete(f"/api/v1/transfers/{tid}").json()["status"] == "cancelled"
        assert b.get(f"/api/v1/transfers/{tid}").json()["status"] == "cancelled"
