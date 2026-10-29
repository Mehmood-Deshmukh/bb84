"""
Transfer orchestration for one backend node. The REST routes are a thin layer over this.

Node-to-node flow (both nodes keep a transfer with the same id):

  sender UI    POST /transfers (file, peer_id)      -> outgoing transfer, pending
  sender       POST peer /transfers/incoming         -> incoming transfer, pending
  receiver UI  PATCH /transfers/{id} accepted        -> starts bob on a free port
  receiver     PATCH sender /transfers/{id} accepted, receiver_port
  sender       starts alice -> receiver_host:receiver_port

Statuses then follow the stage/result events that alice and bob emit.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Optional

from qkd.core.config import IDENTITY_DIR, KNOWN_PEERS_FILE
from qkd.services.api.models import (
    Direction,
    HistoryEntry,
    IncomingTransferRequest,
    Node,
    Peer,
    PeerRef,
    Transfer,
    TransferPatch,
    TransferProgress,
    TransferStatus,
    utcnow,
)
from qkd.services.discovery import NodeIdentity, PeerDirectory, PeerInfo
from qkd.services.events import EventBus
from qkd.services.history import HistoryStore
from qkd.services.identity import Identity, TrustStore, load_or_create_identity
from qkd.services.peer_client import PeerClient, PeerError
from qkd.services.process_runner import ProtocolLauncher, RunningProcess
from qkd.services.transfer_store import ACTIVE, TERMINAL, InvalidTransition, TransferRepository, path_to

log = logging.getLogger(__name__)
S = TransferStatus

# Protocol stage reported by alice/bob -> transfer status
STAGE_STATUS = {
    "authentication": S.key_exchange,
    "quantum_transmission": S.key_exchange,
    "sifting": S.key_exchange,
    "qber_estimation": S.key_exchange,
    "privacy_amplification": S.key_exchange,
    "key_confirmation": S.key_exchange,
    "file_transfer": S.transferring,
}
OUTCOME_STATUS = {
    "completed": S.completed,
    "aborted_qber": S.aborted_qber,
    "aborted_auth": S.aborted_auth,
    "failed": S.failed,
}
METRIC_FIELDS = (
    "raw_qubits",
    "sifted_length",
    "sample_size",
    "qber",
    "qber_threshold",
    "key_bits",
    "output_path",
    "auth_mode",
    "peer_fingerprint",
    "peer_trust",
    "handshake_ms",
    "auth_overhead_bytes",
)


class UnknownPeer(Exception):
    pass


class FingerprintMismatch(Exception):
    """Raised when an incoming transfer offer has a sender fingerprint differing from mDNS."""


class InvalidRequest(Exception):
    """The request is well-formed but does not apply to this transfer."""


class LaunchFailed(Exception):
    pass


@dataclass
class _Runtime:
    """Per-transfer state that is not part of the API resource."""

    upload_path: Optional[Path] = None
    process: Optional[RunningProcess] = None
    supervisor: Optional[asyncio.Task] = None
    listening: Optional[asyncio.Future] = None


class NodeService:
    def __init__(
        self,
        identity: NodeIdentity,
        *,
        repo: TransferRepository,
        bus: EventBus,
        history: HistoryStore,
        directory: PeerDirectory,
        peers: PeerClient,
        launcher: ProtocolLauncher,
        output_dir: str,
        upload_dir: Optional[str] = None,
        version: str = "0",
        listen_timeout: float = 15.0,
        pqc_identity: Optional[Identity] = None,
        identity_dir: Optional[str | Path] = None,
        trust_store: Optional[TrustStore] = None,
        known_peers_file: Optional[str | Path] = None,
    ) -> None:
        self.identity = identity
        self.repo = repo
        self.bus = bus
        self.history = history
        self.directory = directory
        self.peers = peers
        self.launcher = launcher
        self.output_dir = os.path.abspath(output_dir)
        self.upload_dir = Path(upload_dir or tempfile.mkdtemp(prefix="qkd-uploads-"))
        self.version = version
        self.listen_timeout = listen_timeout
        self._runtime: dict[str, _Runtime] = {}
        self._identity_dir = identity_dir
        if pqc_identity is not None:
            self.pqc_identity = pqc_identity
        else:
            self.pqc_identity = load_or_create_identity(Path(identity_dir or IDENTITY_DIR))
        if not self.identity.fingerprint:
            self.identity.fingerprint = self.pqc_identity.fingerprint
        self.trust_store = trust_store or TrustStore(Path(known_peers_file or KNOWN_PEERS_FILE))

    # ── lifecycle ──────────────────────────────────────────────

    async def start(self) -> None:
        if not self.identity.fingerprint:
            self.identity.fingerprint = self.pqc_identity.fingerprint
        await self.directory.start(self.identity)

    async def stop(self) -> None:
        for rt in self._runtime.values():
            if rt.process:
                rt.process.terminate()
        await self.directory.stop()

    # ── node and peers ─────────────────────────────────────────

    def node(self) -> Node:
        busy = bool(self.repo.list(statuses=ACTIVE))
        return Node(
            id=self.identity.id,
            name=self.identity.name,
            host=self.identity.host,
            port=self.identity.port,
            status="busy" if busy else "idle",
            version=self.version,
            fingerprint=self.pqc_identity.fingerprint,
        )

    async def rename(self, name: str) -> Node:
        self.identity.name = name.strip()
        await self.directory.advertise(self.identity)
        return self.node()

    def _peer_trust(self, fp: str) -> str:
        if not fp:
            return "new"
        rec = self.trust_store.get(fp)
        if rec is None:
            return "new"
        return "verified" if rec.verified else "pinned"

    async def list_peers(self) -> list[Peer]:
        infos = self.directory.peers()
        reachable = await asyncio.gather(*(self.peers.probe(p.host, p.port) for p in infos))
        return [
            Peer(
                id=p.id,
                name=p.name,
                host=p.host,
                port=p.port,
                reachable=ok,
                fingerprint=p.fingerprint,
                trust=self._peer_trust(p.fingerprint),
            )
            for p, ok in zip(infos, reachable)
        ]

    async def get_peer(self, peer_id: str) -> Peer:
        info = self._find_peer(peer_id)
        if info is None:
            raise UnknownPeer(peer_id)
        return Peer(
            id=info.id,
            name=info.name,
            host=info.host,
            port=info.port,
            reachable=await self.peers.probe(info.host, info.port),
            fingerprint=info.fingerprint,
            trust=self._peer_trust(info.fingerprint),
        )

    async def set_peer_trust(self, peer_id: str, verified: bool = True) -> Peer:
        info = self._find_peer(peer_id)
        if info is None:
            raise UnknownPeer(peer_id)
        if info.fingerprint:
            rec = self.trust_store.get(info.fingerprint)
            if rec is None:
                self.trust_store.add(info.fingerprint, name=info.name, verified=verified)
            else:
                self.trust_store.set_verified(info.fingerprint, verified=verified)
        return await self.get_peer(peer_id)

    async def delete_peer_trust(self, peer_id: str) -> Peer:
        info = self._find_peer(peer_id)
        if info is None:
            raise UnknownPeer(peer_id)
        if info.fingerprint:
            self.trust_store.forget(info.fingerprint)
        return await self.get_peer(peer_id)

    def _find_peer(self, peer_id: str) -> Optional[PeerInfo]:
        return next((p for p in self.directory.peers() if p.id == peer_id), None)

    # ── transfers: queries ─────────────────────────────────────

    def get(self, transfer_id: str) -> Transfer:
        return self.repo.get(transfer_id)

    def list(self, direction: Optional[Direction] = None, statuses: Optional[Iterable[TransferStatus]] = None) -> list[Transfer]:
        return self.repo.list(direction, statuses)

    # ── transfers: creation ────────────────────────────────────

    async def create_outgoing(self, filename: str, data: BinaryIO, peer_id: str) -> Transfer:
        """Store the upload, record a pending outgoing transfer, and offer it to the peer."""
        peer = self._find_peer(peer_id)
        if peer is None:
            raise UnknownPeer(peer_id)
        name = os.path.basename(filename or "")
        if not name:
            raise InvalidRequest("The uploaded file has no name")

        transfer_id = uuid.uuid4().hex[:12]
        path = self.upload_dir / transfer_id / name
        path.parent.mkdir(parents=True)
        await asyncio.to_thread(_copy_to, data, path)

        transfer = Transfer(id=transfer_id, direction=Direction.outgoing, status=S.pending, filename=name,
                            file_size=path.stat().st_size,
                            peer=PeerRef(id=peer.id, name=peer.name, host=peer.host, port=peer.port))
        self.repo.add(transfer)
        self._runtime[transfer_id] = _Runtime(upload_path=path)
        self._publish_status(transfer)

        offer = IncomingTransferRequest(
            id=transfer_id,
            filename=name,
            file_size=transfer.file_size,
            sender=self._self_ref(),
            sender_fingerprint=self.pqc_identity.fingerprint,
        )
        try:
            await self.peers.offer_transfer(peer.host, peer.port, offer)
        except PeerError as exc:
            self._fail(transfer_id, f"Peer did not accept the offer: {exc}")
            raise
        return self.repo.get(transfer_id)

    def register_incoming(self, request: IncomingTransferRequest) -> Transfer:
        """Record a transfer offered by another node. Raises TransferExists for a duplicate id."""
        peer = self._find_peer(request.sender.id)
        if peer is not None and peer.fingerprint:
            if request.sender_fingerprint != peer.fingerprint:
                raise FingerprintMismatch(
                    f"Offer sender fingerprint {request.sender_fingerprint!r} does not match "
                    f"advertised fingerprint {peer.fingerprint!r} for peer '{request.sender.id}'"
                )

        transfer = Transfer(id=request.id, direction=Direction.incoming, status=S.pending,
                            filename=os.path.basename(request.filename), file_size=request.file_size,
                            peer=request.sender)
        self.repo.add(transfer)
        self._runtime[transfer.id] = _Runtime()
        self._publish_status(transfer)
        return transfer

    # ── transfers: accept / reject / cancel ────────────────────

    async def respond(self, transfer_id: str, patch: TransferPatch) -> Transfer:
        """Apply an accept/reject PATCH. Raises InvalidTransition (409) unless the transfer is pending."""
        transfer = self.repo.get(transfer_id)
        if transfer.status is not S.pending:
            raise InvalidTransition(transfer.status, S(patch.status))

        if transfer.direction is Direction.incoming:
            if patch.receiver_port is not None:
                raise InvalidRequest("receiver_port is only accepted on outgoing transfers")
            if patch.status == "rejected":
                return await self._reject_incoming(transfer)
            return await self._accept_incoming(transfer)

        if patch.status == "rejected":
            return self._move(transfer_id, S.rejected, error="Rejected by the receiver")
        if patch.receiver_port is None:
            raise InvalidRequest("receiver_port is required to accept an outgoing transfer")
        return await self._start_sender(transfer, patch.receiver_port)

    async def cancel(self, transfer_id: str) -> Transfer:
        """Cancel a pending or running transfer and tell the peer. Raises InvalidTransition once finished."""
        transfer = self._move(transfer_id, S.cancelled, error="Cancelled")
        rt = self._runtime.get(transfer_id)
        if rt and rt.process:
            rt.process.terminate()
        try:
            await self.peers.cancel(transfer.peer.host, transfer.peer.port, transfer_id)
        except PeerError as exc:
            log.info("Peer was not told about cancellation of %s: %s", transfer_id, exc)
        return self.repo.get(transfer_id)

    async def _reject_incoming(self, transfer: Transfer) -> Transfer:
        transfer = self._move(transfer.id, S.rejected, error="Rejected by you")
        try:
            await self.peers.respond(transfer.peer.host, transfer.peer.port, transfer.id, TransferPatch(status="rejected"))
        except PeerError as exc:
            log.info("Sender was not told about rejection of %s: %s", transfer.id, exc)
        return transfer

    async def _accept_incoming(self, transfer: Transfer) -> Transfer:
        """Start bob on a free port, then tell the sender where to connect."""
        self._move(transfer.id, S.accepted)
        rt = self._runtime.setdefault(transfer.id, _Runtime())
        rt.listening = asyncio.get_running_loop().create_future()
        args = ["--port", "0", "--output-dir", self.output_dir, "--transfer-id", transfer.id]
        peer = self._find_peer(transfer.peer.id)
        if peer and peer.fingerprint:
            args.extend(["--peer-fingerprint", peer.fingerprint])
        await self._launch(transfer.id, "bob", args)

        try:
            port = await asyncio.wait_for(asyncio.shield(rt.listening), self.listen_timeout)
        except (asyncio.TimeoutError, RuntimeError) as exc:
            if rt.process:
                rt.process.terminate()
            self._fail(transfer.id, f"Receiver did not start: {exc!r}")
            raise LaunchFailed("The receiver process did not start listening") from exc
        if self.repo.get(transfer.id).status in TERMINAL:  # cancelled while bob was starting
            return self.repo.get(transfer.id)

        try:
            await self.peers.respond(transfer.peer.host, transfer.peer.port, transfer.id,
                                     TransferPatch(status="accepted", receiver_port=port))
        except PeerError as exc:
            if rt.process:
                rt.process.terminate()
            self._fail(transfer.id, f"Sender is unreachable: {exc}")
            raise
        return self.repo.get(transfer.id)

    async def _start_sender(self, transfer: Transfer, receiver_port: int) -> Transfer:
        rt = self._runtime.get(transfer.id)
        if rt is None or rt.upload_path is None or not rt.upload_path.exists():
            self._fail(transfer.id, "The uploaded file is no longer available")
            raise LaunchFailed("The uploaded file is no longer available")
        self._move(transfer.id, S.accepted)
        args = [str(rt.upload_path), "--host", transfer.peer.host,
                "--port", str(receiver_port), "--transfer-id", transfer.id]
        peer = self._find_peer(transfer.peer.id)
        if peer and peer.fingerprint:
            args.extend(["--peer-fingerprint", peer.fingerprint])
        await self._launch(transfer.id, "alice", args)
        return self.repo.get(transfer.id)

    # ── runner processes and their events ──────────────────────

    async def _launch(self, transfer_id: str, role: str, args: list[str]) -> None:
        rt = self._runtime.setdefault(transfer_id, _Runtime())
        try:
            rt.process = await self.launcher.launch(role, args)
        except OSError as exc:
            self._fail(transfer_id, f"Could not start {role}: {exc}")
            raise LaunchFailed(f"Could not start {role}") from exc
        rt.supervisor = asyncio.create_task(self._supervise(transfer_id, role, rt))

    async def _supervise(self, transfer_id: str, role: str, rt: _Runtime) -> None:
        assert rt.process is not None
        try:
            async for event in rt.process.events():
                self._apply_event(transfer_id, event)
            code = await rt.process.wait()
            self._fail(transfer_id, f"{role} exited with code {code} before finishing")
        except Exception as exc:  # keep the node alive whatever the runner does
            log.exception("Supervising %s for %s failed", role, transfer_id)
            self._fail(transfer_id, f"{role} supervision failed: {exc!r}")
        finally:
            if rt.listening and not rt.listening.done():
                rt.listening.set_exception(RuntimeError(f"{role} exited before listening"))

    def _apply_event(self, transfer_id: str, event: dict[str, Any]) -> None:
        type_ = event.get("type", "log")
        stage = event.get("stage")
        payload = event.get("payload") or {}
        self.bus.publish(transfer_id, type_ if type_ in _EVENT_TYPES else "log", stage, payload, event.get("ts"))

        transfer = self.repo.get(transfer_id)
        if transfer.status in TERMINAL:
            return
        if stage and stage != "done":
            transfer.stage = stage

        if type_ == "listening":
            rt = self._runtime.get(transfer_id)
            if rt and rt.listening and not rt.listening.done():
                rt.listening.set_result(int(payload["port"]))
        elif type_ == "metrics":
            for key in METRIC_FIELDS:
                if key in payload:
                    setattr(transfer, key, payload[key])
        elif type_ == "progress":
            transfer.progress = TransferProgress(**{k: payload[k] for k in TransferProgress.model_fields})
        self.repo.save(transfer)

        if type_ == "stage" and stage in STAGE_STATUS and transfer.status is not STAGE_STATUS[stage]:
            self._move(transfer_id, STAGE_STATUS[stage])
        elif type_ == "result" and payload.get("outcome") in OUTCOME_STATUS:
            self._move(transfer_id, OUTCOME_STATUS[payload["outcome"]], error=payload.get("error"))

    # ── status changes ─────────────────────────────────────────

    def _move(self, transfer_id: str, target: TransferStatus, error: Optional[str] = None) -> Transfer:
        """Step to target (through intermediate statuses if needed), publish, and finish up on terminal."""
        transfer = self.repo.get(transfer_id)
        for status in path_to(transfer.status, target):
            transfer.status = status
            if status in TERMINAL and status is not S.completed:
                transfer.error = error
            self.repo.save(transfer)
            self._publish_status(transfer)
        if transfer.status in TERMINAL:
            self._finish(transfer)
        return transfer

    def _fail(self, transfer_id: str, error: str) -> Transfer:
        """Move to failed unless the transfer already finished (a runner may have failed it first)."""
        transfer = self.repo.get(transfer_id)
        if transfer.status in TERMINAL:
            return transfer
        return self._move(transfer_id, S.failed, error=error)

    def _publish_status(self, transfer: Transfer) -> None:
        self.bus.publish(transfer.id, "status", transfer.stage,
                         {"status": transfer.status.value, "error": transfer.error})

    def _finish(self, transfer: Transfer) -> None:
        self.bus.close(transfer.id)
        rt = self._runtime.get(transfer.id)
        if rt and rt.upload_path:
            shutil.rmtree(rt.upload_path.parent, ignore_errors=True)
        try:
            self.history.append(HistoryEntry(
                id=transfer.id, finished_at=utcnow(), direction=transfer.direction, status=transfer.status,
                filename=transfer.filename, file_size=transfer.file_size, peer_name=transfer.peer.name,
                peer_host=transfer.peer.host, qber=transfer.qber, key_bits=transfer.key_bits, error=transfer.error,
                auth_mode=transfer.auth_mode, peer_fingerprint=transfer.peer_fingerprint, peer_trust=transfer.peer_trust,
            ))
        except OSError as exc:
            log.warning("Could not write history: %s", exc)

    def _self_ref(self) -> PeerRef:
        return PeerRef(id=self.identity.id, name=self.identity.name, host=self.identity.host, port=self.identity.port)


_EVENT_TYPES = {"log", "stage", "metrics", "progress", "listening", "result"}


def _copy_to(data: BinaryIO, path: Path) -> None:
    with open(path, "wb") as out:
        shutil.copyfileobj(data, out, 1 << 20)
