"""
Transfer orchestration for one backend node. The REST routes are a thin layer over this.

Node-to-node flow (both nodes keep a transfer with the same id):

  sender UI    POST /transfers (file, peer_id)      -> outgoing transfer, pending
  sender       POST peer /transfers/incoming         -> incoming transfer, pending
  receiver UI  PATCH /transfers/{id} accepted        -> starts bob on a free port
  receiver     PATCH sender /transfers/{id} accepted, receiver_port
  sender       starts alice -> receiver_host:receiver_port

Statuses then follow the stage/result events that alice and bob emit.

With QKD_RESUME on, a transfer that stops after key confirmation (the connection drops, a runner is
killed, a chunk fails authentication) becomes `interrupted` instead of `failed`. The sender resumes it
with POST /transfers/{id}/resume: the same id goes back to `pending` on both nodes, the receiver
accepts as for any offer, and a new session continues at the first chunk the receiver has not verified.
Interrupted transfers are written to QKD_STATE_FILE so they survive a restart of the node.
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

from qkd.core.config import IDENTITY_DIR, KNOWN_PEERS_FILE, RESUME, STATE_FILE
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
from qkd.services.interrupted_store import InterruptedStore
from qkd.services.peer_client import PeerClient, PeerError
from qkd.services.process_runner import ProtocolLauncher, RunningProcess
from qkd.services.resume import ResumeStore
from qkd.services.transfer_store import (
    ACTIVE,
    TERMINAL,
    InvalidTransition,
    TransferExists,
    TransferNotFound,
    TransferRepository,
    path_to,
)

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
    "interrupted": S.interrupted,
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
    "resumed_from_bytes",
    "bytes_total",
    "resume_restart_reason",
)
_SIGNED_MODES = ("sign", "hybrid")


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
        resume: Optional[bool] = None,
        state_file: Optional[str | Path] = None,
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
        self.resume_enabled = bool(RESUME) if resume is None else resume
        self._state: Optional[InterruptedStore] = None
        if self.resume_enabled:
            self._state = InterruptedStore(state_file or STATE_FILE)
            self._restore_interrupted()

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

        if request.resume_transfer_id is not None:
            resumed = self._register_resume_offer(request)
            if resumed is not None:
                return resumed

        transfer = Transfer(id=request.id, direction=Direction.incoming, status=S.pending,
                            filename=os.path.basename(request.filename), file_size=request.file_size,
                            peer=request.sender)
        self.repo.add(transfer)
        self._runtime[transfer.id] = _Runtime()
        self._publish_status(transfer)
        return transfer

    def _register_resume_offer(self, request: IncomingTransferRequest) -> Optional[Transfer]:
        """
        An offer that continues an interrupted transfer: put that transfer back to `pending` so the user
        accepts it like any offer. Returns None when this node has no such transfer (it lost its state):
        the offer is then handled as a new transfer, and the sender restarts from byte 0.
        """
        if request.resume_transfer_id != request.id:
            raise InvalidRequest("resume_transfer_id must equal the transfer id")
        try:
            existing = self.repo.get(request.id)
        except TransferNotFound:
            return None
        if (existing.direction is not Direction.incoming or not self._same_sender(existing, request)
                or existing.filename != os.path.basename(request.filename) or existing.file_size != request.file_size):
            raise InvalidRequest("The resume offer does not match the interrupted transfer")
        if existing.status is not S.interrupted:
            raise TransferExists(request.id)
        transfer = self._move(request.id, S.pending)
        self._prepare_new_attempt(transfer)
        transfer.peer = request.sender  # the sender may have a new address
        self.repo.save(transfer)
        return transfer

    @staticmethod
    def _same_sender(existing: Transfer, request: IncomingTransferRequest) -> bool:
        """
        Whether a resume offer comes from the node that started `existing`. Node ids are random per
        start, so after a restart the PQC identity fingerprint (stable, persisted) is what matches;
        ids are compared only when a fingerprint is missing on either side. This is a consistency
        check on an unauthenticated HTTP offer: the binding that matters is the receiver runner
        comparing the *authenticated* fingerprint with the one in its sidecar.
        """
        if existing.peer_fingerprint and request.sender_fingerprint:
            return existing.peer_fingerprint == request.sender_fingerprint
        return existing.peer.id == request.sender.id

    def _find_peer_for(self, transfer: Transfer) -> Optional[PeerInfo]:
        """The discovered peer for a transfer: by node id, else by identity fingerprint (the peer restarted)."""
        peer = self._find_peer(transfer.peer.id)
        if peer is None and transfer.peer_fingerprint:
            peer = next((p for p in self.directory.peers() if p.fingerprint == transfer.peer_fingerprint), None)
        return peer

    def _prepare_new_attempt(self, transfer: Transfer) -> Transfer:
        """Clear what describes the previous attempt; the new one reports its own."""
        transfer.attempt += 1
        transfer.error = None
        transfer.stage = None
        transfer.progress = None
        transfer.resume_restart_reason = None
        return self.repo.save(transfer)

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

    async def resume(self, transfer_id: str) -> Transfer:
        """
        Resume an interrupted outgoing transfer: go back to `pending` and re-offer it to the receiver with
        the same id. The receiver accepts as for any offer, then a new session continues where its
        verified data ends. Raises InvalidTransition (409) unless the transfer is interrupted.
        """
        transfer = self.repo.get(transfer_id)
        if transfer.direction is not Direction.outgoing:
            raise InvalidRequest("Only the sending node can resume a transfer")
        if transfer.status is not S.interrupted:
            raise InvalidTransition(transfer.status, S.pending)
        rt = self._runtime.get(transfer_id)
        if rt is None or rt.upload_path is None or not rt.upload_path.exists():
            self._fail(transfer_id, "The uploaded file is no longer available")
            raise LaunchFailed("The uploaded file is no longer available")

        transfer = self._move(transfer_id, S.pending)
        peer = self._find_peer_for(transfer)
        if peer is not None:  # the receiver may have moved or restarted (new node id) since
            transfer.peer = PeerRef(id=peer.id, name=peer.name, host=peer.host, port=peer.port)
        self._prepare_new_attempt(transfer)
        offer = IncomingTransferRequest(
            id=transfer_id,
            filename=transfer.filename,
            file_size=transfer.file_size,
            sender=self._self_ref(),
            sender_fingerprint=self.pqc_identity.fingerprint,
            resume_transfer_id=transfer_id,
        )
        try:
            await self.peers.offer_transfer(transfer.peer.host, transfer.peer.port, offer)
        except PeerError as exc:  # nothing was lost: it is still resumable
            self._move(transfer_id, S.interrupted, error=f"The receiver did not take the resume offer: {exc}")
            raise
        return self.repo.get(transfer_id)

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
        if self.resume_enabled:
            args.append("--resume")
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
        if self.resume_enabled:
            args.append("--resume")
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
        process = rt.process
        try:
            async for event in process.events():
                self._apply_event(transfer_id, event)
            code = await process.wait()
            if rt.process is process:  # not superseded by a resumed attempt
                self._runner_exited(transfer_id, f"{role} exited with code {code} before finishing")
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

    def _runner_exited(self, transfer_id: str, error: str) -> None:
        """A runner's event stream ended without a result: interrupted if it can be resumed, else failed."""
        transfer = self.repo.get(transfer_id)
        if transfer.status in TERMINAL or transfer.status is S.interrupted:
            return
        resumable = (self.resume_enabled and transfer.status is S.transferring
                     and transfer.auth_mode in _SIGNED_MODES)
        if resumable:
            self._move(transfer_id, S.interrupted, error=error)
        else:
            self._fail(transfer_id, error)

    # ── status changes ─────────────────────────────────────────

    def _move(self, transfer_id: str, target: TransferStatus, error: Optional[str] = None) -> Transfer:
        """Step to target (through intermediate statuses if needed), publish, and finish up on terminal."""
        transfer = self.repo.get(transfer_id)
        came_from = transfer.status
        for status in path_to(transfer.status, target):
            transfer.status = status
            if (status in TERMINAL and status is not S.completed) or status is S.interrupted:
                transfer.error = error
            self.repo.save(transfer)
            self._publish_status(transfer)
        if transfer.status in TERMINAL:
            self._finish(transfer)
        elif transfer.status is S.interrupted:
            self._on_interrupted(transfer, new=came_from is not S.pending)
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
        if self._state is not None:
            self._state.remove(transfer.id)
            if transfer.direction is Direction.incoming:  # nothing left to resume: drop the verified bytes too
                try:
                    ResumeStore(self.output_dir, transfer.id).discard()
                except (ValueError, OSError) as exc:
                    log.warning("Could not remove resume state of %s: %s", transfer.id, exc)
        self._append_history(transfer)

    def _append_history(self, transfer: Transfer) -> None:
        try:
            self.history.append(HistoryEntry(
                id=transfer.id, finished_at=utcnow(), direction=transfer.direction, status=transfer.status,
                filename=transfer.filename, file_size=transfer.file_size, peer_name=transfer.peer.name,
                peer_host=transfer.peer.host, qber=transfer.qber, key_bits=transfer.key_bits, error=transfer.error,
                auth_mode=transfer.auth_mode, peer_fingerprint=transfer.peer_fingerprint, peer_trust=transfer.peer_trust,
                resumed_from_bytes=transfer.resumed_from_bytes, bytes_total=transfer.bytes_total,
            ))
        except OSError as exc:
            log.warning("Could not write history: %s", exc)

    # ── interrupted transfers ──────────────────────────────────

    def _on_interrupted(self, transfer: Transfer, new: bool = True) -> None:
        """Keep what a resume needs: stop the runner, park the upload, persist the record, log it in history."""
        rt = self._runtime.get(transfer.id)
        if rt and rt.process:
            rt.process.terminate()
        if self._state is not None:
            if rt and rt.upload_path and rt.upload_path.exists() and transfer.direction is Direction.outgoing:
                rt.upload_path = self._park_upload(transfer.id, rt.upload_path)
            self._state.put(transfer.id, transfer.model_dump(mode="json"), str(rt.upload_path) if rt and rt.upload_path else None)
        if new:
            self._append_history(transfer)

    def _park_upload(self, transfer_id: str, path: Path) -> Path:
        """Move an upload out of the per-process temp dir into the state directory."""
        assert self._state is not None
        dest = self._state.uploads_dir / transfer_id / path.name
        if path == dest:
            return path
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(path), str(dest))
            shutil.rmtree(path.parent, ignore_errors=True)
            return dest
        except OSError as exc:
            log.warning("Could not keep the upload of %s for a resume: %s", transfer_id, exc)
            return path

    def _restore_interrupted(self) -> None:
        """Load interrupted transfers from the state file (called once, at construction)."""
        assert self._state is not None
        for record in self._state.load_all():
            try:
                transfer = Transfer.model_validate(record["transfer"])
            except (ValueError, KeyError):
                continue
            upload = Path(record["upload_path"]) if record.get("upload_path") else None
            if transfer.direction is Direction.outgoing and (upload is None or not upload.exists()):
                transfer.status, transfer.error = S.failed, "The uploaded file is gone, so the transfer cannot be resumed"
                self._state.remove(transfer.id)
            else:
                transfer.status = S.interrupted
            try:
                self.repo.add(transfer)
            except TransferExists:
                continue
            self._runtime[transfer.id] = _Runtime(upload_path=upload)

    def _self_ref(self) -> PeerRef:
        return PeerRef(id=self.identity.id, name=self.identity.name, host=self.identity.host, port=self.identity.port)


_EVENT_TYPES = {"log", "stage", "metrics", "progress", "listening", "result"}


def _copy_to(data: BinaryIO, path: Path) -> None:
    with open(path, "wb") as out:
        shutil.copyfileobj(data, out, 1 << 20)
