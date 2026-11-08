"""Pydantic request/response models for the node REST API (/api/v1)."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TransferStatus(str, Enum):
    pending = "pending"
    accepted = "accepted"
    key_exchange = "key_exchange"
    transferring = "transferring"
    interrupted = "interrupted"  # resumable: stopped after key confirmation; the sender can POST .../resume
    completed = "completed"
    rejected = "rejected"
    aborted_qber = "aborted_qber"
    aborted_auth = "aborted_auth"
    failed = "failed"
    cancelled = "cancelled"


class Direction(str, Enum):
    outgoing = "outgoing"
    incoming = "incoming"


class PeerRef(BaseModel):
    """The other node of a transfer."""

    id: str
    name: str
    host: str
    port: int = Field(ge=1, le=65535)


class TransferProgress(BaseModel):
    chunks_done: int
    num_chunks: int
    bytes_done: int
    total_bytes: int


class Transfer(BaseModel):
    id: str
    direction: Direction
    status: TransferStatus
    stage: Optional[str] = Field(None, description="Last protocol stage reported by alice/bob")
    filename: str
    file_size: int
    peer: PeerRef
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    raw_qubits: Optional[int] = None
    sifted_length: Optional[int] = None
    sample_size: Optional[int] = None
    qber: Optional[float] = None
    qber_threshold: Optional[float] = None
    key_bits: Optional[int] = None
    progress: Optional[TransferProgress] = None
    output_path: Optional[str] = Field(None, description="Where the received file was written (incoming only)")
    error: Optional[str] = None
    auth_mode: Optional[str] = None
    peer_fingerprint: Optional[str] = None
    peer_trust: Optional[str] = None
    handshake_ms: Optional[float] = None
    auth_overhead_bytes: Optional[int] = None
    attempt: int = Field(1, ge=1, description="1 for the first try; each resume of an interrupted transfer adds one")
    resumed_from_bytes: Optional[int] = Field(None, description="Bytes already verified on the receiver when this attempt started")
    bytes_total: Optional[int] = Field(None, description="Size of the file being transferred")
    resume_restart_reason: Optional[str] = Field(None, description="Why a resume started from byte 0 (source_changed, file_changed, chunk_size_changed)")


class TransferList(BaseModel):
    items: list[Transfer]


class IncomingTransferRequest(BaseModel):
    """Sent by the sending node to POST /api/v1/transfers/incoming on the receiver."""

    id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    filename: str = Field(min_length=1, max_length=255)
    file_size: int = Field(ge=0)
    sender: PeerRef
    sender_fingerprint: Optional[str] = None
    resume_transfer_id: Optional[str] = Field(
        None, min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$",
        description="Set when this offer continues an interrupted transfer; must equal `id`",
    )


class TransferPatch(BaseModel):
    """
    Accept or reject a pending transfer.

    The local user PATCHes an incoming transfer. The receiving node then PATCHes the
    sender's outgoing transfer with the same status, plus `receiver_port` on accept.
    """

    status: Literal["accepted", "rejected"]
    receiver_port: Optional[int] = Field(None, ge=1, le=65535, description="Bob's TCP port. Required when a receiver accepts an outgoing transfer.")


class Node(BaseModel):
    id: str
    name: str
    host: str
    port: int
    status: Literal["idle", "busy"]
    version: str
    fingerprint: str


class NodePatch(BaseModel):
    name: str = Field(min_length=1, max_length=63, pattern=r"^[^.]+$", description="Display name advertised over mDNS (no dots)")


class Peer(BaseModel):
    id: str
    name: str
    host: str
    port: int
    reachable: bool
    fingerprint: str = ""
    trust: Literal["new", "pinned", "verified"] = "new"


class PeerList(BaseModel):
    items: list[Peer]


class HistoryEntry(BaseModel):
    id: str
    finished_at: datetime
    direction: Direction
    status: TransferStatus
    filename: str
    file_size: int
    peer_name: str
    peer_host: str
    qber: Optional[float] = None
    key_bits: Optional[int] = None
    error: Optional[str] = None
    auth_mode: Optional[str] = None
    peer_fingerprint: Optional[str] = None
    peer_trust: Optional[str] = None
    resumed_from_bytes: Optional[int] = None
    bytes_total: Optional[int] = None


class HistoryList(BaseModel):
    items: list[HistoryEntry]


class TransferEvent(BaseModel):
    """One protocol event. Streamed by GET /api/v1/transfers/{id}/events."""

    seq: int = Field(description="Position in this transfer's event log (also the SSE id)")
    type: Literal["log", "stage", "metrics", "progress", "listening", "result", "status"]
    transfer_id: str
    stage: Optional[str] = None
    payload: dict[str, Any] = Field(default_factory=dict)
    ts: float


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: Optional[list[dict[str, Any]]] = None


class ErrorResponse(BaseModel):
    error: ErrorDetail
