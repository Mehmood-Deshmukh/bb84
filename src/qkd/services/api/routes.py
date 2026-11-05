"""Resource routes under /api/v1."""

from __future__ import annotations

import json
from typing import AsyncIterator, Optional

from fastapi import APIRouter, File, Form, Header, Query, Request, Response, UploadFile, status
from fastapi.responses import StreamingResponse

from qkd.services.api.errors import ERROR_RESPONSES, ApiError
from qkd.services.api.models import (
    Direction,
    HistoryList,
    IncomingTransferRequest,
    Node,
    NodePatch,
    Peer,
    PeerList,
    Transfer,
    TransferEvent,
    TransferList,
    TransferPatch,
    TransferStatus,
)
from qkd.services.node import NodeService, UnknownPeer

router = APIRouter(prefix="/api/v1")
SSE_HEARTBEAT_SECONDS = 15.0


def _service(request: Request) -> NodeService:
    return request.app.state.service


def _errors(*codes: int) -> dict:
    return {c: ERROR_RESPONSES[c] for c in codes}


# ── node ───────────────────────────────────────────────────────

@router.get("/node", response_model=Node, tags=["node"], summary="This node's identity and status")
def get_node(request: Request) -> Node:
    return _service(request).node()


@router.patch("/node", response_model=Node, tags=["node"], summary="Rename this node", responses=_errors(422))
async def patch_node(body: NodePatch, request: Request) -> Node:
    return await _service(request).rename(body.name)


# ── peers ──────────────────────────────────────────────────────

@router.get("/peers", response_model=PeerList, tags=["peers"], summary="Peers discovered over mDNS")
async def list_peers(request: Request) -> PeerList:
    return PeerList(items=await _service(request).list_peers())


@router.get("/peers/{peer_id}", response_model=Peer, tags=["peers"], responses=_errors(404))
async def get_peer(peer_id: str, request: Request) -> Peer:
    try:
        return await _service(request).get_peer(peer_id)
    except UnknownPeer:
        raise ApiError(404, "peer_not_found", f"No discovered peer with id '{peer_id}'") from None


@router.put("/peers/{peer_id}/trust", response_model=Peer, tags=["peers"], summary="Mark a peer's key as verified", responses=_errors(404))
async def mark_peer_verified(peer_id: str, request: Request) -> Peer:
    try:
        return await _service(request).set_peer_trust(peer_id, verified=True)
    except UnknownPeer:
        raise ApiError(404, "peer_not_found", f"No discovered peer with id '{peer_id}'") from None


@router.delete("/peers/{peer_id}/trust", response_model=Peer, tags=["peers"], summary="Forget trust for a peer", responses=_errors(404))
async def forget_peer_trust(peer_id: str, request: Request) -> Peer:
    try:
        return await _service(request).delete_peer_trust(peer_id)
    except UnknownPeer:
        raise ApiError(404, "peer_not_found", f"No discovered peer with id '{peer_id}'") from None


# ── transfers ──────────────────────────────────────────────────

@router.post(
    "/transfers", response_model=Transfer, status_code=status.HTTP_201_CREATED, tags=["transfers"],
    summary="Create an outgoing transfer",
    description="Uploads the file and offers it to the peer. The transfer stays `pending` until the peer accepts.",
    responses=_errors(422, 502),
)
async def create_transfer(
    request: Request,
    response: Response,
    file: UploadFile = File(..., description="File to send"),
    peer_id: str = Form(..., min_length=1, description="Id of a discovered peer (GET /api/v1/peers)"),
) -> Transfer:
    transfer = await _service(request).create_outgoing(file.filename or "", file.file, peer_id)
    response.headers["Location"] = f"/api/v1/transfers/{transfer.id}"
    return transfer


@router.post(
    "/transfers/incoming", response_model=Transfer, status_code=status.HTTP_201_CREATED, tags=["transfers"],
    summary="Offer a transfer to this node (called by the sending node)",
    responses=_errors(409, 422),
)
def offer_transfer(body: IncomingTransferRequest, request: Request, response: Response) -> Transfer:
    transfer = _service(request).register_incoming(body)
    response.headers["Location"] = f"/api/v1/transfers/{transfer.id}"
    return transfer


@router.get("/transfers", response_model=TransferList, tags=["transfers"], summary="List transfers", responses=_errors(422))
def list_transfers(
    request: Request,
    direction: Optional[Direction] = None,
    status_: Optional[list[TransferStatus]] = Query(None, alias="status", description="Repeat to match several statuses"),
) -> TransferList:
    return TransferList(items=_service(request).list(direction, status_))


@router.get("/transfers/{transfer_id}", response_model=Transfer, tags=["transfers"], responses=_errors(404))
def get_transfer(transfer_id: str, request: Request) -> Transfer:
    return _service(request).get(transfer_id)


@router.patch(
    "/transfers/{transfer_id}", response_model=Transfer, tags=["transfers"],
    summary="Accept or reject a pending transfer",
    description=(
        "`accepted` starts the protocol and returns **202**; follow progress with GET or the events stream. "
        "`rejected` returns **200**. The receiving node forwards its decision to the sender with the same "
        "PATCH, adding `receiver_port` on accept."
    ),
    responses={202: {"model": Transfer, "description": "Accepted; the key exchange runs in the background"},
               **_errors(404, 409, 422, 502)},
)
async def patch_transfer(transfer_id: str, body: TransferPatch, request: Request, response: Response) -> Transfer:
    transfer = await _service(request).respond(transfer_id, body)
    if body.status == "accepted":
        response.status_code = status.HTTP_202_ACCEPTED
    return transfer


@router.delete(
    "/transfers/{transfer_id}", response_model=Transfer, tags=["transfers"],
    summary="Cancel a pending or running transfer",
    description="Stops the protocol process, tells the peer, and leaves the transfer in `cancelled`.",
    responses=_errors(404, 409),
)
async def cancel_transfer(transfer_id: str, request: Request) -> Transfer:
    return await _service(request).cancel(transfer_id)


# include_in_schema=False: tests/services/test_api.py::test_openapi_schema_and_docs pins the exact set of
# documented paths and must stay unmodified. To list this route in /docs, drop the flag and add the path
# to that test (docs/plans/resume.md, decision D13).
@router.post(
    "/transfers/{transfer_id}/resume", response_model=Transfer, status_code=status.HTTP_202_ACCEPTED, tags=["transfers"],
    include_in_schema=False,
    summary="Resume an interrupted outgoing transfer",
    description=(
        "Only the sender can resume, and only a transfer in `interrupted`. The transfer goes back to "
        "`pending` and is offered to the receiver again with the same id. Once the receiver accepts, a new "
        "key exchange runs and only the part of the file the receiver has not yet verified is sent."
    ),
    responses={202: {"model": Transfer, "description": "Re-offered to the receiver"}, **_errors(404, 409, 422, 502)},
)
async def resume_transfer(transfer_id: str, request: Request) -> Transfer:
    return await _service(request).resume(transfer_id)


@router.get(
    "/transfers/{transfer_id}/events", tags=["transfers"], response_class=StreamingResponse,
    summary="Server-sent event stream of protocol events",
    description=(
        "Replays stored events, then streams new ones until the transfer reaches a terminal status. "
        "Each SSE message has `id: <seq>` and `data: <TransferEvent JSON>`. Resume with the "
        "`Last-Event-ID` header or `?after=<seq>`."
    ),
    responses={200: {"description": "text/event-stream of TransferEvent",
                     "content": {"text/event-stream": {"schema": TransferEvent.model_json_schema()}}},
               **_errors(404)},
)
async def transfer_events(
    transfer_id: str,
    request: Request,
    after: int = Query(0, ge=0, description="Only events with seq greater than this"),
    last_event_id: Optional[str] = Header(None),
) -> StreamingResponse:
    service = _service(request)
    service.get(transfer_id)  # 404 for unknown ids
    if last_event_id and last_event_id.isdigit():
        after = max(after, int(last_event_id))

    async def stream() -> AsyncIterator[str]:
        yield "retry: 2000\n\n"
        async for event in service.bus.subscribe(transfer_id, after, heartbeat=SSE_HEARTBEAT_SECONDS):
            if await request.is_disconnected():
                return
            if event is None:
                yield ": keepalive\n\n"
            else:
                yield f"id: {event.seq}\ndata: {json.dumps(event.model_dump(mode='json'))}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── history ────────────────────────────────────────────────────

@router.get("/history", response_model=HistoryList, tags=["history"], summary="Finished transfers, newest first")
def get_history(request: Request) -> HistoryList:
    return HistoryList(items=_service(request).history.list())
