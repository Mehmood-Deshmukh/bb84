"""FastAPI application for a QKD backend node. Interactive docs at /docs, schema at /openapi.json."""

from __future__ import annotations

import socket
import uuid
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from qkd import __version__
from qkd.core.config import HISTORY_FILE, NODE_HOST, NODE_NAME, NODE_PORT, OUTPUT_DIR
from qkd.services.api.errors import install_error_handlers
from qkd.services.api.routes import router
from qkd.services.discovery import NodeIdentity, ZeroconfPeerDirectory, local_ip
from qkd.services.events import EventBus
from qkd.services.history import HistoryStore
from qkd.services.node import NodeService
from qkd.services.peer_client import HttpPeerClient
from qkd.services.process_runner import SubprocessLauncher
from qkd.services.transfer_store import InMemoryTransferRepository

DESCRIPTION = """
REST API of one QKD node. Nodes find each other over mDNS and use the same
resources to coordinate a transfer: the sender POSTs `/transfers/incoming` on the
receiver, and the receiver PATCHes the sender's transfer to accept or reject.

Transfer statuses: `pending -> accepted -> key_exchange -> transferring -> completed`,
with `rejected`, `aborted_qber`, `aborted_auth`, `failed`, and `cancelled` as terminal states.

With `QKD_RESUME=1` a transfer that stops after key confirmation becomes `interrupted` (not terminal).
The sender resumes it with `POST /transfers/{id}/resume`; only the part of the file the receiver has
not yet verified is sent, under a fresh key.
"""


def default_service(port: Optional[int] = None) -> NodeService:
    node_id = uuid.uuid4().hex[:8]
    identity = NodeIdentity(
        id=node_id,
        name=NODE_NAME or f"QKD-Node-{socket.gethostname()}-{node_id[:4]}",
        host=NODE_HOST or local_ip(),
        port=port or NODE_PORT,
    )
    return NodeService(
        identity,
        repo=InMemoryTransferRepository(),
        bus=EventBus(),
        history=HistoryStore(HISTORY_FILE),
        directory=ZeroconfPeerDirectory(),
        peers=HttpPeerClient(),
        launcher=SubprocessLauncher(),
        output_dir=OUTPUT_DIR,
        version=__version__,
    )


def create_app(service: Optional[NodeService] = None, *, port: Optional[int] = None) -> FastAPI:
    service = service or default_service(port)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await service.start()
        try:
            yield
        finally:
            await service.stop()

    app = FastAPI(title="QKD Node API", version=__version__, description=DESCRIPTION, lifespan=lifespan)
    app.state.service = service
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Location"],
    )
    install_error_handlers(app)
    app.include_router(router)
    return app
