import asyncio
import socket
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from zeroconf import ServiceInfo, Zeroconf
from zeroconf.asyncio import AsyncZeroconf, AsyncServiceBrowser

import os
import uuid

SERVICE_TYPE = "_qkd._tcp.local."
SERVICE_PORT = int(os.environ.get("PORT", 8000))
NODE_ID = str(uuid.uuid4())[:4]
NODE_NAME = f"QKD-Node-{socket.gethostname()}-{NODE_ID}"

zeroconf_instance = None
browser = None
discovered_peers = {}

from zeroconf.asyncio import AsyncServiceInfo

class PeerListener:
    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        if name in discovered_peers:
            del discovered_peers[name]

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        asyncio.create_task(self._async_add_service(zc, type_, name))

    async def _async_add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = AsyncServiceInfo(type_, name)
        await info.async_request(zc, 3000)
        if info and info.addresses:
            addresses = [socket.inet_ntoa(addr) for addr in info.addresses]
            discovered_peers[name] = {
                "name": name.replace(f".{SERVICE_TYPE}", ""),
                "ip": addresses[0] if addresses else None,
                "port": info.port
            }

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        self.add_service(zc, type_, name)

@asynccontextmanager
async def lifespan(app: FastAPI):
    global zeroconf_instance, browser
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
        
    info = ServiceInfo(
        SERVICE_TYPE,
        f"{NODE_NAME}.{SERVICE_TYPE}",
        addresses=[socket.inet_aton(local_ip)],
        port=SERVICE_PORT,
        properties={'version': '1.0', 'status': 'available'},
        server=f"{NODE_NAME}.local."
    )
    
    zeroconf_instance = AsyncZeroconf()
    await zeroconf_instance.async_register_service(info)
    
    # Start discovering other peers
    listener = PeerListener()
    browser = AsyncServiceBrowser(zeroconf_instance.zeroconf, SERVICE_TYPE, listener)
    
    print(f"[*] Registered mDNS service: {NODE_NAME} at {local_ip}:{SERVICE_PORT}")
    
    yield
    
    if browser:
        await browser.async_cancel()
    if zeroconf_instance:
        await zeroconf_instance.async_unregister_service(info)
        await zeroconf_instance.async_close()
        print("[*] Unregistered mDNS service.")

app = FastAPI(title="QKD Backend Node", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
def health_check():
    return {"status": "ok", "node": NODE_NAME}

@app.get("/api/peers")
def get_peers():
    # Return all discovered peers except ourselves
    active_peers = [p for p in discovered_peers.values() if p['name'] != NODE_NAME]
    return {"peers": active_peers}

@app.websocket("/api/ws/status")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    await websocket.send_json({"type": "info", "message": f"Connected to {NODE_NAME}"})
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({"type": "echo", "message": f"Received: {data}"})
    except Exception as e:
        print(f"WebSocket closed: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=SERVICE_PORT, reload=True)
