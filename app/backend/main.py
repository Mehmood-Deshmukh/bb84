import asyncio
import socket
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from zeroconf import ServiceInfo, Zeroconf

SERVICE_TYPE = "_qkd._tcp.local."
SERVICE_PORT = 8000
NODE_NAME = f"QKD-Node-{socket.gethostname()}"

zeroconf_instance = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global zeroconf_instance
    # Get local IP
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
    
    zeroconf_instance = Zeroconf()
    zeroconf_instance.register_service(info)
    print(f"[*] Registered mDNS service: {NODE_NAME} at {local_ip}:{SERVICE_PORT}")
    
    yield
    
    # Cleanup on shutdown
    if zeroconf_instance:
        zeroconf_instance.unregister_service(info)
        zeroconf_instance.close()
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
