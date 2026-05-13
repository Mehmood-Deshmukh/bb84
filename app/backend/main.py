from __future__ import annotations
import asyncio
import socket
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, UploadFile, File, Form, BackgroundTasks
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
current_info = None

from zeroconf.asyncio import AsyncServiceInfo

active_connections = []

async def broadcast_log(message: str):
    for conn in list(active_connections):
        try:
            await conn.send_json({"type": "transfer_log", "message": message})
        except:
            if conn in active_connections:
                active_connections.remove(conn)

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

async def register_mdns(name: str):
    global current_info, zeroconf_instance, NODE_NAME
    NODE_NAME = name
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
        f"{name}.{SERVICE_TYPE}",
        addresses=[socket.inet_aton(local_ip)],
        port=SERVICE_PORT,
        properties={'version': '1.0', 'status': 'available'},
        server=f"{name}.local."
    )
    
    if current_info and zeroconf_instance:
        await zeroconf_instance.async_unregister_service(current_info)
        
    if zeroconf_instance:
        await zeroconf_instance.async_register_service(info)
    current_info = info
    print(f"[*] Registered mDNS service: {name} at {local_ip}:{SERVICE_PORT}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    global zeroconf_instance, browser
    zeroconf_instance = AsyncZeroconf()
    await register_mdns(NODE_NAME)
    
    # Start discovering other peers
    listener = PeerListener()
    browser = AsyncServiceBrowser(zeroconf_instance.zeroconf, SERVICE_TYPE, listener)
    
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

@app.post("/api/set-username")
async def set_username(data: dict):
    username = data.get("username")
    if not username:
        return {"status": "error"}
    await register_mdns(username)
    return {"status": "ok", "username": username}

@app.get("/api/peers")
def get_peers():
    import urllib.request
    import concurrent.futures
    
    def check_peer(p):
        try:
            req = urllib.request.Request(f"http://{p['ip']}:{p['port']}/api/health")
            with urllib.request.urlopen(req, timeout=0.5) as resp:
                if resp.status == 200:
                    return p
        except:
            return None
            
    active_peers = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(check_peer, p) for p in discovered_peers.values() if p['name'] != NODE_NAME]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                active_peers.append(res)
    
    return {"peers": active_peers}

@app.post("/api/transfer")
async def initiate_transfer(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    target_ip: str = Form(...),
    target_port: int = Form(...)
):
    import tempfile
    import shutil
    import socket
    import urllib.request
    import json
    import threading

    temp_dir = tempfile.mkdtemp()
    filepath = os.path.join(temp_dir, file.filename)
    with open(filepath, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        my_ip = s.getsockname()[0]
    except:
        my_ip = '127.0.0.1'
    finally:
        s.close()
        
    global alice_pending_transfer
    alice_pending_transfer = {
        "filepath": filepath,
        "filename": file.filename,
        "target_ip": target_ip
    }
    
    data = json.dumps({
        "filename": file.filename,
        "file_size": os.path.getsize(filepath),
        "sender_ip": my_ip
    }).encode()
    
    def send_req():
        try:
            req = urllib.request.Request(f"http://{target_ip}:8000/api/request-transfer", data=data, headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            pass
            
    threading.Thread(target=send_req, daemon=True).start()
    return {"status": "ok", "message": "Request sent to peer. Waiting for acceptance..."}

pending_requests = {}
alice_pending_transfer = {}

@app.post("/api/request-transfer")
async def request_transfer(data: dict):
    transfer_id = str(uuid.uuid4())[:8]
    pending_requests[transfer_id] = data
    for conn in list(active_connections):
        try:
            await conn.send_json({"type": "incoming_request", "transfer_id": transfer_id, "data": data})
        except:
            pass
    return {"status": "pending"}

@app.post("/api/respond-transfer")
async def respond_transfer(data: dict):
    import os
    import sys
    import subprocess
    import threading
    import urllib.request
    import json

    transfer_id = data["transfer_id"]
    if transfer_id not in pending_requests:
        return {"status": "error", "message": "Invalid transfer ID"}
    req = pending_requests.pop(transfer_id)
    sender_ip = req["sender_ip"]
    
    loop = asyncio.get_running_loop()
    
    if data["accept"]:
        bob_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "bob.py")
        root_venv_python = os.path.join(os.path.dirname(bob_path), ".venv", "bin", "python")
        python_exe = root_venv_python if os.path.exists(root_venv_python) else sys.executable
        
        def run_bob_bg():
            import re
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            asyncio.run_coroutine_threadsafe(broadcast_log("[*] Receiver launched, waiting for sender..."), loop)
            
            process = subprocess.Popen(
                [python_exe, "-u", bob_path],
                cwd=os.path.dirname(bob_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            for line in iter(process.stdout.readline, ''):
                clean_line = ansi_escape.sub('', line).strip()
                if clean_line:
                    asyncio.run_coroutine_threadsafe(broadcast_log(clean_line), loop)
            process.stdout.close()
            process.wait()
            asyncio.run_coroutine_threadsafe(broadcast_log("[*] Receiver Process Complete"), loop)

        threading.Thread(target=run_bob_bg, daemon=True).start()
        
        # Determine actual BOB_PORT from config
        sys.path.append(os.path.dirname(bob_path))
        try:
            import config
            bob_port = config.BOB_PORT
        except:
            bob_port = 65432
            
        try:
            req_data = json.dumps({"target_port": bob_port}).encode()
            req_obj = urllib.request.Request(f"http://{sender_ip}:8000/api/start-alice", data=req_data, headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req_obj)
        except Exception as e:
            print(f"[!] HTTP Error notifying Alice to start: {e}")
        return {"status": "accepted"}
    else:
        try:
            req_obj = urllib.request.Request(f"http://{sender_ip}:8000/api/reject-alice", data=b"{}", headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req_obj)
        except:
            pass
        return {"status": "rejected"}

@app.post("/api/start-alice")
async def start_alice(data: dict):
    import re
    import subprocess
    import sys
    import threading

    print("[!] Received request to start Alice")
    print("[!] Target port: ", data.get("target_port"))
    print("[!] Target IP: ", data.get("target_ip"))

    target_port = data.get("target_port", 65432)
    filepath = alice_pending_transfer.get("filepath")
    filename = alice_pending_transfer.get("filename")
    target_ip = alice_pending_transfer.get("target_ip")
    
    if not filepath:
        return {"status": "error"}

    loop = asyncio.get_running_loop()

    def run_alice_bg():
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        alice_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "alice.py")
        root_venv_python = os.path.join(os.path.dirname(alice_path), ".venv", "bin", "python")
        python_exe = root_venv_python if os.path.exists(root_venv_python) else sys.executable
        
        asyncio.run_coroutine_threadsafe(broadcast_log(f"[*] Peer ACCEPTED! Starting transfer of {filename} to {target_ip}:{target_port}"), loop)

        process = subprocess.Popen(
            [python_exe, "-u", alice_path, filepath, "--host", target_ip, "--port", str(target_port)],
            cwd=os.path.dirname(alice_path),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        for line in iter(process.stdout.readline, ''):
            clean_line = ansi_escape.sub('', line).strip()
            if clean_line:
                asyncio.run_coroutine_threadsafe(broadcast_log(clean_line), loop)
        process.stdout.close()
        process.wait()
        asyncio.run_coroutine_threadsafe(broadcast_log(f"[*] Transfer Process Complete"), loop)

    threading.Thread(target=run_alice_bg, daemon=True).start()
    return {"status": "ok"}

@app.post("/api/reject-alice")
async def reject_alice():
    for conn in list(active_connections):
        try:
            await conn.send_json({"type": "transfer_log", "message": "[!] Transfer REJECTED by peer."})
        except:
            pass
    return {"status": "ok"}

@app.websocket("/api/ws/status")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.clear()
    active_connections.append(websocket)
    try:
        await websocket.send_json({"type": "info", "message": f"Connected to {NODE_NAME}"})
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({"type": "echo", "message": f"Received: {data}"})
    except Exception as e:
        pass
    finally:
        if websocket in active_connections:
            active_connections.remove(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=SERVICE_PORT, reload=True)
