"""qkd-node: run the FastAPI backend node with mDNS peer discovery."""

from __future__ import annotations

import argparse

import uvicorn

from qkd.services.api.app import SERVICE_PORT


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a QKD backend node.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=SERVICE_PORT)
    parser.add_argument("--reload", action="store_true", help="Restart on source changes (development)")
    args = parser.parse_args()
    uvicorn.run("qkd.services.api.app:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
