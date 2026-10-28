"""qkd-node: run the backend node (REST API + mDNS discovery). API docs at http://<host>:<port>/docs."""

from __future__ import annotations

import argparse
import os

import uvicorn

from qkd.core.config import NODE_PORT


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a QKD backend node.")
    parser.add_argument("--host", default="0.0.0.0", help="Interface to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=NODE_PORT, help=f"HTTP port (default: {NODE_PORT}, env QKD_NODE_PORT)")
    parser.add_argument("--reload", action="store_true", help="Restart on source changes (development)")
    args = parser.parse_args()

    if args.reload:
        # The reloader imports the app in a fresh process, which reads the port from the environment.
        os.environ["QKD_NODE_PORT"] = str(args.port)
        uvicorn.run("qkd.services.api.app:create_app", factory=True, host=args.host, port=args.port, reload=True)
    else:
        from qkd.services.api.app import create_app

        uvicorn.run(create_app(port=args.port), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
