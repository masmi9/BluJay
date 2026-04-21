"""
Start the BluJay server.

Use this instead of invoking uvicorn directly:
    python run.py              # production-style (no reload)
    python run.py --reload     # development (hot-reload)

Why: On Windows, asyncio.WindowsProactorEventLoopPolicy must be set BEFORE
uvicorn creates its event loop, which happens before main.py is imported.
Running via this script guarantees the policy is in place first.
"""
import sys
import asyncio

# Must happen before ANY uvicorn import so the ProactorEventLoop is used
# for every subprocess call (apktool, jadx, adb, logcat, etc.)
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

import argparse
import uvicorn

parser = argparse.ArgumentParser(description="BluJay server")
parser.add_argument("--host", default="127.0.0.1")
parser.add_argument("--port", type=int, default=8000)
parser.add_argument("--reload", action="store_true", default=True)
parser.add_argument("--no-reload", dest="reload", action="store_false")
args = parser.parse_args()

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )
