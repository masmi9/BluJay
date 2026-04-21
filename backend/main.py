import asyncio
import sys
from contextlib import asynccontextmanager
from pathlib import Path

# Windows: uvicorn's watchfiles reloader spawns a child process that inherits
# SelectorEventLoop, which does not support asyncio.create_subprocess_exec.
# Force ProactorEventLoop so subprocess calls work in all uvicorn modes.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from config import settings
from database import init_db
# Import all models so SQLAlchemy metadata knows about every table before create_all
import models.analysis    # noqa: F401
import models.session     # noqa: F401
import models.agent       # noqa: F401
import models.owasp       # noqa: F401
import models.testing     # noqa: F401
import models.screenshot  # noqa: F401
import models.cve         # noqa: F401
import models.tls_audit   # noqa: F401
import models.jwt_test    # noqa: F401
import models.fuzzing      # noqa: F401
import models.brute_force  # noqa: F401
import models.api_testing    # noqa: F401
import models.analysis_diff  # noqa: F401
import models.campaign       # noqa: F401

logger = structlog.get_logger()

FRONTEND_DIST = Path(__file__).parent.parent / "frontend" / "dist"


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.ensure_dirs()
    await init_db()
    logger.info("Database initialised", db=str(settings.db_path))

    from core import tool_detector
    tools = await tool_detector.check_all()
    for name, status in tools.items():
        if status["found"]:
            logger.info("Tool found", tool=name, version=status["version"], path=status["path"])
        else:
            logger.warning("Tool missing", tool=name, hint=status["install_hint"])

    yield

    # Shutdown: stop any running proxy/frida managers
    from api.router import get_proxy_manager, get_frida_manager
    pm = get_proxy_manager()
    if pm:
        await pm.stop_all()
    fm = get_frida_manager()
    if fm:
        await fm.detach_all()


def create_app() -> FastAPI:
    app = FastAPI(
        title="BluJay",
        version="1.0.0",
        description="Mobile application security analysis platform for Android and iOS",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    from api.router import api_router
    app.include_router(api_router, prefix="/api/v1")

    from api.ws import ws_router
    app.include_router(ws_router, prefix="/ws")

    # Serve frontend in production
    if FRONTEND_DIST.exists():
        app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        async def spa_fallback(full_path: str):
            index = FRONTEND_DIST / "index.html"
            return FileResponse(str(index))

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=True)
