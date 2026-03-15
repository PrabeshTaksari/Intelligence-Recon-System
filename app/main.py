"""Main FastAPI application."""
import sys
import os
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from contextlib import asynccontextmanager

from dotenv import load_dotenv

# Always load .env from project root so config is correct regardless of cwd
load_dotenv(project_root / ".env")

from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import FastAPI, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings


class NoCacheStaticMiddleware(BaseHTTPMiddleware):
    """Set no-cache headers so clients always load latest UI."""

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        # Avoid stale frontend assets and HTML when accessed from other devices/browsers.
        # Static JS/CSS live under /static, and index.html is served at /.
        if request.url.path.startswith("/static/") or request.url.path == "/":
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response
from app.core.database import init_db
from app.core.logging import setup_logging
from app.api import health, scans, reports, tools, scheduled_scans, settings as settings_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    import asyncio
    from app.core.database import AsyncSessionLocal
    from app.services.scheduled_scan_service import run_due_schedules

    setup_logging()
    await init_db()

    async def scheduled_scan_loop():
        """Every minute, run due scheduled scans (by next_run_at)."""
        while True:
            await asyncio.sleep(60)  # 1 minute
            try:
                async with AsyncSessionLocal() as db:
                    await run_due_schedules(db)
            except asyncio.CancelledError:
                break
            except Exception as e:
                from app.core.logging import get_logger
                get_logger(__name__).exception("Scheduled scan loop error: %s", e)

    task = asyncio.create_task(scheduled_scan_loop())

    yield

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="Intelligence Recon System (IRS)",
    description="AI-assisted OWASP Top 10 reconnaissance platform",
    version="1.0.0",
    lifespan=lifespan,
)


app.add_middleware(NoCacheStaticMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="Frontend"), name="static")

# API prefix like "/api"
app.include_router(health.router, prefix=settings.API_PREFIX)
app.include_router(scans.router, prefix=settings.API_PREFIX)
app.include_router(reports.router, prefix=settings.API_PREFIX)
app.include_router(tools.router, prefix=settings.API_PREFIX)
app.include_router(scheduled_scans.router, prefix=settings.API_PREFIX)
app.include_router(settings_router.router, prefix=settings.API_PREFIX)


@app.get("/", include_in_schema=False)
async def root():
  # Serve the frontend HTML directly
  from fastapi.responses import HTMLResponse
  import os
  frontend_path = os.path.join(
      os.path.dirname(__file__), '..', 'Frontend', 'index.html'
  )
  with open(frontend_path, 'r') as f:
      html_content = f.read()
  return HTMLResponse(content=html_content)


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """
    Serve an empty favicon to avoid 404 noise in logs.
    Add a real icon under /static and redirect here if desired.
    """
    return Response(status_code=204)


if __name__ == "__main__":
    import os
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8080,
        reload=os.getenv("FASTAPI_RELOAD", "false").lower() == "true",
    )
