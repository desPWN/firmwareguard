import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.requests import Request

from app.config import get_settings
from app.database import async_session_factory
from app.routers import (
    analysis,
    auth,
    comparison,
    component_map,
    documents,
    emulation,
    export_import,
    files,
    findings,
    firmware,
    fuzzing,
    kernels,
    projects,
    sbom,
    secrets,
    terminal,
    uart,
)
from app.routers.auth import is_authenticated
from app.services.emulation_service import EmulationService
from app.services.fuzzing_service import FuzzingService
from app.utils.sandbox import PathTraversalError

logger = logging.getLogger(__name__)


async def _periodic_cleanup_loop(interval_seconds: int) -> None:
    """Periodically stop expired emulation sessions and fuzzing campaigns."""
    interval = max(30, interval_seconds)
    while True:
        await asyncio.sleep(interval)
        try:
            async with async_session_factory() as db:
                emu_cleaned = await EmulationService(db).cleanup_expired()
                fuzz_cleaned = await FuzzingService(db).cleanup_expired()
                if emu_cleaned or fuzz_cleaned:
                    await db.commit()
                    logger.info(
                        "Periodic cleanup stopped %d emulation session(s) and %d fuzzing campaign(s)",
                        emu_cleaned,
                        fuzz_cleaned,
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Periodic container cleanup sweep failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    os.makedirs(settings.storage_root, exist_ok=True)
    os.makedirs(settings.emulation_kernel_dir, exist_ok=True)
    cleanup_task = asyncio.create_task(
        _periodic_cleanup_loop(settings.cleanup_interval_seconds)
    )
    try:
        yield
    finally:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="FirmwareGuard",
    description="FirmwareGuard - AI-Assisted Firmware Reverse Engineering & Security Assessment",
    version="0.1.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if (
        request.method != "OPTIONS"
        and path.startswith("/api/v1/")
        and not path.startswith("/api/v1/auth/")
    ):
        if not is_authenticated(request.cookies, request.headers, request.query_params):
            return JSONResponse(status_code=401, content={"detail": "Authentication required"})
    return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(projects.router)
app.include_router(firmware.router)
app.include_router(files.router)
app.include_router(analysis.router)
app.include_router(secrets.router)
app.include_router(component_map.router)
app.include_router(findings.router)
app.include_router(documents.router)
app.include_router(sbom.router)
app.include_router(terminal.router)
app.include_router(emulation.router)
app.include_router(fuzzing.router)
app.include_router(kernels.router)
app.include_router(comparison.router)
app.include_router(export_import.router)
app.include_router(uart.router)


@app.exception_handler(PathTraversalError)
async def path_traversal_handler(request: Request, exc: PathTraversalError):
    return JSONResponse(status_code=403, content={"detail": str(exc)})


@app.get("/health")
async def health():
    return {"status": "ok"}
