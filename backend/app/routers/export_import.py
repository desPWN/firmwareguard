"""Project export and import endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import get_settings
from app.database import get_db
from app.models.project import Project
from app.schemas.project import ProjectResponse
from app.services.export_service import ExportService
from app.services.import_service import ImportService

router = APIRouter(
    prefix="/api/v1/projects",
    tags=["export-import"],
)


async def _get_project_or_404(project_id: uuid.UUID, db: AsyncSession) -> Project:
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    return project


@router.post("/{project_id}/export")
async def export_project(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Export a project as a .firmwareguard archive."""
    project = await _get_project_or_404(project_id, db)
    svc = ExportService(db)

    try:
        buf = await svc.export_project(project_id)
    except ValueError as e:
        raise HTTPException(400, str(e))

    safe_name = project.name.replace(" ", "_").replace("/", "_")
    filename = f"{safe_name}.firmwareguard"

    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.post("/import", response_model=ProjectResponse)
async def import_project(
    file: UploadFile,
    db: AsyncSession = Depends(get_db),
):
    """Import a .firmwareguard archive as a new project."""
    if not file.filename or not (
        file.filename.endswith(".firmwareguard")
        or file.filename.endswith(".zip")
    ):
        raise HTTPException(
            400,
            "Invalid file type. Please upload a .firmwareguard archive.",
        )

    settings = get_settings()
    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    chunks: list[bytes] = []
    total_bytes = 0
    while chunk := await file.read(65536):
        total_bytes += len(chunk)
        if total_bytes > max_bytes:
            raise HTTPException(
                413,
                f"Archive exceeds maximum upload size of {settings.max_upload_size_mb} MB",
            )
        chunks.append(chunk)

    contents = b"".join(chunks)
    if not contents:
        raise HTTPException(400, "Empty file")

    svc = ImportService(db)
    try:
        project = await svc.import_project(contents)
    except ValueError as e:
        raise HTTPException(400, str(e))

    # Flush to ensure all records are written, then reload with firmware relationship
    await db.flush()
    result = await db.execute(
        select(Project)
        .where(Project.id == project.id)
        .options(selectinload(Project.firmware))
    )
    return result.scalar_one()
