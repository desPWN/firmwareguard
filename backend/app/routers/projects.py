import logging
import os
import shutil
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import get_settings
from app.database import get_db
from app.models.emulation_session import EmulationSession
from app.models.fuzzing import FuzzingCampaign
from app.models.project import Project
from app.schemas.project import (
    ProjectCreate,
    ProjectListResponse,
    ProjectResponse,
    ProjectUpdate,
)
from app.services.document_service import DocumentService
from app.services.emulation_service import EmulationService
from app.services.fuzzing_service import FuzzingService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/projects", tags=["projects"])

SCRATCHPAD_MD_TEMPLATE = """\
# Agent Scratchpad

This document is used by AI agents to persist analysis notes, progress, and context across sessions.
Agents will read this at the start of each session and update it as they work.

---

*No notes yet.*
"""

FIRMWAREGUARD_MD_TEMPLATE = """\
# FIRMWAREGUARD.md — Project Instructions

Add custom instructions, notes, or context here for the AI assistant.
The AI will read this file automatically at the start of each conversation.

## Examples of what to put here

- Project-specific analysis focus areas
- Known components or versions to investigate
- Custom credentials or default passwords to check
- Architecture notes or device information
- Links to related documentation or datasheets
"""


@router.post("", response_model=ProjectResponse, status_code=201)
async def create_project(data: ProjectCreate, db: AsyncSession = Depends(get_db)):
    project = Project(name=data.name, description=data.description)
    db.add(project)
    await db.flush()

    # Create default FIRMWAREGUARD.md note
    doc_svc = DocumentService(db)
    await doc_svc.create_note(
        project_id=project.id,
        title="FIRMWAREGUARD",
        content=FIRMWAREGUARD_MD_TEMPLATE,
    )

    # Create default SCRATCHPAD.md note
    await doc_svc.create_note(
        project_id=project.id,
        title="SCRATCHPAD",
        content=SCRATCHPAD_MD_TEMPLATE,
    )

    # Load firmware relationship (empty for new project)
    await db.refresh(project, ["firmware"])
    return project


@router.get("", response_model=list[ProjectListResponse])
async def list_projects(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).order_by(Project.created_at.desc()))
    return result.scalars().all()


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Project)
        .options(selectinload(Project.firmware))
        .where(Project.id == project_id)
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    return project


@router.patch("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: uuid.UUID, data: ProjectUpdate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Project)
        .options(selectinload(Project.firmware))
        .where(Project.id == project_id)
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(project, key, value)
    await db.flush()
    return project


@router.delete("/{project_id}", status_code=204)
async def delete_project(project_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    # Stop active emulation containers before removing DB rows
    emu_res = await db.execute(
        select(EmulationSession).where(
            EmulationSession.project_id == project_id,
            EmulationSession.status.in_(("starting", "running")),
        )
    )
    emu_svc = EmulationService(db)
    for session in emu_res.scalars().all():
        try:
            await emu_svc.stop_session(session.id)
        except Exception:
            logger.warning(
                "Failed to stop emulation session %s during project deletion",
                session.id,
                exc_info=True,
            )

    # Stop active fuzzing containers before removing DB rows
    fuzz_res = await db.execute(
        select(FuzzingCampaign).where(
            FuzzingCampaign.project_id == project_id,
            FuzzingCampaign.status.in_(("starting", "running")),
        )
    )
    fuzz_svc = FuzzingService(db)
    for campaign in fuzz_res.scalars().all():
        try:
            await fuzz_svc.stop_campaign(campaign.id)
        except Exception:
            logger.warning(
                "Failed to stop fuzzing campaign %s during project deletion",
                campaign.id,
                exc_info=True,
            )

    await db.delete(project)
    await db.flush()

    # Clean up project files on disk
    settings = get_settings()
    project_storage_dir = os.path.join(settings.storage_root, "projects", str(project_id))
    if os.path.isdir(project_storage_dir):
        shutil.rmtree(project_storage_dir, ignore_errors=True)
