import asyncio
import logging
import os
import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory, get_db
from app.models.firmware import Firmware
from app.models.project import Project
from app.schemas.firmware import (
    EntropyBlockResponse,
    FirmwareDecryptRequest,
    FirmwareDecryptResponse,
    FirmwareDetailResponse,
    FirmwareEntropyResponse,
    FirmwareMetadataResponse,
    FirmwareUpdate,
    FirmwareUploadResponse,
)
from app.services.decryption_service import (
    analyze_encryption,
    auto_decrypt_if_known,
    decrypt_custom,
)
from app.services.firmware_metadata_service import FirmwareMetadataService
from app.services.firmware_service import FirmwareService, UploadSizeLimitError
from app.workers.unpack import detect_kernel, unpack_firmware

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/projects/{project_id}/firmware", tags=["firmware"])


def get_firmware_service(db: AsyncSession = Depends(get_db)) -> FirmwareService:
    return FirmwareService(db)


@router.post("", response_model=FirmwareUploadResponse, status_code=201)
async def upload_firmware(
    project_id: uuid.UUID,
    file: UploadFile,
    version_label: str | None = Form(None),
    service: FirmwareService = Depends(get_firmware_service),
):
    try:
        firmware = await service.upload(project_id, file, version_label=version_label)
    except UploadSizeLimitError as exc:
        raise HTTPException(413, str(exc))
    return firmware


@router.get("", response_model=list[FirmwareDetailResponse])
async def list_firmware(
    project_id: uuid.UUID,
    service: FirmwareService = Depends(get_firmware_service),
):
    return await service.list_by_project(project_id)


@router.get("/{firmware_id}", response_model=FirmwareDetailResponse)
async def get_single_firmware(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    service: FirmwareService = Depends(get_firmware_service),
):
    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")
    return firmware


@router.patch("/{firmware_id}", response_model=FirmwareDetailResponse)
async def update_firmware(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    data: FirmwareUpdate,
    service: FirmwareService = Depends(get_firmware_service),
):
    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")
    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(firmware, key, value)
    await service.db.flush()
    return firmware


@router.delete("/{firmware_id}", status_code=204)
async def delete_firmware(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")
    await service.delete(firmware)


@router.post("/{firmware_id}/unpack", response_model=FirmwareDetailResponse, status_code=202)
async def unpack(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    # Get project and firmware
    proj_result = await db.execute(select(Project).where(Project.id == project_id))
    project = proj_result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")

    if firmware.extracted_path:
        raise HTTPException(409, "Firmware already unpacked")

    if project.status == "unpacking":
        raise HTTPException(409, "Firmware is already being unpacked")

    # Update status to unpacking
    project.status = "unpacking"
    await db.flush()

    # Launch background task (uses its own DB session)
    asyncio.create_task(
        _run_unpack_background(project_id, firmware_id, firmware.storage_path)
    )

    return firmware


async def _run_unpack_background(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    storage_path: str,
    output_base: str | None = None,
) -> None:
    """Run firmware unpacking in the background with its own DB session."""
    try:
        resolved_base = output_base or os.path.dirname(storage_path)
        result = await unpack_firmware(storage_path, resolved_base)

        async with async_session_factory() as db:
            try:
                proj_result = await db.execute(
                    select(Project).where(Project.id == project_id)
                )
                project = proj_result.scalar_one_or_none()
                fw_result = await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
                firmware = fw_result.scalar_one_or_none()

                if not project or not firmware:
                    logger.error("Background unpack: project or firmware not found")
                    return

                if result.success:
                    firmware.extracted_path = result.extracted_path
                    firmware.extraction_dir = result.extraction_dir
                    firmware.architecture = result.architecture
                    firmware.endianness = result.endianness
                    firmware.os_info = result.os_info
                    firmware.kernel_path = result.kernel_path
                    firmware.unpack_log = result.unpack_log
                    project.status = "ready"
                else:
                    firmware.unpack_log = result.unpack_log
                    project.status = "error"

                await db.commit()
            except Exception:
                await db.rollback()
                raise
    except Exception:
        logger.exception("Background firmware unpack failed for firmware %s", firmware_id)
        # Try to set error status
        try:
            async with async_session_factory() as db:
                try:
                    proj_result = await db.execute(
                        select(Project).where(Project.id == project_id)
                    )
                    project = proj_result.scalar_one_or_none()
                    if project:
                        project.status = "error"
                    await db.commit()
                except Exception:
                    await db.rollback()
        except Exception:
            logger.exception("Failed to set error status for project %s", project_id)


@router.post("/{firmware_id}/redetect-kernel", response_model=FirmwareDetailResponse)
async def redetect_kernel(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    """Re-run kernel detection on already-extracted firmware."""
    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")

    if not firmware.extracted_path:
        raise HTTPException(400, "Firmware has not been unpacked yet")

    extraction_dir = os.path.dirname(firmware.extracted_path)
    firmware.kernel_path = detect_kernel(extraction_dir, firmware.extracted_path)
    await db.flush()

    return firmware


@router.get("/{firmware_id}/metadata", response_model=FirmwareMetadataResponse)
async def get_firmware_metadata(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    """Get structural metadata for a firmware image (partitions, U-Boot, MTD)."""
    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")
    if not firmware.storage_path:
        raise HTTPException(400, "Firmware file not available")

    metadata_service = FirmwareMetadataService()
    metadata = await metadata_service.scan_firmware_image(
        firmware.storage_path, firmware.id, db,
    )
    return metadata


@router.get("/{firmware_id}/entropy", response_model=FirmwareEntropyResponse)
async def get_firmware_entropy(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    service: FirmwareService = Depends(get_firmware_service),
):
    """Analyze Shannon entropy, detect vendor encryption headers, and diagnose unpack failures."""
    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")
    if not firmware.storage_path or not os.path.isfile(firmware.storage_path):
        raise HTTPException(400, "Firmware file not available on disk")

    analysis = await asyncio.to_thread(analyze_encryption, firmware.storage_path)
    return FirmwareEntropyResponse(
        file_size=analysis.file_size,
        overall_entropy=analysis.overall_entropy,
        min_entropy=analysis.min_entropy,
        max_entropy=analysis.max_entropy,
        high_entropy_ratio=analysis.high_entropy_ratio,
        verdict=analysis.verdict,
        detected_format=analysis.detected_format,
        detected_format_label=analysis.detected_format_label,
        known_signatures=analysis.known_signatures,
        summary=analysis.summary,
        blocks=[
            EntropyBlockResponse(offset=b.offset, size=b.size, entropy=b.entropy)
            for b in analysis.blocks
        ],
    )


@router.post("/{firmware_id}/decrypt", response_model=FirmwareDecryptResponse)
async def decrypt_firmware(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    body: FirmwareDecryptRequest,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    """Decrypt a firmware image using a known vendor decryptor or custom key/IV, optionally unpacking it."""
    proj_result = await db.execute(select(Project).where(Project.id == project_id))
    project = proj_result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")
    if not firmware.storage_path or not os.path.isfile(firmware.storage_path):
        raise HTTPException(400, "Firmware file not available on disk")

    if project.status == "unpacking":
        raise HTTPException(409, "Firmware is already being unpacked")

    output_base = os.path.dirname(firmware.storage_path)
    dec_dir = os.path.join(output_base, "decrypted")

    try:
        if body.mode == "auto":
            dec_res = await asyncio.to_thread(auto_decrypt_if_known, firmware.storage_path, dec_dir)
            if not dec_res:
                raise HTTPException(
                    400,
                    "No built-in vendor decryptor matched this image header. Use custom key/IV mode.",
                )
        elif body.mode == "custom":
            dec_res = await asyncio.to_thread(
                decrypt_custom,
                firmware.storage_path,
                dec_dir,
                algorithm=body.algorithm,
                key=body.key,
                key_format=body.key_format,
                iv=body.iv,
                offset=body.offset,
                unpad=body.unpad,
            )
        else:
            raise HTTPException(400, f"Invalid decryption mode: {body.mode}")
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        logger.exception("Firmware decryption failed for %s", firmware_id)
        raise HTTPException(500, f"Decryption failed: {exc}")

    unpack_started = False
    if body.auto_unpack:
        firmware.extracted_path = None
        firmware.extraction_dir = None
        firmware.unpack_log = f"[firmwareguard] {dec_res.message}\nStarting binwalk extraction...\n"
        project.status = "unpacking"
        await db.flush()
        asyncio.create_task(
            _run_unpack_background(
                project_id, firmware_id, dec_res.output_path, output_base=output_base
            )
        )
        unpack_started = True

    return FirmwareDecryptResponse(
        success=dec_res.success,
        method=dec_res.method,
        output_size=dec_res.output_size,
        post_entropy=dec_res.post_entropy,
        known_signatures=dec_res.known_signatures,
        unpack_started=unpack_started,
        message=dec_res.message,
    )


# ── Backward-compatible endpoints (no firmware_id in path) ──
# These use the first/only firmware for the project, preserving existing behavior.


@router.post("/unpack", response_model=FirmwareDetailResponse, status_code=202, deprecated=True)
async def unpack_legacy(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    """Legacy unpack endpoint — uses first firmware for the project."""
    firmware = await service.get_by_project(project_id)
    if not firmware:
        raise HTTPException(404, "No firmware uploaded for this project")

    return await unpack(project_id, firmware.id, db, service)


@router.post("/redetect-kernel", response_model=FirmwareDetailResponse, deprecated=True)
async def redetect_kernel_legacy(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    """Legacy redetect-kernel endpoint — uses first firmware for the project."""
    firmware = await service.get_by_project(project_id)
    if not firmware:
        raise HTTPException(404, "No firmware uploaded for this project")

    return await redetect_kernel(project_id, firmware.id, db, service)
