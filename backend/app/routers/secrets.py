"""REST endpoints for hardcoded secrets, private keys, certificates, accounts, and router credentials."""

from __future__ import annotations

import asyncio
import logging
import os
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.analysis_cache import AnalysisCache
from app.models.finding import Finding
from app.models.firmware import Firmware
from app.models.project import Project
from app.schemas.secrets import (
    CertificateFinding,
    ExportSecretsFindingsRequest,
    ExportSecretsFindingsResponse,
    GenericSecretFinding,
    PrivateKeyFinding,
    RouterCredentialFinding,
    SecretsHarvestResponse,
    SecretsHarvestSummary,
    ShadowAccountFinding,
)
from app.services.firmware_service import FirmwareService
from app.services.secrets_service import SecretsService

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/secrets",
    tags=["secrets"],
)


async def _resolve_firmware(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID | None = Query(
        None, description="Specific firmware ID (defaults to latest unpacked)"
    ),
    db: AsyncSession = Depends(get_db),
) -> Firmware:
    """Resolve project and firmware.

    Verifies project exists (404).
    If firmware_id provided, verifies ownership (404) and unpack status (400).
    If firmware_id omitted, resolves latest unpacked firmware with non-null extracted_path.
    """
    proj_stmt = select(Project).where(Project.id == project_id)
    proj_res = await db.execute(proj_stmt)
    project = proj_res.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    svc = FirmwareService(db)

    if firmware_id:
        firmware = await svc.get_by_id(firmware_id)
        if not firmware or firmware.project_id != project_id:
            raise HTTPException(404, "Firmware not found")
        if not firmware.extracted_path or not os.path.isdir(firmware.extracted_path):
            raise HTTPException(400, "Firmware extraction has not completed")
        return firmware

    # Auto-resolve latest unpacked firmware
    stmt = (
        select(Firmware)
        .where(
            Firmware.project_id == project_id,
            Firmware.extracted_path.isnot(None),
        )
        .order_by(Firmware.created_at.desc())
        .limit(1)
    )
    res = await db.execute(stmt)
    firmware = res.scalar_one_or_none()
    if firmware:
        if not os.path.isdir(firmware.extracted_path):
            raise HTTPException(400, "Firmware extraction has not completed")
        return firmware

    # Check if any firmware was ever uploaded for this project
    any_fw = await svc.get_by_project(project_id)
    if not any_fw:
        raise HTTPException(404, "No firmware uploaded for this project")

    raise HTTPException(400, "Firmware extraction has not completed")


@router.get("", response_model=SecretsHarvestResponse)
@router.get("/", response_model=SecretsHarvestResponse, include_in_schema=False)
async def get_firmware_secrets(
    project_id: uuid.UUID,
    firmware: Firmware = Depends(_resolve_firmware),
    refresh: bool = Query(
        False, description="Bypass cache and force re-scanning of secrets"
    ),
    db: AsyncSession = Depends(get_db),
) -> SecretsHarvestResponse:
    """Harvest hardcoded secrets, private keys, certificates, password hashes, and router credentials.

    Caches results in analysis_cache with operation='secrets_harvest'.
    Uses refresh=true to re-scan the firmware rootfs.
    """
    cache_entry = None
    if not refresh:
        stmt = select(AnalysisCache).where(
            AnalysisCache.firmware_id == firmware.id,
            AnalysisCache.operation == "secrets_harvest",
        )
        res = await db.execute(stmt)
        cache_entry = res.scalar_one_or_none()
        if cache_entry and cache_entry.result:
            cached_data = cache_entry.result
            try:
                return SecretsHarvestResponse(
                    project_id=project_id,
                    firmware_id=firmware.id,
                    extracted_root=firmware.extracted_path,
                    summary=SecretsHarvestSummary.model_validate(
                        cached_data.get("summary", {})
                    ),
                    private_keys=[
                        PrivateKeyFinding.model_validate(k)
                        for k in cached_data.get("private_keys", [])
                    ],
                    certificates=[
                        CertificateFinding.model_validate(c)
                        for c in cached_data.get("certificates", [])
                    ],
                    accounts=[
                        ShadowAccountFinding.model_validate(a)
                        for a in cached_data.get("accounts", [])
                    ],
                    router_credentials=[
                        RouterCredentialFinding.model_validate(r)
                        for r in cached_data.get("router_credentials", [])
                    ],
                    generic_secrets=[
                        GenericSecretFinding.model_validate(g)
                        for g in cached_data.get("generic_secrets", [])
                    ],
                    cached=True,
                )
            except Exception as exc:
                logger.warning(
                    "Failed to deserialize cached secrets result for firmware %s: %s; re-harvesting",
                    firmware.id,
                    exc,
                )

    # Offload traversal and cryptographic parsing to thread pool
    loop = asyncio.get_running_loop()
    try:
        audit_data = await loop.run_in_executor(
            None,
            SecretsService.audit_firmware_secrets,
            firmware.extracted_path,
            str(project_id),
            str(firmware.id),
        )
    except Exception as exc:
        logger.error(
            "Secrets harvest failed for firmware %s: %s",
            firmware.id,
            exc,
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail=f"Secrets harvest failed: {exc}"
        )

    # Upsert in AnalysisCache table safely
    try:
        if not cache_entry:
            stmt = select(AnalysisCache).where(
                AnalysisCache.firmware_id == firmware.id,
                AnalysisCache.operation == "secrets_harvest",
            )
            cache_entry = (await db.execute(stmt)).scalar_one_or_none()

        if cache_entry:
            cache_entry.result = audit_data
            cache_entry.binary_path = "ROOTFS"
            cache_entry.binary_sha256 = firmware.sha256
        else:
            cache_entry = AnalysisCache(
                firmware_id=firmware.id,
                binary_path="ROOTFS",
                binary_sha256=firmware.sha256,
                operation="secrets_harvest",
                result=audit_data,
            )
            db.add(cache_entry)

        await db.commit()
    except Exception as exc:
        logger.warning(
            "Failed to save secrets harvest cache for firmware %s: %s",
            firmware.id,
            exc,
        )
        await db.rollback()

    return SecretsHarvestResponse(
        project_id=project_id,
        firmware_id=firmware.id,
        extracted_root=firmware.extracted_path,
        summary=SecretsHarvestSummary.model_validate(audit_data.get("summary", {})),
        private_keys=[
            PrivateKeyFinding.model_validate(k)
            for k in audit_data.get("private_keys", [])
        ],
        certificates=[
            CertificateFinding.model_validate(c)
            for c in audit_data.get("certificates", [])
        ],
        accounts=[
            ShadowAccountFinding.model_validate(a)
            for a in audit_data.get("accounts", [])
        ],
        router_credentials=[
            RouterCredentialFinding.model_validate(r)
            for r in audit_data.get("router_credentials", [])
        ],
        generic_secrets=[
            GenericSecretFinding.model_validate(g)
            for g in audit_data.get("generic_secrets", [])
        ],
        cached=False,
    )


@router.get("/summary", response_model=SecretsHarvestSummary)
async def get_firmware_secrets_summary(
    project_id: uuid.UUID,
    firmware: Firmware = Depends(_resolve_firmware),
    refresh: bool = Query(False),
    db: AsyncSession = Depends(get_db),
) -> SecretsHarvestSummary:
    """Retrieve summary KPIs for secrets and credentials."""
    harvest = await get_firmware_secrets(
        project_id=project_id,
        firmware=firmware,
        refresh=refresh,
        db=db,
    )
    return harvest.summary


@router.post("/export-findings", response_model=ExportSecretsFindingsResponse)
async def export_secrets_to_findings(
    project_id: uuid.UUID,
    payload: ExportSecretsFindingsRequest | None = None,
    firmware: Firmware = Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> ExportSecretsFindingsResponse:
    """Export discovered high and critical secrets directly to the project's Findings tracker."""
    loop = asyncio.get_running_loop()
    audit_data = await loop.run_in_executor(
        None,
        SecretsService.audit_firmware_secrets,
        firmware.extracted_path,
        str(project_id),
        str(firmware.id),
    )

    created_count = 0
    skipped_count = 0

    existing_stmt = select(Finding.title).where(Finding.project_id == project_id)
    existing_res = await db.execute(existing_stmt)
    existing_titles = set(existing_res.scalars().all())

    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    min_sev = payload.min_severity.value if payload else "high"
    min_rank = sev_rank.get(min_sev, 3)

    # Export private keys
    for k in audit_data.get("private_keys", []):
        sev = k.get("severity", "medium")
        if sev_rank.get(sev, 0) >= min_rank:
            title = f"Unencrypted Private Key: {k.get('path')}"
            if title in existing_titles:
                skipped_count += 1
                continue
            f = Finding(
                project_id=project_id,
                title=title,
                severity=sev,
                description=f"Discovered unencrypted {k.get('key_type')} private key in firmware filesystem.",
                evidence=k.get("preview"),
                file_path=k.get("path"),
                line_number=k.get("line_number", 1),
                source="secrets_harvester",
                status="open",
            )
            db.add(f)
            existing_titles.add(title)
            created_count += 1

    # Export accounts with empty or cracked passwords
    for a in audit_data.get("accounts", []):
        sev = a.get("severity", "info")
        if sev_rank.get(sev, 0) >= min_rank:
            cracked = a.get("cracked_password")
            status_text = (
                f"Cracked password '{cracked}'"
                if cracked
                else "Empty password / UID 0 backdoor"
            )
            title = f"Vulnerable Account '{a.get('username')}': {status_text}"
            if title in existing_titles:
                skipped_count += 1
                continue
            f = Finding(
                project_id=project_id,
                title=title,
                severity=sev,
                description=f"Account '{a.get('username')}' in {a.get('source_file')} has {status_text}.",
                evidence=f"Hash: {a.get('hash_value')}\nCracked: {cracked}",
                file_path=a.get("source_file"),
                line_number=a.get("line_number", 1),
                source="secrets_harvester",
                status="open",
            )
            db.add(f)
            existing_titles.add(title)
            created_count += 1

    # Export router default credentials
    for r in audit_data.get("router_credentials", []):
        sev = r.get("severity", "critical")
        if sev_rank.get(sev, 0) < min_rank:
            continue
        title = f"Default Credential ({r.get('service')}): {r.get('matched_rule')}"
        if title in existing_titles:
            skipped_count += 1
            continue
        f = Finding(
            project_id=project_id,
            title=title,
            severity=sev,
            description=f"Hardcoded service credential found in {r.get('source_file')}.",
            evidence=f"User: {r.get('username')}\nPass: {r.get('password')}",
            file_path=r.get("source_file"),
            line_number=r.get("line_number"),
            source="secrets_harvester",
            status="open",
        )
        db.add(f)
        existing_titles.add(title)
        created_count += 1

    # Export hardcoded API tokens & high-entropy generic secrets
    for g in audit_data.get("generic_secrets", []):
        sev = g.get("severity", "high")
        if sev_rank.get(sev, 0) < min_rank:
            continue
        title = f"Hardcoded Secret ({g.get('category')}): {g.get('path')}:{g.get('line_number')}"
        if title in existing_titles:
            skipped_count += 1
            continue
        f = Finding(
            project_id=project_id,
            title=title,
            severity=sev,
            description=(
                f"Detected {g.get('category')} secret (Shannon entropy {g.get('entropy')}) "
                f"in {g.get('path')}."
            ),
            evidence=g.get("match_text"),
            file_path=g.get("path"),
            line_number=g.get("line_number", 1),
            source="secrets_harvester",
            status="open",
        )
        db.add(f)
        existing_titles.add(title)
        created_count += 1

    if created_count > 0:
        await db.commit()

    return ExportSecretsFindingsResponse(
        created_count=created_count,
        skipped_count=skipped_count,
        message=f"Exported {created_count} findings to project tracker ({skipped_count} duplicates skipped).",
    )
