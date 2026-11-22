import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.analysis_cache import AnalysisCache
from app.models.project import Project
from app.models.sbom import SbomComponent, SbomVulnerability
from app.schemas.finding import FindingCreate, FindingResponse, FindingUpdate
from app.services.finding_service import FindingService
from app.services.firmware_service import FirmwareService
from app.services.report_service import (
    SEVERITY_ORDER,
    generate_markdown_report,
    generate_pdf_report,
)

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/findings",
    tags=["findings"],
)


async def _get_project_or_404(project_id: uuid.UUID, db: AsyncSession) -> Project:
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    return project


@router.post("", response_model=FindingResponse, status_code=201)
async def create_finding(
    project_id: uuid.UUID,
    data: FindingCreate,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = FindingService(db)
    finding = await svc.create(project_id, data)
    return finding


@router.get("", response_model=list[FindingResponse])
async def list_findings(
    project_id: uuid.UUID,
    severity: str | None = Query(None),
    status: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = FindingService(db)
    return await svc.list_by_project(project_id, severity=severity, status=status)


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    project_id: uuid.UUID,
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = FindingService(db)
    finding = await svc.get(finding_id)
    if not finding or finding.project_id != project_id:
        raise HTTPException(404, "Finding not found")
    return finding


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    project_id: uuid.UUID,
    finding_id: uuid.UUID,
    data: FindingUpdate,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = FindingService(db)
    # Verify finding belongs to this project
    existing = await svc.get(finding_id)
    if not existing or existing.project_id != project_id:
        raise HTTPException(404, "Finding not found")
    finding = await svc.update(finding_id, data)
    return finding


@router.delete("/{finding_id}", status_code=204)
async def delete_finding(
    project_id: uuid.UUID,
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = FindingService(db)
    existing = await svc.get(finding_id)
    if not existing or existing.project_id != project_id:
        raise HTTPException(404, "Finding not found")
    await svc.delete(finding_id)


@router.post("/export")
async def export_findings(
    project_id: uuid.UUID,
    format: str = Query("markdown", pattern="^(markdown|pdf)$"),
    db: AsyncSession = Depends(get_db),
):
    project = await _get_project_or_404(project_id, db)

    # Resolve latest unpacked firmware consistently
    firmware = await FirmwareService(db).get_by_project(project_id)

    # Load findings
    svc = FindingService(db)
    findings = await svc.list_by_project(project_id)

    # Load cached hardening, secrets, and SBOM/CVE telemetry for the report
    hardening_data = None
    secrets_data = None
    sbom_summary = None
    if firmware:
        cache_res = await db.execute(
            select(AnalysisCache).where(
                AnalysisCache.firmware_id == firmware.id,
                AnalysisCache.operation.in_(("binary_hardening", "secrets_harvest")),
            )
        )
        for entry in cache_res.scalars().all():
            if entry.operation == "binary_hardening" and entry.result:
                hardening_data = entry.result
            elif entry.operation == "secrets_harvest" and entry.result:
                secrets_data = entry.result

        comp_res = await db.execute(
            select(SbomComponent).where(SbomComponent.firmware_id == firmware.id)
        )
        components = list(comp_res.scalars().all())
        if components:
            comp_map = {c.id: c for c in components}
            vuln_res = await db.execute(
                select(SbomVulnerability).where(SbomVulnerability.firmware_id == firmware.id)
            )
            vulns = list(vuln_res.scalars().all())
            sev_counts: dict[str, int] = {}
            vuln_rows = []
            for v in vulns:
                eff_sev = (v.adjusted_severity or v.severity or "info").lower()
                sev_counts[eff_sev] = sev_counts.get(eff_sev, 0) + 1
                comp = comp_map.get(v.component_id)
                eff_score = v.adjusted_cvss_score if v.adjusted_cvss_score is not None else v.cvss_score
                vuln_rows.append(
                    {
                        "cve_id": v.cve_id,
                        "component_name": comp.name if comp else "unknown",
                        "component_version": comp.version if comp else None,
                        "severity": eff_sev,
                        "cvss_score": float(eff_score) if eff_score is not None else None,
                        "resolution_status": v.resolution_status,
                    }
                )
            vuln_rows.sort(
                key=lambda item: (
                    SEVERITY_ORDER.get(item["severity"], 99),
                    -(item["cvss_score"] or 0.0),
                    item["cve_id"],
                )
            )
            sbom_summary = {
                "total_components": len(components),
                "total_vulnerabilities": len(vulns),
                "severity_counts": sev_counts,
                "top_vulnerabilities": vuln_rows[:15],
            }

    safe_name = project.name.replace(" ", "_")

    if format == "pdf":
        pdf_bytes = generate_pdf_report(
            project,
            firmware,
            findings,
            hardening=hardening_data,
            secrets=secrets_data,
            sbom_summary=sbom_summary,
        )
        filename = f"{safe_name}_security_report.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    md = generate_markdown_report(
        project,
        firmware,
        findings,
        hardening=hardening_data,
        secrets=secrets_data,
        sbom_summary=sbom_summary,
    )
    filename = f"{safe_name}_security_report.md"
    return Response(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
