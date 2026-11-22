"""REST endpoints for binary analysis: functions, disassembly, decompilation, protections."""

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
from app.schemas.analysis import (
    BinaryHardeningRecord,
    CertificateFinding,
    ExportSecretsFindingsRequest,
    ExportSecretsFindingsResponse,
    FirmwareHardeningResponse,
    GenericSecretFinding,
    HardeningSummary,
    PrivateKeyFinding,
    RouterCredentialFinding,
    SecretsHarvestResponse,
    SecretsHarvestSummary,
    ShadowAccountFinding,
)
from app.services.analysis_service import (
    audit_firmware_hardening,
    check_binary_protections,
)
from app.services.secrets_service import audit_firmware_secrets
from app.services.file_service import FileService
from app.services.firmware_service import FirmwareService
from app.services.ghidra_service import (
    decompile_function as ghidra_decompile,
    get_analysis_cache,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/analysis",
    tags=["analysis"],
)


async def _resolve_firmware(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID | None = Query(
        None, description="Specific firmware ID (defaults to latest unpacked)"
    ),
    db: AsyncSession = Depends(get_db),
) -> Firmware:
    """Resolve project -> firmware.

    If firmware_id is provided, verify it belongs to project and is unpacked.
    If omitted, resolve the most recently created unpacked firmware with a non-null extracted_path.
    """
    svc = FirmwareService(db)

    if firmware_id:
        firmware = await svc.get_by_id(firmware_id)
        if not firmware or firmware.project_id != project_id:
            raise HTTPException(404, "Firmware not found")
        if not firmware.extracted_path:
            raise HTTPException(400, "Firmware not yet unpacked")
        return firmware

    # Resolve latest unpacked firmware
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
        return firmware

    # Fallback check: check if any firmware exists for project to return proper error code
    any_fw = await svc.get_by_project(project_id)
    if not any_fw:
        raise HTTPException(404, "No firmware uploaded for this project")

    raise HTTPException(400, "Firmware not yet unpacked")


def _resolve_path(firmware, path: str) -> str:
    """Resolve a virtual firmware path using FileService.

    Handles virtual prefixes like /rootfs/ that the file explorer adds,
    so analysis endpoints work consistently with the file browser.
    """
    svc = FileService(firmware.extracted_path, extraction_dir=firmware.extraction_dir)
    return svc._resolve(path)


@router.get("/functions")
async def list_functions(
    path: str = Query(..., description="Path to ELF binary in firmware filesystem"),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """List functions found in an ELF binary, sorted by size (largest first)."""
    try:
        full_path = _resolve_path(firmware, path)
    except Exception:
        raise HTTPException(403, "Invalid path")

    cache = get_analysis_cache()
    try:
        functions = await cache.get_functions(full_path, firmware.id, db)
    except TimeoutError:
        raise HTTPException(504, "Binary analysis timed out")
    except Exception as e:
        raise HTTPException(400, f"Failed to analyze binary: {e}")

    return {
        "binary_path": path,
        "functions": [
            {
                "name": fn.get("name", "unknown"),
                "offset": fn.get("address", "0"),
                "size": fn.get("size", 0),
            }
            for fn in functions
        ],
    }


@router.get("/imports")
async def list_imports(
    path: str = Query(..., description="Path to ELF binary in firmware filesystem"),
    firmware=Depends(_resolve_firmware),
):
    """List imported symbols with their source library.

    Uses pyelftools to parse DT_NEEDED + .dynsym, then cross-references
    each undefined symbol against library exports to determine which
    function comes from which library.
    """
    try:
        full_path = _resolve_path(firmware, path)
    except Exception:
        raise HTTPException(403, "Invalid path")

    extracted_root = firmware.extracted_path
    loop = asyncio.get_event_loop()
    imports = await loop.run_in_executor(
        None, _resolve_elf_imports, full_path, extracted_root
    )

    return {
        "binary_path": path,
        "imports": imports,
    }


def _resolve_elf_imports(binary_path: str, extracted_root: str) -> list[dict]:
    """Parse ELF imports and resolve each to its source library.

    For each needed library, reads its exports and cross-references
    with the binary's undefined symbols.
    """
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    STANDARD_LIB_PATHS = [
        "/lib", "/usr/lib", "/lib64", "/usr/lib64",
    ]

    try:
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)

            # 1. Get DT_NEEDED libraries and rpath
            needed_libs: list[str] = []
            search_paths: list[str] = []
            for seg in elf.iter_segments():
                if seg.header.p_type == "PT_DYNAMIC":
                    for tag in seg.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            needed_libs.append(tag.needed)
                        elif tag.entry.d_tag in ("DT_RPATH", "DT_RUNPATH"):
                            rp = tag.runpath if hasattr(tag, "runpath") else tag.rpath
                            search_paths.extend(rp.split(":"))
                    break
            search_paths.extend(STANDARD_LIB_PATHS)

            # 2. Get undefined symbols (what this binary imports)
            undefined_syms: set[str] = set()
            dynsym = elf.get_section_by_name(".dynsym")
            if dynsym and isinstance(dynsym, SymbolTableSection):
                for sym in dynsym.iter_symbols():
                    if (sym.entry.st_shndx == "SHN_UNDEF"
                            and sym.name
                            and sym.entry.st_info.type in ("STT_FUNC", "STT_NOTYPE")):
                        undefined_syms.add(sym.name)

            if not undefined_syms or not needed_libs:
                return []

    except Exception as exc:
        logger.debug("Failed to parse ELF for imports: %s", exc)
        return []

    # 3. For each needed library, resolve its path and get its exports
    #    to determine which functions come from it
    func_to_lib: dict[str, str] = {}

    for lib_name in needed_libs:
        lib_abs = _find_library(extracted_root, lib_name, search_paths)
        if not lib_abs:
            continue

        try:
            lib_exports: set[str] = set()
            with open(lib_abs, "rb") as lf:
                lib_elf = ELFFile(lf)
                lib_dynsym = lib_elf.get_section_by_name(".dynsym")
                if lib_dynsym and isinstance(lib_dynsym, SymbolTableSection):
                    for sym in lib_dynsym.iter_symbols():
                        if (sym.entry.st_shndx != "SHN_UNDEF"
                                and sym.name
                                and sym.entry.st_info.type in ("STT_FUNC", "STT_GNU_IFUNC")):
                            lib_exports.add(sym.name)

            for sym_name in undefined_syms & lib_exports:
                if sym_name not in func_to_lib:
                    func_to_lib[sym_name] = lib_name
        except Exception:
            continue

    # 4. Build result
    results: list[dict] = []
    for sym_name, lib_name in func_to_lib.items():
        results.append({"name": sym_name, "libname": lib_name})

    # Also include unresolved imports (no library found)
    for sym_name in undefined_syms - func_to_lib.keys():
        results.append({"name": sym_name, "libname": None})

    return results


def _find_library(extracted_root: str, lib_name: str, search_paths: list[str]) -> str | None:
    """Resolve a library name to an absolute path within the extracted firmware."""
    import os

    for search_dir in search_paths:
        candidate = os.path.join(extracted_root, search_dir.lstrip("/"), lib_name)
        # Follow symlinks
        real = os.path.realpath(candidate)
        if os.path.isfile(real) and real.startswith(os.path.realpath(extracted_root)):
            return real

    return None


@router.get("/disasm")
async def disassemble_function(
    path: str = Query(..., description="Path to ELF binary"),
    function: str = Query(..., description="Function name to disassemble"),
    max_instructions: int = Query(100, ge=1, le=200),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Disassemble a function from an ELF binary."""
    try:
        full_path = _resolve_path(firmware, path)
    except Exception:
        raise HTTPException(403, "Invalid path")

    cache = get_analysis_cache()
    try:
        disasm = await cache.get_disassembly(
            full_path, function, firmware.id, db, max_instructions,
        )
    except TimeoutError:
        raise HTTPException(504, "Binary analysis timed out")
    except Exception as e:
        raise HTTPException(400, f"Failed to analyze binary: {e}")

    return {
        "binary_path": path,
        "function": function,
        "disassembly": disasm,
    }


@router.get("/binary-info")
async def get_binary_info(
    path: str = Query(..., description="Path to ELF binary"),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Get binary metadata and security protections."""
    try:
        full_path = _resolve_path(firmware, path)
    except Exception:
        raise HTTPException(403, "Invalid path")

    cache = get_analysis_cache()
    try:
        info = await cache.get_binary_info(full_path, firmware.id, db)
    except TimeoutError:
        raise HTTPException(504, "Binary analysis timed out")
    except Exception as e:
        raise HTTPException(400, f"Failed to analyze binary: {e}")

    protections = check_binary_protections(full_path)

    return {
        "binary_path": path,
        "info": info,
        "protections": protections,
    }


@router.get("/cleaned-code")
async def get_cleaned_code(
    path: str = Query(..., description="Path to ELF binary"),
    function: str = Query(..., description="Function name"),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Check if AI-cleaned decompiled code exists for a function."""
    try:
        full_path = _resolve_path(firmware, path)
    except Exception:
        raise HTTPException(403, "Invalid path")

    cache = get_analysis_cache()
    binary_sha256 = await cache.get_binary_sha256(full_path)
    operation = f"code_cleanup:{function}"
    cached = await cache.get_cached(firmware.id, binary_sha256, operation, db)

    if cached and cached.get("cleaned_code"):
        return {"available": True, "cleaned_code": cached["cleaned_code"]}
    return {"available": False, "cleaned_code": None}


@router.get("/decompile")
async def decompile_function(
    path: str = Query(..., description="Path to ELF binary"),
    function: str = Query(..., description="Function name to decompile"),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Decompile a function from an ELF binary using Ghidra headless."""
    try:
        full_path = _resolve_path(firmware, path)
    except Exception:
        raise HTTPException(403, "Invalid path")

    try:
        decompiled = await ghidra_decompile(full_path, function, firmware.id, db)
    except FileNotFoundError:
        raise HTTPException(404, f"Binary not found: {path}")
    except TimeoutError as e:
        raise HTTPException(504, str(e))
    except RuntimeError as e:
        raise HTTPException(400, str(e))

    return {
        "binary_path": path,
        "function": function,
        "decompiled_code": decompiled,
    }


@router.get("/hardening", response_model=FirmwareHardeningResponse)
async def get_firmware_hardening(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID | None = Query(
        None, description="Specific firmware ID (defaults to latest unpacked)"
    ),
    refresh: bool = Query(
        False, description="Bypass cache and force re-scan"
    ),
    firmware: Firmware = Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> FirmwareHardeningResponse:
    """Audit security hardening mitigations (NX, Canary, PIE, RELRO) for all binaries in firmware.

    Results are cached in analysis_cache under operation='binary_hardening'.
    Use refresh=true to bypass cache and rescan.
    """
    if not firmware.extracted_path or not os.path.isdir(firmware.extracted_path):
        raise HTTPException(
            status_code=404,
            detail=f"Extracted firmware directory not found on disk: {firmware.extracted_path}",
        )

    cache_entry = None
    if not refresh:
        stmt = select(AnalysisCache).where(
            AnalysisCache.firmware_id == firmware.id,
            AnalysisCache.operation == "binary_hardening",
        )
        res = await db.execute(stmt)
        cache_entry = res.scalar_one_or_none()
        if cache_entry and cache_entry.result:
            cached_data = cache_entry.result
            try:
                return FirmwareHardeningResponse(
                    firmware_id=firmware.id,
                    project_id=project_id,
                    summary=HardeningSummary.model_validate(cached_data.get("summary", {})),
                    binaries=[
                        BinaryHardeningRecord.model_validate(b)
                        for b in cached_data.get("binaries", [])
                    ],
                    cached=True,
                )
            except Exception as exc:
                logger.warning(
                    "Failed to deserialize cached hardening result for firmware %s: %s; re-auditing",
                    firmware.id,
                    exc,
                )

    loop = asyncio.get_running_loop()
    try:
        audit_data = await loop.run_in_executor(
            None,
            audit_firmware_hardening,
            firmware.extracted_path,
        )
    except Exception as exc:
        logger.error(
            "Binary hardening audit failed for firmware %s: %s",
            firmware.id,
            exc,
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail=f"Binary hardening audit failed: {exc}"
        )

    cache_payload = {
        "summary": audit_data.get("summary", {}),
        "binaries": audit_data.get("binaries", []),
    }

    if not cache_entry:
        stmt = select(AnalysisCache).where(
            AnalysisCache.firmware_id == firmware.id,
            AnalysisCache.operation == "binary_hardening",
        )
        cache_entry = (await db.execute(stmt)).scalar_one_or_none()

    if cache_entry:
        cache_entry.result = cache_payload
        cache_entry.binary_path = "ROOTFS"
        cache_entry.binary_sha256 = firmware.sha256
    else:
        cache_entry = AnalysisCache(
            firmware_id=firmware.id,
            binary_path="ROOTFS",
            binary_sha256=firmware.sha256,
            operation="binary_hardening",
            result=cache_payload,
        )
        db.add(cache_entry)

    await db.commit()

    return FirmwareHardeningResponse(
        firmware_id=firmware.id,
        project_id=project_id,
        summary=HardeningSummary.model_validate(audit_data.get("summary", {})),
        binaries=[
            BinaryHardeningRecord.model_validate(b)
            for b in audit_data.get("binaries", [])
        ],
        cached=False,
    )


@router.get("/secrets", response_model=SecretsHarvestResponse)
async def get_firmware_secrets(
    project_id: uuid.UUID,
    firmware: Firmware = Depends(_resolve_firmware),
    refresh: bool = Query(
        False, description="Bypass cache and force re-scanning of secrets"
    ),
    db: AsyncSession = Depends(get_db),
) -> SecretsHarvestResponse:
    """Harvest hardcoded secrets, private keys, certificates, password hashes, and router credentials.

    Results are cached in analysis_cache under operation='secrets_harvest'.
    Use refresh=true to re-scan the firmware filesystem.
    """
    if not firmware.extracted_path or not os.path.isdir(firmware.extracted_path):
        raise HTTPException(
            status_code=404,
            detail=f"Extracted firmware directory not found on disk: {firmware.extracted_path}",
        )

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

    loop = asyncio.get_running_loop()
    try:
        audit_data = await loop.run_in_executor(
            None,
            audit_firmware_secrets,
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


@router.post("/secrets/export-findings", response_model=ExportSecretsFindingsResponse)
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
        audit_firmware_secrets,
        firmware.extracted_path,
        str(project_id),
        str(firmware.id),
    )

    created_count = 0
    skipped_count = 0

    # Query existing finding titles for project to prevent duplicates
    existing_stmt = select(Finding.title).where(Finding.project_id == project_id)
    existing_res = await db.execute(existing_stmt)
    existing_titles = set(existing_res.scalars().all())

    # Export private keys
    for k in audit_data.get("private_keys", []):
        sev = k.get("severity", "medium")
        if sev in ("critical", "high"):
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

    # Export accounts with empty passwords or cracked passwords
    for a in audit_data.get("accounts", []):
        sev = a.get("severity", "info")
        if sev in ("critical", "high"):
            cracked = a.get("cracked_password")
            status_text = f"Cracked password '{cracked}'" if cracked else "Empty password / UID 0 backdoor"
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
        title = f"Default Credential ({r.get('service')}): {r.get('matched_rule')}"
        if title in existing_titles:
            skipped_count += 1
            continue
        f = Finding(
            project_id=project_id,
            title=title,
            severity=r.get("severity", "critical"),
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

    if created_count > 0:
        await db.commit()

    return ExportSecretsFindingsResponse(
        created_count=created_count,
        skipped_count=skipped_count,
        message=f"Exported {created_count} findings to project tracker ({skipped_count} duplicates skipped).",
    )
