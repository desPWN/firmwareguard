"""Pydantic schemas for static binary hardening analysis and secrets harvesting."""

from __future__ import annotations

import uuid
from pydantic import BaseModel, ConfigDict, Field

# --- Secrets & Credential Harvester Schemas (Re-exported from app.schemas.secrets) ---
from app.schemas.secrets import (
    CertificateFinding,
    CertificateIssue,
    ExportSecretsFindingsRequest,
    ExportSecretsFindingsResponse,
    GenericSecretFinding,
    PrivateKeyFinding,
    RouterCredentialFinding,
    SecretCategory,
    SecretSeverity,
    SecretsHarvestResponse,
    SecretsHarvestSummary,
    SecretsSummary,
    ShadowAccountFinding,
)


class BinaryHardeningRecord(BaseModel):
    """Hardening posture and mitigations for a single ELF binary or shared library."""

    model_config = ConfigDict(from_attributes=True, extra="ignore")

    path: str
    filename: str
    binary_type: str = Field(description="'executable', 'shared_library', or 'other'")
    size: int
    architecture: str
    bits: int
    endianness: str
    nx: bool
    canary: bool
    pie: bool
    pie_status: str = Field(description="'Full PIE', 'DSO', or 'No PIE'")
    relro: str = Field(description="'full', 'partial', or 'none'")
    fortify: bool
    stripped: bool
    score: float


class HardeningSummary(BaseModel):
    """Aggregate checksec statistics across all binaries in the firmware."""

    model_config = ConfigDict(from_attributes=True, extra="ignore")

    total_binaries: int
    executable_count: int = 0
    library_count: int = 0
    nx_count: int = 0
    nx_percentage: float = 0.0
    canary_count: int = 0
    canary_percentage: float = 0.0
    pie_count: int = 0
    pie_percentage: float = 0.0
    full_relro_count: int = 0
    full_relro_percentage: float = 0.0
    partial_relro_count: int = 0
    no_relro_count: int = 0
    average_score: float = 0.0


class FirmwareHardeningResponse(BaseModel):
    """Top-level response payload for firmware checksec hardening audit."""

    model_config = ConfigDict(from_attributes=True, extra="ignore")

    firmware_id: uuid.UUID | str
    summary: HardeningSummary
    binaries: list[BinaryHardeningRecord] = Field(default_factory=list)
    cached: bool = False
    project_id: uuid.UUID | str | None = None


__all__ = [
    "BinaryHardeningRecord",
    "CertificateFinding",
    "CertificateIssue",
    "ExportSecretsFindingsRequest",
    "ExportSecretsFindingsResponse",
    "FirmwareHardeningResponse",
    "GenericSecretFinding",
    "HardeningSummary",
    "PrivateKeyFinding",
    "RouterCredentialFinding",
    "SecretCategory",
    "SecretSeverity",
    "SecretsHarvestResponse",
    "SecretsHarvestSummary",
    "SecretsSummary",
    "ShadowAccountFinding",
]
