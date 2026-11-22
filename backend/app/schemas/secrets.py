"""Pydantic v2 models for FirmwareGuard Hardcoded Secrets & Credential Harvester."""

from __future__ import annotations

import uuid
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field


class SecretSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecretCategory(str, Enum):
    PRIVATE_KEY = "private_key"
    CERTIFICATE = "certificate"
    SHADOW_ACCOUNT = "shadow_account"
    PASSWD_ACCOUNT = "passwd_account"
    ROUTER_DEFAULT = "router_default"
    NVRAM_CREDENTIAL = "nvram_credential"
    API_TOKEN = "api_token"
    CONFIG_CREDENTIAL = "config_credential"


class PrivateKeyFinding(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="ignore")

    path: str
    key_type: str
    encrypted: bool
    format: str
    preview: str
    severity: SecretSeverity
    line_number: int | None = None


class CertificateIssue(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="ignore")

    severity: SecretSeverity
    issue: str


class CertificateFinding(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="ignore")

    path: str
    subject: str
    issuer: str
    not_before: str
    not_after: str
    serial: str
    key_type: str
    key_size: int
    signature_algorithm: str
    self_signed: bool
    sans: list[str] = Field(default_factory=list)
    wildcard: bool = False
    is_expired: bool = False
    is_not_yet_valid: bool = False
    issues: list[CertificateIssue] = Field(default_factory=list)


class ShadowAccountFinding(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="ignore")

    username: str
    uid: int | None = None
    gid: int | None = None
    shell: str | None = None
    home_dir: str | None = None
    status: str
    hash_type: str
    hash_strength: str
    hash_value: str | None = None
    salt: str | None = None
    cracked_password: str | None = None
    source_file: str
    line_number: int
    severity: SecretSeverity


class RouterCredentialFinding(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="ignore")

    service: str
    username: str | None = None
    password: str | None = None
    source_file: str
    line_number: int | None = None
    matched_rule: str
    severity: SecretSeverity


class GenericSecretFinding(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="ignore")

    path: str
    line_number: int
    category: str
    match_text: str
    entropy: float
    severity: SecretSeverity


class SecretsHarvestSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="ignore")

    total_findings: int = 0
    total_private_keys: int = 0
    unencrypted_private_keys: int = 0
    total_certificates: int = 0
    expired_certificates: int = 0
    total_accounts: int = 0
    empty_password_accounts: int = 0
    cracked_accounts: int = 0
    router_default_credentials: int = 0
    high_entropy_secrets: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0


# Alias for compatibility with external references
SecretsSummary = SecretsHarvestSummary


class SecretsHarvestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="ignore")

    project_id: uuid.UUID | str
    firmware_id: uuid.UUID | str
    extracted_root: str
    summary: SecretsHarvestSummary
    private_keys: list[PrivateKeyFinding] = Field(default_factory=list)
    certificates: list[CertificateFinding] = Field(default_factory=list)
    accounts: list[ShadowAccountFinding] = Field(default_factory=list)
    router_credentials: list[RouterCredentialFinding] = Field(default_factory=list)
    generic_secrets: list[GenericSecretFinding] = Field(default_factory=list)
    cached: bool = False


class ExportSecretsFindingsRequest(BaseModel):
    firmware_id: uuid.UUID | str | None = None
    min_severity: SecretSeverity = SecretSeverity.MEDIUM


class ExportSecretsFindingsResponse(BaseModel):
    created_count: int
    skipped_count: int
    message: str
