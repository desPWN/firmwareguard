"""Unit tests for auth gate, upload size limits, report enrichment, and host terminal safety."""

import io
import os
import tempfile
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import UploadFile

from app.config import Settings
from app.routers.auth import (
    SESSION_COOKIE_NAME,
    create_session_token,
    is_authenticated,
    verify_session_token,
)
from app.services.firmware_service import FirmwareService, UploadSizeLimitError
from app.services.report_service import generate_html_report, generate_markdown_report


def test_session_token_roundtrip_and_expiry():
    token = create_session_token("s3cr3t")
    assert verify_session_token(token, "s3cr3t") is True
    assert verify_session_token(token, "wrong") is False
    assert verify_session_token("malformed", "s3cr3t") is False

    expired = create_session_token("s3cr3t", expires_at=1)
    assert verify_session_token(expired, "s3cr3t") is False


def test_is_authenticated_modes():
    with patch("app.routers.auth.get_settings", return_value=Settings(auth_password="")):
        assert is_authenticated({}, {}) is True

    with patch("app.routers.auth.get_settings", return_value=Settings(auth_password="hunter2")):
        assert is_authenticated({}, {}) is False
        assert is_authenticated({}, {"Authorization": "Bearer wrong"}) is False
        assert is_authenticated({}, {"Authorization": "Bearer hunter2"}) is True
        assert is_authenticated({}, {"X-API-Password": "hunter2"}) is True
        tok = create_session_token("hunter2")
        assert is_authenticated({SESSION_COOKIE_NAME: tok}, {}) is True
        assert is_authenticated({}, {}, {"token": tok}) is True


def test_host_terminal_disabled_by_default():
    s = Settings()
    assert s.enable_host_terminal is False
    assert s.auth_password == ""
    assert s.cleanup_interval_seconds == 300


@pytest.mark.asyncio
async def test_firmware_upload_enforces_max_size_and_cleans_up():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = AsyncMock()
        svc = FirmwareService(db)
        svc.settings = Settings(storage_root=tmpdir, max_upload_size_mb=1)

        # 1.2 MB payload exceeds 1 MB limit
        oversized = UploadFile(filename="too_big.bin", file=io.BytesIO(b"A" * (1200 * 1024)))
        project_id = uuid.uuid4()

        with pytest.raises(UploadSizeLimitError):
            await svc.upload(project_id, oversized)

        # Ensure partial directory was cleaned up
        fw_parent = os.path.join(tmpdir, "projects", str(project_id), "firmware")
        if os.path.isdir(fw_parent):
            assert os.listdir(fw_parent) == []


def test_reports_include_hardening_secrets_and_sbom_sections():
    project = SimpleNamespace(name="Demo Router", description="Test assessment")
    firmware = SimpleNamespace(
        original_filename="fw.bin",
        sha256="a" * 64,
        file_size=4 * 1024 * 1024,
        architecture="mips",
        endianness="big",
        os_info="Linux 3.2",
    )
    findings = [
        SimpleNamespace(
            title="Command Injection in httpd",
            severity="critical",
            status="open",
            file_path="/bin/httpd",
            line_number=42,
            cve_ids=["CVE-2024-0001"],
            cwe_ids=["CWE-78"],
            description="Unsanitized input passed to system().",
            evidence="system(buf);",
        )
    ]
    hardening = {
        "summary": {
            "total_binaries": 50,
            "executable_count": 30,
            "library_count": 20,
            "nx_count": 25,
            "nx_percentage": 50.0,
            "canary_count": 10,
            "canary_percentage": 20.0,
            "pie_count": 5,
            "pie_percentage": 10.0,
            "full_relro_count": 2,
            "full_relro_percentage": 4.0,
            "average_score": 28.5,
        },
        "binaries": [
            {
                "path": "/bin/httpd",
                "binary_type": "executable",
                "score": 0.0,
                "nx": False,
                "canary": False,
                "pie_status": "No PIE",
                "relro": "none",
            }
        ],
    }
    secrets = {
        "summary": {
            "total_private_keys": 2,
            "unencrypted_private_keys": 1,
            "total_certificates": 3,
            "expired_certificates": 2,
            "total_accounts": 4,
            "cracked_accounts": 1,
            "empty_password_accounts": 1,
            "total_router_credentials": 2,
            "total_generic_secrets": 5,
        },
        "shadow_accounts": [
            {
                "username": "root",
                "shell": "/bin/sh",
                "status": "cracked",
                "cracked_password": "admin",
                "source_file": "/etc/shadow",
            }
        ],
    }
    sbom_summary = {
        "total_components": 12,
        "total_vulnerabilities": 8,
        "severity_counts": {"critical": 2, "high": 4, "medium": 2},
        "top_vulnerabilities": [
            {
                "cve_id": "CVE-2023-1234",
                "component_name": "busybox",
                "component_version": "1.24.1",
                "severity": "critical",
                "cvss_score": 9.8,
                "resolution_status": "open",
            }
        ],
    }

    md = generate_markdown_report(
        project,
        firmware,
        findings,
        hardening=hardening,
        secrets=secrets,
        sbom_summary=sbom_summary,
    )
    assert "## Binary Hardening Posture" in md
    assert "28.5 / 100" in md
    assert "/bin/httpd" in md
    assert "## Secrets & Credentials Audit" in md
    assert "Cracked password" in md
    assert "## SBOM & Known Vulnerabilities (CVEs)" in md
    assert "CVE-2023-1234" in md

    html = generate_html_report(
        project,
        firmware,
        findings,
        hardening=hardening,
        secrets=secrets,
        sbom_summary=sbom_summary,
    )
    assert "Binary Hardening Posture" in html
    assert "Secrets &amp; Credentials Audit" in html
    assert "SBOM &amp; Known Vulnerabilities (CVEs)" in html
    assert "CVE-2023-1234" in html

    # Backward compatibility when optional sections omitted
    md_basic = generate_markdown_report(project, firmware, findings)
    assert "## Binary Hardening Posture" not in md_basic
    assert "Command Injection in httpd" in md_basic
