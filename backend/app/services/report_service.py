from datetime import datetime, timezone
from html import escape
from typing import Any

from app.models.finding import Finding
from app.models.firmware import Firmware
from app.models.project import Project

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_EMOJI = {"critical": "!!!", "high": "!!", "medium": "!", "low": "-", "info": "i"}
SEVERITY_COLORS = {
    "critical": ("#991b1b", "#fef2f2", "#fecaca"),
    "high": ("#9a3412", "#fff7ed", "#fed7aa"),
    "medium": ("#854d0e", "#fefce8", "#fef08a"),
    "low": ("#1e40af", "#eff6ff", "#bfdbfe"),
    "info": ("#374151", "#f9fafb", "#e5e7eb"),
}


def _weakest_executables(hardening: dict[str, Any], limit: int = 10) -> list[dict[str, Any]]:
    binaries = hardening.get("binaries") or []
    execs = [b for b in binaries if b.get("binary_type") == "executable"]
    if not execs:
        execs = list(binaries)
    execs.sort(key=lambda b: (float(b.get("score", 0.0)), str(b.get("path", ""))))
    return execs[:limit]


def generate_markdown_report(
    project: Project,
    firmware: Firmware | None,
    findings: list[Finding],
    *,
    hardening: dict[str, Any] | None = None,
    secrets: dict[str, Any] | None = None,
    sbom_summary: dict[str, Any] | None = None,
) -> str:
    """Generate a Markdown security assessment report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sections: list[str] = []

    # Title
    sections.append(f"# Security Assessment Report: {project.name}\n")
    sections.append(f"**Generated:** {now}  ")
    sections.append(f"**Project:** {project.name}  ")
    if project.description:
        sections.append(f"**Description:** {project.description}  ")
    sections.append("")

    # Firmware info
    if firmware:
        sections.append("## Firmware Information\n")
        sections.append("| Property | Value |")
        sections.append("|---|---|")
        if firmware.original_filename:
            sections.append(f"| Filename | {firmware.original_filename} |")
        sections.append(f"| SHA256 | `{firmware.sha256}` |")
        if firmware.file_size:
            size_mb = firmware.file_size / (1024 * 1024)
            sections.append(f"| File Size | {size_mb:.1f} MB ({firmware.file_size:,} bytes) |")
        if firmware.architecture:
            sections.append(f"| Architecture | {firmware.architecture} |")
        if firmware.endianness:
            sections.append(f"| Endianness | {firmware.endianness} |")
        if firmware.os_info:
            sections.append(f"| OS Info | {firmware.os_info} |")
        sections.append("")

    # Executive summary
    sections.append("## Executive Summary\n")
    if not findings:
        sections.append("No security findings were recorded for this project.\n")
    else:
        by_severity: dict[str, list[Finding]] = {}
        for f in findings:
            by_severity.setdefault(f.severity, []).append(f)

        total = len(findings)
        summary_parts = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = len(by_severity.get(sev, []))
            if count:
                summary_parts.append(f"**{count}** {sev}")

        sections.append(
            f"A total of **{total}** finding(s) were identified: "
            + ", ".join(summary_parts)
            + ".\n"
        )

        sections.append("| Severity | Count |")
        sections.append("|---|---|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = len(by_severity.get(sev, []))
            if count:
                sections.append(f"| {sev.capitalize()} | {count} |")
        sections.append("")

    # Binary Hardening Posture
    if hardening and isinstance(hardening.get("summary"), dict):
        hs = hardening["summary"]
        sections.append("## Binary Hardening Posture\n")
        sections.append("| Metric | Value |")
        sections.append("|---|---|")
        sections.append(f"| Total ELF Binaries | {hs.get('total_binaries', 0)} ({hs.get('executable_count', 0)} executables, {hs.get('library_count', 0)} libraries) |")
        sections.append(f"| Average Hardening Score | {float(hs.get('average_score', 0.0)):.1f} / 100 |")
        sections.append(f"| NX (Non-Executable Stack) | {hs.get('nx_count', 0)} ({float(hs.get('nx_percentage', 0.0)):.1f}%) |")
        sections.append(f"| Stack Canary | {hs.get('canary_count', 0)} ({float(hs.get('canary_percentage', 0.0)):.1f}%) |")
        sections.append(f"| PIE / ASLR | {hs.get('pie_count', 0)} ({float(hs.get('pie_percentage', 0.0)):.1f}%) |")
        sections.append(f"| Full RELRO | {hs.get('full_relro_count', 0)} ({float(hs.get('full_relro_percentage', 0.0)):.1f}%) |")
        sections.append("")

        weakest = _weakest_executables(hardening, limit=10)
        if weakest:
            sections.append("### Lowest-Scoring Binaries\n")
            sections.append("| Binary | Score | NX | Canary | PIE | RELRO |")
            sections.append("|---|---|---|---|---|---|")
            for b in weakest:
                sections.append(
                    f"| `{b.get('path', '')}` | {float(b.get('score', 0.0)):.0f} "
                    f"| {'Yes' if b.get('nx') else 'No'} "
                    f"| {'Yes' if b.get('canary') else 'No'} "
                    f"| {b.get('pie_status', 'No PIE')} "
                    f"| {str(b.get('relro', 'none')).capitalize()} |"
                )
            sections.append("")

    # Secrets & Credentials Summary
    if secrets and isinstance(secrets.get("summary"), dict):
        ss = secrets["summary"]
        sections.append("## Secrets & Credentials Audit\n")
        sections.append("| Category | Count |")
        sections.append("|---|---|")
        sections.append(f"| Private Keys | {ss.get('total_private_keys', 0)} ({ss.get('unencrypted_private_keys', 0)} unencrypted) |")
        sections.append(f"| X.509 Certificates | {ss.get('total_certificates', 0)} ({ss.get('expired_certificates', 0)} expired) |")
        sections.append(f"| System Accounts | {ss.get('total_accounts', 0)} ({ss.get('cracked_accounts', 0)} cracked, {ss.get('empty_password_accounts', 0)} empty password) |")
        sections.append(f"| Router / Config Credentials | {ss.get('total_router_credentials', 0)} |")
        sections.append(f"| Generic High-Entropy Secrets | {ss.get('total_generic_secrets', 0)} |")
        sections.append("")

        risky_accounts = [
            a for a in (secrets.get("shadow_accounts") or [])
            if a.get("cracked_password") or a.get("status") == "empty_password"
        ][:10]
        if risky_accounts:
            sections.append("### Highlighted High-Risk Accounts\n")
            sections.append("| Username | Shell | Risk | Source |")
            sections.append("|---|---|---|---|")
            for a in risky_accounts:
                risk = "Cracked password" if a.get("cracked_password") else "Empty password"
                sections.append(
                    f"| `{a.get('username', '')}` | `{a.get('shell') or 'n/a'}` | {risk} | `{a.get('source_file', '')}` |"
                )
            sections.append("")

    # SBOM & CVE Summary
    if sbom_summary and sbom_summary.get("total_components", 0) > 0:
        sections.append("## SBOM & Known Vulnerabilities (CVEs)\n")
        sev_counts = sbom_summary.get("severity_counts") or {}
        sections.append("| Metric | Value |")
        sections.append("|---|---|")
        sections.append(f"| Detected Components | {sbom_summary.get('total_components', 0)} |")
        sections.append(f"| Total Matched CVEs | {sbom_summary.get('total_vulnerabilities', 0)} |")
        for sev in ("critical", "high", "medium", "low"):
            if sev_counts.get(sev, 0):
                sections.append(f"| {sev.capitalize()} CVEs | {sev_counts[sev]} |")
        sections.append("")

        top_cves = sbom_summary.get("top_vulnerabilities") or []
        if top_cves:
            sections.append("### Top Priority CVEs\n")
            sections.append("| CVE | Component | Severity | CVSS | Resolution |")
            sections.append("|---|---|---|---|---|")
            for v in top_cves:
                comp = f"{v.get('component_name', '')} {v.get('component_version') or ''}".strip()
                cvss = f"{float(v['cvss_score']):.1f}" if v.get("cvss_score") is not None else "N/A"
                sections.append(
                    f"| `{v.get('cve_id', '')}` | {comp} | {str(v.get('severity', 'info')).capitalize()} | {cvss} | {v.get('resolution_status', 'open')} |"
                )
            sections.append("")

    # Findings by severity
    if findings:
        sorted_findings = sorted(
            findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.title)
        )

        sections.append("## Findings\n")

        current_severity = None
        for f in sorted_findings:
            if f.severity != current_severity:
                current_severity = f.severity
                sections.append(f"### {current_severity.capitalize()} Severity\n")

            sections.append(f"#### {f.title}\n")
            sections.append(f"**Severity:** {f.severity.capitalize()}  ")
            sections.append(f"**Status:** {f.status}  ")
            if f.file_path:
                line_info = f":{f.line_number}" if f.line_number else ""
                sections.append(f"**File:** `{f.file_path}{line_info}`  ")
            if f.cve_ids:
                sections.append(f"**CVEs:** {', '.join(f.cve_ids)}  ")
            if f.cwe_ids:
                sections.append(f"**CWEs:** {', '.join(f.cwe_ids)}  ")
            sections.append("")

            if f.description:
                sections.append(f"{f.description}\n")

            if f.evidence:
                sections.append("**Evidence:**\n")
                sections.append(f"```\n{f.evidence}\n```\n")

    # Footer
    sections.append("---\n")
    sections.append(
        "*Report generated by [FirmwareGuard](https://firmwareguard.ai) "
        "— AI-Assisted Firmware Security Assessment*\n"
    )

    return "\n".join(sections)


def _severity_badge_html(severity: str) -> str:
    text_color, _, bg_color = SEVERITY_COLORS.get(severity.lower(), SEVERITY_COLORS["info"])
    return (
        f'<span style="display:inline-block;padding:2px 10px;border-radius:9999px;'
        f"font-size:12px;font-weight:600;color:{text_color};background:{bg_color};\">"
        f"{escape(severity.capitalize())}</span>"
    )


def generate_html_report(
    project: Project,
    firmware: Firmware | None,
    findings: list[Finding],
    *,
    hardening: dict[str, Any] | None = None,
    secrets: dict[str, Any] | None = None,
    sbom_summary: dict[str, Any] | None = None,
) -> str:
    """Generate a self-contained HTML security assessment report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    e = escape

    # Build firmware info rows
    fw_rows = ""
    if firmware:
        if firmware.original_filename:
            fw_rows += f"<tr><td>Filename</td><td>{e(firmware.original_filename)}</td></tr>"
        fw_rows += f"<tr><td>SHA256</td><td><code>{e(firmware.sha256)}</code></td></tr>"
        if firmware.file_size:
            size_mb = firmware.file_size / (1024 * 1024)
            fw_rows += f"<tr><td>File Size</td><td>{size_mb:.1f} MB ({firmware.file_size:,} bytes)</td></tr>"
        if firmware.architecture:
            fw_rows += f"<tr><td>Architecture</td><td>{e(firmware.architecture)}</td></tr>"
        if firmware.endianness:
            fw_rows += f"<tr><td>Endianness</td><td>{e(firmware.endianness)}</td></tr>"
        if firmware.os_info:
            fw_rows += f"<tr><td>OS Info</td><td>{e(firmware.os_info)}</td></tr>"

    # Executive summary
    by_severity: dict[str, list[Finding]] = {}
    for f in findings:
        by_severity.setdefault(f.severity, []).append(f)

    summary_badges = ""
    if findings:
        total = len(findings)
        badge_parts = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = len(by_severity.get(sev, []))
            if count:
                badge_parts.append(f"{_severity_badge_html(sev)} {count}")
        summary_badges = "&nbsp;&nbsp;".join(badge_parts)
        summary_text = f"A total of <strong>{total}</strong> finding(s) were identified."
    else:
        summary_text = "No security findings were recorded for this project."

    # Binary Hardening HTML section
    hardening_html = ""
    if hardening and isinstance(hardening.get("summary"), dict):
        hs = hardening["summary"]
        hardening_html += "<h2>Binary Hardening Posture</h2>"
        hardening_html += (
            "<table><tbody>"
            f"<tr><td>Total ELF Binaries</td><td>{int(hs.get('total_binaries', 0))} "
            f"({int(hs.get('executable_count', 0))} executables, {int(hs.get('library_count', 0))} libraries)</td></tr>"
            f"<tr><td>Average Hardening Score</td><td><strong>{float(hs.get('average_score', 0.0)):.1f} / 100</strong></td></tr>"
            f"<tr><td>NX (Non-Executable Stack)</td><td>{int(hs.get('nx_count', 0))} ({float(hs.get('nx_percentage', 0.0)):.1f}%)</td></tr>"
            f"<tr><td>Stack Canary</td><td>{int(hs.get('canary_count', 0))} ({float(hs.get('canary_percentage', 0.0)):.1f}%)</td></tr>"
            f"<tr><td>PIE / ASLR</td><td>{int(hs.get('pie_count', 0))} ({float(hs.get('pie_percentage', 0.0)):.1f}%)</td></tr>"
            f"<tr><td>Full RELRO</td><td>{int(hs.get('full_relro_count', 0))} ({float(hs.get('full_relro_percentage', 0.0)):.1f}%)</td></tr>"
            "</tbody></table>"
        )
        weakest = _weakest_executables(hardening, limit=10)
        if weakest:
            rows = "".join(
                f"<tr><td><code>{e(str(b.get('path', '')))}</code></td>"
                f"<td>{float(b.get('score', 0.0)):.0f}</td>"
                f"<td>{'Yes' if b.get('nx') else 'No'}</td>"
                f"<td>{'Yes' if b.get('canary') else 'No'}</td>"
                f"<td>{e(str(b.get('pie_status', 'No PIE')))}</td>"
                f"<td>{e(str(b.get('relro', 'none')).capitalize())}</td></tr>"
                for b in weakest
            )
            hardening_html += (
                "<h3>Lowest-Scoring Binaries</h3>"
                "<table><thead><tr><th>Binary</th><th>Score</th><th>NX</th><th>Canary</th><th>PIE</th><th>RELRO</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
            )

    # Secrets HTML section
    secrets_html = ""
    if secrets and isinstance(secrets.get("summary"), dict):
        ss = secrets["summary"]
        secrets_html += "<h2>Secrets &amp; Credentials Audit</h2>"
        secrets_html += (
            "<table><tbody>"
            f"<tr><td>Private Keys</td><td>{int(ss.get('total_private_keys', 0))} ({int(ss.get('unencrypted_private_keys', 0))} unencrypted)</td></tr>"
            f"<tr><td>X.509 Certificates</td><td>{int(ss.get('total_certificates', 0))} ({int(ss.get('expired_certificates', 0))} expired)</td></tr>"
            f"<tr><td>System Accounts</td><td>{int(ss.get('total_accounts', 0))} ({int(ss.get('cracked_accounts', 0))} cracked, {int(ss.get('empty_password_accounts', 0))} empty password)</td></tr>"
            f"<tr><td>Router / Config Credentials</td><td>{int(ss.get('total_router_credentials', 0))}</td></tr>"
            f"<tr><td>Generic High-Entropy Secrets</td><td>{int(ss.get('total_generic_secrets', 0))}</td></tr>"
            "</tbody></table>"
        )
        risky_accounts = [
            a for a in (secrets.get("shadow_accounts") or [])
            if a.get("cracked_password") or a.get("status") == "empty_password"
        ][:10]
        if risky_accounts:
            rows = "".join(
                f"<tr><td><code>{e(str(a.get('username', '')))}</code></td>"
                f"<td><code>{e(str(a.get('shell') or 'n/a'))}</code></td>"
                f"<td>{'Cracked password' if a.get('cracked_password') else 'Empty password'}</td>"
                f"<td><code>{e(str(a.get('source_file', '')))}</code></td></tr>"
                for a in risky_accounts
            )
            secrets_html += (
                "<h3>Highlighted High-Risk Accounts</h3>"
                "<table><thead><tr><th>Username</th><th>Shell</th><th>Risk</th><th>Source</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
            )

    # SBOM & CVE HTML section
    sbom_html = ""
    if sbom_summary and sbom_summary.get("total_components", 0) > 0:
        sev_counts = sbom_summary.get("severity_counts") or {}
        sbom_rows = (
            f"<tr><td>Detected Components</td><td>{int(sbom_summary.get('total_components', 0))}</td></tr>"
            f"<tr><td>Total Matched CVEs</td><td>{int(sbom_summary.get('total_vulnerabilities', 0))}</td></tr>"
        )
        for sev in ("critical", "high", "medium", "low"):
            if sev_counts.get(sev, 0):
                sbom_rows += f"<tr><td>{e(sev.capitalize())} CVEs</td><td>{int(sev_counts[sev])}</td></tr>"
        sbom_html += f"<h2>SBOM &amp; Known Vulnerabilities (CVEs)</h2><table><tbody>{sbom_rows}</tbody></table>"

        top_cves = sbom_summary.get("top_vulnerabilities") or []
        if top_cves:
            row_parts = []
            for v in top_cves:
                cvss_val = v.get("cvss_score")
                cvss_str = f"{float(cvss_val):.1f}" if cvss_val is not None else "N/A"
                row_parts.append(
                    f"<tr><td><code>{e(str(v.get('cve_id', '')))}</code></td>"
                    f"<td>{e(str(v.get('component_name', '')))} {e(str(v.get('component_version') or ''))}</td>"
                    f"<td>{_severity_badge_html(str(v.get('severity', 'info')))}</td>"
                    f"<td>{cvss_str}</td>"
                    f"<td>{e(str(v.get('resolution_status', 'open')))}</td></tr>"
                )
            rows = "".join(row_parts)
            sbom_html += (
                "<h3>Top Priority CVEs</h3>"
                "<table><thead><tr><th>CVE</th><th>Component</th><th>Severity</th><th>CVSS</th><th>Resolution</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
            )

    # Findings sections grouped by severity
    findings_html = ""
    if findings:
        sorted_findings = sorted(
            findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.title)
        )
        current_severity = None
        for f in sorted_findings:
            if f.severity != current_severity:
                if current_severity is not None:
                    findings_html += "</div>"
                current_severity = f.severity
                text_color, _, _ = SEVERITY_COLORS.get(
                    current_severity, SEVERITY_COLORS["info"]
                )
                findings_html += (
                    f'<div class="severity-section" style="page-break-before:auto;">'
                    f"<h2 style=\"color:{text_color};border-bottom:2px solid {text_color};"
                    f'padding-bottom:4px;">{e(current_severity.capitalize())} Severity</h2>'
                )

            findings_html += '<div class="finding-card">'
            findings_html += (
                f'<h3 style="margin:0 0 8px 0;">'
                f"{_severity_badge_html(f.severity)} {e(f.title)}</h3>"
            )
            meta_parts = [f"<strong>Status:</strong> {e(f.status)}"]
            if f.file_path:
                line_info = f":{f.line_number}" if f.line_number else ""
                meta_parts.append(
                    f"<strong>File:</strong> <code>{e(f.file_path)}{line_info}</code>"
                )
            if f.cve_ids:
                meta_parts.append(
                    f"<strong>CVEs:</strong> {e(', '.join(f.cve_ids))}"
                )
            if f.cwe_ids:
                meta_parts.append(
                    f"<strong>CWEs:</strong> {e(', '.join(f.cwe_ids))}"
                )
            findings_html += (
                '<p style="font-size:13px;color:#555;margin:0 0 8px 0;">'
                + " &nbsp;|&nbsp; ".join(meta_parts)
                + "</p>"
            )

            if f.description:
                findings_html += f"<p>{e(f.description)}</p>"
            if f.evidence:
                findings_html += (
                    f"<div><strong>Evidence:</strong></div>"
                    f"<pre><code>{e(f.evidence)}</code></pre>"
                )
            findings_html += "</div>"

        if current_severity is not None:
            findings_html += "</div>"

    desc_row = (
        f"<p class='header-meta'><strong>Description:</strong> {e(project.description)}</p>"
        if project.description else ""
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Assessment Report: {e(project.name)}</title>
<style>
  @page {{
    size: A4;
    margin: 20mm 15mm;
    @bottom-left {{
      content: "Generated by firmwareguard.ai — AI-assisted firmware security assessment";
      font-size: 8px;
      color: #999;
    }}
    @bottom-right {{
      content: "Page " counter(page) " of " counter(pages);
      font-size: 10px;
      color: #999;
    }}
  }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #1a1a1a;
    line-height: 1.6;
    max-width: 800px;
    margin: 0 auto;
    padding: 0 20px;
    font-size: 14px;
  }}
  h1 {{
    color: #111827;
    border-bottom: 3px solid #2563eb;
    padding-bottom: 8px;
  }}
  h2 {{
    margin-top: 28px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0;
  }}
  th, td {{
    border: 1px solid #d1d5db;
    padding: 8px 12px;
    text-align: left;
  }}
  th {{
    background: #f3f4f6;
    font-weight: 600;
  }}
  code {{
    background: #f3f4f6;
    padding: 1px 4px;
    border-radius: 3px;
    font-size: 13px;
  }}
  pre {{
    background: #1e293b;
    color: #e2e8f0;
    padding: 12px 16px;
    border-radius: 6px;
    overflow-x: auto;
    font-size: 12px;
    line-height: 1.5;
  }}
  pre code {{
    background: none;
    padding: 0;
    color: inherit;
  }}
  .finding-card {{
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 16px;
    margin: 12px 0;
    background: #fafafa;
  }}
  .header-meta {{
    color: #6b7280;
    font-size: 13px;
    margin: 4px 0;
  }}
  .footer {{
    margin-top: 40px;
    padding-top: 16px;
    border-top: 1px solid #d1d5db;
    text-align: center;
    color: #9ca3af;
    font-size: 12px;
  }}
</style>
</head>
<body>

<h1>Security Assessment Report</h1>
<p class="header-meta"><strong>Project:</strong> {e(project.name)}</p>
{desc_row}
<p class="header-meta"><strong>Generated:</strong> {now}</p>

{"<h2>Firmware Information</h2><table><tbody>" + fw_rows + "</tbody></table>" if fw_rows else ""}

<h2>Executive Summary</h2>
<p>{summary_text}</p>
{"<p>" + summary_badges + "</p>" if summary_badges else ""}

{hardening_html}
{secrets_html}
{sbom_html}
{findings_html}

<div class="footer">
  Report generated by <strong>FirmwareGuard</strong> — AI-Assisted Firmware Security Assessment<br>
  <a href="https://firmwareguard.ai" style="color:#2563eb;">firmwareguard.ai</a>
</div>

</body>
</html>"""
    return html


def generate_pdf_report(
    project: Project,
    firmware: Firmware | None,
    findings: list[Finding],
    *,
    hardening: dict[str, Any] | None = None,
    secrets: dict[str, Any] | None = None,
    sbom_summary: dict[str, Any] | None = None,
) -> bytes:
    """Generate a PDF security assessment report via weasyprint."""
    import weasyprint

    html = generate_html_report(
        project,
        firmware,
        findings,
        hardening=hardening,
        secrets=secrets,
        sbom_summary=sbom_summary,
    )
    return weasyprint.HTML(string=html).write_pdf()
