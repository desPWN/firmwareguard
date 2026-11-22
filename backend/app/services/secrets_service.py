"""Hardcoded secrets and credential harvester service for unpacked firmware.

Detects:
- PEM private keys (RSA, EC, DSA, OpenSSH) with per-block encryption checks and accurate line numbers
- X.509 certificates (expiry, weak signatures, weak RSA keys <1024/<2048, self-signed; skips OS CA trust bundles)
- /etc/passwd and /etc/shadow accounts (UID 0 backdoors, empty passwords honoring NO_LOGIN_SHELLS, offline dictionary cracking)
- Router default credentials (NVRAM/default .cfg/.conf/.default files, BusyBox httpd.conf, Lighttpd, Boa, PPP chap/pap, OpenWrt wireless)
- Hardcoded API tokens, bearer credentials, and high-entropy secret assignments in scripts and configs
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

from app.schemas.secrets import SecretSeverity

EMBEDDED_PASSWORDS = [
    "",
    "admin",
    "root",
    "password",
    "1234",
    "12345",
    "123456",
    "12345678",
    "123456789",
    "0000",
    "000000",
    "1111",
    "666666",
    "888888",
    "admin123",
    "admin1234",
    "root123",
    "root1234",
    "password123",
    "pass",
    "pass123",
    "passwd",
    "default",
    "changeme",
    "toor",
    "guest",
    "user",
    "test",
    "administrator",
    "support",
    "system",
    "operator",
    "supervisor",
    "service",
    "manager",
    "tech",
    "debug",
    "backdoor",
    "qwerty",
    "letmein",
    "welcome",
    "login",
    "5up",
    "soho",
    "soho123",
    "tplink",
    "tp-link",
    "tenda",
    "dlink",
    "d-link",
    "netgear",
    "linksys",
    "asus",
    "belkin",
    "huawei",
    "zte",
    "ubnt",
    "mikrotik",
    "cisco",
    "motorola",
    "zyxel",
    "arris",
    "broadcom",
    "realtek",
    "atheros",
    "mediatek",
    "openwrt",
    "dd-wrt",
    "buildroot",
    "telecomadmin",
    "admintelecom",
    "smcadmin",
    "epicrouter",
    "vizxv",
    "xc3511",
    "juantech",
    "anko",
    "zlxx.",
    "hikvision",
    "dahua",
    "7ujMko0admin",
    "7ujMko0vizxv",
    "oelinux123",
    "hi3518",
    "klv123",
    "klv1234",
    "Zte521",
    "jvbzd",
    "xmhdipc",
    "taZz@23495859",
    "20110421",
    "realtek123",
    "fireport",
    "meinsm",
    "icatch99",
    "hichip",
    "ipcam",
    "camera",
]

PRIVATE_KEY_BLOCK_RE = re.compile(
    rb"-----BEGIN\s+(?:([A-Z0-9_-]+)\s+)?PRIVATE KEY-----.*?-----END\s+(?:[A-Z0-9_-]+\s+)?PRIVATE KEY-----",
    re.DOTALL,
)

# Exact NVRAM / default config keys holding actual credentials (never IP addresses like lan_ipaddr)
NVRAM_PASSWORD_KEYS = {
    "http_passwd",
    "http_password",
    "http_admin_password",
    "admin_password",
    "admin_passwd",
    "default_passwd",
    "default_password",
    "telnet_passwd",
    "telnet_password",
    "ssh_passwd",
    "wpa_psk",
    "wl0_wpa_psk",
    "wl1_wpa_psk",
    "wl1.1_wpa_psk",
    "http_login_pwd",
    "system_passwd",
    "sys.baseuserpass",
    "sys.userpass",
    "usb.ftp.pwd",
    "usb.samba.pwd",
    "usb.samba.guest.pwd",
    "wps_device_pin",
    "wl2g.public.wps_ap_pin",
    "wl5g.public.wps_ap_pin",
}

NVRAM_USERNAME_PAIRED: dict[str, str] = {
    "http_passwd": "http_username",
    "http_password": "http_username",
    "http_login_pwd": "http_login_name",
    "sys.baseuserpass": "sys.baseusername",
    "sys.userpass": "sys.username",
    "usb.ftp.pwd": "usb.ftp.user",
    "usb.samba.pwd": "usb.samba.user",
    "usb.samba.guest.pwd": "usb.samba.guest.user",
}

# Standard OS root CA trust stores (public Root CAs are self-signed by definition)
SYSTEM_CA_BUNDLE_NAMES = {
    "ca-certificates.crt",
    "ca-bundle.crt",
    "ca-bundle.trust.crt",
    "cacert.pem",
    "cert.pem",
}

SYSTEM_CA_BUNDLE_PATHS = (
    "/etc/ssl/certs/",
    "/usr/share/ca-certificates/",
    "/etc/ca-certificates/",
)

SEVERITY_LEVELS: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

NO_LOGIN_SHELLS = {
    "/sbin/nologin",
    "/usr/sbin/nologin",
    "/bin/false",
    "/usr/bin/false",
    "/bin/sync",
    "/dev/null",
}

PASSWD_SUFFIXES = (
    "/etc/passwd",
    "/etc_ro/passwd",
    "/rom/etc/passwd",
    "/var/etc/passwd",
    "/etc/master.passwd",
)

SHADOW_SUFFIXES = (
    "/etc/shadow",
    "/etc_ro/shadow",
    "/rom/etc/shadow",
    "/var/etc/shadow",
)

GENERIC_SCAN_EXTENSIONS = {
    ".sh", ".conf", ".cfg", ".ini", ".env", ".json", ".yaml", ".yml",
    ".xml", ".lua", ".py", ".php", ".cgi", ".txt", ".properties",
}

TOKEN_PATTERNS: list[tuple[str, re.Pattern, SecretSeverity]] = [
    ("aws_access_key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), SecretSeverity.CRITICAL),
    ("github_token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{30,})\b"), SecretSeverity.CRITICAL),
    ("google_api_key", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"), SecretSeverity.HIGH),
    ("slack_token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b"), SecretSeverity.CRITICAL),
    ("stripe_live_key", re.compile(r"\b(sk_live_[0-9A-Za-z]{20,})\b"), SecretSeverity.CRITICAL),
    ("bearer_token", re.compile(r"(?i)Authorization\s*[:=]\s*['\"]?Bearer\s+([A-Za-z0-9._~+/=-]{20,})"), SecretSeverity.HIGH),
    ("jwt_token", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"), SecretSeverity.HIGH),
]

HARDCODED_ASSIGNMENT_RE = re.compile(
    r"""(?i)\b(wpa_passphrase|api[_-]?key|api[_-]?secret|secret[_-]?key|auth[_-]?token|access[_-]?token|private[_-]?token|client[_-]?secret|db[_-]?pass(?:word)?|master[_-]?key)\s*[:=]\s*['"]?([^\s'"#,;]{6,120})['"]?"""
)

PLACEHOLDER_VALUES = {
    "none", "null", "true", "false", "undefined", "empty", "default",
    "your_api_key", "your_secret", "changeme", "placeholder", "example",
    "xxxxxxxx", "00000000", "********", "disabled", "enabled",
}


def resolve_higher_severity(sev_a: str | None, sev_b: str | None) -> str:
    """Return whichever severity string has higher precedence."""
    val_a = SEVERITY_LEVELS.get((sev_a or "").lower(), 0)
    val_b = SEVERITY_LEVELS.get((sev_b or "").lower(), 0)
    return (sev_a or "info").lower() if val_a >= val_b else (sev_b or "info").lower()


def is_path_safe(candidate_path: str, root_dir: str) -> bool:
    """Check if candidate_path resolves strictly within root_dir without directory traversal."""
    try:
        real_root = os.path.realpath(root_dir)
        real_target = os.path.realpath(candidate_path)
        real_root_sep = real_root if real_root.endswith(os.sep) else real_root + os.sep
        return real_target == real_root or real_target.startswith(real_root_sep)
    except Exception:
        return False


def safe_walk_files(root_dir: str | Path, max_file_size: int = 2_000_000) -> list[str]:
    """Safely traverse files in root_dir skipping cyclic symlinks, sockets, block devices, and oversized files."""
    root_str = str(root_dir)
    real_root = os.path.realpath(root_str)
    real_root_sep = real_root if real_root.endswith(os.sep) else real_root + os.sep
    visited_inodes: set[tuple[int, int]] = set()
    safe_files: list[str] = []

    for dirpath, dirnames, filenames in os.walk(root_str, followlinks=False):
        try:
            dirnames.sort(key=lambda d: (os.lstat(os.path.join(dirpath, d)).st_ctime_ns, d))
        except Exception:
            pass

        try:
            d_st = os.stat(dirpath)
            d_key = (d_st.st_dev, d_st.st_ino)
            if d_key in visited_inodes:
                dirnames.clear()
                continue
            visited_inodes.add(d_key)
        except (OSError, PermissionError):
            dirnames.clear()
            continue

        for fname in filenames:
            abs_p = os.path.join(dirpath, fname)
            try:
                if os.path.islink(abs_p):
                    real_p = os.path.realpath(abs_p)
                    if not (real_p == real_root or real_p.startswith(real_root_sep)):
                        continue
                    lst = os.stat(abs_p)
                else:
                    lst = os.lstat(abs_p)

                if not stat.S_ISREG(lst.st_mode):
                    continue

                if lst.st_size > max_file_size:
                    continue

                safe_files.append(abs_p)
            except (OSError, PermissionError):
                continue

    return sorted(safe_files)


def identify_hash_format(hash_str: str) -> tuple[str, str, str | None]:
    """Identify password hash type, strength rating, and salt."""
    if not hash_str:
        return "none", "NONE", None
    if hash_str in ("*", "!", "!!", "x", "NP", "LK"):
        return "locked", "LOCKED", None

    target = hash_str
    if target.startswith("!") and len(target) > 1:
        target = target[1:]

    if target.startswith("$1$"):
        parts = target.split("$")
        salt = parts[2] if len(parts) > 2 else None
        return "MD5", "WEAK", salt
    elif target.startswith(("$2a$", "$2b$", "$2y$")):
        parts = target.split("$")
        salt = parts[3][:22] if len(parts) > 3 else None
        return "Blowfish", "OK", salt
    elif target.startswith("$5$"):
        parts = target.split("$")
        salt = (
            parts[3]
            if len(parts) > 3 and "rounds=" in parts[2]
            else (parts[2] if len(parts) > 2 else None)
        )
        return "SHA-256", "OK", salt
    elif target.startswith("$6$"):
        parts = target.split("$")
        salt = (
            parts[3]
            if len(parts) > 3 and "rounds=" in parts[2]
            else (parts[2] if len(parts) > 2 else None)
        )
        return "SHA-512", "OK", salt
    elif target.startswith("$y$"):
        return "yescrypt", "OK", None
    elif len(target) == 13 and not target.startswith("$"):
        salt = target[:2]
        return "DES", "WEAK", salt

    return "unknown", "UNKNOWN", None


def _md5_crypt(password: str, salt: str) -> str:
    """Pure-Python implementation of FreeBSD/Linux MD5 crypt ($1$)."""
    pw_bytes = password.encode("utf-8")
    salt_bytes = salt.encode("utf-8")[:8]

    ctx = hashlib.md5(pw_bytes + b"$1$" + salt_bytes)
    alt = hashlib.md5(pw_bytes + salt_bytes + pw_bytes).digest()
    for i in range(len(pw_bytes), 0, -16):
        ctx.update(alt[: min(i, 16)])

    i = len(pw_bytes)
    while i > 0:
        ctx.update(b"\x00" if (i & 1) else pw_bytes[:1])
        i >>= 1

    final = bytearray(ctx.digest())
    for round_idx in range(1000):
        c = hashlib.md5()
        if round_idx & 1:
            c.update(pw_bytes)
        else:
            c.update(final)
        if round_idx % 3:
            c.update(salt_bytes)
        if round_idx % 7:
            c.update(pw_bytes)
        if round_idx & 1:
            c.update(final)
        else:
            c.update(pw_bytes)
        final = bytearray(c.digest())

    b64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    def _b64_from_24bit(b2: int, b1: int, b0: int, n: int) -> str:
        w = (b2 << 16) | (b1 << 8) | b0
        res = []
        while n > 0:
            res.append(b64[w & 0x3F])
            w >>= 6
            n -= 1
        return "".join(res)

    encoded = (
        _b64_from_24bit(final[0], final[6], final[12], 4)
        + _b64_from_24bit(final[1], final[7], final[13], 4)
        + _b64_from_24bit(final[2], final[8], final[14], 4)
        + _b64_from_24bit(final[3], final[9], final[15], 4)
        + _b64_from_24bit(final[4], final[10], final[5], 4)
        + _b64_from_24bit(0, 0, final[11], 2)
    )
    return f"$1${salt_bytes.decode('utf-8')}${encoded}"


def crack_hash(hash_val: str | None, hash_type: str, salt: str | None) -> str | None:
    """Test common embedded passwords against the hash or stored password tail."""
    if not hash_val:
        return None

    effective_hash = (
        hash_val[1:]
        if hash_val.startswith("!") and len(hash_val) > 1
        else hash_val
    )

    for cand in EMBEDDED_PASSWORDS:
        if not cand:
            continue
        if (
            effective_hash == cand
            or effective_hash.endswith(f"${cand}")
            or effective_hash.endswith(f":{cand}")
        ):
            return cand
        parts = effective_hash.split("$")
        if len(parts) >= 3 and parts[-1] == cand:
            return cand

        if hash_type == "MD5" and salt is not None:
            try:
                if _md5_crypt(cand, salt) == effective_hash:
                    return cand
            except Exception:
                pass

        try:
            import crypt

            if crypt.crypt(cand, effective_hash) == effective_hash:
                return cand
        except Exception:
            pass

    return None


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy for a string."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


def sanitize_null_bytes(val: Any) -> Any:
    """Recursively strip null bytes (\x00) from strings to ensure PostgreSQL JSONB compatibility."""
    if isinstance(val, str):
        return val.replace("\x00", "")
    elif isinstance(val, dict):
        return {k: sanitize_null_bytes(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [sanitize_null_bytes(item) for item in val]
    return val


def _is_system_ca_bundle(rel_p: str) -> bool:
    """Return True if path points to a standard OS root CA trust store."""
    low = rel_p.lower()
    bname = os.path.basename(low)
    if bname in SYSTEM_CA_BUNDLE_NAMES:
        return True
    return any(low.startswith(prefix) for prefix in SYSTEM_CA_BUNDLE_PATHS)


def audit_certificates_and_keys(
    safe_files: list[str], root_dir: str
) -> tuple[list[dict], list[dict]]:
    """Scan filesystem for PEM private keys and device X.509 certificates."""
    private_keys: list[dict] = []
    certificates: list[dict] = []
    now = datetime.now(timezone.utc)

    for fpath in safe_files:
        rel_p = os.path.relpath(fpath, root_dir).replace("\\", "/")
        if not rel_p.startswith("/"):
            rel_p = "/" + rel_p

        try:
            with open(fpath, "rb") as f:
                content = f.read(2_000_000)
        except Exception:
            continue

        if content.startswith((b"\x7fELF", b"!<arch>\n", b"MZ")):
            continue

        if b"-----BEGIN" not in content:
            continue

        # 1. Scan all PEM private key blocks individually
        for key_match in PRIVATE_KEY_BLOCK_RE.finditer(content):
            block = key_match.group(0)
            prefix_b = key_match.group(1) or b""
            prefix = prefix_b.decode("ascii", errors="ignore").upper()

            encrypted = (
                b"ENCRYPTED PRIVATE KEY" in block[:80]
                or b"Proc-Type: 4,ENCRYPTED" in block[:200]
            )
            key_type = "RSA"
            if "EC" in prefix:
                key_type = "EC"
            elif "DSA" in prefix:
                key_type = "DSA"
            elif "OPENSSH" in prefix:
                key_type = "OPENSSH"
            elif prefix in ("", "ENCRYPTED"):
                key_type = "PKCS8"

            line_number = content[: key_match.start()].count(b"\n") + 1
            snippet = block[:300].decode("utf-8", errors="ignore")
            preview_lines = [l.strip() for l in snippet.splitlines() if l.strip()][:2]
            preview = "\n".join(preview_lines).replace("\x00", "")

            severity = SecretSeverity.MEDIUM if encrypted else SecretSeverity.CRITICAL
            private_keys.append({
                "path": rel_p,
                "key_type": key_type,
                "encrypted": encrypted,
                "format": "OPENSSH" if key_type == "OPENSSH" else "PEM",
                "preview": preview,
                "severity": severity.value,
                "line_number": line_number,
            })

        # 2. Scan device X.509 certificates (skip OS Mozilla/CA trust stores to prevent 100+ Root CA false positives)
        if b"-----BEGIN CERTIFICATE-----" in content and not _is_system_ca_bundle(rel_p):
            for cert_match in re.finditer(
                rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                content,
                re.DOTALL,
            ):
                try:
                    cert = x509.load_pem_x509_certificate(cert_match.group(0))
                    issues: list[dict] = []
                    subject = cert.subject.rfc4514_string()
                    issuer = cert.issuer.rfc4514_string()
                    self_signed = subject == issuer
                    if self_signed:
                        issues.append({
                            "severity": "medium",
                            "issue": "Self-signed certificate",
                        })

                    not_before = cert.not_valid_before_utc
                    not_after = cert.not_valid_after_utc
                    is_expired = now > not_after
                    is_not_yet_valid = now < not_before

                    if is_expired:
                        issues.append({
                            "severity": "high",
                            "issue": f"Certificate expired on {not_after.date()}",
                        })
                    if is_not_yet_valid:
                        issues.append({
                            "severity": "high",
                            "issue": "Certificate is not yet valid",
                        })

                    sig_alg = cert.signature_algorithm_oid._name.lower()
                    if "md5" in sig_alg:
                        issues.append({
                            "severity": "critical",
                            "issue": "MD5 signature algorithm",
                        })
                    elif "sha1" in sig_alg:
                        issues.append({
                            "severity": "high",
                            "issue": "SHA-1 signature algorithm",
                        })

                    pub = cert.public_key()
                    key_type = "UNKNOWN"
                    key_size = 0
                    if isinstance(pub, rsa.RSAPublicKey):
                        key_type = "RSA"
                        key_size = pub.key_size
                        if key_size < 1024:
                            issues.append({
                                "severity": "critical",
                                "issue": f"RSA key size {key_size} bits is critically weak",
                            })
                        elif key_size < 2048:
                            issues.append({
                                "severity": "high",
                                "issue": f"RSA key size {key_size} bits is weak",
                            })
                    elif isinstance(pub, ec.EllipticCurvePublicKey):
                        key_type = "EC"
                        key_size = pub.key_size
                    elif isinstance(pub, dsa.DSAPublicKey):
                        key_type = "DSA"
                        key_size = pub.key_size

                    sans: list[str] = []
                    try:
                        san_ext = cert.extensions.get_extension_for_class(
                            x509.SubjectAlternativeName
                        )
                        sans = [str(n.value) for n in san_ext.value]
                    except Exception:
                        sans = []

                    certificates.append({
                        "path": rel_p,
                        "subject": subject,
                        "issuer": issuer,
                        "not_before": not_before.isoformat(),
                        "not_after": not_after.isoformat(),
                        "serial": hex(cert.serial_number),
                        "key_type": key_type,
                        "key_size": key_size,
                        "signature_algorithm": cert.signature_algorithm_oid._name,
                        "self_signed": self_signed,
                        "sans": sans,
                        "wildcard": "*" in subject,
                        "is_expired": is_expired,
                        "is_not_yet_valid": is_not_yet_valid,
                        "issues": issues,
                    })
                except Exception:
                    pass

    return private_keys, certificates


def parse_shadow_and_passwd(safe_files: list[str], root_dir: str) -> list[dict]:
    """Parse /etc/passwd and /etc/shadow for root backdoors, empty passwords, and weak hashes."""
    account_map: dict[str, dict] = {}

    # Pass 1: Parse Passwd Files
    for fpath in safe_files:
        norm = fpath.replace("\\", "/")
        if any(norm.endswith(sfx) for sfx in PASSWD_SUFFIXES):
            rel_p = os.path.relpath(fpath, root_dir).replace("\\", "/")
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    for line_no, line in enumerate(f, start=1):
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(":")
                        if len(parts) >= 7:
                            uname = parts[0]
                            pw_field = parts[1]
                            uid = int(parts[2]) if parts[2].isdigit() else None
                            gid = int(parts[3]) if parts[3].isdigit() else None
                            home = parts[5]
                            shell = parts[6]

                            is_root_backdoor = uid == 0 and uname != "root"
                            is_empty_pw = pw_field == ""

                            severity = SecretSeverity.INFO
                            if is_root_backdoor or (
                                is_empty_pw and shell not in NO_LOGIN_SHELLS
                            ):
                                severity = SecretSeverity.CRITICAL

                            htype = "none" if is_empty_pw else "unknown"
                            hstrength = "NONE" if is_empty_pw else "UNKNOWN"
                            salt = None
                            cracked = None

                            if len(pw_field) > 1 and pw_field not in ("x", "*", "!", "!!"):
                                htype, hstrength, salt = identify_hash_format(pw_field)
                                cracked = crack_hash(pw_field, htype, salt)
                                if cracked or (htype == "none" and shell not in NO_LOGIN_SHELLS):
                                    severity = SecretSeverity.CRITICAL
                                elif hstrength == "WEAK":
                                    severity = SecretSeverity.HIGH

                            info = {
                                "username": uname,
                                "uid": uid,
                                "gid": gid,
                                "shell": shell,
                                "home_dir": home,
                                "status": "empty"
                                if is_empty_pw
                                else (
                                    "has_hash"
                                    if len(pw_field) > 1 and pw_field != "x"
                                    else "locked"
                                ),
                                "hash_type": htype,
                                "hash_strength": hstrength,
                                "hash_value": pw_field
                                if len(pw_field) > 1 and pw_field != "x"
                                else None,
                                "salt": salt,
                                "cracked_password": cracked,
                                "source_file": rel_p,
                                "line_number": line_no,
                                "severity": severity.value,
                            }

                            if uname not in account_map:
                                account_map[uname] = info
                            else:
                                curr = account_map[uname]
                                curr["severity"] = resolve_higher_severity(
                                    curr["severity"], info["severity"]
                                )
            except Exception:
                continue

    # Pass 2: Parse Shadow Files (respecting NO_LOGIN_SHELLS from /etc/passwd)
    for fpath in safe_files:
        norm = fpath.replace("\\", "/")
        if any(norm.endswith(sfx) for sfx in SHADOW_SUFFIXES):
            rel_p = os.path.relpath(fpath, root_dir).replace("\\", "/")
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    for line_no, line in enumerate(f, start=1):
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(":")
                        if len(parts) >= 2:
                            uname = parts[0]
                            hash_val = parts[1]

                            htype, hstrength, salt = identify_hash_format(hash_val)
                            cracked = crack_hash(hash_val, htype, salt)

                            existing_shell = (
                                account_map[uname].get("shell")
                                if uname in account_map
                                else None
                            )
                            has_login_shell = existing_shell not in NO_LOGIN_SHELLS

                            shadow_sev = SecretSeverity.INFO
                            if cracked:
                                shadow_sev = SecretSeverity.CRITICAL
                            elif htype == "none":
                                shadow_sev = (
                                    SecretSeverity.CRITICAL
                                    if has_login_shell
                                    else SecretSeverity.LOW
                                )
                            elif hstrength == "WEAK":
                                shadow_sev = SecretSeverity.HIGH

                            is_locked = htype == "locked" or hash_val.startswith("!")

                            if uname in account_map:
                                acc = account_map[uname]
                                acc["severity"] = resolve_higher_severity(
                                    acc["severity"], shadow_sev.value
                                )
                                acc["status"] = (
                                    "empty"
                                    if htype == "none"
                                    else ("locked" if is_locked else "has_hash")
                                )
                                acc["hash_type"] = htype
                                acc["hash_strength"] = hstrength
                                acc["hash_value"] = (
                                    hash_val
                                    if not is_locked and htype != "none"
                                    else None
                                )
                                acc["salt"] = salt
                                acc["cracked_password"] = cracked
                                acc["source_file"] = rel_p
                                acc["line_number"] = line_no
                            else:
                                account_map[uname] = {
                                    "username": uname,
                                    "uid": None,
                                    "gid": None,
                                    "shell": None,
                                    "home_dir": None,
                                    "status": (
                                        "empty"
                                        if htype == "none"
                                        else ("locked" if is_locked else "has_hash")
                                    ),
                                    "hash_type": htype,
                                    "hash_strength": hstrength,
                                    "hash_value": (
                                        hash_val
                                        if not is_locked and htype != "none"
                                        else None
                                    ),
                                    "salt": salt,
                                    "cracked_password": cracked,
                                    "source_file": rel_p,
                                    "line_number": line_no,
                                    "severity": shadow_sev.value,
                                }
            except Exception:
                continue

    return list(account_map.values())


def _infer_service_from_key(key: str) -> str:
    low = key.lower()
    if "ftp" in low:
        return "ftp"
    if "samba" in low or "smb" in low:
        return "samba"
    if "wps" in low:
        return "wps"
    if "wpa" in low or "psk" in low or "wl" in low:
        return "wifi"
    if "telnet" in low:
        return "telnet"
    if "ssh" in low:
        return "ssh"
    if "http" in low or "login" in low or "sys." in low:
        return "web"
    return "nvram"


def parse_router_credentials(safe_files: list[str], root_dir: str) -> list[dict]:
    """Extract default credentials from NVRAM/.cfg defaults, web servers, PPP secrets, and UCI wireless."""
    creds: list[dict] = []
    seen_dedup: set[tuple[str, str | None, str | None, str]] = set()

    def _add_cred(item: dict) -> None:
        dedup_key = (
            item["service"],
            item.get("username"),
            item.get("password"),
            item["source_file"],
        )
        if dedup_key in seen_dedup:
            return
        seen_dedup.add(dedup_key)
        creds.append(item)

    for fpath in safe_files:
        norm = fpath.replace("\\", "/")
        rel_p = os.path.relpath(fpath, root_dir).replace("\\", "/")
        bname = os.path.basename(norm).lower()

        # 1. NVRAM / router factory default configs (.default, .conf, .cfg, nvram)
        is_default_cfg = (
            ("nvram" in bname or "default" in bname)
            and bname.endswith((".default", ".conf", ".cfg", "nvram"))
        )
        if is_default_cfg:
            try:
                kv_lines: list[tuple[int, str, str]] = []
                kv_map: dict[str, str] = {}
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    for line_no, line in enumerate(f, start=1):
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k and v:
                            kv_lines.append((line_no, k, v))
                            kv_map[k] = v

                for line_no, k, v in kv_lines:
                    k_low = k.lower()
                    is_exact_key = k in NVRAM_PASSWORD_KEYS or k_low in NVRAM_PASSWORD_KEYS
                    is_wifi_psk = k_low.endswith(("_wpa_psk", ".wpapsk_psk", "wpa_passphrase"))
                    if not (is_exact_key or is_wifi_psk):
                        continue
                    if v.lower() in PLACEHOLDER_VALUES:
                        continue

                    paired_user_key = NVRAM_USERNAME_PAIRED.get(k) or NVRAM_USERNAME_PAIRED.get(k_low)
                    username = kv_map.get(paired_user_key) if paired_user_key else None
                    service = _infer_service_from_key(k)
                    if not username and service in ("web", "nvram", "telnet", "ssh"):
                        username = kv_map.get("http_username") or kv_map.get("sys.username") or "admin"

                    severity = (
                        SecretSeverity.HIGH
                        if service in ("wifi", "wps")
                        else SecretSeverity.CRITICAL
                    )
                    _add_cred({
                        "service": service,
                        "username": username,
                        "password": v,
                        "source_file": rel_p,
                        "line_number": line_no,
                        "matched_rule": f"nvram:{k}",
                        "severity": severity.value,
                    })
            except Exception:
                continue

        # 2. BusyBox httpd.conf
        if norm.endswith("/httpd.conf") or bname == "httpd.conf":
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    for line_no, line in enumerate(f, start=1):
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(":")
                        if len(parts) >= 3 and parts[1].strip() and parts[2].strip():
                            _add_cred({
                                "service": "web",
                                "username": parts[1].strip(),
                                "password": parts[2].strip(),
                                "source_file": rel_p,
                                "line_number": line_no,
                                "matched_rule": "httpd.conf:basic_auth",
                                "severity": SecretSeverity.CRITICAL.value,
                            })
            except Exception:
                continue

        # 3. Lighttpd lighttpd.conf (with safe path check against traversal)
        if bname == "lighttpd.conf":
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    m = re.search(
                        r'auth\.backend\.plain\.userfile\s*=\s*["\']([^"\']+)["\']',
                        content,
                    )
                    if m:
                        userfile_rel = m.group(1).lstrip("/")
                        userfile_path = os.path.join(root_dir, userfile_rel)
                        if is_path_safe(userfile_path, root_dir) and os.path.isfile(userfile_path):
                            with open(
                                userfile_path, "r", encoding="utf-8", errors="ignore"
                            ) as uf:
                                for uf_lno, uf_line in enumerate(uf, start=1):
                                    uf_parts = uf_line.strip().split(":")
                                    if len(uf_parts) >= 2 and uf_parts[0].strip() and uf_parts[1].strip():
                                        _add_cred({
                                            "service": "web",
                                            "username": uf_parts[0].strip(),
                                            "password": uf_parts[1].strip(),
                                            "source_file": os.path.relpath(
                                                userfile_path, root_dir
                                            ).replace("\\", "/"),
                                            "line_number": uf_lno,
                                            "matched_rule": "lighttpd:plain_userfile",
                                            "severity": SecretSeverity.CRITICAL.value,
                                        })
            except Exception:
                continue

        # 4. Boa Web Server boa.conf
        if bname == "boa.conf":
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    for line_no, line in enumerate(f, start=1):
                        line = line.strip()
                        if line.startswith("Auth "):
                            parts = line.split()
                            if len(parts) >= 3 and ":" in parts[2]:
                                u, p = parts[2].split(":", 1)
                                _add_cred({
                                    "service": "web",
                                    "username": u.strip(),
                                    "password": p.strip(),
                                    "source_file": rel_p,
                                    "line_number": line_no,
                                    "matched_rule": "boa:auth_direct",
                                    "severity": SecretSeverity.CRITICAL.value,
                                })
            except Exception:
                continue

        # 5. PPP chap-secrets / pap-secrets
        if bname in ("chap-secrets", "pap-secrets"):
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    for line_no, line in enumerate(f, start=1):
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split()
                        if len(parts) >= 3:
                            u = parts[0].strip("'\"")
                            p = parts[2].strip("'\"")
                            if p and p != "*" and p.lower() not in PLACEHOLDER_VALUES:
                                _add_cred({
                                    "service": "ppp",
                                    "username": u,
                                    "password": p,
                                    "source_file": rel_p,
                                    "line_number": line_no,
                                    "matched_rule": f"ppp:{bname}",
                                    "severity": SecretSeverity.HIGH.value,
                                })
            except Exception:
                continue

        # 6. OpenWrt UCI wireless (strict path match)
        if norm.endswith(("/etc/config/wireless", "/config/wireless")):
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    cur_ssid = None
                    for line_no, line in enumerate(f, start=1):
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "option ssid" in line:
                            parts = line.split("option ssid", 1)
                            cur_ssid = parts[1].strip().strip("'\"")
                        elif "option key" in line:
                            parts = line.split("option key", 1)
                            key_val = parts[1].strip().strip("'\"")
                            if key_val and key_val.lower() not in PLACEHOLDER_VALUES:
                                _add_cred({
                                    "service": "uci_wifi",
                                    "username": cur_ssid or "wireless_ssid",
                                    "password": key_val,
                                    "source_file": rel_p,
                                    "line_number": line_no,
                                    "matched_rule": "uci:wireless_key",
                                    "severity": SecretSeverity.HIGH.value,
                                })
            except Exception:
                continue

    return creds


def scan_generic_secrets(
    safe_files: list[str], root_dir: str, max_findings: int = 100
) -> list[dict]:
    """Scan text configs and scripts for API tokens, bearer keys, and high-entropy hardcoded secrets."""
    findings: list[dict] = []
    seen: set[tuple[str, int, str]] = set()

    for fpath in safe_files:
        if len(findings) >= max_findings:
            break

        norm = fpath.replace("\\", "/")
        rel_p = os.path.relpath(fpath, root_dir).replace("\\", "/")
        if not rel_p.startswith("/"):
            rel_p = "/" + rel_p

        ext = os.path.splitext(norm)[1].lower()
        if ext not in GENERIC_SCAN_EXTENSIONS:
            continue
        if _is_system_ca_bundle(rel_p):
            continue

        try:
            with open(fpath, "rb") as f:
                raw = f.read(512_000)
        except Exception:
            continue

        if raw.startswith((b"\x7fELF", b"!<arch>\n", b"MZ")) or b"\x00" in raw[:4096]:
            continue

        text = raw.decode("utf-8", errors="ignore")
        for line_no, line in enumerate(text.splitlines(), start=1):
            if len(findings) >= max_findings:
                break
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or len(stripped) > 500:
                continue

            # 1. High-confidence known API/token prefixes
            matched_token = False
            for cat, pat, sev in TOKEN_PATTERNS:
                m = pat.search(stripped)
                if m:
                    matched_token = True
                    val = m.group(1)
                    key = (rel_p, line_no, cat)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        "path": rel_p,
                        "line_number": line_no,
                        "category": cat,
                        "match_text": val,
                        "entropy": round(calculate_entropy(val), 2),
                        "severity": sev.value,
                    })

            if matched_token:
                continue

            # 2. Hardcoded secret/passphrase assignments with entropy validation
            m_assign = HARDCODED_ASSIGNMENT_RE.search(stripped)
            if m_assign:
                var_name = m_assign.group(1).lower()
                val = m_assign.group(2).strip()
                # Skip shell variables, template markers, regexes, URLs, paths, or placeholders
                if (
                    val.startswith(("$", "%", "/", "http://", "https://", "{", "<", ".*", "^"))
                    or ".*" in val
                    or ".+" in val
                    or val.lower() in PLACEHOLDER_VALUES
                ):
                    continue
                ent = round(calculate_entropy(val), 2)
                is_passphrase = "passphrase" in var_name
                if not is_passphrase and ent < 3.2:
                    continue
                key = (rel_p, line_no, var_name)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "path": rel_p,
                    "line_number": line_no,
                    "category": var_name,
                    "match_text": val,
                    "entropy": ent,
                    "severity": (
                        SecretSeverity.HIGH.value
                        if (is_passphrase or ent >= 4.0)
                        else SecretSeverity.MEDIUM.value
                    ),
                })

    return findings


def audit_firmware_secrets(
    rootfs_path: str | Path,
    project_id: str = "00000000-0000-0000-0000-000000000001",
    firmware_id: str = "00000000-0000-0000-0000-000000000002",
) -> dict[str, Any]:
    """Execute whole-firmware secrets and credential harvest."""
    safe_files = safe_walk_files(rootfs_path)
    root_str = str(rootfs_path)

    private_keys, certs = audit_certificates_and_keys(safe_files, root_str)
    accounts = parse_shadow_and_passwd(safe_files, root_str)
    router_creds = parse_router_credentials(safe_files, root_str)
    generic_secrets = scan_generic_secrets(safe_files, root_str)

    # Sort each collection by severity descending for immediate analyst triage
    private_keys.sort(key=lambda x: SEVERITY_LEVELS.get(x["severity"], 0), reverse=True)
    accounts.sort(key=lambda x: (SEVERITY_LEVELS.get(x["severity"], 0), bool(x["cracked_password"])), reverse=True)
    router_creds.sort(key=lambda x: SEVERITY_LEVELS.get(x["severity"], 0), reverse=True)
    generic_secrets.sort(key=lambda x: (SEVERITY_LEVELS.get(x["severity"], 0), x["entropy"]), reverse=True)

    unenc_keys = sum(1 for k in private_keys if not k["encrypted"])
    expired_certs = sum(1 for c in certs if c["is_expired"])
    empty_pw = sum(
        1
        for a in accounts
        if a["status"] == "empty" and a["severity"] in ("critical", "high")
    )
    cracked_acc = sum(1 for a in accounts if a["cracked_password"])

    all_items = private_keys + certs + accounts + router_creds + generic_secrets
    critical_c = sum(
        1
        for i in all_items
        if i.get("severity") == "critical"
        or any(iss.get("severity") == "critical" for iss in i.get("issues", []))
    )
    high_c = sum(
        1
        for i in all_items
        if i.get("severity") == "high"
        or any(iss.get("severity") == "high" for iss in i.get("issues", []))
    )
    medium_c = sum(
        1
        for i in all_items
        if i.get("severity") == "medium"
        or any(iss.get("severity") == "medium" for iss in i.get("issues", []))
    )
    low_c = sum(1 for i in all_items if i.get("severity") == "low")

    summary = {
        "total_findings": len(all_items),
        "total_private_keys": len(private_keys),
        "unencrypted_private_keys": unenc_keys,
        "total_certificates": len(certs),
        "expired_certificates": expired_certs,
        "total_accounts": len(accounts),
        "empty_password_accounts": empty_pw,
        "cracked_accounts": cracked_acc,
        "router_default_credentials": len(router_creds),
        "high_entropy_secrets": len(generic_secrets),
        "critical_count": critical_c,
        "high_count": high_c,
        "medium_count": medium_c,
        "low_count": low_c,
    }

    return sanitize_null_bytes({
        "project_id": str(project_id),
        "firmware_id": str(firmware_id),
        "extracted_root": str(rootfs_path),
        "summary": summary,
        "private_keys": private_keys,
        "certificates": certs,
        "accounts": accounts,
        "router_credentials": router_creds,
        "generic_secrets": generic_secrets,
    })


class SecretsService:
    """Class wrapper for firmware secrets harvesting service."""

    @staticmethod
    def audit_firmware_secrets(
        rootfs_path: str | Path,
        project_id: str = "00000000-0000-0000-0000-000000000001",
        firmware_id: str = "00000000-0000-0000-0000-000000000002",
    ) -> dict[str, Any]:
        """Class method wrapper for static whole-firmware secret harvesting."""
        return audit_firmware_secrets(rootfs_path, project_id, firmware_id)
