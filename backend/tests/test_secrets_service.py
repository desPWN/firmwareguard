"""Unit and regression tests for SecretsService (keys, certs, accounts, router defaults, tokens)."""

from __future__ import annotations

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.services.secrets_service import (
    SecretsService,
    _md5_crypt,
    audit_firmware_secrets,
)


def _generate_self_signed_cert_pem(cn: str = "router.local", expired: bool = False) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    if expired:
        not_before = now - datetime.timedelta(days=400)
        not_after = now - datetime.timedelta(days=10)
    else:
        not_before = now - datetime.timedelta(days=1)
        not_after = now + datetime.timedelta(days=365)

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def test_skips_system_ca_bundle_but_audits_device_cert(tmp_path: Path):
    ca_dir = tmp_path / "etc" / "ssl" / "certs"
    ca_dir.mkdir(parents=True)
    ca_cert = _generate_self_signed_cert_pem("Mozilla Root CA")
    (ca_dir / "ca-certificates.crt").write_bytes(ca_cert + b"\n" + ca_cert)

    device_cert = _generate_self_signed_cert_pem("router.lan", expired=True)
    (tmp_path / "etc" / "uhttpd.crt").write_bytes(device_cert)

    result = audit_firmware_secrets(tmp_path)
    certs = result["certificates"]

    assert len(certs) == 1
    assert certs[0]["path"] == "/etc/uhttpd.crt"
    assert certs[0]["is_expired"] is True
    assert result["summary"]["total_certificates"] == 1
    assert result["summary"]["expired_certificates"] == 1


def test_multi_key_pem_reports_per_block_encryption_and_line_numbers(tmp_path: Path):
    pem_file = tmp_path / "etc" / "keys.pem"
    pem_file.parent.mkdir(parents=True)
    pem_content = (
        "# header comment\n"
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        "MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIfakeencrypted\n"
        "-----END ENCRYPTED PRIVATE KEY-----\n"
        "\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAfakeunencryptedkeydata\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    pem_file.write_text(pem_content, encoding="utf-8")

    result = audit_firmware_secrets(tmp_path)
    keys = result["private_keys"]

    assert len(keys) == 2
    # Sorted by severity descending: critical unencrypted first, medium encrypted second
    unenc = [k for k in keys if not k["encrypted"]]
    enc = [k for k in keys if k["encrypted"]]
    assert len(unenc) == 1
    assert len(enc) == 1
    assert unenc[0]["key_type"] == "RSA"
    assert unenc[0]["severity"] == "critical"
    assert unenc[0]["line_number"] == 6
    assert enc[0]["key_type"] == "PKCS8"
    assert enc[0]["severity"] == "medium"
    assert enc[0]["line_number"] == 2
    assert result["summary"]["unencrypted_private_keys"] == 1


def test_shadow_honors_nologin_shell_and_cracks_iot_defaults(tmp_path: Path):
    etc = tmp_path / "etc"
    etc.mkdir(parents=True)
    md5_hash = _md5_crypt("7ujMko0admin", "ab12cd34")

    (etc / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/ash\n"
        "admin:x:1000:1000:admin:/home/admin:/bin/sh\n"
        "daemon:x:1:1:daemon:/var:/sbin/nologin\n",
        encoding="utf-8",
    )
    (etc / "shadow").write_text(
        f"root:{md5_hash}:19000:0:99999:7:::\n"
        "admin::19000:0:99999:7:::\n"
        "daemon::19000:0:99999:7:::\n",
        encoding="utf-8",
    )

    result = audit_firmware_secrets(tmp_path)
    accounts = {a["username"]: a for a in result["accounts"]}

    assert accounts["root"]["cracked_password"] == "7ujMko0admin"
    assert accounts["root"]["severity"] == "critical"

    assert accounts["admin"]["status"] == "empty"
    assert accounts["admin"]["severity"] == "critical"

    # nologin daemon with empty shadow entry must NOT be critical
    assert accounts["daemon"]["status"] == "empty"
    assert accounts["daemon"]["severity"] == "low"

    assert result["summary"]["cracked_accounts"] == 1
    assert result["summary"]["empty_password_accounts"] == 1


def test_router_credentials_cfg_pairing_ignores_ip_and_fake_uhttpd(tmp_path: Path):
    webroot = tmp_path / "webroot_ro"
    webroot.mkdir(parents=True)
    (webroot / "default.cfg").write_text(
        "lan_ipaddr=192.168.0.1\n"
        "sys.baseusername=user\n"
        "sys.baseuserpass=user\n"
        "usb.ftp.user=admin\n"
        "usb.ftp.pwd=admin\n"
        "usb.samba.user=admin\n"
        "usb.samba.pwd=admin\n"
        "wl2g.ssid0.wpapsk_psk=12345678\n"
        "wl2g.public.wps_ap_pin=16677883\n",
        encoding="utf-8",
    )

    # OpenWrt uhttpd config + ELF binary must NOT produce fake credentials
    etc_cfg = tmp_path / "etc" / "config"
    etc_cfg.mkdir(parents=True)
    (etc_cfg / "uhttpd").write_text(
        "config uhttpd 'main'\n\toption config '/etc/httpd.conf'\n",
        encoding="utf-8",
    )
    sbin = tmp_path / "usr" / "sbin"
    sbin.mkdir(parents=True)
    (sbin / "uhttpd").write_bytes(b"\x7fELF\x01\x01\x01\x00fakebinary")

    # PPP chap-secrets
    ppp = tmp_path / "etc" / "ppp"
    ppp.mkdir(parents=True)
    (ppp / "chap-secrets").write_text(
        "# client server secret IP\n"
        "isp_user * s3cr3tPPP *\n"
        "wildcard * * *\n",
        encoding="utf-8",
    )

    result = audit_firmware_secrets(tmp_path)
    creds = result["router_credentials"]

    rules = {c["matched_rule"] for c in creds}
    assert "nvram:lan_ipaddr" not in rules
    assert "uhttpd:config_reference" not in rules
    assert "nvram:sys.baseuserpass" in rules
    assert "nvram:usb.ftp.pwd" in rules
    assert "nvram:usb.samba.pwd" in rules
    assert "nvram:wl2g.ssid0.wpapsk_psk" in rules
    assert "nvram:wl2g.public.wps_ap_pin" in rules
    assert "ppp:chap-secrets" in rules

    by_rule = {c["matched_rule"]: c for c in creds}
    assert by_rule["nvram:sys.baseuserpass"]["username"] == "user"
    assert by_rule["nvram:usb.ftp.pwd"]["service"] == "ftp"
    assert by_rule["nvram:usb.ftp.pwd"]["username"] == "admin"
    assert by_rule["ppp:chap-secrets"]["username"] == "isp_user"
    assert by_rule["ppp:chap-secrets"]["password"] == "s3cr3tPPP"


def test_lighttpd_blocks_path_traversal(tmp_path: Path):
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("root:leakedpass\n", encoding="utf-8")

    rootfs = tmp_path / "rootfs"
    (rootfs / "etc").mkdir(parents=True)
    (rootfs / "etc" / "lighttpd.conf").write_text(
        'auth.backend.plain.userfile = "/../outside_secret.txt"\n',
        encoding="utf-8",
    )

    result = SecretsService.audit_firmware_secrets(rootfs)
    assert result["router_credentials"] == []


def test_scan_generic_secrets_detects_tokens_and_filters_noise(tmp_path: Path):
    cfg = tmp_path / "etc" / "cloud.conf"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(
        "# comment with AKIAIOSFODNN7EXAMPLE\n"
        "aws_key=AKIAIOSFODNN7EXAMPLE\n"
        "api_key=ghp_1234567890abcdefABCDEF1234567890abcd\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\n"
        "client_secret=9fK2mP8qR4vW7xZ1aB5cD9eF3gH6jL0n\n"
        "api_secret=$ENV_VAR_REF\n"
        "db_password=changeme\n"
        "access_token=aaaaaaaaaaaa\n"
        "url_rule_api_key=.*&plat=.*&sver=.*&partner\n",
        encoding="utf-8",
    )

    result = audit_firmware_secrets(tmp_path)
    secrets = result["generic_secrets"]
    cats = [s["category"] for s in secrets]

    assert "aws_access_key" in cats
    assert "github_token" in cats
    # Line with ghp_ token should NOT also emit a duplicate api_key finding
    assert "api_key" not in cats
    assert "bearer_token" in cats
    assert "client_secret" in cats
    # Noise must be excluded
    assert "api_secret" not in cats
    assert "db_password" not in cats
    assert "access_token" not in cats
    assert not any(".*&plat=" in s["match_text"] for s in secrets)
    assert result["summary"]["high_entropy_secrets"] == len(secrets)
