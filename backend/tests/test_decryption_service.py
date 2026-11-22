"""Unit tests for firmware entropy analysis, vendor auto-decryptors, and custom BYOK decryption."""

import os
import struct
import tempfile

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.services.decryption_service import (
    _DLINK_SHRS_HEADER_SIZE,
    _DLINK_SHRS_KEY,
    _HIKVISION_DAV_XOR_KEY,
    _xor_bytes,
    analyze_encryption,
    auto_decrypt_if_known,
    decrypt_custom,
)


def test_entropy_classifies_random_as_likely_encrypted():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "enc.bin")
        with open(path, "wb") as f:
            f.write(os.urandom(256 * 1024))

        res = analyze_encryption(path)
        assert res.verdict == "likely_encrypted"
        assert res.overall_entropy >= 7.85
        assert res.high_entropy_ratio >= 0.9
        assert len(res.blocks) >= 16


def test_entropy_classifies_plaintext_as_unencrypted():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "plain.bin")
        with open(path, "wb") as f:
            f.write((b"HELLO FIRMWAREGUARD " * 4096))

        res = analyze_encryption(path)
        assert res.verdict == "unencrypted"
        assert res.overall_entropy < 5.0


def test_detects_openssl_salted_header():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "ssl.bin")
        with open(path, "wb") as f:
            f.write(b"Salted__" + os.urandom(64 * 1024))

        res = analyze_encryption(path)
        assert res.detected_format == "openssl_salted"
        assert res.verdict == "likely_encrypted"


def test_dlink_shrs_auto_decrypt_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        plaintext = b"hsqs" + (b"\x00" * 4092)  # 4096 bytes (multiple of 16)
        iv = bytes.fromhex("00112233445566778899aabbccddeeff")
        enc = Cipher(algorithms.AES(_DLINK_SHRS_KEY), modes.CBC(iv)).encryptor()
        ciphertext = enc.update(plaintext) + enc.finalize()

        header = bytearray(_DLINK_SHRS_HEADER_SIZE)
        header[0:4] = b"SHRS"
        header[8:12] = struct.pack(">I", len(ciphertext))
        header[12:28] = iv

        src = os.path.join(tmp, "dlink.bin")
        with open(src, "wb") as f:
            f.write(bytes(header) + ciphertext)

        analysis = analyze_encryption(src)
        assert analysis.detected_format == "dlink_shrs"
        assert analysis.verdict == "auto_decryptable"

        dec = auto_decrypt_if_known(src, os.path.join(tmp, "out"))
        assert dec is not None
        assert dec.success is True
        assert dec.method == "dlink_shrs"
        assert "SquashFS (little-endian)" in dec.known_signatures
        assert open(dec.output_path, "rb").read() == plaintext


def test_hikvision_dav_auto_decrypt_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        # Original plaintext starts with 'HEAD' -> XORed with first 4 bytes of Hikvision key produces 'SWKH'
        # Wait: verify 'SWKH' ^ key[:4] recovers plaintext cleanly
        raw_magic = b"SWKH"
        original = _xor_bytes(raw_magic, _HIKVISION_DAV_XOR_KEY[:4]) + b"hsqs" + (b"\x00" * 2040)
        obfuscated = _xor_bytes(original, _HIKVISION_DAV_XOR_KEY)
        assert obfuscated[:4] == b"SWKH"

        src = os.path.join(tmp, "digicap.dav")
        with open(src, "wb") as f:
            f.write(obfuscated)

        analysis = analyze_encryption(src)
        assert analysis.detected_format == "hikvision_dav"
        assert analysis.verdict == "auto_decryptable"

        dec = auto_decrypt_if_known(src, os.path.join(tmp, "out"))
        assert dec is not None
        assert dec.success is True
        assert open(dec.output_path, "rb").read() == original


def test_netgear_chk_auto_unwrap():
    with tempfile.TemporaryDirectory() as tmp:
        inner = b"hsqs" + (b"\x00" * 2048)
        hdr_len = 58
        header = b"*#$^" + struct.pack(">I", hdr_len) + (b"\x00" * (hdr_len - 8))

        src = os.path.join(tmp, "netgear.chk")
        with open(src, "wb") as f:
            f.write(header + inner)

        analysis = analyze_encryption(src)
        assert analysis.detected_format == "netgear_chk"
        assert analysis.verdict == "auto_decryptable"

        dec = auto_decrypt_if_known(src, os.path.join(tmp, "out"))
        assert dec is not None
        assert open(dec.output_path, "rb").read() == inner


def test_custom_aes_cbc_ctr_xor_and_validation():
    with tempfile.TemporaryDirectory() as tmp:
        plaintext = b"hsqs" + (b"\x42" * 4092)
        key_hex = "0123456789abcdef0123456789abcdef"
        iv_hex = "fedcba9876543210fedcba9876543210"

        # AES-128-CBC with 64-byte vendor header prefix
        enc_cbc = Cipher(
            algorithms.AES(bytes.fromhex(key_hex)), modes.CBC(bytes.fromhex(iv_hex))
        ).encryptor()
        ct_cbc = (b"\xAA" * 64) + enc_cbc.update(plaintext) + enc_cbc.finalize()
        cbc_path = os.path.join(tmp, "custom_cbc.bin")
        with open(cbc_path, "wb") as f:
            f.write(ct_cbc)

        res_cbc = decrypt_custom(
            cbc_path,
            os.path.join(tmp, "out_cbc"),
            algorithm="aes-128-cbc",
            key=key_hex,
            key_format="hex",
            iv=iv_hex,
            offset=64,
        )
        assert open(res_cbc.output_path, "rb").read() == plaintext
        assert "SquashFS (little-endian)" in res_cbc.known_signatures

        # AES-256-CTR
        key256 = "00" * 32
        enc_ctr = Cipher(
            algorithms.AES(bytes.fromhex(key256)), modes.CTR(bytes.fromhex(iv_hex))
        ).encryptor()
        ct_ctr = enc_ctr.update(plaintext) + enc_ctr.finalize()
        ctr_path = os.path.join(tmp, "custom_ctr.bin")
        with open(ctr_path, "wb") as f:
            f.write(ct_ctr)

        res_ctr = decrypt_custom(
            ctr_path,
            os.path.join(tmp, "out_ctr"),
            algorithm="aes-256-ctr",
            key=key256,
            iv=iv_hex,
        )
        assert open(res_ctr.output_path, "rb").read() == plaintext

        # XOR with UTF-8 key
        xor_path = os.path.join(tmp, "custom_xor.bin")
        with open(xor_path, "wb") as f:
            f.write(_xor_bytes(plaintext, b"vendor-secret"))

        res_xor = decrypt_custom(
            xor_path,
            os.path.join(tmp, "out_xor"),
            algorithm="xor",
            key="vendor-secret",
            key_format="utf8",
        )
        assert open(res_xor.output_path, "rb").read() == plaintext

        # Validation errors
        with pytest.raises(ValueError, match="16-byte key"):
            decrypt_custom(cbc_path, tmp, algorithm="aes-128-cbc", key="deadbeef", iv=iv_hex)
        with pytest.raises(ValueError, match="out of range"):
            decrypt_custom(cbc_path, tmp, algorithm="strip-header", offset=99999999)
