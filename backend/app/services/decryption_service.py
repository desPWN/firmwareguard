"""Firmware entropy analysis, known vendor auto-decryptors, and custom BYOK decryption."""

from __future__ import annotations

import math
import os
import struct
from collections import Counter
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Publicly documented vendor static keys / masks
_DLINK_SHRS_KEY = bytes.fromhex("c05fbf1936c99429ce2a0781f08d6ad8")
_DLINK_SHRS_HEADER_SIZE = 0x6DC  # 1756 bytes
_HIKVISION_DAV_XOR_KEY = bytes.fromhex("bacdbcfed6caddd3bab9a3abbfcbb5be")

# Unencrypted / standard embedded Linux filesystem & container magic bytes
_KNOWN_MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"hsqs", "SquashFS (little-endian)"),
    (b"sqsh", "SquashFS (big-endian)"),
    (b"qshs", "SquashFS (LZMA/vendor)"),
    (b"shsq", "SquashFS (vendor)"),
    (b"UBI#", "UBI image"),
    (b"\x27\x05\x19\x56", "U-Boot uImage"),
    (b"\x1f\x8b\x08", "gzip compressed data"),
    (b"\x5d\x00\x00", "LZMA compressed data"),
    (b"\xfd7zXZ\x00", "XZ compressed data"),
    (b"070701", "CPIO archive (newc)"),
    (b"\x7fELF", "ELF executable"),
    (b"\x45\x3d\xcd\x28", "CramFS filesystem"),
]

_VENDOR_FORMAT_LABELS: dict[str, str] = {
    "dlink_shrs": "D-Link SHRS (AES-128-CBC static key)",
    "hikvision_dav": "Hikvision digicap.dav (XOR obfuscated)",
    "netgear_chk": "Netgear CHK firmware wrapper",
    "openssl_salted": "OpenSSL Salted__ encrypted container",
}

AUTO_DECRYPTABLE_FORMATS = {"dlink_shrs", "hikvision_dav", "netgear_chk"}


@dataclass
class EntropyBlock:
    offset: int
    size: int
    entropy: float


@dataclass
class EncryptionAnalysis:
    file_size: int
    overall_entropy: float
    min_entropy: float
    max_entropy: float
    high_entropy_ratio: float
    verdict: str  # "auto_decryptable" | "likely_encrypted" | "compressed_or_mixed" | "unencrypted"
    detected_format: str | None = None
    detected_format_label: str | None = None
    known_signatures: list[str] = field(default_factory=list)
    summary: str = ""
    blocks: list[EntropyBlock] = field(default_factory=list)


@dataclass
class DecryptResult:
    success: bool
    method: str
    output_path: str
    output_size: int
    post_entropy: float
    known_signatures: list[str]
    message: str


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits/byte (0.0 to 8.0)."""
    length = len(data)
    if length == 0:
        return 0.0
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def detect_vendor_format(header: bytes, file_size: int) -> str | None:
    """Inspect leading header bytes for known vendor encrypted/wrapped firmware formats."""
    if len(header) >= _DLINK_SHRS_HEADER_SIZE and header[:4] == b"SHRS":
        return "dlink_shrs"
    if len(header) >= 4 and header[:4] == b"SWKH":
        return "hikvision_dav"
    if len(header) >= 8 and header[:4] == b"*#$^":
        hdr_len = struct.unpack(">I", header[4:8])[0]
        if 32 <= hdr_len < file_size:
            return "netgear_chk"
    if len(header) >= 16 and header[:8] == b"Salted__":
        return "openssl_salted"
    return None


def scan_known_signatures(file_path: str, max_scan_bytes: int = 8 * 1024 * 1024) -> list[str]:
    """Quickly scan up to max_scan_bytes for standard filesystem/archive magic bytes."""
    found: list[str] = []
    seen: set[str] = set()
    try:
        with open(file_path, "rb") as f:
            sample = f.read(max_scan_bytes)
    except OSError:
        return found

    for magic, label in _KNOWN_MAGIC_SIGNATURES:
        if label not in seen and magic in sample:
            found.append(label)
            seen.add(label)
    return found


def analyze_encryption(file_path: str, max_blocks: int = 64) -> EncryptionAnalysis:
    """Compute block-level Shannon entropy, detect vendor headers, and diagnose encryption."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Firmware file not found: {file_path}")

    file_size = os.path.getsize(file_path)
    if file_size == 0:
        return EncryptionAnalysis(
            file_size=0,
            overall_entropy=0.0,
            min_entropy=0.0,
            max_entropy=0.0,
            high_entropy_ratio=0.0,
            verdict="unencrypted",
            summary="Firmware file is empty (0 bytes).",
        )

    with open(file_path, "rb") as f:
        header = f.read(min(file_size, 4096))

    detected_format = detect_vendor_format(header, file_size)
    detected_label = _VENDOR_FORMAT_LABELS.get(detected_format) if detected_format else None

    # Partition file into up to max_blocks windows (sampling up to 64 KB per window for speed)
    num_blocks = min(max_blocks, max(1, math.ceil(file_size / 4096)))
    step = file_size / num_blocks
    sample_cap = 65536

    blocks: list[EntropyBlock] = []
    overall_counts: Counter[int] = Counter()
    overall_total = 0

    with open(file_path, "rb") as f:
        for idx in range(num_blocks):
            start = int(idx * step)
            end = int((idx + 1) * step) if idx < num_blocks - 1 else file_size
            block_len = max(1, end - start)
            read_len = min(block_len, sample_cap)
            f.seek(start)
            chunk = f.read(read_len)
            if not chunk:
                continue
            ent = shannon_entropy(chunk)
            blocks.append(EntropyBlock(offset=start, size=block_len, entropy=ent))
            overall_counts.update(chunk)
            overall_total += len(chunk)

    overall_ent = 0.0
    if overall_total > 0:
        for count in overall_counts.values():
            p = count / overall_total
            overall_ent -= p * math.log2(p)
    overall_ent = round(overall_ent, 4)

    entropies = [b.entropy for b in blocks] or [0.0]
    min_ent = min(entropies)
    max_ent = max(entropies)
    high_blocks = sum(1 for e in entropies if e >= 7.8)
    high_ratio = round(high_blocks / len(entropies), 4)

    known_sigs = scan_known_signatures(file_path)

    if detected_format in AUTO_DECRYPTABLE_FORMATS:
        verdict = "auto_decryptable"
        summary = (
            f"Recognized {detected_label}. FirmwareGuard can decrypt/unwrap this format "
            "automatically before running binwalk."
        )
    elif detected_format == "openssl_salted":
        verdict = "likely_encrypted"
        summary = (
            f"Detected OpenSSL Salted__ header with {overall_ent:.2f} bits/byte entropy. "
            "Supply the AES key and IV (or decrypt via OpenSSL) before unpacking."
        )
    elif overall_ent >= 7.75 and high_ratio >= 0.85 and not known_sigs:
        verdict = "likely_encrypted"
        summary = (
            f"Uniformly high entropy ({overall_ent:.2f} bits/byte across {int(high_ratio * 100)}% of blocks) "
            "with no recognized filesystem magic bytes. This image is likely encrypted or custom-packed. "
            "If you recovered the key/IV (via UART, SPI dump, or an older firmware), use Custom Decrypt."
        )
    elif overall_ent >= 7.0 or known_sigs:
        verdict = "compressed_or_mixed"
        sig_note = f"Found: {', '.join(known_sigs[:4])}." if known_sigs else "No standard Linux rootfs signatures detected."
        summary = (
            f"Mixed/compressed entropy ({overall_ent:.2f} bits/byte, range {min_ent:.2f}–{max_ent:.2f}). "
            f"{sig_note}"
        )
    else:
        verdict = "unencrypted"
        summary = (
            f"Low-to-moderate entropy ({overall_ent:.2f} bits/byte) — image does not appear encrypted."
        )

    return EncryptionAnalysis(
        file_size=file_size,
        overall_entropy=overall_ent,
        min_entropy=min_ent,
        max_entropy=max_ent,
        high_entropy_ratio=high_ratio,
        verdict=verdict,
        detected_format=detected_format,
        detected_format_label=detected_label,
        known_signatures=known_sigs,
        summary=summary,
        blocks=blocks,
    )


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def _decrypt_dlink_shrs(raw: bytes) -> bytes:
    if len(raw) <= _DLINK_SHRS_HEADER_SIZE or raw[:4] != b"SHRS":
        raise ValueError("Invalid D-Link SHRS header")
    payload_len = struct.unpack(">I", raw[8:12])[0]
    iv = raw[12:28]
    ciphertext = raw[_DLINK_SHRS_HEADER_SIZE:]
    if payload_len and payload_len <= len(ciphertext):
        ciphertext = ciphertext[:payload_len]
    # AES-CBC requires 16-byte multiple; trim trailing checksum bytes if present
    rem = len(ciphertext) % 16
    if rem:
        ciphertext = ciphertext[:-rem]
    if not ciphertext:
        raise ValueError("D-Link SHRS payload is empty")
    decryptor = Cipher(algorithms.AES(_DLINK_SHRS_KEY), modes.CBC(iv)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def _decrypt_hikvision_dav(raw: bytes) -> bytes:
    if len(raw) < 4 or raw[:4] != b"SWKH":
        raise ValueError("Invalid Hikvision digicap.dav header")
    return _xor_bytes(raw, _HIKVISION_DAV_XOR_KEY)


def _unwrap_netgear_chk(raw: bytes) -> bytes:
    if len(raw) < 8 or raw[:4] != b"*#$^":
        raise ValueError("Invalid Netgear CHK header")
    hdr_len = struct.unpack(">I", raw[4:8])[0]
    if hdr_len < 32 or hdr_len >= len(raw):
        raise ValueError(f"Invalid Netgear CHK header length: {hdr_len}")
    return raw[hdr_len:]


def auto_decrypt_if_known(input_path: str, output_dir: str) -> DecryptResult | None:
    """Detect and decrypt known vendor firmware formats automatically.

    Returns DecryptResult if a known format was detected and decrypted, or None otherwise.
    """
    file_size = os.path.getsize(input_path)
    with open(input_path, "rb") as f:
        header = f.read(min(file_size, 4096))

    fmt = detect_vendor_format(header, file_size)
    if fmt not in AUTO_DECRYPTABLE_FORMATS:
        return None

    with open(input_path, "rb") as f:
        raw = f.read()

    if fmt == "dlink_shrs":
        decrypted = _decrypt_dlink_shrs(raw)
    elif fmt == "hikvision_dav":
        decrypted = _decrypt_hikvision_dav(raw)
    elif fmt == "netgear_chk":
        decrypted = _unwrap_netgear_chk(raw)
    else:
        return None

    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, "decrypted_auto.bin")
    with open(out_path, "wb") as f:
        f.write(decrypted)

    post_analysis = analyze_encryption(out_path)
    label = _VENDOR_FORMAT_LABELS.get(fmt, fmt)
    return DecryptResult(
        success=True,
        method=fmt,
        output_path=out_path,
        output_size=len(decrypted),
        post_entropy=post_analysis.overall_entropy,
        known_signatures=post_analysis.known_signatures,
        message=f"Auto-decrypted {label} ({len(decrypted):,} bytes).",
    )


def _parse_key_bytes(raw_key: str, key_format: str) -> bytes:
    cleaned = raw_key.strip()
    if key_format == "hex":
        cleaned = cleaned.replace(" ", "").replace(":", "").removeprefix("0x").removeprefix("0X")
        try:
            return bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ValueError("Invalid hex key — expected even number of hexadecimal characters") from exc
    if key_format == "utf8":
        return raw_key.encode("utf-8")
    raise ValueError(f"Unsupported key_format: {key_format}")


def _parse_hex_bytes(raw_hex: str, label: str) -> bytes:
    cleaned = raw_hex.strip().replace(" ", "").replace(":", "").removeprefix("0x").removeprefix("0X")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"Invalid hex {label}") from exc


def decrypt_custom(
    input_path: str,
    output_dir: str,
    *,
    algorithm: str,
    key: str = "",
    key_format: str = "hex",
    iv: str = "",
    offset: int = 0,
    unpad: bool = False,
) -> DecryptResult:
    """Decrypt or unwrap a firmware image with analyst-supplied cipher parameters."""
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Firmware file not found: {input_path}")

    file_size = os.path.getsize(input_path)
    if offset < 0 or offset >= file_size:
        raise ValueError(f"Header offset {offset} is out of range for file of size {file_size} bytes")

    with open(input_path, "rb") as f:
        f.seek(offset)
        payload = f.read()

    alg = algorithm.lower().strip()

    if alg == "strip-header":
        decrypted = payload
    elif alg == "xor":
        key_bytes = _parse_key_bytes(key, key_format)
        if not key_bytes:
            raise ValueError("XOR key cannot be empty")
        decrypted = _xor_bytes(payload, key_bytes)
    elif alg in ("aes-128-cbc", "aes-256-cbc", "aes-128-ctr", "aes-256-ctr", "aes-128-ecb", "aes-256-ecb"):
        expected_key_len = 16 if "128" in alg else 32
        key_bytes = _parse_key_bytes(key, key_format)
        if len(key_bytes) != expected_key_len:
            raise ValueError(
                f"{alg.upper()} requires a {expected_key_len}-byte key (got {len(key_bytes)} bytes)"
            )

        if alg.endswith("-cbc") or alg.endswith("-ctr"):
            iv_bytes = _parse_hex_bytes(iv, "IV/nonce")
            if len(iv_bytes) != 16:
                raise ValueError(f"{alg.upper()} requires a 16-byte (32 hex chars) IV/nonce (got {len(iv_bytes)} bytes)")
            mode = modes.CBC(iv_bytes) if alg.endswith("-cbc") else modes.CTR(iv_bytes)
        else:
            mode = modes.ECB()

        if alg.endswith("-cbc") or alg.endswith("-ecb"):
            rem = len(payload) % 16
            if rem:
                payload = payload[:-rem]
            if not payload:
                raise ValueError("Payload after offset is shorter than one 16-byte AES block")

        decryptor = Cipher(algorithms.AES(key_bytes), mode).decryptor()
        decrypted = decryptor.update(payload) + decryptor.finalize()

        if unpad and (alg.endswith("-cbc") or alg.endswith("-ecb")):
            try:
                unpadder = sym_padding.PKCS7(128).unpadder()
                decrypted = unpadder.update(decrypted) + unpadder.finalize()
            except ValueError:
                # Firmware payloads often omit PKCS#7 padding; keep raw plaintext if invalid
                pass
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, "decrypted_custom.bin")
    with open(out_path, "wb") as f:
        f.write(decrypted)

    post_analysis = analyze_encryption(out_path)
    if post_analysis.known_signatures:
        msg = (
            f"Decrypted with {alg.upper()} ({len(decrypted):,} bytes). "
            f"Detected signatures: {', '.join(post_analysis.known_signatures[:4])}."
        )
    elif post_analysis.overall_entropy >= 7.85:
        msg = (
            f"Decrypted {len(decrypted):,} bytes with {alg.upper()}, but entropy remains very high "
            f"({post_analysis.overall_entropy:.2f} bits/byte) with no filesystem magic — "
            "double-check key, IV, cipher mode, or header offset."
        )
    else:
        msg = (
            f"Decrypted {len(decrypted):,} bytes with {alg.upper()} "
            f"(post-decryption entropy: {post_analysis.overall_entropy:.2f} bits/byte)."
        )

    return DecryptResult(
        success=True,
        method=alg,
        output_path=out_path,
        output_size=len(decrypted),
        post_entropy=post_analysis.overall_entropy,
        known_signatures=post_analysis.known_signatures,
        message=msg,
    )
