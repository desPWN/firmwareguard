"""Binary analysis service — pyelftools-based ELF protection checks with pure-Python fallback."""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Any

from app.utils.sandbox import safe_walk

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    HAS_PYELFTOOLS = True
except ImportError:
    HAS_PYELFTOOLS = False
    ELFFile = None
    SymbolTableSection = None

CANARY_SYMBOLS = {
    "__stack_chk_fail",
    "__stack_chk_guard",
    "__stack_chk_fail_local",
    "__intel_security_cookie",
}

ARCH_MAP: dict[str | int, str] = {
    "EM_X86_64": "x86_64",
    "EM_386": "i386",
    "EM_ARM": "ARM",
    "EM_AARCH64": "AArch64",
    "EM_MIPS": "MIPS",
    "EM_PPC": "PowerPC",
    "EM_PPC64": "PowerPC",
    "EM_SPARC": "SPARC",
    62: "x86_64",
    3: "i386",
    40: "ARM",
    183: "AArch64",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC",
    2: "SPARC",
}


def discover_elf_files(rootfs_path: str | Path) -> list[str]:
    """Find all regular ELF files within rootfs_path, skipping symlinks and kmods."""
    elf_files: list[str] = []
    elf_magic = b"\x7fELF"
    real_root = os.path.realpath(str(rootfs_path))

    for dirpath, dirs, filenames in safe_walk(str(rootfs_path)):
        # Prevent directory symlink escapes outside the firmware sandbox
        real_dir = os.path.realpath(dirpath)
        if real_dir != real_root and not real_dir.startswith(real_root + os.sep):
            dirs.clear()
            continue

        for name in filenames:
            abs_path = os.path.join(dirpath, name)

            # Skip symlinks to prevent duplicate auditing of busybox applets
            if os.path.islink(abs_path):
                continue

            # Skip Linux kernel modules
            if name.endswith(".ko") or ".ko." in name:
                continue

            # Check ELF magic bytes
            try:
                with open(abs_path, "rb") as f:
                    magic = f.read(4)
                if magic == elf_magic:
                    elf_files.append(abs_path)
            except (OSError, PermissionError):
                continue

    return sorted(elf_files)


def _pure_python_checksec(file_path: str, data: bytes) -> dict[str, Any]:
    """Pure-Python struct-based ELF checksec parser fallback."""
    ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
    ei_data = data[5]   # 1 = LE, 2 = BE
    prefix = "<" if ei_data == 1 else ">"
    bits = 32 if ei_class == 1 else 64
    endianness = "little" if ei_data == 1 else "big"

    # Read e_type and e_machine
    if bits == 32:
        (
            e_type, e_machine, _e_version, _e_entry, e_phoff, e_shoff,
            _e_flags, _e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, _e_shstrndx,
        ) = struct.unpack_from(f"{prefix}HHIIIIIHHHHHH", data, 16)
    else:
        (
            e_type, e_machine, _e_version, _e_entry, e_phoff, e_shoff,
            _e_flags, _e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, _e_shstrndx,
        ) = struct.unpack_from(f"{prefix}HHIQQQIHHHHHH", data, 16)

    architecture = ARCH_MAP.get(e_machine, f"Unknown ({e_machine})")

    # Parse Program Headers
    has_pt_gnu_stack = False
    stack_flags = 0
    has_pt_gnu_relro = False
    has_pt_interp = False
    dynamic_offset = 0
    dynamic_size = 0

    PT_DYNAMIC = 2
    PT_INTERP = 3
    PT_GNU_STACK = 0x6474E551
    PT_GNU_RELRO = 0x6474E552

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(data):
            break
        if bits == 32:
            p_type, p_offset, _p_vaddr, _p_paddr, p_filesz, _p_memsz, p_flags, _p_align = struct.unpack_from(
                f"{prefix}IIIIIIII", data, off
            )
        else:
            p_type, p_flags, p_offset, _p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_align = struct.unpack_from(
                f"{prefix}IIQQQQQQ", data, off
            )

        if p_type == PT_GNU_STACK:
            has_pt_gnu_stack = True
            stack_flags = p_flags
        elif p_type == PT_GNU_RELRO:
            has_pt_gnu_relro = True
        elif p_type == PT_INTERP:
            has_pt_interp = True
        elif p_type == PT_DYNAMIC:
            dynamic_offset = p_offset
            dynamic_size = p_filesz

    # NX check
    if has_pt_gnu_stack:
        nx = (stack_flags & 0x1) == 0
    else:
        nx = False

    # Dynamic tags check for RELRO and PIE
    dt_bind_now = False
    dt_debug = False

    if dynamic_offset > 0 and dynamic_size > 0:
        entry_size = 8 if bits == 32 else 16
        num_dyn = dynamic_size // entry_size
        for j in range(num_dyn):
            dyn_off = dynamic_offset + j * entry_size
            if dyn_off + entry_size > len(data):
                break
            if bits == 32:
                d_tag, d_val = struct.unpack_from(f"{prefix}ii", data, dyn_off)
            else:
                d_tag, d_val = struct.unpack_from(f"{prefix}qq", data, dyn_off)

            if d_tag == 0:  # DT_NULL
                break
            elif d_tag == 24:  # DT_BIND_NOW
                dt_bind_now = True
            elif d_tag == 30:  # DT_FLAGS
                if (d_val & 0x8) != 0:  # DF_BIND_NOW
                    dt_bind_now = True
            elif d_tag == 0x6ffffffb:  # DT_FLAGS_1
                if (d_val & 0x1) != 0:  # DF_1_NOW
                    dt_bind_now = True
            elif d_tag == 21:  # DT_DEBUG
                dt_debug = True

    # RELRO classification
    if not has_pt_gnu_relro:
        relro = "none"
    elif dt_bind_now:
        relro = "full"
    else:
        relro = "partial"

    # PIE classification
    file_name = os.path.basename(file_path)
    is_so = file_name.endswith(".so") or ".so." in file_name or "/lib" in file_path.replace("\\", "/")

    if e_type in (2, 0x0002):  # ET_EXEC
        pie = False
        pie_status = "No PIE"
        binary_type = "executable"
    elif e_type in (3, 0x0003):  # ET_DYN
        pie = True
        if dt_debug or has_pt_interp or not is_so:
            pie_status = "Full PIE"
            binary_type = "executable"
        else:
            pie_status = "DSO"
            binary_type = "shared_library"
    else:
        pie = False
        pie_status = "No PIE"
        binary_type = "other"

    # Canary symbol search
    found_symbols: set[str] = set()
    for sym_cand in CANARY_SYMBOLS:
        if sym_cand.encode("utf-8") in data:
            found_symbols.add(sym_cand)

    canary = len(found_symbols.intersection(CANARY_SYMBOLS)) > 0

    # Fortify check
    fortify = (
        b"_chk\x00" in data
        or b"__sprintf_chk" in data
        or b"__snprintf_chk" in data
        or b"__memcpy_chk" in data
    )

    # Stripped check: presence of SHT_SYMTAB (type 2)
    stripped = True
    if e_shoff > 0 and e_shnum > 0 and e_shentsize > 0:
        for k in range(e_shnum):
            sh_off = e_shoff + k * e_shentsize
            if sh_off + e_shentsize > len(data):
                break
            _sh_name, sh_type = struct.unpack_from(f"{prefix}II", data, sh_off)
            if sh_type == 2:  # SHT_SYMTAB
                stripped = False
                break

    # Score calculation
    score = 0.0
    if nx:
        score += 1.0
    if canary:
        score += 1.0
    if pie:
        score += 1.0
    if fortify:
        score += 1.0
    if relro == "full":
        score += 1.0
    elif relro == "partial":
        score += 0.5

    return {
        "path": file_path,
        "filename": file_name,
        "binary_type": binary_type,
        "size": len(data),
        "architecture": architecture,
        "bits": bits,
        "endianness": endianness,
        "nx": nx,
        "canary": canary,
        "pie": pie,
        "pie_status": pie_status,
        "relro": relro,
        "fortify": fortify,
        "stripped": stripped,
        "score": round(score, 2),
    }


def check_binary_protections(binary_path: str) -> dict[str, Any]:
    """Check ELF binary security protections using pyelftools with pure-Python fallback.

    Returns a dict containing checksec mitigations:
      - path, filename, binary_type, size, architecture, bits, endianness
      - nx, canary, pie, pie_status, relro, fortify, stripped, score
    """
    if not os.path.exists(binary_path):
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    try:
        with open(binary_path, "rb") as f:
            data = f.read()
    except Exception as exc:
        raise OSError(f"Could not read ELF file {binary_path}: {exc}") from exc

    if len(data) < 52 or data[:4] != b"\x7fELF":
        return {"error": "Not a valid ELF file"}

    # Attempt pyelftools parsing if available
    if HAS_PYELFTOOLS:
        try:
            import io
            f_io = io.BytesIO(data)
            elf = ELFFile(f_io)

            bits = elf.elfclass
            endianness = "little" if elf.little_endian else "big"
            raw_arch = elf.header.e_machine
            architecture = ARCH_MAP.get(raw_arch, str(raw_arch).replace("EM_", ""))

            filename = os.path.basename(binary_path)
            size = len(data)

            # 1. NX: PT_GNU_STACK
            has_stack = False
            nx = False
            has_relro = False
            has_bind_now = False
            has_dt_debug = False
            has_pt_interp = False

            for seg in elf.iter_segments():
                stype = seg.header.p_type
                if stype in ("PT_GNU_STACK", 0x6474E551):
                    has_stack = True
                    nx = (seg.header.p_flags & 0x1) == 0
                elif stype in ("PT_GNU_RELRO", 0x6474E552):
                    has_relro = True
                elif stype in ("PT_INTERP", 3):
                    has_pt_interp = True
                elif stype in ("PT_DYNAMIC", 2):
                    try:
                        for tag in seg.iter_tags():
                            d_tag = tag.entry.d_tag
                            if d_tag in ("DT_BIND_NOW", 24):
                                has_bind_now = True
                            elif d_tag in ("DT_FLAGS", 30) and (tag.entry.d_val & 0x8):
                                has_bind_now = True
                            elif d_tag in ("DT_FLAGS_1", 0x6ffffffb) and (tag.entry.d_val & 0x1):
                                has_bind_now = True
                            elif d_tag in ("DT_DEBUG", 21):
                                has_dt_debug = True
                    except Exception:
                        pass
                    if not has_bind_now or not has_dt_debug:
                        dyn_off = seg.header.p_offset
                        dyn_sz = seg.header.p_filesz
                        e_sz = 8 if bits == 32 else 16
                        prefix = "<" if elf.little_endian else ">"
                        fmt = f"{prefix}ii" if bits == 32 else f"{prefix}qq"
                        for j in range(dyn_sz // e_sz):
                            o = dyn_off + j * e_sz
                            if o + e_sz > len(data):
                                break
                            tag_id, tag_val = struct.unpack_from(fmt, data, o)
                            if tag_id == 0:
                                break
                            is_bind_now = (
                                tag_id == 24
                                or (tag_id == 30 and (tag_val & 0x8))
                                or (tag_id == 0x6ffffffb and (tag_val & 0x1))
                            )
                            if is_bind_now:
                                has_bind_now = True
                            if tag_id == 21:
                                has_dt_debug = True

            if not has_stack:
                nx = False

            # 2. RELRO
            if not has_relro:
                relro = "none"
            elif has_bind_now:
                relro = "full"
            else:
                relro = "partial"

            # 3. PIE / Binary type
            e_type = elf.header.e_type
            is_so = filename.endswith(".so") or ".so." in filename or "/lib" in binary_path.replace("\\", "/")

            if e_type in ("ET_EXEC", 2):
                pie = False
                pie_status = "No PIE"
                binary_type = "executable"
            elif e_type in ("ET_DYN", 3):
                pie = True
                if has_dt_debug or has_pt_interp or not is_so:
                    pie_status = "Full PIE"
                    binary_type = "executable"
                else:
                    pie_status = "DSO"
                    binary_type = "shared_library"
            else:
                pie = False
                pie_status = "No PIE"
                binary_type = "other"

            # 4. Canary & Fortify
            canary = False
            fortify = False
            for sec_name in (".dynsym", ".symtab"):
                try:
                    sec = elf.get_section_by_name(sec_name)
                    if sec and isinstance(sec, SymbolTableSection):
                        for sym in sec.iter_symbols():
                            sname = sym.name
                            if not sname:
                                continue
                            if sname in CANARY_SYMBOLS:
                                canary = True
                            if sname.startswith("__") and sname.endswith("_chk"):
                                fortify = True
                except Exception:
                    pass

            # Fast symbol check if sections omitted/stripped
            if not canary:
                for sym_cand in CANARY_SYMBOLS:
                    if sym_cand.encode("utf-8") in data:
                        canary = True
                        break
            if not fortify:
                if (
                    b"_chk\x00" in data
                    or b"__sprintf_chk" in data
                    or b"__snprintf_chk" in data
                    or b"__memcpy_chk" in data
                ):
                    fortify = True

            # 5. Stripped
            try:
                symtab = elf.get_section_by_name(".symtab")
                stripped = symtab is None or symtab.num_symbols() == 0
            except Exception:
                stripped = True

            # 6. Score
            score = 0.0
            if nx:
                score += 1.0
            if canary:
                score += 1.0
            if pie:
                score += 1.0
            if fortify:
                score += 1.0
            if relro == "full":
                score += 1.0
            elif relro == "partial":
                score += 0.5

            return {
                "path": binary_path,
                "filename": filename,
                "binary_type": binary_type,
                "size": size,
                "architecture": architecture,
                "bits": bits,
                "endianness": endianness,
                "nx": nx,
                "canary": canary,
                "pie": pie,
                "pie_status": pie_status,
                "relro": relro,
                "fortify": fortify,
                "stripped": stripped,
                "score": round(score, 2),
            }
        except Exception:
            # Fall back to pure Python parsing
            pass

    return _pure_python_checksec(binary_path, data)


def audit_firmware_hardening(extracted_root: str | Path) -> dict[str, Any]:
    """Scan all ELF files in extracted_root and compute hardening summary and binary matrix."""
    root_str = str(extracted_root)
    elf_files = discover_elf_files(root_str)
    binaries: list[dict[str, Any]] = []

    for f_path in elf_files:
        try:
            record = check_binary_protections(f_path)
            if "error" in record:
                continue

            rel_path = os.path.relpath(f_path, root_str).replace("\\", "/")
            if not rel_path.startswith("/"):
                rel_path = "/" + rel_path
            record["path"] = rel_path
            binaries.append(record)
        except Exception:
            continue

    total = len(binaries)
    executables = sum(1 for b in binaries if b.get("binary_type") == "executable")
    libraries = sum(1 for b in binaries if b.get("binary_type") == "shared_library")
    nx_count = sum(1 for b in binaries if b.get("nx") is True)
    canary_count = sum(1 for b in binaries if b.get("canary") is True)
    pie_count = sum(1 for b in binaries if b.get("pie") is True)
    full_relro = sum(1 for b in binaries if b.get("relro") == "full")
    partial_relro = sum(1 for b in binaries if b.get("relro") == "partial")
    no_relro = sum(1 for b in binaries if b.get("relro") == "none")

    avg_score = (sum(float(b.get("score", 0.0)) for b in binaries) / total) if total > 0 else 0.0

    summary = {
        "total_binaries": total,
        "executable_count": executables,
        "library_count": libraries,
        "nx_count": nx_count,
        "nx_percentage": round((nx_count / total * 100), 1) if total > 0 else 0.0,
        "canary_count": canary_count,
        "canary_percentage": round((canary_count / total * 100), 1) if total > 0 else 0.0,
        "pie_count": pie_count,
        "pie_percentage": round((pie_count / total * 100), 1) if total > 0 else 0.0,
        "full_relro_count": full_relro,
        "full_relro_percentage": round((full_relro / total * 100), 1) if total > 0 else 0.0,
        "partial_relro_count": partial_relro,
        "no_relro_count": no_relro,
        "average_score": round(avg_score, 2),
    }

    # Sort least hardened binaries first so critical vulnerabilities appear at the top
    binaries.sort(key=lambda b: (b.get("score", 0.0), b.get("path", "")))

    return {
        "total_binaries": total,
        "summary": summary,
        "binaries": binaries,
    }


# Contract alias
audit_hardening_matrix = audit_firmware_hardening
