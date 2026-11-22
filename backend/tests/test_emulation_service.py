"""Unit tests for EmulationService helpers, Bourne/msh init wrapper, and validation."""

import os
from unittest.mock import MagicMock, patch

import pytest

from app.services.emulation_service import (
    EmulationService,
    _validate_kernel_file,
)


class TestNormalizeBinaryPath:
    def test_standard_and_relative_paths(self, tmp_path):
        root = tmp_path / "squashfs-root"
        (root / "bin").mkdir(parents=True)
        (root / "bin" / "busybox").write_bytes(b"\x7fELF")

        assert EmulationService._normalize_binary_path(str(root), "/bin/busybox") == "/bin/busybox"
        assert EmulationService._normalize_binary_path(str(root), "bin/busybox") == "/bin/busybox"

    def test_strips_explorer_rootfs_and_dir_prefix(self, tmp_path):
        root = tmp_path / "squashfs-root"
        (root / "usr" / "bin").mkdir(parents=True)
        (root / "usr" / "bin" / "httpd").write_bytes(b"\x7fELF")

        assert (
            EmulationService._normalize_binary_path(str(root), "/rootfs/usr/bin/httpd")
            == "/usr/bin/httpd"
        )
        assert (
            EmulationService._normalize_binary_path(str(root), "/squashfs-root/usr/bin/httpd")
            == "/usr/bin/httpd"
        )

    def test_allows_firmware_internal_absolute_symlink(self, tmp_path):
        root = tmp_path / "squashfs-root"
        (root / "sbin").mkdir(parents=True)
        link = root / "sbin" / "reboot"
        # Absolute symlink pointing to /bin/busybox (target does not exist on host)
        os.symlink("/bin/busybox", link)

        assert EmulationService._normalize_binary_path(str(root), "/sbin/reboot") == "/sbin/reboot"

    def test_rejects_traversal_and_directory_and_missing(self, tmp_path):
        root = tmp_path / "squashfs-root"
        (root / "bin").mkdir(parents=True)

        with pytest.raises(ValueError, match="not found|traversal"):
            EmulationService._normalize_binary_path(str(root), "../../etc/passwd")

        with pytest.raises(ValueError, match="directory"):
            EmulationService._normalize_binary_path(str(root), "/bin")

        with pytest.raises(ValueError, match="Binary not found"):
            EmulationService._normalize_binary_path(str(root), "/bin/does_not_exist")


class TestGenerateInitWrapper:
    def test_bourne_msh_compatibility(self):
        script = EmulationService._generate_init_wrapper(
            original_init=None,
            pre_init_script="echo pre",
            stub_profile="generic",
            stub_paths="/opt/stubs/stubs_generic_mips.so",
        )
        assert script.startswith("#!/bin/sh\n")
        # BusyBox v1.01 msh crashes with syntax error on $() and ${var%pat}
        assert "$(" not in script
        assert "${" not in script
        # Stripped router firmware often lacks command, sed, mkdir, sleep
        assert "command -v" not in script
        assert "sed -i" not in script
        assert "mkdir -p" not in script
        assert 'LD_PRELOAD="/opt/stubs/stubs_generic_mips.so"\nexport LD_PRELOAD' in script
        assert "/sbin/ifconfig eth0 10.0.2.15" in script
        assert ". /firmwareguard_pre_init.sh" in script
        assert "for candidate in /sbin/init" in script

    def test_explicit_original_init(self):
        script = EmulationService._generate_init_wrapper(original_init="/bin/sh")
        assert script.rstrip().endswith("exec /bin/sh")
        assert "LD_PRELOAD" not in script


class TestBuildUserShellCmd:
    def test_basic_and_with_log(self):
        assert EmulationService.build_user_shell_cmd("mips") == [
            "chroot",
            "/firmware",
            "/qemu-mips-static",
            "/bin/sh",
        ]
        cmd_with_log = EmulationService.build_user_shell_cmd("mips", show_log=True)
        assert cmd_with_log[:2] == ["sh", "-c"]
        assert "/tmp/qemu-user.log" in cmd_with_log[2]
        assert "exec chroot /firmware /qemu-mips-static /bin/sh" in cmd_with_log[2]


class TestValidateKernelFile:
    def test_valid_elf_exec(self, tmp_path):
        k = tmp_path / "vmlinux"
        # Big-endian MIPS ELF ET_EXEC (ei_data=2, e_type=0x0002)
        header = b"\x7fELF\x01\x02\x01" + b"\x00" * 9 + b"\x00\x02" + b"\x00" * 46
        k.write_bytes(header + b"\x00" * 600_000)
        ok, reason = _validate_kernel_file(str(k))
        assert ok is True
        assert "ELF executable" in reason

    def test_rejects_7z_archive_and_shared_lib(self, tmp_path):
        archive = tmp_path / "3B00.7z"
        archive.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 600_000)
        ok, _ = _validate_kernel_file(str(archive))
        assert ok is False

        so = tmp_path / "lib.so"
        header = b"\x7fELF\x01\x02\x01" + b"\x00" * 9 + b"\x00\x03" + b"\x00" * 46
        so.write_bytes(header + b"\x00" * 600_000)
        ok, _ = _validate_kernel_file(str(so))
        assert ok is False


class TestFindKernelPriority:
    def test_prefers_prebuilt_qemu_kernel_over_firmware_kernel(self, tmp_path):
        kdir = tmp_path / "kernels"
        kdir.mkdir()
        prebuilt = kdir / "debian-mips-kernel"
        prebuilt.write_bytes(b"\x7fELF\x01\x02\x01" + b"\x00" * 9 + b"\x00\x02" + b"\x00" * 600_000)
        fw_k = tmp_path / "fw_vmlinux"
        fw_k.write_bytes(b"\x7fELF\x01\x02\x01" + b"\x00" * 9 + b"\x00\x02" + b"\x00" * 600_000)

        svc = EmulationService(db=MagicMock())
        svc._settings = MagicMock(emulation_kernel_dir=str(kdir))

        with patch("app.services.kernel_service.KernelService.find_kernel_for_arch") as mock_find:
            mock_find.return_value = {"name": "debian-mips-kernel", "architecture": "mips"}
            chosen = svc._find_kernel("mips", firmware_kernel_path=str(fw_k))
            assert chosen == str(prebuilt)
