"""Unit tests for FuzzingService helpers, launcher quoting, arch normalization, and crash triage."""

import os
import pytest

from app.services.fuzzing_service import FuzzingService


class TestNormalizeArch:
    def test_aliases(self):
        assert FuzzingService._normalize_arch("mipsbe") == "mips"
        assert FuzzingService._normalize_arch("MIPS") == "mips"
        assert FuzzingService._normalize_arch("MIPS-LE") == "mipsel"
        assert FuzzingService._normalize_arch("armhf") == "arm"
        assert FuzzingService._normalize_arch("arm64") == "aarch64"
        assert FuzzingService._normalize_arch("amd64") == "x86_64"
        assert FuzzingService._normalize_arch(None) == "arm"


class TestResolveTargetFile:
    def test_resolves_explorer_prefix_and_internal_symlink(self, tmp_path):
        root = tmp_path / "squashfs-root"
        (root / "bin").mkdir(parents=True)
        (root / "sbin").mkdir(parents=True)
        bb = root / "bin" / "busybox"
        bb.write_bytes(b"\x7fELF")
        os.symlink("/bin/busybox", root / "sbin" / "httpd")

        norm, host = FuzzingService._resolve_target_file(str(root), "/rootfs/sbin/httpd")
        assert norm == "/sbin/httpd"
        assert host == str(bb)

    def test_rejects_traversal(self, tmp_path):
        root = tmp_path / "squashfs-root"
        (root / "bin").mkdir(parents=True)
        with pytest.raises(ValueError):
            FuzzingService._resolve_target_file(str(root), "../../etc/passwd")


class TestBuildAflLauncherScript:
    def test_quotes_arguments_env_and_desock_safely(self):
        script = FuzzingService._build_afl_launcher_script(
            binary_path="/usr/bin/httpd",
            arch="mips",
            config={
                "timeout_per_exec": 2500,
                "desock": True,
                "arguments": "-c 'foo bar' @@",
                "environment": {
                    "REQUEST_METHOD": "POST",
                    "BAD;KEY": "ignored",
                    "QUERY_STRING": "a=1&b='2'",
                },
            },
            has_dictionary=True,
        )
        assert script.startswith("#!/bin/sh\n")
        assert "export AFL_PRELOAD=/opt/desock/desock_mips.so" in script
        assert "export REQUEST_METHOD=POST" in script
        assert "BAD;KEY" not in script
        assert "QUERY_STRING=" in script
        assert "-t 2500" in script
        assert "-x /opt/fuzzing/dictionary.dict" in script
        assert "exec afl-fuzz -Q" in script
        assert "-- /firmware/usr/bin/httpd -c 'foo bar' @@" in script

    def test_harness_script_target(self):
        script = FuzzingService._build_afl_launcher_script(
            binary_path="/usr/bin/cgi",
            arch="arm",
            config={"timeout_per_exec": 1000},
            harness_target="/opt/fuzzing/harness.sh",
        )
        assert "-- /firmware/bin/sh /opt/fuzzing/harness.sh" in script
        assert "AFL_PRELOAD" not in script


class TestClassifyCrash:
    def test_parses_explicit_exit_code_from_stdout(self):
        out = "=== QEMU reproduction ===\nEXIT_CODE=139\n"
        sig, exp = FuzzingService._classify_crash(out)
        assert sig == "SIGSEGV"
        assert exp == "probably_exploitable"

    def test_falls_back_to_afl_filename_signal(self):
        out = "=== QEMU reproduction ===\nEXIT_CODE=0\n"
        sig, exp = FuzzingService._classify_crash(
            out, "id:000001,sig:06,src:000000,time:42,execs:100,op:havoc,rep:4"
        )
        assert sig == "SIGABRT"
        assert exp == "exploitable"

    def test_detects_text_signals(self):
        sig, exp = FuzzingService._classify_crash("Program received signal SIGBUS, Bus error.")
        assert sig == "SIGBUS"
        assert exp == "probably_exploitable"
