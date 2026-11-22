"""Regression tests for SBOM component classification and kernel CVE filtering."""

import os
from types import SimpleNamespace

from app.services.sbom_service import SbomService
from app.services.vulnerability_service import (
    _collect_kernel_modules,
    _is_relevant_kernel_cve,
    _normalize_arch_base,
)


def _make_cve(desc: str, published: str = "2020-01-01T00:00:00Z"):
    return SimpleNamespace(
        published=published,
        descriptions=[SimpleNamespace(lang="en", value=desc)],
    )


def _write_fake_elf(path: str, payload: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(b"\x7fELF" + b"\x00" * 60 + payload)


class TestSbomClassification:
    def test_statically_linked_zlib_does_not_swallow_httpd(self, tmp_path):
        root = str(tmp_path)
        _write_fake_elf(
            os.path.join(root, "usr", "bin", "httpd"),
            b"\x00TP-LINK TECHNOLOGIES\x00inflate 1.1.4 Copyright 1995-2002 Mark Adler\x00",
        )

        comps = SbomService(root).generate_sbom()
        by_name = {c["name"]: c for c in comps}

        assert "zlib" in by_name
        assert by_name["zlib"]["type"] == "library"
        assert by_name["zlib"]["version"] == "1.1.4"
        assert "service_risk" not in (by_name["zlib"].get("metadata") or {})

        assert "httpd" in by_name
        assert by_name["httpd"]["type"] == "application"
        assert by_name["httpd"]["supplier"] is None  # not mislabeled as Apache
        assert (by_name["httpd"].get("metadata") or {}).get("service_risk") == "high"

    def test_busybox_symlink_not_duplicated_as_standalone_daemon(self, tmp_path):
        root = str(tmp_path)
        _write_fake_elf(
            os.path.join(root, "bin", "busybox"),
            b"\x00BusyBox v1.01 (2014.09.29-03:09+0000)\x00",
        )
        os.makedirs(os.path.join(root, "sbin"), exist_ok=True)
        os.symlink("../bin/busybox", os.path.join(root, "sbin", "syslogd"))

        comps = SbomService(root).generate_sbom()
        names = {c["name"] for c in comps}

        assert "busybox" in names
        assert "syslogd" not in names

    def test_hostapd_version_past_256kb_detected(self, tmp_path):
        root = str(tmp_path)
        _write_fake_elf(
            os.path.join(root, "sbin", "hostapd"),
            b"\x00" * (300 * 1024) + b"hostapd v0.5.9\x00",
        )

        comps = SbomService(root).generate_sbom()
        by_name = {c["name"]: c for c in comps}

        assert "hostapd" in by_name
        assert by_name["hostapd"]["version"] == "0.5.9"
        assert by_name["hostapd"]["cpe"] == "cpe:2.3:a:w1.fi:hostapd:0.5.9:*:*:*:*:*:*:*"

    def test_gcc_uses_dominant_version_without_compiler_cpe(self, tmp_path):
        root = str(tmp_path)
        payload = (
            b"GCC: (GNU) 3.3.2\x00"
            + b"GCC: (GNU) 4.3.3\x00" * 10
        )
        _write_fake_elf(os.path.join(root, "lib", "libuClibc-0.9.30.so"), payload)
        os.symlink("libuClibc-0.9.30.so", os.path.join(root, "lib", "libc.so.0"))

        comps = SbomService(root).generate_sbom()
        gcc_comps = [c for c in comps if c["name"] == "gcc"]
        uclibc_comps = [c for c in comps if c["name"] == "uclibc"]

        assert len(gcc_comps) == 1
        assert gcc_comps[0]["version"] == "4.3.3"
        assert gcc_comps[0]["type"] == "library"
        assert gcc_comps[0]["cpe"] is None

        assert len(uclibc_comps) == 1
        assert uclibc_comps[0]["version"] == "0.9.30"
        assert uclibc_comps[0]["cpe"] == "cpe:2.3:a:uclibc:uclibc:0.9.30:*:*:*:*:*:*:*"

    def test_uclibc_ng_preserves_ng_name(self, tmp_path):
        root = str(tmp_path)
        _write_fake_elf(
            os.path.join(root, "lib", "libc.so.0"),
            b"\x00uClibc-ng 1.0.42\x00",
        )

        comps = SbomService(root).generate_sbom()
        names = {c["name"]: c["version"] for c in comps}
        assert names.get("uclibc-ng") == "1.0.42"


class TestKernelCveFiltering:
    def test_arch_normalization(self):
        assert _normalize_arch_base("aarch64") == "arm64"
        assert _normalize_arch_base("arm64") == "arm64"
        assert _normalize_arch_base("arm") == "arm"
        assert _normalize_arch_base("mipsel") == "mips"
        assert _normalize_arch_base("x86_64") == "x86"

    def test_preserves_router_soc_vendor_cves(self):
        brcm_cve = _make_cve("Buffer overflow in Broadcom brcmfmac wireless driver in Linux kernel.")
        rtk_cve = _make_cve("Heap overflow in Realtek Wi-Fi driver in Linux kernel.")
        assert _is_relevant_kernel_cve(brcm_cve, "2.6.36", "arm", set()) is True
        assert _is_relevant_kernel_cve(rtk_cve, "4.14.0", "mips", set()) is True

    def test_preserves_openwrt_nftables_and_overlayfs_on_5_15(self, tmp_path):
        os.makedirs(os.path.join(tmp_path, "etc"), exist_ok=True)
        with open(os.path.join(tmp_path, "etc", "openwrt_release"), "w") as f:
            f.write("DISTRIB_ID='OpenWrt'\n")
        os.makedirs(os.path.join(tmp_path, "usr", "lib", "opkg"), exist_ok=True)
        with open(os.path.join(tmp_path, "usr", "lib", "opkg", "status"), "w") as f:
            f.write("Package: kmod-nft-core\nPackage: kmod-hwmon-core\n")

        evidence = _collect_kernel_modules(str(tmp_path))
        nft_cve = _make_cve("Use-after-free in net/netfilter/nf_tables_api.c in Linux kernel 5.15.")
        ovl_cve = _make_cve("Privilege escalation in overlayfs in Linux kernel 5.15.")
        hwmon_cve = _make_cve("Out-of-bounds read in drivers/hwmon/core.c.")

        assert _is_relevant_kernel_cve(nft_cve, "5.15.167", "mips", evidence) is True
        assert _is_relevant_kernel_cve(ovl_cve, "5.15.167", "mips", evidence) is True
        assert _is_relevant_kernel_cve(hwmon_cve, "5.15.167", "mips", evidence) is True

    def test_filters_impossible_future_features_on_legacy_2_6_kernel(self):
        for desc in [
            "Use-after-free in nf_tables in Linux kernel.",
            "Out-of-bounds access in eBPF verifier.",
            "Flaw in udmabuf device driver.",
            "Race condition in io_uring subsystem.",
            "Privilege escalation in ksmbd server.",
            "Bypass in seccomp PTRACE_SEIZE path.",
        ]:
            cve = _make_cve(desc)
            assert _is_relevant_kernel_cve(cve, "2.6.31", "mips", {"x_tables"}) is False

    def test_filters_virtualization_desktop_and_wrong_arch_noise(self):
        for desc in [
            "KVM guest DoS in arch/x86/kvm/svm.c.",
            "Buffer overflow in drivers/char/virtio_console.c.",
            "Use-after-free in drivers/gpu/drm/amdgpu/amdgpu_cs.c.",
            "Buffer overflow in drivers/net/e1000e/netdev.c.",
            "Use-after-free in Xircom 16-bit PCMCIA driver.",
        ]:
            assert _is_relevant_kernel_cve(_make_cve(desc), "2.6.31", "mips", set()) is False

        # ARM64 firmware excludes x86/MIPS CVEs
        x86_cve = _make_cve("Flaw in arch/x86/kernel/traps.c on x86_64.")
        assert _is_relevant_kernel_cve(x86_cve, "5.15.0", "aarch64", set()) is False

    def test_preserves_present_usb_and_netfilter_cves_on_mips_router(self):
        evidence = {"pppol2tp", "x_tables", "usb-storage", "usbnet"}
        l2tp_cve = _make_cve("The pppol2tp_xmit function in drivers/net/pppol2tp.c allows DoS.")
        xt_cve = _make_cve("Heap out-of-bounds write in net/netfilter/x_tables.c since v2.6.19-rc1.")
        usb_cve = _make_cve("Memory leak in drivers/usb/host/ehci-hcd.c.")

        assert _is_relevant_kernel_cve(l2tp_cve, "2.6.31", "mips", evidence) is True
        assert _is_relevant_kernel_cve(xt_cve, "2.6.31", "mips", evidence) is True
        assert _is_relevant_kernel_cve(usb_cve, "2.6.31", "mips", evidence) is True

    def test_filters_2024_linux_cna_commits_on_eol_2_6_kernel(self):
        cna_2025 = _make_cve(
            "In the Linux kernel, the following vulnerability has been resolved:\n\nnet: fix race",
            published="2025-05-01T00:00:00Z",
        )
        assert _is_relevant_kernel_cve(cna_2025, "2.6.31", "mips", set()) is False
        # Still kept on active 5.15 kernel!
        assert _is_relevant_kernel_cve(cna_2025, "5.15.167", "mips", set()) is True
