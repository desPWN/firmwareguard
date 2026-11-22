"""Service for managing AFL++ fuzzing campaigns.

Uses the Docker SDK to spawn isolated containers running AFL++ in QEMU mode
for cross-architecture firmware binary fuzzing.
"""

import asyncio
import base64
import io
import logging
import os
import re
import shlex
import tarfile
from datetime import datetime, timezone
from uuid import UUID

import docker
import docker.errors
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.firmware import Firmware
from app.models.fuzzing import FuzzingCampaign, FuzzingCrash
from app.services.analysis_service import check_binary_protections
from app.services.emulation_service import ARCH_ALIASES, EmulationService

logger = logging.getLogger(__name__)

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\r")
_EXIT_CODE_RE = re.compile(r"EXIT_CODE=(\d+)")
_AFL_SIG_RE = re.compile(r"(?:^|,)sig:(\d+)(?:,|$)")
_SIG_MAP: dict[int, str] = {
    4: "SIGILL",
    5: "SIGTRAP",
    6: "SIGABRT",
    7: "SIGBUS",
    8: "SIGFPE",
    11: "SIGSEGV",
}

# Architecture → AFL++ QEMU trace binary (instrumented QEMU for coverage)
QEMU_TRACE_MAP: dict[str, str] = {
    "arm": "afl-qemu-trace-arm",
    "aarch64": "afl-qemu-trace-aarch64",
    "mips": "afl-qemu-trace-mips",
    "mipsel": "afl-qemu-trace-mipsel",
    "x86": "afl-qemu-trace-i386",
    "x86_64": "afl-qemu-trace-x86_64",
}

# Architecture → stock QEMU user-mode static binary (for crash triage)
QEMU_USER_MAP: dict[str, str] = {
    "arm": "qemu-arm-static",
    "aarch64": "qemu-aarch64-static",
    "mips": "qemu-mips-static",
    "mipsel": "qemu-mipsel-static",
    "x86": "qemu-i386-static",
    "x86_64": "qemu-x86_64-static",
}

# Dangerous sink functions — indicate fuzzing value
DANGEROUS_SINKS = {
    "system", "popen", "execve", "execl", "execlp", "execle", "execv",
    "execvp", "execvpe", "sprintf", "vsprintf", "strcpy", "strcat",
    "gets", "scanf", "sscanf", "fscanf", "printf", "fprintf",
    "snprintf", "vsnprintf", "memcpy", "memmove", "strncpy",
    "strncat", "realpath", "wordexp",
}

# Input-handling functions — indicate the binary processes external input
INPUT_FUNCTIONS = {
    "read", "recv", "recvfrom", "recvmsg", "fread", "fgets", "getenv",
    "fopen", "open", "accept", "listen", "socket", "getline",
    "fgetc", "getc", "getchar", "gets", "scanf", "fscanf",
}

# Network-related functions — indicate network-facing binary
NETWORK_FUNCTIONS = {
    "socket", "bind", "listen", "accept", "connect",
    "recv", "recvfrom", "recvmsg", "send", "sendto", "sendmsg",
    "select", "poll", "epoll_wait",
}

# Architecture → desock shared library path inside the fuzzing container
DESOCK_LIB_MAP: dict[str, str] = {
    "arm": "/opt/desock/desock_arm.so",
    "aarch64": "/opt/desock/desock_aarch64.so",
    "mips": "/opt/desock/desock_mips.so",
    "mipsel": "/opt/desock/desock_mipsel.so",
}


class FuzzingService:
    """Manages AFL++ fuzzing campaign lifecycle via Docker containers."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self._settings = get_settings()

    def _get_docker_client(self) -> docker.DockerClient:
        return docker.from_env()

    @staticmethod
    def _write_file_to_container(
        container: "docker.models.containers.Container",
        dest_path: str,
        data: bytes,
    ) -> None:
        """Write arbitrary bytes to a file inside a container using put_archive."""
        dest_dir = os.path.dirname(dest_path)
        dest_name = os.path.basename(dest_path)

        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            info = tarfile.TarInfo(name=dest_name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        tar_stream.seek(0)

        container.put_archive(dest_dir, tar_stream)

    @staticmethod
    def _write_seeds_to_container(
        container: "docker.models.containers.Container",
        seeds_b64: list[str],
    ) -> None:
        """Write base64-encoded seed files to /opt/fuzzing/input/ using put_archive."""
        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            for i, seed_b64 in enumerate(seeds_b64):
                try:
                    seed_data = base64.b64decode(seed_b64)
                except Exception:
                    logger.warning("Failed to decode seed corpus entry %d", i)
                    continue
                info = tarfile.TarInfo(name=f"seed_{i}")
                info.size = len(seed_data)
                tar.addfile(info, io.BytesIO(seed_data))
        tar_stream.seek(0)

        container.put_archive("/opt/fuzzing/input", tar_stream)

    def _resolve_host_path(self, container_path: str) -> str | None:
        """Resolve a container path to a host path for Docker volume mounts."""
        real_path = os.path.realpath(container_path)

        if not os.path.exists("/.dockerenv"):
            return real_path

        client = self._get_docker_client()
        hostname = os.environ.get("HOSTNAME", "")
        if not hostname:
            return real_path

        try:
            our_container = client.containers.get(hostname)
            mounts = our_container.attrs.get("Mounts", [])

            for mount in mounts:
                dest = mount.get("Destination", "")
                source = mount.get("Source", "")
                if not dest or not source:
                    continue
                if real_path.startswith(dest + os.sep) or real_path == dest:
                    relative = os.path.relpath(real_path, dest)
                    return os.path.join(source, relative)
        except Exception:
            logger.warning("Could not inspect own container for path translation")

        return None

    @staticmethod
    def _normalize_arch(arch: str | None) -> str:
        if not arch:
            return "arm"
        return ARCH_ALIASES.get(arch, arch.lower())

    @staticmethod
    def _resolve_target_file(extracted_path: str, binary_path: str) -> tuple[str, str]:
        """Normalize binary_path and resolve firmware-internal symlinks safely.

        Returns `(normalized_firmware_path, host_file_path)`.
        """
        norm = EmulationService._normalize_binary_path(extracted_path, binary_path)
        root = os.path.normpath(os.path.realpath(extracted_path))
        current_rel = norm.lstrip("/")
        seen: set[str] = set()

        for _ in range(16):
            if current_rel in seen:
                break
            seen.add(current_rel)
            candidate = os.path.normpath(os.path.join(root, current_rel))
            if not (candidate == root or candidate.startswith(root + os.sep)):
                raise ValueError(f"Path traversal detected in binary_path: {binary_path}")
            if os.path.islink(candidate):
                link_target = os.readlink(candidate)
                if link_target.startswith("/"):
                    current_rel = os.path.normpath(link_target).lstrip("/")
                else:
                    parent = os.path.dirname(current_rel)
                    current_rel = os.path.normpath(os.path.join(parent, link_target)).lstrip("/")
                continue
            if os.path.isfile(candidate):
                return norm, candidate
            break

        raise ValueError(f"Binary not found: {binary_path}")

    @staticmethod
    def _build_afl_launcher_script(
        binary_path: str,
        arch: str,
        config: dict,
        has_dictionary: bool = False,
        harness_target: str | None = None,
    ) -> str:
        """Build a safely quoted shell launcher script for AFL++ QEMU mode."""
        timeout_ms = int(config.get("timeout_per_exec", 1000))
        binary_in_firmware = binary_path.lstrip("/")

        lines = [
            "#!/bin/sh",
            "export AFL_NO_UI=1",
            "export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1",
            "export AFL_SKIP_CPUFREQ=1",
            "export AFL_AUTORESUME=1",
            "export QEMU_LD_PREFIX=/firmware",
        ]

        if config.get("desock", False):
            desock_lib = DESOCK_LIB_MAP.get(arch)
            if desock_lib:
                lines.append(f"export AFL_PRELOAD={shlex.quote(desock_lib)}")
            else:
                logger.warning("Desock requested but no library for arch %s", arch)

        extra_env = config.get("environment") or {}
        for k, v in extra_env.items():
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", str(k)):
                lines.append(f"export {k}={shlex.quote(str(v))}")

        cmd_parts = [
            "exec",
            "afl-fuzz",
            "-Q",
            "-i", "/opt/fuzzing/input",
            "-o", "/opt/fuzzing/output",
            "-m", "none",
            "-t", str(timeout_ms),
        ]
        if has_dictionary:
            cmd_parts.extend(["-x", "/opt/fuzzing/dictionary.dict"])

        cmd_parts.append("--")
        if harness_target:
            cmd_parts.extend(["/firmware/bin/sh", harness_target])
        else:
            cmd_parts.append(f"/firmware/{binary_in_firmware}")

        arguments = config.get("arguments")
        if arguments:
            for tok in shlex.split(str(arguments)):
                cmd_parts.append(tok)

        lines.append(" ".join(shlex.quote(p) for p in cmd_parts))
        return "\n".join(lines) + "\n"

    @staticmethod
    def _classify_crash(
        combined_output: str,
        crash_filename: str = "",
    ) -> tuple[str | None, str]:
        """Classify crash signal and exploitability from QEMU/GDB output and filename."""
        signal: str | None = None
        exploitability = "unknown"

        if "SIGSEGV" in combined_output or "Segmentation fault" in combined_output:
            signal = "SIGSEGV"
            exploitability = "probably_exploitable"
        elif "SIGABRT" in combined_output or "Aborted" in combined_output:
            signal = "SIGABRT"
            exploitability = "exploitable"
        elif "SIGBUS" in combined_output or "Bus error" in combined_output:
            signal = "SIGBUS"
            exploitability = "probably_exploitable"
        elif "SIGFPE" in combined_output:
            signal = "SIGFPE"
            exploitability = "probably_not"
        elif "SIGILL" in combined_output or "Illegal instruction" in combined_output:
            signal = "SIGILL"
            exploitability = "probably_exploitable"
        elif "SIGTRAP" in combined_output:
            signal = "SIGTRAP"
            exploitability = "probably_not"

        if not signal:
            # Parse explicit EXIT_CODE=<n> printed after QEMU execution
            m = _EXIT_CODE_RE.search(combined_output)
            if m:
                code = int(m.group(1))
                if code > 128:
                    sig_num = code - 128
                    signal = _SIG_MAP.get(sig_num, f"SIG{sig_num}")

        if not signal and crash_filename:
            # Fallback: AFL++ encodes the crash signal in the filename (e.g. id:000000,sig:11,...)
            m = _AFL_SIG_RE.search(crash_filename)
            if m:
                sig_num = int(m.group(1))
                signal = _SIG_MAP.get(sig_num, f"SIG{sig_num}")

        if signal and exploitability == "unknown":
            if signal in ("SIGSEGV", "SIGBUS", "SIGILL"):
                exploitability = "probably_exploitable"
            elif signal == "SIGABRT":
                exploitability = "exploitable"
            elif signal in ("SIGFPE", "SIGTRAP"):
                exploitability = "probably_not"

        return signal, exploitability

    async def analyze_target(
        self, firmware: Firmware, binary_path: str
    ) -> dict:
        """Analyze a binary for fuzzing suitability.

        Returns a dict with fuzzing_score (0-100), input_sources,
        dangerous_functions, protections, and recommended_strategy.
        """
        if not firmware.extracted_path:
            raise ValueError("Firmware has not been unpacked")

        norm_path, full_path = self._resolve_target_file(firmware.extracted_path, binary_path)
        binary_path = norm_path

        # Parse ELF imports using pyelftools
        imports: list[str] = []
        function_count = 0
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.elf.sections import SymbolTableSection

            with open(full_path, "rb") as f:
                elf = ELFFile(f)

                # Get dynamic imports
                dynsym = elf.get_section_by_name(".dynsym")
                if dynsym and isinstance(dynsym, SymbolTableSection):
                    for symbol in dynsym.iter_symbols():
                        if (
                            symbol.entry["st_info"]["type"] == "STT_FUNC"
                            and symbol.entry["st_shndx"] == "SHN_UNDEF"
                            and symbol.name
                        ):
                            imports.append(symbol.name)

                # Count defined functions
                symtab = elf.get_section_by_name(".symtab")
                if symtab and isinstance(symtab, SymbolTableSection):
                    for symbol in symtab.iter_symbols():
                        if symbol.entry["st_info"]["type"] == "STT_FUNC":
                            function_count += 1
                elif dynsym and isinstance(dynsym, SymbolTableSection):
                    for symbol in dynsym.iter_symbols():
                        if (
                            symbol.entry["st_info"]["type"] == "STT_FUNC"
                            and symbol.entry["st_shndx"] != "SHN_UNDEF"
                        ):
                            function_count += 1

        except Exception as exc:
            logger.warning("Failed to parse ELF %s: %s", binary_path, exc)
            return {
                "binary_path": binary_path,
                "error": f"Failed to parse ELF: {exc}",
                "fuzzing_score": 0,
            }

        # Categorize imports
        found_sinks = [i for i in imports if i in DANGEROUS_SINKS]
        found_input = [i for i in imports if i in INPUT_FUNCTIONS]
        found_network = [i for i in imports if i in NETWORK_FUNCTIONS]

        # Get binary protections
        protections = check_binary_protections(full_path)

        # Calculate fuzzing score (0-100)
        score = 0

        # Input handling (25 pts)
        if found_input:
            score += min(25, len(found_input) * 5)

        # Dangerous sinks (30 pts)
        if found_sinks:
            score += min(30, len(found_sinks) * 5)

        # Weak protections (25 pts)
        if not protections.get("nx"):
            score += 8
        if protections.get("relro") == "none":
            score += 6
        if not protections.get("canary"):
            score += 6
        if not protections.get("pie"):
            score += 5

        # Network-facing (10 pts)
        if found_network:
            score += min(10, len(found_network) * 3)

        # Binary size / complexity (10 pts)
        file_size = os.path.getsize(full_path)
        if file_size > 100_000:
            score += 5
        if function_count > 50:
            score += 5

        # Determine recommended strategy
        if found_network:
            strategy = "network"
        elif any(f in imports for f in ("fopen", "open", "fread")):
            strategy = "file"
        elif any(f in imports for f in ("read", "fgets", "getline", "scanf")):
            strategy = "stdin"
        else:
            strategy = "stdin"

        return {
            "binary_path": binary_path,
            "fuzzing_score": min(100, score),
            "input_sources": found_input,
            "dangerous_functions": found_sinks,
            "network_functions": found_network,
            "protections": protections,
            "recommended_strategy": strategy,
            "function_count": function_count,
            "imports_of_interest": found_sinks + found_input + found_network,
            "file_size": file_size,
        }

    async def _count_active_campaigns(self, project_id: UUID) -> int:
        result = await self.db.scalar(
            select(func.count(FuzzingCampaign.id)).where(
                FuzzingCampaign.project_id == project_id,
                FuzzingCampaign.status.in_(["created", "running"]),
            )
        )
        return result or 0

    async def create_campaign(
        self,
        firmware: Firmware,
        binary_path: str,
        config: dict | None = None,
    ) -> FuzzingCampaign:
        """Create a new fuzzing campaign."""
        if not firmware.extracted_path:
            raise ValueError("Firmware has not been unpacked")

        binary_path, _ = self._resolve_target_file(firmware.extracted_path, binary_path)

        active = await self._count_active_campaigns(firmware.project_id)
        if active >= self._settings.fuzzing_max_campaigns:
            raise ValueError(
                f"Maximum concurrent campaigns ({self._settings.fuzzing_max_campaigns}) reached. "
                "Stop an existing campaign first."
            )

        campaign_config = {
            "timeout_per_exec": 1000,
            "memory_limit": 256,
            "dictionary": None,
            "seed_corpus": None,
            "arguments": None,
            "environment": None,
            "harness_script": None,
            "desock": False,
        }
        if config:
            campaign_config.update(config)

        campaign = FuzzingCampaign(
            project_id=firmware.project_id,
            firmware_id=firmware.id,
            binary_path=binary_path,
            status="created",
            config=campaign_config,
        )
        self.db.add(campaign)
        await self.db.flush()

        return campaign

    async def start_campaign(self, campaign_id: UUID, project_id: UUID) -> FuzzingCampaign:
        """Start a fuzzing campaign by spawning an AFL++ container."""
        result = await self.db.execute(
            select(FuzzingCampaign).where(
                FuzzingCampaign.id == campaign_id,
                FuzzingCampaign.project_id == project_id,
            )
        )
        campaign = result.scalar_one_or_none()
        if not campaign:
            raise ValueError("Campaign not found")

        if campaign.status not in ("created", "stopped"):
            raise ValueError(f"Campaign cannot be started (status: {campaign.status})")

        # Get firmware for paths
        fw_result = await self.db.execute(
            select(Firmware).where(Firmware.id == campaign.firmware_id)
        )
        firmware = fw_result.scalar_one_or_none()
        if not firmware or not firmware.extracted_path:
            raise ValueError("Firmware not found or not unpacked")

        settings = self._settings
        client = self._get_docker_client()

        # Resolve host path for read-only firmware mount; stage into ephemeral /firmware
        # inside the container so we can fix execute bits without mutating firmware_data.
        real_path = os.path.realpath(firmware.extracted_path)
        host_path = self._resolve_host_path(real_path)

        volumes = {}
        if host_path:
            volumes[host_path] = {"bind": "/firmware_src", "mode": "ro"}

        arch = self._normalize_arch(firmware.architecture)
        config = campaign.config or {}

        qemu_trace = QEMU_TRACE_MAP.get(arch)
        if not qemu_trace:
            raise ValueError(
                f"Unsupported architecture for fuzzing: {arch}. "
                f"Supported: {', '.join(QEMU_TRACE_MAP.keys())}"
            )

        container = None
        try:
            container = await asyncio.to_thread(
                client.containers.run,
                image=settings.fuzzing_image,
                command=["sleep", "infinity"],
                detach=True,
                volumes=volumes or None,
                mem_limit=f"{settings.fuzzing_memory_limit_mb}m",
                nano_cpus=int(settings.fuzzing_cpu_limit * 1e9),
                privileged=False,
                network_mode="none",
                labels={
                    "firmwareguard.campaign_id": str(campaign.id),
                    "firmwareguard.project_id": str(campaign.project_id),
                    "firmwareguard.type": "fuzzing",
                },
            )

            # Stage firmware rootfs into ephemeral /firmware inside the container
            if not host_path:
                await asyncio.to_thread(container.exec_run, ["mkdir", "-p", "/firmware"])
                await asyncio.to_thread(
                    EmulationService._copy_dir_to_container,
                    container,
                    real_path,
                    "/firmware",
                )
            else:
                copy_res = await asyncio.to_thread(
                    container.exec_run,
                    ["sh", "-c", "mkdir -p /firmware && cp -a /firmware_src/. /firmware/"],
                )
                if copy_res.exit_code != 0:
                    err_out = copy_res.output.decode("utf-8", errors="replace").strip()
                    raise RuntimeError(f"Failed to stage firmware copy: {err_out}")

            # Ensure target binary and shared libraries have execute bits
            binary_in_firmware = campaign.binary_path.lstrip("/")
            await asyncio.to_thread(
                container.exec_run,
                [
                    "sh", "-c",
                    f"chmod +x {shlex.quote('/firmware/' + binary_in_firmware)} 2>/dev/null || true; "
                    "mkdir -p /opt/fuzzing/input /opt/fuzzing/output /firmware/tmp /firmware/var/run",
                ],
            )

            # Verify target is a valid ELF binary unless a custom harness_script is used
            if not config.get("harness_script"):
                elf_check = await asyncio.to_thread(
                    container.exec_run,
                    [
                        "sh", "-c",
                        f"head -c 4 {shlex.quote('/firmware/' + binary_in_firmware)} | od -An -tx1 | tr -d ' \\n'",
                    ],
                )
                magic = elf_check.output.decode("utf-8", errors="replace").strip()
                if magic != "7f454c46":
                    raise ValueError(
                        f"Target '{campaign.binary_path}' is not an ELF executable (magic: {magic or 'empty'}). "
                        "AFL++ QEMU mode requires a compiled ELF binary (not a shell script or data file)."
                    )

            # Verify the arch-specific AFL++ QEMU trace binary exists in the image
            trace_check = await asyncio.to_thread(
                container.exec_run,
                ["test", "-x", f"/usr/local/bin/{qemu_trace}"],
            )
            if trace_check.exit_code != 0:
                raise RuntimeError(
                    f"AFL++ QEMU trace binary '/usr/local/bin/{qemu_trace}' is not installed "
                    f"in fuzzing image '{settings.fuzzing_image}' for architecture '{arch}'."
                )

            # Symlink the arch-specific trace binary so afl-fuzz -Q finds it
            await asyncio.to_thread(
                container.exec_run,
                [
                    "ln", "-sf",
                    f"/usr/local/bin/{qemu_trace}",
                    "/usr/local/bin/afl-qemu-trace",
                ],
            )

            # Write seed corpus using put_archive for binary-safe transfer
            seed_corpus = config.get("seed_corpus")
            if seed_corpus:
                await asyncio.to_thread(self._write_seeds_to_container, container, seed_corpus)
            else:
                await asyncio.to_thread(
                    self._write_seeds_to_container,
                    container,
                    [base64.b64encode(b"AAAA").decode()],
                )

            # Write dictionary if provided
            dictionary = config.get("dictionary")
            if dictionary:
                await asyncio.to_thread(
                    self._write_file_to_container,
                    container,
                    "/opt/fuzzing/dictionary.dict",
                    dictionary.encode("utf-8"),
                )

            # Write harness script if provided
            harness_script = config.get("harness_script")
            harness_target = None
            if harness_script:
                await asyncio.to_thread(
                    self._write_file_to_container,
                    container,
                    "/opt/fuzzing/harness.sh",
                    harness_script.encode("utf-8"),
                )
                await asyncio.to_thread(
                    container.exec_run, ["chmod", "+x", "/opt/fuzzing/harness.sh"]
                )
                harness_target = "/opt/fuzzing/harness.sh"

            # Write safely-quoted launcher script and start AFL++ in background
            launcher_script = self._build_afl_launcher_script(
                binary_path=campaign.binary_path,
                arch=arch,
                config=config,
                has_dictionary=bool(dictionary),
                harness_target=harness_target,
            )
            await asyncio.to_thread(
                self._write_file_to_container,
                container,
                "/opt/fuzzing/run_afl.sh",
                launcher_script.encode("utf-8"),
            )
            await asyncio.to_thread(
                container.exec_run, ["chmod", "+x", "/opt/fuzzing/run_afl.sh"]
            )

            await asyncio.to_thread(
                container.exec_run,
                [
                    "sh", "-c",
                    "nohup /opt/fuzzing/run_afl.sh > /opt/fuzzing/afl.log 2>&1 & "
                    "echo $! > /opt/fuzzing/afl.pid",
                ],
            )

            # Startup health check: wait up to 4s to catch immediate AFL++ startup errors
            # (bad binary, missing library, forkserver abort, invalid arguments, etc.)
            for _ in range(8):
                await asyncio.sleep(0.5)
                alive = await asyncio.to_thread(self._is_afl_running, container)
                if not alive:
                    afl_log = await asyncio.to_thread(self._read_afl_log, container)
                    summary = self._summarize_afl_error(afl_log)
                    raise RuntimeError(
                        f"{summary}\n\n"
                        f"--- AFL++ log ---\n{afl_log}"
                    )
                stats_ready = await asyncio.to_thread(
                    container.exec_run,
                    ["test", "-s", "/opt/fuzzing/output/default/fuzzer_stats"],
                )
                if stats_ready.exit_code == 0:
                    break

            campaign.container_id = container.id
            campaign.status = "running"
            campaign.error_message = None
            campaign.started_at = datetime.now(timezone.utc)
            campaign.stopped_at = None

        except Exception as exc:
            logger.exception("Failed to start fuzzing container")
            if container is not None:
                try:
                    await asyncio.to_thread(container.remove, force=True)
                except Exception:
                    logger.debug("Failed to remove fuzzing container on error", exc_info=True)
            campaign.container_id = None
            campaign.status = "error"
            campaign.error_message = str(exc)

        await self.db.flush()
        return campaign

    @staticmethod
    def _summarize_afl_error(afl_log: str) -> str:
        """Extract the primary PROGRAM ABORT / error line from an AFL++ log."""
        for line in afl_log.splitlines():
            stripped = line.strip()
            if "PROGRAM ABORT" in stripped:
                _, _, msg = stripped.partition("PROGRAM ABORT")
                msg = msg.lstrip(" :").strip()
                return f"AFL++ aborted: {msg}" if msg else "AFL++ aborted during startup."
            if stripped.startswith("[-] ") and "core_pattern" not in stripped:
                return f"AFL++ error: {stripped[4:].strip()}"
        return "AFL++ exited immediately during startup."

    @staticmethod
    def _is_afl_running(container: "docker.models.containers.Container") -> bool:
        """Return True if afl-fuzz is alive (and NOT a defunct zombie) inside the container.

        Because PID 1 is `sleep infinity`, an exited afl-fuzz child remains in the
        process table as a zombie (`Z` state), which still passes `kill -0` and `pgrep`.
        Checking `/proc/<pid>/stat` state explicitly distinguishes live vs zombie.
        """
        res = container.exec_run(
            [
                "sh", "-c",
                "PID=$(cat /opt/fuzzing/afl.pid 2>/dev/null); "
                "if [ -n \"$PID\" ] && [ -r \"/proc/$PID/stat\" ]; then "
                "  STATE=$(awk '{print $3}' \"/proc/$PID/stat\" 2>/dev/null); "
                "  [ \"$STATE\" != \"Z\" ] && [ \"$STATE\" != \"X\" ] && exit 0; "
                "  exit 1; "
                "fi; "
                "ps -eo stat=,comm= | awk '$2==\"afl-fuzz\" && $1 !~ /^Z/ {found=1} END{exit !found}'",
            ]
        )
        return res.exit_code == 0

    @staticmethod
    def _read_afl_log(
        container: "docker.models.containers.Container",
        max_bytes: int = 8000,
    ) -> str:
        """Read and sanitize /opt/fuzzing/afl.log from inside a container."""
        try:
            res = container.exec_run(["cat", "/opt/fuzzing/afl.log"])
            if res.exit_code != 0:
                return "(no AFL++ log available)"
            text = _ANSI_RE.sub("", res.output.decode("utf-8", errors="replace")).strip()
            if len(text) > max_bytes:
                text = "... [truncated]\n" + text[-max_bytes:]
            return text or "(AFL++ log is empty)"
        except Exception as exc:
            return f"(failed to read AFL++ log: {exc})"

    async def get_campaign_logs(
        self, campaign_id: UUID, project_id: UUID
    ) -> str:
        """Return AFL++ stdout/stderr logs for a campaign."""
        result = await self.db.execute(
            select(FuzzingCampaign).where(
                FuzzingCampaign.id == campaign_id,
                FuzzingCampaign.project_id == project_id,
            )
        )
        campaign = result.scalar_one_or_none()
        if not campaign:
            raise ValueError("Campaign not found")

        if not campaign.container_id:
            if campaign.error_message:
                return campaign.error_message
            return "No active container for this campaign — logs are only available while running."

        try:
            client = self._get_docker_client()
            container = await asyncio.to_thread(client.containers.get, campaign.container_id)
            return await asyncio.to_thread(self._read_afl_log, container)
        except docker.errors.NotFound:
            if campaign.error_message:
                return campaign.error_message
            return "Campaign container has been removed — no logs available."
        except Exception as exc:
            return f"Failed to read logs: {exc}"

    async def stop_campaign(self, campaign_id: UUID, project_id: UUID | None = None) -> FuzzingCampaign:
        """Stop a fuzzing campaign and clean up its container."""
        query = select(FuzzingCampaign).where(FuzzingCampaign.id == campaign_id)
        if project_id is not None:
            query = query.where(FuzzingCampaign.project_id == project_id)
        result = await self.db.execute(query)
        campaign = result.scalar_one_or_none()
        if not campaign:
            raise ValueError("Campaign not found")

        if campaign.status in ("stopped", "completed"):
            return campaign

        # Sync crashes and stats before stopping
        if campaign.container_id:
            if campaign.status == "running":
                try:
                    await self._sync_stats(campaign)
                    await self._sync_crashes(campaign)
                except Exception:
                    logger.warning("Failed to sync data before stopping campaign %s", campaign_id)

            def _stop_and_remove(cid: str) -> None:
                client = self._get_docker_client()
                container = client.containers.get(cid)
                container.stop(timeout=5)
                container.remove(force=True)

            try:
                await asyncio.to_thread(_stop_and_remove, campaign.container_id)
            except docker.errors.NotFound:
                logger.info("Container already removed: %s", campaign.container_id)
            except Exception:
                logger.exception("Error stopping container: %s", campaign.container_id)

        if campaign.status != "error":
            campaign.status = "stopped"
        campaign.container_id = None
        campaign.stopped_at = datetime.now(timezone.utc)
        await self.db.flush()
        return campaign

    async def get_campaign_status(self, campaign_id: UUID, project_id: UUID | None = None) -> FuzzingCampaign:
        """Get live status of a fuzzing campaign, updating stats from container."""
        query = select(FuzzingCampaign).where(FuzzingCampaign.id == campaign_id)
        if project_id is not None:
            query = query.where(FuzzingCampaign.project_id == project_id)
        result = await self.db.execute(query)
        campaign = result.scalar_one_or_none()
        if not campaign:
            raise ValueError("Campaign not found")

        if campaign.status == "running" and campaign.container_id:
            try:
                client = self._get_docker_client()
                container = await asyncio.to_thread(client.containers.get, campaign.container_id)

                if container.status != "running":
                    campaign.status = "error"
                    campaign.error_message = "Container exited unexpectedly"
                    campaign.stopped_at = datetime.now(timezone.utc)
                else:
                    await self._sync_stats(campaign)
                    await self._sync_crashes(campaign)

                    # Also verify the afl-fuzz process inside the container is still alive
                    afl_alive = await asyncio.to_thread(self._is_afl_running, container)
                    if not afl_alive:
                        afl_log = await asyncio.to_thread(self._read_afl_log, container)
                        summary = self._summarize_afl_error(afl_log)
                        campaign.status = "error"
                        campaign.error_message = (
                            f"{summary}\n\n"
                            f"--- AFL++ log ---\n{afl_log}"
                        )
                        campaign.stopped_at = datetime.now(timezone.utc)
                        try:
                            await asyncio.to_thread(container.remove, force=True)
                        except Exception:
                            pass
                        campaign.container_id = None

            except docker.errors.NotFound:
                campaign.status = "stopped"
                campaign.error_message = "Container no longer exists"
                campaign.container_id = None
                campaign.stopped_at = datetime.now(timezone.utc)
            except Exception:
                logger.exception("Error checking campaign status")

            await self.db.flush()

        return campaign

    async def _sync_stats(self, campaign: FuzzingCampaign) -> None:
        """Read AFL++ fuzzer_stats from the container and update the campaign."""
        if not campaign.container_id:
            return

        client = self._get_docker_client()
        try:
            container = await asyncio.to_thread(client.containers.get, campaign.container_id)
            result = await asyncio.to_thread(
                container.exec_run, ["cat", "/opt/fuzzing/output/default/fuzzer_stats"]
            )

            if result.exit_code != 0:
                return

            stats_text = result.output.decode("utf-8", errors="replace")
            stats = {}
            for line in stats_text.strip().split("\n"):
                if ":" in line:
                    key, _, value = line.partition(":")
                    key = key.strip()
                    value = value.strip()
                    # Parse numeric values
                    try:
                        if "." in value:
                            stats[key] = float(value)
                        else:
                            stats[key] = int(value)
                    except ValueError:
                        stats[key] = value

            campaign.stats = {
                "execs_per_sec": stats.get("execs_per_sec", 0),
                "total_execs": stats.get("execs_done", 0),
                "corpus_count": stats.get("corpus_count", stats.get("paths_total", 0)),
                "saved_crashes": stats.get("saved_crashes", stats.get("unique_crashes", 0)),
                "saved_hangs": stats.get("saved_hangs", stats.get("unique_hangs", 0)),
                "stability": stats.get("stability", "N/A"),
                "bitmap_cvg": stats.get("bitmap_cvg", "N/A"),
                "last_find": stats.get("last_find", 0),
                "run_time": stats.get("run_time", 0),
            }

        except docker.errors.NotFound:
            pass
        except Exception:
            logger.debug("Failed to sync stats for campaign %s", campaign.id)

    async def _sync_crashes(self, campaign: FuzzingCampaign) -> list[FuzzingCrash]:
        """Discover new crash files in the container and create DB records."""
        if not campaign.container_id:
            return []

        client = self._get_docker_client()
        new_crashes: list[FuzzingCrash] = []

        try:
            container = await asyncio.to_thread(client.containers.get, campaign.container_id)

            # List crash files
            result = await asyncio.to_thread(
                container.exec_run,
                [
                    "sh", "-c",
                    "ls -1 /opt/fuzzing/output/default/crashes/ 2>/dev/null | grep -v README.txt",
                ],
            )

            if result.exit_code != 0 or not result.output.strip():
                return []

            crash_files = result.output.decode("utf-8", errors="replace").strip().split("\n")

            # Get existing crash filenames for this campaign
            existing = await self.db.execute(
                select(FuzzingCrash.crash_filename).where(
                    FuzzingCrash.campaign_id == campaign.id
                )
            )
            existing_names = {row[0] for row in existing}

            for filename in crash_files:
                filename = filename.strip()
                if not filename or filename in existing_names:
                    continue

                # Read crash input bytes
                read_result = await asyncio.to_thread(
                    container.exec_run,
                    ["cat", f"/opt/fuzzing/output/default/crashes/{filename}"],
                )
                crash_data = read_result.output if read_result.exit_code == 0 else None

                crash = FuzzingCrash(
                    campaign_id=campaign.id,
                    crash_filename=filename,
                    crash_input=crash_data,
                    crash_size=len(crash_data) if crash_data else 0,
                )
                self.db.add(crash)
                new_crashes.append(crash)

            if new_crashes:
                campaign.crashes_count = (campaign.crashes_count or 0) + len(new_crashes)
                await self.db.flush()

        except docker.errors.NotFound:
            pass
        except Exception:
            logger.debug("Failed to sync crashes for campaign %s", campaign.id)

        return new_crashes

    async def triage_crash(
        self, campaign_id: UUID, crash_id: UUID, project_id: UUID
    ) -> FuzzingCrash:
        """Reproduce a crash under QEMU user mode and classify exploitability.

        For cross-architecture firmware binaries, GDB alone cannot execute the
        binary on x86_64.  Instead we:
          1. Run the binary under qemu-{arch}-static with the crash input,
             capturing the exit signal.
          2. Optionally attach gdb-multiarch via QEMU's GDB server for a
             stack trace (best-effort).
        """
        result = await self.db.execute(
            select(FuzzingCrash)
            .join(FuzzingCampaign, FuzzingCrash.campaign_id == FuzzingCampaign.id)
            .where(
                FuzzingCrash.id == crash_id,
                FuzzingCrash.campaign_id == campaign_id,
                FuzzingCampaign.project_id == project_id,
            )
        )
        crash = result.scalar_one_or_none()
        if not crash:
            raise ValueError("Crash not found")

        # Get campaign and firmware
        camp_result = await self.db.execute(
            select(FuzzingCampaign).where(FuzzingCampaign.id == campaign_id)
        )
        campaign = camp_result.scalar_one_or_none()
        if not campaign:
            raise ValueError("Campaign not found")

        fw_result = await self.db.execute(
            select(Firmware).where(Firmware.id == campaign.firmware_id)
        )
        firmware = fw_result.scalar_one_or_none()
        if not firmware or not firmware.extracted_path:
            raise ValueError("Firmware not found or not unpacked")

        arch = self._normalize_arch(firmware.architecture)
        qemu_bin = QEMU_USER_MAP.get(arch, "qemu-arm-static")
        config = campaign.config or {}
        binary_in_firmware = campaign.binary_path.lstrip("/")

        client = self._get_docker_client()
        container = None
        ephemeral = False

        if campaign.container_id:
            try:
                container = await asyncio.to_thread(client.containers.get, campaign.container_id)
                if container.status != "running":
                    container = None
            except docker.errors.NotFound:
                container = None

        # If the campaign was stopped, spin up a short-lived ephemeral container
        # using the persisted crash_input bytes from PostgreSQL so triage always works.
        if container is None:
            if not crash.crash_input:
                raise ValueError(
                    "Campaign container is stopped and crash input bytes were not saved"
                )
            ephemeral = True
            real_path = os.path.realpath(firmware.extracted_path)
            host_path = self._resolve_host_path(real_path)
            volumes = {host_path: {"bind": "/firmware_src", "mode": "ro"}} if host_path else None
            container = await asyncio.to_thread(
                client.containers.run,
                image=self._settings.fuzzing_image,
                command=["sleep", "infinity"],
                detach=True,
                volumes=volumes,
                mem_limit=f"{self._settings.fuzzing_memory_limit_mb}m",
                privileged=False,
                network_mode="none",
                labels={
                    "firmwareguard.campaign_id": str(campaign.id),
                    "firmwareguard.type": "fuzzing-triage",
                },
            )
            try:
                if host_path:
                    await asyncio.to_thread(
                        container.exec_run,
                        ["sh", "-c", "mkdir -p /firmware && cp -a /firmware_src/. /firmware/"],
                    )
                else:
                    await asyncio.to_thread(container.exec_run, ["mkdir", "-p", "/firmware"])
                    await asyncio.to_thread(
                        EmulationService._copy_dir_to_container, container, real_path, "/firmware"
                    )
                await asyncio.to_thread(
                    container.exec_run,
                    ["chmod", "+x", f"/firmware/{binary_in_firmware}"],
                )
            except Exception:
                await asyncio.to_thread(container.remove, force=True)
                raise

        triage_output = ""

        try:
            # Always write crash input to a clean path with no special chars
            crash_path = "/tmp/triage_input"
            if crash.crash_input is not None:
                await asyncio.to_thread(
                    self._write_file_to_container, container, crash_path, crash.crash_input
                )
            else:
                crash_path = f"/opt/fuzzing/output/default/crashes/{crash.crash_filename}"

            # Build env + target args matching the campaign configuration
            env_assignments = ["QEMU_LD_PREFIX=/firmware"]
            if config.get("desock", False):
                desock_lib = DESOCK_LIB_MAP.get(arch)
                if desock_lib:
                    env_assignments.append(f"QEMU_SET_ENV=LD_PRELOAD={desock_lib}")
            for k, v in (config.get("environment") or {}).items():
                if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", str(k)):
                    env_assignments.append(f"{k}={shlex.quote(str(v))}")
            env_str = " ".join(env_assignments)

            raw_args = config.get("arguments") or ""
            uses_file_arg = "@@" in raw_args
            arg_tokens = [
                crash_path if tok == "@@" else tok
                for tok in (shlex.split(raw_args) if raw_args else [])
            ]
            target_args_str = " ".join(shlex.quote(tok) for tok in arg_tokens)
            stdin_redir = "" if uses_file_arg else f"< {shlex.quote(crash_path)}"
            target_bin = shlex.quote(f"/firmware/{binary_in_firmware}")

            # Step 1: Reproduce the crash under QEMU user-mode to capture signal/exit code
            reproduce_cmd = (
                f"{env_str} timeout 20 {shlex.quote(qemu_bin)} "
                f"{target_bin} {target_args_str} {stdin_redir} 2>&1; echo EXIT_CODE=$?"
            )
            reproduce_result = await asyncio.to_thread(
                container.exec_run, ["sh", "-c", reproduce_cmd], demux=True
            )
            stdout = (reproduce_result.output[0] or b"").decode("utf-8", errors="replace")
            stderr = (reproduce_result.output[1] or b"").decode("utf-8", errors="replace")

            triage_output = f"=== QEMU reproduction ({qemu_bin}) ===\n{stdout}"
            if stderr:
                triage_output += f"\n--- stderr ---\n{stderr}"

            # Step 2: GDB remote debugging for stack trace & registers
            gdb_port = 12345
            GDB_ARCH_MAP = {
                "arm": ("arm", "little"),
                "aarch64": ("aarch64", "little"),
                "mips": ("mips", "big"),
                "mipsel": ("mips", "little"),
                "x86": ("i386", "little"),
                "x86_64": ("i386:x86-64", "little"),
            }
            gdb_arch, gdb_endian = GDB_ARCH_MAP.get(arch, ("arm", "little"))

            gdb_script = (
                f"{env_str} {shlex.quote(qemu_bin)} -g {gdb_port} "
                f"{target_bin} {target_args_str} {stdin_redir} >/dev/null 2>&1 &\n"
                "QPID=$!\n"
                "sleep 1\n"
                f"timeout 20 gdb-multiarch -batch "
                f'-ex "set confirm off" '
                f'-ex "set pagination off" '
                f'-ex "set architecture {gdb_arch}" '
                f'-ex "set endian {gdb_endian}" '
                f'-ex "target remote 127.0.0.1:{gdb_port}" '
                f'-ex "continue" '
                f'-ex "bt" '
                f'-ex "info registers" '
                f"{target_bin}\n"
                "kill $QPID 2>/dev/null || true\n"
            )
            gdb_result = await asyncio.to_thread(
                container.exec_run, ["sh", "-c", gdb_script], demux=True
            )
            gdb_stdout = (gdb_result.output[0] or b"").decode("utf-8", errors="replace")
            gdb_stderr = (gdb_result.output[1] or b"").decode("utf-8", errors="replace")

            if gdb_stdout.strip():
                triage_output += f"\n\n=== GDB backtrace ===\n{gdb_stdout}"
            if gdb_stderr.strip():
                triage_output += f"\n--- gdb stderr ---\n{gdb_stderr}"

            signal, exploitability = self._classify_crash(triage_output, crash.crash_filename)

            # Extract stack trace from GDB output
            stack_trace = ""
            in_bt = False
            for line in triage_output.split("\n"):
                if line.startswith("#"):
                    in_bt = True
                    stack_trace += line + "\n"
                elif in_bt and not line.strip():
                    break
                elif in_bt:
                    stack_trace += line + "\n"

            crash.signal = signal
            crash.exploitability = exploitability
            crash.stack_trace = stack_trace.strip() if stack_trace else None
            crash.triage_output = triage_output[:10000]  # cap at 10KB

        except Exception as exc:
            crash.triage_output = f"Triage failed: {exc}"
            crash.exploitability = "unknown"
        finally:
            if ephemeral and container is not None:
                try:
                    await asyncio.to_thread(container.remove, force=True)
                except Exception:
                    logger.debug("Failed to remove ephemeral triage container", exc_info=True)

        await self.db.flush()
        return crash

    async def list_campaigns(self, project_id: UUID) -> list[FuzzingCampaign]:
        """List all fuzzing campaigns for a project."""
        result = await self.db.execute(
            select(FuzzingCampaign)
            .where(FuzzingCampaign.project_id == project_id)
            .order_by(FuzzingCampaign.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_crashes(self, campaign_id: UUID, project_id: UUID) -> list[FuzzingCrash]:
        """List all crashes for a campaign, verifying project ownership."""
        result = await self.db.execute(
            select(FuzzingCrash)
            .join(FuzzingCampaign, FuzzingCrash.campaign_id == FuzzingCampaign.id)
            .where(
                FuzzingCrash.campaign_id == campaign_id,
                FuzzingCampaign.project_id == project_id,
            )
            .order_by(FuzzingCrash.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_crash_detail(
        self, campaign_id: UUID, crash_id: UUID, project_id: UUID
    ) -> FuzzingCrash:
        """Get a single crash with full details, verifying project ownership."""
        result = await self.db.execute(
            select(FuzzingCrash)
            .join(FuzzingCampaign, FuzzingCrash.campaign_id == FuzzingCampaign.id)
            .where(
                FuzzingCrash.id == crash_id,
                FuzzingCrash.campaign_id == campaign_id,
                FuzzingCampaign.project_id == project_id,
            )
        )
        crash = result.scalar_one_or_none()
        if not crash:
            raise ValueError("Crash not found")
        return crash

    async def cleanup_expired(self) -> int:
        """Stop campaigns that have exceeded the timeout. Returns count stopped."""
        timeout_minutes = self._settings.fuzzing_timeout_minutes
        cutoff = datetime.now(timezone.utc).timestamp() - (timeout_minutes * 60)

        result = await self.db.execute(
            select(FuzzingCampaign).where(
                FuzzingCampaign.status == "running",
                FuzzingCampaign.started_at.isnot(None),
            )
        )
        campaigns = result.scalars().all()
        count = 0

        for campaign in campaigns:
            if campaign.started_at and campaign.started_at.timestamp() < cutoff:
                try:
                    await self.stop_campaign(campaign.id)
                    count += 1
                except Exception:
                    logger.exception("Failed to stop expired campaign: %s", campaign.id)

        return count
