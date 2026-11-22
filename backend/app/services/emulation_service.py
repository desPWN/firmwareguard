"""Service for managing QEMU-based firmware emulation sessions.

Uses the Docker SDK to spawn isolated containers running QEMU in user-mode
(single binary chroot) or system-mode (full OS boot).
"""

import asyncio
import io
import logging
import os
import platform
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
from app.models.emulation_preset import EmulationPreset
from app.models.emulation_session import EmulationSession
from app.models.firmware import Firmware
from app.utils.sandbox import validate_path

logger = logging.getLogger(__name__)

# Map canonical architecture → QEMU user-mode binary
QEMU_USER_BIN_MAP: dict[str, str] = {
    "arm": "qemu-arm-static",
    "aarch64": "qemu-aarch64-static",
    "mips": "qemu-mips-static",
    "mipsel": "qemu-mipsel-static",
    "x86": "qemu-i386-static",
    "x86_64": "qemu-x86_64-static",
}

# Architecture aliases → canonical names used by QEMU
ARCH_ALIASES: dict[str, str] = {
    "arm": "arm",
    "armhf": "arm",
    "armel": "arm",
    "ARM": "arm",
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "mips": "mips",
    "MIPS": "mips",
    "mipsbe": "mips",
    "mipsel": "mipsel",
    "MIPS-LE": "mipsel",
    "mipsle": "mipsel",
    "x86": "x86",
    "i386": "x86",
    "i686": "x86",
    "x86_64": "x86_64",
    "amd64": "x86_64",
}

# binfmt_misc registration entries for each architecture.
# Format: ":name:type:offset:magic:mask:interpreter:flags"
# Flags: F = fix binary (kernel caches interpreter fd — works in chroots/containers)
#        P = preserve argv[0]
#        C = use caller's credentials
# The \x sequences are interpreted by the kernel's binfmt_misc parser, not the shell.
# Mask \xfe on e_type byte matches both ET_EXEC (2) and ET_DYN (3) for PIE support.
BINFMT_ENTRIES: dict[str, tuple[str, str]] = {
    "arm": (
        "qemu-arm",
        r":qemu-arm:M::\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        r"\x02\x00\x28\x00:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff"
        r"\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/qemu-arm-static:FPC",
    ),
    "aarch64": (
        "qemu-aarch64",
        r":qemu-aarch64:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00"
        r"\x00\x02\x00\xb7\x00:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff"
        r"\xff\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/qemu-aarch64-static:FPC",
    ),
    "mips": (
        "qemu-mips",
        r":qemu-mips:M::\x7fELF\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        r"\x00\x02\x00\x08:\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00"
        r"\x00\x00\x00\xff\xfe\xff\xff:/usr/bin/qemu-mips-static:FPC",
    ),
    "mipsel": (
        "qemu-mipsel",
        r":qemu-mipsel:M::\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00"
        r"\x00\x02\x00\x08\x00:\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00"
        r"\x00\x00\x00\x00\xfe\xff\xff\xff:/usr/bin/qemu-mipsel-static:FPC",
    ),
    "x86": (
        "qemu-i386",
        r":qemu-i386:M::\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        r"\x02\x00\x03\x00:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff"
        r"\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/qemu-i386-static:FPC",
    ),
    "x86_64": (
        "qemu-x86_64",
        r":qemu-x86_64:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00"
        r"\x00\x02\x00\x3e\x00:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff"
        r"\xff\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/qemu-x86_64-static:FPC",
    ),
}

# Detect host architecture so we can skip binfmt_misc for native binaries
_HOST_ARCH = ARCH_ALIASES.get(platform.machine())

# Regex to strip ANSI escape sequences, OSC sequences, and carriage returns
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07|\r")

# Regex to strip residual serial-exec markers that may leak through
_MARKER_RE = re.compile(r"FIRMWAREGUARD_(?:START|END)_FGE\w+")

# Regex to strip serial timeout markers with optional newline
_TIMEOUT_RE = re.compile(r"FIRMWAREGUARD_SERIAL_TIMEOUT\r?\n?")


def _validate_kernel_file(path: str) -> tuple[bool, str]:
    """Check whether a file looks like a valid kernel image by inspecting magic bytes.

    Returns (is_valid, reason) where reason describes what was detected or
    why the file was rejected.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return False, "file not found or unreadable"

    if size < 500_000:
        return False, f"too small ({size} bytes) — kernels are typically >500KB"

    try:
        with open(path, "rb") as f:
            header = f.read(64)
    except OSError:
        return False, "unable to read file"

    if len(header) < 4:
        return False, "file too short to identify"

    # ELF — must be ET_EXEC (vmlinux), not ET_DYN (shared lib)
    if header[:4] == b"\x7fELF":
        # e_type is at offset 16 (2 bytes). ET_EXEC = 2
        if len(header) >= 18:
            # Check both endiannesses (EI_DATA at offset 5: 1=LE, 2=BE)
            ei_data = header[5]
            if ei_data == 1:  # little-endian
                e_type = int.from_bytes(header[16:18], "little")
            else:
                e_type = int.from_bytes(header[16:18], "big")
            if e_type == 2:
                return True, "ELF executable (vmlinux)"
            return False, f"ELF file but type={e_type} (not ET_EXEC=2) — likely a shared library or firmware image"
        return False, "ELF header too short"

    # U-Boot uImage
    if header[:4] == b"\x27\x05\x19\x56":
        return True, "U-Boot uImage"

    # ARM zImage — magic at offset 0x24: 0x016f2818 (little-endian)
    if len(header) >= 0x28:
        arm_magic = header[0x24:0x28]
        if arm_magic == b"\x18\x28\x6f\x01":
            return True, "ARM zImage"

    # gzip-compressed (common for compressed kernels)
    if header[:2] == b"\x1f\x8b" and size > 500_000:
        return True, "gzip-compressed (possibly vmlinuz)"

    # LZMA-compressed
    if header[:3] == b"\x5d\x00\x00" and size > 500_000:
        return True, "LZMA-compressed (possibly vmlinuz)"

    return False, "unrecognized format — not ELF/uImage/zImage/gzip/LZMA"


class EmulationService:
    """Manages QEMU emulation session lifecycle via Docker containers."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self._settings = get_settings()

    def _get_docker_client(self) -> docker.DockerClient:
        """Create a Docker client (created per-call, not cached)."""
        return docker.from_env()

    def _normalize_arch(self, arch: str | None) -> str | None:
        if not arch:
            return None
        return ARCH_ALIASES.get(arch, arch.lower())

    @staticmethod
    def _normalize_binary_path(extracted_path: str, binary_path: str) -> str:
        """Validate and normalize a firmware-relative binary path.

        Handles common prefixes copied from File Explorer (e.g., `/rootfs/bin/busybox`,
        `squashfs-root/bin/busybox`) and uses lexical normalization + `lexists` so
        valid firmware-internal absolute symlinks (e.g., `/sbin/reboot -> /bin/busybox`)
        are not falsely rejected as host path traversal.
        """
        raw = binary_path.strip().replace("\\", "/")
        if not raw:
            raise ValueError("binary_path cannot be empty")

        root = os.path.normpath(os.path.realpath(extracted_path))
        root_base = os.path.basename(root)

        # Build candidate relative paths to try against extracted_path
        stripped = raw.lstrip("/")
        candidates = [stripped]
        for prefix in ("rootfs/", f"{root_base}/"):
            if stripped.startswith(prefix):
                candidates.append(stripped[len(prefix):])

        for rel in candidates:
            if not rel:
                continue
            # Lexical traversal check (never follow firmware-internal absolute symlinks)
            norm_rel = os.path.normpath("/" + rel).lstrip("/")
            if norm_rel in ("", ".") or norm_rel.startswith(".."):
                raise ValueError(f"Path traversal detected in binary_path: {binary_path}")

            full_path = os.path.normpath(os.path.join(root, norm_rel))
            if not (full_path == root or full_path.startswith(root + os.sep)):
                raise ValueError(f"Path traversal detected in binary_path: {binary_path}")

            if os.path.lexists(full_path):
                if os.path.isdir(full_path) and not os.path.islink(full_path):
                    raise ValueError(f"Binary path points to a directory, not a file: /{norm_rel}")
                return "/" + norm_rel

        raise ValueError(
            f"Binary not found in extracted firmware: {binary_path}. "
            "Use a path relative to the firmware rootfs (e.g., /bin/busybox or /usr/bin/httpd)."
        )

    def _ensure_binfmt_misc(self, arch: str) -> None:
        """Register binfmt_misc for the target architecture if not already present.

        Uses a short-lived privileged Docker container to register the QEMU
        user-mode interpreter with the kernel's binfmt_misc subsystem.  The
        ``F`` (fix binary) flag causes the kernel to cache the interpreter's
        file descriptor at registration time, so it works transparently inside
        chroots and containers — any execve() of a foreign-arch ELF is handled
        by the kernel without the binary needing to be accessible from the
        process's mount namespace.

        Docker containers see an empty ``/proc/sys/fs/binfmt_misc`` by default
        (it's not the host's mount), so the privileged container must first
        ``mount -t binfmt_misc`` to access the real kernel entries.

        This is a host-level operation (binfmt_misc is kernel-wide) and
        persists until the host reboots or the entry is explicitly removed.
        A flag file in ``/tmp`` avoids re-running the privileged container
        on every emulation start within the same backend container lifetime.

        Failures are logged as warnings but never raised — user-mode
        emulation still works for the initial shell; only child processes
        would fail with "Exec format error".
        """
        # Skip for the host's native architecture — the kernel handles it
        if arch == _HOST_ARCH:
            logger.debug("Skipping binfmt_misc for native architecture: %s", arch)
            return

        entry = BINFMT_ENTRIES.get(arch)
        if not entry:
            logger.debug("No binfmt_misc entry defined for architecture: %s", arch)
            return

        binfmt_name, registration = entry

        # Check local flag file — avoids running a privileged container on
        # every emulation start.  The flag persists within this backend
        # container's lifetime (cleared on container restart).
        flag_file = f"/tmp/.binfmt_registered_{binfmt_name}"
        if os.path.exists(flag_file):
            logger.debug("binfmt_misc already registered (cached): %s", binfmt_name)
            return

        logger.info(
            "Registering binfmt_misc for %s (requires privileged container)...",
            binfmt_name,
        )

        client = self._get_docker_client()
        try:
            # Run a short-lived privileged container that:
            # 1. Mounts binfmt_misc (Docker containers don't see the host's mount)
            # 2. Checks if the entry already exists (idempotent)
            # 3. Registers if needed
            # Must be privileged because Docker's default seccomp profile blocks
            # writes to /proc/sys even with the SYS_ADMIN capability.
            # The F flag causes the kernel to open /usr/bin/qemu-{arch}-static
            # from within this container's filesystem and cache the fd.
            result = client.containers.run(
                image=self._settings.emulation_image,
                command=[
                    "sh", "-c",
                    "mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc 2>/dev/null; "
                    f"if [ -f /proc/sys/fs/binfmt_misc/{binfmt_name} ]; then "
                    "echo ALREADY_REGISTERED; "
                    "else "
                    f"echo '{registration}' > /proc/sys/fs/binfmt_misc/register 2>&1 "
                    "&& echo REGISTERED || echo FAILED; "
                    "fi",
                ],
                remove=True,
                privileged=True,
            )

            output = result.decode("utf-8", errors="replace").strip()

            if "REGISTERED" in output or "ALREADY_REGISTERED" in output:
                # Create flag file so subsequent calls skip the privileged container
                try:
                    with open(flag_file, "w") as f:
                        f.write("1")
                except OSError:
                    pass  # Non-critical — just means we'll check again next time
                logger.info("binfmt_misc for %s: %s", binfmt_name, output)
            else:
                logger.warning(
                    "binfmt_misc registration for %s returned unexpected output: %s",
                    binfmt_name,
                    output,
                )
        except Exception as exc:
            logger.warning(
                "Could not register binfmt_misc for %s: %s. "
                "Child processes in user-mode emulation may fail with 'Exec format error'. "
                "To fix manually: docker run --rm --privileged multiarch/qemu-user-static --reset -p yes",
                binfmt_name,
                exc,
            )

    async def _count_active_sessions(self, project_id: UUID) -> int:
        result = await self.db.scalar(
            select(func.count(EmulationSession.id)).where(
                EmulationSession.project_id == project_id,
                EmulationSession.status.in_(["created", "starting", "running"]),
            )
        )
        return result or 0

    async def start_session(
        self,
        firmware: Firmware,
        mode: str,
        binary_path: str | None = None,
        arguments: str | None = None,
        port_forwards: list[dict] | None = None,
        kernel_name: str | None = None,
        init_path: str | None = None,
        pre_init_script: str | None = None,
        stub_profile: str = "none",
    ) -> EmulationSession:
        """Start a new emulation session.

        Args:
            firmware: The firmware record (must have extracted_path).
            mode: "user" or "system".
            binary_path: For user mode — path to the binary within the extracted FS.
            arguments: Optional CLI arguments for user mode.
            port_forwards: List of {"host": int, "guest": int} dicts.
            kernel_name: Specific kernel to use for system mode.
            init_path: Override init binary for system mode (e.g., "/bin/sh").
            pre_init_script: Shell script to run before firmware init (system mode).
            stub_profile: Stub library profile ("none", "generic", "tenda").
        """
        if mode not in ("user", "system"):
            raise ValueError("mode must be 'user' or 'system'")

        if not firmware.extracted_path:
            raise ValueError("Firmware has not been unpacked")

        if mode == "user" and not binary_path:
            raise ValueError("binary_path is required for user-mode emulation")

        # Validate and normalize binary_path against extracted root
        if binary_path:
            binary_path = self._normalize_binary_path(firmware.extracted_path, binary_path)

        # Check concurrent session limit
        active = await self._count_active_sessions(firmware.project_id)
        if active >= self._settings.emulation_max_sessions:
            raise ValueError(
                f"Maximum concurrent sessions ({self._settings.emulation_max_sessions}) reached. "
                "Stop an existing session first."
            )

        arch = self._normalize_arch(firmware.architecture)
        if not arch:
            raise ValueError(
                "Cannot determine firmware architecture. "
                "Architecture detection must complete before emulation."
            )

        # Create DB record
        session = EmulationSession(
            project_id=firmware.project_id,
            firmware_id=firmware.id,
            mode=mode,
            status="starting",
            binary_path=binary_path,
            arguments=arguments,
            architecture=arch,
            port_forwards=port_forwards or [],
        )
        self.db.add(session)
        await self.db.flush()

        # Start Docker container
        try:
            container_id = await self._start_container(
                session=session,
                extracted_path=firmware.extracted_path,
                kernel_name=kernel_name,
                firmware_kernel_path=firmware.kernel_path,
                init_path=init_path,
                pre_init_script=pre_init_script,
                stub_profile=stub_profile,
            )
            session.container_id = container_id
            session.status = "running"
            session.started_at = datetime.now(timezone.utc)
        except Exception as exc:
            logger.exception("Failed to start emulation container")
            session.status = "error"
            session.error_message = str(exc)

        await self.db.flush()
        return session

    def _resolve_host_path(self, container_path: str) -> str | None:
        """Resolve a path inside this container to a host path for Docker mounts.

        When the backend runs inside Docker and uses the Docker socket, volume
        mounts reference HOST paths, not container paths. This method inspects
        our own container's mounts to translate paths.

        If not running in Docker, returns the path as-is.
        Returns None if the path is not on any mount (baked into image).
        """
        real_path = os.path.realpath(container_path)

        # Not running in Docker — path is already a host path
        if not os.path.exists("/.dockerenv"):
            return real_path

        client = self._get_docker_client()

        # Find our own container by hostname (Docker sets HOSTNAME to container ID)
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

                # Check if our path falls under this mount
                if real_path.startswith(dest + os.sep) or real_path == dest:
                    relative = os.path.relpath(real_path, dest)
                    host_path = os.path.join(source, relative)
                    logger.info(
                        "Path translation: %s -> %s (via mount %s -> %s)",
                        real_path, host_path, source, dest,
                    )
                    return host_path

        except Exception:
            logger.warning(
                "Could not inspect own container for path translation: %s",
                real_path,
            )

        # Path is not on any Docker mount — baked into the container image
        return None

    @staticmethod
    def _copy_dir_to_container(
        container: "docker.models.containers.Container",
        src_path: str,
        dst_path: str,
    ) -> None:
        """Copy a directory tree into a running container using put_archive.

        Creates a tar archive of src_path contents and streams it into
        dst_path inside the container.
        """
        import io
        import tarfile

        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            # Add all files from src_path, with arcname="" so they land
            # directly in dst_path (not in a subdirectory)
            for entry in os.scandir(src_path):
                tar.add(entry.path, arcname=entry.name)
        tar_stream.seek(0)

        container.put_archive(dst_path, tar_stream)

    @staticmethod
    def _copy_file_to_container(
        container: "docker.models.containers.Container",
        src_path: str,
        dst_path: str,
    ) -> None:
        """Copy a single file into a running container using put_archive."""
        import io
        import tarfile

        dst_dir = os.path.dirname(dst_path)
        dst_name = os.path.basename(dst_path)

        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            tar.add(src_path, arcname=dst_name)
        tar_stream.seek(0)

        container.put_archive(dst_dir, tar_stream)

    @staticmethod
    def _fix_firmware_permissions(
        container: "docker.models.containers.Container",
    ) -> None:
        """Fix execute permissions and broken symlinks in firmware.

        Binwalk extraction often loses execute bits and corrupts symlinks
        (replacing them with small files containing the original symlink
        target as text, or just null bytes). This method:
        1. Makes files in common binary/library directories executable.
        2. Restores corrupted symlinks across the entire firmware tree by
           reading small file contents to recover the original target path.
        3. Falls back to heuristics for .so versioned libraries and busybox.
        """
        bin_dirs = [
            "/firmware/bin", "/firmware/sbin",
            "/firmware/usr/bin", "/firmware/usr/sbin",
            "/firmware/lib", "/firmware/usr/lib",
            "/firmware/lib32", "/firmware/usr/lib32",
        ]
        for d in bin_dirs:
            container.exec_run(
                ["sh", "-c", f"[ -d {d} ] && chmod -R +x {d} 2>/dev/null || true"]
            )

        # Generic symlink restoration script.
        # Binwalk corruption patterns:
        #   a) Small file whose content IS the symlink target (as text, possibly null-padded)
        #   b) Small file of pure null bytes (target lost — need heuristics)
        #
        # Strategy:
        #   Pass 1: Scan ONLY binary/library directories (never /etc or config dirs!)
        #           for small non-ELF, non-script files whose content resolves to an
        #           existing file inside /firmware.
        #   Pass 2: Fix remaining .so stubs using versioned-name matching.
        #   Pass 3: Fix remaining null stubs in bin/sbin using busybox (if present).
        fix_symlinks_script = r"""
FIXED=0
PASS1=0
PASS2=0
PASS3=0

# --- Pass 1: Content-based symlink recovery (scoped to bin/lib dirs only) ---
# Only touches files inside binary/library directories (and top-level init/linuxrc)
# and verifies the resolved target exists inside /firmware so small config files
# or scripts are never turned into broken symlinks.
for search_target in \
    /firmware/bin /firmware/sbin \
    /firmware/usr/bin /firmware/usr/sbin \
    /firmware/lib /firmware/usr/lib \
    /firmware/lib32 /firmware/usr/lib32 \
    /firmware/linuxrc /firmware/init; do
    [ -e "$search_target" ] || continue
    find "$search_target" -type f -size -256c 2>/dev/null | while read stub; do
        # Never touch shell scripts (#!) or ELF binaries (\x7fELF)
        magic=$(head -c 4 "$stub" 2>/dev/null | od -An -tx1 | tr -d ' \n')
        case "$magic" in
            7f454c46*|2321*) continue ;;
        esac

        # Read file content, strip null bytes and whitespace
        target=$(tr -d '\000' < "$stub" 2>/dev/null | tr -d '\r\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [ -z "$target" ] && continue

        case "$target" in
            /*|./*|../*)
                ;;
            *)
                case "$target" in
                    *[[:space:]]*|*[^a-zA-Z0-9._-]*) continue ;;
                esac
                [ ${#target} -gt 64 ] && continue
                ;;
        esac

        # Don't create circular symlinks
        stubname=$(basename "$stub")
        targetname=$(basename "$target")
        [ "$stubname" = "$targetname" ] && [ "$target" = "$targetname" ] && continue

        # Verify the target actually exists inside /firmware before replacing
        stubdir=$(dirname "$stub")
        case "$target" in
            /*) resolved="/firmware${target}" ;;
            *)  resolved="${stubdir}/${target}" ;;
        esac
        [ -e "$resolved" ] || [ -L "$resolved" ] || continue

        rm -f "$stub"
        ln -s "$target" "$stub"
        PASS1=$((PASS1 + 1))
    done
done

# --- Pass 2: Versioned .so heuristic for remaining stubs ---
# Some corrupted .so stubs may have been pure null (no readable target).
# Match libfoo.so -> libfoo.so.X.Y.Z by name pattern.
for dir in /firmware/lib /firmware/usr/lib /firmware/lib32 /firmware/usr/lib32; do
    [ -d "$dir" ] || continue
    for stub in $(find "$dir" -maxdepth 1 \( -name '*.so' -o -name '*.so.[0-9]*' \) 2>/dev/null); do
        # Skip if already a symlink (fixed in pass 1)
        [ -L "$stub" ] && continue
        [ -f "$stub" ] || continue
        size=$(stat -c%s "$stub" 2>/dev/null || echo 999999)
        [ "$size" -lt 256 ] || continue
        base=$(basename "$stub")
        best=""
        best_len=0
        for candidate in "$dir"/${base}*; do
            [ -f "$candidate" ] || [ -L "$candidate" ] || continue
            cand_name=$(basename "$candidate")
            [ "$cand_name" = "$base" ] && continue
            cand_size=$(stat -c%s "$candidate" 2>/dev/null || echo 0)
            [ "$cand_size" -gt 256 ] || [ -L "$candidate" ] || continue
            cand_len=${#cand_name}
            if [ "$cand_len" -gt "$best_len" ]; then
                best="$cand_name"
                best_len=$cand_len
            fi
        done
        if [ -n "$best" ]; then
            rm -f "$stub"
            ln -s "$best" "$stub"
            PASS2=$((PASS2 + 1))
        fi
    done
done

# --- Pass 3: Busybox fallback for remaining null stubs ---
# Only applies to files in bin/sbin dirs that are still tiny and not
# yet symlinks. This is the last resort for pure-null stubs.
bb=""
for candidate in /firmware/bin/busybox /firmware/usr/bin/busybox; do
    if [ -f "$candidate" ] && [ ! -L "$candidate" ]; then
        cand_size=$(stat -c%s "$candidate" 2>/dev/null || echo 0)
        if [ "$cand_size" -gt 1000 ]; then
            # Strip /firmware prefix so symlinks work as both chroot
            # and ext4 root paths
            bb="${candidate#/firmware}"
            break
        fi
    fi
done
if [ -n "$bb" ]; then
    for dir in /firmware/bin /firmware/sbin /firmware/usr/bin /firmware/usr/sbin; do
        [ -d "$dir" ] || continue
        for stub in "$dir"/*; do
            # Skip symlinks (already fixed) and directories
            [ -L "$stub" ] && continue
            [ -f "$stub" ] || continue
            size=$(stat -c%s "$stub" 2>/dev/null || echo 999999)
            [ "$size" -lt 64 ] || continue
            name=$(basename "$stub")
            [ "$name" = "busybox" ] && continue
            # Verify it's actually null/empty content (not a real tiny script)
            content=$(tr -d '\000' < "$stub" 2>/dev/null)
            [ -z "$content" ] || continue
            rm -f "$stub"
            ln -s "$bb" "$stub"
            PASS3=$((PASS3 + 1))
        done
    done
fi

echo "Symlink repair: pass1=$PASS1 pass2=$PASS2 pass3=$PASS3"
"""
        result = container.exec_run(["sh", "-c", fix_symlinks_script])
        output = result.output.decode("utf-8", errors="replace").strip()
        if output:
            logger.info("Firmware symlink repair: %s", output)

    @staticmethod
    def _put_file_in_container(
        container: "docker.models.containers.Container",
        path: str,
        content: str,
        mode: int = 0o755,
    ) -> None:
        """Write a file into a Docker container using put_archive.

        This avoids heredoc/shell escaping issues that can corrupt file content
        when using container.exec_run with 'cat << EOF'.
        """
        filename = os.path.basename(path)
        directory = os.path.dirname(path)

        data = content.encode("utf-8")
        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            info = tarfile.TarInfo(name=filename)
            info.size = len(data)
            info.mode = mode
            tar.addfile(info, io.BytesIO(data))
        tar_stream.seek(0)
        container.put_archive(directory, tar_stream)

    # Map stub profile + architecture → list of .so filenames to inject
    STUB_PROFILE_MAP: dict[str, dict[str, list[str]]] = {
        "none": {},
        "generic": {
            "mipsel": ["stubs_generic_mipsel.so"],
            "mips": ["stubs_generic_mips.so"],
            "arm": ["stubs_generic_arm.so"],
            "aarch64": ["stubs_generic_aarch64.so"],
        },
        "tenda": {
            "mipsel": ["stubs_generic_mipsel.so", "stubs_tenda_mipsel.so"],
            "mips": ["stubs_generic_mips.so", "stubs_tenda_mips.so"],
            "arm": ["stubs_generic_arm.so", "stubs_tenda_arm.so"],
            "aarch64": ["stubs_generic_aarch64.so", "stubs_tenda_aarch64.so"],
        },
    }

    @staticmethod
    def _inject_stub_libraries(
        container: "docker.models.containers.Container",
        architecture: str | None,
        stub_profile: str = "none",
    ) -> None:
        """Copy arch-matched LD_PRELOAD stub libraries into the firmware rootfs.

        Pre-compiled stubs live in /opt/stubs/ inside the emulation container.
        Based on the stub_profile, copies the appropriate .so files into
        /firmware/opt/stubs/ so they're available inside the emulated firmware.

        Profiles:
          - "none": no stubs injected
          - "generic": MTD flash + wireless ioctl stubs
          - "tenda": generic + Tenda-specific function stubs
        """
        if stub_profile == "none" or not architecture:
            if stub_profile != "none":
                logger.debug("No architecture for stub injection, skipping")
            return

        arch_map = EmulationService.STUB_PROFILE_MAP.get(stub_profile, {})
        stub_files = arch_map.get(architecture, [])
        if not stub_files:
            logger.debug(
                "No stub libraries for profile=%s arch=%s", stub_profile, architecture
            )
            return

        # Build shell command to copy all stubs
        copy_cmds = ["mkdir -p /firmware/opt/stubs"]
        for stub_file in stub_files:
            copy_cmds.append(
                f"if [ -f /opt/stubs/{stub_file} ]; then "
                f"cp /opt/stubs/{stub_file} /firmware/opt/stubs/{stub_file} && "
                f"chmod 755 /firmware/opt/stubs/{stub_file} && "
                f"echo 'OK: {stub_file}'; else echo 'MISSING: {stub_file}'; fi"
            )

        result = container.exec_run(["sh", "-c", " && ".join(copy_cmds)])
        output = result.output.decode("utf-8", errors="replace").strip()
        for line in output.splitlines():
            if line.startswith("OK:"):
                logger.info("Injected stub: %s", line[4:].strip())
            elif line.startswith("MISSING:"):
                logger.warning("Stub not found in container: %s", line[9:].strip())

    def _find_initrd(
        self,
        kernel_path: str | None,
        kernel_name: str | None = None,
    ) -> str | None:
        """Find the initrd/initramfs companion for a kernel.

        Checks the kernel service sidecar metadata and convention-based
        naming (<kernel>.initrd).
        """
        from app.services.kernel_service import KernelService

        if not kernel_path:
            return None

        svc = KernelService()

        # If kernel_name was specified, check sidecar directly
        if kernel_name:
            initrd = svc._initrd_path(kernel_name)
            if initrd:
                return initrd

        # Try convention: look for <kernel_basename>.initrd in the kernel dir
        kernel_basename = os.path.basename(kernel_path)
        initrd = svc._initrd_path(kernel_basename)
        if initrd:
            return initrd

        return None

    def _find_dtb(
        self,
        kernel_path: str | None,
        kernel_name: str | None = None,
    ) -> str | None:
        """Find the companion DTB (Device Tree Blob) for a kernel."""
        from app.services.kernel_service import KernelService

        if not kernel_path:
            return None

        svc = KernelService()

        if kernel_name:
            dtb = svc._dtb_path(kernel_name)
            if dtb:
                return dtb

        kernel_basename = os.path.basename(kernel_path)
        dtb = svc._dtb_path(kernel_basename)
        if dtb:
            return dtb

        return None

    @staticmethod
    def _prepare_system_rootfs(
        container: "docker.models.containers.Container",
        stub_profile: str = "none",
    ) -> str:
        """Prepare /firmware inside the container BEFORE mkfs.ext4 runs.

        Runs with the emulation container's full Debian GNU toolchain (`sed`,
        `readlink`, `mkdir`, `cp`) so minimal router BusyBox guests (e.g.,
        BusyBox v1.01 msh without `sed`, `mkdir`, or `readlink`) still boot
        directly into an interactive root shell on the serial console.

        Returns a space-separated string of guest `/opt/stubs/stubs_*.so` paths
        to export via LD_PRELOAD (empty string if stub_profile == "none").
        """
        prep_script = r"""
set -u

# 1. Replace broken /dev/null directory symlinks produced by binwalk
for lnk in /firmware/etc /firmware/home /firmware/root /firmware/webroot /firmware/debug; do
    if [ -L "$lnk" ] && [ "$(readlink "$lnk" 2>/dev/null)" = "/dev/null" ]; then
        rm -f "$lnk"
        mkdir -p "$lnk"
        echo "Fixed broken symlink: $lnk"
    fi
done

# 2. Populate writable dirs from read-only counterparts (/etc_ro -> /etc, /webroot_ro -> /webroot)
for rodir in /firmware/etc_ro /firmware/webroot_ro; do
    target="${rodir%_ro}"
    if [ -d "$rodir" ] && [ -d "$target" ]; then
        cp -an "$rodir"/. "$target"/ 2>/dev/null || cp -a "$rodir"/* "$target"/ 2>/dev/null || true
        echo "Populated $target from $rodir"
    fi
done

# 3. Remove dangling /dev/null symlinks inside key directories
for dir in /firmware/etc /firmware/webroot /firmware/webroot_ro /firmware/home /firmware/root; do
    [ -d "$dir" ] || continue
    for f in "$dir"/*; do
        [ -L "$f" ] && [ "$(readlink "$f" 2>/dev/null)" = "/dev/null" ] && rm -f "$f"
    done
done

# 4. Ensure essential mountpoints and runtime dirs exist (guest may lack mkdir)
mkdir -p /firmware/proc /firmware/sys /firmware/dev /firmware/tmp /firmware/tmp/cores /firmware/var/run 2>/dev/null || true

# 5. Patch root password & inittab so serial console opens a root shell directly
#    without blocking on login: prompts, sulogin, or askfirst prompts.
for d in /firmware/etc /firmware/etc_ro; do
    [ -d "$d" ] || continue
    if [ -f "$d/passwd" ] && [ ! -L "$d/passwd" ]; then
        sed -i 's|^root:[^:]*:|root::|' "$d/passwd" 2>/dev/null || true
    fi
    if [ -f "$d/shadow" ] && [ ! -L "$d/shadow" ]; then
        sed -i 's|^root:[^:]*:|root::|' "$d/shadow" 2>/dev/null || true
    fi
    if [ -f "$d/inittab" ] && [ ! -L "$d/inittab" ]; then
        sed -i -E 's#(/sbin/sulogin|/sbin/getty[^:]*|/bin/getty[^:]*|/sbin/agetty[^:]*|/bin/login[^:]*|/usr/bin/login[^:]*)#/bin/sh#g' "$d/inittab" 2>/dev/null || true
        sed -i 's|:askfirst:|:respawn:|g' "$d/inittab" 2>/dev/null || true
    fi
done
"""
        res = container.exec_run(["bash", "-c", prep_script])
        out = res.output.decode("utf-8", errors="replace").strip()
        if out:
            logger.info("Host-side system rootfs prep: %s", out)

        if stub_profile == "none":
            return ""

        stub_res = container.exec_run(
            ["sh", "-c", "ls /firmware/opt/stubs/stubs_*.so 2>/dev/null | sed 's|^/firmware||' | tr '\\n' ' '"]
        )
        return stub_res.output.decode("utf-8", errors="replace").strip()

    @staticmethod
    def _generate_init_wrapper(
        original_init: str | None = None,
        pre_init_script: str | None = None,
        stub_profile: str = "none",
        stub_paths: str = "",
    ) -> str:
        """Generate a minimal, Bourne/msh-safe init wrapper script for system mode.

        Strictly avoids POSIX/bash extensions (`$(...)`, `${var%...}`, `command -v`,
        `sed`, `mkdir`, `sleep`, `export VAR=VAL`) so it works identically on ancient
        BusyBox v1.01 `msh` as well as modern `ash`/`dash`/`bash`.
        """
        if original_init:
            exec_line = f"exec {original_init}"
        else:
            exec_line = (
                "for candidate in /sbin/init /etc/preinit /sbin/procd /init /linuxrc; do\n"
                '    if [ -x "$candidate" ] || [ -L "$candidate" ]; then\n'
                '        exec "$candidate"\n'
                "    fi\n"
                "done\n"
                'echo "[firmwareguard] No init found, dropping to shell"\n'
                "exec /bin/sh"
            )

        pre_init_block = ""
        if pre_init_script:
            pre_init_block = (
                "\n# User pre-init script\n"
                "if [ -f /firmwareguard_pre_init.sh ]; then\n"
                '    echo "[firmwareguard] Running pre-init script..."\n'
                "    chmod +x /firmwareguard_pre_init.sh 2>/dev/null\n"
                "    . /firmwareguard_pre_init.sh\n"
                '    echo "[firmwareguard] Pre-init script finished (exit=$?)"\n'
                "fi\n"
            )

        stub_block = ""
        if stub_profile != "none" and stub_paths:
            stub_block = (
                "\n# Export LD_PRELOAD for injected stub libraries\n"
                f'LD_PRELOAD="{stub_paths}"\n'
                "export LD_PRELOAD\n"
                f'echo "[firmwareguard] LD_PRELOAD set: {stub_paths}"\n'
            )

        return (
            "#!/bin/sh\n"
            "# FirmwareGuard emulation init wrapper (Bourne/msh compatible)\n"
            'echo "[firmwareguard] Init wrapper starting..."\n'
            "\n"
            "# Mount essential virtual filesystems\n"
            "mount -t proc proc /proc 2>/dev/null\n"
            "mount -t sysfs sysfs /sys 2>/dev/null\n"
            "[ -c /dev/null ] || mount -t devtmpfs devtmpfs /dev 2>/dev/null\n"
            "mount -t tmpfs tmpfs /tmp 2>/dev/null\n"
            "mount -t tmpfs tmpfs /var/run 2>/dev/null\n"
            "\n"
            "# Configure QEMU user-mode networking (10.0.2.0/24)\n"
            "if [ -x /sbin/ifconfig ]; then\n"
            "    /sbin/ifconfig lo 127.0.0.1 up 2>/dev/null\n"
            "    /sbin/ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up 2>/dev/null\n"
            "elif [ -x /bin/ifconfig ]; then\n"
            "    /bin/ifconfig lo 127.0.0.1 up 2>/dev/null\n"
            "    /bin/ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up 2>/dev/null\n"
            "elif [ -x /sbin/ip ]; then\n"
            "    /sbin/ip link set lo up 2>/dev/null\n"
            "    /sbin/ip addr add 10.0.2.15/24 dev eth0 2>/dev/null\n"
            "    /sbin/ip link set eth0 up 2>/dev/null\n"
            "    /sbin/ip route add default via 10.0.2.2 2>/dev/null\n"
            "elif [ -x /bin/ip ]; then\n"
            "    /bin/ip link set lo up 2>/dev/null\n"
            "    /bin/ip addr add 10.0.2.15/24 dev eth0 2>/dev/null\n"
            "    /bin/ip link set eth0 up 2>/dev/null\n"
            "    /bin/ip route add default via 10.0.2.2 2>/dev/null\n"
            "fi\n"
            "if [ -x /sbin/route ]; then\n"
            "    /sbin/route add default gw 10.0.2.2 2>/dev/null\n"
            "elif [ -x /bin/route ]; then\n"
            "    /bin/route add default gw 10.0.2.2 2>/dev/null\n"
            "fi\n"
            f"{pre_init_block}"
            "\n"
            "# Enable core dumps for crash analysis\n"
            "if [ -d /proc/sys/kernel ]; then\n"
            '    echo "/tmp/cores/core.%e.%p" > /proc/sys/kernel/core_pattern 2>/dev/null\n'
            "fi\n"
            f"{stub_block}"
            'echo "[firmwareguard] Starting firmware init..."\n'
            f"{exec_line}\n"
        )

    @staticmethod
    def _inject_init_wrapper(
        container: "docker.models.containers.Container",
        init_path: str | None = None,
        pre_init_script: str | None = None,
        stub_profile: str = "none",
        stub_paths: str = "",
    ) -> str:
        """Inject the FirmwareGuard init wrapper into the firmware rootfs.

        Writes /firmware/firmwareguard_init.sh (and optionally /firmware/firmwareguard_pre_init.sh)
        into the container's ephemeral firmware directory. These files are included
        in the ext4 rootfs image created by start-system-mode.sh.

        Returns the init_path to pass to start-system-mode.sh ("/firmwareguard_init.sh").
        """
        wrapper = EmulationService._generate_init_wrapper(
            init_path,
            pre_init_script,
            stub_profile=stub_profile,
            stub_paths=stub_paths,
        )

        # Write scripts into the container using put_archive (avoids heredoc/escaping issues)
        EmulationService._put_file_in_container(container, "/firmware/firmwareguard_init.sh", wrapper)

        # Write the pre-init script if provided
        if pre_init_script:
            EmulationService._put_file_in_container(container, "/firmware/firmwareguard_pre_init.sh", pre_init_script)
            logger.info("Injected pre-init script (%d bytes)", len(pre_init_script))

        logger.info(
            "Injected init wrapper (original_init=%s, has_pre_init=%s)",
            init_path or "auto-detect",
            bool(pre_init_script),
        )
        return "/firmwareguard_init.sh"

    async def _start_container(
        self,
        session: EmulationSession,
        extracted_path: str,
        kernel_name: str | None = None,
        firmware_kernel_path: str | None = None,
        init_path: str | None = None,
        pre_init_script: str | None = None,
        stub_profile: str = "none",
    ) -> str:
        """Spawn a Docker container for this emulation session."""
        client = self._get_docker_client()
        settings = self._settings

        # Resolve the extracted path to a host path for Docker volume mounts.
        # ALWAYS mount the source rootfs read-only at /firmware_src and copy it
        # into an ephemeral /firmware directory inside the container so emulation
        # NEVER mutates the original extracted firmware filesystem on disk.
        real_path = os.path.realpath(extracted_path)
        host_path = self._resolve_host_path(real_path)
        use_docker_cp = host_path is None

        volumes = {}
        if not use_docker_cp:
            volumes[host_path] = {"bind": "/firmware_src", "mode": "ro"}

        # Build port bindings for system mode
        port_bindings = {}
        if session.port_forwards:
            for pf in session.port_forwards:
                host_ = pf.get("host", 0)
                if host_:
                    # QEMU listens on the host port INSIDE the container
                    # (hostfwd=tcp::HOST_PORT-:GUEST_PORT), so Docker must
                    # map the same port on both sides: host:PORT → container:PORT
                    port_bindings[f"{host_}/tcp"] = [{"HostPort": str(host_)}]

        # Resolve kernel path for system mode (backend-side path)
        kernel_backend_path = None
        initrd_backend_path = None
        dtb_backend_path = None
        if session.mode == "system":
            kernel_backend_path = self._find_kernel(
                session.architecture,
                kernel_name=kernel_name,
                firmware_kernel_path=firmware_kernel_path,
            )
            # Look for companion initrd
            initrd_backend_path = self._find_initrd(
                kernel_backend_path, kernel_name
            )
            if initrd_backend_path:
                logger.info("Found initrd: %s", initrd_backend_path)
            # Look for companion dtb
            dtb_backend_path = self._find_dtb(
                kernel_backend_path, kernel_name
            )
            if dtb_backend_path:
                logger.info("Found dtb: %s", dtb_backend_path)

        # Container-internal path where the kernel will be placed
        CONTAINER_KERNEL_PATH = "/tmp/kernel"

        common_labels = {
            "firmwareguard.session_id": str(session.id),
            "firmwareguard.project_id": str(session.project_id),
            "firmwareguard.mode": session.mode,
        }

        container = await asyncio.to_thread(
            client.containers.run,
            image=settings.emulation_image,
            command=["sleep", "infinity"],
            detach=True,
            volumes=volumes or None,
            ports=port_bindings or None,
            mem_limit=f"{settings.emulation_memory_limit_mb}m",
            nano_cpus=int(settings.emulation_cpu_limit * 1e9),
            privileged=False,
            cap_add=["SYS_ADMIN"],
            network_mode="bridge",
            labels=common_labels,
        )

        try:
            if use_docker_cp:
                await asyncio.to_thread(container.exec_run, ["mkdir", "-p", "/firmware"])
                logger.info("Copying firmware to emulation container via tar stream: %s", real_path)
                await asyncio.to_thread(self._copy_dir_to_container, container, real_path, "/firmware")
            else:
                copy_res = await asyncio.to_thread(
                    container.exec_run,
                    ["sh", "-c", "mkdir -p /firmware && cp -a /firmware_src/. /firmware/"],
                )
                if copy_res.exit_code != 0:
                    err_out = copy_res.output.decode("utf-8", errors="replace").strip()
                    raise RuntimeError(f"Failed to stage read-only firmware copy: {err_out}")

            # Fix permissions — binwalk extraction may lose execute bits.
            await asyncio.to_thread(self._fix_firmware_permissions, container)

            # Inject LD_PRELOAD stub libraries into the ephemeral /firmware rootfs.
            await asyncio.to_thread(
                self._inject_stub_libraries, container, session.architecture, stub_profile
            )

            # For user mode, register binfmt_misc, prepare chroot, and execute the
            # requested binary_path + arguments with output captured to /tmp/qemu-user.log.
            if session.mode == "user":
                await asyncio.to_thread(self._ensure_binfmt_misc, session.architecture or "arm")
                arch = session.architecture or "arm"
                qemu_bin = QEMU_USER_BIN_MAP.get(arch, "qemu-arm-static")
                await asyncio.to_thread(
                    container.exec_run,
                    [
                        "sh", "-c",
                        f"cp $(which {qemu_bin}) /firmware/{qemu_bin} && "
                        f"chmod +x /firmware/{qemu_bin}",
                    ],
                )
                await asyncio.to_thread(
                    container.exec_run,
                    [
                        "sh", "-c",
                        "mkdir -p /firmware/proc /firmware/dev /firmware/tmp /firmware/sys && "
                        "mount -t proc proc /firmware/proc 2>/dev/null || true && "
                        "mount --bind /dev /firmware/dev 2>/dev/null || true",
                    ],
                )
                if session.binary_path:
                    await asyncio.to_thread(
                        self._launch_user_binary,
                        container,
                        arch,
                        session.binary_path,
                        session.arguments,
                    )
                logger.info(
                    "User-mode chroot prepared: copied %s into /firmware/ (binary=%s)",
                    qemu_bin,
                    session.binary_path,
                )

            # For system mode, copy the kernel into the container and launch QEMU
            if session.mode == "system":
                if not kernel_backend_path:
                    raise ValueError(
                        "System-mode emulation requires a valid kernel, but none was found. "
                        "The firmware-extracted kernel (if any) failed validation and no "
                        "pre-built kernels are available. Upload a QEMU-compatible kernel "
                        "via the Kernel Manager."
                    )

                await asyncio.to_thread(
                    self._copy_file_to_container,
                    container,
                    kernel_backend_path,
                    CONTAINER_KERNEL_PATH,
                )

                # Copy initrd if available
                CONTAINER_INITRD_PATH = "/tmp/initrd"
                initrd_arg = ""
                if initrd_backend_path and os.path.isfile(initrd_backend_path):
                    await asyncio.to_thread(
                        self._copy_file_to_container,
                        container,
                        initrd_backend_path,
                        CONTAINER_INITRD_PATH,
                    )
                    initrd_arg = CONTAINER_INITRD_PATH
                    logger.info("Copied initrd to container: %s", initrd_backend_path)

                # Copy DTB if available
                CONTAINER_DTB_PATH = "/tmp/dtb"
                dtb_arg = ""
                if dtb_backend_path and os.path.isfile(dtb_backend_path):
                    await asyncio.to_thread(
                        self._copy_file_to_container,
                        container,
                        dtb_backend_path,
                        CONTAINER_DTB_PATH,
                    )
                    dtb_arg = CONTAINER_DTB_PATH
                    logger.info("Copied dtb to container: %s", dtb_backend_path)

                # Host-side rootfs preparation (broken /dev/null symlinks, /etc_ro copy,
                # mountpoints, passwordless root, inittab shell patch) BEFORE mkfs.ext4.
                stub_paths = await asyncio.to_thread(
                    self._prepare_system_rootfs, container, stub_profile
                )

                # Inject Bourne/msh-compatible init wrapper into the ephemeral rootfs.
                wrapper_init = await asyncio.to_thread(
                    self._inject_init_wrapper,
                    container,
                    init_path,
                    pre_init_script,
                    stub_profile,
                    stub_paths,
                )

                pf_str = ""
                if session.port_forwards:
                    pf_str = ",".join(
                        f"{pf['host']}:{pf['guest']}" for pf in session.port_forwards
                    )
                cmd = [
                    "/opt/scripts/start-system-mode.sh",
                    session.architecture or "arm",
                    "/firmware",
                    CONTAINER_KERNEL_PATH,
                    pf_str,
                    initrd_arg,
                    wrapper_init,
                    dtb_arg,
                ]
                await asyncio.to_thread(container.exec_run, cmd, detach=True)

                # Health check: wait briefly to catch early QEMU failures
                await self._await_system_startup(container)

            return container.id
        except Exception:
            try:
                await asyncio.to_thread(container.remove, force=True)
            except Exception:
                logger.debug("Failed to clean up container after startup error", exc_info=True)
            raise

    @staticmethod
    def _launch_user_binary(
        container: "docker.models.containers.Container",
        arch: str,
        binary_path: str,
        arguments: str | None = None,
    ) -> None:
        """Run the user-selected binary inside the chroot and capture output to /tmp/qemu-user.log.

        CLI binaries finish quickly and their stdout/stderr + exit code are saved in
        /tmp/qemu-user.log. Long-running daemons continue running in the background
        while their startup logs remain readable in /tmp/qemu-user.log.
        """
        qemu_bin = QEMU_USER_BIN_MAP.get(arch, "qemu-arm-static")
        arg_tokens = shlex.split(arguments) if arguments else []
        cmdline = " ".join(shlex.quote(tok) for tok in [binary_path, *arg_tokens])

        runner = (
            "LOG=/tmp/qemu-user.log\n"
            f"printf '=== QEMU User-Mode Start ===\\nArch: {shlex.quote(arch)}\\n"
            f"Command: %s\\n\\n' {shlex.quote(cmdline)} > \"$LOG\"\n"
            f"chroot /firmware /{qemu_bin} {cmdline} >> \"$LOG\" 2>&1 &\n"
            "PID=$!\n"
            "echo $PID > /tmp/qemu-user.pid\n"
            "for i in 1 2 3 4 5 6 7 8; do\n"
            "    kill -0 \"$PID\" 2>/dev/null || break\n"
            "    sleep 0.25\n"
            "done\n"
            "if kill -0 \"$PID\" 2>/dev/null; then\n"
            "    printf '\\n[firmwareguard] Process still running in background (pid %s)\\n' \"$PID\" >> \"$LOG\"\n"
            "else\n"
            "    wait \"$PID\"\n"
            "    RC=$?\n"
            "    printf '\\n[firmwareguard] Process exited with code %s\\n' \"$RC\" >> \"$LOG\"\n"
            "fi\n"
        )
        container.exec_run(["bash", "-c", runner])

    async def _await_system_startup(
        self,
        container: "docker.models.containers.Container",
        timeout: int = 30,
    ) -> None:
        """Wait briefly after QEMU launch and check for early failures.

        The startup script creates an ext4 rootfs image (takes a few seconds),
        decompresses the kernel if needed, then exec's to QEMU. We need to
        account for this preparation phase where the QEMU process doesn't
        exist yet but the startup script is still running.

        Checks each second whether the startup script or QEMU is still alive.
        If both are gone, reads /tmp/qemu-system.log and raises with the log
        content so the caller can set error status.
        """
        qemu_was_seen = False

        for i in range(timeout):
            await asyncio.sleep(1)

            # Check if the container itself is still running
            try:
                container.reload()
                if container.status not in ("running", "created"):
                    log = self._read_container_qemu_log(container, quiet=True)
                    raise RuntimeError(
                        f"Emulation container exited during startup.\n\n"
                        f"--- QEMU log ---\n{log}"
                    )
            except docker.errors.NotFound:
                raise RuntimeError("Emulation container disappeared during startup")

            # Check if either the startup script or QEMU process is alive.
            # During ext4 creation, only the script runs. After exec, only
            # QEMU runs. If neither is found, something failed.
            try:
                result = container.exec_run(
                    ["sh", "-c",
                     "pgrep -f 'qemu-system' >/dev/null 2>&1 && echo qemu || "
                     "(pgrep -f 'start-system-mode' >/dev/null 2>&1 && echo script || echo none)"],
                )
                output = result.output.decode("utf-8", errors="replace").strip()

                if output == "qemu":
                    qemu_was_seen = True
                elif output == "none":
                    if qemu_was_seen:
                        # QEMU was running but now it's gone — it crashed
                        log = self._read_container_qemu_log(container)
                        raise RuntimeError(
                            f"QEMU process exited during startup.\n\n"
                            f"--- QEMU log ---\n{log}"
                        )
                    elif i > 15:
                        # Neither script nor QEMU found after 15s — something is wrong
                        log = self._read_container_qemu_log(container)
                        raise RuntimeError(
                            f"Neither startup script nor QEMU found after {i}s.\n\n"
                            f"--- QEMU log ---\n{log}"
                        )
                    # else: still early, script may not have started yet
            except docker.errors.APIError:
                pass  # Container may be in a transient state

            # Check if the serial socket appeared (means QEMU is up and listening)
            try:
                result = container.exec_run(["test", "-S", "/tmp/qemu-serial.sock"])
                if result.exit_code == 0:
                    logger.info("QEMU serial socket ready after %ds", i + 1)
                    return  # QEMU is healthy
            except docker.errors.APIError:
                pass

        # Timeout without socket, but QEMU is still running — that's OK,
        # it may just be slow (ext4 creation, kernel boot). Let it continue.
        logger.info(
            "QEMU still starting after %ds (no serial socket yet), "
            "continuing in background",
            timeout,
        )

    @staticmethod
    def _read_container_qemu_log(
        container: "docker.models.containers.Container",
        max_bytes: int = 8000,
        quiet: bool = False,
        mode: str | None = None,
    ) -> str:
        """Read emulation startup and console logs from inside a container.

        For system mode, combines `/tmp/qemu-system.log` with recent serial console
        output from `/tmp/qemu-serial.log`. For user mode, reads `/tmp/qemu-user.log`.
        """
        try:
            script = (
                "if [ -f /tmp/qemu-system.log ]; then "
                "  cat /tmp/qemu-system.log; "
                "  if [ -s /tmp/qemu-serial.log ]; then "
                "    printf '\\n--- Serial Console Output ---\\n'; "
                "    tail -c 6000 /tmp/qemu-serial.log; "
                "  fi; "
                "elif [ -f /tmp/qemu-user.log ]; then "
                "  cat /tmp/qemu-user.log; "
                "fi"
            )
            result = container.exec_run(["sh", "-c", script])
            log = result.output.decode("utf-8", errors="replace")
            log = _ANSI_RE.sub("", log)
            if len(log) > max_bytes:
                log = "... [truncated]\n" + log[-max_bytes:]
            return log.strip() if log.strip() else "(log file is empty)"
        except Exception:
            if not quiet:
                logger.debug("Could not read QEMU log from container")
            # Fall back to container logs
            try:
                log = container.logs(tail=50).decode("utf-8", errors="replace")
                return log.strip() if log.strip() else "(no log available)"
            except Exception:
                return "(no log available)"

    def _find_kernel(
        self,
        arch: str | None,
        kernel_name: str | None = None,
        firmware_kernel_path: str | None = None,
    ) -> str:
        """Find a kernel for system-mode emulation.

        Priority order:
        1. Explicit kernel_name (user-specified from kernel management)
        2. Pre-built QEMU-compatible kernel in emulation_kernel_dir (matching architecture)
        3. Fallback to kernel extracted from the firmware during unpacking (validated)
        """
        from app.services.kernel_service import KernelService

        kernel_dir = self._settings.emulation_kernel_dir

        # 1) User-specified kernel from the kernel management system
        if kernel_name:
            if "/" in kernel_name or "\\" in kernel_name or ".." in kernel_name:
                raise ValueError(f"Invalid kernel name: {kernel_name}")
            kernel_path = os.path.join(kernel_dir, kernel_name)
            if not os.path.isfile(kernel_path):
                raise ValueError(
                    f"Kernel '{kernel_name}' not found in {kernel_dir}. "
                    "Upload a kernel via the kernel management API."
                )
            return kernel_path

        # 2) Pre-built QEMU-compatible kernel matching architecture
        svc = KernelService()
        match = svc.find_kernel_for_arch(arch or "arm")
        if match:
            return os.path.join(kernel_dir, match["name"])

        # 3) Fallback: kernel extracted from the firmware itself (often vendor SoC specific)
        if firmware_kernel_path and os.path.isfile(firmware_kernel_path):
            is_valid, reason = _validate_kernel_file(firmware_kernel_path)
            if is_valid:
                logger.info(
                    "Using kernel extracted from firmware: %s (%s)",
                    firmware_kernel_path, reason,
                )
                return firmware_kernel_path
            logger.warning(
                "Firmware kernel candidate rejected: %s — %s.",
                firmware_kernel_path, reason,
            )

        raise ValueError(
            f"No kernel available for architecture '{arch or 'arm'}'. "
            "System-mode emulation requires a pre-built Linux kernel. "
            "A kernel was not found in the firmware image. "
            "Upload one via the kernel management page or API "
            "(GET/POST /api/v1/kernels)."
        )

    @staticmethod
    def build_user_shell_cmd(arch: str, show_log: bool = False) -> list[str]:
        """Return the command list for an interactive QEMU user-mode shell.

        Uses chroot so all firmware paths work naturally (e.g., /bin/foo
        resolves to /firmware/bin/foo). The qemu-static binary was copied
        into /firmware/ during session setup. When show_log is True, prints
        any startup binary output from /tmp/qemu-user.log before dropping
        into the interactive shell.
        """
        qemu_bin = QEMU_USER_BIN_MAP.get(arch, "qemu-arm-static")
        if show_log:
            return [
                "sh", "-c",
                f"[ -s /tmp/qemu-user.log ] && cat /tmp/qemu-user.log && echo ''; "
                f"exec chroot /firmware /{qemu_bin} /bin/sh",
            ]
        return ["chroot", "/firmware", f"/{qemu_bin}", "/bin/sh"]

    async def stop_session(self, session_id: UUID) -> EmulationSession:
        """Stop an emulation session and remove its container."""
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError("Session not found")

        if session.status == "stopped":
            return session

        # Stop and remove the Docker container (even for errored sessions if still present)
        if session.container_id:
            def _stop_and_remove(cid: str) -> None:
                client = self._get_docker_client()
                container = client.containers.get(cid)
                container.stop(timeout=5)
                container.remove(force=True)

            try:
                await asyncio.to_thread(_stop_and_remove, session.container_id)
            except docker.errors.NotFound:
                logger.info("Container already removed: %s", session.container_id)
            except Exception:
                logger.exception("Error stopping container: %s", session.container_id)

        if session.status != "error":
            session.status = "stopped"
        session.stopped_at = datetime.now(timezone.utc)
        await self.db.flush()
        return session

    async def exec_command(
        self,
        session_id: UUID,
        command: str,
        timeout: int = 30,
        environment: dict[str, str] | None = None,
    ) -> dict:
        """Execute a command inside a running emulation session."""
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError("Session not found")

        if session.status != "running":
            raise ValueError(f"Session is not running (status: {session.status})")

        if not session.container_id:
            raise ValueError("No container associated with this session")

        client = self._get_docker_client()
        try:
            container = client.containers.get(session.container_id)
        except docker.errors.NotFound:
            session.status = "error"
            session.error_message = "Container not found"
            await self.db.flush()
            raise ValueError("Container not found — session may have been terminated")

        # Build exec command.
        # User mode: chroot into /firmware so all firmware paths work naturally.
        # The qemu-static binary was copied into /firmware/ during session start.
        # System mode: send command through QEMU's serial console socket.
        #
        # Environment variables are prepended as shell exports so they're
        # available to the command inside the chroot/emulated system.
        env_prefix = ""
        if environment:
            exports = " ".join(
                f"export {shlex.quote(k)}={shlex.quote(v)};"
                for k, v in environment.items()
            )
            env_prefix = exports + " "

        if session.mode == "user":
            arch = session.architecture or "arm"
            qemu_bin = QEMU_USER_BIN_MAP.get(arch, "qemu-arm-static")
            exec_cmd = [
                "timeout", str(timeout),
                "chroot", "/firmware",
                f"/{qemu_bin}", "/bin/sh", "-c", env_prefix + command,
            ]
        else:
            # System mode: use serial-exec.sh to send commands through the
            # QEMU serial console socket with proper output capture.
            # The script wraps the command in unique markers, keeps the socat
            # connection alive until output is captured, and extracts the
            # guest command's stdout and exit code.
            full_cmd = env_prefix + command if env_prefix else command
            exec_cmd = [
                "/opt/scripts/serial-exec.sh",
                full_cmd,
                str(timeout),
            ]

        try:
            exec_result = await asyncio.to_thread(container.exec_run, exec_cmd, demux=True)

            stdout_bytes = exec_result.output[0] if exec_result.output[0] else b""
            stderr_bytes = exec_result.output[1] if exec_result.output[1] else b""
            exit_code = exec_result.exit_code

            # `timeout` and serial-exec.sh return exit code 124 for timeouts
            timed_out = exit_code == 124

            stdout_str = stdout_bytes.decode("utf-8", errors="replace")
            stderr_str = stderr_bytes.decode("utf-8", errors="replace")

            # Strip ANSI escape codes and residual markers (safety net for
            # anything serial-exec.sh misses or user-mode terminal output)
            if session.mode == "system":
                stdout_str = _ANSI_RE.sub("", stdout_str)
                stdout_str = _MARKER_RE.sub("", stdout_str)
                stderr_str = _ANSI_RE.sub("", stderr_str)

            # For system mode, the serial-exec.sh script outputs a timeout
            # marker if no response was received from the guest
            if session.mode == "system" and "FIRMWAREGUARD_SERIAL_TIMEOUT" in stdout_str:
                # Strip the marker and return whatever raw serial output was captured
                stdout_str = _TIMEOUT_RE.sub("", stdout_str).strip()
                if not stderr_str:
                    stderr_str = (
                        "No response from serial console within timeout. "
                        "The guest OS may still be booting or no shell is available."
                    )
                timed_out = True

            return {
                "stdout": stdout_str,
                "stderr": stderr_str,
                "exit_code": exit_code if not timed_out else -1,
                "timed_out": timed_out,
            }

        except Exception as exc:
            raise ValueError(f"Command execution failed: {exc}")

    async def send_ctrl_c(self, session_id: UUID) -> dict:
        """Send Ctrl-C to a running system-mode emulation session.

        This kills any stuck foreground process on the serial console,
        allowing subsequent commands to execute. Only works for system-mode
        sessions (user-mode sessions don't have a serial console).
        """
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError("Session not found")
        if session.status != "running":
            raise ValueError(f"Session is not running (status: {session.status})")
        if session.mode != "system":
            raise ValueError("send_ctrl_c is only supported for system-mode sessions")
        if not session.container_id:
            raise ValueError("No container associated with this session")

        client = self._get_docker_client()
        try:
            container = client.containers.get(session.container_id)
        except docker.errors.NotFound:
            session.status = "error"
            session.error_message = "Container not found"
            await self.db.flush()
            raise ValueError("Container not found — session may have been terminated")

        # Send Ctrl-C (\x03) followed by a newline to the serial socket
        ctrl_c_cmd = [
            "sh", "-c",
            "printf '\\x03\\n' | socat - UNIX-CONNECT:/tmp/qemu-serial.sock",
        ]
        try:
            exec_result = container.exec_run(ctrl_c_cmd, demux=True)
            stdout = (exec_result.output[0] or b"").decode("utf-8", errors="replace")
            return {
                "success": exec_result.exit_code == 0,
                "message": "Ctrl-C sent to serial console" if exec_result.exit_code == 0 else f"Failed: {stdout}",
            }
        except Exception as exc:
            raise ValueError(f"Failed to send Ctrl-C: {exc}")

    async def get_status(self, session_id: UUID) -> EmulationSession:
        """Get the status of an emulation session, updating from Docker if running."""
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError("Session not found")

        # If session claims to be running, verify with Docker
        if session.status == "running" and session.container_id:
            try:
                client = self._get_docker_client()
                container = client.containers.get(session.container_id)
                if container.status not in ("running", "created"):
                    # Container died — try to read QEMU log for diagnostics
                    log = self._read_container_qemu_log(container, quiet=True)
                    session.status = "error"
                    session.error_message = (
                        f"Emulation container exited unexpectedly.\n\n"
                        f"--- QEMU log ---\n{log}"
                    )
                    session.stopped_at = datetime.now(timezone.utc)
                    await self.db.flush()
                elif session.mode == "system":
                    # Container is running, but check if QEMU (or its startup script) is alive
                    try:
                        check = await asyncio.to_thread(
                            container.exec_run,
                            [
                                "sh", "-c",
                                "pgrep -f 'qemu-system' >/dev/null 2>&1 || "
                                "pgrep -f 'start-system-mode' >/dev/null 2>&1; echo $?",
                            ],
                        )
                        output = check.output.decode("utf-8", errors="replace").strip()
                        if output != "0":
                            log = await asyncio.to_thread(
                                self._read_container_qemu_log, container
                            )
                            session.status = "error"
                            session.error_message = (
                                f"QEMU process has exited.\n\n"
                                f"--- QEMU log ---\n{log}"
                            )
                            session.stopped_at = datetime.now(timezone.utc)
                            await self.db.flush()
                    except docker.errors.APIError:
                        pass  # transient Docker error, don't update status
            except docker.errors.NotFound:
                session.status = "stopped"
                session.error_message = "Container no longer exists"
                session.stopped_at = datetime.now(timezone.utc)
                await self.db.flush()
            except Exception:
                logger.exception("Error checking container status")

        return session

    async def list_sessions(self, project_id: UUID) -> list[EmulationSession]:
        """List all emulation sessions for a project."""
        result = await self.db.execute(
            select(EmulationSession)
            .where(EmulationSession.project_id == project_id)
            .order_by(EmulationSession.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_session_logs(self, session_id: UUID) -> str:
        """Read QEMU startup logs from a session's container.

        Works for both running and recently-stopped containers.
        Returns the log text or an explanatory message.
        """
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError("Session not found")

        if not session.container_id:
            # No container — return stored error_message if available
            if session.error_message:
                return session.error_message
            return "No container associated with this session — no logs available."

        try:
            client = self._get_docker_client()
            container = client.containers.get(session.container_id)
            return self._read_container_qemu_log(container, max_bytes=8000)
        except docker.errors.NotFound:
            # Container removed — return stored error_message
            if session.error_message:
                return session.error_message
            return "Container has been removed — no logs available."
        except Exception as exc:
            return f"Failed to read logs: {exc}"

    async def cleanup_expired(self) -> int:
        """Stop sessions that have exceeded the timeout. Returns count stopped."""
        timeout_minutes = self._settings.emulation_timeout_minutes
        cutoff = datetime.now(timezone.utc).timestamp() - (timeout_minutes * 60)

        result = await self.db.execute(
            select(EmulationSession).where(
                EmulationSession.status == "running",
                EmulationSession.started_at.isnot(None),
            )
        )
        sessions = result.scalars().all()
        count = 0

        for session in sessions:
            if session.started_at and session.started_at.timestamp() < cutoff:
                try:
                    await self.stop_session(session.id)
                    count += 1
                except Exception:
                    logger.exception("Failed to stop expired session: %s", session.id)

        return count

    # ── Emulation Presets ──

    async def create_preset(
        self,
        project_id: UUID,
        name: str,
        mode: str,
        description: str | None = None,
        binary_path: str | None = None,
        arguments: str | None = None,
        architecture: str | None = None,
        port_forwards: list[dict] | None = None,
        kernel_name: str | None = None,
        init_path: str | None = None,
        pre_init_script: str | None = None,
        stub_profile: str = "none",
    ) -> EmulationPreset:
        """Create a new emulation preset for a project."""
        preset = EmulationPreset(
            project_id=project_id,
            name=name,
            description=description,
            mode=mode,
            binary_path=binary_path,
            arguments=arguments,
            architecture=architecture,
            port_forwards=port_forwards or [],
            kernel_name=kernel_name,
            init_path=init_path,
            pre_init_script=pre_init_script,
            stub_profile=stub_profile,
        )
        self.db.add(preset)
        await self.db.flush()
        return preset

    async def list_presets(self, project_id: UUID) -> list[EmulationPreset]:
        """List all emulation presets for a project."""
        result = await self.db.execute(
            select(EmulationPreset)
            .where(EmulationPreset.project_id == project_id)
            .order_by(EmulationPreset.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_preset(self, preset_id: UUID) -> EmulationPreset:
        """Get a single emulation preset by ID."""
        result = await self.db.execute(
            select(EmulationPreset).where(EmulationPreset.id == preset_id)
        )
        preset = result.scalar_one_or_none()
        if not preset:
            raise ValueError("Preset not found")
        return preset

    async def update_preset(
        self, preset_id: UUID, updates: dict
    ) -> EmulationPreset:
        """Update an existing emulation preset."""
        preset = await self.get_preset(preset_id)
        for key, value in updates.items():
            if value is not None and hasattr(preset, key):
                setattr(preset, key, value)
        await self.db.flush()
        return preset

    async def delete_preset(self, preset_id: UUID) -> None:
        """Delete an emulation preset."""
        preset = await self.get_preset(preset_id)
        await self.db.delete(preset)
        await self.db.flush()
