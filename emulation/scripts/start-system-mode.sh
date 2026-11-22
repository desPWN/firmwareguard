#!/bin/bash
# start-system-mode.sh — Boot firmware via QEMU system-mode
#
# Usage: start-system-mode.sh <arch> <rootfs_path> <kernel_path> [port_forwards] [initrd] [init_path] [dtb]
#
# This script boots a full system-mode QEMU instance with the firmware
# filesystem as the root. Serial console is exposed via socat on a Unix socket.

ARCH="$1"
ROOTFS="$2"
KERNEL="$3"
PORT_FORWARDS="$4"  # comma-separated host:guest pairs, e.g., "8080:80,2222:22"
INITRD="$5"         # optional path to initramfs/initrd image
INIT_PATH="$6"      # optional init binary override (e.g., /bin/sh)
DTB="$7"            # optional path to device tree blob (.dtb)

LOG="/tmp/qemu-system.log"
SERIAL_LOG="/tmp/qemu-serial.log"
SERIAL_SOCK="/tmp/qemu-serial.sock"
ROOTFS_IMG="/tmp/rootfs.ext4"

# Always create the log file immediately so diagnostics are available
exec > >(tee -a "$LOG") 2>&1

echo "=== QEMU System-Mode Start ==="
echo "Time: $(date -u 2>/dev/null || echo unknown)"
echo "Arch: $ARCH"
echo "Rootfs: $ROOTFS"
echo "Kernel: $KERNEL"
echo "Port forwards: $PORT_FORWARDS"

if [ -z "$ARCH" ] || [ -z "$ROOTFS" ] || [ -z "$KERNEL" ]; then
    echo "ERROR: Usage: start-system-mode.sh <arch> <rootfs_path> <kernel_path> [port_forwards] [initrd] [init_path] [dtb]"
    exit 1
fi

if [ ! -f "$KERNEL" ]; then
    echo "ERROR: Kernel not found: $KERNEL"
    echo "System-mode emulation requires a pre-built kernel for the target architecture."
    echo "Upload a kernel via the Kernel Manager or place one in emulation/kernels/."
    exit 1
fi

if [ ! -d "$ROOTFS" ]; then
    echo "ERROR: Rootfs directory not found: $ROOTFS"
    exit 1
fi

echo "Kernel file size: $(wc -c < "$KERNEL") bytes"

# Suppress ALSA audio warnings from QEMU
export QEMU_AUDIO_DRV=none

# Validate kernel file format before proceeding with slow ext4 image creation
KERNEL_MAGIC=$(xxd -p -l 4 "$KERNEL" 2>/dev/null)
KERNEL_VALID=0
case "$KERNEL_MAGIC" in
    7f454c46) echo "Kernel format: ELF"; KERNEL_VALID=1 ;;           # ELF
    27051956) echo "Kernel format: U-Boot uImage"; KERNEL_VALID=1 ;; # uImage
    1f8b*)    echo "Kernel format: gzip-compressed"; KERNEL_VALID=1 ;; # gzip
    5d0000*)  echo "Kernel format: LZMA-compressed"; KERNEL_VALID=1 ;; # LZMA
esac
# Check ARM zImage magic at offset 0x24
if [ "$KERNEL_VALID" -eq 0 ]; then
    ARM_MAGIC=$(xxd -p -l 4 -s 0x24 "$KERNEL" 2>/dev/null)
    if [ "$ARM_MAGIC" = "18286f01" ]; then
        echo "Kernel format: ARM zImage"
        KERNEL_VALID=1
    fi
fi
if [ "$KERNEL_VALID" -eq 0 ]; then
    echo "ERROR: Unrecognized kernel format (magic: $KERNEL_MAGIC)"
    echo "The file does not appear to be a valid kernel image (ELF/uImage/zImage/gzip/LZMA)."
    echo "This may be a filesystem image or raw data extracted by binwalk."
    echo "Upload a proper QEMU-compatible kernel via the Kernel Manager."
    exit 1
fi

# Decompress kernel if gzip/LZMA compressed — QEMU may not handle compressed
# kernels directly (especially for aarch64 Image format)
case "$KERNEL_MAGIC" in
    1f8b*)
        echo "Decompressing gzip-compressed kernel..."
        KERNEL_DECOMPRESSED="/tmp/kernel_decompressed"
        if gunzip -c "$KERNEL" > "$KERNEL_DECOMPRESSED" 2>&1; then
            KERNEL="$KERNEL_DECOMPRESSED"
            echo "Decompressed kernel: $(wc -c < "$KERNEL") bytes"
        else
            echo "WARNING: Failed to decompress kernel, trying as-is"
        fi
        ;;
    5d0000*)
        echo "Decompressing LZMA-compressed kernel..."
        KERNEL_DECOMPRESSED="/tmp/kernel_decompressed"
        if unlzma -c "$KERNEL" > "$KERNEL_DECOMPRESSED" 2>/dev/null || \
           lzma -dc "$KERNEL" > "$KERNEL_DECOMPRESSED" 2>/dev/null; then
            KERNEL="$KERNEL_DECOMPRESSED"
            echo "Decompressed kernel: $(wc -c < "$KERNEL") bytes"
        else
            echo "WARNING: Failed to decompress kernel, trying as-is"
        fi
        ;;
esac

# Clean up stale files from previous runs
rm -f "$SERIAL_SOCK" "$SERIAL_LOG" "$ROOTFS_IMG"

# Compute ext4 image size dynamically (minimum 256 MB, or rootfs + 128 MB headroom)
ROOTFS_MB=$(du -sm "$ROOTFS" 2>/dev/null | awk '{print $1}')
ROOTFS_MB="${ROOTFS_MB:-64}"
IMG_MB=$((ROOTFS_MB + 128))
if [ "$IMG_MB" -lt 256 ]; then
    IMG_MB=256
fi

# Create a temporary ext4 image from the rootfs.
# Disable metadata_csum, 64bit, and orphan_file so older Linux kernels
# (e.g., 3.2 MIPS Malta, 4.19 ARM Buster) can mount the filesystem cleanly.
echo "Creating ext4 rootfs image (${IMG_MB} MB for ${ROOTFS_MB} MB rootfs)..."
dd if=/dev/zero of="$ROOTFS_IMG" bs=1M count="$IMG_MB" 2>/dev/null
if ! mkfs.ext4 -q -O ^metadata_csum,^64bit,^orphan_file -d "$ROOTFS" "$ROOTFS_IMG" 2>&1; then
    echo "Retrying mkfs.ext4 without ^orphan_file..."
    if ! mkfs.ext4 -q -O ^metadata_csum,^64bit -d "$ROOTFS" "$ROOTFS_IMG" 2>&1; then
        echo "WARNING: mkfs.ext4 -d failed, trying without directory copy..."
        mkfs.ext4 -q -O ^metadata_csum,^64bit "$ROOTFS_IMG" 2>&1 || true
    fi
fi
echo "Rootfs image created: $(wc -c < "$ROOTFS_IMG") bytes"

# Select QEMU binary, machine type, drive interface, and root device
# Different machine types expose block devices differently:
#   - versatilepb (ARM): IDE -> /dev/sda
#   - virt (aarch64): virtio only -> /dev/vda
#   - malta (MIPS): IDE -> /dev/sda
#   - pc (x86): IDE -> /dev/sda
case "$ARCH" in
    arm|armhf|armel)
        QEMU_BIN="qemu-system-arm"
        MACHINE="versatilepb"
        CONSOLE="ttyAMA0"
        DRIVE_IF=""
        ROOT_DEV="/dev/sda"
        CPU_ARGS="-cpu arm1176"
        GUEST_RAM="256"  # versatilepb max is 256MB
        NIC_DEVICE="smc91c111"  # built into versatilepb machine
        ;;
    aarch64|arm64)
        QEMU_BIN="qemu-system-aarch64"
        MACHINE="virt"
        CONSOLE="ttyAMA0"
        DRIVE_IF=",if=virtio"
        ROOT_DEV="/dev/vda"
        CPU_ARGS="-cpu cortex-a57"
        GUEST_RAM="512"
        NIC_DEVICE="virtio-net-pci"  # standard for virt machine
        ;;
    mips|mipsbe)
        QEMU_BIN="qemu-system-mips"
        MACHINE="malta"
        CONSOLE="ttyS0"
        DRIVE_IF=""
        ROOT_DEV="/dev/sda"
        CPU_ARGS="-cpu 34Kf"  # MIPS32r2 + DSP + FPU (4Kc default only supports r1)
        GUEST_RAM="256"  # malta max is 256MB
        NIC_DEVICE="pcnet"  # Malta native NIC; pcnet32+mii modules loaded by initramfs
        ;;
    mipsel|mipsle)
        QEMU_BIN="qemu-system-mipsel"
        MACHINE="malta"
        CONSOLE="ttyS0"
        DRIVE_IF=""
        ROOT_DEV="/dev/sda"
        CPU_ARGS="-cpu 34Kf"  # MIPS32r2 + DSP + FPU (4Kc default only supports r1)
        GUEST_RAM="256"  # malta max is 256MB
        NIC_DEVICE="pcnet"  # Malta native NIC; pcnet32+mii modules loaded by initramfs
        ;;
    x86|i386|i686)
        QEMU_BIN="qemu-system-i386"
        MACHINE="pc"
        CONSOLE="ttyS0"
        DRIVE_IF=""
        ROOT_DEV="/dev/sda"
        CPU_ARGS=""
        GUEST_RAM="512"
        NIC_DEVICE="e1000"  # built into most x86 kernels
        ;;
    x86_64|amd64)
        QEMU_BIN="qemu-system-x86_64"
        MACHINE="pc"
        CONSOLE="ttyS0"
        DRIVE_IF=""
        ROOT_DEV="/dev/sda"
        CPU_ARGS=""
        GUEST_RAM="512"
        NIC_DEVICE="e1000"  # built into most x86 kernels
        ;;
    *)
        echo "ERROR: Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Build networking with explicit NIC device per architecture.
# On versatilepb, smc91c111 is an on-board sysbus device, so -net nic is used.
# For pluggable PCI NICs, -device is used.
NETDEV_ARGS="user,id=net0"
RELAY_PIDS=""
if [ -n "$PORT_FORWARDS" ]; then
    IFS=',' read -ra PAIRS <<< "$PORT_FORWARDS"
    for pair in "${PAIRS[@]}"; do
        host_port="${pair%%:*}"
        guest_port="${pair##*:}"
        if ! [[ "$host_port" =~ ^[0-9]+$ ]] || ! [[ "$guest_port" =~ ^[0-9]+$ ]]; then
            continue
        fi
        relay_port=$((host_port + 10000))
        NETDEV_ARGS="${NETDEV_ARGS},hostfwd=tcp:127.0.0.1:${relay_port}-:${guest_port}"
        # Start socat relay: listens on all interfaces, forwards to QEMU via localhost
        socat TCP-LISTEN:${host_port},bind=0.0.0.0,fork,reuseaddr \
              TCP:127.0.0.1:${relay_port} &
        RELAY_PIDS="$RELAY_PIDS $!"
        echo "Port relay: 0.0.0.0:${host_port} -> 127.0.0.1:${relay_port} -> guest:${guest_port}"
    done
fi

if [ "$NIC_DEVICE" = "smc91c111" ]; then
    NET_ARGS="-net nic,model=smc91c111 -net ${NETDEV_ARGS}"
else
    NET_ARGS="-device ${NIC_DEVICE},netdev=net0 -netdev ${NETDEV_ARGS}"
fi

# Verify QEMU binary exists
if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
    echo "ERROR: $QEMU_BIN not found in PATH"
    exit 1
fi

echo "Starting: $QEMU_BIN -M $MACHINE $CPU_ARGS"
echo "Serial console: $SERIAL_SOCK"
echo "Drive interface: ${DRIVE_IF:-default}"

# Build optional initrd argument
INITRD_ARGS=""
if [ -n "$INITRD" ] && [ -f "$INITRD" ]; then
    echo "Initrd: $INITRD ($(wc -c < "$INITRD") bytes)"
    INITRD_ARGS="-initrd $INITRD"
else
    echo "Initrd: none"
fi

# Build optional DTB argument
if [ -z "$DTB" ]; then
    if [ -f "/tmp/dtb" ]; then
        DTB="/tmp/dtb"
    elif [ -f "${KERNEL}.dtb" ]; then
        DTB="${KERNEL}.dtb"
    fi
fi

DTB_ARGS=""
if [ -n "$DTB" ] && [ -f "$DTB" ]; then
    echo "DTB: $DTB ($(wc -c < "$DTB") bytes)"
    DTB_ARGS="-dtb $DTB"
else
    echo "DTB: none"
fi

# Build kernel append string
APPEND_ARGS="root=$ROOT_DEV rw console=$CONSOLE panic=0"
if [ -n "$INIT_PATH" ]; then
    APPEND_ARGS="$APPEND_ARGS init=$INIT_PATH"
    echo "Init override: $INIT_PATH"
fi
echo "Kernel append: $APPEND_ARGS"

# Launch QEMU
# -nodefaults: suppress audio/USB/etc warnings
# -no-reboot: exit instead of rebooting (prevents infinite loops)
# -gdb tcp::1234: expose GDB stub for remote debugging
# -chardev ... logfile=: capture full kernel boot and console output even when no client is attached
exec "$QEMU_BIN" \
    -M "$MACHINE" \
    $CPU_ARGS \
    -m "${GUEST_RAM:-256}" \
    -nographic \
    -nodefaults \
    -no-reboot \
    -chardev "socket,id=ser0,path=${SERIAL_SOCK},server=on,wait=off,logfile=${SERIAL_LOG}" \
    -serial chardev:ser0 \
    -monitor none \
    -gdb tcp::1234 \
    $DTB_ARGS \
    -kernel "$KERNEL" \
    $INITRD_ARGS \
    -drive "file=$ROOTFS_IMG,format=raw${DRIVE_IF}" \
    -append "$APPEND_ARGS" \
    $NET_ARGS
