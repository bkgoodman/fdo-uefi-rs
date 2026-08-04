#!/bin/bash
# test-di.sh - Test Device Initialization (DI) protocol
# Runs UEFI client against go-fdo server with CLEAN TPM (no credentials)

set -e

TIMEOUT_QEMU=60
WORKDIR=/tmp/fdo-di-test
VOUCHER_DIR=/tmp/fdo-di-vouchers

echo "=== FDO DI Protocol Test ==="

echo "=== Cleanup ==="
sudo killall -9 swtpm server qemu-system-x86_64 2>/dev/null || true
sleep 1
rm -rf "$WORKDIR" "$VOUCHER_DIR"
mkdir -p "$WORKDIR" "$VOUCHER_DIR"

FDO_SERVER=/tmp/fdo-server

echo "=== Build go-fdo server ==="
cd /home/bradgoodman/go-fdo && go build -o "$FDO_SERVER" ./examples/cmd/ 2>&1

echo "=== Init database ==="
rm -f "$WORKDIR/fdo.db"
timeout 10 "$FDO_SERVER" server -db "$WORKDIR/fdo.db" -http 127.0.0.1:19999 -initOnly 2>&1 || true

echo "=== Start swtpm (CLEAN - no credentials) ==="
swtpm socket --tpmstate dir="$WORKDIR" \
    --server type=unixio,path="$WORKDIR/swtpm-server" \
    --ctrl type=unixio,path="$WORKDIR/swtpm-ctrl" \
    --tpm2 --flags startup-clear &
SWTPM_PID=$!
sleep 2

if [ ! -S "$WORKDIR/swtpm-ctrl" ]; then
    echo "ERROR: swtpm socket not created"
    exit 1
fi
echo "swtpm started (PID $SWTPM_PID) - CLEAN STATE"

echo "=== Starting go-fdo server (handles DI automatically) ==="
# Start server on port 8080 - it will handle DI requests
"$FDO_SERVER" -debug server -http 0.0.0.0:8080 -db "$WORKDIR/fdo.db" \
    -rv-bypass > "$WORKDIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "ERROR: Server failed to start"
    cat "$WORKDIR/server.log"
    exit 1
fi
echo "Server started (PID $SERVER_PID) on port 8080"

echo "=== Building Rust FDO client ==="
cd /home/bradgoodman/fdo-uefi-rs
source ~/.cargo/env 2>/dev/null || true
cargo +nightly build --release 2>&1 | tail -3

echo "=== Creating boot disk ==="
RUST_EFI="/home/bradgoodman/fdo-uefi-rs/target/x86_64-unknown-uefi/release/fdo-uefi.efi"
DISK_IMG="$WORKDIR/fdo-disk.img"
dd if=/dev/zero of="$DISK_IMG" bs=1M count=64 2>/dev/null
mkfs.vfat -F 32 "$DISK_IMG" >/dev/null
mmd -i "$DISK_IMG" ::/EFI
mmd -i "$DISK_IMG" ::/EFI/BOOT
mcopy -i "$DISK_IMG" "$RUST_EFI" ::/EFI/BOOT/BOOTX64.EFI
echo "Disk image created"

echo "=== Copying OVMF vars ==="
# Try common OVMF locations
OVMF_CODE=""
OVMF_VARS_SRC=""
for path in /usr/share/OVMF /usr/share/edk2/ovmf /usr/share/qemu; do
    if [ -f "$path/OVMF_CODE_4M.fd" ]; then
        OVMF_CODE="$path/OVMF_CODE_4M.fd"
        OVMF_VARS_SRC="$path/OVMF_VARS_4M.fd"
        break
    elif [ -f "$path/OVMF_CODE.fd" ]; then
        OVMF_CODE="$path/OVMF_CODE.fd"
        OVMF_VARS_SRC="$path/OVMF_VARS.fd"
        break
    fi
done

if [ -z "$OVMF_CODE" ]; then
    echo "ERROR: OVMF firmware not found. Install edk2-ovmf package."
    echo "On Debian/Ubuntu: sudo apt install ovmf"
    echo "On Fedora: sudo dnf install edk2-ovmf"
    exit 1
fi
echo "Using OVMF: $OVMF_CODE"
cp "$OVMF_VARS_SRC" "$WORKDIR/OVMF_VARS.fd"

echo ""
echo "=== Starting QEMU (timeout ${TIMEOUT_QEMU}s) ==="
echo "Expected: No TPM credentials -> attempt DI -> connect to server:8080"
echo ""

sudo timeout $TIMEOUT_QEMU qemu-system-x86_64 \
    -machine q35 -m 2048 \
    -drive if=pflash,format=raw,unit=0,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,unit=1,file="$WORKDIR/OVMF_VARS.fd" \
    -drive file="$DISK_IMG",format=raw,index=0 \
    -chardev socket,id=chrtpm,path="$WORKDIR/swtpm-ctrl" \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 \
    -device virtio-rng-pci \
    -nic user,model=virtio-net-pci \
    -nographic 2>&1

QEMU_EXIT=$?
echo ""
echo "=== QEMU exited (code $QEMU_EXIT) ==="

echo ""
echo "=== Server log ==="
cat "$WORKDIR/server.log" 2>/dev/null || echo "(no log)"

echo ""
echo "=== Vouchers created ==="
ls -la "$VOUCHER_DIR"/*.fdoov 2>/dev/null || echo "(none)"

echo ""
echo "=== Cleanup ==="
kill $SERVER_PID 2>/dev/null || true
kill $SWTPM_PID 2>/dev/null || true

echo "=== Done ==="
