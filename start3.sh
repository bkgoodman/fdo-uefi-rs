#!/bin/bash
# start3.sh - FDO test script with built-in timeouts for safe SSH execution
# All steps have timeouts to prevent hanging

set -e

TIMEOUT_SHORT=10
TIMEOUT_MEDIUM=30
TIMEOUT_QEMU=90
WORKDIR=/tmp/fdo-test3
VOUCHER_DIR=/tmp/fdo-vouchers3

echo "=== Cleanup ==="
sudo killall -9 swtpm server qemu-system-x86_64 2>/dev/null || true
sleep 1
rm -rf "$WORKDIR" "$VOUCHER_DIR"
mkdir -p "$WORKDIR" "$VOUCHER_DIR"

echo "=== Init database ==="
rm -f "$WORKDIR/fdo.db"
timeout $TIMEOUT_SHORT /home/bkg/bkgvm/server server -db "$WORKDIR/fdo.db" -http 127.0.0.1:19999 -initOnly 2>&1 || true

echo "=== Export owner key ==="
/home/bkg/bkgvm/server server -db "$WORKDIR/fdo.db" -print-owner-public SECP256R1 2>/dev/null | grep -A100 "BEGIN PUBLIC" > "$WORKDIR/owner.pem"
echo "Owner key exported"

echo "=== Start swtpm ==="
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
echo "swtpm started (PID $SWTPM_PID)"

echo "=== Creating voucher ==="
timeout $TIMEOUT_MEDIUM env FDO_TPM_DEVICE="$WORKDIR/swtpm-server" \
    /home/bkg/quick-di-tpm -quick -rv 10.0.2.2:8080:http \
    -device-info EFI-FDO-Test -output-dir "$VOUCHER_DIR" \
    -signover-key "$WORKDIR/owner.pem" 2>&1 | grep -E "GUID|completed|error" || true

VOUCHER=$(ls -t "$VOUCHER_DIR"/*.fdoov 2>/dev/null | head -1)
if [ -z "$VOUCHER" ]; then
    echo "ERROR: No voucher created"
    exit 1
fi
sed -i "s/FDO OWNERSHIP VOUCHER/OWNERSHIP VOUCHER/g" "$VOUCHER"
echo "Voucher: $VOUCHER"

echo "=== Import voucher ==="
/home/bkg/bkgvm/server server -db "$WORKDIR/fdo.db" -import-voucher "$VOUCHER" -initOnly 2>&1 || {
    echo "Voucher import failed (may already exist), continuing..."
}

echo "=== Starting server with BMO ==="
# BMO payload - use fdo-stub.efi as test chainload target
BMO_PAYLOAD="/home/bkg/efi-fdo-bmo/build/fdo-stub.efi"
if [ ! -f "$BMO_PAYLOAD" ]; then
    echo "WARNING: BMO payload not found, running without BMO"
    /home/bkg/bkgvm/server -debug server -http 0.0.0.0:8080 -db "$WORKDIR/fdo.db" -rv-bypass > "$WORKDIR/server.log" 2>&1 &
else
    echo "BMO payload: $BMO_PAYLOAD ($(stat -c%s "$BMO_PAYLOAD") bytes)"
    # Use -bmo-file and -bmo-type flags (as per go-fdo test script)
    # Add -reuse-cred to allow credential reuse for testing
    /home/bkg/bkgvm/server-debug -debug server -http 0.0.0.0:8080 -db "$WORKDIR/fdo.db" -rv-bypass \
        -reuse-cred -bmo-file "$BMO_PAYLOAD" -bmo-type "application/x-uefi-image" > "$WORKDIR/server.log" 2>&1 &
fi
SERVER_PID=$!
sleep 2

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "ERROR: Server failed to start"
    cat "$WORKDIR/server.log"
    exit 1
fi
echo "Server started (PID $SERVER_PID)"

echo "=== Building Rust FDO client ==="
cd /home/bkg/fdo-uefi-rs
source ~/.cargo/env
cargo +nightly build --release 2>&1 | tail -3

echo "=== Creating boot disk ==="
RUST_EFI="/home/bkg/fdo-uefi-rs/target/x86_64-unknown-uefi/release/fdo-uefi.efi"
DISK_IMG="$WORKDIR/fdo-disk.img"
dd if=/dev/zero of="$DISK_IMG" bs=1M count=64 2>/dev/null
mkfs.vfat -F 32 "$DISK_IMG" >/dev/null
mmd -i "$DISK_IMG" ::/EFI
mmd -i "$DISK_IMG" ::/EFI/BOOT
mcopy -i "$DISK_IMG" "$RUST_EFI" ::/EFI/BOOT/BOOTX64.EFI
echo "Disk image created with Rust FDO client"

echo "=== Copying OVMF vars ==="
cp /usr/share/OVMF/OVMF_VARS_4M.fd "$WORKDIR/OVMF_VARS.fd"

echo "=== Starting QEMU (timeout ${TIMEOUT_QEMU}s) ==="
sudo timeout $TIMEOUT_QEMU qemu-system-x86_64 \
    -machine q35 -m 2048 \
    -drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
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

echo "=== Cleanup ==="
kill $SERVER_PID 2>/dev/null || true
kill $SWTPM_PID 2>/dev/null || true

echo "=== Server log (last 20 lines) ==="
tail -20 "$WORKDIR/server.log" 2>/dev/null || echo "(no log)"

echo "=== Done ==="
