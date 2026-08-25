#!/bin/bash
# test-rv-firmware.sh - QEMU integration test for RV-based firmware delivery
#
# Tests the full end-to-end flow:
#   1. swtpm setup
#   2. quick-di with firmware RV extension tags in DCTPM
#   3. HTTP server serving signed firmware payload
#   4. QEMU boots Rust FDO UEFI client (with rv-firmware feature)
#   5. UEFI client reads DCTPM, downloads firmware, verifies COSE_Sign1, chainloads
#
# Prerequisites (on pe2):
#   - qemu-system-x86_64, swtpm, OVMF, mkfs.vfat, mmd, mcopy
#   - ~/bkgvm/server (go-fdo server binary)
#   - ~/quick-di-tpm (go-fdo-quick-di binary with TPM support)
#   - signed_payload.cose (COSE_Sign1 signed test firmware, placed in WORKDIR)
#   - fdo-uefi.efi (Rust UEFI binary built with --features rv-firmware)
#
# Usage:
#   ./test-rv-firmware.sh                    # Run full test
#   ./test-rv-firmware.sh --skip-build       # Skip Rust build (use existing binary)
#   ./test-rv-firmware.sh --timeout 120      # Override QEMU timeout

set -e

# --- Configuration ---
WORKDIR=/tmp/fdo-rv-firmware-test
VOUCHER_DIR="$WORKDIR/vouchers"
TIMEOUT_SHORT=10
TIMEOUT_MEDIUM=30
TIMEOUT_QEMU="${QEMU_TIMEOUT:-90}"
SKIP_BUILD=false

# Paths on pe2
SERVER_BIN="${FDO_SERVER:-$HOME/bkgvm/server}"
QUICKDI_BIN="${QUICKDI:-$HOME/quick-di-tpm}"
OVMF_CODE="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS_SRC="${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"

# Source paths (may be overridden)
RUST_SRC="${RUST_SRC:-$HOME/fdo-uefi-rs}"
SIGNED_PAYLOAD="${SIGNED_PAYLOAD:-$RUST_SRC/test-keys/signed_payload.cose}"

# HTTP server for firmware delivery (QEMU guest sees host as 10.0.2.2)
HTTP_PORT=9080
FIRMWARE_FILENAME="signed_payload.cose"

# FDO server for TO1/TO2 (not strictly needed for rv-firmware test, but
# the UEFI client falls through to onboarding after firmware delivery)
FDO_PORT=8080

# --- Parse arguments ---
while [ $# -gt 0 ]; do
    case "$1" in
        --skip-build) SKIP_BUILD=true; shift ;;
        --timeout) TIMEOUT_QEMU="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# --- Helpers ---
log_section() { echo ""; echo "========================================"; echo "  $1"; echo "========================================"; }
log_step()    { echo ">>> $1"; }
log_ok()      { echo "✓ $1"; }
log_err()     { echo "✗ $1" >&2; }

cleanup() {
    log_section "Cleanup"
    kill "$HTTP_PID" 2>/dev/null || true
    kill "$SERVER_PID" 2>/dev/null || true
    kill "$SWTPM_PID" 2>/dev/null || true
    echo "Processes stopped"
}
trap cleanup EXIT

# --- Preflight checks ---
log_section "Preflight Checks"

for cmd in qemu-system-x86_64 swtpm mkfs.vfat mmd mcopy; do
    if ! command -v "$cmd" &>/dev/null; then
        log_err "Required command not found: $cmd"
        exit 1
    fi
done
log_ok "System commands available"

for f in "$SERVER_BIN" "$QUICKDI_BIN" "$OVMF_CODE" "$OVMF_VARS_SRC"; do
    if [ ! -f "$f" ]; then
        log_err "Required file not found: $f"
        exit 1
    fi
done
log_ok "Server and quick-di binaries found"

if [ ! -f "$SIGNED_PAYLOAD" ]; then
    log_err "Signed firmware payload not found: $SIGNED_PAYLOAD"
    log_err "Generate with: cd efi-fdo-bmo/tools && python3 sign_firmware.py --key ../../fdo-uefi-rs/test-keys/platform_key.pem --input payload.efi --output ../../fdo-uefi-rs/test-keys/signed_payload.cose"
    exit 1
fi
log_ok "Signed payload: $SIGNED_PAYLOAD ($(stat -c%s "$SIGNED_PAYLOAD") bytes)"

# --- Build Rust UEFI binary ---
if [ "$SKIP_BUILD" = false ] && [ -d "$RUST_SRC" ]; then
    log_section "Building Rust FDO UEFI Client (rv-firmware)"
    cd "$RUST_SRC"
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi
    cargo +nightly build --release --features rv-firmware 2>&1 | tail -5
    log_ok "Build complete"
fi

RUST_EFI="$RUST_SRC/target/x86_64-unknown-uefi/release/fdo-uefi.efi"
if [ ! -f "$RUST_EFI" ]; then
    log_err "UEFI binary not found: $RUST_EFI"
    log_err "Build with: cd $RUST_SRC && cargo +nightly build --release --features rv-firmware"
    exit 1
fi
log_ok "UEFI binary: $RUST_EFI ($(stat -c%s "$RUST_EFI") bytes)"

# --- Setup workspace ---
log_section "Setting Up Workspace"

sudo killall -9 swtpm server qemu-system-x86_64 2>/dev/null || true
sleep 1
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR" "$VOUCHER_DIR" "$WORKDIR/www"

# Copy signed payload to HTTP serve directory
cp "$SIGNED_PAYLOAD" "$WORKDIR/www/$FIRMWARE_FILENAME"
log_ok "Copied signed payload to HTTP directory"

# --- Init FDO database ---
log_step "Initializing FDO database"
rm -f "$WORKDIR/fdo.db"
timeout $TIMEOUT_SHORT "$SERVER_BIN" server -db "$WORKDIR/fdo.db" -http "127.0.0.1:$FDO_PORT" -initOnly 2>&1 || true

# Export owner key for quick-di signover
"$SERVER_BIN" server -db "$WORKDIR/fdo.db" -print-owner-public SECP256R1 2>/dev/null | grep -A100 "BEGIN PUBLIC" > "$WORKDIR/owner.pem"
log_ok "Database initialized, owner key exported"

# --- Start swtpm ---
log_section "Starting swtpm"
swtpm socket --tpmstate dir="$WORKDIR" \
    --server type=unixio,path="$WORKDIR/swtpm-server" \
    --ctrl type=unixio,path="$WORKDIR/swtpm-ctrl" \
    --tpm2 --flags startup-clear &
SWTPM_PID=$!
sleep 2

if [ ! -S "$WORKDIR/swtpm-ctrl" ]; then
    log_err "swtpm socket not created"
    exit 1
fi
log_ok "swtpm started (PID $SWTPM_PID)"

# --- Create voucher with firmware RV tags via quick-di ---
log_section "Device Initialization (with firmware RV tags)"

# The firmware URL uses 10.0.2.2 which is QEMU's host-to-guest NAT address
FIRMWARE_URL="http://10.0.2.2:${HTTP_PORT}/${FIRMWARE_FILENAME}"
RV_HOST="10.0.2.2"

log_step "Creating quick-di config with firmware tags"
cat > "$WORKDIR/quick-di-config.yaml" <<EOF
manufacturer_key_mode: "ephemeral"

device:
  key_type: "ec256"
  device_info: "RV-Firmware-Test"

rendezvous:
  entries:
    - host: "$RV_HOST"
      port: $FDO_PORT
      scheme: "http"
      firmware_url: "$FIRMWARE_URL"
      firmware_path: "/$FIRMWARE_FILENAME"
      min_firmware_rev: 1

owner_signover:
  enabled: true
  next_owner_public_key_file: "$WORKDIR/owner.pem"

voucher_output:
  directory: "$VOUCHER_DIR"
EOF
log_ok "Config written to $WORKDIR/quick-di-config.yaml"
cat "$WORKDIR/quick-di-config.yaml"

log_step "Running quick-di with TPM"
timeout $TIMEOUT_MEDIUM env FDO_TPM_DEVICE="$WORKDIR/swtpm-server" \
    "$QUICKDI_BIN" -config "$WORKDIR/quick-di-config.yaml" 2>&1 | tee "$WORKDIR/quickdi.log" | grep -E "GUID|completed|error|firmware|RV" || true

VOUCHER=$(ls -t "$VOUCHER_DIR"/*.fdoov 2>/dev/null | head -1)
if [ -z "$VOUCHER" ]; then
    log_err "No voucher created"
    echo "--- quick-di log ---"
    cat "$WORKDIR/quickdi.log"
    exit 1
fi
# Fix PEM header if needed (quick-di uses "FDO OWNERSHIP VOUCHER")
sed -i "s/FDO OWNERSHIP VOUCHER/OWNERSHIP VOUCHER/g" "$VOUCHER"
log_ok "Voucher created: $VOUCHER"

# Import voucher into server DB
log_step "Importing voucher into FDO server"
"$SERVER_BIN" server -db "$WORKDIR/fdo.db" -import-voucher "$VOUCHER" -initOnly 2>&1 || {
    echo "Voucher import failed (may already exist), continuing..."
}
log_ok "Voucher imported"

# --- Start HTTP server for firmware payload ---
log_section "Starting HTTP Server (firmware payload)"
cd "$WORKDIR/www"
python3 -m http.server "$HTTP_PORT" --bind 0.0.0.0 > "$WORKDIR/http.log" 2>&1 &
HTTP_PID=$!
sleep 1
if ! kill -0 "$HTTP_PID" 2>/dev/null; then
    log_err "HTTP server failed to start"
    cat "$WORKDIR/http.log"
    exit 1
fi
log_ok "HTTP server on port $HTTP_PORT (PID $HTTP_PID) serving: $(ls "$WORKDIR/www/")"

# Verify payload is accessible
if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${HTTP_PORT}/${FIRMWARE_FILENAME}" | grep -q 200; then
    log_ok "Payload accessible via HTTP (200 OK)"
else
    log_err "Payload NOT accessible via HTTP!"
    exit 1
fi

# --- Start FDO server (for TO1/TO2 fallback after firmware delivery) ---
log_section "Starting FDO Server"
"$SERVER_BIN" -debug server -http "0.0.0.0:$FDO_PORT" -db "$WORKDIR/fdo.db" \
    -rv-bypass -reuse-cred > "$WORKDIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 2
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    log_err "FDO server failed to start"
    cat "$WORKDIR/server.log"
    exit 1
fi
log_ok "FDO server on port $FDO_PORT (PID $SERVER_PID)"

# --- Create boot disk ---
log_section "Creating Boot Disk"
DISK_IMG="$WORKDIR/fdo-disk.img"
dd if=/dev/zero of="$DISK_IMG" bs=1M count=64 2>/dev/null
mkfs.vfat -F 32 "$DISK_IMG" >/dev/null
mmd -i "$DISK_IMG" ::/EFI
mmd -i "$DISK_IMG" ::/EFI/BOOT
mcopy -i "$DISK_IMG" "$RUST_EFI" ::/EFI/BOOT/BOOTX64.EFI
log_ok "Boot disk: $DISK_IMG with BOOTX64.EFI"

# --- Copy OVMF vars ---
cp "$OVMF_VARS_SRC" "$WORKDIR/OVMF_VARS.fd"

# --- Launch QEMU ---
log_section "Starting QEMU (timeout ${TIMEOUT_QEMU}s)"
echo "Firmware delivery URL: $FIRMWARE_URL"
echo "FDO server: http://10.0.2.2:$FDO_PORT"
echo ""

QEMU_LOG="$WORKDIR/qemu.log"
sudo timeout "$TIMEOUT_QEMU" qemu-system-x86_64 \
    -machine q35 -m 2048 \
    -drive if=pflash,format=raw,unit=0,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,unit=1,file="$WORKDIR/OVMF_VARS.fd" \
    -drive file="$DISK_IMG",format=raw,index=0 \
    -chardev socket,id=chrtpm,path="$WORKDIR/swtpm-ctrl" \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 \
    -device virtio-rng-pci \
    -nic user,model=virtio-net-pci \
    -nographic 2>&1 | tee "$QEMU_LOG"

QEMU_EXIT=$?
echo ""

# --- Analyze Results ---
log_section "Test Results Analysis"

echo "QEMU exit code: $QEMU_EXIT"
echo ""

# Check for RV firmware delivery evidence in QEMU output
PASS=0
FAIL=0

check_evidence() {
    local pattern="$1"
    local description="$2"
    if grep -q "$pattern" "$QEMU_LOG"; then
        log_ok "$description"
        PASS=$((PASS + 1))
    else
        log_err "$description — NOT FOUND in output"
        FAIL=$((FAIL + 1))
    fi
}

check_evidence "RV-Based Firmware Delivery" "RV firmware delivery module started"
check_evidence "Reading DCTPM" "Step 1: DCTPM read from TPM NV"
check_evidence "Parsing RV firmware" "Step 2: RV firmware info parsed"
check_evidence "FirmwareURL" "Firmware URL extracted from RV tags"
check_evidence "Downloading firmware" "Step 3: Firmware download attempted"
check_evidence "Downloaded.*bytes" "Firmware payload downloaded"
check_evidence "Verifying COSE" "Step 4: COSE_Sign1 verification"
check_evidence "Signature VALID" "COSE signature verified successfully"
check_evidence "Chain-loading\|Launching FDO Installer" "Step 5: Chainload attempted"

echo ""
echo "--- HTTP server log ---"
cat "$WORKDIR/http.log" 2>/dev/null | head -10
echo ""
echo "--- FDO server log (last 10 lines) ---"
tail -10 "$WORKDIR/server.log" 2>/dev/null
echo ""

# Summary
log_section "Summary"
echo "Evidence checks: $PASS passed, $FAIL failed"

if [ "$FAIL" -eq 0 ] && [ "$PASS" -gt 0 ]; then
    log_ok "RV Firmware Delivery QEMU test PASSED"
    exit 0
else
    log_err "RV Firmware Delivery QEMU test FAILED ($FAIL checks failed)"
    echo ""
    echo "Full QEMU log: $QEMU_LOG"
    echo "Quick-DI log:  $WORKDIR/quickdi.log"
    echo "Server log:    $WORKDIR/server.log"
    echo "HTTP log:      $WORKDIR/http.log"
    exit 1
fi
