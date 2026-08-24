#!/bin/bash
# test-di.sh - FDO Device Initialization (DI) Protocol Integration Test
#
# Tests the full DI protocol flow between the Rust UEFI client and
# the go-fdo server, running in a QEMU VM with swtpm TPM emulator.
#
# Usage:
#   ./test-di.sh              # Run positive test (default)
#   ./test-di.sh positive     # Run positive test (DI should succeed)
#   ./test-di.sh negative     # Run negative test (DI should fail with clear error)
#   ./test-di.sh all          # Run both positive and negative tests
#
# Prerequisites (on test machine):
#   - qemu-system-x86_64, ovmf, mtools, dosfstools, swtpm
#   - go-fdo server binary (set FDO_SERVER env var, or builds from ../go-fdo)
#   - Rust UEFI client binary (set RUST_EFI env var, or uses default path)
#
# Environment variables:
#   FDO_SERVER   Path to go-fdo server binary (default: builds from ../go-fdo)
#   RUST_EFI     Path to fdo-uefi.efi (default: target/x86_64-unknown-uefi/release/fdo-uefi.efi)
#   WORKDIR      Working directory for test artifacts (default: /tmp/fdo-di-test)
#   TIMEOUT      QEMU timeout in seconds (default: 90)
#   KEEP_LOGS    Set to 1 to preserve workdir after test (default: clean up)
#
# Evidence:
#   The test checks for specific evidence of success or failure:
#   - Server log: Message-Type headers, CBOR bodies, voucher creation
#   - QEMU output: UEFI client log messages (GUID, HMAC, NV writes)
#   - Test verdict: PASS/FAIL with specific evidence cited
#
# Copyright 2026 Dell Technologies. All Rights Reserved.
# Licensed under Apache License 2.0.

set -euo pipefail

# ─── Configuration ──────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKDIR="${WORKDIR:-/tmp/fdo-di-test}"
TIMEOUT="${TIMEOUT:-90}"
KEEP_LOGS="${KEEP_LOGS:-0}"

# Server binary: use env var, or look for pre-built, or build from source
if [ -n "${FDO_SERVER:-}" ]; then
    :
elif [ -x /home/bkg/fdo-server-new ]; then
    FDO_SERVER=/home/bkg/fdo-server-new
elif [ -x "$SCRIPT_DIR/../go-fdo/fdo-server" ]; then
    FDO_SERVER="$SCRIPT_DIR/../go-fdo/fdo-server"
else
    echo "Building go-fdo server..."
    FDO_SERVER="$WORKDIR/fdo-server"
    (cd "$SCRIPT_DIR/../go-fdo" && go build -o "$FDO_SERVER" ./examples/cmd/) 2>&1
fi

# UEFI binary
RUST_EFI="${RUST_EFI:-$SCRIPT_DIR/target/x86_64-unknown-uefi/release/fdo-uefi.efi}"

# OVMF firmware
find_ovmf() {
    for path in /usr/share/OVMF /usr/share/edk2/ovmf /usr/share/qemu; do
        if [ -f "$path/OVMF_CODE_4M.fd" ]; then
            OVMF_CODE="$path/OVMF_CODE_4M.fd"
            OVMF_VARS_SRC="$path/OVMF_VARS_4M.fd"
            return 0
        elif [ -f "$path/OVMF_CODE.fd" ]; then
            OVMF_CODE="$path/OVMF_CODE.fd"
            OVMF_VARS_SRC="$path/OVMF_VARS.fd"
            return 0
        fi
    done
    echo "ERROR: OVMF firmware not found. Install: apt install ovmf"
    return 1
}

# ─── Helpers ────────────────────────────────────────────────────────
PASS_COUNT=0
FAIL_COUNT=0

pass() {
    echo "  ✓ PASS: $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
    echo "  ✗ FAIL: $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

cleanup() {
    echo ""
    echo "--- Cleanup ---"
    kill "$SERVER_PID" 2>/dev/null || true
    sudo killall -9 swtpm 2>/dev/null || true
    if [ "$KEEP_LOGS" = "0" ] && [ "$FAIL_COUNT" -eq 0 ]; then
        rm -rf "$WORKDIR"
        echo "Cleaned up $WORKDIR (set KEEP_LOGS=1 to preserve)"
    else
        echo "Logs preserved in $WORKDIR"
        echo "  Server log: $WORKDIR/server.log"
        echo "  QEMU output: $WORKDIR/qemu.log"
    fi
}

# ─── Setup (shared by all tests) ───────────────────────────────────
setup() {
    echo ""
    echo "============================================"
    echo "  FDO DI Protocol Test: $1"
    echo "============================================"
    echo ""

    # Preflight checks
    if [ ! -x "$FDO_SERVER" ] && [ ! -f "$FDO_SERVER" ]; then
        echo "ERROR: FDO server not found at $FDO_SERVER"
        exit 1
    fi
    if [ ! -f "$RUST_EFI" ]; then
        echo "ERROR: UEFI binary not found at $RUST_EFI"
        echo "Build with: cargo +nightly build --release"
        exit 1
    fi
    find_ovmf

    echo "Config:"
    echo "  FDO server:  $FDO_SERVER"
    echo "  UEFI binary: $RUST_EFI ($(wc -c < "$RUST_EFI") bytes)"
    echo "  OVMF:        $OVMF_CODE"
    echo "  Workdir:     $WORKDIR"
    echo "  Timeout:     ${TIMEOUT}s"
    echo ""

    # Clean slate
    sudo killall -9 swtpm qemu-system-x86_64 2>/dev/null || true
    sudo fuser -k 8080/tcp 2>/dev/null || true
    sleep 1
    rm -rf "$WORKDIR"
    mkdir -p "$WORKDIR"

    # Init database (creates manufacturer keys for EC256, EC384, RSA)
    echo "--- Initializing go-fdo database ---"
    "$FDO_SERVER" server -db "$WORKDIR/fdo.db" -http 127.0.0.1:19999 -initOnly 2>&1
    echo "Database: $WORKDIR/fdo.db ($(wc -c < "$WORKDIR/fdo.db") bytes)"

    # Start swtpm (clean TPM state = no FDO credentials)
    echo ""
    echo "--- Starting swtpm (clean state) ---"
    swtpm socket --tpmstate dir="$WORKDIR" \
        --ctrl type=unixio,path="$WORKDIR/swtpm-ctrl" \
        --tpm2 --flags startup-clear --daemon
    sleep 1
    if [ ! -S "$WORKDIR/swtpm-ctrl" ]; then
        echo "ERROR: swtpm control socket not created"
        exit 1
    fi
    echo "swtpm: daemon mode, ctrl=$WORKDIR/swtpm-ctrl"

    # Start go-fdo server
    echo ""
    echo "--- Starting go-fdo server (port 8080) ---"
    "$FDO_SERVER" -debug server -http 0.0.0.0:8080 -db "$WORKDIR/fdo.db" \
        -rv-bypass > "$WORKDIR/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 2
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "ERROR: Server failed to start"
        cat "$WORKDIR/server.log"
        exit 1
    fi
    echo "Server PID: $SERVER_PID"

    # Create boot disk
    # The UEFI client needs -di flag to know the server address.
    # In QEMU user-mode networking, the host is at 10.0.2.2.
    # We use a startup.nsh script to pass the -di argument.
    echo ""
    echo "--- Creating boot disk ---"
    DISK_IMG="$WORKDIR/fdo-disk.img"
    dd if=/dev/zero of="$DISK_IMG" bs=1M count=64 2>/dev/null
    mkfs.vfat -F 32 "$DISK_IMG" >/dev/null
    mmd -i "$DISK_IMG" ::/EFI
    mmd -i "$DISK_IMG" ::/EFI/BOOT
    mcopy -i "$DISK_IMG" "$RUST_EFI" ::/EFI/BOOT/BOOTX64.EFI

    # Create startup.nsh that passes the DI server URL
    STARTUP_NSH="$WORKDIR/startup.nsh"
    printf 'fs0:\\EFI\\BOOT\\BOOTX64.EFI -di http://10.0.2.2:8080\r\n' > "$STARTUP_NSH"
    mcopy -i "$DISK_IMG" "$STARTUP_NSH" ::/startup.nsh

    cp "$OVMF_VARS_SRC" "$WORKDIR/OVMF_VARS.fd"
    echo "Boot disk: $DISK_IMG"
    echo "DI server: http://10.0.2.2:8080 (QEMU host)"
}

# ─── Run QEMU ──────────────────────────────────────────────────────
run_qemu() {
    echo ""
    echo "--- Running QEMU (timeout ${TIMEOUT}s) ---"
    echo ""

    # QEMU exits via timeout (code 124) or -no-reboot (code 0); both are OK
    sudo timeout "$TIMEOUT" qemu-system-x86_64 \
        -machine q35 -m 2048 \
        -drive if=pflash,format=raw,unit=0,readonly=on,file="$OVMF_CODE" \
        -drive if=pflash,format=raw,unit=1,file="$WORKDIR/OVMF_VARS.fd" \
        -drive file="$WORKDIR/fdo-disk.img",format=raw,index=0 \
        -chardev socket,id=chrtpm,path="$WORKDIR/swtpm-ctrl" \
        -tpmdev emulator,id=tpm0,chardev=chrtpm \
        -device tpm-tis,tpmdev=tpm0 \
        -device virtio-rng-pci \
        -nic user,model=virtio-net-pci \
        -nographic -no-reboot 2>&1 | tee "$WORKDIR/qemu.log" || true

    echo ""
}

# ─── Positive Test ──────────────────────────────────────────────────
# Verifies that DI completes successfully with:
#   - Server accepts DIAppStart (msg 10) and returns DISetCredentials (msg 11)
#   - Server accepts DISetHMAC (msg 12) and returns DIDone (msg 13)
#   - Client logs "Device Initialization COMPLETE" with a GUID
#   - Client writes DCTPM to TPM NV index
test_positive() {
    setup "POSITIVE (DI should succeed)"

    run_qemu

    echo "--- Checking evidence ---"
    echo ""

    # Evidence 1: Server received DIAppStart and returned DISetCredentials
    if grep -q "Message-Type: 11" "$WORKDIR/server.log" 2>/dev/null; then
        pass "Server returned DISetCredentials (Message-Type: 11)"
    else
        fail "Server did not return DISetCredentials"
    fi

    # Evidence 2: Server received DISetHMAC and returned DIDone
    if grep -q "Message-Type: 13" "$WORKDIR/server.log" 2>/dev/null; then
        pass "Server returned DIDone (Message-Type: 13)"
    else
        fail "Server did not return DIDone"
    fi

    # Evidence 3: No error responses from server
    if grep -q "Message-Type: 255" "$WORKDIR/server.log" 2>/dev/null; then
        fail "Server returned error (Message-Type: 255)"
        # Show error details
        grep "body:" "$WORKDIR/server.log" | tail -1
    else
        pass "No server errors (no Message-Type: 255)"
    fi

    # Evidence 4: Client logged "Device Initialization COMPLETE"
    if grep -q "Device Initialization COMPLETE" "$WORKDIR/qemu.log" 2>/dev/null; then
        pass "Client logged 'Device Initialization COMPLETE'"
    else
        fail "Client did not log completion"
    fi

    # Evidence 5: Client logged a GUID
    if grep -q "GUID:" "$WORKDIR/qemu.log" 2>/dev/null; then
        GUID_LINE=$(grep "GUID:" "$WORKDIR/qemu.log" | head -1)
        pass "Client received GUID: $GUID_LINE"
    else
        fail "Client did not log GUID"
    fi

    # Evidence 6: Client wrote to TPM NV
    if grep -q "NV DefineSpace" "$WORKDIR/qemu.log" 2>/dev/null; then
        pass "Client wrote DCTPM to TPM NV index"
    else
        fail "Client did not write to TPM NV"
    fi

    # Evidence 7: Server log shows 2 successful request/response pairs
    REQ_COUNT=$(grep -c "request" "$WORKDIR/server.log" 2>/dev/null || echo 0)
    if [ "$REQ_COUNT" -ge 2 ]; then
        pass "Server processed $REQ_COUNT requests (expected 2: msg 10, msg 12)"
    else
        fail "Server only processed $REQ_COUNT requests (expected 2)"
    fi

    # Evidence 8: Session token was used (Authorization header in msg 12)
    if grep -q "Authorization: Bearer" "$WORKDIR/server.log" 2>/dev/null; then
        pass "Session token (Authorization: Bearer) present in requests"
    else
        fail "No session token found in server log"
    fi
}

# ─── Negative Test ──────────────────────────────────────────────────
# Verifies that errors are properly detected and reported when the
# server rejects the DI request. We start the server without a
# database (no manufacturer keys) so it cannot process DI.
test_negative() {
    setup "NEGATIVE (DI should fail with clear error)"

    # Sabotage: delete the database so server has no manufacturer keys
    # The server will start but fail when trying to look up keys
    echo ""
    echo "--- Sabotage: removing database to trigger server error ---"
    rm -f "$WORKDIR/fdo.db"
    # Reinitialize with empty db (no keys)
    kill "$SERVER_PID" 2>/dev/null || true
    sleep 1

    # Start server with a fresh empty database (no -initOnly = no keys)
    touch "$WORKDIR/fdo.db"
    "$FDO_SERVER" -debug server -http 0.0.0.0:8080 -db "$WORKDIR/fdo.db" \
        -rv-bypass > "$WORKDIR/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 2
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "Server failed to start (expected for some error modes)"
        # Try with no server at all
        SERVER_PID=0
    fi

    run_qemu

    echo "--- Checking evidence ---"
    echo ""

    # Evidence 1: Server returned an error (Message-Type: 255)
    if grep -q "Message-Type: 255" "$WORKDIR/server.log" 2>/dev/null; then
        pass "Server returned error (Message-Type: 255) as expected"
    elif ! grep -q "Message-Type: 11" "$WORKDIR/server.log" 2>/dev/null; then
        pass "Server did not return DISetCredentials (DI rejected as expected)"
    else
        fail "Server unexpectedly succeeded (returned Message-Type: 11)"
    fi

    # Evidence 2: Client detected and logged the error
    if grep -q "FDO Error" "$WORKDIR/qemu.log" 2>/dev/null; then
        ERR_LINE=$(grep "FDO Error" "$WORKDIR/qemu.log" | head -1)
        pass "Client decoded server error: $ERR_LINE"
    elif grep -q "Server returned error" "$WORKDIR/qemu.log" 2>/dev/null; then
        pass "Client detected server error (Message-Type 255)"
    elif grep -q "PROTOCOL_ERROR\|Failed to send" "$WORKDIR/qemu.log" 2>/dev/null; then
        pass "Client reported protocol error"
    else
        fail "Client did not detect or report any error"
    fi

    # Evidence 3: Client did NOT log "Device Initialization COMPLETE"
    if grep -q "Device Initialization COMPLETE" "$WORKDIR/qemu.log" 2>/dev/null; then
        fail "Client falsely reported DI completion despite server error"
    else
        pass "Client correctly did NOT report DI completion"
    fi

    # Evidence 4: Client logged a meaningful error message (not just crash)
    if grep -q "Device Initialization failed" "$WORKDIR/qemu.log" 2>/dev/null; then
        pass "Client logged 'Device Initialization failed' (clean failure)"
    else
        fail "Client did not log clean failure message"
    fi
}

# ─── Main ───────────────────────────────────────────────────────────
trap cleanup EXIT

TEST_MODE="${1:-positive}"

case "$TEST_MODE" in
    positive)
        test_positive
        ;;
    negative)
        test_negative
        ;;
    all)
        test_positive
        cleanup
        PASS_COUNT_POS=$PASS_COUNT
        FAIL_COUNT_POS=$FAIL_COUNT
        PASS_COUNT=0
        FAIL_COUNT=0
        test_negative
        PASS_COUNT=$((PASS_COUNT + PASS_COUNT_POS))
        FAIL_COUNT=$((FAIL_COUNT + FAIL_COUNT_POS))
        ;;
    *)
        echo "Usage: $0 [positive|negative|all]"
        exit 1
        ;;
esac

echo ""
echo "============================================"
echo "  Results: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "============================================"

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "  VERDICT: FAIL"
    echo "  Logs: $WORKDIR/"
    exit 1
else
    echo "  VERDICT: PASS"
    exit 0
fi
