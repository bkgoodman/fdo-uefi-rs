#!/bin/bash
#
# start-hw-server.sh -- FDO server for real hardware EFI client testing
#
# Runs on pe2 (192.168.200.30). The onlogic (192.168.200.26) connects
# over the real network -- no QEMU, no swtpm.
#
# Usage:
#   ./start-hw-server.sh di               DI (device initialization)
#   ./start-hw-server.sh to2              TO2 + unsigned BMO (Model 1)
#   ./start-hw-server.sh to2-signed       TO2 + owner-signed BMO (Model 3)
#   ./start-hw-server.sh to2-scope        TO2 + signed BMO with scope
#   ./start-hw-server.sh stop             Kill server
#   ./start-hw-server.sh status           Show server status + recent log
#
# On EFI shell (DI):
#   fs0:\EFI\fdo-uefi.efi -force-di -di http://192.168.200.30:8080
#
# On EFI shell (TO2, no flags needed):
#   fs0:\EFI\fdo-uefi.efi
#
# Logs:  /tmp/fdo-hw-test/server.log

set -e

WORKDIR=/tmp/fdo-hw-test
SERVER="$HOME/bkgvm/server"
FIRMWARE_DIR=/tmp/fdo-firmware-server
TEST_IMAGE="${TEST_IMAGE:-$FIRMWARE_DIR/test.efi}"   # override, e.g. TEST_IMAGE=~/bkgvm/hello-efi.efi
UKI="$FIRMWARE_DIR/ubuntu-26.04.1-live-server-fdo.efi"
EXT_HTTP=192.168.200.30:8080

DELEGATE_NAME=provDelegate

META_HTTP_PORT=9090
META_HTTP_DIR=/tmp/fdo-meta-hw

usage() {
    echo "Usage: $0 {di|to2|to2-signed|to2-scope|to2-delegate|to2-delegate-signed|to2-meta|to2-meta-signed|to2-uki|stop|status}"
    echo ""
    echo "  di                   Init fresh DB + start server for DI"
    echo "  to2                  TO2 + unsigned BMO test image (Model 1)"
    echo "  to2-signed           TO2 + owner-signed BMO test image (Model 3)"
    echo "  to2-scope            TO2 + signed BMO with scope (not_before/not_after/generation)"
    echo "  to2-delegate         TO2 via delegate with PERM.7, unsigned BMO (Model 2)"
    echo "  to2-delegate-signed  TO2 via delegate, delegate-signed BMO (Model 4)"
    echo "  to2-meta             TO2 + unsigned meta-payload delivery (mode 2)"
    echo "  to2-meta-signed      TO2 + signed meta-payload delivery (mode 2, COSE_Sign1)"
    echo "  to2-uki              TO2 + unsigned BMO with full 106MB UKI"
    echo "  stop                 Kill server"
    echo "  status               Show server status and recent log"
    exit 1
}

stop_server() {
    killall server 2>/dev/null || true
    # Also stop any meta-payload HTTP server on META_HTTP_PORT
    fuser -k ${META_HTTP_PORT}/tcp 2>/dev/null || true
    sleep 1
}

ensure_test_image() {
    if [ ! -f "$TEST_IMAGE" ]; then
        echo "Creating 10KB test image..."
        dd if=/dev/urandom of="$TEST_IMAGE" bs=1024 count=10 2>/dev/null
    fi
}

case "${1:-}" in
    di)
        stop_server
        mkdir -p "$WORKDIR"
        rm -f "$WORKDIR/fdo.db"

        echo "=== Initializing fresh database ==="
        timeout 10 "$SERVER" server -db "$WORKDIR/fdo.db" -http 127.0.0.1:8080 -initOnly 2>&1 || true
        echo "Database: $WORKDIR/fdo.db"
        echo ""
        echo "=== Starting DI server ==="
        echo "Listening on 0.0.0.0:8080 (external: $EXT_HTTP)"
        echo ""
        echo "On EFI shell:"
        echo "  fs0:\\EFI\\fdo-uefi.efi -force-di -di http://$EXT_HTTP"
        echo ""
        echo "Press Ctrl-C after DI completes, then run: $0 to2"
        echo ""

        "$SERVER" server -http 0.0.0.0:8080 -db "$WORKDIR/fdo.db" \
            -ext-http "$EXT_HTTP" \
            -rv-bypass 2>&1 | tee "$WORKDIR/server.log"
        ;;

    to2)
        if [ ! -f "$WORKDIR/fdo.db" ]; then
            echo "ERROR: No database. Run '$0 di' first." >&2
            exit 1
        fi
        ensure_test_image
        stop_server

        echo "=== Starting TO2 server (unsigned BMO, Model 1) ==="
        echo "BMO image: $TEST_IMAGE ($(du -h "$TEST_IMAGE" | cut -f1))"
        echo ""
        echo "On EFI shell:"
        echo "  fs0:\\EFI\\fdo-uefi.efi"
        echo ""

        "$SERVER" -debug server -http 0.0.0.0:8080 -db "$WORKDIR/fdo.db" \
            -ext-http "$EXT_HTTP" \
            -rv-bypass -reuse-cred \
            -bmo "application/x-uefi-image:$TEST_IMAGE" \
            2>&1 | tee "$WORKDIR/server.log"
        ;;

    to2-signed)
        if [ ! -f "$WORKDIR/fdo.db" ]; then
            echo "ERROR: No database. Run '$0 di' first." >&2
            exit 1
        fi
        ensure_test_image
        stop_server

        echo "=== Starting TO2 server (owner-signed BMO, Model 3) ==="
        echo "BMO image: $TEST_IMAGE ($(du -h "$TEST_IMAGE" | cut -f1))"
        echo ""
        echo "On EFI shell:"
        echo "  fs0:\\EFI\\fdo-uefi.efi"
        echo ""

        "$SERVER" -debug server -http 0.0.0.0:8080 -db "$WORKDIR/fdo.db" \
            -ext-http "$EXT_HTTP" \
            -rv-bypass -reuse-cred -bmo-sign \
            -bmo "application/x-uefi-image:$TEST_IMAGE" \
            2>&1 | tee "$WORKDIR/server.log"
        ;;

    to2-scope)
        if [ ! -f "$WORKDIR/fdo.db" ]; then
            echo "ERROR: No database. Run '$0 di' first." >&2
            exit 1
        fi
        ensure_test_image
        stop_server

        echo "=== Starting TO2 server (signed BMO + scope, Model 3) — NEGATIVE ==="
        echo "BMO image: $TEST_IMAGE ($(du -h "$TEST_IMAGE" | cut -f1))"
        echo "Scope: not_before=2025-01-01, not_after=2030-01-01, generation=1"
        echo "EXPECT: the device REJECTS this artifact. The EFI client has no"
        echo "trustworthy clock and no rollback-protected storage, so time and"
        echo "generation constraints are unevaluable and MUST fail closed"
        echo "(errors 17/18, chunking-strategy.md 'Unevaluable constraints')."
        echo ""
        echo "On EFI shell:"
        echo "  fs0:\\EFI\\fdo-uefi.efi"
        echo ""

        "$SERVER" -debug server -http 0.0.0.0:8080 -db "$WORKDIR/fdo.db" \
            -ext-http "$EXT_HTTP" \
            -rv-bypass -reuse-cred -bmo-sign \
            -bmo-scope-not-before "2025-01-01T00:00:00Z" \
            -bmo-scope-not-after "2030-01-01T00:00:00Z" \
            -bmo-scope-generation 1 \
            -bmo "application/x-uefi-image:$TEST_IMAGE" \
            2>&1 | tee "$WORKDIR/server.log"
        ;;

    to2-delegate)
        if [ ! -f "$WORKDIR/fdo.db" ]; then
            echo "ERROR: No database. Run '$0 di' first." >&2
            exit 1
        fi
        ensure_test_image
        stop_server

        # Create delegate if it doesn't exist
        if ! "$SERVER" delegate -db "$WORKDIR/fdo.db" list 2>/dev/null | grep -q "$DELEGATE_NAME"; then
            echo "Creating delegate '$DELEGATE_NAME' with onboard+provision..."
            "$SERVER" delegate -db "$WORKDIR/fdo.db" create "$DELEGATE_NAME" onboard,provision SECP256R1 ec256 2>&1
        fi

        echo "=== Starting TO2 server (delegate + unsigned BMO, Model 2) ==="
        echo "Delegate: $DELEGATE_NAME (onboard+provision, PERM.7)"
        echo "BMO image: $TEST_IMAGE ($(du -h "$TEST_IMAGE" | cut -f1))"
        echo ""
        echo "On EFI shell:"
        echo "  fs0:\\EFI\\fdo-uefi.efi"
        echo ""

        "$SERVER" -debug server -http 0.0.0.0:8080 -db "$WORKDIR/fdo.db" \
            -ext-http "$EXT_HTTP" \
            -rv-bypass -reuse-cred \
            -onboardDelegate "$DELEGATE_NAME" \
            -bmo "application/x-uefi-image:$TEST_IMAGE" \
            2>&1 | tee "$WORKDIR/server.log"
        ;;

    to2-delegate-signed)
        if [ ! -f "$WORKDIR/fdo.db" ]; then
            echo "ERROR: No database. Run '$0 di' first." >&2
            exit 1
        fi
        ensure_test_image
        stop_server

        # Create delegate if it doesn't exist
        if ! "$SERVER" delegate -db "$WORKDIR/fdo.db" list 2>/dev/null | grep -q "$DELEGATE_NAME"; then
            echo "Creating delegate '$DELEGATE_NAME' with onboard+provision..."
            "$SERVER" delegate -db "$WORKDIR/fdo.db" create "$DELEGATE_NAME" onboard,provision SECP256R1 ec256 2>&1
        fi

        # Export delegate cert chain and key
        "$SERVER" delegate -db "$WORKDIR/fdo.db" print "$DELEGATE_NAME" > "$WORKDIR/delegate-chain.pem"
        "$SERVER" delegate -db "$WORKDIR/fdo.db" key "$DELEGATE_NAME" > "$WORKDIR/delegate-key.pem"

        echo "=== Starting TO2 server (delegate-signed BMO, Model 4) ==="
        echo "Delegate: $DELEGATE_NAME (onboard+provision, PERM.7)"
        echo "BMO signing: delegate cert chain + key (x5chain in COSE)"
        echo "BMO image: $TEST_IMAGE ($(du -h "$TEST_IMAGE" | cut -f1))"
        echo ""
        echo "On EFI shell:"
        echo "  fs0:\\EFI\\fdo-uefi.efi"
        echo ""

        "$SERVER" -debug server -http 0.0.0.0:8080 -db "$WORKDIR/fdo.db" \
            -ext-http "$EXT_HTTP" \
            -rv-bypass -reuse-cred \
            -onboardDelegate "$DELEGATE_NAME" \
            -bmo-delegate-provision "$WORKDIR/delegate-chain.pem:$WORKDIR/delegate-key.pem" \
            -bmo "application/x-uefi-image:$TEST_IMAGE" \
            2>&1 | tee "$WORKDIR/server.log"
        ;;

    to2-meta)
        if [ ! -f "$WORKDIR/fdo.db" ]; then
            echo "ERROR: No database. Run '$0 di' first." >&2
            exit 1
        fi
        stop_server
        mkdir -p "$META_HTTP_DIR"

        echo "=== Create test image + unsigned meta-payload ==="
        dd if=/dev/urandom of="$META_HTTP_DIR/test-image.efi" bs=1K count=8 2>/dev/null
        IMAGE_HASH=$(sha256sum "$META_HTTP_DIR/test-image.efi" | cut -d' ' -f1)
        IMAGE_URL="http://192.168.200.30:${META_HTTP_PORT}/test-image.efi"
        echo "Image: 8 KB, SHA256=$IMAGE_HASH"
        echo "Image URL: $IMAGE_URL"

        "$SERVER" meta create \
            -mime "application/x-uefi-image" \
            -url "$IMAGE_URL" \
            -hash-file "$META_HTTP_DIR/test-image.efi" \
            -name "hw-meta-test" \
            -out "$META_HTTP_DIR/meta.cbor"
        echo "Meta-payload: $(wc -c < "$META_HTTP_DIR/meta.cbor") bytes"
        META_URL="http://192.168.200.30:${META_HTTP_PORT}/meta.cbor"

        echo "=== Start HTTP server for meta + image ==="
        cd "$META_HTTP_DIR"
        python3 -m http.server $META_HTTP_PORT --bind 0.0.0.0 > "$WORKDIR/meta-http.log" 2>&1 &
        META_PID=$!
        cd - > /dev/null
        sleep 1
        echo "HTTP server: PID $META_PID, port $META_HTTP_PORT"

        echo "=== Starting TO2 server (unsigned meta-URL, mode 2) ==="
        echo "Meta URL: $META_URL"
        echo "The meta-payload is unsigned and fetched over plain HTTP, so it is only"
        echo "a pointer: image-begin pins the image hash (-bmo-meta-hash / key 8)."
        echo "Without it the device refuses (error 19). Requires a go-fdo server"
        echo "built 2026-10-02 or later (-bmo-meta-hash)."
        echo ""
        echo "On EFI shell:"
        echo "  fs0:\\EFI\\fdo-uefi.efi"
        echo ""

        "$SERVER" -debug server -http 0.0.0.0:8080 -db "$WORKDIR/fdo.db" \
            -ext-http "$EXT_HTTP" \
            -rv-bypass -reuse-cred -bmo-sign \
            -bmo-meta-url "$META_URL" -bmo-meta-hash "$IMAGE_HASH" \
            2>&1 | tee "$WORKDIR/server.log"
        ;;

    to2-meta-signed)
        if [ ! -f "$WORKDIR/fdo.db" ]; then
            echo "ERROR: No database. Run '$0 di' first." >&2
            exit 1
        fi
        stop_server
        mkdir -p "$META_HTTP_DIR"

        echo "=== Create test image + signed meta-payload ==="
        dd if=/dev/urandom of="$META_HTTP_DIR/test-image.efi" bs=1K count=8 2>/dev/null
        IMAGE_HASH=$(sha256sum "$META_HTTP_DIR/test-image.efi" | cut -d' ' -f1)
        IMAGE_URL="http://192.168.200.30:${META_HTTP_PORT}/test-image.efi"
        echo "Image: 8 KB, SHA256=$IMAGE_HASH"
        echo "Image URL: $IMAGE_URL"

        # Generate vendor signing key
        openssl ecparam -name prime256v1 -genkey -noout -out "$WORKDIR/meta-signer.pem" 2>/dev/null
        echo "Vendor key generated"

        "$SERVER" meta create-signed \
            -mime "application/x-uefi-image" \
            -url "$IMAGE_URL" \
            -hash-file "$META_HTTP_DIR/test-image.efi" \
            -name "hw-meta-test-signed" \
            -key "$WORKDIR/meta-signer.pem" \
            -out "$META_HTTP_DIR/meta.cbor"
        echo "Signed meta-payload: $(wc -c < "$META_HTTP_DIR/meta.cbor") bytes"

        "$SERVER" meta export-pubkey \
            -key "$WORKDIR/meta-signer.pem" \
            -out "$WORKDIR/signer.cbor"
        echo "COSE_Key exported: $(wc -c < "$WORKDIR/signer.cbor") bytes"

        META_URL="http://192.168.200.30:${META_HTTP_PORT}/meta.cbor"

        echo "=== Start HTTP server for meta + image ==="
        cd "$META_HTTP_DIR"
        python3 -m http.server $META_HTTP_PORT --bind 0.0.0.0 > "$WORKDIR/meta-http.log" 2>&1 &
        META_PID=$!
        cd - > /dev/null
        sleep 1
        echo "HTTP server: PID $META_PID, port $META_HTTP_PORT"

        echo "=== Starting TO2 server (signed meta-URL, mode 2) ==="
        echo "Meta URL: $META_URL (signed with vendor key)"
        echo ""
        echo "On EFI shell:"
        echo "  fs0:\\EFI\\fdo-uefi.efi"
        echo ""

        "$SERVER" -debug server -http 0.0.0.0:8080 -db "$WORKDIR/fdo.db" \
            -ext-http "$EXT_HTTP" \
            -rv-bypass -reuse-cred -bmo-sign \
            -bmo-meta-url "$META_URL:$WORKDIR/signer.cbor" \
            2>&1 | tee "$WORKDIR/server.log"
        ;;

    to2-uki)
        if [ ! -f "$WORKDIR/fdo.db" ]; then
            echo "ERROR: No database. Run '$0 di' first." >&2
            exit 1
        fi
        if [ ! -f "$UKI" ]; then
            echo "ERROR: UKI not found: $UKI" >&2
            exit 1
        fi
        stop_server

        echo "=== Starting TO2 server (unsigned BMO, full UKI) ==="
        echo "BMO image: $UKI ($(du -h "$UKI" | cut -f1))"
        echo "WARNING: ~106MB transfer, ~10-12 minutes at 65KB/round"
        echo ""
        echo "On EFI shell:"
        echo "  fs0:\\EFI\\fdo-uefi.efi"
        echo ""

        "$SERVER" -debug server -http 0.0.0.0:8080 -db "$WORKDIR/fdo.db" \
            -ext-http "$EXT_HTTP" \
            -rv-bypass -reuse-cred \
            -bmo "application/x-uefi-image:$UKI" \
            2>&1 | tee "$WORKDIR/server.log"
        ;;

    status)
        if pgrep -x server >/dev/null; then
            echo "Server is RUNNING (PID $(pgrep -x server))"
            pgrep -la server
        else
            echo "Server is NOT running"
        fi
        if [ -f "$WORKDIR/server.log" ]; then
            echo ""
            echo "=== Last 20 lines ==="
            tail -20 "$WORKDIR/server.log"
        fi
        ;;

    stop)
        stop_server
        echo "Server stopped."
        ;;

    *)
        usage
        ;;
esac
