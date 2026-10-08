#!/bin/bash
# start16-metatool.sh - BMO meta-URL delivery with meta-payloads produced by
# go-fdo-meta-tool (not the go-fdo CLI), consumed by the UEFI client in QEMU.
# Modeled on start15-meta-url.sh. Image is ~/bkgvm/hello-efi.efi, so a
# successful run ends with "HELLO-EFI" in the device log.
#
# Usage: ./start16-metatool.sh [unsigned|signed|signed-wrongkey|unsigned-bootargs|all]
#   unsigned          - unsigned meta as a pointer, image hash pinned in
#                       image-begin (-bmo-meta-hash). Expect ACCEPT + chainload.
#   signed            - meta signed by a named publisher key (meta_signer).
#                       Expect signature VERIFIED + chainload.
#   signed-wrongkey   - NEGATIVE: meta signed with key A, image-begin names key B.
#                       Expect REFUSAL, nothing chainloaded.
#   unsigned-bootargs - NEGATIVE: unsigned meta carrying boot_args (an
#                       instruction field), hash pinned. Expect REFUSAL (error 15).

set -e
source ~/bkgvm/fdo-cleanup.sh

MODE=${1:-all}
FDO_TOOL=/home/bkg/bkgvm/server
META_TOOL=/home/bkg/bkgvm/fdo-meta-tool
IMAGE_SRC=/home/bkg/bkgvm/hello-efi.efi
TIMEOUT_SHORT=10
TIMEOUT_MEDIUM=30
TIMEOUT_QEMU=${TIMEOUT_QEMU:-150}
WORKDIR=/tmp/fdo-metatool-test
VOUCHER_DIR=/tmp/fdo-vouchers-metatool
HTTP_DIR=/tmp/fdo-metatool-http
HTTP_PORT=9091
RESULTS=()

cleanup_http() {
    if [ -n "$HTTP_PID" ] && kill -0 "$HTTP_PID" 2>/dev/null; then
        kill "$HTTP_PID" 2>/dev/null || true
        wait "$HTTP_PID" 2>/dev/null || true
    fi
}

run_test() {
    local T=$1
    echo ""
    echo "=========================================="
    echo "=== meta-tool test: $T ==="
    echo "=========================================="

    fdo_cleanup "$WORKDIR"
    cleanup_http
    sleep 1
    rm -rf "$WORKDIR" "$VOUCHER_DIR" "$HTTP_DIR"
    mkdir -p "$WORKDIR" "$VOUCHER_DIR" "$HTTP_DIR"
    cp /usr/share/OVMF/OVMF_VARS_4M.fd "$WORKDIR/OVMF_VARS.fd"

    cp "$IMAGE_SRC" "$HTTP_DIR/test-image.efi"
    PIN=$(sha256sum "$HTTP_DIR/test-image.efi" | cut -d' ' -f1)
    echo "Image: $(wc -c < "$HTTP_DIR/test-image.efi") bytes, sha256 $PIN"
    IMAGE_URL="http://10.0.2.2:$HTTP_PORT/test-image.efi"
    META_URL="http://10.0.2.2:$HTTP_PORT/meta.cbor"

    echo "=== Create meta-payload with fdo-meta-tool ==="
    case "$T" in
        unsigned)
            $META_TOOL meta create -mime "application/x-uefi-image" -url "$IMAGE_URL" \
                -hash-file "$HTTP_DIR/test-image.efi" -name "metatool-unsigned" \
                -out "$HTTP_DIR/meta.cbor"
            BMO_META_ARG="-bmo-meta-url $META_URL -bmo-meta-hash $PIN"
            ;;
        unsigned-bootargs)
            $META_TOOL meta create -mime "application/x-uefi-image" -url "$IMAGE_URL" \
                -hash-file "$HTTP_DIR/test-image.efi" -name "metatool-bootargs" \
                -boot-args "init=/bin/sh" -out "$HTTP_DIR/meta.cbor"
            BMO_META_ARG="-bmo-meta-url $META_URL -bmo-meta-hash $PIN"
            ;;
        signed | signed-wrongkey)
            openssl ecparam -name prime256v1 -genkey -noout -out "$WORKDIR/signer-a.pem" 2>/dev/null
            openssl ecparam -name prime256v1 -genkey -noout -out "$WORKDIR/signer-b.pem" 2>/dev/null
            $META_TOOL meta create-signed -mime "application/x-uefi-image" -url "$IMAGE_URL" \
                -hash-file "$HTTP_DIR/test-image.efi" -name "metatool-signed" \
                -key "$WORKDIR/signer-a.pem" -out "$HTTP_DIR/meta.cbor"
            NAMED=signer-a.pem
            [ "$T" = "signed-wrongkey" ] && NAMED=signer-b.pem
            $META_TOOL meta export-pubkey -key "$WORKDIR/$NAMED" -out "$WORKDIR/signer.cbor"
            echo "Meta signed with signer-a.pem; image-begin names $NAMED"
            $META_TOOL meta verify -in "$HTTP_DIR/meta.cbor" -key "$WORKDIR/signer-a.pem" \
                -hash-file "$HTTP_DIR/test-image.efi" 2>&1 | head -3 || true
            BMO_META_ARG="-bmo-meta-url $META_URL:$WORKDIR/signer.cbor"
            ;;
    esac
    $META_TOOL meta inspect -in "$HTTP_DIR/meta.cbor" 2>&1 | head -12 || true

    cd "$HTTP_DIR"
    python3 -m http.server $HTTP_PORT --bind 0.0.0.0 > "$WORKDIR/http.log" 2>&1 &
    HTTP_PID=$!
    cd - > /dev/null
    sleep 1

    timeout $TIMEOUT_SHORT $FDO_TOOL server -db "$WORKDIR/fdo.db" -http 127.0.0.1:8080 -initOnly 2>&1 || true
    $FDO_TOOL server -db "$WORKDIR/fdo.db" -print-owner-public SECP256R1 2>/dev/null | grep -A100 "BEGIN PUBLIC" > "$WORKDIR/owner.pem"

    swtpm socket --tpmstate dir="$WORKDIR" \
        --server type=unixio,path="$WORKDIR/swtpm-server" \
        --ctrl type=unixio,path="$WORKDIR/swtpm-ctrl" \
        --tpm2 --flags startup-clear &
    SWTPM_PID=$!
    fdo_record_pid "$WORKDIR" $SWTPM_PID swtpm
    sleep 2

    echo "=== quick-di over swtpm ==="
    timeout $TIMEOUT_MEDIUM env FDO_TPM_DEVICE="$WORKDIR/swtpm-server" \
        /home/bkg/quick-di-tpm -quick -protocol-version 2.0 -rv 10.0.2.2:8080:http \
        -device-info "EFI-FDO-MetaTool-Test" -output-dir "$VOUCHER_DIR" \
        -signover-key "$WORKDIR/owner.pem" 2>&1 | grep -E "GUID|completed|error" || true
    VOUCHER=$(ls -t "$VOUCHER_DIR"/*.fdoov 2>/dev/null | head -1)
    [ -n "$VOUCHER" ] || { echo "ERROR: No voucher created"; exit 1; }
    GUID=$(basename "$VOUCHER" .fdoov)
    sed -i "s/FDO OWNERSHIP VOUCHER/OWNERSHIP VOUCHER/g" "$VOUCHER"

    $FDO_TOOL server -db "$WORKDIR/fdo.db" -import-voucher "$VOUCHER" -initOnly 2>&1 || true
    timeout $TIMEOUT_SHORT $FDO_TOOL server -db "$WORKDIR/fdo.db" \
        -to0 http://127.0.0.1:8080 -to0-guid "$GUID" -initOnly 2>&1 || true

    # shellcheck disable=SC2086 # BMO_META_ARG is intentionally word-split
    $FDO_TOOL -debug server -http 0.0.0.0:8080 -db "$WORKDIR/fdo.db" -reuse-cred \
        $BMO_META_ARG -bmo-sign > "$WORKDIR/server.log" 2>&1 &
    SERVER_PID=$!
    fdo_record_pid "$WORKDIR" $SERVER_PID server
    sleep 2
    kill -0 $SERVER_PID 2>/dev/null || { echo "ERROR: server failed"; cat "$WORKDIR/server.log"; exit 1; }

    echo "=== QEMU (timeout ${TIMEOUT_QEMU}s) ==="
    sudo timeout "$TIMEOUT_QEMU" qemu-system-x86_64 \
        -machine q35 -m 2048 \
        -drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
        -drive if=pflash,format=raw,unit=1,file="$WORKDIR/OVMF_VARS.fd" \
        -drive file=/home/bkg/bkgvm/efi-disk-release.img,format=raw,index=0 \
        -chardev socket,id=chrtpm,path="$WORKDIR/swtpm-ctrl" \
        -tpmdev emulator,id=tpm0,chardev=chrtpm \
        -device tpm-tis,tpmdev=tpm0 \
        -device virtio-rng-pci \
        -nic user,model=virtio-net-pci \
        -display none -serial file:"$WORKDIR/qemu.log" || true

    local Q="$WORKDIR/qemu.log" V=FAIL
    local RAN=false SIGOK=false REFUSED=false FETCHED=false
    grep -q "HELLO-EFI" "$Q" && RAN=true
    grep -qi "meta-payload signature VERIFIED" "$Q" && SIGOK=true
    grep -qE "REFUSING|signature verification FAILED" "$Q" && REFUSED=true
    grep -q "test-image.efi" "$WORKDIR/http.log" && FETCHED=true
    case "$T" in
        unsigned) $RAN && grep -q "usable only as a pointer" "$Q" && V=PASS ;;
        signed) $RAN && $SIGOK && V=PASS ;;
        signed-wrongkey) ! $RAN && ! $SIGOK && $REFUSED && ! $FETCHED && V=PASS ;;
        unsigned-bootargs) ! $RAN && $REFUSED && grep -q "carries instruction fields" "$Q" && ! $FETCHED && V=PASS ;;
    esac
    echo ""
    echo "RESULT ($T): $V  [chainloaded=$RAN sig_verified=$SIGOK refused=$REFUSED image_fetched=$FETCHED]"
    grep -aE "(BMO meta|COSE|REFUSING|HELLO-EFI|TO2 Protocol Complete|instruction)" "$Q" | head -15
    RESULTS+=("$T: $V")

    fdo_cleanup "$WORKDIR"
    cleanup_http
}

case "$MODE" in
    unsigned | signed | signed-wrongkey | unsigned-bootargs) run_test "$MODE" ;;
    all) for t in unsigned signed signed-wrongkey unsigned-bootargs; do run_test "$t"; done ;;
    *) echo "Usage: $0 [unsigned|signed|signed-wrongkey|unsigned-bootargs|all]"; exit 1 ;;
esac

echo ""
echo "=== Summary ==="
printf '%s\n' "${RESULTS[@]}"
