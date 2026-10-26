#!/bin/bash
# test-uefi-tpm.sh - fdo-uefi DI + TO2 on QEMU/OVMF with swtpm, and a check of
# the TPM state fdo-uefi leaves against "Securing FDO Credentials in the TPM".
#
# Phases, all on one swtpm state directory:
#   A  DI:       fdo-uefi -di http://10.0.2.2:$PORT  (go-fdo server, fresh TPM)
#   B  check:    swtpm restarted on the same state with a Unix socket;
#                go-fdo `fdo-client-tpm client -tpm-check` (+ -tpm-show)
#   C  TO2:      fdo-uefi (stored credentials) -> TO1/TO2 + BMO of a small EFI app
#
# fdo-uefi gets its arguments from startup.nsh, run by the UEFI shell
# (Shell.efi as \EFI\BOOT\BOOTX64.EFI); each script ends with `reset -s`.
#
# Usage (on the QEMU host):
#   FDO_SERVER=... FDO_CLIENT_TPM=... FDO_UEFI=... SHELL_EFI=... BMO_EFI=... \
#     ./test-uefi-tpm.sh
#
#   FDO_SERVER      go-fdo examples server            (CGO_ENABLED=0 go build ./cmd)
#   FDO_CLIENT_TPM  go-fdo examples client, -tags tpm (provides -tpm-check)
#   FDO_UEFI        fdo-uefi.efi (release build)
#   SHELL_EFI       UEFI shell (this repo's Shell.efi)
#   BMO_EFI         small EFI application delivered by BMO (e.g. hello-efi.efi)
#   WORK            work directory (default /tmp/fdo-uefi-tpm)
#   PORT            server port (default 19999)
#   PHASES          subset, e.g. "A B" (default "A B C")
#
# Exit status: non-zero if DI or TO2 fails. Phase B only records -tpm-check
# results (its exit status is reported, not fatal).

set -u

WORK=${WORK:-/tmp/fdo-uefi-tpm}
PORT=${PORT:-19999}
PHASES=${PHASES:-"A B C"}
TIMEOUT_QEMU=${TIMEOUT_QEMU:-240}

for v in FDO_SERVER FDO_CLIENT_TPM FDO_UEFI SHELL_EFI BMO_EFI; do
	[ -f "${!v:-}" ] || {
		echo "set $v (missing: ${!v:-unset})"
		exit 2
	}
done

FDO_SERVER=$(realpath "$FDO_SERVER")
FDO_CLIENT_TPM=$(realpath "$FDO_CLIENT_TPM")
FDO_UEFI=$(realpath "$FDO_UEFI")
SHELL_EFI=$(realpath "$SHELL_EFI")
BMO_EFI=$(realpath "$BMO_EFI")

OVMF_CODE=/usr/share/OVMF/OVMF_CODE_4M.fd
OVMF_VARS=/usr/share/OVMF/OVMF_VARS_4M.fd
SERVER_PID=""
SWTPM_PID=""
FAILED=0

cleanup() {
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null
	[ -n "$SWTPM_PID" ] && kill "$SWTPM_PID" 2>/dev/null && wait "$SWTPM_PID" 2>/dev/null
	SERVER_PID=""
	SWTPM_PID=""
}
trap cleanup EXIT INT TERM

say() { printf '\n=== %s ===\n' "$*"; }
ok() { echo "PASS $*"; }
bad() {
	echo "FAIL $*"
	FAILED=1
}

# start_swtpm ctrl|socket  - same state dir; "ctrl" for QEMU, "socket" for Go tools
start_swtpm() {
	[ -n "$SWTPM_PID" ] && kill "$SWTPM_PID" 2>/dev/null && wait "$SWTPM_PID" 2>/dev/null
	rm -f "$WORK/tpm/ctrl" "$WORK/tpm/sock"
	if [ "$1" = ctrl ]; then
		swtpm socket --tpm2 --tpmstate "dir=$WORK/tpm" \
			--ctrl "type=unixio,path=$WORK/tpm/ctrl" --flags startup-clear --log level=0 &
		SWTPM_PID=$!
		local want="$WORK/tpm/ctrl"
	else
		swtpm socket --tpm2 --tpmstate "dir=$WORK/tpm" \
			--server "type=unixio,path=$WORK/tpm/sock" \
			--ctrl "type=unixio,path=$WORK/tpm/ctrl" --flags startup-clear --log level=0 &
		SWTPM_PID=$!
		local want="$WORK/tpm/sock"
	fi
	for _ in $(seq 20); do
		[ -S "$want" ] && return 0
		sleep 0.25
	done
	bad "swtpm did not start"
	return 1
}

start_server() {
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null
	echo "\$ $FDO_SERVER -debug server -http 0.0.0.0:$PORT -ext-http 10.0.2.2:$PORT -db $WORK/fdo.db $*"
	"$FDO_SERVER" -debug server -http "0.0.0.0:$PORT" -ext-http "10.0.2.2:$PORT" \
		-db "$WORK/fdo.db" "$@" >"$WORK/server-$PHASE.log" 2>&1 &
	SERVER_PID=$!
	for _ in $(seq 40); do
		kill -0 "$SERVER_PID" 2>/dev/null || {
			bad "server exited (see $WORK/server-$PHASE.log)"
			return 1
		}
		(echo >"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && return 0
		sleep 0.25
	done
	bad "server not listening"
	return 1
}

# boot <startup.nsh command line>
boot() {
	local disk="$WORK/disk-$PHASE.img"
	dd if=/dev/zero of="$disk" bs=1M count=64 status=none
	mkfs.vfat -F 32 "$disk" >/dev/null
	mmd -i "$disk" ::/EFI ::/EFI/BOOT
	mcopy -i "$disk" "$SHELL_EFI" ::/EFI/BOOT/BOOTX64.EFI
	mcopy -i "$disk" "$FDO_UEFI" ::/fdo-uefi.efi
	printf 'fs0:\r\n%s\r\nreset -s\r\n' "$1" >"$WORK/startup.nsh"
	mcopy -i "$disk" "$WORK/startup.nsh" ::/startup.nsh
	cp "$OVMF_VARS" "$WORK/OVMF_VARS-$PHASE.fd"
	start_swtpm ctrl || return 1
	echo "\$ qemu (startup.nsh: $1)"
	sudo timeout "$TIMEOUT_QEMU" qemu-system-x86_64 -machine q35 -m 2048 \
		-drive "if=pflash,format=raw,unit=0,readonly=on,file=$OVMF_CODE" \
		-drive "if=pflash,format=raw,unit=1,file=$WORK/OVMF_VARS-$PHASE.fd" \
		-drive "file=$disk,format=raw,index=0" \
		-chardev "socket,id=chrtpm,path=$WORK/tpm/ctrl" \
		-tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 \
		-device virtio-rng-pci -nic user,model=virtio-net-pci \
		-display none -serial "file:$WORK/qemu-$PHASE.log" -no-reboot
	echo "qemu exit $? (124 = timeout)"
	[ -n "$SWTPM_PID" ] && wait "$SWTPM_PID" 2>/dev/null
	SWTPM_PID=""
}

for p in $PHASES; do
	PHASE=$p
	case $p in
	A)
		say "A: fdo-uefi DI into a fresh swtpm"
		cleanup
		rm -rf "$WORK" && mkdir -p "$WORK/tpm"
		echo "binaries:" && md5sum "$FDO_SERVER" "$FDO_CLIENT_TPM" "$FDO_UEFI"
		"$FDO_SERVER" server -db "$WORK/fdo.db" -initOnly >/dev/null 2>&1
		start_server || exit 1
		boot "\\fdo-uefi.efi -di http://10.0.2.2:$PORT" || exit 1
		grep -E "GUID|NV |DCTPM|Device Initialization" "$WORK/qemu-A.log" | head -20
		if grep -q "Device Initialization COMPLETE" "$WORK/qemu-A.log" &&
			! grep -q "Message-Type: 255" "$WORK/server-A.log"; then
			ok "fdo-uefi DI (server msgs: $(grep -oE 'Message-Type: 1[13]' "$WORK/server-A.log" | sort -u | tr '\n' ' '))"
		else
			bad "fdo-uefi DI (see $WORK/qemu-A.log, $WORK/server-A.log)"
			exit 1
		fi
		cleanup
		;;
	B)
		say "B: TPM state left by fdo-uefi, checked with go-fdo -tpm-check (record)"
		start_swtpm socket || exit 1
		export FDO_TPM_DEVICE="$WORK/tpm/sock"
		(cd "$WORK" && "$FDO_CLIENT_TPM" client -tpm-show) 2>&1 | tee "$WORK/tpm-show.txt"
		(cd "$WORK" && "$FDO_CLIENT_TPM" client -tpm-check) 2>&1 | tee "$WORK/tpm-check.txt"
		echo "tpm-check exit ${PIPESTATUS[0]} (recorded, not fatal): $(grep -c '^PASS' "$WORK/tpm-check.txt") PASS, $(grep -c '^FAIL' "$WORK/tpm-check.txt") FAIL"
		unset FDO_TPM_DEVICE
		cleanup
		;;
	C)
		say "C: fdo-uefi TO1/TO2 + BMO (stored credentials)"
		start_server -reuse-cred -bmo "application/efi:$BMO_EFI" || exit 1
		boot "\\fdo-uefi.efi" || exit 1
		grep -E "TO1 complete|TO2 Step [0-9]+ complete|VERIFIED|BMO|chainload|Hello|ERROR|FAILED" "$WORK/qemu-C.log" | head -30
		if grep -q "TO2 Step 6 complete: DoneAck received" "$WORK/qemu-C.log"; then
			ok "fdo-uefi TO2 against the fixed server (msgs: $(grep -oE 'POST /fdo/[0-9]+/msg/[0-9]+' "$WORK/server-C.log" | awk -F/ '{print $NF}' | sort -n | uniq | tr '\n' ' '))"
		else
			bad "fdo-uefi TO2 (see $WORK/qemu-C.log, $WORK/server-C.log)"
		fi
		cleanup
		;;
	esac
done

say "Result"
[ $FAILED -eq 0 ] && echo "PASS (logs in $WORK)" || echo "FAIL (logs in $WORK)"
exit $FAILED
