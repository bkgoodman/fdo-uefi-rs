# FDO UEFI Client (Rust)

A UEFI application implementing FDO 2.0 TO1/TO2 protocols and BMO FSIM, written in Rust.

## Overview

This is a full FDO (FIDO Device Onboard) client running as a UEFI application for device
onboarding during firmware boot. It implements:

- **DI protocol** - Device Initialization (manufacturing/provisioning)
- **TO1 protocol** - Rendezvous server communication
- **TO2 protocol** - Owner server communication with encrypted ServiceInfo exchange
- **BMO FSIM** - Bare Metal Onboarding for EFI image transfer and chainload
- **TPM 2.0** - Key creation, credential storage, HMAC, and ECDH key exchange

## Prerequisites

### Build Machine

```bash
# Rust nightly with UEFI target
rustup install nightly
rustup +nightly component add rust-src

# Or use: make deps
```

### Test Machine (pe2)

```bash
# Ubuntu/Debian packages
sudo apt-get install qemu-system-x86 ovmf mtools dosfstools swtpm

# go-fdo server binary
# Build from ../go-fdo with: make build
```

## Building

```bash
# Release build (recommended)
cargo +nightly build --release \
    -Zbuild-std=core,alloc \
    -Zbuild-std-features=compiler-builtins-mem \
    --target x86_64-unknown-uefi

# Output: target/x86_64-unknown-uefi/release/fdo-uefi.efi
```

## Execution Flow

The UEFI client automatically detects which protocol to run based on TPM state:

1. **No credentials in TPM** → Run **DI protocol** (Device Initialization)
2. **Credentials exist** → Run **TO1/TO2 protocols** (Onboarding)

```text
Boot → Check TPM NV → No credentials? → DI Protocol → Write DCTPM → Done
                   → Has credentials? → TO1 → TO2 → BMO → Chainload
```

## Testing

### Test Architecture

Tests are **evidence-based**: each test checks for specific observable artifacts
(log messages, server responses, TPM NV writes) rather than just exit codes.
Both positive and negative tests are provided.

| Test | Script | What it verifies |
|------|--------|-----------------|
| DI positive | `./test-di.sh positive` | Full DI protocol completes, voucher created |
| DI negative | `./test-di.sh negative` | Server errors are detected and reported cleanly |
| DI all | `./test-di.sh all` | Both positive and negative |
| TO2 + BMO | `start3.sh` | Full onboarding with image transfer |

### Prerequisites (Test Machine)

```bash
# Required packages (Debian/Ubuntu)
sudo apt-get install qemu-system-x86 ovmf mtools dosfstools swtpm

# go-fdo server binary (one of):
#   - Set FDO_SERVER=/path/to/binary
#   - Build: cd ../go-fdo && make build
#   - Pre-built on pe2: /home/bkg/fdo-server-new
```

### DI Protocol Test (Automated)

The `test-di.sh` script runs the complete Device Initialization flow
in a QEMU VM against a go-fdo server with swtpm TPM emulation.

```bash
# Positive test: DI should complete successfully
./test-di.sh positive

# Negative test: DI should fail with clear error reporting
./test-di.sh negative

# Both tests
./test-di.sh all
```

**Environment variables** for customization:

```bash
FDO_SERVER=/path/to/server  # go-fdo server binary
RUST_EFI=/path/to/fdo.efi   # UEFI client binary
WORKDIR=/tmp/fdo-di-test     # Test artifact directory
TIMEOUT=90                   # QEMU timeout (seconds)
KEEP_LOGS=1                  # Preserve logs after test
```

**Remote execution** (e.g., on pe2):

```bash
# Copy binary and run
scp target/x86_64-unknown-uefi/release/fdo-uefi.efi pe2:/home/bkg/fdo-uefi-rs/target/x86_64-unknown-uefi/release/
ssh pe2 'cd /home/bkg/fdo-uefi-rs && bash test-di.sh all'
```

### What the DI Positive Test Checks

The positive test verifies 8 pieces of evidence:

| # | Evidence | Where to look | What it means |
|---|----------|---------------|---------------|
| 1 | `Message-Type: 11` in server log | Server HTTP response header | Server accepted DIAppStart, returned DISetCredentials |
| 2 | `Message-Type: 13` in server log | Server HTTP response header | Server accepted DISetHMAC, returned DIDone |
| 3 | No `Message-Type: 255` in server log | Server HTTP response header | No errors from server |
| 4 | `Device Initialization COMPLETE` in QEMU output | UEFI client log | Client completed all DI steps |
| 5 | `GUID:` in QEMU output | UEFI client log | Client received and parsed OVHeader with device GUID |
| 6 | `NV DefineSpace` in QEMU output | UEFI client log | Client wrote DCTPM credentials to TPM NV index |
| 7 | 2+ `request` entries in server log | Server debug log | Both DI messages (10, 12) were received |
| 8 | `Authorization: Bearer` in server log | Server HTTP request header | Session token was threaded from msg 11 to msg 12 |

Example positive test output:

```text
============================================
  FDO DI Protocol Test: POSITIVE (DI should succeed)
============================================

--- Checking evidence ---

  ✓ PASS: Server returned DISetCredentials (Message-Type: 11)
  ✓ PASS: Server returned DIDone (Message-Type: 13)
  ✓ PASS: No server errors (no Message-Type: 255)
  ✓ PASS: Client logged 'Device Initialization COMPLETE'
  ✓ PASS: Client received GUID: [4a, 89, a5, 84, ...]
  ✓ PASS: Client wrote DCTPM to TPM NV index
  ✓ PASS: Server processed 2 requests (expected 2: msg 10, msg 12)
  ✓ PASS: Session token (Authorization: Bearer) present in requests

============================================
  Results: 8 passed, 0 failed
============================================
  VERDICT: PASS
```

### What the DI Negative Test Checks

The negative test sabotages the server (removes manufacturer keys from DB)
and verifies the client handles the error gracefully:

| # | Evidence | What it means |
|---|----------|---------------|
| 1 | `Message-Type: 255` in server log | Server correctly rejected the request |
| 2 | `FDO Error` or `Server returned error` in QEMU output | Client decoded the error response |
| 3 | No `Device Initialization COMPLETE` in QEMU output | Client did NOT falsely report success |
| 4 | `Device Initialization failed` in QEMU output | Client reported clean failure |

Example negative test output:

```text
--- Sabotage: removing database to trigger server error ---

--- Checking evidence ---

  ✓ PASS: Server returned error (Message-Type: 255) as expected
  ✓ PASS: Client decoded server error: FDO Error 500: msg_type=10, "error getting device info: not found"
  ✓ PASS: Client correctly did NOT report DI completion
  ✓ PASS: Client logged 'Device Initialization failed' (clean failure)

============================================
  Results: 4 passed, 0 failed
============================================
  VERDICT: PASS
```

### DI Protocol Manual Test (Step-by-Step)

For debugging or understanding the protocol flow, here are the manual steps:

**1. Initialize the go-fdo database** (creates manufacturer keys for EC256, EC384, RSA):

```bash
WORKDIR=/tmp/fdo-di-test
mkdir -p "$WORKDIR"
fdo-server server -db "$WORKDIR/fdo.db" -http 127.0.0.1:19999 -initOnly
```

**2. Start swtpm** in daemon mode with clean TPM state (no existing FDO credentials):

```bash
swtpm socket --tpmstate dir="$WORKDIR" \
    --ctrl type=unixio,path="$WORKDIR/swtpm-ctrl" \
    --tpm2 --flags startup-clear --daemon
```

> **Note:** Use `--daemon` mode with only `--ctrl` socket for QEMU.
> Do NOT add `--server` socket unless you also need go-tpm/quick-di access.
> QEMU connects to the `--ctrl` socket, not the `--server` socket.

**3. Start the go-fdo server** with debug logging:

```bash
fdo-server -debug server -http 0.0.0.0:8080 -db "$WORKDIR/fdo.db" \
    -rv-bypass > "$WORKDIR/server.log" 2>&1 &
```

**4. Create a FAT32 boot disk** with the UEFI client:

```bash
dd if=/dev/zero of="$WORKDIR/disk.img" bs=1M count=64
mkfs.vfat -F 32 "$WORKDIR/disk.img"
mmd -i "$WORKDIR/disk.img" ::/EFI ::/EFI/BOOT
mcopy -i "$WORKDIR/disk.img" fdo-uefi.efi ::/EFI/BOOT/BOOTX64.EFI
cp /usr/share/OVMF/OVMF_VARS_4M.fd "$WORKDIR/OVMF_VARS.fd"
```

**5. Run QEMU** with TPM, network, and RNG:

```bash
sudo qemu-system-x86_64 -machine q35 -m 2048 \
    -drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,unit=1,file="$WORKDIR/OVMF_VARS.fd" \
    -drive file="$WORKDIR/disk.img",format=raw,index=0 \
    -chardev socket,id=chrtpm,path="$WORKDIR/swtpm-ctrl" \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 \
    -device virtio-rng-pci \
    -nic user,model=virtio-net-pci \
    -nographic -no-reboot
```

> **Critical QEMU flags:**
>
> - `-device virtio-rng-pci` — Required for OVMF network stack (EFI_RNG_PROTOCOL dependency)
> - `-nic user,model=virtio-net-pci` — User-mode networking; server at `10.0.2.2` from guest
> - `-no-reboot` — Exit QEMU when UEFI app finishes (instead of rebooting)

**6. Verify success** by checking both the QEMU output and server log:

```bash
# Client-side evidence (in QEMU console output):
#   "Device Initialization COMPLETE"
#   "GUID: [xx, xx, xx, ...]"
#   "NV DefineSpace"

# Server-side evidence:
grep "Message-Type:" "$WORKDIR/server.log"
# Expected:
#   Message-Type: 11   (DISetCredentials - success)
#   Message-Type: 13   (DIDone - success)
# Bad:
#   Message-Type: 255  (Error - check body for details)
```

### DI Protocol Message Flow

```text
UEFI Client                              go-fdo Server
    |                                         |
    |  POST /fdo/200/msg/10 (DIAppStart)      |
    |  Body: [DeviceMfgInfo_bstr, CapFlags]   |
    |  DeviceMfgInfo = [KeyType=10,           |
    |    KeyEnc=2, Serial, DevInfo, CSR_DER]  |
    |---------------------------------------->|
    |                                         |  - Parse DeviceMfgInfo
    |                                         |  - Sign CSR -> device cert
    |                                         |  - Generate GUID
    |                                         |  - Build OVHeader
    |  HTTP 200, Message-Type: 11             |
    |  Authorization: Bearer <token>          |
    |  Body: OVHeader_bstr                    |
    |<----------------------------------------|
    |                                         |
    |  - Parse OVHeader (preserve raw CBOR)   |
    |  - Compute HMAC over raw OVHeader bytes |
    |  - TPM HMAC key used                    |
    |                                         |
    |  POST /fdo/200/msg/12 (DISetHMAC)       |
    |  Authorization: Bearer <token>          |
    |  Body: [hash_type, hmac_bytes]          |
    |---------------------------------------->|
    |                                         |  - Verify HMAC
    |                                         |  - Persist voucher
    |  HTTP 200, Message-Type: 13             |
    |  Body: [] (empty = DIDone)              |
    |<----------------------------------------|
    |                                         |
    |  - Persist DAK to TPM (0x81020002)      |
    |  - Persist HMAC key (0x81020003)        |
    |  - Write DCTPM to NV (0x01D10001)       |
    |  - Log "Device Initialization COMPLETE" |
```

### Interpreting Errors

When DI fails, the server returns `Message-Type: 255` with a CBOR error body:

```text
[error_code, prev_msg_type, error_string, timestamp, correlation_id]
```

The client decodes this and logs:

```text
[ERROR] Server returned error (Message-Type 255)
[ERROR] FDO Error 500: msg_type=10, "error getting device info: not found"
```

Common errors and fixes:

| Error message | Cause | Fix |
|--------------|-------|-----|
| `error getting device info: not found` | No manufacturer key for KeyType | Run server with `-initOnly` first |
| `error decoding device manufacturing info` | DeviceMfgInfo CBOR format wrong | Check CBOR array field order matches go-fdo |
| `error parsing x509 certificate request` | CSR DER encoding bug | Check ASN.1 structure, length encoding |
| `unsupported type: protocol.KeyType` | KeyType value unknown to server | Use go-fdo constants (P-256=10, P-384=11) |
| `voucher header not found for session` | Session token missing from msg 12 | Ensure Authorization header is sent |

### TO1/TO2 Manual Test (with external DI)

For testing TO1/TO2 with an externally-created voucher (via quick-di-tpm):

```bash
# 1. Init DB and export owner key
fdo-server server -db /tmp/fdo.db -initOnly
fdo-server server -db /tmp/fdo.db -print-owner-public SECP256R1 > owner.pem

# 2. Start swtpm with BOTH server and ctrl sockets
swtpm socket --tpmstate dir=/tmp/tpm \
    --server type=unixio,path=/tmp/tpm/swtpm-server \
    --ctrl type=unixio,path=/tmp/tpm/swtpm-ctrl \
    --tpm2 --flags startup-clear &

# 3. Create voucher via quick-di-tpm (connects to swtpm-server socket)
FDO_TPM_DEVICE=/tmp/tpm/swtpm-server \
    quick-di-tpm -quick -rv 10.0.2.2:8080:http \
    -device-info "Test" -output-dir /tmp/vouchers \
    -signover-key owner.pem

# 4. Import voucher and start server with BMO payload
fdo-server server -db /tmp/fdo.db \
    -import-voucher /tmp/vouchers/*.fdoov -initOnly
fdo-server -debug server -http 0.0.0.0:8080 -db /tmp/fdo.db -rv-bypass \
    -reuse-cred -bmo-file payload.efi -bmo-type "application/x-uefi-image"

# 5. Run QEMU (UEFI client will find credentials in TPM -> TO1/TO2)
#    (same QEMU command as DI test, using swtpm-ctrl socket)
```

## Project Structure

```text
fdo-uefi-rs/
├── Cargo.toml          # Package manifest
├── README.md           # This file
├── TODO.md             # Development status and known issues
├── spec.md             # Technical specification
├── test-di.sh          # DI protocol integration test (positive + negative)
├── start3.sh           # Full TO2+BMO automated test script
├── .cargo/
│   └── config.toml     # Cargo config (UEFI target)
└── src/
    ├── main.rs         # Entry point, auto-detects DI vs TO1/TO2
    ├── di/             # DI protocol module
    │   ├── mod.rs      # Module exports
    │   ├── protocol.rs # DI message flow and TPM operations
    │   └── mfginfo.rs  # DeviceMfgInfo structure
    ├── fdo.rs          # FDO TO1/TO2 protocol implementation
    ├── http.rs         # UEFI HTTP client
    ├── tpm.rs          # TPM 2.0 operations (keys, HMAC, NV, signing)
    ├── cbor.rs         # CBOR encoder/decoder
    ├── bmo.rs          # BMO FSIM handler
    └── chainload.rs    # EFI image chainloading
```

## Current Status

- **DI**: ✅ Complete (DIAppStart, DISetCredentials, DISetHMAC, DIDone)
- **TO1**: ✅ Complete (HelloRV, ProveToRV, RVRedirect)
- **TO2**: ✅ Complete (all 12 message types, encrypted ServiceInfo)
- **BMO**: ✅ Working (image transfer, chainload)
- **TPM**: ✅ Working (key creation, HMAC, NV storage, ECDH, signing)

See [TODO.md](TODO.md) for detailed status and known issues.

## References

- [uefi-rs](https://github.com/rust-osdev/uefi-rs) - Rust UEFI library
- [go-fdo](../go-fdo) - Go FDO server implementation
- [FDO Specification](https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-RD-v1.1-20211214.html)

## License

Copyright 2026 Dell Technologies, All Rights Reserved

Author: Brad Goodman <bradley.goodman@dell.com>

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
