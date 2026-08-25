# FDO UEFI Client (Rust)

A modular UEFI application for FIDO Device Onboard (FDO), written in Rust.
Supports the full device lifecycle — from factory provisioning (DI) through
owner onboarding (TO1/TO2) to OS/firmware delivery (BMO) — as a set of
build-time composable stages.

## Boot Chain Overview

The FDO UEFI client implements a multi-stage boot chain. Each stage is
optional and controlled by Cargo build features. The stages are:

```text
┌─────────────────────────────────────────────────────────────────────┐
│  FDO Firmware Stub  (feature: rv-firmware)                         │
│  Lives in platform firmware (SPI flash / BIOS)                     │
│                                                                     │
│  ┌─ Optional DI (feature: rv-firmware-di) ──────────────────────┐  │
│  │  If no credentials in TPM:                                    │  │
│  │    DI Protocol → manufacturing server → Write DCTPM to TPM   │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  1. Read DCTPM from TPM NV (includes RV firmware extension tags)   │
│  2. HTTP GET signed firmware image from FirmwareURL                │
│  3. Verify COSE_Sign1 signature against platform vendor key        │
│  4. Anti-rollback check (firmware revision counter in TPM NV)      │
│  5. Chainload FDO Installer Image ──┐                              │
└──────────────────────────────────────┼──────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│  FDO Installer Image  (default build, no extra features needed)    │
│  Downloaded at runtime by the FDO Firmware Stub,                   │
│  or stored in firmware alongside it, or run standalone             │
│                                                                     │
│  ┌─ DI (always compiled in) ────────────────────────────────────┐  │
│  │  If no credentials in TPM:                                    │  │
│  │    DI Protocol → manufacturing server → Write DCTPM to TPM   │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  1. TO1: Rendezvous server discovery                               │
│  2. TO2: Owner server communication (encrypted ServiceInfo)        │
│  3. BMO FSIM: Receive OS/firmware payload (inline, URL, or meta)   │
│  4. Chainload payload ──────────────┐                              │
└──────────────────────────────────────┼──────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Payload  (not part of this project)                               │
│  Delivered by the FDO Installer Image via BMO                      │
│  Examples: OS installer, UKI, firmware update, BIOS config tool    │
└─────────────────────────────────────────────────────────────────────┘
```

**Key point:** DI (Device Initialization) can run in either stage — or both.
If the FDO Firmware Stub includes DI (`rv-firmware-di`), the device can
self-provision at the factory without needing a server to serve the
FDO Installer Image just for DI. If the FDO Installer Image is run directly
(without the FDO Firmware Stub), it handles DI on its own.

## Building

All builds use Rust nightly with the UEFI target. The common build flags are:

```bash
CARGO_FLAGS="-Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem --target x86_64-unknown-uefi"
```

### Build Configurations

**FDO Installer Image** — the default build. Runs DI (if no credentials),
TO1/TO2, BMO, and chainloads the payload. This is what most people want.

```bash
cargo +nightly build --release $CARGO_FLAGS

# Output: target/x86_64-unknown-uefi/release/fdo-uefi.efi
```

**FDO Firmware Stub** — minimal firmware-resident image. Reads firmware
RV tags from TPM, downloads and verifies a signed FDO Installer Image,
and chainloads it. No DI; assumes TPM was provisioned externally
(e.g., by `quick-di`).

```bash
cargo +nightly build --release --features rv-firmware $CARGO_FLAGS
```

**FDO Firmware Stub with DI** — same as above, but if no credentials
exist in the TPM, runs DI first. This is the recommended OEM
configuration: a single firmware image that self-provisions at the
factory and then downloads + chainloads the FDO Installer Image.

```bash
cargo +nightly build --release --features rv-firmware-di $CARGO_FLAGS
```

### Build Features Reference

| Feature | Stage | Description |
|---------|-------|-------------|
| `uefi-http` | Both | HTTP via `EFI_HTTP_PROTOCOL` (default; works in OVMF/QEMU) |
| `tcp4-http` | Both | HTTP via raw TCP4 (default; works on real hardware without HttpDxe) |
| `rv-firmware` | FDO Firmware Stub | RV-based firmware delivery: download + COSE_Sign1 verify + chainload |
| `rv-firmware-di` | FDO Firmware Stub | Adds DI support inside the FDO Firmware Stub (implies `rv-firmware`) |

See [docs/modular-architecture.md](docs/modular-architecture.md) for
deployment scenarios and how the stages compose in different environments.

### Prerequisites

**Build machine:**

```bash
rustup install nightly
rustup +nightly component add rust-src
```

**Test machine (pe2):**

```bash
sudo apt-get install qemu-system-x86 ovmf mtools dosfstools swtpm
# go-fdo server: build from ../go-fdo with `make build`
```

## Command-Line Options

Both the FDO Firmware Stub and FDO Installer Image accept arguments from
the EFI shell:

```text
Usage: fdo-uefi.efi [options]
  -di <url>   DI (manufacturing) server URL
  -rv <url>   RV/Owner server URL (TO1/TO2 override)
  -h          Show usage help
```

### Examples

```text
# DI against a specific manufacturing server
Shell> fdo-uefi.efi -di http://192.168.1.100:8080

# TO1/TO2 against a specific owner server (overrides credential)
Shell> fdo-uefi.efi -rv http://fdo-server.local:8080

# Both (DI server for first boot, RV for onboarding)
Shell> fdo-uefi.efi -di http://mfg-server:8080 -rv http://owner-server:8080
```

### Server Discovery

**DI (Device Initialization):**

1. **`-di` flag** — explicit URL from the command line
2. **Well-known DNS names** — `_fdo._tcp:8080`, `fdo-mfg:8080` (per DNS-SD conventions)

> **Note:** DNS resolution is not yet implemented in the UEFI client.
> Use the `-di` flag to specify the server explicitly.

**TO1/TO2 (Onboarding):**

1. **`-rv` flag** — explicit URL from the command line
2. **TPM credential** — the RV URL stored in DCTPM NV index during DI
3. **Error** — if neither is available, logs error and exits

## Execution Flow

```text
Boot
  │
  ├─ TPM present? ──No──▶ error, exit
  │
  ├─ [FDO Firmware Stub: rv-firmware enabled?]
  │    │
  │    ├─ [rv-firmware-di enabled + no DCTPM?]
  │    │     └─▶ DI Protocol → Write DCTPM to TPM
  │    │
  │    ├─ Read DCTPM → parse RV firmware tags
  │    │    ├─ FirmwareURL found → HTTP GET → COSE verify → chainload FDO Installer Image
  │    │    └─ No firmware URL → fall through to FDO Installer Image logic
  │    │
  │    └─ (chainloaded image returns → exit)
  │
  ├─ [FDO Installer Image logic]
  │    ├─ DCTPM exists + GUID found → TO1 → TO2 → BMO → chainload payload
  │    └─ No credentials → DI Protocol → Write DCTPM → done (reboot to onboard)
  │
  └─ exit
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
├── Cargo.toml               # Package manifest (features defined here)
├── README.md                # This file
├── TODO.md                  # Development status and known issues
├── spec.md                  # Technical specification
├── docs/
│   └── modular-architecture.md  # Deployment scenarios, stage composition
├── test-di.sh               # DI protocol integration test (positive + negative)
├── test-rv-firmware.sh      # FDO Firmware Stub QEMU integration test
├── start3.sh                # Full TO2+BMO automated test script
├── boot_to_efi_shell.sh     # Reboot k800 into EFI shell for hardware tests
├── update.sh                # Deploy EFI binary to k800 hardware
├── .cargo/
│   └── config.toml          # Cargo config (UEFI target)
└── src/
    ├── main.rs              # Entry point: FDO Firmware Stub → FDO Installer Image
    ├── di/                  # DI protocol module (used by both stages)
    │   ├── mod.rs           # Module exports
    │   ├── protocol.rs      # DI message flow and TPM operations
    │   └── mfginfo.rs       # DeviceMfgInfo structure
    ├── rv_firmware/         # FDO Firmware Stub module (feature: rv-firmware)
    │   ├── mod.rs           # Entry point: check_and_deliver()
    │   ├── rv_parse.rs      # Parse RV firmware tags (16/17/18) from DCTPM
    │   ├── cose_verify.rs   # COSE_Sign1 parsing + ECDSA P-256 verification
    │   ├── platform_key.rs  # Hardcoded platform vendor public key
    │   └── anti_rollback.rs # Firmware revision counter in TPM NV
    ├── fdo.rs               # FDO TO1/TO2 protocol implementation
    ├── http_api.rs          # HTTP dispatcher (uefi-http or tcp4-http)
    ├── http.rs              # EFI_HTTP_PROTOCOL client (feature: uefi-http)
    ├── tcp4_http.rs         # Raw TCP4 HTTP client (feature: tcp4-http)
    ├── tpm.rs               # TPM 2.0 (keys, HMAC, NV, signing, DCTPM)
    ├── bmo.rs               # BMO FSIM handler
    └── chainload.rs         # EFI image chainloading (LoadImage/StartImage)
```

## Current Status

- **FDO Firmware Stub** (`rv-firmware`): ✅ Verified on k800 hardware (2026-08-25)
- **FDO Firmware Stub DI** (`rv-firmware-di`): ✅ Implemented, compiles
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
