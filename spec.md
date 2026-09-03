<!-- Copyright 2026 Dell Technologies, All Rights Reserved -->
<!-- Author: Brad Goodman <bradley.goodman@dell.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# FDO UEFI Client - Technical Specification

## Scope

This document describes the UEFI FDO client implementation for bare metal device onboarding.

## Execution Flow

The client automatically detects which protocol to run:

1. **Check TPM NV** for existing credentials (DCTPM at index 0x01500001)
2. **No credentials** → Run DI protocol against manufacturing server
3. **Has credentials** → Run TO1/TO2 protocols for onboarding

## Protocol Support

### FDO Version

- **FDO 2.0** - Device-proves-first flow
- CapabilityFlags negotiation in DI/TO1/TO2

### DI Messages (Device Initialization)

| Message | Type | Direction | Status |
|---------|------|-----------|--------|
| DIAppStart | 10 | Device→Mfg | ✅ |
| DISetCredentials | 11 | Mfg→Device | ✅ |
| DISetHMAC | 12 | Device→Mfg | ✅ |
| DIDone | 13 | Mfg→Device | ✅ |

### TO1 Messages

| Message | Type | Direction | Status |
|---------|------|-----------|--------|
| HelloRV | 30 | Device→RV | ✅ |
| HelloRVAck | 31 | RV→Device | ✅ |
| ProveToRV | 32 | Device→RV | ✅ |
| RVRedirect | 33 | RV→Device | ✅ |

### TO2 Messages

| Message | Type | Direction | Status |
|---------|------|-----------|--------|
| HelloDeviceProbe | 80 | Device→Owner | ✅ |
| HelloDeviceAck20 | 81 | Owner→Device | ✅ |
| ProveDevice20 | 82 | Device→Owner | ✅ |
| ProveOVHdr20 | 83 | Owner→Device | ✅ |
| GetOVNextEntry20 | 84 | Device→Owner | ✅ |
| OVNextEntry20 | 85 | Owner→Device | ✅ |
| DeviceSvcInfoRdy20 | 86 | Device→Owner | ✅ |
| SetupDevice20 | 87 | Owner→Device | ✅ |
| DeviceSvcInfo20 | 88 | Device→Owner | ✅ |
| OwnerSvcInfo20 | 89 | Owner→Device | ✅ |
| Done20 | 90 | Device→Owner | ✅ |
| DoneAck20 | 91 | Owner→Device | ✅ |

## Cryptographic Support

### Key Exchange

- **ECDH256** (P-256) - Default, TPM-accelerated

### Cipher Suites

- **A256GCM** (Suite 3) - AES-256-GCM encryption

### Signing

- **ES256** - ECDSA with P-256, TPM-backed

## Service Info Modules (FSIMs)

### devmod (Required)

Device module advertisement:

- `devmod:nummodules` - Count of supported modules
- `devmod:modules` - List of module names
- `devmod:os`, `devmod:arch`, `devmod:version` - Device info
- `devmod:device`, `devmod:sep`, `devmod:bin` - Serial, separator, binary format

### fdo.bmo (Bare Metal Onboarding)

BMO FSIM for EFI image transfer:

**Device→Owner:**

- `fdo.bmo:active` = true
- `fdo.bmo:supported-types` = ["application/x-uefi-image"]

**Owner→Device:**

- `fdo.bmo:image-begin` - Start transfer (includes metadata)
- `fdo.bmo:image-data-N` - Binary chunks (1014 bytes each)
- `fdo.bmo:image-end` - Transfer complete

**Device Response:**

- `fdo.bmo:image-result` - Transfer status (0 = success)

### Chunk Size Constraint

UEFI HTTP client has ~1KB response size limit. BMO chunks are fixed at **1014 bytes** to fit within UEFI HTTP response buffers after CBOR/encryption overhead.

## TPM Integration

### DI Key Creation

During Device Initialization, the client creates:

- **DAK (Device Attestation Key)** - ECC P-256 signing key, persisted at handle `0x81020002`
- **HMAC Key** - SHA-256 HMAC key, persisted at handle `0x81020003`

### NV Storage

Credential (DCTPM) stored in TPM NV index `0x01500001` (Owner range).

Attributes: `OWNERWRITE | OWNERREAD` (0x00020002)

### Key Operations

- **CreatePrimary** - Create DAK and HMAC keys under Endorsement hierarchy
- **EvictControl** - Persist keys to permanent handles
- **HMAC** - Compute HMAC over OVHeader during DI
- **Sign** - CSR signing during DI, COSE_Sign1 during TO1/TO2
- **ECDH** - Shared secret computation via TPM
- **NV DefineSpace/Write** - Store DCTPM after DI

## HTTP Client

### Constraints

- Single HTTP request/response per protocol message
- ~32KB receive buffer
- HTTP child handles must be destroyed after each request (resource limit ~80 handles)
- Network stack (DHCP/SNP) initialized once and cached

### QEMU Networking

Requires:

- `-device virtio-rng-pci` - For UEFI network driver binding
- `-nic user,model=virtio-net-pci` - User-mode networking
- Host server accessible at `10.0.2.2` from QEMU guest

## Chainloading

After BMO image transfer, the received EFI image is chainloaded via:

1. `LoadImage()` - Load EFI binary
2. `StartImage()` - Execute loaded image

Fallback: Write to temp file and load from filesystem if direct memory load fails.

## Test Environment

### Components

- **pe2** - Test VM with QEMU, OVMF, swtpm
- **go-fdo server** - Owner/RV server
- **swtpm** - TPM 2.0 simulator
- **quick-di-tpm** - Device initialization tool

### Test Script

`start3.sh` automates full test flow:

1. Initialize database
2. Export owner key
3. Start swtpm
4. Create voucher (DI)
5. Import voucher
6. Start server with BMO payload
7. Build and run UEFI client in QEMU

### Verification

```bash
# Check BMO transfer completion
grep -E "Sending chunk|image-end|Done" /tmp/fdo-test3/server.log

# Check for errors
grep -i error /tmp/fdo-test3/server.log
```

## Known Limitations

1. **HTTP only** - No TLS support yet
2. **ECDH256 only** - P-384 not implemented
3. **No credential replacement** - Reuse mode only
4. **Single image** - One BMO payload per onboard

## Performance

- **BMO inline transfer**: ~65KB per round via TCP4, ~170 rounds/minute
- **51KB payload.efi**: ~51 rounds, under 1 minute (OnLogic k800)
- **27MB UKI (stripped initrd)**: ~425 rounds, ~3 minutes (QEMU)
- **120MB UKI (full initrd+fdo)**: ~1,830 rounds, ~10-12 minutes (QEMU)
- **Bottleneck**: Round-trip latency per ServiceInfo exchange, not bandwidth

## Ubuntu UKI Boot Chain (Stage 1 Complete)

End-to-end verified flow (2026-09-03):

1. UEFI FDO client boots from flash, reads TPM credentials
2. TO2 protocol completes (HelloDeviceProbe → DoneAck)
3. 120MB UKI transferred via BMO inline delivery (~1,830 rounds, SHA256 verified)
4. Chainloaded into Linux 7.0.0-14-generic via EFI LoadImage/StartImage
5. Custom init: mounts proc/sys/dev, starts udevd, runs DHCP (10.0.2.15)
6. go-fdo client available at /usr/local/bin/fdo
7. BusyBox shell ready for Stage 2

UKI built with `ukify` from Ubuntu mini-ISO kernel + full initrd + custom init
(replaces casper scripts that expected squashfs on CD-ROM).

Stage 2 (not yet implemented): go-fdo-endpoint client runs inside Linux to
receive configuration (autoinstall.yaml, ISO payload) from orchestrator via FSIMs.
