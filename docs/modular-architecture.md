# FDO UEFI Client — Modular Architecture

**Date**: 2026-08-25
**Author**: Brad Goodman
**Status**: DRAFT

---

## 1. Overview

The FDO UEFI client is built as a set of modular components that can be
composed into different build configurations depending on the deployment
scenario. Each component is a Cargo feature that can be included or excluded
at build time.

The boot flow has up to three stages:

```text
┌──────────────────────────────────────────────────────────────────────┐
│  Stage 1: FDO Firmware Stub (rv-firmware)                           │
│  Lives in platform firmware (SPI flash / BIOS)                      │
│  - Reads DCTPM from TPM NV                                         │
│  - Optionally performs DI if no credentials exist                   │
│  - Downloads signed FDO Installer Image via HTTP                    │
│  - Verifies COSE_Sign1 signature against platform vendor key        │
│  - Anti-rollback check (firmware revision counter in TPM NV)        │
│  - Chainloads Stage 2                                               │
└──────────────┬───────────────────────────────────────────────────────┘
               │ chainload
               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Stage 2: FDO Installer Image (TO1/TO2 + BMO)                      │
│  Downloaded at runtime OR stored in firmware alongside Stage 1      │
│  - Optionally performs DI if no credentials exist                   │
│  - TO1: Rendezvous server discovery                                 │
│  - TO2: Owner server communication, encrypted ServiceInfo           │
│  - BMO FSIM: Receives OS/firmware payload (inline or URL)           │
│  - Chainloads Stage 3                                               │
└──────────────┬───────────────────────────────────────────────────────┘
               │ chainload
               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Stage 3: OS / UKI / Firmware Payload                               │
│  Delivered via BMO or other FSIM                                    │
│  - Operating system installer                                       │
│  - Unified Kernel Image (UKI)                                       │
│  - Firmware update binary                                           │
│  - Any EFI application the owner wants to deploy                    │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 2. Build Features (Cargo Features)

| Feature | Description | Includes |
|---------|-------------|----------|
| `uefi-http` | EFI_HTTP_PROTOCOL transport (OVMF, some server firmware) | HTTP via UEFI stack |
| `tcp4-http` | TCP4-based HTTP (most real hardware) | HTTP via raw TCP4 |
| `rv-firmware` | RV-based firmware delivery (FDO Firmware Stub) | COSE_Sign1, p256, ecdsa |
| `rv-firmware-di` | DI support inside FDO Firmware Stub | DI protocol + rv-firmware |

### Build Configurations

**FDO Installer Image only** (TO1/TO2 + BMO, with DI auto-detect):

```bash
cargo +nightly build --release   # default features: uefi-http, tcp4-http
```

**FDO Firmware Stub only** (rv-firmware, no DI — smallest image):

```bash
cargo +nightly build --release --features rv-firmware
```

**FDO Firmware Stub with DI** (rv-firmware + DI — OEM-friendly, no factory server needed):

```bash
cargo +nightly build --release --features rv-firmware-di
```

**Combined FDO Firmware Stub + FDO Installer Image** (rv-firmware with full fallback to TO1/TO2):

```bash
cargo +nightly build --release --features rv-firmware   # single binary, both stages
```

---

## 3. Deployment Scenarios

### Scenario A: OEM with RV-Firmware in BIOS (Recommended)

The OEM ships a BIOS with the FDO Firmware Stub (Stage 1) built in,
including DI support. This is the lowest-friction path for adoption.

```text
Factory floor:
  BIOS contains: Stage 1 (rv-firmware + DI)
  1. Device boots → Stage 1 runs
  2. No credentials in TPM → DI runs against manufacturing server
  3. TPM provisioned with DCTPM (includes firmware RV tags)
  4. Device ships to customer

Customer site:
  1. Device boots → Stage 1 runs
  2. Reads DCTPM → firmware URL found
  3. Downloads signed Stage 2 image
  4. Verifies COSE_Sign1 → chainloads Stage 2
  5. Stage 2 runs TO1/TO2 → receives Stage 3 payload
  6. Stage 3 runs (OS install, UKI boot, etc.)
```

**Pros**: No factory server needed to serve Stage 2 during manufacturing.
Stage 1 handles DI directly. Single firmware image for OEM.

**Cons**: Slightly larger firmware footprint (DI code included).

### Scenario B: Minimal RV-Firmware in BIOS (Space-Sensitive)

The OEM ships a BIOS with only the FDO Firmware Stub (Stage 1), without DI.
DI is handled by a separate Stage 2 component served during manufacturing.

```text
Factory floor:
  BIOS contains: Stage 1 (rv-firmware only, no DI)
  Manufacturing server serves: Stage 2 (with DI)
  1. Device boots → Stage 1 runs
  2. Stage 1 downloads Stage 2 from manufacturing server
  3. Stage 2 performs DI → TPM provisioned
  4. Device ships to customer

Customer site:
  (same as Scenario A steps 1-6)
```

**Pros**: Smallest possible firmware footprint for Stage 1.

**Cons**: Requires a manufacturing server that can serve a vendor-signed
Stage 2 component during factory provisioning.

### Scenario C: No RV-Firmware (Stage 2 in Firmware)

The OEM bakes Stage 2 directly into firmware. No RV-based firmware delivery.
This is the simplest approach but loses the ability to update Stage 2
independently of the BIOS.

```text
BIOS contains: Stage 2 (TO1/TO2 + BMO + DI)
  1. Device boots → Stage 2 runs
  2. No credentials? → DI
  3. Has credentials? → TO1/TO2 → BMO → Stage 3
```

**Pros**: Simplest deployment. No HTTP download needed for Stage 2.

**Cons**: Stage 2 updates require a full BIOS update. No independent
firmware update path for the FDO client.

### Scenario D: RV-Firmware for Flash Updates (Self-Updating)

Stage 1 checks for a newer version of itself or Stage 2. If a newer
version is available, it writes to SPI flash and reboots. The updated
component runs on next boot.

```text
BIOS contains: Stage 1 (rv-firmware) + Stage 2 (in flash)
  1. Device boots → Stage 1 runs
  2. Checks firmware revision vs. server
  3. If newer version: download → verify → flash-write → reboot
  4. If same version: fall through to Stage 2
  5. Stage 2 runs TO1/TO2 → BMO → Stage 3
```

**Pros**: Self-updating firmware. Stage 2 can be updated without full
BIOS reflash.

**Cons**: Requires SPI flash write support (not yet implemented).
Version-aware Stage 1 must know its own revision number.

---

## 4. Component Responsibilities

### Stage 1: FDO Firmware Stub (`rv-firmware`)

| Responsibility | Required | Notes |
|----------------|----------|-------|
| Read DCTPM from TPM NV | Yes | Index 0x01D10001 |
| Parse RV firmware extensions (tags 16/17/18) | Yes | FirmwareURL, FirmwarePath, MinFirmwareRev |
| HTTP GET firmware image | Yes | From FirmwareURL |
| COSE_Sign1 verification | Yes | Platform vendor public key |
| Anti-rollback check | Yes | TPM NV counter at 0x01D10002 |
| Chainload FDO Installer Image | Yes | LoadImage/StartImage |
| Device Initialization (DI) | Optional | Build feature `rv-firmware-di` |

### Stage 2: FDO Installer Image (default build)

| Responsibility | Required | Notes |
|----------------|----------|-------|
| Device Initialization (DI) | Auto-detect | Run if no credentials in TPM |
| TO1 protocol | Yes | Rendezvous server discovery |
| TO2 protocol | Yes | Owner server, encrypted ServiceInfo |
| BMO FSIM | Yes | Image transfer (inline/URL/meta) |
| devmod FSIM | Yes | Device module advertisement |
| Chainload payload | Yes | LoadImage/StartImage |

### Stage 3: Payload

Stage 3 is whatever the device owner wants to deploy via BMO. It is not
part of this project — it is the payload delivered by the FDO protocol.
Examples: OS installer, UKI, firmware update, BIOS config tool.

---

## 5. Execution Flow Detail

```text
main()
  │
  ├─ TPM present?  ──No──▶  error, exit
  │
  ├─ [rv-firmware feature enabled?]
  │     │
  │     ├─ [rv-firmware-di feature enabled?]
  │     │     │
  │     │     └─ No DCTPM in TPM? ──▶  Run DI protocol
  │     │         │                     (provisions TPM with credentials
  │     │         │                      including firmware RV tags)
  │     │         ▼
  │     ├─ Read DCTPM from TPM NV
  │     ├─ Parse RV firmware info
  │     ├─ Has firmware URL?
  │     │     ├─ Yes: Download → Verify COSE → Anti-rollback → Chainload
  │     │     │   └─ Chainloaded image returns → exit
  │     │     └─ No: fall through
  │     │
  │     └─ (fall through to FDO Installer Image logic)
  │
  ├─ Check DCTPM for GUID
  │     ├─ Found: run TO1/TO2 (onboarding)
  │     │     └─ BMO → chainload payload → exit
  │     └─ Not found: run DI protocol → exit
  │
  └─ exit
```

---

## 6. Testing Configurations

| Test | Build Features | What It Tests |
|------|---------------|---------------|
| QEMU DI | (default) | DI protocol against go-fdo server |
| QEMU TO2+BMO | (default) | Full onboarding with BMO chainload |
| QEMU rv-firmware | rv-firmware | Firmware download + COSE verify + chainload |
| QEMU full stack | rv-firmware, rv-firmware-di | DI → rv-firmware → chainload FDO Installer Image → TO2 → BMO |
| k800 DI | (default) | DI on real hardware TPM |
| k800 TO2+BMO | (default) | Full onboarding on real hardware |
| k800 rv-firmware | rv-firmware | Firmware delivery on real hardware |
| k800 full stack | rv-firmware, rv-firmware-di | Full 3-stage boot on real hardware |
