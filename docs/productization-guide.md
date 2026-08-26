<!-- Copyright 2026 Dell Technologies, All Rights Reserved -->
<!-- Author: Brad Goodman <bradley.goodman@dell.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# FDO UEFI Client — Productization Guide

**Date**: 2026-08-26
**Author**: Brad Goodman <bradley.goodman@dell.com>
**Status**: DRAFT

---

## 1. Purpose

This document discusses the practical logistics of deploying the FDO UEFI
client components on a real platform. It covers decisions an OEM or platform
integrator must make about where components live, how they are updated, and
what tradeoffs each choice implies.

**This is NOT about how to build or test the code** — see
[README.md](../README.md) for build instructions and
[modular-architecture.md](modular-architecture.md) for the stage/feature
composition. This document is about what happens *after* the code works and
you need to ship it on real hardware.

---

## 2. Components and Their Roles

For terminology and detailed architecture, see the Boot Chain Overview in
[README.md](../README.md). The short version:

| Component | Proper Name | What It Does |
|-----------|-------------|--------------|
| Stage 1 | **FDO Firmware Stub** | Reads TPM, downloads signed Stage 2, verifies, chainloads |
| Stage 1a | **DI in Firmware Stub** | Optional: runs DI if no credentials exist (build feature) |
| Stage 2 | **FDO Installer Image** | Runs FDO protocol (DI/TO1/TO2), receives payload via BMO |
| Stage 3 | **Payload** | OS installer, UKI, firmware update, etc. (not our code) |

---

## 3. Test Environment vs. Production

### 3.1 What We Do Today (Test/PoC)

Our entire test infrastructure uses **standalone EFI applications on a
FAT32 filesystem**:

```text
FAT32 disk image (or USB stick):
  /EFI/BOOT/BOOTX64.EFI    ← our .efi binary
```

This is loaded by the UEFI Boot Manager as a removable media boot option.
In QEMU, the disk image is attached as a virtio drive. On the k800, it's
written to the internal FAT32 EFI System Partition.

**This avoids all real platform integration questions:**

- No SPI flash involvement
- No firmware volume (FV) packaging
- No DXE driver registration
- No boot order management beyond "boot from this disk"
- No firmware update mechanism — we just overwrite the file

This is fine for validating the FDO protocol, TPM operations, BMO transfer,
COSE verification, and chainloading. It is **not** how a production device
would work.

### 3.2 What Production Looks Like

In production, the FDO Firmware Stub is **part of the platform firmware
image** — it lives in SPI flash alongside the UEFI firmware itself. The FDO
Installer Image may or may not also be in flash, depending on the deployment
model chosen (see §4).

```text
SPI Flash Layout (conceptual):
┌──────────────────────────────────────────────┐
│  Platform Firmware (UEFI/BIOS)               │
│  ├─ PEI (Pre-EFI Initialization)             │
│  ├─ DXE Core + Drivers                       │
│  │   └─ FDO Firmware Stub (DXE driver)  ◄────│── Our Stage 1
│  ├─ BDS (Boot Device Selection)              │
│  └─ NVRAM variables                          │
├──────────────────────────────────────────────┤
│  FDO Installer Image region (optional)       │
│  Only if running-from-flash model    ◄───────│── Our Stage 2 (maybe)
├──────────────────────────────────────────────┤
│  Platform vendor trust anchors               │
│  (Platform key for COSE verification)        │
└──────────────────────────────────────────────┘
```

The gap between "EFI app on FAT32" and "DXE driver in SPI flash" is
significant. This document does not cover the EDK2 DXE porting work —
see [delivery-options.md](../../efi-fdo-bmo/docs/delivery-options.md) for
that analysis. This document focuses on the *deployment decisions* that
are independent of the delivery vehicle.

---

## 4. Deployment Models

### 4.1 Model A: Download-to-RAM (Recommended Starting Point)

The FDO Firmware Stub lives in flash. The FDO Installer Image is
**downloaded at boot time** into RAM, verified, and chainloaded. Nothing
is written to flash during normal operation.

```text
In flash:    FDO Firmware Stub (small, ~100KB)
In RAM:      FDO Installer Image (downloaded each boot, ~500KB-1MB)
From BMO:    Payload (downloaded via TO2, chainloaded from RAM)
```

**How it works:**

1. FDO Firmware Stub reads DCTPM from TPM NV
2. HTTP GET → signed FDO Installer Image (COSE_Sign1)
3. Verify signature against platform vendor key embedded in firmware
4. LoadImage into RAM → StartImage
5. FDO Installer Image runs TO1/TO2, receives payload, chainloads it

**Pros:**

- Simplest flash layout — only the stub needs to be in firmware
- FDO Installer Image can be updated server-side without touching flash
- No flash write support needed in the stub
- Smallest firmware footprint
- Natural separation: platform vendor owns the stub, service provider
  owns the Installer Image

**Cons:**

- Requires network access every boot (until onboarding is complete)
- If the firmware server is unreachable, device cannot onboard
- Downloaded image is in RAM only — lost on reboot/power cycle

**When to use:** Most deployments. This is the model our test environment
approximates (just with FAT32 instead of SPI flash for the stub).

### 4.2 Model B: Installer Image in Flash

Both the FDO Firmware Stub and FDO Installer Image live in flash. No
download needed — the stub chainloads the Installer Image directly from
a firmware volume.

```text
In flash:    FDO Firmware Stub (~100KB) + FDO Installer Image (~500KB-1MB)
From BMO:    Payload (downloaded via TO2, chainloaded from RAM)
```

**How it works:**

1. FDO Firmware Stub locates the FDO Installer Image in firmware volume
2. LoadImage from firmware volume → StartImage (no network, no HTTP)
3. FDO Installer Image runs DI/TO1/TO2, receives payload, chainloads it

**Pros:**

- No network dependency for Stage 1 → Stage 2 transition
- Works even if firmware server is down
- Faster boot (no HTTP download)

**Cons:**

- Larger firmware footprint (stub + installer image both in flash)
- Updating the FDO Installer Image requires a firmware/BIOS update
- Platform vendor must include the Installer Image in their firmware
  build process

**When to use:** Platforms with sufficient flash space where the platform
vendor wants a fully self-contained firmware image, or where network
access during early boot is unreliable.

### 4.3 Model C: No Stub (Installer Image Only)

Skip the FDO Firmware Stub entirely. The FDO Installer Image runs directly
as a DXE driver or standalone EFI app. This is the simplest model but loses
the separation between platform firmware and FDO client.

```text
In flash:    FDO Installer Image only (~500KB-1MB)
From BMO:    Payload (downloaded via TO2, chainloaded from RAM)
```

**Pros:**

- Simplest — one component, no chainloading
- No COSE verification infrastructure needed
- No firmware download server needed

**Cons:**

- No independent update path for the FDO client
- FDO client updates require full BIOS updates
- No anti-rollback for the FDO client itself
- Platform vendor must build and maintain the full FDO client

**When to use:** Simple deployments, prototyping, or platforms where the
FDO client is tightly coupled to the firmware release cycle.

### 4.4 Model D: Self-Updating Flash (Future)

The FDO Firmware Stub downloads a newer FDO Installer Image and writes it
to flash, replacing the previous version. On next boot, the updated
Installer Image runs from flash.

```text
In flash:    FDO Firmware Stub + FDO Installer Image (updatable region)
On update:   Stub downloads new Installer Image → writes to flash → reboot
```

**Pros:**

- FDO client can be updated independently of full BIOS updates
- Persistent — survives reboot without re-downloading
- Anti-rollback protection via TPM NV counter

**Cons:**

- Requires SPI flash write support in the stub
- Flash layout must reserve an updatable region
- Must handle partial-write / power-loss scenarios (A/B partitioning?)
- Signed firmware capsule or custom update mechanism needed
- **Not yet implemented** — requires flash write APIs

**When to use:** Production platforms that need persistent, updatable FDO
client firmware without full BIOS reflash cycles.

---

## 5. DI Placement Decision

Device Initialization (DI) is the manufacturing/provisioning step that
writes credentials (DCTPM) to the TPM. The question is: **where does DI
run?**

### 5.1 Option 1: DI in the FDO Firmware Stub (`rv-firmware` + `di`)

Build the FDO Firmware Stub with both the `rv-firmware` and `di` features. If no
credentials exist in the TPM, the stub runs DI against a manufacturing
server before proceeding to firmware delivery.

```text
Factory:
  Device powers on → Stub finds no DCTPM → runs DI → TPM provisioned
  No other software needed on the factory floor

Customer site:
  Device powers on → Stub finds DCTPM → downloads Installer Image → onboards
```

**Implications:**

- The firmware image ships with DI capability built in
- Manufacturing server only needs to speak FDO DI protocol
- No need to serve a separate FDO Installer Image at the factory
- Slightly larger firmware footprint (~50KB for DI code)
- The platform vendor key is NOT needed for DI — only for verifying
  the Installer Image download

**Best for:** OEMs who want a single firmware image that handles both
factory provisioning and field deployment.

### 5.2 Option 2: DI in the FDO Installer Image (Factory-Served)

Build the FDO Firmware Stub WITHOUT DI. At the factory, the manufacturing
server serves a vendor-signed FDO Installer Image that includes DI. The
stub downloads and chainloads it; the Installer Image runs DI.

```text
Factory:
  Device powers on → Stub downloads Installer Image → Installer runs DI
  Requires: manufacturing server + firmware server (serving signed Installer Image)

Customer site:
  Device powers on → Stub downloads (possibly different) Installer Image → onboards
```

**Implications:**

- Smallest possible firmware footprint for the stub
- Factory infrastructure must host both FDO DI server AND firmware server
- The Installer Image served at the factory could be different from the
  one served in the field (factory version has DI, field version does not)
- More moving parts at the factory

**Best for:** Space-constrained firmware where every KB matters, or where
factory infrastructure already exists and can serve signed images.

### 5.3 Option 3: DI via External Tool (quick-di)

Don't run DI in firmware at all. Use an external tool (`quick-di`,
`go-fdo-manufacturing-station`) connected to the TPM (directly or via
swtpm) to provision credentials before the device ships.

```text
Factory:
  Manufacturing station connects to device TPM (USB, network, swtpm)
  quick-di provisions DCTPM directly into TPM NV
  No FDO Installer Image needed at factory

Customer site:
  Device powers on → Stub downloads Installer Image → onboards
```

**Implications:**

- No DI in firmware at all — smallest possible images
- Requires physical or network access to the TPM at the factory
- Manufacturing station software is separate from the device firmware
- Most flexible — the device firmware doesn't need to know anything
  about DI

**Best for:** High-volume manufacturing with dedicated provisioning
stations, or development/testing environments.

---

## 6. Flash Layout Considerations

### 6.1 Where Things Live

A production platform must allocate space for FDO components in the
firmware flash layout. Typical SPI flash sizes are 16MB-32MB for modern
x86 UEFI platforms.

| Region | Size Estimate | Updatable? | Notes |
|--------|---------------|------------|-------|
| FDO Firmware Stub | ~100-200KB | With BIOS update | Part of firmware volume |
| FDO Installer Image | ~500KB-1MB | See §6.2 | If stored in flash (Model B/D) |
| Platform vendor public key | ~64 bytes | With BIOS update | Embedded in stub binary |
| TPM NV: DCTPM | ~1-4KB | By FDO protocol | TPM manages this, not flash |
| TPM NV: Anti-rollback counter | ~8 bytes | By stub | TPM NV index 0x01D10002 |

### 6.2 Update Mechanisms

How each component gets updated in the field:

| Component | Update Mechanism | Who Controls It |
|-----------|-----------------|-----------------|
| FDO Firmware Stub | BIOS/firmware update (capsule, flashrom, vendor tool) | Platform vendor |
| FDO Installer Image (in flash) | Either BIOS update or self-update (Model D) | Platform vendor or service provider |
| FDO Installer Image (downloaded) | Update the image on the firmware server | Service provider |
| Platform vendor key | BIOS/firmware update (key rotation = new firmware) | Platform vendor |
| DCTPM credentials | FDO DI protocol (re-provisioning) | Manufacturing/service provider |
| Anti-rollback counter | FDO Firmware Stub (monotonic increment) | Automatic |
| Payload | FDO TO2 + BMO (new image from owner server) | Device owner |

### 6.3 Key Rotation

The platform vendor public key is embedded in the FDO Firmware Stub at
build time. Rotating this key requires:

1. Build new FDO Firmware Stub with new key
2. Sign new FDO Installer Images with the corresponding private key
3. Deploy firmware update to devices (changes the stub)
4. Old Installer Images signed with the old key will be rejected

This is a **firmware update** — there is no in-band key rotation mechanism.
The key is a trust anchor, not a credential.

---

## 7. Security Boundaries

### 7.1 Trust Model

```text
Platform Vendor
  └─ Signs: FDO Installer Image (COSE_Sign1)
  └─ Embeds: Platform vendor public key in FDO Firmware Stub
  └─ Controls: What firmware the device will accept

Device Owner (via FDO)
  └─ Controls: What payload the device receives after onboarding
  └─ Owns: Ownership voucher chain
  └─ Cannot: Tamper with the FDO Firmware Stub or platform key

Manufacturing / Factory
  └─ Provisions: TPM with DCTPM (credentials + RV info)
  └─ Creates: Ownership voucher
  └─ Cannot: Change platform vendor key or firmware
```

### 7.2 What Each Component Trusts

| Component | Trusts | Verified By |
|-----------|--------|-------------|
| FDO Firmware Stub | Platform vendor key (hardcoded) | Build-time embedding |
| FDO Firmware Stub | DCTPM in TPM NV | TPM access control (Platform hierarchy) |
| FDO Installer Image | COSE_Sign1 signature | FDO Firmware Stub verifies before chainload |
| FDO Installer Image | FDO server credentials | TO2 protocol (ownership voucher chain) |
| Payload | FDO owner server | TO2 encrypted ServiceInfo exchange |

---

## 8. Deployment Checklist

For an OEM integrating FDO firmware delivery into a platform:

### 8.1 Decisions to Make

- [ ] **Deployment model**: Download-to-RAM (A), In-flash (B), No-stub (C), or Self-updating (D)?
- [ ] **DI placement**: In firmware stub, in installer image, or external tool?
- [ ] **Flash budget**: How much space is available for FDO components?
- [ ] **Key management**: Who generates and controls the platform vendor keypair?
- [ ] **Firmware server**: Who hosts the signed FDO Installer Images?
- [ ] **Update path**: How will the FDO components be updated in the field?
- [ ] **Manufacturing flow**: How are devices provisioned (DI) at the factory?

### 8.2 Artifacts to Produce

| Artifact | Tool | Destination |
|----------|------|-------------|
| Platform vendor keypair | `fdo-meta-tool platform generate-key` | Secure key storage |
| Platform vendor public key (C/Rust) | `fdo-meta-tool platform export-pubkey` | Embedded in FDO Firmware Stub source |
| Signed FDO Installer Image | `fdo-meta-tool platform sign` | Firmware server or flash |
| FDO Firmware Stub binary | `cargo build --features rv-firmware[-di]` | Platform firmware image |
| FDO Installer Image binary | `cargo build` (default features) | Firmware server or flash |
| Ownership vouchers | DI protocol or `quick-di` | FDO owner service database |

### 8.3 Infrastructure Required

| Service | Purpose | Required For |
|---------|---------|--------------|
| FDO Manufacturing Server | DI protocol endpoint | Factory provisioning |
| Firmware Server (HTTP) | Hosts signed FDO Installer Images | Model A (download-to-RAM) |
| FDO Rendezvous Server | TO1 protocol endpoint | Field onboarding |
| FDO Owner Server | TO2 protocol + BMO payload | Field onboarding |

---

## 9. Current Limitations

Things that work in our test environment but need attention for production:

| Area | Test Environment | Production Requirement |
|------|-----------------|----------------------|
| Delivery vehicle | Standalone EFI app on FAT32 | DXE driver in firmware volume |
| Flash storage | File on FAT32 partition | SPI flash firmware volume |
| Flash updates | Overwrite file on disk | Firmware capsule update, A/B partitioning |
| Platform key | Hardcoded in source | Secure provisioning, HSM-backed |
| Network | QEMU user-mode NAT or direct Ethernet | Platform-specific NIC drivers, PXE, HTTPS |
| TPM access | swtpm or raw /dev/tpmrm0 | Platform hierarchy, NV index ACLs |
| Anti-rollback | TPM NV counter (implemented) | Needs production NV index allocation |
| Secure Boot | Not enforced | Must coexist with platform Secure Boot policy |
| Error recovery | Reboot and try again | Fallback boot path, recovery mode |
| Logging | Serial console | Platform event log, UEFI variables, or BMC |

---

## 10. References

- [README.md](../README.md) — Build instructions, boot chain overview
- [modular-architecture.md](modular-architecture.md) — Stage composition and deployment scenarios
- [delivery-options.md](../../efi-fdo-bmo/docs/delivery-options.md) — EFI app vs DXE driver vs PEI module analysis
- [product-requirements-spec.md](../../efi-fdo-bmo/docs/product-requirements-spec.md) — Functional and non-functional requirements
