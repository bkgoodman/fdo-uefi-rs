# UEFI Device Initialization (DI) Protocol Design

## Overview

This document proposes adding FDO Device Initialization (DI) protocol support to the fdo-uefi-rs project. The design supports **both** integrated and separate build options via Cargo features.

## Scope

**This is a MINIMAL reference implementation** — not a comprehensive, production-ready solution. The goal is to demonstrate spec compliance and provide a working baseline.

## Specifications

- **fdo-appnote-device-mfg-info.bs** — DeviceMfgInfo structure, payload types, CSR handling
- **securing-fdo-in-tpm.bs** — TPM credential storage (DCTPM format, persistent handles)
- **FIDO-IoT-spec.bs** — Base FDO 2.0 protocol

## Background

### Current State
- `fdo-uefi-rs`: Implements TO1/TO2 protocols, TPM access (NV read, signing), HTTP client
- `go-fdo-manufacturing-station`: DI server that devices connect to
- `go-fdo-quick-di`: Reference for local-only DI (no network, does both sides)
- `fido-device-onboard-rs/manufacturing-client`: Rust DI client (Linux, not UEFI)

### DI Protocol Flow (FDO 2.0)
```
Device                              Manufacturing Station
   |                                        |
   |  ---- DIAppStart (DeviceMfgInfo) ---> |  (msg type 10)
   |                                        |
   |  <--- DISetCredentials (OVHeader) --- |  (msg type 11)
   |                                        |
   |  ---- DISetHMAC (hmac) -------------> |  (msg type 12)
   |                                        |
   |  <--- DIDone ----------------------- |  (msg type 13)
   |                                        |
```

## Design Goals

1. **Build Flexibility**: Support both integrated (single binary) and separate (dedicated DI app) builds
2. **TPM Compliance**: Follow `securing-fdo-in-tpm.bs` spec exactly (DCTPM format, handle conventions)
3. **Manufacturing Station Compatibility**: Must work with `go-fdo-manufacturing-station`
4. **Reuse Existing Code**: Leverage existing `tpm.rs`, `http.rs`, CBOR encoding from TO1/TO2

## Architecture

### Module Structure

```
fdo-uefi-rs/src/
├── main.rs              # Entry point (dispatches based on build config)
├── di/                  # NEW: DI protocol module
│   ├── mod.rs           # Module exports
│   ├── protocol.rs      # DI message types and protocol flow
│   ├── credentials.rs   # Device credential generation
│   └── tpm_provision.rs # TPM key creation, DCTPM write
├── tpm.rs               # Existing + new: key creation, HMAC, NV write
├── http.rs              # Existing HTTP client
├── fdo.rs               # Existing TO1/TO2 (shares CBOR utils)
├── bmo.rs               # Existing BMO handling
└── chainload.rs         # Existing chainload
```

### Cargo Features

```toml
[features]
default = ["to1_to2"]           # Default: onboarding only
to1_to2 = []                    # TO1/TO2 protocol support
di = []                         # DI protocol support
full = ["to1_to2", "di"]        # Everything

# Build options:
# 1. Integrated (BIOS vendor): cargo build --features full
# 2. DI only (BMO-loaded):     cargo build --features di --no-default-features
# 3. TO1/TO2 only (default):   cargo build
```

### Entry Point Logic

```rust
#[entry]
fn main() -> Status {
    // Detect mode from:
    // 1. Command-line args (if loaded by shell)
    // 2. TPM state (DCTPM present/absent, DCActive flag)
    // 3. Build features
    
    #[cfg(feature = "di")]
    if needs_di() {
        return di::run_di_protocol();
    }
    
    #[cfg(feature = "to1_to2")]
    if needs_onboarding() {
        return run_onboarding();
    }
    
    Status::SUCCESS
}

fn needs_di() -> bool {
    // Check if DCTPM NV index is absent OR DCActive=false
    // Could also check for manufacturing network/DHCP option
    match tpm::read_dctpm() {
        None => true,  // No credentials, need DI
        Some(dctpm) if !dctpm.active => true,  // Explicitly marked for re-DI
        _ => false
    }
}
```

## DI Protocol Implementation

### Message Types (FDO 2.0)

```rust
// di/protocol.rs

/// DIAppStart (Type 10) - Device → Server
/// FDO 2.0: Contains DeviceMfgInfo with CSR
pub struct DIAppStart {
    pub device_mfg_info: DeviceMfgInfo,
    pub capability_flags: u32,
}

/// DeviceMfgInfo structure (per fdo-appnote-device-mfg-info.bs)
/// This is the MINIMAL implementation - only required fields
pub struct DeviceMfgInfo {
    // Top-level map keys (from spec)
    pub key_type: u8,           // DMI_KEY_TYPE (key 0): 13=P-256, 14=P-384
    pub key_encoding: u8,       // DMI_KEY_ENCODING (key 1): 1=X509
    pub csr_der: Vec<u8>,       // DMI_CSR (key 2): DER-encoded PKCS#10
    pub spec_version: u8,       // DMI_SPEC_VERSION (key 3): always 1
    
    // DMI_OVE_EXTRA_REQUEST (key 4) - minimal identity for OVEExtraInfo
    pub serial_number: String,  // PT_DEVICE_SERIAL (payload key 0)
    pub model: String,          // PT_MODEL (payload key 2)
}

/// DISetCredentials (Type 11) - Server → Device
pub struct DISetCredentials {
    pub ov_header: OVHeader,    // Ownership Voucher header
    pub server_capability_flags: u32,
}

/// DISetHMAC (Type 12) - Device → Server
pub struct DISetHMAC {
    pub hmac: Vec<u8>,          // HMAC over OVHeader
}

/// DIDone (Type 13) - Server → Device
pub struct DIDone;
```

### Protocol Flow

```rust
// di/protocol.rs

pub fn run_di_protocol() -> Status {
    info!("Starting Device Initialization (DI) protocol");
    
    // 1. Get manufacturing server URL (from DHCP option, config, or hardcoded)
    let mfg_server_url = get_manufacturing_server_url();
    
    // 2. Generate/retrieve device key in TPM
    let (dak_handle, public_key) = tpm::create_or_get_device_key()?;
    
    // 3. Generate HMAC key in TPM
    let hmac_handle = tpm::create_hmac_key()?;
    
    // 4. Generate CSR using TPM-based private key
    let csr_der = generate_csr_tpm(dak_handle)?;
    
    // 5. Build DeviceMfgInfo (per fdo-appnote-device-mfg-info.bs)
    let device_mfg_info = DeviceMfgInfo {
        key_type: KEY_TYPE_SECP256R1,      // DMI_KEY_TYPE
        key_encoding: KEY_ENCODING_X509,   // DMI_KEY_ENCODING
        csr_der,                           // DMI_CSR
        spec_version: 1,                   // DMI_SPEC_VERSION
        serial_number: get_device_serial(), // PT_DEVICE_SERIAL in OVE_EXTRA_REQUEST
        model: get_device_model(),          // PT_MODEL in OVE_EXTRA_REQUEST
    };
    
    // 6. Send DIAppStart, receive DISetCredentials
    let ov_header = send_app_start(&mfg_server_url, &device_mfg_info)?;
    
    // 7. Compute HMAC over OVHeader using TPM HMAC key
    let ov_header_cbor = encode_ov_header(&ov_header);
    let hmac = tpm::compute_hmac(hmac_handle, &ov_header_cbor)?;
    
    // 8. Send DISetHMAC, receive DIDone
    send_set_hmac(&mfg_server_url, &hmac)?;
    
    // 9. Write DCTPM to TPM NV index
    let dctpm = build_dctpm(&ov_header, dak_handle, hmac_handle);
    tpm::write_dctpm(&dctpm)?;
    
    info!("DI completed successfully. GUID: {:02x?}", ov_header.guid);
    Status::SUCCESS
}
```

## TPM Operations for DI

### New TPM Functions Required

```rust
// tpm.rs additions

/// Create ECC P-256 signing key (DAK) and persist at handle
pub fn create_device_key() -> Option<(u32, Vec<u8>)> {
    // 1. TPM2_CreatePrimary under Owner hierarchy (SRK)
    // 2. TPM2_Create child ECC signing key
    // 3. TPM2_Load
    // 4. TPM2_EvictControl to persist at 0x81020002
    // Returns (handle, public_key_der)
}

/// Create HMAC key and persist at handle
pub fn create_hmac_key() -> Option<u32> {
    // 1. TPM2_CreatePrimary under Owner hierarchy (SRK)
    // 2. TPM2_Create child HMAC key (SHA-256)
    // 3. TPM2_Load
    // 4. TPM2_EvictControl to persist at 0x81020003
}

/// Compute HMAC using TPM key
pub fn compute_hmac(key_handle: u32, data: &[u8]) -> Option<Vec<u8>> {
    // TPM2_HMAC command
}

/// Write DCTPM structure to NV index
pub fn write_dctpm(dctpm: &DCTPM) -> Option<()> {
    // 1. TPM2_NV_DefineSpace (if not exists)
    // 2. TPM2_NV_Write
}

/// Read DCTPM structure from NV index  
pub fn read_dctpm() -> Option<DCTPM> {
    // Existing read_fdo_credential() enhanced to parse full DCTPM
}
```

### DCTPM Structure (per securing-fdo-in-tpm.bs)

```rust
// di/credentials.rs

/// DCTPM - Device Credentials stored in TPM NV
/// CBOR array format per securing-fdo-in-tpm.bs
pub struct DCTPM {
    pub magic: u32,              // 0x46444F31 ("FDO1")
    pub active: bool,            // DCActive flag
    pub prot_ver: u16,           // 101=FDO 1.1, 200=FDO 2.0
    pub device_info: String,     // Device description
    pub guid: [u8; 16],          // Device GUID
    pub rv_info: Vec<u8>,        // RendezvousInfo (CBOR)
    pub pub_key_hash: Vec<u8>,   // Hash of owner public key
    pub device_key_type: u8,     // 0=DAK, 1=IDevID, 2=LDevID
    pub device_key_handle: u32,  // TPM handle for DAK
    pub hmac_key_handle: u32,    // TPM handle for HMAC key
}

impl DCTPM {
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut enc = CborEncoder::new();
        enc.array(10);
        enc.uint(self.magic);
        enc.bool(self.active);
        enc.uint(self.prot_ver as u64);
        enc.text(&self.device_info);
        enc.bytes(&self.guid);
        enc.raw(&self.rv_info);  // Pre-encoded RendezvousInfo
        enc.raw(&self.pub_key_hash);  // Pre-encoded Hash
        enc.uint(self.device_key_type as u64);
        enc.uint(self.device_key_handle as u64);
        enc.uint(self.hmac_key_handle as u64);
        enc.into_bytes()
    }
}

// NV Index handles (per spec)
const FDO_NV_INDEX_DCTPM: u32 = 0x01D10001;  // Standard
const FDO_NV_INDEX_DCTPM_ALT: u32 = 0x01C10130;  // go-fdo compatibility

// Persistent key handles
const FDO_DAK_HANDLE: u32 = 0x81020002;
const FDO_HMAC_HANDLE: u32 = 0x81020003;
```

## CSR Generation

### Approach: TPM-based CSR Signing

Since the private key never leaves the TPM, CSR generation requires:

```rust
// di/credentials.rs

/// Generate CSR with TPM-based signing
pub fn generate_csr_tpm(dak_handle: u32, device_info: &str) -> Option<Vec<u8>> {
    // 1. Build CertificationRequestInfo (TBS) structure
    let tbs = build_csr_tbs(device_info);
    
    // 2. Hash TBS with SHA-256
    let tbs_hash = sha256(&tbs);
    
    // 3. Sign hash with TPM using DAK
    let signature = tpm::tpm_sign_ecdsa(dak_handle, &tbs_hash)?;
    
    // 4. Assemble complete CSR DER
    let csr_der = assemble_csr_der(&tbs, &signature);
    
    Some(csr_der)
}

fn build_csr_tbs(device_info: &str) -> Vec<u8> {
    // Build X.509 CertificationRequestInfo:
    // SEQUENCE {
    //   version INTEGER (0),
    //   subject Name (CN=device_info),
    //   subjectPKInfo SubjectPublicKeyInfo,
    //   attributes [0] (empty)
    // }
}
```

## Manufacturing Server Discovery

### Options for Server URL

```rust
// di/protocol.rs

fn get_manufacturing_server_url() -> String {
    // Priority order:
    
    // 1. UEFI variable (set by BIOS setup or previous config)
    if let Some(url) = read_uefi_variable("FdoMfgServerUrl") {
        return url;
    }
    
    // 2. DHCP vendor option (common in factory environments)
    if let Some(url) = get_dhcp_vendor_option(224) {  // Example option
        return url;
    }
    
    // 3. mDNS/DNS-SD discovery (_fdo-di._tcp.local)
    // Complex for UEFI, may skip
    
    // 4. Compile-time default (for testing)
    #[cfg(debug_assertions)]
    return "http://10.0.2.2:8080".to_string();
    
    // 5. Panic if no server found
    panic!("No manufacturing server URL configured");
}
```

## Build Configurations

### 1. Integrated Build (BIOS Vendor)

```bash
# Single binary with both DI and TO1/TO2
cargo build --release --features full

# Entry point logic determines which protocol to run:
# - No DCTPM → Run DI
# - DCTPM with DCActive=true → Run TO1/TO2
# - DCTPM with DCActive=false → Skip (already onboarded)
```

### 2. Separate DI App (BMO-Loaded)

```bash
# Minimal DI-only binary (loaded via efi-fdo-bmo)
cargo build --release --features di --no-default-features

# This produces a smaller binary that:
# - Only contains DI protocol code
# - Can be chainloaded by BMO after initial factory boot
# - Useful for late-stage provisioning
```

### 3. TO1/TO2 Only (Default)

```bash
# Standard onboarding client (assumes DI done by go-fdo-quick-di)
cargo build --release

# This is the current behavior - reads existing DCTPM
```

## Testing Strategy

### 1. Unit Tests (Host)
- CBOR encoding/decoding for DI messages
- DCTPM structure serialization
- CSR building (without TPM)

### 2. Integration Tests (QEMU + swtpm)
```bash
# 1. Start swtpm
swtpm socket --tpmstate dir=/tmp/fdo-tpm \
  --server type=unixio,path=/tmp/fdo-tpm/swtpm-server \
  --ctrl type=unixio,path=/tmp/fdo-tpm/swtpm-ctrl \
  --tpm2 --flags startup-clear

# 2. Start go-fdo-manufacturing-station
cd go-fdo-manufacturing-station
./fdo-manufacturing-station -config config.yaml

# 3. Run UEFI DI app in QEMU
qemu-system-x86_64 \
  -drive if=pflash,format=raw,file=OVMF_CODE.fd \
  -drive format=raw,file=fat:rw:esp \
  -chardev socket,id=chrtpm,path=/tmp/fdo-tpm/swtpm-ctrl \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 \
  -device virtio-net-pci,netdev=net0 \
  -netdev user,id=net0,hostfwd=tcp::8080-:8080
```

### 3. End-to-End Test
```bash
# 1. Run DI (UEFI app against go-fdo-manufacturing-station)
# 2. Verify voucher created
# 3. Import voucher to go-fdo owner server
# 4. Run TO1/TO2 (UEFI app against go-fdo)
# 5. Verify onboarding completes
```

## Implementation Status

### Phase 1: Core DI Messages ✅ COMPLETE
- [x] DI message CBOR encoding (AppStart, SetCredentials, SetHMAC, Done)
- [x] DeviceMfgInfo structure with CSR
- [x] HTTP client integration for DI endpoints

### Phase 2: TPM Key Creation ✅ COMPLETE
- [x] TPM2_CreatePrimary for DAK (ECC P-256) under Endorsement hierarchy
- [x] TPM2_CreatePrimary for HMAC key (SHA-256)
- [x] TPM2_EvictControl for persistence (DAK @ 0x81020002, HMAC @ 0x81020003)
- [x] TPM2_HMAC for voucher header HMAC
- [x] TPM2_Sign for CSR signing

### Phase 3: DCTPM Storage ✅ COMPLETE
- [x] TPM2_NV_DefineSpace (index 0x01500001, OWNERWRITE|OWNERREAD)
- [x] TPM2_NV_Write with DCTPM CBOR
- [x] Integration with existing credential check

### Phase 4: Entry Point ✅ COMPLETE
- [x] Auto-detect: check TPM NV for credentials
- [x] No credentials → run DI protocol
- [x] Has credentials → run TO1/TO2 protocols

### Phase 5: Testing ✅ COMPLETE
- [x] QEMU + swtpm integration tests
- [x] go-fdo server compatibility
- [x] End-to-end DI flow verified

## Resolved Questions (via specs)

1. **CSR Subject**: Per `fdo-appnote-device-mfg-info.bs` §cert-subject-dn:
   `CN=<SerialNumber>, O=<Manufacturer>[, OU=<Model>]`
   Manufacturing station has authority to override.

2. **Server Discovery**: Per `fdo-appnote-device-mfg-info.bs` §mfg-server-discovery:
   - UEFI variable `FdoMfgServerUrl` (priority 1)
   - DHCP vendor option (priority 2)
   - mDNS `_fdo-di._tcp.local` (optional)
   **Minimal impl**: UEFI variable only.

3. **DeviceMfgInfo Format**: Per `fdo-appnote-device-mfg-info.bs`:
   CBOR map with keys 0-5. Minimal impl uses keys 0,1,2,3,4.

4. **FDO Version**: FDO 2.0 only (per project scope).

## Open Questions

1. **Key Rotation**: Should DI support re-provisioning (replace existing keys)?
   → For minimal impl: No. Require TPM clear first.

2. **Error Recovery**: What if DI fails mid-protocol?
   → For minimal impl: Retry from start. No partial state.

## References

- [fdo-appnote-device-mfg-info.bs](../internet-of-things-specs/fdo-appnote-device-mfg-info.bs) - **DeviceMfgInfo structure spec (primary)**
- [securing-fdo-in-tpm.bs](../internet-of-things-specs/securing-fdo-in-tpm.bs) - TPM credential storage spec
- [go-fdo-manufacturing-station](../go-fdo-manufacturing-station/) - DI server
- [go-fdo-quick-di](../go-fdo-quick-di/) - Reference DI implementation
- [fido-device-onboard-rs/manufacturing-client](../fido-device-onboard-rs/manufacturing-client/) - Rust DI client
