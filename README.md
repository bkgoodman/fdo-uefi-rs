# FDO UEFI Client (Rust)

A UEFI application implementing the FDO TO1/TO2 protocols and BMO FSIM, written in Rust.

## Overview

This project aims to implement a full FDO (FIDO Device Onboard) client as a UEFI application,
suitable for device onboarding during firmware boot. It is a Rust rewrite of the C-based
`efi-fdo-bmo` project.

### Goals

- Full TO1 and TO2 protocol implementation
- BMO FSIM (Firmware Service Info Module) support
- TPM-based credential storage
- HTTP(S) communication
- Pure Rust, no_std compatible

## Prerequisites

### Rust Toolchain

```bash
# Install nightly toolchain with rust-src
make deps

# Or manually:
rustup install nightly
rustup +nightly component add rust-src
```

### QEMU Testing (optional)

```bash
# Ubuntu/Debian
sudo apt-get install qemu-system-x86 ovmf mtools dosfstools
```

## Building

```bash
# Debug build
make build

# Release build (optimized, smaller)
make release

# Or directly with cargo:
cargo +nightly build
```

## Testing in QEMU

```bash
# Build and run in QEMU
make run

# Press Ctrl-A X to exit QEMU
```

## Project Structure

```
fdo-uefi-rs/
├── Cargo.toml          # Package manifest
├── Makefile            # Build automation
├── README.md           # This file
├── .cargo/
│   └── config.toml     # Cargo config (UEFI target)
└── src/
    └── main.rs         # Entry point
```

## Roadmap

### Phase 1: Scaffolding (Current)
- [x] Basic UEFI application structure
- [x] Build system with QEMU support
- [ ] Verify builds and runs

### Phase 2: Protocol Foundation
- [ ] TPM support via `uefi::proto::tcg`
- [ ] HTTP support via `uefi::proto::network`
- [ ] CBOR parsing (minicbor)
- [ ] Crypto (RustCrypto: p256, ecdsa, sha2)

### Phase 3: FDO Protocol
- [ ] Port fdo-data-formats to no_std
- [ ] TO1 protocol
- [ ] TO2 protocol
- [ ] FSIM handlers

### Phase 4: Integration
- [ ] Chain-loading support
- [ ] Anti-rollback
- [ ] E2E testing

## References

- [uefi-rs](https://github.com/rust-osdev/uefi-rs) - Rust UEFI library
- [fido-device-onboard-rs](../fido-device-onboard-rs) - Reference Rust FDO implementation
- [efi-fdo-bmo](../efi-fdo-bmo) - Reference C UEFI implementation
- [UEFI Specification](https://uefi.org/specifications)

## License

Copyright (c) 2026 Dell Technologies. All rights reserved.
