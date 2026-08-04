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

```
Boot → Check TPM NV → No credentials? → DI Protocol → Write DCTPM → Done
                   → Has credentials? → TO1 → TO2 → BMO → Chainload
```

## Testing

### Quick Test (on pe2)

```bash
# Full end-to-end test with DI, TO2, and BMO
ssh pe2 "cd ~/fdo-uefi-rs && bash start3.sh"
```

### DI Protocol Test

To test Device Initialization (DI) protocol with UEFI client:

```bash
# 1. Start fresh swtpm (no existing state)
rm -rf /tmp/fdo-tpm && mkdir -p /tmp/fdo-tpm
swtpm socket --tpmstate dir=/tmp/fdo-tpm \
    --server type=unixio,path=/tmp/fdo-tpm/swtpm-server \
    --ctrl type=unixio,path=/tmp/fdo-tpm/swtpm-ctrl \
    --tpm2 --flags startup-clear &

# 2. Start go-fdo manufacturing server
server server -http 0.0.0.0:8080 -db /tmp/fdo.db

# 3. Run UEFI client in QEMU (will auto-detect no credentials and run DI)
qemu-system-x86_64 -machine q35 -m 2048 \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,file=OVMF_VARS.fd \
    -drive file=disk.img,format=raw \
    -chardev socket,id=chrtpm,path=/tmp/fdo-tpm/swtpm-ctrl \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 \
    -device virtio-rng-pci \
    -nic user,model=virtio-net-pci \
    -nographic
```

Expected output:
```
Attempting Device Initialization (DI)...
FDO Device Initialization (DI) Protocol
Sending DIAppStart...
Received DISetCredentials
Sending DISetHMAC...
Received DIDone
Device Initialization COMPLETE
```

### Manual Test Steps (TO1/TO2 with external DI)

1. **Initialize database and export owner key:**

   ```bash
   server server -db /tmp/fdo.db -initOnly
   server server -db /tmp/fdo.db -print-owner-public SECP256R1 > owner.pem
   ```

2. **Start swtpm (TPM simulator):**

   ```bash
   swtpm socket --tpmstate dir=/tmp/tpm \
       --server type=unixio,path=/tmp/tpm/swtpm-server \
       --ctrl type=unixio,path=/tmp/tpm/swtpm-ctrl \
       --tpm2 --flags startup-clear &
   ```

3. **Create voucher via Device Initialization:**

   ```bash
   FDO_TPM_DEVICE=/tmp/tpm/swtpm-server \
       quick-di-tpm -quick -rv 10.0.2.2:8080:http \
       -device-info "Test" -output-dir /tmp/vouchers \
       -signover-key owner.pem
   ```

4. **Import voucher and start server with BMO:**

   ```bash
   server server -db /tmp/fdo.db -import-voucher /tmp/vouchers/*.fdoov -initOnly
   server -debug server -http 0.0.0.0:8080 -db /tmp/fdo.db -rv-bypass \
       -reuse-cred -bmo-file payload.efi -bmo-type "application/x-uefi-image"
   ```

5. **Create boot disk and run QEMU:**

   ```bash
   dd if=/dev/zero of=disk.img bs=1M count=64
   mkfs.vfat -F 32 disk.img
   mmd -i disk.img ::/EFI ::/EFI/BOOT
   mcopy -i disk.img fdo-uefi.efi ::/EFI/BOOT/BOOTX64.EFI
   
   qemu-system-x86_64 -machine q35 -m 2048 \
       -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
       -drive if=pflash,format=raw,file=OVMF_VARS.fd \
       -drive file=disk.img,format=raw \
       -chardev socket,id=chrtpm,path=/tmp/tpm/swtpm-ctrl \
       -tpmdev emulator,id=tpm0,chardev=chrtpm \
       -device tpm-tis,tpmdev=tpm0 \
       -device virtio-rng-pci \
       -nic user,model=virtio-net-pci \
       -nographic
   ```

### Verifying Success

Check server log for BMO completion:
```bash
grep -E "image-end|All chunks sent|Done" /tmp/fdo-test3/server.log
```

Expected output shows all chunks sent and protocol completion.

## Project Structure

```
fdo-uefi-rs/
├── Cargo.toml          # Package manifest
├── README.md           # This file
├── TODO.md             # Development status and known issues
├── spec.md             # Technical specification
├── start3.sh           # Automated test script
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
