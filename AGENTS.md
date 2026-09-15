# Agents

## Test Environment

Use `ssh pe2` for access to system w/ QEMU environment to run on.

Test scripts live in `pe2:~/bkgvm/`:
- `init-tpm.sh` — one-time: creates device credentials + voucher via quick-di
- `start4.sh` — repeatable: runs FDO server + QEMU with swtpm, tests TO1/TO2/BMO

## Be Careful

About commands such as `apt` and others which require user-interaction as they may hang agent work.

## Build & Ship

```bash
# Build (on dev machine)
cargo build --release --features fdo-installer

# Create disk image
rm -f build/efi-disk-release.img && make build/efi-disk-release.img

# Ship to pe2
scp build/efi-disk-release.img pe2:/home/bkg/bkgvm/efi-disk-release.img
```

## Documentation

### Spec
Keep a rolling `spec.md` as a somewhat posthumous document that we update as we develop and learn — serves as an after-the-fact spec on the scope of work.

### Tutorialization
Maintain a running tutorialization (in README.md) on how to build and run this project — e.g. in our QEMU environment.

### TODO
Maintain a running `TODO.md` of remaining/outstanding items and technical debt.

## Key Files on pe2

| File | Purpose |
|------|---------|
| `/tmp/fdo-test4/fdo.db` | FDO server database (restored each run) |
| `/tmp/fdo-test4/fdo.db.orig` | Original database with matching owner key |
| `/tmp/fdo-vouchers4/*.fdoov` | Device voucher (created by init-tpm.sh) |
| `/tmp/fdo-test4/tpm2-00.permall` | TPM state file |
| `/tmp/fdo-test4/qemu.log` | QEMU serial output (device logs) |
| `/tmp/fdo-test4/server.log` | FDO server logs |
| `/tmp/fdo-firmware-server/` | BMO payload files served to device |

## UKI Build (on pe2)

```bash
# Build UKI from Ubuntu mini-ISO kernel + initrd
ukify build \
  --linux /tmp/ubuntu-vmlinuz \
  --initrd /tmp/ubuntu-initrd \
  --cmdline 'console=ttyS0 ip=dhcp' \
  --output /tmp/ubuntu-installer-full.efi

# Copy to server directory
cp /tmp/ubuntu-installer-full.efi /tmp/fdo-firmware-server/ubuntu-installer.efi
```

## Develop and Build on DevVM

Develop and build on `devvm` only. This is the source-of-truth for all code, tools, and where our working code and git repos live. We must build *here*, and copy any required components to other machines we actually run and deliver code, servers, etc. 


