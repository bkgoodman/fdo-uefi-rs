# FDO UEFI Client (Rust) - Makefile
#
# Build and test UEFI application using Rust + uefi-rs
#

# UEFI build flags (build-std is needed for no_std UEFI target)
UEFI_TARGET = x86_64-unknown-uefi
UEFI_FLAGS = --target $(UEFI_TARGET) -Z build-std=core,compiler_builtins,alloc -Z build-std-features=compiler-builtins-mem

# Native test flags (no build-std — use pre-built std)
TEST_TARGET = x86_64-unknown-linux-gnu

# Output binary
TARGET = target/$(UEFI_TARGET)/debug/fdo-uefi.efi
TARGET_RELEASE = target/$(UEFI_TARGET)/release/fdo-uefi.efi

# QEMU settings (Ubuntu 25.04+ uses 4M variant)
OVMF_CODE = /usr/share/OVMF/OVMF_CODE_4M.fd
OVMF_VARS = /usr/share/OVMF/OVMF_VARS_4M.fd
QEMU = qemu-system-x86_64
QEMU_MEM = 2048
QEMU_OPTS = -machine q35 -m $(QEMU_MEM) -nographic \
	-drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) \
	-netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
	-device virtio-rng-pci

# Build directory
BUILDDIR = build

.PHONY: all
all: build

# Build debug (UEFI target)
.PHONY: build
build:
	cargo +nightly build $(UEFI_FLAGS)

# Build release (UEFI target)
.PHONY: release
release:
	cargo +nightly build --release $(UEFI_FLAGS)

# Build release with specific features (UEFI target)
.PHONY: release-installer
release-installer:
	cargo +nightly build --release --features fdo-installer $(UEFI_FLAGS)

# Native unit tests (no UEFI, no QEMU, no TPM)
.PHONY: test
test:
	cargo +nightly test --lib --target $(TEST_TARGET)

# Create FAT disk image for QEMU
$(BUILDDIR)/efi-disk.img: $(TARGET)
	@mkdir -p $(BUILDDIR)
	@echo "Creating EFI boot disk image..."
	dd if=/dev/zero of=$@ bs=1M count=64
	mkfs.vfat -F 32 $@
	mmd -i $@ ::/EFI
	mmd -i $@ ::/EFI/BOOT
	mcopy -i $@ $(TARGET) ::/EFI/BOOT/BOOTX64.EFI

# Create release FAT disk image
$(BUILDDIR)/efi-disk-release.img: $(TARGET_RELEASE)
	@mkdir -p $(BUILDDIR)
	@echo "Creating EFI boot disk image (release)..."
	dd if=/dev/zero of=$@ bs=1M count=64
	mkfs.vfat -F 32 $@
	mmd -i $@ ::/EFI
	mmd -i $@ ::/EFI/BOOT
	mcopy -i $@ $(TARGET_RELEASE) ::/EFI/BOOT/BOOTX64.EFI

# Run in QEMU (debug build)
.PHONY: run
run: build $(BUILDDIR)/efi-disk.img
	@echo "Starting QEMU with fdo-uefi.efi..."
	@echo "Press Ctrl-A X to exit QEMU"
	$(QEMU) $(QEMU_OPTS) -drive file=$(BUILDDIR)/efi-disk.img,format=raw

# Run in QEMU (release build)
.PHONY: run-release
run-release: release $(BUILDDIR)/efi-disk-release.img
	@echo "Starting QEMU with fdo-uefi.efi (release)..."
	@echo "Press Ctrl-A X to exit QEMU"
	$(QEMU) $(QEMU_OPTS) -drive file=$(BUILDDIR)/efi-disk-release.img,format=raw

# Clean
.PHONY: clean
clean:
	cargo clean
	rm -rf $(BUILDDIR)

# Check toolchain
.PHONY: check
check:
	@echo "Checking Rust toolchain..."
	@rustup show
	@echo ""
	@echo "Checking nightly target..."
	@rustup +nightly target list --installed | grep -q uefi || \
		(echo "Installing x86_64-unknown-uefi target..." && \
		 rustup +nightly target add x86_64-unknown-uefi)
	@echo "Toolchain OK"

# Check QEMU environment
.PHONY: check-qemu
check-qemu:
	@echo "Checking QEMU environment..."
	@which $(QEMU) > /dev/null || (echo "ERROR: qemu-system-x86_64 not found" && exit 1)
	@test -f $(OVMF_CODE) || (echo "ERROR: OVMF firmware not found at $(OVMF_CODE)" && exit 1)
	@echo "QEMU environment OK"

# Install Rust nightly and UEFI target
.PHONY: deps
deps:
	@echo "Installing Rust nightly toolchain..."
	rustup install nightly
	rustup +nightly component add rust-src
	@echo "Done. Use 'cargo +nightly build' to compile."

# Help
.PHONY: help
help:
	@echo "FDO UEFI Client (Rust) - Build Targets"
	@echo ""
	@echo "  make              - Build debug binary"
	@echo "  make build        - Build debug binary"
	@echo "  make release      - Build release binary"
	@echo "  make run          - Build and run in QEMU (debug)"
	@echo "  make run-release  - Build and run in QEMU (release)"
	@echo "  make clean        - Remove build artifacts"
	@echo ""
	@echo "  make check        - Verify Rust toolchain"
	@echo "  make check-qemu   - Verify QEMU environment"
	@echo "  make deps         - Install Rust nightly + rust-src"
	@echo ""
	@echo "Requirements:"
	@echo "  - Rust nightly with rust-src component"
	@echo "  - QEMU + OVMF for testing"
