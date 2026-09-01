#!/bin/bash
scp /home/bradgoodman/fdo-uefi-rs/target/x86_64-unknown-uefi/release/fdo-uefi.efi onlogic:/tmp/fdo-uefi.efi
ssh onlogic 'sudo cp /tmp/fdo-uefi.efi /boot/efi/EFI/fdo-uefi.efi && sudo sync && ls -la /boot/efi/EFI/fdo-uefi.efi && md5sum /boot/efi/EFI/fdo-uefi.efi'
ls -la /home/bradgoodman/fdo-uefi-rs/target/x86_64-unknown-uefi/release/fdo-uefi.efi
md5sum /home/bradgoodman/fdo-uefi-rs/target/x86_64-unknown-uefi/release/fdo-uefi.efi

# Control-test payload: the exact EFI image embedded in test-keys/signed_payload.cose.
# Pushing it lets leg 0 (-chainload) and the BMO leg use a byte-identical binary.
# scp /home/bradgoodman/fdo-uefi-rs/test-keys/payload_image.efi onlogic:/tmp/payload_image.efi
# ssh onlogic 'sudo cp /tmp/payload_image.efi /boot/efi/EFI/payload_image.efi && sudo sync && ls -la /boot/efi/EFI/payload_image.efi && md5sum /boot/efi/EFI/payload_image.efi'
# md5sum /home/bradgoodman/fdo-uefi-rs/test-keys/payload_image.efi

# One-liner: set next boot to FDO client and reboot
#sudo efibootmgr -n $(efibootmgr | grep "FDO Shell" | awk '{print $1}' | tr -d 'Boot*') && sudo reboot
