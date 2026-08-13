#!/bin/bash
scp /home/bradgoodman/fdo-uefi-rs/target/x86_64-unknown-uefi/release/fdo-uefi.efi onlogic:/tmp/fdo-uefi.efi
ssh onlogic 'sudo cp /tmp/fdo-uefi.efi /boot/efi/EFI/fdo-uefi.efi && sudo sync && ls -la /boot/efi/EFI/fdo-uefi.efi && md5sum /boot/efi/EFI/fdo-uefi.efi'
ls -la /home/bradgoodman/fdo-uefi-rs/target/x86_64-unknown-uefi/release/fdo-uefi.efi
md5sum /home/bradgoodman/fdo-uefi-rs/target/x86_64-unknown-uefi/release/fdo-uefi.efi

# One-liner: set next boot to FDO client and reboot
#sudo efibootmgr -n $(efibootmgr | grep "FDO Shell" | awk '{print $1}' | tr -d 'Boot*') && sudo reboot
