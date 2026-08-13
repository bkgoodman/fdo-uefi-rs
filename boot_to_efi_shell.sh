#!/bin/bash

set -x 1
set -e 1
sudo efibootmgr -n $(efibootmgr | grep "Shell" | awk '{print $1}' | tr -d 'Boot*')
sudo reboot &
exit

# List current boot entries
#sudo efibootmgr -v
 
# Create a new boot entry for fdo-uefi.efi
#sudo efibootmgr -c -d /dev/sda -p 1 -L "FDO UEFI Client" -l '\EFI\Dell\fdo-uefi.efi'
 
# Create one for the UEFI Shell too
#sudo efibootmgr -c -d /dev/sda -p 1 -L "UEFI Shell" -l '\EFI\Dell\Shell.efi'
 
# Set next boot (one-time) to a specific entry number
#sudo efibootmgr -n 0005   # where 0005 is the boot entry number from the list
