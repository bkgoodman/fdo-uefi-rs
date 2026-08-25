#!/bin/bash
# boot_to_efi_shell.sh - Set next boot to UEFI Shell and reboot.
# Run on the OnLogic k800 (directly or via ssh onlogic).

set -e
set -x

HOSTNAME=$(hostname)
echo "Running on: $HOSTNAME"
if [ "$HOSTNAME" != "k800" ] && [ "$HOSTNAME" != "onlogic" ]; then
	echo "ERROR: Must run on the OnLogic k800, not $HOSTNAME"
	exit 1
fi

BOOT_NUM=$(efibootmgr | grep -i "Shell" | head -1 | awk '{print $1}' | tr -d 'Boot*')
if [ -z "$BOOT_NUM" ]; then
	echo "ERROR: No UEFI Shell boot entry found"
	efibootmgr
	exit 1
fi

echo "Setting next boot to UEFI Shell (Boot${BOOT_NUM})"
sudo efibootmgr -n "$BOOT_NUM"
sudo reboot
