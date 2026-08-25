// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// Anti-Rollback Protection for RV-Based Firmware Delivery
//
// Maintains a monotonic firmware revision counter in TPM NV storage.
// The effective minimum revision is MAX(RVMinFirmwareRev, persisted counter).
// After successful signature verification, the counter is ratcheted up.

use log::{info, warn};
use crate::tpm;

/// TPM NV index for firmware revision counter (Profile A)
const FDO_NV_INDEX_FWREV: u32 = 0x01D10002;

/// Read the persisted firmware revision counter from TPM NV.
/// Returns 0 if the index doesn't exist (first boot).
pub fn read_firmware_rev_counter() -> u64 {
    match tpm::tpm_nv_read(FDO_NV_INDEX_FWREV) {
        Some(data) => {
            if data.len() == 8 {
                let rev = u64::from_le_bytes([
                    data[0], data[1], data[2], data[3],
                    data[4], data[5], data[6], data[7],
                ]);
                info!("Anti-rollback: Persisted rev counter = {}", rev);
                rev
            } else {
                warn!("Anti-rollback: Invalid counter size {} (expected 8)", data.len());
                0
            }
        }
        None => {
            info!("Anti-rollback: No counter found (first boot)");
            0
        }
    }
}

/// Write (ratchet) the firmware revision counter to TPM NV.
/// Only writes if the new value is greater than the current persisted value.
pub fn update_firmware_rev_counter(new_rev: u64) -> bool {
    if new_rev == 0 {
        return true; // Nothing to persist
    }

    let current = read_firmware_rev_counter();
    if new_rev <= current {
        info!("Anti-rollback: Rev {} <= current {}, no update needed", new_rev, current);
        return true;
    }

    info!("Anti-rollback: Ratcheting counter {} -> {}", current, new_rev);
    let bytes = new_rev.to_le_bytes();
    if tpm::tpm_nv_write(FDO_NV_INDEX_FWREV, &bytes) {
        info!("Anti-rollback: Counter updated successfully");
        true
    } else {
        warn!("Anti-rollback: Failed to write counter to TPM NV");
        false
    }
}

/// Check if a firmware revision passes the anti-rollback check.
/// The effective minimum is MAX(rv_min_rev, persisted_counter).
/// Returns true if the firmware revision is acceptable.
pub fn check_firmware_rev(firmware_rev: u64, rv_min_rev: Option<u64>) -> bool {
    let persisted = read_firmware_rev_counter();
    let rv_min = rv_min_rev.unwrap_or(0);
    let effective_min = core::cmp::max(persisted, rv_min);

    if effective_min == 0 {
        info!("Anti-rollback: No minimum revision set, accepting rev {}", firmware_rev);
        return true;
    }

    info!("Anti-rollback: Checking rev {} >= min {} (persisted={}, rv_min={})",
          firmware_rev, effective_min, persisted, rv_min);

    if firmware_rev < effective_min {
        warn!("Anti-rollback: REJECTED! Firmware rev {} < minimum {}", firmware_rev, effective_min);
        return false;
    }

    info!("Anti-rollback: PASSED (rev {} >= min {})", firmware_rev, effective_min);
    true
}
