// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// Anti-Rollback Protection for RV-Based Firmware Delivery
//
// Maintains the monotonic minimum firmware revision in DCTPM.DCMinFirmwareRev.
// The effective minimum revision is MAX(RVMinFirmwareRev, DCMinFirmwareRev).
// After successful signature verification, the counter is ratcheted up.

use log::{info, warn};
use crate::{dctpm, tpm, tpm_policy};

// The ratchet lives in DCTPM.DCMinFirmwareRev (TPM spec, DCTPM item 10).
// Earlier builds used a separate NV index 0x01D10002, which the TPM spec
// assigns to DCOV; that index is no longer read or written.

/// Read DCMinFirmwareRev from DCTPM. Returns 0 if DCTPM is missing, has no
/// such item (older ten-item DCTPM), or cannot be parsed.
pub fn read_firmware_rev_counter() -> u64 {
    match tpm::tpm_nv_read(tpm_policy::DCTPM_NV_INDEX) {
        Some(data) => match dctpm::min_firmware_rev(&data) {
            Some(rev) => {
                info!("Anti-rollback: DCMinFirmwareRev = {}", rev);
                rev
            }
            None => {
                warn!("Anti-rollback: DCTPM not parseable; treating minimum as 0");
                0
            }
        },
        None => {
            info!("Anti-rollback: No DCTPM (minimum 0)");
            0
        }
    }
}

/// Raise (ratchet) DCMinFirmwareRev in DCTPM. Never lowers it. Writes DCTPM in
/// place with one NV_Write when the updated structure fits the index;
/// otherwise (an old exact-size index) redefines it at the spec size.
pub fn update_firmware_rev_counter(new_rev: u64) -> bool {
    if new_rev == 0 {
        return true; // Nothing to persist
    }
    let data = match tpm::tpm_nv_read(tpm_policy::DCTPM_NV_INDEX) {
        Some(d) => d,
        None => {
            warn!("Anti-rollback: No DCTPM; cannot persist minimum revision");
            return false;
        }
    };
    let current = dctpm::min_firmware_rev(&data).unwrap_or(0);
    if new_rev <= current {
        info!("Anti-rollback: Rev {} <= current {}, no update needed", new_rev, current);
        return true;
    }
    let updated = match dctpm::with_min_firmware_rev(&data, new_rev) {
        Some(u) => u,
        None => {
            warn!("Anti-rollback: DCTPM not parseable; not updating");
            return false;
        }
    };
    info!("Anti-rollback: Ratcheting DCMinFirmwareRev {} -> {}", current, new_rev);
    let ok = if updated.len() <= data.len() {
        let mut padded = updated;
        padded.resize(data.len(), 0);
        tpm::tpm_nv_write_in_place(tpm_policy::DCTPM_NV_INDEX, &padded)
    } else {
        warn!("Anti-rollback: DCTPM index too small ({} < {}); redefining (not atomic)", data.len(), updated.len());
        tpm::tpm_nv_write(tpm_policy::DCTPM_NV_INDEX, &tpm_policy::dctpm_padded(&updated), tpm_policy::DCTPM_NV_ATTRIBUTES)
    };
    if ok {
        info!("Anti-rollback: DCMinFirmwareRev updated");
    } else {
        warn!("Anti-rollback: Failed to write DCTPM");
    }
    ok
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
