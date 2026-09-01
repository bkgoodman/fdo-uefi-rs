// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// RV-Based Firmware Delivery Module
//
// Implements pre-onboarding firmware delivery per fdo-firmware-delivery-spec:
// 1. Read DCTPM from TPM NV to get RV server info + firmware extensions
// 2. Download signed firmware image (COSE_Sign1) via HTTP GET
// 3. Verify COSE_Sign1 signature against embedded platform key
// 4. Check anti-rollback (firmware revision counter)
// 5. Chainload the extracted EFI image
//
// In combined binary mode, if no update is available or the firmware is
// the same version, falls through to normal TO1/TO2 onboarding.

pub mod anti_rollback;
pub mod cose_verify;
pub mod platform_key;
pub mod rv_parse;

use alloc::vec::Vec;
use log::{info, warn, error};

use crate::tpm;
use crate::chainload;

/// Result of the firmware delivery check
pub enum DeliveryResult {
    /// A newer firmware image was found and chainloaded successfully.
    /// The chainloaded image has returned — caller should exit.
    Chainloaded,
    /// No firmware update available (server unreachable, same version, etc.)
    /// Caller should fall through to normal onboarding.
    NoUpdate,
    /// An error occurred during the process, but not fatal.
    /// Caller should fall through to normal onboarding.
    Error,
}

/// Check for and deliver firmware updates via RV-based delivery.
///
/// This is the main entry point for the rv-firmware feature.
/// Returns `DeliveryResult` indicating whether to continue to onboarding.
pub fn check_and_deliver() -> DeliveryResult {
    info!("===========================================");
    info!("  RV-Based Firmware Delivery");
    info!("===========================================");

    // Optional DI: If the `di` feature is enabled and no credentials exist,
    // run DI first to provision the TPM with DCTPM (including firmware RV tags).
    // This allows an OEM to ship a BIOS with rv-firmware + di and have the
    // device self-provision at the factory without needing a server to serve
    // a separate FDO Installer Image for DI.
    #[cfg(feature = "di")]
    {
        if tpm::tpm_nv_read(0x01D10001).is_none() {
            info!("No DCTPM in TPM — attempting Device Initialization...");
            match crate::di::run_di_protocol(None) {
                uefi::Status::SUCCESS => {
                    info!("DI completed — credentials now in TPM.");
                    info!("Continuing to firmware delivery check...");
                }
                uefi::Status::NOT_FOUND => {
                    info!("No DI server available — skipping firmware delivery.");
                    return DeliveryResult::NoUpdate;
                }
                status => {
                    warn!("DI failed ({:?}) — skipping firmware delivery.", status);
                    return DeliveryResult::NoUpdate;
                }
            }
        }
    }

    // Step 1: Read DCTPM from TPM NV
    info!("[1/5] Reading DCTPM from TPM...");
    let dctpm_data = match tpm::tpm_nv_read(0x01D10001) {
        Some(d) => {
            info!("  DCTPM: {} bytes", d.len());
            d
        }
        None => {
            info!("  No DCTPM found in TPM NV — skipping firmware delivery");
            return DeliveryResult::NoUpdate;
        }
    };

    // Step 2: Parse RV firmware info (extensions)
    info!("[2/5] Parsing RV firmware info...");
    let rv_info = match rv_parse::parse_rv_firmware_info(&dctpm_data) {
        Some(info) => {
            info!("  Firmware info parsed successfully");
            info
        }
        None => {
            info!("  No firmware delivery info in RV — skipping");
            return DeliveryResult::NoUpdate;
        }
    };

    let firmware_url = match rv_info.firmware_url() {
        Some(url) => {
            info!("  Firmware URL: {}", url);
            url
        }
        None => {
            warn!("  No firmware URL could be constructed from RV info");
            return DeliveryResult::NoUpdate;
        }
    };

    // Step 3: Download firmware image
    info!("[3/5] Downloading firmware image...");
    let signed_data = match crate::http_api::http_get(&firmware_url) {
        Some(data) => {
            info!("  Downloaded {} bytes", data.len());
            data
        }
        None => {
            warn!("  HTTP GET failed for firmware URL: {}", firmware_url);
            warn!("  Continuing to normal onboarding...");
            return DeliveryResult::Error;
        }
    };

    // Step 4: Verify COSE_Sign1 and extract firmware
    info!("[4/5] Verifying COSE_Sign1 signature...");
    let (payload, image_data) = match cose_verify::verify_firmware(&signed_data) {
        cose_verify::VerifyResult::Ok(payload, image) => {
            info!("  Signature VALID");
            info!("  Platform: {}", payload.platform_type);
            info!("  Architecture: {}", payload.architecture);
            info!("  Firmware revision: {}", payload.firmware_rev);
            info!("  EFI image size: {} bytes", image.len());
            (payload, image)
        }
        cose_verify::VerifyResult::SignatureInvalid => {
            error!("  COSE signature verification FAILED!");
            error!("  Firmware image is NOT trusted. Skipping.");
            return DeliveryResult::Error;
        }
        cose_verify::VerifyResult::UnsupportedAlgorithm(alg) => {
            error!("  Unsupported COSE algorithm: {}", alg);
            return DeliveryResult::Error;
        }
        cose_verify::VerifyResult::ArchitectureMismatch(arch) => {
            error!("  Architecture mismatch: {} (expected x86_64)", arch);
            return DeliveryResult::Error;
        }
        cose_verify::VerifyResult::ImageHashMismatch => {
            error!("  FWImageHash does not match the extracted EFI image!");
            error!("  Image is NOT trusted. Refusing to chainload.");
            return DeliveryResult::Error;
        }
        cose_verify::VerifyResult::UnsupportedHashAlgorithm(alg) => {
            error!("  Unsupported FWImageHash algorithm: {}", alg);
            error!("  Cannot verify image integrity. Refusing to chainload.");
            return DeliveryResult::Error;
        }
        cose_verify::VerifyResult::ParseError(msg) => {
            error!("  COSE parse error: {}", msg);
            return DeliveryResult::Error;
        }
    };

    // Step 4b: Anti-rollback check
    info!("  Anti-rollback check...");
    if !anti_rollback::check_firmware_rev(payload.firmware_rev, rv_info.min_firmware_rev) {
        error!("  Anti-rollback check FAILED! Firmware rejected.");
        return DeliveryResult::Error;
    }

    // Ratchet the counter after successful verification
    if payload.firmware_rev > 0 {
        if !anti_rollback::update_firmware_rev_counter(payload.firmware_rev) {
            warn!("  Warning: Could not persist firmware revision counter");
            // Continue anyway — signature was valid
        }
    }

    // Step 5: Chainload the extracted EFI image
    info!("[5/5] Chain-loading firmware image...");
    info!("========================================");
    info!("  Launching FDO Installer Image...");
    info!("========================================");

    match chainload::chainload_image(&image_data) {
        Ok(()) => {
            info!("========================================");
            info!("  FDO Installer returned successfully");
            info!("========================================");
            DeliveryResult::Chainloaded
        }
        Err(e) => {
            error!("========================================");
            error!("  Chain-load failed: {:?}", e);
            error!("========================================");
            DeliveryResult::Error
        }
    }
}
