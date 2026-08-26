// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0

#![no_main]
#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;
use log::{info, error, warn};
use uefi::prelude::*;
use uefi::boot;
use uefi::proto::loaded_image::LoadedImage;

mod tpm;
mod http_api;
#[cfg(feature = "uefi-http")]
mod http;
#[cfg(feature = "tcp4-http")]
mod tcp4_http;
#[cfg(feature = "fdo-installer")]
mod fdo;
#[cfg(feature = "fdo-installer")]
mod bmo;
mod chainload;
#[cfg(feature = "di")]
mod di;
#[cfg(feature = "rv-firmware")]
mod rv_firmware;

/// Parsed command-line options
struct FdoOptions {
    /// Override DI (manufacturing) server URL
    di_url: Option<String>,
    /// Override RV/Owner server URL (for TO1/TO2)
    rv_url: Option<String>,
}

/// Well-known FDO manufacturing server DNS names (per fdo-appnote-device-mfg-info.bs)
/// Devices try these in order when no explicit DI server URL is provided.
const WELL_KNOWN_DI_NAMES: &[&str] = &[
    "_fdo._tcp",        // DNS-SD service discovery
    "fdo-mfg",          // Simple well-known hostname
];

/// Default DI server port
const DEFAULT_DI_PORT: u16 = 8080;

/// Parse command-line arguments from EFI shell load options.
/// Supports:  -di <url>   Override DI server URL
///            -rv <url>   Override RV/Owner server URL
///            -h          Show usage help
fn parse_args() -> FdoOptions {
    let mut opts = FdoOptions { di_url: None, rv_url: None };

    let loaded_image = match boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle()) {
        Ok(li) => li,
        Err(_) => return opts,
    };

    let args_str = match loaded_image.load_options_as_cstr16() {
        Ok(s) => {
            // Convert UCS-2 to ASCII string
            let mut buf = Vec::new();
            for c in s.iter() {
                let ch = u16::from(*c) as u8;
                if ch == 0 { break; }
                buf.push(ch);
            }
            match core::str::from_utf8(&buf) {
                Ok(s) => String::from(s),
                Err(_) => return opts,
            }
        }
        Err(_) => return opts,
    };

    if args_str.is_empty() {
        return opts;
    }
    info!("Command line: {}", args_str);

    // Split on whitespace and parse flags
    // Note: first token is typically the EFI app path itself, skip it
    let tokens: Vec<&str> = args_str.split_ascii_whitespace().collect();
    let mut i = 1; // skip argv[0] (the EFI binary path)
    while i < tokens.len() {
        match tokens[i] {
            "-di" => {
                if i + 1 < tokens.len() {
                    opts.di_url = Some(String::from(tokens[i + 1]));
                    info!("CLI: DI server URL = {}", tokens[i + 1]);
                    i += 2;
                } else {
                    warn!("CLI: -di requires a URL argument");
                    i += 1;
                }
            }
            "-rv" => {
                if i + 1 < tokens.len() {
                    opts.rv_url = Some(String::from(tokens[i + 1]));
                    info!("CLI: RV/Owner URL = {}", tokens[i + 1]);
                    i += 2;
                } else {
                    warn!("CLI: -rv requires a URL argument");
                    i += 1;
                }
            }
            "-h" | "--help" | "-help" | "/?" => {
                info!("");
                info!("Usage: fdo-uefi.efi [options]");
                info!("  -di <url>   DI (manufacturing) server URL");
                info!("              e.g. -di http://192.168.1.100:8080");
                info!("  -rv <url>   RV/Owner server URL (TO1/TO2 override)");
                info!("              e.g. -rv http://fdo-server.local:8080");
                info!("  -h          Show this help");
                info!("");
                info!("If no -di URL is given, the client tries well-known DNS names:");
                for name in WELL_KNOWN_DI_NAMES {
                    info!("  http://{}:{}", name, DEFAULT_DI_PORT);
                }
                info!("");
                info!("If no -rv URL is given, the RV URL is read from the FDO");
                info!("device credential stored in the TPM (written during DI).");
                i += 1;
            }
            _ => {
                info!("CLI: ignoring unknown argument: {}", tokens[i]);
                i += 1;
            }
        }
    }

    opts
}

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    
    info!("===========================================");
    info!("  FDO UEFI Client");
    info!("===========================================");
    
    // Parse command-line arguments
    let opts = parse_args();
    
    // Check for TPM presence first
    if !tpm::tpm_is_present() {
        error!("No TPM found! TCG2 protocol not available in this UEFI environment.");
        error!("Please enable TPM in BIOS (e.g. Intel PTT under System Security).");
        info!("");
        info!("FDO UEFI Client exiting.");
        boot::stall(Duration::from_secs(5));
        return Status::DEVICE_ERROR;
    }
    info!("TPM detected (TCG2 protocol available).");
    
    // RV-based firmware delivery check (if feature enabled)
    // In combined binary mode, check for firmware updates first.
    // If a newer image is available, chainload it.
    // If no update (same version or server unreachable), fall through to normal onboarding.
    #[cfg(feature = "rv-firmware")]
    {
        info!("Checking for RV-based firmware update...");
        match rv_firmware::check_and_deliver() {
            rv_firmware::DeliveryResult::Chainloaded => {
                info!("Firmware image was chainloaded and returned.");
                info!("FDO UEFI Client exiting.");
                boot::stall(Duration::from_secs(2));
                return Status::SUCCESS;
            }
            rv_firmware::DeliveryResult::NoUpdate => {
                info!("No firmware update available, continuing to onboarding...");
            }
            rv_firmware::DeliveryResult::Error => {
                info!("Firmware delivery error, continuing to onboarding...");
            }
        }
    }

    // Check if device credentials exist in TPM
    #[cfg(any(feature = "di", feature = "fdo-installer"))]
    {
        info!("Checking for FDO credentials in TPM...");
        
        match tpm::read_fdo_guid() {
            Some(guid) => {
                // Credentials exist - run TO1/TO2 onboarding
                info!("Device GUID found: {:02x?}", guid);
                #[cfg(feature = "fdo-installer")]
                run_onboarding(&guid, &opts);
                #[cfg(not(feature = "fdo-installer"))]
                {
                    let _ = guid;
                    info!("FDO Installer not compiled in — nothing to do.");
                }
            }
            None => {
                // No credentials - attempt Device Initialization
                #[cfg(feature = "di")]
                {
                    info!("No credentials found in TPM.");
                    info!("Attempting Device Initialization (DI)...");
                    
                    match di::run_di_protocol(opts.di_url.as_deref()) {
                        Status::SUCCESS => {
                            info!("Device Initialization completed successfully.");
                            info!("Reboot required to proceed with onboarding.");
                        }
                        Status::NOT_FOUND => {
                            info!("No manufacturing server available. Exiting.");
                        }
                        status => {
                            info!("Device Initialization failed: {:?}", status);
                        }
                    }
                }
                #[cfg(not(feature = "di"))]
                {
                    info!("No credentials found in TPM.");
                    info!("DI not compiled in — cannot provision. Exiting.");
                }
            }
        }
    }
    
    info!("");
    info!("FDO UEFI Client exiting.");
    boot::stall(Duration::from_secs(2));
    
    Status::SUCCESS
}

#[cfg(feature = "fdo-installer")]
/// Run TO1/TO2 onboarding protocols
fn run_onboarding(device_guid: &[u8; 16], opts: &FdoOptions) {
    // RV URL priority: 1) CLI -rv flag, 2) parsed from TPM credential, 3) error
    let owner_url = if let Some(ref url) = opts.rv_url {
        info!("Using CLI-provided RV/Owner URL");
        url.clone()
    } else {
        match tpm::read_fdo_rv_info() {
            Some(url) => {
                info!("Using RV URL from device credential");
                url
            }
            None => {
                error!("No RV/Owner URL available!");
                error!("  Provide one with: fdo-uefi.efi -rv http://server:port");
                error!("  Or ensure DI stored valid rendezvous info in TPM.");
                return;
            }
        }
    };
    info!("Owner/RV URL: {}", owner_url);
    
    // Run TO1 protocol
    info!("");
    info!("--- TO1 Protocol ---");
    fdo::test_to1_protocol(&owner_url, device_guid);
    
    // Run TO2 protocol
    info!("");
    info!("--- TO2 Protocol ---");
    fdo::test_to2_protocol(&owner_url, device_guid);
}
