// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0

#![no_main]
#![no_std]

extern crate alloc;

use core::time::Duration;
use log::{info, error};
use uefi::prelude::*;
use uefi::boot;

mod tpm;
mod http_api;
#[cfg(feature = "uefi-http")]
mod http;
#[cfg(feature = "tcp4-http")]
mod tcp4_http;
mod fdo;
mod bmo;
mod chainload;
mod di;

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    
    info!("===========================================");
    info!("  FDO UEFI Client");
    info!("===========================================");
    
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
    
    // Check if device credentials exist in TPM
    info!("Checking for FDO credentials in TPM...");
    
    match tpm::read_fdo_guid() {
        Some(guid) => {
            // Credentials exist - run TO1/TO2 onboarding
            info!("Device GUID found: {:02x?}", guid);
            run_onboarding(&guid);
        }
        None => {
            // No credentials - attempt Device Initialization
            info!("No credentials found in TPM.");
            info!("Attempting Device Initialization (DI)...");
            
            match di::run_di_protocol() {
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
    }
    
    info!("");
    info!("FDO UEFI Client exiting.");
    boot::stall(Duration::from_secs(2));
    
    Status::SUCCESS
}

/// Run TO1/TO2 onboarding protocols
fn run_onboarding(device_guid: &[u8; 16]) {
    let owner_url = tpm::read_fdo_rv_info()
        .unwrap_or_else(|| alloc::string::String::from("http://192.168.200.30:8080"));
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
