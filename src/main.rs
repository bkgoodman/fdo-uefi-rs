// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0

#![no_main]
#![no_std]

extern crate alloc;

use core::time::Duration;
use log::info;
use uefi::prelude::*;

mod tpm;
mod http;
mod fdo;
mod bmo;
mod chainload;

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    
    info!("===========================================");
    info!("  FDO UEFI Client - Test Suite");
    info!("===========================================");
    
    // Test TPM
    info!("");
    info!("--- TPM Test ---");
    tpm::test_tpm();
    
    // Test TPM ECDH key generation
    info!("");
    info!("--- TPM ECDH Test ---");
    if let Some(key_pair) = tpm::tpm_create_ecdh_key() {
        info!("TPM ECDH key created successfully!");
        info!("  Handle: 0x{:08x}", key_pair.handle);
        info!("  Public X ({} bytes): {:02x?}", key_pair.public_x.len(), &key_pair.public_x[..core::cmp::min(8, key_pair.public_x.len())]);
        info!("  Public Y ({} bytes): {:02x?}", key_pair.public_y.len(), &key_pair.public_y[..core::cmp::min(8, key_pair.public_y.len())]);
        // Clean up the key
        tpm::tpm_flush_context(key_pair.handle);
    } else {
        info!("TPM ECDH key creation failed (TPM may not be available)");
    }
    
    // Test HTTP (skipped - takes too long with DHCP)
    // info!("");
    // info!("--- HTTP Test ---");
    // http::test_http();
    
    // Test FDO message serialization
    info!("");
    info!("--- FDO Message Test ---");
    fdo::test_fdo_messages();
    
    // Read device credential from TPM NV
    info!("");
    info!("--- Reading FDO Credentials from TPM ---");
    let device_guid = match tpm::read_fdo_guid() {
        Some(guid) => {
            info!("Device GUID from TPM: {:02x?}", guid);
            guid
        }
        None => {
            // GUID from quick-di-tpm: d0ec2cf2038e96a0a501a0b8c3991e29
            info!("Failed to read GUID from TPM NV, using quick-di-tpm GUID");
            [0xd0, 0xec, 0x2c, 0xf2, 0x03, 0x8e, 0x96, 0xa0,
             0xa5, 0x01, 0xa0, 0xb8, 0xc3, 0x99, 0x1e, 0x29]
        }
    };
    
    let owner_url = tpm::read_fdo_rv_info().unwrap_or_else(|| alloc::string::String::from("http://10.0.2.2:8080"));
    info!("Owner URL: {}", owner_url);
    
    // Test TO1 protocol against go-fdo server
    info!("");
    info!("--- TO1 Protocol Test ---");
    fdo::test_to1_protocol(&owner_url, &device_guid);
    
    // Test BMO state machine with mock data
    info!("");
    info!("--- BMO Mock Test ---");
    bmo::test_bmo_handling();
    
    // Test TO2 protocol against go-fdo server
    info!("");
    info!("--- TO2 Protocol Test ---");
    fdo::test_to2_protocol(&owner_url, &device_guid);
    
    info!("");
    info!("Tests complete. Waiting 5 seconds...");
    boot::stall(Duration::from_secs(5));
    
    Status::SUCCESS
}
