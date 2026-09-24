// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// Library crate: contains all protocol logic. On UEFI targets this is no_std;
// on native targets (linux) it uses std, enabling `cargo test` without QEMU.

#![cfg_attr(target_os = "uefi", no_std)]

extern crate alloc;

// --- UEFI-only modules (transport, TPM hardware, chainloading) ---
#[cfg(target_os = "uefi")]
pub mod tpm;
#[cfg(target_os = "uefi")]
pub mod http_api;
#[cfg(all(target_os = "uefi", feature = "uefi-http"))]
pub mod http;
#[cfg(all(target_os = "uefi", feature = "tcp4-http"))]
pub mod tcp4_http;
#[cfg(target_os = "uefi")]
pub mod chainload;

// --- Pure + mixed modules (protocol logic, crypto, parsing) ---
// These compile on both UEFI and native targets.
#[cfg(any(feature = "fdo-installer", feature = "rv-firmware"))]
pub mod cose;
#[cfg(feature = "fdo-installer")]
pub mod voucher;
#[cfg(feature = "fdo-installer")]
pub mod delegate;
#[cfg(feature = "fdo-installer")]
pub mod fdo;
#[cfg(feature = "fdo-installer")]
pub mod bmo;
#[cfg(feature = "di")]
pub mod di;
#[cfg(all(target_os = "uefi", feature = "rv-firmware"))]
pub mod rv_firmware;

/// Global watchdog timeout, in seconds.
pub const WATCHDOG_TIMEOUT_SECS: usize = 1800;
