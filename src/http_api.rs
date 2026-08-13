// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0

//! Unified HTTP API that dispatches to the appropriate transport backend.
//!
//! Build with feature flags to select transport:
//!   - `uefi-http`: Use EFI_HTTP_PROTOCOL (OVMF/QEMU, some server firmware)
//!   - `tcp4-http`: Use TCP4-based HTTP (most real hardware)
//!   - Both (default): Runtime auto-detect — try HTTP protocol first, fall back to TCP4

use alloc::string::String;
use alloc::vec::Vec;

/// HTTP POST response containing body, auth token, and message type
pub struct HttpPostResponse {
    pub body: Vec<u8>,
    pub auth_token: Option<String>,
    pub message_type: Option<u8>,
}

/// Perform HTTP POST request with session token support.
/// Dispatches to the appropriate transport backend based on compile-time features
/// and runtime protocol availability.
pub fn http_post_with_session(url: &str, body: &[u8], msg_type: u8, auth_token: Option<&str>) -> Option<HttpPostResponse> {
    // Try UEFI HTTP protocol first (if compiled in)
    #[cfg(feature = "uefi-http")]
    {
        let result = crate::http::http_post_with_session(url, body, msg_type, auth_token);
        if result.is_some() {
            return result;
        }
        // HTTP protocol not available on this firmware — fall through to TCP4 if available
    }

    // Fall back to TCP4-based HTTP (if compiled in)
    #[cfg(feature = "tcp4-http")]
    {
        // Ensure network is configured (DHCP) before TCP4 can connect.
        // When uefi-http ran first, it initialized SNP but may not have run DHCP
        // (DHCP only runs after finding an HTTP NIC handle, which didn't exist).
        ensure_network_configured();

        log::info!("Using TCP4 HTTP transport");
        return crate::tcp4_http::tcp4_http_post(url, body, msg_type, auth_token);
    }

    // If we get here, UEFI HTTP was tried but failed, and TCP4 is not compiled in
    #[cfg(not(feature = "tcp4-http"))]
    {
        log::error!("UEFI HTTP protocol not available and tcp4-http feature not enabled");
        return None;
    }
}

/// Ensure network is configured (SNP started + DHCP) before TCP4 can connect.
/// This handles both the case where uefi-http already initialized SNP (but skipped
/// DHCP because HTTP protocol wasn't found) and the tcp4-only case.
#[cfg(feature = "tcp4-http")]
fn ensure_network_configured() {
    use core::sync::atomic::{AtomicBool, Ordering};
    use uefi::boot;
    use uefi::Identify;
    use uefi::proto::network::ip4config2::Ip4Config2;

    static TCP4_NET_INIT: AtomicBool = AtomicBool::new(false);
    if TCP4_NET_INIT.load(Ordering::Relaxed) {
        return;
    }

    // When uefi-http is not compiled in, we also need to start SNP
    #[cfg(not(feature = "uefi-http"))]
    {
        use uefi::proto::network::snp::SimpleNetwork;
        if let Ok(snp_handles) = boot::locate_handle_buffer(boot::SearchType::ByProtocol(
            &SimpleNetwork::GUID
        )) {
            for handle in snp_handles.iter() {
                if let Ok(snp) = boot::open_protocol_exclusive::<SimpleNetwork>(*handle) {
                    let _ = snp.start();
                    let _ = snp.initialize(0, 0);
                    let empty_list: &[Option<uefi::Handle>] = &[];
                    let _ = boot::connect_controller(*handle, empty_list, None, true);
                    break;
                }
            }
        }
    }

    // Run DHCP via IP4Config2
    if let Ok(ip4_handles) = boot::locate_handle_buffer(boot::SearchType::ByProtocol(
        &Ip4Config2::GUID
    )) {
        if let Some(&h) = ip4_handles.first() {
            if let Ok(mut ip4cfg) = Ip4Config2::new(h) {
                match ip4cfg.ifup() {
                    Ok(()) => {
                        log::info!("TCP4: Network configured via DHCP");
                        if let Ok(info) = ip4cfg.get_interface_info() {
                            log::info!("TCP4: IP Address: {}", info.station_addr);
                        }
                    }
                    Err(e) => log::warn!("TCP4: DHCP failed: {:?}", e),
                }
            }
        }
    }

    TCP4_NET_INIT.store(true, Ordering::Relaxed);
}

/// Perform HTTP POST request (no session token).
pub fn http_post(url: &str, body: &[u8], msg_type: u8) -> Option<Vec<u8>> {
    http_post_with_session(url, body, msg_type, None).map(|r| r.body)
}
