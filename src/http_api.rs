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

#[cfg(feature = "tcp4-http")]
use core::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

/// Whether DHCP succeeded — used by tcp4_http to decide address mode
#[cfg(feature = "tcp4-http")]
static DHCP_SUCCEEDED: AtomicBool = AtomicBool::new(false);

/// Returns true if DHCP completed successfully (IP4 stack has a valid address)
#[cfg(feature = "tcp4-http")]
pub fn dhcp_succeeded() -> bool {
    DHCP_SUCCEEDED.load(AtomicOrdering::Relaxed)
}

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
    // Use TCP4 directly for POST — UEFI HTTP protocol cannot reliably
    // receive large responses (OVMF body drain fails with TIMEOUT for
    // payloads > ~2KB), and mid-session fallback corrupts server state.
    #[cfg(feature = "tcp4-http")]
    {
        ensure_network_configured();
        log::debug!("Using TCP4 HTTP transport for POST");
        return crate::tcp4_http::tcp4_http_post(url, body, msg_type, auth_token);
    }

    // Fall back to UEFI HTTP only when TCP4 is not compiled in
    #[cfg(not(feature = "tcp4-http"))]
    {
        #[cfg(feature = "uefi-http")]
        {
            let result = crate::http::http_post_with_session(url, body, msg_type, auth_token);
            if result.is_some() {
                return result;
            }
        }
        log::error!("No HTTP transport available for POST");
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

    // Try DHCP via IP4Config2, but only on NICs with link (media_present).
    // The OnLogic k800 has 6 NICs but only one has a cable. Running DHCP on
    // a NIC with no link wastes 30 seconds per NIC.
    if let Ok(ip4_handles) = boot::locate_handle_buffer(boot::SearchType::ByProtocol(
        &Ip4Config2::GUID
    )) {
        log::debug!("TCP4: Found {} IP4Config2 handle(s), checking link state...", ip4_handles.len());

        // Build list of SNP handles with media_present for link detection
        use uefi::proto::network::snp::SimpleNetwork;
        let snp_link_macs = {
            let mut macs_with_link: alloc::vec::Vec<[u8; 6]> = alloc::vec::Vec::new();
            if let Ok(snp_handles) = boot::locate_handle_buffer(boot::SearchType::ByProtocol(
                &SimpleNetwork::GUID
            )) {
                for &sh in snp_handles.iter() {
                    let snp_result = unsafe {
                        boot::open_protocol::<SimpleNetwork>(
                            boot::OpenProtocolParams {
                                handle: sh,
                                agent: boot::image_handle(),
                                controller: None,
                            },
                            boot::OpenProtocolAttributes::GetProtocol,
                        )
                    };
                    if let Ok(snp) = snp_result {
                        let mode = snp.mode();
                        let mac = &mode.current_address.0[..6];
                        let has_link = mode.media_present_supported.into()
                            && bool::from(mode.media_present);
                        let mac6: [u8; 6] = [mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]];
                        log::debug!("TCP4: SNP {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} media_present={}",
                            mac6[0], mac6[1], mac6[2], mac6[3], mac6[4], mac6[5], has_link);
                        if has_link {
                            macs_with_link.push(mac6);
                        }
                    }
                }
            }
            macs_with_link
        };

        for (idx, &h) in ip4_handles.iter().enumerate() {
            if let Ok(mut ip4cfg) = Ip4Config2::new(h) {
                if let Ok(info) = ip4cfg.get_interface_info() {
                    let hw = info.hw_addr.0;
                    let mac6: [u8; 6] = [hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]];

                    // Check if this NIC has link by matching MAC to SNP results
                    let has_link = snp_link_macs.iter().any(|m| *m == mac6);
                    log::debug!("TCP4: IP4Config2 #{}: MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} link={}",
                        idx, mac6[0], mac6[1], mac6[2], mac6[3], mac6[4], mac6[5], has_link);

                    if !has_link {
                        log::debug!("TCP4: IP4Config2 #{}: skipping DHCP (no link)", idx);
                        continue;
                    }

                    // This NIC has link — try DHCP
                    log::debug!("TCP4: IP4Config2 #{}: attempting DHCP (link detected)...", idx);
                    match ip4cfg.ifup() {
                        Ok(()) => {
                            log::debug!("TCP4: DHCP succeeded on handle #{}", idx);
                            if let Ok(info2) = ip4cfg.get_interface_info() {
                                log::debug!("TCP4: DHCP IP={}, Mask={}", info2.station_addr, info2.subnet_mask);
                            }
                            DHCP_SUCCEEDED.store(true, AtomicOrdering::Relaxed);
                            break;
                        }
                        Err(e) => {
                            log::warn!("TCP4: DHCP failed on handle #{}: {:?}", idx, e);
                        }
                    }
                }
            }
        }
        if !DHCP_SUCCEEDED.load(AtomicOrdering::Relaxed) {
            log::warn!("TCP4: DHCP not available, will use static IP fallback");
        }
    }

    TCP4_NET_INIT.store(true, Ordering::Relaxed);
}

/// Perform HTTP POST request (no session token).
pub fn http_post(url: &str, body: &[u8], msg_type: u8) -> Option<Vec<u8>> {
    http_post_with_session(url, body, msg_type, None).map(|r| r.body)
}

/// Perform HTTP GET request, returning the response body.
/// Dispatches to the appropriate transport backend (EFI_HTTP or TCP4).
/// Used by rv-firmware to download firmware images and by BMO URL delivery
/// mode to download boot images.
#[cfg(any(feature = "rv-firmware", feature = "fdo-installer"))]
pub fn http_get(url: &str) -> Option<alloc::vec::Vec<u8>> {
    // Try UEFI HTTP protocol first (if compiled in)
    #[cfg(feature = "uefi-http")]
    {
        let result = crate::http::http_get(url);
        if result.is_some() {
            return result;
        }
    }

    // Fall back to TCP4-based HTTP (if compiled in)
    #[cfg(feature = "tcp4-http")]
    {
        ensure_network_configured();
        log::debug!("Using TCP4 HTTP transport for GET");
        return crate::tcp4_http::tcp4_http_get(url);
    }

    #[cfg(not(feature = "tcp4-http"))]
    {
        log::error!("No HTTP transport available for GET");
        return None;
    }
}
