// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0

//! TCP4-based HTTP client for UEFI environments that lack EFI_HTTP_PROTOCOL.
//!
//! Most real-world UEFI firmware does not include the HTTP DXE driver (HttpDxe),
//! but does include the TCP4 stack (TcpDxe). This module implements HTTP/1.1
//! POST requests over raw TCP4, providing a fallback when EFI_HTTP_PROTOCOL
//! is unavailable.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;
use log::{info, warn, error, debug};
use uefi::boot;
use uefi_raw::protocol::network::tcp4::{
    Tcp4Protocol, Tcp4ConfigData, Tcp4AccessPoint, Tcp4Option,
    Tcp4CompletionToken, Tcp4ConnectionToken, Tcp4IoToken,
    Tcp4CloseToken, Tcp4Packet, Tcp4TransmitData, Tcp4FragmentData,
    Tcp4ReceiveData,
};
use uefi_raw::{Boolean, Ipv4Address, Status as RawStatus, Event};

use crate::http_api::HttpPostResponse;

use core::sync::atomic::{AtomicI8, Ordering};

/// Static IP fallback for when DHCP fails
/// OnLogic k800: 192.168.200.26/24
const STATIC_IP: [u8; 4] = [192, 168, 200, 26];
const STATIC_SUBNET: [u8; 4] = [255, 255, 255, 0];

/// Cache of last working ServiceBinding handle index (-1 = none cached)
static LAST_WORKING_NIC: AtomicI8 = AtomicI8::new(-1);

/// EFI_SERVICE_BINDING_PROTOCOL function signatures
#[repr(C)]
struct ServiceBindingProtocol {
    create_child: unsafe extern "efiapi" fn(
        this: *mut Self,
        child_handle: *mut uefi_raw::Handle,
    ) -> RawStatus,
    destroy_child: unsafe extern "efiapi" fn(
        this: *mut Self,
        child_handle: uefi_raw::Handle,
    ) -> RawStatus,
}

/// Parse URL into (host, port, path) components
fn parse_url(url: &str) -> Option<([u8; 4], u16, &str)> {
    // Strip scheme
    let rest = url.strip_prefix("http://")?;
    
    // Split host:port from path
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    
    // Split host from port
    let (host_str, port) = match hostport.rfind(':') {
        Some(i) => (&hostport[..i], hostport[i+1..].parse::<u16>().ok()?),
        None => (hostport, 80),
    };
    
    // Parse IPv4 address
    let parts: Vec<&str> = host_str.split('.').collect();
    if parts.len() != 4 { return None; }
    let ip = [
        parts[0].parse::<u8>().ok()?,
        parts[1].parse::<u8>().ok()?,
        parts[2].parse::<u8>().ok()?,
        parts[3].parse::<u8>().ok()?,
    ];
    
    Some((ip, port, path))
}

/// Find all TCP4 Service Binding handles
fn find_tcp4_service_bindings() -> Vec<uefi::Handle> {
    let tcp4_sb_guid = uefi::guid!("00720665-67eb-4a99-baf7-d3c33a1c7cc9");
    match boot::locate_handle_buffer(boot::SearchType::ByProtocol(&tcp4_sb_guid)) {
        Ok(handles) => {
            debug!("TCP4: Found {} ServiceBinding handle(s)", handles.len());
            handles.to_vec()
        }
        Err(_) => {
            warn!("TCP4: No ServiceBinding handles found");
            Vec::new()
        }
    }
}

/// Create a TCP4 child instance via Service Binding
unsafe fn create_tcp4_child(sb_handle: uefi::Handle) -> Option<uefi_raw::Handle> {
    let mut sb_ptr: *mut c_void = core::ptr::null_mut();
    let st = uefi::table::system_table_raw().expect("no system table");
    let bs = (*st.as_ptr()).boot_services;
    
    let tcp4_sb_guid = uefi::guid!("00720665-67eb-4a99-baf7-d3c33a1c7cc9");
    let status = ((*bs).open_protocol)(
        sb_handle.as_ptr(),
        &tcp4_sb_guid,
        &mut sb_ptr,
        boot::image_handle().as_ptr(),
        core::ptr::null_mut(),
        0x02, // EFI_OPEN_PROTOCOL_GET_PROTOCOL
    );
    if status != uefi::Status::SUCCESS {
        error!("TCP4: Failed to open ServiceBinding: {:?}", status);
        return None;
    }
    
    let sb = sb_ptr.cast::<ServiceBindingProtocol>();
    let mut child_handle: uefi_raw::Handle = core::ptr::null_mut();
    let status = ((*sb).create_child)(sb, &mut child_handle);
    if status != RawStatus::SUCCESS {
        error!("TCP4: CreateChild failed: {:?}", status);
        return None;
    }
    
    debug!("TCP4: Created child handle: {:p}", child_handle);
    Some(child_handle)
}

/// Open TCP4 protocol on a child handle
unsafe fn open_tcp4(child_handle: uefi_raw::Handle) -> Option<*mut Tcp4Protocol> {
    let mut proto_ptr: *mut c_void = core::ptr::null_mut();
    let st = uefi::table::system_table_raw().expect("no system table");
    let bs = (*st.as_ptr()).boot_services;
    
    let status = ((*bs).open_protocol)(
        child_handle,
        &Tcp4Protocol::GUID,
        &mut proto_ptr,
        boot::image_handle().as_ptr(),
        core::ptr::null_mut(),
        0x20, // EFI_OPEN_PROTOCOL_EXCLUSIVE
    );
    if status != uefi::Status::SUCCESS {
        error!("TCP4: Failed to open protocol: {:?}", status);
        return None;
    }
    
    Some(proto_ptr.cast())
}

/// Destroy a TCP4 child instance
unsafe fn destroy_tcp4_child(sb_handle: uefi::Handle, child_handle: uefi_raw::Handle) {
    let mut sb_ptr: *mut c_void = core::ptr::null_mut();
    let st = uefi::table::system_table_raw().expect("no system table");
    let bs = (*st.as_ptr()).boot_services;
    
    let tcp4_sb_guid = uefi::guid!("00720665-67eb-4a99-baf7-d3c33a1c7cc9");
    let status = ((*bs).open_protocol)(
        sb_handle.as_ptr(),
        &tcp4_sb_guid,
        &mut sb_ptr,
        boot::image_handle().as_ptr(),
        core::ptr::null_mut(),
        0x02,
    );
    if status == uefi::Status::SUCCESS {
        let sb = sb_ptr.cast::<ServiceBindingProtocol>();
        let _ = ((*sb).destroy_child)(sb, child_handle);
    }
}

/// Create a UEFI event for async operations
unsafe fn create_event() -> Option<Event> {
    use uefi_raw::table::boot::{EventType, Tpl};
    
    let st = uefi::table::system_table_raw().expect("no system table");
    let bs = (*st.as_ptr()).boot_services;
    let mut event: Event = core::ptr::null_mut();
    
    // Create a basic event with no notification — we'll poll/check manually
    let status = ((*bs).create_event)(
        EventType::empty(), // No flags — basic event
        Tpl::APPLICATION,
        None, // no notify function
        core::ptr::null_mut(),
        &mut event,
    );
    if status != uefi::Status::SUCCESS {
        error!("TCP4: CreateEvent failed: {:?}", status);
        return None;
    }
    Some(event)
}

/// Close/free a UEFI event
unsafe fn close_event(event: Event) {
    let st = uefi::table::system_table_raw().expect("no system table");
    let bs = (*st.as_ptr()).boot_services;
    let _ = ((*bs).close_event)(event);
}

/// Check if an event has been signaled
unsafe fn check_event(event: Event) -> bool {
    let st = uefi::table::system_table_raw().expect("no system table");
    let bs = (*st.as_ptr()).boot_services;
    let status = ((*bs).check_event)(event);
    status == uefi::Status::SUCCESS
}

/// Check if a ServiceBinding handle has a non-zero MAC address.
/// Returns true if the NIC has a real MAC, false if zeroed or unreadable.
/// Uses GET_PROTOCOL (non-exclusive) to avoid locking out the ServiceBinding.
fn has_nonzero_mac(handle: uefi::Handle) -> bool {
    use uefi::proto::network::snp::SimpleNetwork;
    use uefi::Identify;
    
    unsafe {
        let st = uefi::table::system_table_raw().expect("no system table");
        let bs = (*st.as_ptr()).boot_services;
        let mut snp_ptr: *mut c_void = core::ptr::null_mut();
        
        let status = ((*bs).open_protocol)(
            handle.as_ptr(),
            &SimpleNetwork::GUID,
            &mut snp_ptr,
            boot::image_handle().as_ptr(),
            core::ptr::null_mut(),
            0x02, // EFI_OPEN_PROTOCOL_GET_PROTOCOL (non-exclusive)
        );
        if status != uefi::Status::SUCCESS {
            // Can't read SNP on this handle — don't skip, might still work
            return true;
        }
        
        let snp = snp_ptr.cast::<uefi_raw::protocol::network::snp::SimpleNetworkProtocol>();
        let mode = (*snp).mode;
        if mode.is_null() {
            return true;
        }
        let mac = (*mode).current_address.0;
        let all_zero = mac.iter().all(|&b| b == 0);
        if all_zero {
            debug!("TCP4: Handle({:?}) has zeroed MAC, skipping", handle);
            return false;
        }
        debug!("TCP4: Handle({:?}) MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            handle, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        true
    }
}

/// Try to connect a TCP4 child on a specific ServiceBinding handle.
/// Returns (tcp4_protocol, child_handle, sb_handle) on success.
unsafe fn try_connect_on_handle(
    sb_handle: uefi::Handle,
    handle_idx: usize,
    ip: [u8; 4],
    port: u16,
) -> Option<(*mut Tcp4Protocol, uefi_raw::Handle, uefi::Handle)> {
    debug!("TCP4: Trying ServiceBinding handle #{} ({:?})", handle_idx, sb_handle);
    
    let child_handle = create_tcp4_child(sb_handle)?;
    let tcp4 = match open_tcp4(child_handle) {
        Some(p) => p,
        None => {
            destroy_tcp4_child(sb_handle, child_handle);
            return None;
        }
    };
    
    let mut tcp_option = Tcp4Option {
        receive_buffer_size: 65536,
        send_buffer_size: 65536,
        max_syn_back_log: 0,
        connection_timeout: 5,
        data_retries: 2,
        fin_timeout: 2,
        time_wait_timeout: 2,
        keep_alive_probes: 0,
        keep_alive_time: 0,
        keep_alive_interval: 0,
        enable_nagle: Boolean::FALSE,
        enable_time_stamp: Boolean::FALSE,
        enable_window_scaling: Boolean::FALSE,
        enable_selective_ack: Boolean::FALSE,
        enable_path_mtu_discovery: Boolean::FALSE,
    };
    
    // Use DHCP-assigned address if available, otherwise fall back to static IP
    let use_dhcp = crate::http_api::dhcp_succeeded();
    let config = Tcp4ConfigData {
        type_of_service: 0,
        time_to_live: 64,
        access_point: Tcp4AccessPoint {
            use_default_address: if use_dhcp { Boolean::TRUE } else { Boolean::FALSE },
            station_address: if use_dhcp { Ipv4Address([0, 0, 0, 0]) } else { Ipv4Address(STATIC_IP) },
            subnet_mask: if use_dhcp { Ipv4Address([0, 0, 0, 0]) } else { Ipv4Address(STATIC_SUBNET) },
            station_port: 0,
            remote_address: Ipv4Address(ip),
            remote_port: port,
            active_flag: Boolean::TRUE,
        },
        control_option: &mut tcp_option,
    };
    if use_dhcp {
        debug!("TCP4: Handle #{}: Using DHCP address (use_default_address=TRUE)", handle_idx);
    } else {
        debug!("TCP4: Handle #{}: Using static IP {}.{}.{}.{} (DHCP not available)",
            handle_idx, STATIC_IP[0], STATIC_IP[1], STATIC_IP[2], STATIC_IP[3]);
    }
    
    let status = ((*tcp4).configure)(tcp4, &config);
    if status != RawStatus::SUCCESS {
        warn!("TCP4: Handle #{}: Configure failed: {:?}", handle_idx, status);
        destroy_tcp4_child(sb_handle, child_handle);
        return None;
    }
    debug!("TCP4: Handle #{}: Configured", handle_idx);
    
    // Connect (TCP handshake) — 5 second timeout per handle
    let connect_event = match create_event() {
        Some(e) => e,
        None => {
            destroy_tcp4_child(sb_handle, child_handle);
            return None;
        }
    };
    
    let mut connect_token = Tcp4ConnectionToken {
        completion_token: Tcp4CompletionToken {
            event: connect_event,
            status: RawStatus::NOT_READY,
        },
    };
    
    debug!("TCP4: Handle #{}: Connecting to {}.{}.{}.{}:{}...",
        handle_idx, ip[0], ip[1], ip[2], ip[3], port);
    let status = ((*tcp4).connect)(tcp4, &mut connect_token);
    if status != RawStatus::SUCCESS {
        warn!("TCP4: Handle #{}: Connect call failed: {:?}", handle_idx, status);
        close_event(connect_event);
        destroy_tcp4_child(sb_handle, child_handle);
        return None;
    }
    
    // Poll until connected (5 second timeout)
    let mut connected = false;
    for i in 0..500 {
        let _ = ((*tcp4).poll)(tcp4);
        if check_event(connect_event) {
            if connect_token.completion_token.status == RawStatus::SUCCESS {
                debug!("TCP4: Handle #{}: Connected after {} polls!", handle_idx, i);
                connected = true;
            } else {
                warn!("TCP4: Handle #{}: Connect error: {:?}", handle_idx, connect_token.completion_token.status);
            }
            break;
        }
        boot::stall(core::time::Duration::from_millis(10));
    }
    close_event(connect_event);
    
    if !connected {
        warn!("TCP4: Handle #{}: Connection timed out", handle_idx);
        destroy_tcp4_child(sb_handle, child_handle);
        return None;
    }
    
    Some((tcp4, child_handle, sb_handle))
}

/// Perform an HTTP POST via TCP4 protocol
/// This is the fallback path when EFI_HTTP_PROTOCOL is not available.
/// Tries all available TCP4 ServiceBinding handles to find one that connects.
pub fn tcp4_http_post(url: &str, body: &[u8], _msg_type: u8, auth_token: Option<&str>) -> Option<HttpPostResponse> {
    let (ip, port, path) = parse_url(url)?;
    let hostname = url.split('/').nth(2).unwrap_or("localhost");
    
    debug!("TCP4 HTTP POST to {}.{}.{}.{}:{}{} ({} bytes)", ip[0], ip[1], ip[2], ip[3], port, path, body.len());
    
    // Find all TCP4 Service Binding handles and try each one
    let sb_handles = find_tcp4_service_bindings();
    if sb_handles.is_empty() {
        error!("TCP4: No ServiceBinding handles available");
        return None;
    }
    
    let (tcp4, child_handle, sb_handle) = unsafe {
        let mut result = None;
        let cached = LAST_WORKING_NIC.load(Ordering::Relaxed);
        
        // If we have a cached working handle, try it first
        if cached >= 0 && (cached as usize) < sb_handles.len() {
            let idx = cached as usize;
            debug!("TCP4: Trying cached NIC handle #{} first", idx);
            if let Some(conn) = try_connect_on_handle(sb_handles[idx], idx, ip, port) {
                result = Some(conn);
            }
        }
        
        // If cached handle didn't work, scan all handles
        if result.is_none() {
            for (idx, &handle) in sb_handles.iter().enumerate() {
                // Skip the cached handle (already tried)
                if cached >= 0 && idx == cached as usize {
                    continue;
                }
                // Skip NICs with zeroed MAC addresses
                if !has_nonzero_mac(handle) {
                    continue;
                }
                if let Some(conn) = try_connect_on_handle(handle, idx, ip, port) {
                    LAST_WORKING_NIC.store(idx as i8, Ordering::Relaxed);
                    debug!("TCP4: Caching NIC handle #{} for future use", idx);
                    result = Some(conn);
                    break;
                }
            }
        }
        
        match result {
            Some(r) => r,
            None => {
                error!("TCP4: Failed to connect on any of {} ServiceBinding handles", sb_handles.len());
                return None;
            }
        }
    };
    
    unsafe {
        
        // Build HTTP request
        let mut request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/cbor\r\n\
             Content-Length: {}\r\n",
            path, hostname, body.len()
        );
        if let Some(token) = auth_token {
            request.push_str(&format!("Authorization: Bearer {}\r\n", token));
        }
        request.push_str("Connection: close\r\n");
        request.push_str("\r\n");
        
        // Combine headers + body into single send buffer
        let mut send_buf: Vec<u8> = Vec::with_capacity(request.len() + body.len());
        send_buf.extend_from_slice(request.as_bytes());
        send_buf.extend_from_slice(body);
        
        debug!("TCP4: Sending {} bytes ({} header + {} body)", 
            send_buf.len(), request.len(), body.len());
        
        // Transmit
        let tx_event = match create_event() {
            Some(e) => e,
            None => {
                destroy_tcp4_child(sb_handle, child_handle);
                return None;
            }
        };
        
        // Build transmit data with fragment
        // We need to allocate the TxData + 1 fragment entry contiguously
        // Since Tcp4TransmitData has a flexible array member, we'll use a manual layout
        #[repr(C)]
        struct TxDataWithFragment {
            push: Boolean,
            urgent: Boolean,
            data_length: u32,
            fragment_count: u32,
            fragment: Tcp4FragmentData,
        }
        
        let mut tx_data = TxDataWithFragment {
            push: Boolean::TRUE,
            urgent: Boolean::FALSE,
            data_length: send_buf.len() as u32,
            fragment_count: 1,
            fragment: Tcp4FragmentData {
                fragment_length: send_buf.len() as u32,
                fragment_buf: send_buf.as_mut_ptr(),
            },
        };
        
        let mut tx_token = Tcp4IoToken {
            completion_token: Tcp4CompletionToken {
                event: tx_event,
                status: RawStatus::NOT_READY,
            },
            packet: Tcp4Packet {
                tx_data: &mut tx_data as *mut TxDataWithFragment as *mut Tcp4TransmitData,
            },
        };
        
        let status = ((*tcp4).transmit)(tcp4, &mut tx_token);
        if status != RawStatus::SUCCESS {
            error!("TCP4: Transmit call failed: {:?}", status);
            close_event(tx_event);
            destroy_tcp4_child(sb_handle, child_handle);
            return None;
        }
        
        // Poll until sent
        let mut sent = false;
        for i in 0..1000 {
            let _ = ((*tcp4).poll)(tcp4);
            if check_event(tx_event) {
                if tx_token.completion_token.status == RawStatus::SUCCESS {
                    debug!("TCP4: Data sent after {} polls", i);
                    sent = true;
                } else {
                    error!("TCP4: Transmit error: {:?}", tx_token.completion_token.status);
                }
                break;
            }
            boot::stall(core::time::Duration::from_millis(10));
        }
        close_event(tx_event);
        
        if !sent {
            error!("TCP4: Transmit timed out");
            destroy_tcp4_child(sb_handle, child_handle);
            return None;
        }
        
        // Receive response
        let mut response_buf = vec![0u8; 65536];
        let mut total_received = 0usize;
        
        // Read in a loop until we have complete HTTP response
        for _round in 0..50 {
            let rx_event = match create_event() {
                Some(e) => e,
                None => break,
            };
            
            #[repr(C)]
            struct RxDataWithFragment {
                urgent: Boolean,
                data_length: u32,
                fragment_count: u32,
                fragment: Tcp4FragmentData,
            }
            
            let remaining = response_buf.len() - total_received;
            if remaining == 0 { break; }
            
            let mut rx_data = RxDataWithFragment {
                urgent: Boolean::FALSE,
                data_length: remaining as u32,
                fragment_count: 1,
                fragment: Tcp4FragmentData {
                    fragment_length: remaining as u32,
                    fragment_buf: response_buf[total_received..].as_mut_ptr(),
                },
            };
            
            let mut rx_token = Tcp4IoToken {
                completion_token: Tcp4CompletionToken {
                    event: rx_event,
                    status: RawStatus::NOT_READY,
                },
                packet: Tcp4Packet {
                    rx_data: &mut rx_data as *mut RxDataWithFragment as *mut Tcp4ReceiveData,
                },
            };
            
            let status = ((*tcp4).receive)(tcp4, &mut rx_token);
            if status != RawStatus::SUCCESS {
                debug!("TCP4: Receive call returned: {:?}", status);
                close_event(rx_event);
                break;
            }
            
            // Poll until data received (10 second timeout per chunk)
            let mut got_data = false;
            for _j in 0..1000 {
                let _ = ((*tcp4).poll)(tcp4);
                if check_event(rx_event) {
                    if rx_token.completion_token.status == RawStatus::SUCCESS {
                        let chunk_len = rx_data.fragment.fragment_length as usize;
                        total_received += chunk_len;
                        debug!("TCP4: Received {} bytes (total: {})", chunk_len, total_received);
                        got_data = true;
                    } else {
                        // Connection closed or error - this is normal for "Connection: close"
                        debug!("TCP4: Receive status: {:?}", rx_token.completion_token.status);
                    }
                    break;
                }
                boot::stall(core::time::Duration::from_millis(10));
            }
            close_event(rx_event);
            
            if !got_data {
                break;
            }
            
            // Check if we have complete HTTP response (headers + body)
            if let Some(header_end) = find_header_end(&response_buf[..total_received]) {
                // Check Content-Length to know if body is complete
                if let Some(content_len) = extract_content_length(&response_buf[..header_end]) {
                    if total_received >= header_end + content_len {
                        debug!("TCP4: Complete response received ({} headers + {} body)", 
                            header_end, content_len);
                        break;
                    }
                } else {
                    // No Content-Length; rely on Connection: close
                    // Keep reading until connection closes
                }
            }
        }
        
        // Close TCP connection
        let close_event_handle = create_event();
        if let Some(evt) = close_event_handle {
            let mut close_token = Tcp4CloseToken {
                completion_token: Tcp4CompletionToken {
                    event: evt,
                    status: RawStatus::NOT_READY,
                },
                abort_on_close: Boolean::TRUE, // RST for fast cleanup
            };
            let _ = ((*tcp4).close)(tcp4, &mut close_token);
            // Brief poll for close
            for _ in 0..100 {
                let _ = ((*tcp4).poll)(tcp4);
                if check_event(evt) { break; }
                boot::stall(core::time::Duration::from_millis(5));
            }
            close_event(evt);
        }
        
        // Destroy child handle
        destroy_tcp4_child(sb_handle, child_handle);
        
        if total_received == 0 {
            error!("TCP4: No response data received");
            return None;
        }
        
        // Parse HTTP response
        response_buf.truncate(total_received);
        parse_http_response(&response_buf)
    }
}

/// Find the end of HTTP headers (position after \r\n\r\n)
fn find_header_end(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if data[i] == b'\r' && data[i+1] == b'\n' && data[i+2] == b'\r' && data[i+3] == b'\n' {
            return Some(i + 4);
        }
    }
    None
}

/// Extract Content-Length from HTTP headers
fn extract_content_length(headers: &[u8]) -> Option<usize> {
    let headers_str = core::str::from_utf8(headers).ok()?;
    for line in headers_str.lines() {
        if line.to_lowercase().starts_with("content-length:") {
            let val = line.splitn(2, ':').nth(1)?.trim();
            return val.parse().ok();
        }
    }
    None
}

/// Parse raw HTTP response into HttpPostResponse
fn parse_http_response(data: &[u8]) -> Option<HttpPostResponse> {
    let header_end = find_header_end(data)?;
    let headers_section = &data[..header_end];
    let body = data[header_end..].to_vec();
    
    let headers_str = core::str::from_utf8(headers_section).ok()?;
    
    // Parse status line
    let first_line = headers_str.lines().next()?;
    debug!("TCP4 HTTP response: {}", first_line);
    
    // Extract headers we care about
    let mut auth_token: Option<String> = None;
    let mut msg_type: Option<u8> = None;
    
    for line in headers_str.lines().skip(1) {
        let lower = line.to_lowercase();
        if lower.starts_with("authorization:") {
            let value = line.splitn(2, ':').nth(1).map(|v| v.trim());
            if let Some(val) = value {
                let token = if val.starts_with("Bearer ") {
                    &val[7..]
                } else {
                    val
                };
                auth_token = Some(String::from(token));
                debug!("TCP4: Found Authorization token: {}...", &token[..token.len().min(20)]);
            }
        } else if lower.starts_with("message-type:") {
            let value = line.splitn(2, ':').nth(1).map(|v| v.trim());
            if let Some(val) = value {
                if let Ok(mt) = val.parse::<u8>() {
                    msg_type = Some(mt);
                }
            }
        }
    }
    
    if !body.is_empty() {
        debug!("TCP4 HTTP body: {} bytes, hex: {:02x?}", body.len(), &body[..body.len().min(80)]);
    }
    
    debug!("TCP4 HTTP POST completed: {} bytes body, msg_type={:?}", body.len(), msg_type);
    Some(HttpPostResponse {
        body,
        auth_token,
        message_type: msg_type,
    })
}

/// Perform an HTTP GET via TCP4 protocol
/// Used by rv-firmware to download firmware images from RV URLs.
/// Tries all available TCP4 ServiceBinding handles to find one that connects.
#[cfg(feature = "rv-firmware")]
pub fn tcp4_http_get(url: &str) -> Option<Vec<u8>> {
    let (ip, port, path) = parse_url(url)?;
    let hostname = url.split('/').nth(2).unwrap_or("localhost");

    info!("TCP4 HTTP GET {}.{}.{}.{}:{}{}", ip[0], ip[1], ip[2], ip[3], port, path);

    let sb_handles = find_tcp4_service_bindings();
    if sb_handles.is_empty() {
        error!("TCP4: No ServiceBinding handles available");
        return None;
    }

    let (tcp4, child_handle, sb_handle) = unsafe {
        let mut result = None;
        let cached = LAST_WORKING_NIC.load(Ordering::Relaxed);

        if cached >= 0 && (cached as usize) < sb_handles.len() {
            let idx = cached as usize;
            if let Some(conn) = try_connect_on_handle(sb_handles[idx], idx, ip, port) {
                result = Some(conn);
            }
        }

        if result.is_none() {
            for (idx, &handle) in sb_handles.iter().enumerate() {
                if cached >= 0 && idx == cached as usize { continue; }
                if !has_nonzero_mac(handle) { continue; }
                if let Some(conn) = try_connect_on_handle(handle, idx, ip, port) {
                    LAST_WORKING_NIC.store(idx as i8, Ordering::Relaxed);
                    result = Some(conn);
                    break;
                }
            }
        }

        match result {
            Some(r) => r,
            None => {
                error!("TCP4: Failed to connect on any handle for GET");
                return None;
            }
        }
    };

    unsafe {
        // Build HTTP GET request
        let request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: close\r\n\
             \r\n",
            path, hostname
        );

        let mut send_buf: Vec<u8> = Vec::with_capacity(request.len());
        send_buf.extend_from_slice(request.as_bytes());

        debug!("TCP4: Sending GET request ({} bytes)", send_buf.len());

        // Transmit
        let tx_event = match create_event() {
            Some(e) => e,
            None => {
                destroy_tcp4_child(sb_handle, child_handle);
                return None;
            }
        };

        #[repr(C)]
        struct TxDataWithFragment {
            push: Boolean,
            urgent: Boolean,
            data_length: u32,
            fragment_count: u32,
            fragment: Tcp4FragmentData,
        }

        let mut tx_data = TxDataWithFragment {
            push: Boolean::TRUE,
            urgent: Boolean::FALSE,
            data_length: send_buf.len() as u32,
            fragment_count: 1,
            fragment: Tcp4FragmentData {
                fragment_length: send_buf.len() as u32,
                fragment_buf: send_buf.as_mut_ptr(),
            },
        };

        let mut tx_token = Tcp4IoToken {
            completion_token: Tcp4CompletionToken {
                event: tx_event,
                status: RawStatus::NOT_READY,
            },
            packet: Tcp4Packet {
                tx_data: &mut tx_data as *mut TxDataWithFragment as *mut Tcp4TransmitData,
            },
        };

        let status = ((*tcp4).transmit)(tcp4, &mut tx_token);
        if status != RawStatus::SUCCESS {
            error!("TCP4: GET transmit failed: {:?}", status);
            close_event(tx_event);
            destroy_tcp4_child(sb_handle, child_handle);
            return None;
        }

        let mut sent = false;
        for i in 0..1000 {
            let _ = ((*tcp4).poll)(tcp4);
            if check_event(tx_event) {
                if tx_token.completion_token.status == RawStatus::SUCCESS {
                    debug!("TCP4: GET request sent after {} polls", i);
                    sent = true;
                }
                break;
            }
            boot::stall(core::time::Duration::from_millis(10));
        }
        close_event(tx_event);

        if !sent {
            error!("TCP4: GET transmit timed out");
            destroy_tcp4_child(sb_handle, child_handle);
            return None;
        }

        // Receive response — firmware images can be large, start with 1MB
        let mut response_buf = vec![0u8; 1024 * 1024];
        let mut total_received = 0usize;

        for _round in 0..500 {
            let rx_event = match create_event() {
                Some(e) => e,
                None => break,
            };

            #[repr(C)]
            struct RxDataWithFragment {
                urgent: Boolean,
                data_length: u32,
                fragment_count: u32,
                fragment: Tcp4FragmentData,
            }

            let remaining = response_buf.len() - total_received;
            if remaining == 0 {
                // Grow buffer
                response_buf.resize(response_buf.len() + 1024 * 1024, 0);
            }
            let remaining = response_buf.len() - total_received;

            let mut rx_data = RxDataWithFragment {
                urgent: Boolean::FALSE,
                data_length: remaining as u32,
                fragment_count: 1,
                fragment: Tcp4FragmentData {
                    fragment_length: remaining as u32,
                    fragment_buf: response_buf[total_received..].as_mut_ptr(),
                },
            };

            let mut rx_token = Tcp4IoToken {
                completion_token: Tcp4CompletionToken {
                    event: rx_event,
                    status: RawStatus::NOT_READY,
                },
                packet: Tcp4Packet {
                    rx_data: &mut rx_data as *mut RxDataWithFragment as *mut Tcp4ReceiveData,
                },
            };

            let status = ((*tcp4).receive)(tcp4, &mut rx_token);
            if status != RawStatus::SUCCESS {
                debug!("TCP4: GET receive returned: {:?}", status);
                close_event(rx_event);
                break;
            }

            let mut got_data = false;
            for _j in 0..1000 {
                let _ = ((*tcp4).poll)(tcp4);
                if check_event(rx_event) {
                    if rx_token.completion_token.status == RawStatus::SUCCESS {
                        let chunk_len = rx_data.fragment.fragment_length as usize;
                        total_received += chunk_len;
                        debug!("TCP4: GET received {} bytes (total: {})", chunk_len, total_received);
                        got_data = true;
                    }
                    break;
                }
                boot::stall(core::time::Duration::from_millis(10));
            }
            close_event(rx_event);

            if !got_data { break; }

            // Check if response is complete
            if let Some(header_end) = find_header_end(&response_buf[..total_received]) {
                if let Some(content_len) = extract_content_length(&response_buf[..header_end]) {
                    if total_received >= header_end + content_len {
                        debug!("TCP4: GET complete ({} headers + {} body)", header_end, content_len);
                        break;
                    }
                }
            }
        }

        // Close TCP connection
        let close_evt = create_event();
        if let Some(evt) = close_evt {
            let mut close_token = Tcp4CloseToken {
                completion_token: Tcp4CompletionToken {
                    event: evt,
                    status: RawStatus::NOT_READY,
                },
                abort_on_close: Boolean::TRUE,
            };
            let _ = ((*tcp4).close)(tcp4, &mut close_token);
            for _ in 0..100 {
                let _ = ((*tcp4).poll)(tcp4);
                if check_event(evt) { break; }
                boot::stall(core::time::Duration::from_millis(5));
            }
            close_event(evt);
        }

        destroy_tcp4_child(sb_handle, child_handle);

        if total_received == 0 {
            error!("TCP4: GET received no data");
            return None;
        }

        // Extract body from HTTP response
        response_buf.truncate(total_received);
        if let Some(header_end) = find_header_end(&response_buf) {
            // Check HTTP status
            if let Ok(headers_str) = core::str::from_utf8(&response_buf[..header_end]) {
                if let Some(first_line) = headers_str.lines().next() {
                    debug!("TCP4 HTTP GET response: {}", first_line);
                    // Check for non-200 status
                    if !first_line.contains("200") {
                        error!("TCP4: GET failed with status: {}", first_line);
                        return None;
                    }
                }
            }
            let body = response_buf[header_end..].to_vec();
            debug!("TCP4 HTTP GET completed: {} bytes", body.len());
            Some(body)
        } else {
            error!("TCP4: GET response has no HTTP headers");
            None
        }
    }
}

/// Check if TCP4 Service Binding is available
pub fn tcp4_is_available() -> bool {
    !find_tcp4_service_bindings().is_empty()
}
