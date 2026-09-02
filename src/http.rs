// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use log::{info, warn, error, debug};
use uefi::boot;
use uefi::Identify;
use uefi::proto::network::http::{HttpBinding, HttpHelper};
use uefi::proto::network::ip4config2::Ip4Config2;

/// Track if network has been configured (DHCP completed)
static NETWORK_CONFIGURED: AtomicBool = AtomicBool::new(false);

/// Track if SNP interface has been initialized
static SNP_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Test URL - points to host machine from QEMU guest
const TEST_URL: &str = "http://10.0.2.2:8080/test.txt";

/// Find the end of HTTP headers (position after \r\n\r\n)
fn find_header_end(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if data[i] == b'\r' && data[i+1] == b'\n' && data[i+2] == b'\r' && data[i+3] == b'\n' {
            return Some(i + 4);
        }
    }
    None
}

/// Start SNP network interface to trigger IP stack initialization
fn start_snp_interface() -> Option<uefi::Handle> {
    use uefi::proto::network::snp::SimpleNetwork;
    
    let snp_handles = match boot::locate_handle_buffer(boot::SearchType::ByProtocol(
        &SimpleNetwork::GUID
    )) {
        Ok(h) => h,
        Err(_) => {
            warn!("No SNP handles found");
            return None;
        }
    };
    
    debug!("Found {} SNP handle(s), starting interface...", snp_handles.len());
    
    for handle in snp_handles.iter() {
        if let Ok(snp) = boot::open_protocol_exclusive::<SimpleNetwork>(*handle) {
            debug!("SNP mode: {:?}", snp.mode());
            
            // Try to start the interface
            match snp.start() {
                Ok(_) => debug!("SNP started successfully"),
                Err(e) => debug!("SNP start: {:?} (may already be started)", e),
            }
            
            // Initialize the interface
            match snp.initialize(0, 0) {
                Ok(_) => {
                    debug!("SNP initialized successfully");
                    return Some(*handle);
                }
                Err(e) => {
                    debug!("SNP initialize: {:?}", e);
                    // Already initialized is OK
                    return Some(*handle);
                }
            }
        }
    }
    None
}

/// Connect network controller to load IP/HTTP stack
fn connect_network_controller(handle: uefi::Handle) -> bool {
    debug!("Connecting network controller recursively...");
    
    // Connect all drivers to this controller recursively
    // This should trigger IP4Dxe, TcpDxe, HttpDxe to bind
    let empty_list: &[Option<uefi::Handle>] = &[];
    match boot::connect_controller(handle, empty_list, None, true) {
        Ok(_) => {
            debug!("Network controller connected successfully");
            true
        }
        Err(e) => {
            warn!("Connect controller failed: {:?}", e);
            false
        }
    }
}

/// Find a NIC handle that supports HTTP
fn find_http_nic() -> Option<uefi::Handle> {
    use uefi::proto::network::snp::SimpleNetwork;
    
    // Check for SNP (basic network driver)
    let snp_handles = match boot::locate_handle_buffer(boot::SearchType::ByProtocol(
        &SimpleNetwork::GUID
    )) {
        Ok(h) => {
            debug!("Found {} SNP (network driver) handle(s)", h.len());
            h
        }
        Err(_) => {
            warn!("No SNP handles found - network driver not loaded");
            return None;
        }
    };
    
    // Only initialize SNP once
    let snp_handle = if SNP_INITIALIZED.load(Ordering::Relaxed) {
        debug!("SNP already initialized, reusing handle");
        *snp_handles.first()?
    } else {
        // Try to start SNP interface and get handle
        let h = match start_snp_interface() {
            Some(h) => h,
            None => {
                warn!("Could not start SNP interface");
                *snp_handles.first()?
            }
        };
        
        // Connect the network controller to trigger IP/HTTP driver binding
        connect_network_controller(h);
        SNP_INITIALIZED.store(true, Ordering::Relaxed);
        h
    };
    
    // Check for IP4Config2 (IP stack)
    if let Ok(ip4_handles) = boot::locate_handle_buffer(boot::SearchType::ByProtocol(
        &Ip4Config2::GUID
    )) {
        debug!("Found {} IP4Config2 handle(s)", ip4_handles.len());
    } else {
        warn!("No IP4Config2 handles after connect");
    }
    
    // Check for TCP4 Service Binding Protocol
    let tcp4_sb_guid = uefi::guid!("00720665-67eb-4a99-baf7-d3c33a1c7cc9");
    match boot::locate_handle_buffer(boot::SearchType::ByProtocol(&tcp4_sb_guid)) {
        Ok(handles) => debug!("Found {} TCP4 ServiceBinding handle(s)", handles.len()),
        Err(_) => warn!("No TCP4 ServiceBinding handles found"),
    }
    
    // Look for HTTP Service Binding Protocol handles
    match boot::locate_handle_buffer(boot::SearchType::ByProtocol(
        &HttpBinding::GUID
    )) {
        Ok(handles) => {
            debug!("Found {} HTTP-capable NIC(s)", handles.len());
            handles.first().copied()
        }
        Err(_) => {
            debug!("No HTTP handles found after connect");
            None
        }
    }
}

/// Configure network via DHCP using IP4Config2 (only runs once)
pub fn configure_network(nic_handle: uefi::Handle) -> bool {
    // Skip if already configured
    if NETWORK_CONFIGURED.load(Ordering::Relaxed) {
        debug!("Network already configured, skipping DHCP");
        return true;
    }
    
    debug!("Configuring network via DHCP (first time)...");
    
    match Ip4Config2::new(nic_handle) {
        Ok(mut ip4cfg) => {
            match ip4cfg.ifup() {
                Ok(()) => {
                    debug!("Network configured successfully");
                    if let Ok(info) = ip4cfg.get_interface_info() {
                        debug!("IP Address: {}", info.station_addr);
                    }
                    NETWORK_CONFIGURED.store(true, Ordering::Relaxed);
                    true
                }
                Err(e) => {
                    error!("DHCP failed: {:?}", e);
                    false
                }
            }
        }
        Err(e) => {
            error!("Failed to open IP4Config2: {:?}", e);
            false
        }
    }
}

/// Perform HTTP GET request
pub fn http_get(url: &str) -> Option<Vec<u8>> {
    let nic_handle = find_http_nic()?;
    
    // Configure network first
    if !configure_network(nic_handle) {
        warn!("Network configuration failed, trying HTTP anyway...");
    }
    
    debug!("Using NIC handle for HTTP...");
    
    // Create HTTP helper
    let mut http = match HttpHelper::new(nic_handle) {
        Ok(h) => h,
        Err(e) => {
            error!("HttpHelper::new failed: {:?}", e);
            return None;
        }
    };
    
    // Configure with defaults
    if let Err(e) = http.configure() {
        error!("http.configure() failed: {:?}", e);
        return None;
    }
    
    debug!("Sending GET request to: {}", url);
    
    // Send GET request
    if let Err(e) = http.request_get(url) {
        error!("http.request_get() failed: {:?}", e);
        return None;
    }
    
    // Get response
    match http.response_first(true) {
        Ok(response) => {
            debug!("HTTP Status: {:?}", response.status);
            
            let mut body = response.body;
            
            // Check if we need more data
            loop {
                match http.response_more(&mut body) {
                    Ok(chunk) => {
                        if chunk.is_empty() {
                            break;
                        }
                        debug!("Received {} more bytes", chunk.len());
                    }
                    Err(_) => break,
                }
            }
            
            debug!("Total body size: {} bytes", body.len());
            Some(body)
        }
        Err(e) => {
            error!("http.response_first() failed: {:?}", e);
            None
        }
    }
}

use crate::http_api::HttpPostResponse;

/// Perform HTTP POST request using raw UEFI HTTP protocol
/// Returns HttpPostResponse with body, authorization token, and Message-Type header
pub fn http_post_with_session(url: &str, body: &[u8], _msg_type: u8, auth_token: Option<&str>) -> Option<HttpPostResponse> {
    http_post_internal(url, body, _msg_type, auth_token)
}

pub fn http_post(url: &str, body: &[u8], _msg_type: u8) -> Option<Vec<u8>> {
    http_post_internal(url, body, _msg_type, None).map(|r| r.body)
}

fn http_post_internal(url: &str, body: &[u8], _msg_type: u8, auth_token: Option<&str>) -> Option<HttpPostResponse> {
    use alloc::string::String;
    use alloc::vec;
    use core::ffi::c_void;
    use uefi_raw::protocol::network::http::{
        HttpConfigData, HttpV4AccessPoint, HttpAccessPoint, HttpVersion,
        HttpHeader, HttpMessage, HttpRequestData, HttpRequestOrResponse,
        HttpToken, HttpMethod, HttpProtocol as RawHttpProtocol,
    };
    use uefi_raw::{Boolean, Ipv4Address};
    
    let nic_handle = match find_http_nic() {
        Some(h) => h,
        None => {
            debug!("No HTTP protocol available");
            return None;
        }
    };
    
    // Configure network first
    if !configure_network(nic_handle) {
        warn!("Network configuration failed, trying HTTP anyway...");
    }
    
    info!("HTTP POST to: {} (body: {} bytes)", url, body.len());
    debug!("Body hex: {:02x?}", &body[..body.len().min(32)]);
    
    // Get HTTP Service Binding and create child
    let mut binding = boot::open_protocol_exclusive::<HttpBinding>(nic_handle).ok()?;
    let child_handle = binding.create_child().ok()?;
    debug!("Created HTTP child handle: {:?}", child_handle);
    
    // Open raw HTTP protocol on child handle
    let proto_ptr: *mut RawHttpProtocol = {
        let mut proto: *mut c_void = core::ptr::null_mut();
        let st = uefi::table::system_table_raw().expect("no system table");
        let bs = unsafe { (*st.as_ptr()).boot_services };
        let status = unsafe {
            ((*bs).open_protocol)(
                child_handle.as_ptr(),
                &RawHttpProtocol::GUID,
                &mut proto,
                boot::image_handle().as_ptr(),
                core::ptr::null_mut(),
                0x20, // EFI_OPEN_PROTOCOL_EXCLUSIVE
            )
        };
        if status != uefi::Status::SUCCESS {
            error!("Failed to open HTTP protocol: {:?}", status);
            return None;
        }
        proto.cast()
    };
    
    // Configure HTTP protocol for IPv4
    let ipv4_access = HttpV4AccessPoint {
        use_default_addr: Boolean::TRUE,
        local_address: Ipv4Address([0, 0, 0, 0]),
        local_subnet: Ipv4Address([0, 0, 0, 0]),
        local_port: 0,
    };
    
    let config = HttpConfigData {
        http_version: HttpVersion::HTTP_VERSION_11,
        time_out_millisec: 30000,
        local_addr_is_ipv6: Boolean::FALSE,
        access_point: HttpAccessPoint {
            ipv4_node: &ipv4_access,
        },
    };
    
    let status = unsafe { ((*proto_ptr).configure)(proto_ptr, &config) };
    if status != uefi::Status::SUCCESS {
        error!("HTTP configure failed: {:?}", status);
        return None;
    }
    debug!("HTTP configured");
    
    // Build URL as null-terminated UTF-16
    let url16 = uefi::CString16::try_from(url).ok()?;
    
    // Extract hostname for Host header
    let hostname = url.split('/').nth(2).unwrap_or("localhost");
    let mut c_hostname = String::from(hostname);
    c_hostname.push('\0');
    
    // Build request data
    let mut tx_req = HttpRequestData {
        method: HttpMethod::POST,
        url: url16.as_ptr().cast::<u16>(),
    };
    
    // Headers - use raw pointers
    let host_name = c"Host";
    let content_type_name = c"Content-Type";
    let content_type_value = c"application/cbor";
    let content_length_name = c"Content-Length";
    let content_length_value = alloc::format!("{}\0", body.len());
    let auth_name = c"Authorization";
    // Server expects "Bearer <token>" format
    let auth_value_owned = auth_token.map(|t| alloc::format!("Bearer {}\0", t));
    
    let mut headers_vec: alloc::vec::Vec<HttpHeader> = alloc::vec![
        HttpHeader {
            field_name: host_name.as_ptr().cast::<u8>(),
            field_value: c_hostname.as_ptr().cast::<u8>(),
        },
        HttpHeader {
            field_name: content_type_name.as_ptr().cast::<u8>(),
            field_value: content_type_value.as_ptr().cast::<u8>(),
        },
        HttpHeader {
            field_name: content_length_name.as_ptr().cast::<u8>(),
            field_value: content_length_value.as_ptr().cast::<u8>(),
        },
    ];
    
    // Add Authorization header if provided
    if let Some(ref auth_val) = auth_value_owned {
        debug!("Including Authorization header");
        headers_vec.push(HttpHeader {
            field_name: auth_name.as_ptr().cast::<u8>(),
            field_value: auth_val.as_ptr().cast::<u8>(),
        });
    }
    
    // Copy body to mutable buffer
    let mut body_buf = body.to_vec();
    
    // Build message with union
    let mut tx_msg = HttpMessage {
        data: HttpRequestOrResponse { request: &mut tx_req },
        header_count: headers_vec.len(),
        header: headers_vec.as_mut_ptr(),
        body_length: body_buf.len(),
        body: body_buf.as_mut_ptr().cast::<c_void>(),
    };
    
    let mut tx_token = HttpToken {
        event: core::ptr::null_mut(),
        status: uefi::Status::SUCCESS,
        message: &mut tx_msg,
    };
    
    debug!("Sending POST request...");
    // Mark the token pending so a driver that completes asynchronously can be
    // told apart from one that has already finished.
    tx_token.status = uefi::Status::NOT_READY;
    let status = unsafe { ((*proto_ptr).request)(proto_ptr, &mut tx_token) };
    if status != uefi::Status::SUCCESS {
        error!("HTTP POST request failed: {:?}", status);
        return None;
    }

    // OVMF completes Request() synchronously, exactly as the Response() path
    // below assumes, so a SUCCESS return means the request is already out and
    // there is nothing to wait for.
    //
    // This loop used to run a fixed 300 iterations with a 10ms stall, breaking
    // only if poll() reported an *error*. Since poll() normally returns
    // SUCCESS/NOT_READY, it ran to completion every time and burned a flat 3
    // seconds on every HTTP request in the client — TO1, TO2 and ServiceInfo
    // alike, regardless of payload size.
    if tx_token.status == uefi::Status::NOT_READY {
        for i in 0..3000 {
            let poll_status = unsafe { ((*proto_ptr).poll)(proto_ptr) };
            if tx_token.status == uefi::Status::SUCCESS {
                debug!("Request completed after {} polls", i);
                break;
            }
            if tx_token.status != uefi::Status::NOT_READY {
                error!("HTTP POST request failed asynchronously: {:?}", tx_token.status);
                return None;
            }
            if poll_status != uefi::Status::SUCCESS && poll_status != uefi::Status::NOT_READY {
                break;
            }
            boot::stall(core::time::Duration::from_millis(1));
        }
    }
    debug!("Request sent");
    
    // Receive response
    // Must provide HttpResponseData for response to populate status code
    use uefi_raw::protocol::network::http::HttpResponseData;
    let mut response_data = HttpResponseData {
        status_code: uefi_raw::protocol::network::http::HttpStatusCode::STATUS_200_OK,
    };
    
    // Allocate space for response headers (UEFI HTTP returns headers separately)
    // We need at least space for Authorization header
    let mut rx_headers: [HttpHeader; 16] = unsafe { core::mem::zeroed() };
    
    // Must exceed the ServiceInfo MTU advertised in fdo.rs (65535) plus COSE and
    // HTTP framing; the drain loop below will not collect more than this.
    let mut rx_body = vec![0u8; 131072]; // 128KB
    let mut rx_msg = HttpMessage {
        data: HttpRequestOrResponse { response: &mut response_data },
        header_count: rx_headers.len(),
        header: rx_headers.as_mut_ptr(),
        body_length: rx_body.len(),
        body: rx_body.as_mut_ptr().cast::<c_void>(),
    };
    
    let mut rx_token = HttpToken {
        event: core::ptr::null_mut(),
        status: uefi::Status::SUCCESS,
        message: &mut rx_msg,
    };
    
    debug!("Receiving response...");
    
    let status = unsafe { ((*proto_ptr).response)(proto_ptr, &mut rx_token) };
    debug!("Response call returned: {:?}, token status: {:?}", status, rx_token.status);
    
    // OVMF returns response synchronously - if status is SUCCESS, we have the response
    if status == uefi::Status::SUCCESS {
        debug!("Response received synchronously");
    } else {
        // Async mode - poll until complete
        // 3000 iterations × 10ms = 30 seconds max
        for i in 0..3000 {
            let poll_status = unsafe { ((*proto_ptr).poll)(proto_ptr) };
            // Check token status for completion
            if rx_token.status == uefi::Status::SUCCESS {
                debug!("Response completed after {} polls", i);
                break;
            }
            // Check for actual error status (not SUCCESS or NOT_READY)
            if rx_token.status != uefi::Status::SUCCESS && 
               rx_token.status != uefi::Status::NOT_READY {
                error!("Response failed with status: {:?}", rx_token.status);
                return None;
            }
            if poll_status != uefi::Status::SUCCESS && poll_status != uefi::Status::NOT_READY {
                debug!("Poll returned: {:?}", poll_status);
            }
            boot::stall(core::time::Duration::from_millis(10));
        }
    }
    
    debug!("Final token status: {:?}", rx_token.status);
    
    let body_len = rx_msg.body_length;
    let header_count = rx_msg.header_count;
    debug!("First response call: {} body bytes, {} headers", body_len, header_count);
    
    // Extract Authorization and Message-Type headers from UEFI HTTP headers
    let mut auth_header: Option<String> = None;
    let mut msg_type_header: Option<u8> = None;
    let mut content_length: Option<usize> = None;
    let header_ptr = rx_msg.header;
    debug!("Header ptr: {:p}, count: {}", header_ptr, header_count);
    if !header_ptr.is_null() && header_count > 0 {
        for i in 0..header_count {
            let hdr = unsafe { &*header_ptr.add(i) };
            debug!("  Header[{}] name_ptr: {:p}, value_ptr: {:p}", i, hdr.field_name, hdr.field_value);
            if !hdr.field_name.is_null() && !hdr.field_value.is_null() {
                let name = unsafe { 
                    let mut len = 0;
                    let mut p = hdr.field_name;
                    while *p != 0 { len += 1; p = p.add(1); }
                    core::str::from_utf8_unchecked(core::slice::from_raw_parts(hdr.field_name, len))
                };
                let value = unsafe {
                    let mut len = 0;
                    let mut p = hdr.field_value;
                    while *p != 0 { len += 1; p = p.add(1); }
                    core::str::from_utf8_unchecked(core::slice::from_raw_parts(hdr.field_value, len))
                };
                debug!("  Header: {} = {}", name, &value[..value.len().min(60)]);
                if name.eq_ignore_ascii_case("Content-Length") {
                    content_length = value.trim().parse::<usize>().ok();
                }
                if name.eq_ignore_ascii_case("Authorization") {
                    // Strip "Bearer " prefix if present
                    let token = if value.starts_with("Bearer ") {
                        &value[7..]
                    } else {
                        value
                    };
                    auth_header = Some(String::from(token));
                    debug!("Found Authorization token: {}...", &token[..token.len().min(20)]);
                } else if name.eq_ignore_ascii_case("Message-Type") {
                    if let Ok(mt) = value.trim().parse::<u8>() {
                        msg_type_header = Some(mt);
                    }
                }
            }
        }
    }
    
    // A single EFI_HTTP_PROTOCOL.Response() call only delivers the body bytes that
    // have arrived so far — for anything past the first segment or two that is a
    // fraction of the whole. Keep calling Response() until Content-Length bytes
    // have been collected. Subsequent calls must pass Data.Response = NULL and no
    // header array, which tells the driver "body continuation only".
    //
    // Note: this relies on the driver reporting Content-Length in the header array.
    // When firmware instead returns raw HTTP inside the body (the fallback path
    // below), no length is available and we take a single read as-is.
    // 64 spins plus ~50k * 100us gives roughly a 5s ceiling on waiting for any
    // single segment, independent of how large the body is.
    const MAX_DRAIN_IDLE: u32 = 50_000;
    let mut total = body_len;
    let mut drain_calls = 0u32;
    let mut idle_waits = 0u32;
    if let Some(cl) = content_length {
        let mut idle = 0;
        while total < cl && total < rx_body.len() {
            let want = core::cmp::min(rx_body.len() - total, cl - total);

            // OVMF reports BodyLength as the amount we asked for, not the amount
            // it wrote, so its count cannot be used to advance our offset. Stamp
            // the pending region with a sentinel first; whatever still holds the
            // sentinel afterwards was never written. A trailing run shorter than
            // the pattern width is treated as filled, so a false reading needs 4
            // consecutive sentinel bytes at the exact boundary (~2^-32) and would
            // be caught by the GCM tag rather than passing silently.
            const RX_SENTINEL: u8 = 0xA5;
            for b in &mut rx_body[total..total + want] {
                *b = RX_SENTINEL;
            }
            let mut more_msg = HttpMessage {
                data: HttpRequestOrResponse { response: core::ptr::null_mut() },
                header_count: 0,
                header: core::ptr::null_mut(),
                body_length: want,
                body: unsafe { rx_body.as_mut_ptr().add(total) }.cast::<c_void>(),
            };
            let mut more_token = HttpToken {
                event: core::ptr::null_mut(),
                status: uefi::Status::SUCCESS,
                message: &mut more_msg,
            };

            drain_calls += 1;
            // Response() returning SUCCESS means the read was *queued*, not that
            // the body arrived — completion is signalled through the token. Only
            // ever have one token outstanding: previously we measured straight
            // away and, seeing nothing, queued another, leaving abandoned tokens
            // holding pointers into regions we had already advanced past. A late
            // token then wrote its segment at a stale offset, which corrupted the
            // body intermittently and passed the length check.
            more_token.status = uefi::Status::NOT_READY;
            let st = unsafe { ((*proto_ptr).response)(proto_ptr, &mut more_token) };
            if st != uefi::Status::SUCCESS && st != uefi::Status::NOT_READY {
                error!("HTTP rx drain: Response() failed at {}/{} bytes (status {:?})",
                       total, cl, st);
                break;
            }

            // Drive the stack until this token completes. Poll() is safe here
            // because the token it can complete is the one we just queued.
            let mut waited = 0u32;
            while more_token.status == uefi::Status::NOT_READY {
                unsafe { ((*proto_ptr).poll)(proto_ptr) };
                if more_token.status != uefi::Status::NOT_READY {
                    break;
                }
                waited += 1;
                if waited > MAX_DRAIN_IDLE {
                    break;
                }
                boot::stall(core::time::Duration::from_micros(100));
            }
            idle_waits += waited;

            // body_length is only meaningful once the token has completed; the
            // earlier "driver lies" reading came from sampling it while the read
            // was still queued, when it still held the size we asked for.
            let got = more_msg.body_length;

            // Cross-check against the sentinel, which cannot be trusted on its
            // own: a written segment whose final byte happens to equal the
            // sentinel makes the trailing run over-count, so this is a
            // diagnostic only, never the source of truth.
            let mut run = 0usize;
            while run < want && rx_body[total + want - 1 - run] == RX_SENTINEL {
                run += 1;
            }
            let sentinel_got = want - run;
            if sentinel_got != got && drain_calls <= 6 {
                debug!("  drain: token reports {}, sentinel suggests {}", got, sentinel_got);
            }
            if got > want {
                // The driver wrote past the buffer size we advertised, which means
                // it has already scribbled over the heap. Say so loudly rather
                // than letting it surface later as a fault inside firmware.
                error!("HTTP rx drain: driver overran buffer — wrote {}, cap was {}", got, want);
                return None;
            }
            if got == 0 {
                // Nothing ready yet. Drive the stack with poll() and retry. The
                // previous 10ms stall per empty call cost ~2.2s per 64KB body,
                // since ~46 calls are needed and roughly half come back empty.
                // Spin first, then back off in 100us steps, bounded by a total
                // wait budget (~5s) instead of an iteration count that scaled
                // with body size and truncated large responses.
                idle += 1;
                idle_waits += 1;
                if idle > MAX_DRAIN_IDLE {
                    error!("HTTP rx drain: stalled at {}/{} bytes after {} empty polls",
                           total, cl, idle);
                    break;
                }
                // Do not call Http->Poll() here: doing so between Response()
                // calls consumes the pending segments instead of buffering them,
                // and the drain then never sees a single byte.
                boot::stall(core::time::Duration::from_micros(100));
                continue;
            }
            idle = 0;
            if drain_calls <= 6 {
                info!("  drain call {}: asked {} at off {}, got {}", drain_calls, want, total, got);
            }
            total += got;
        }

        if total == cl {
            debug!("HTTP rx complete: {} bytes in {} call(s)", total,
                   if total == body_len { 1 } else { 2 });
        } else {
            error!("HTTP rx SHORT READ: got {} bytes, Content-Length {} (missing {})",
                   total, cl, cl.saturating_sub(total));
        }
    } else {
        debug!("HTTP rx: {} bytes, no Content-Length header", total);
    }
    info!("HTTP rx cost: {} bytes | first call {} | Content-Length {:?} | {} drain calls | {} idle waits",
          total, body_len, content_length, drain_calls, idle_waits);
    if drain_calls > 0 && total > body_len + 8 && body_len >= 8 {
        // If the driver restarted the body instead of continuing, the COSE prefix
        // seen at offset 0 will reappear at the drain boundary.
        info!("  boundary: head {:02x?} | at off {} {:02x?} | tail {:02x?}",
              &rx_body[..8], body_len, &rx_body[body_len..body_len + 8],
              &rx_body[total - 8..total]);
    }
    rx_body.truncate(total);

    // Fallback: try parsing headers from body (some UEFI implementations return raw HTTP)
    let body = if auth_header.is_none() {
        if let Some(pos) = find_header_end(&rx_body) {
            debug!("Headers in body, end at byte {}", pos);
            let headers_section = &rx_body[..pos];
            auth_header = extract_authorization_header(headers_section);
            rx_body[pos..].to_vec()
        } else {
            rx_body
        }
    } else {
        rx_body
    };
    
    if !body.is_empty() {
        debug!("Body hex: {:02x?}", &body[..body.len().min(80)]);
    }
    
    // Clean up: destroy HTTP child handle to avoid resource leak
    // This is critical - without it, we run out of handles after ~80 requests
    //
    // The raw HTTP protocol above was opened EXCLUSIVE on the child handle, and
    // DestroyChild returns ACCESS_DENIED while any protocol on that child is
    // still open. Close it first, otherwise every request leaks a child handle
    // and its underlying TCP instance.
    {
        let st = uefi::table::system_table_raw().expect("no system table");
        let bs = unsafe { (*st.as_ptr()).boot_services };
        let status = unsafe {
            ((*bs).close_protocol)(
                child_handle.as_ptr(),
                &RawHttpProtocol::GUID,
                boot::image_handle().as_ptr(),
                core::ptr::null_mut(),
            )
        };
        if status != uefi::Status::SUCCESS {
            warn!("Failed to close HTTP protocol on child: {:?}", status);
        }
    }

    if let Err(e) = binding.destroy_child(child_handle) {
        warn!("Failed to destroy HTTP child handle: {:?}", e);
    }
    
    debug!("HTTP POST completed: {} bytes body, msg_type={:?}", body.len(), msg_type_header);
    Some(HttpPostResponse {
        body,
        auth_token: auth_header,
        message_type: msg_type_header,
    })
}

/// Extract Authorization header from raw HTTP headers
fn extract_authorization_header(headers: &[u8]) -> Option<String> {
    let headers_str = core::str::from_utf8(headers).ok()?;
    for line in headers_str.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("authorization:") {
            let value = line.splitn(2, ':').nth(1)?.trim();
            return Some(String::from(value));
        }
    }
    None
}

/// Test HTTP functionality
pub fn test_http() {
    info!("Looking for HTTP-capable NICs...");
    
    match find_http_nic() {
        Some(handle) => {
            info!("Found HTTP NIC: {:?}", handle);
            
            info!("Attempting HTTP GET: {}", TEST_URL);
            match http_get(TEST_URL) {
                Some(body) => {
                    info!("HTTP GET succeeded!");
                    info!("Body length: {} bytes", body.len());
                    
                    // Try to print as string if it looks like text
                    if body.len() < 256 && body.iter().all(|&b| b.is_ascii()) {
                        if let Ok(text) = core::str::from_utf8(&body) {
                            info!("Body text: {}", text);
                        }
                    } else {
                        let preview: Vec<u8> = body.iter().take(64).cloned().collect();
                        info!("Body preview: {:02x?}", preview);
                    }
                }
                None => {
                    warn!("HTTP GET failed");
                    warn!("Make sure HTTP server is running on host:");
                    warn!("  echo 'Hello from HTTP!' > /tmp/test.txt");
                    warn!("  cd /tmp && python3 -m http.server 8080");
                }
            }
        }
        None => {
            warn!("No HTTP-capable NIC found");
            warn!("Ensure QEMU has: -netdev user,id=net0 -device virtio-net-pci,netdev=net0");
            warn!("And OVMF has network drivers (virtio-rng-pci required)");
        }
    }
}
