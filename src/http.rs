use alloc::string::String;
use alloc::vec::Vec;
use log::{info, warn, error, debug};
use uefi::boot;
use uefi::Identify;
use uefi::proto::network::http::{HttpBinding, HttpHelper};
use uefi::proto::network::ip4config2::Ip4Config2;

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
    
    info!("Found {} SNP handle(s), starting interface...", snp_handles.len());
    
    for handle in snp_handles.iter() {
        if let Ok(snp) = boot::open_protocol_exclusive::<SimpleNetwork>(*handle) {
            info!("SNP mode: {:?}", snp.mode());
            
            // Try to start the interface
            match snp.start() {
                Ok(_) => info!("SNP started successfully"),
                Err(e) => debug!("SNP start: {:?} (may already be started)", e),
            }
            
            // Initialize the interface
            match snp.initialize(0, 0) {
                Ok(_) => {
                    info!("SNP initialized successfully");
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
    info!("Connecting network controller recursively...");
    
    // Connect all drivers to this controller recursively
    // This should trigger IP4Dxe, TcpDxe, HttpDxe to bind
    let empty_list: &[Option<uefi::Handle>] = &[];
    match boot::connect_controller(handle, empty_list, None, true) {
        Ok(_) => {
            info!("Network controller connected successfully");
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
            info!("Found {} SNP (network driver) handle(s)", h.len());
            h
        }
        Err(_) => {
            warn!("No SNP handles found - network driver not loaded");
            return None;
        }
    };
    
    // Try to start SNP interface and get handle
    let snp_handle = match start_snp_interface() {
        Some(h) => h,
        None => {
            warn!("Could not start SNP interface");
            *snp_handles.first()?
        }
    };
    
    // Connect the network controller to trigger IP/HTTP driver binding
    connect_network_controller(snp_handle);
    
    // Check for IP4Config2 (IP stack)
    if let Ok(ip4_handles) = boot::locate_handle_buffer(boot::SearchType::ByProtocol(
        &Ip4Config2::GUID
    )) {
        info!("Found {} IP4Config2 handle(s)", ip4_handles.len());
    } else {
        warn!("No IP4Config2 handles after connect");
    }
    
    // Look for HTTP Service Binding Protocol handles
    match boot::locate_handle_buffer(boot::SearchType::ByProtocol(
        &HttpBinding::GUID
    )) {
        Ok(handles) => {
            info!("Found {} HTTP-capable NIC(s)", handles.len());
            handles.first().copied()
        }
        Err(_) => {
            warn!("No HTTP handles found after connect");
            None
        }
    }
}

/// Configure network via DHCP using IP4Config2
fn configure_network(nic_handle: uefi::Handle) -> bool {
    info!("Configuring network via DHCP...");
    
    match Ip4Config2::new(nic_handle) {
        Ok(mut ip4cfg) => {
            match ip4cfg.ifup() {
                Ok(()) => {
                    info!("Network configured successfully");
                    if let Ok(info) = ip4cfg.get_interface_info() {
                        info!("IP Address: {}", info.station_addr);
                    }
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
    
    info!("Using NIC handle for HTTP...");
    
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
    
    info!("Sending GET request to: {}", url);
    
    // Send GET request
    if let Err(e) = http.request_get(url) {
        error!("http.request_get() failed: {:?}", e);
        return None;
    }
    
    // Get response
    match http.response_first(true) {
        Ok(response) => {
            info!("HTTP Status: {:?}", response.status);
            
            let mut body = response.body;
            
            // Check if we need more data
            loop {
                match http.response_more(&mut body) {
                    Ok(chunk) => {
                        if chunk.is_empty() {
                            break;
                        }
                        info!("Received {} more bytes", chunk.len());
                    }
                    Err(_) => break,
                }
            }
            
            info!("Total body size: {} bytes", body.len());
            Some(body)
        }
        Err(e) => {
            error!("http.response_first() failed: {:?}", e);
            None
        }
    }
}

/// Perform HTTP POST request using raw UEFI HTTP protocol
/// This bypasses uefi-rs HttpHelper to access HttpMethod::POST
/// HTTP POST with session token support
/// Returns (body, authorization_header) where authorization_header can be used for subsequent requests
pub fn http_post_with_session(url: &str, body: &[u8], _msg_type: u8, auth_token: Option<&str>) -> Option<(Vec<u8>, Option<String>)> {
    let (response_body, auth_header) = http_post_internal(url, body, _msg_type, auth_token)?;
    Some((response_body, auth_header))
}

pub fn http_post(url: &str, body: &[u8], _msg_type: u8) -> Option<Vec<u8>> {
    http_post_internal(url, body, _msg_type, None).map(|(body, _)| body)
}

fn http_post_internal(url: &str, body: &[u8], _msg_type: u8, auth_token: Option<&str>) -> Option<(Vec<u8>, Option<String>)> {
    use alloc::string::String;
    use alloc::vec;
    use core::ffi::c_void;
    use uefi_raw::protocol::network::http::{
        HttpConfigData, HttpV4AccessPoint, HttpAccessPoint, HttpVersion,
        HttpHeader, HttpMessage, HttpRequestData, HttpRequestOrResponse,
        HttpToken, HttpMethod, HttpProtocol as RawHttpProtocol,
    };
    use uefi_raw::{Boolean, Ipv4Address};
    
    let nic_handle = find_http_nic()?;
    
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
    let auth_value_owned = auth_token.map(|t| alloc::format!("{}\0", t));
    
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
    let status = unsafe { ((*proto_ptr).request)(proto_ptr, &mut tx_token) };
    if status != uefi::Status::SUCCESS {
        error!("HTTP POST request failed: {:?}", status);
        return None;
    }
    
    // Poll until complete
    for _ in 0..300 {
        let poll_status = unsafe { ((*proto_ptr).poll)(proto_ptr) };
        if poll_status != uefi::Status::SUCCESS && poll_status != uefi::Status::NOT_READY {
            break;
        }
        boot::stall(core::time::Duration::from_millis(10));
    }
    debug!("Request sent");
    
    // Receive response
    let mut rx_body = vec![0u8; 16384];
    let mut rx_msg = HttpMessage {
        data: HttpRequestOrResponse { request: core::ptr::null() },
        header_count: 0,
        header: core::ptr::null_mut(),
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
    if status != uefi::Status::SUCCESS {
        error!("HTTP response failed: {:?}", status);
        return None;
    }
    
    // Poll until complete
    for _ in 0..300 {
        let poll_status = unsafe { ((*proto_ptr).poll)(proto_ptr) };
        if poll_status != uefi::Status::SUCCESS && poll_status != uefi::Status::NOT_READY {
            break;
        }
        boot::stall(core::time::Duration::from_millis(10));
    }
    
    let body_len = rx_msg.body_length;
    debug!("Response received: {} bytes", body_len);
    rx_body.truncate(body_len);
    
    // Parse HTTP response - extract body after headers and Authorization header
    // Headers end with \r\n\r\n
    let (body, auth_header) = if let Some(pos) = find_header_end(&rx_body) {
        debug!("Headers end at byte {}", pos);
        let headers_section = &rx_body[..pos];
        let auth = extract_authorization_header(headers_section);
        if auth.is_some() {
            debug!("Found Authorization header in response");
        }
        (rx_body[pos..].to_vec(), auth)
    } else {
        warn!("Could not find header end, returning raw response");
        (rx_body, None)
    };
    
    if !body.is_empty() {
        debug!("Body hex: {:02x?}", &body[..body.len().min(80)]);
    }
    
    info!("HTTP POST completed: {} bytes body", body.len());
    Some((body, auth_header))
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
