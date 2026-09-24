// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// DNS resolver for UEFI environments.
//
// Implements a minimal DNS A-record resolver over EFI_UDP4_PROTOCOL.
// DNS server addresses are obtained from DHCP via EFI_IP4_CONFIG2_PROTOCOL.
// Results are cached to avoid repeated lookups.
//
// DNS wire format (RFC 1035):
//   Header: 12 bytes (ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)
//   Question: QNAME (label-encoded) + QTYPE(2) + QCLASS(2)
//   Answer: NAME + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA
//
// This module only queries A records (IPv4 addresses).

use alloc::string::String;
use alloc::vec::Vec;
use log::{debug, info, warn, error};

/// DNS header flags
const DNS_FLAG_RD: u16 = 0x0100;         // Recursion Desired
const DNS_FLAG_QR: u16 = 0x8000;         // Query Response
const DNS_RCODE_MASK: u16 = 0x000F;      // Response code mask

/// DNS record types
const DNS_TYPE_A: u16 = 1;               // IPv4 address
const DNS_CLASS_IN: u16 = 1;             // Internet

/// DNS server port
const DNS_PORT: u16 = 53;

/// Maximum DNS response size
const MAX_DNS_RESPONSE: usize = 512;

/// DNS query timeout in microseconds (3 seconds)
const DNS_TIMEOUT_US: u32 = 3_000_000;

/// Maximum number of cached entries
const MAX_CACHE_ENTRIES: usize = 16;

/// DNS query transaction ID counter
#[cfg(target_os = "uefi")]
static DNS_TX_ID: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(1);

// ─── DNS Packet Builder/Parser (pure, works on native + UEFI) ───

/// Encode a DNS name in label format: "www.example.com" → \x03www\x07example\x03com\x00
pub fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let len = label.len();
        if len > 63 {
            // Label too long — truncate (shouldn't happen in practice)
            buf.push(63);
            buf.extend_from_slice(&label.as_bytes()[..63]);
        } else {
            buf.push(len as u8);
            buf.extend_from_slice(label.as_bytes());
        }
    }
    buf.push(0); // Root label terminator
    buf
}

/// Build a DNS query packet for an A record lookup.
/// Returns the packet bytes and the transaction ID used.
pub fn build_dns_query(hostname: &str, tx_id: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);

    // Header (12 bytes)
    pkt.extend_from_slice(&tx_id.to_be_bytes());     // ID
    pkt.extend_from_slice(&DNS_FLAG_RD.to_be_bytes()); // Flags: standard query, recursion desired
    pkt.extend_from_slice(&1u16.to_be_bytes());       // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes());       // ANCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes());       // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes());       // ARCOUNT = 0

    // Question section
    pkt.extend_from_slice(&encode_dns_name(hostname));
    pkt.extend_from_slice(&DNS_TYPE_A.to_be_bytes());  // QTYPE = A
    pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes()); // QCLASS = IN

    pkt
}

/// Parse a DNS response and extract the first A record IPv4 address.
/// Returns None if no valid A record is found or the response is malformed.
pub fn parse_dns_response(data: &[u8], expected_id: u16) -> Option<[u8; 4]> {
    if data.len() < 12 {
        debug!("DNS: response too short ({} bytes)", data.len());
        return None;
    }

    // Parse header
    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);

    if id != expected_id {
        debug!("DNS: ID mismatch: expected {}, got {}", expected_id, id);
        return None;
    }

    if flags & DNS_FLAG_QR == 0 {
        debug!("DNS: response QR flag not set");
        return None;
    }

    let rcode = flags & DNS_RCODE_MASK;
    if rcode != 0 {
        debug!("DNS: server returned error code {}", rcode);
        return None;
    }

    if ancount == 0 {
        debug!("DNS: no answers in response");
        return None;
    }

    // Skip the question section
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_dns_name(data, pos)?;
        pos += 4; // QTYPE + QCLASS
        if pos > data.len() {
            return None;
        }
    }

    // Parse answer records — find the first A record
    for _ in 0..ancount {
        if pos >= data.len() {
            break;
        }

        // Skip/parse name (might be compressed)
        pos = skip_dns_name(data, pos)?;

        if pos + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        // TTL at pos+4..pos+8 (unused for now)
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > data.len() {
            break;
        }

        if rtype == DNS_TYPE_A && rclass == DNS_CLASS_IN && rdlength == 4 {
            let ip = [data[pos], data[pos + 1], data[pos + 2], data[pos + 3]];
            return Some(ip);
        }

        pos += rdlength;
    }

    debug!("DNS: no A record found in {} answers", ancount);
    None
}

/// Skip a DNS name at the given position (handles label compression).
/// Returns the new position after the name, or None if malformed.
fn skip_dns_name(data: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumps = 0;
    let mut end_pos: Option<usize> = None;

    loop {
        if pos >= data.len() {
            return None;
        }

        let len = data[pos] as usize;

        if len == 0 {
            // Root label — end of name
            pos += 1;
            break;
        } else if len & 0xC0 == 0xC0 {
            // Compression pointer (2 bytes)
            if pos + 1 >= data.len() {
                return None;
            }
            if end_pos.is_none() {
                end_pos = Some(pos + 2);
            }
            let offset = ((len & 0x3F) << 8) | data[pos + 1] as usize;
            pos = offset;
            jumps += 1;
            if jumps > 64 {
                // Prevent infinite loops
                return None;
            }
        } else {
            // Regular label
            pos += 1 + len;
        }
    }

    Some(end_pos.unwrap_or(pos))
}

/// Check if a string looks like an IPv4 address (4 dot-separated decimal octets)
pub fn is_ipv4_address(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

// ─── DNS Cache ───

/// A cached DNS result
struct DnsCacheEntry {
    hostname: String,
    ip: [u8; 4],
}

/// Simple DNS cache (static, no TTL eviction — fine for short-lived UEFI boot)
#[cfg(target_os = "uefi")]
static mut DNS_CACHE: Option<Vec<DnsCacheEntry>> = None;

/// Global DNS server address (set once after DHCP)
#[cfg(target_os = "uefi")]
static mut DNS_SERVER: Option<[u8; 4]> = None;

// ─── UEFI UDP4 Transport ───

#[cfg(target_os = "uefi")]
use uefi::boot;

#[cfg(target_os = "uefi")]
use uefi_raw::{Boolean, Ipv4Address, Status as RawStatus, Event};

/// EFI_UDP4_SERVICE_BINDING_PROTOCOL GUID
#[cfg(target_os = "uefi")]
const UDP4_SB_GUID: uefi::Guid = uefi::guid!("83f01464-99bd-45e5-b383-af6305d8e9e6");

/// EFI_UDP4_PROTOCOL GUID
#[cfg(target_os = "uefi")]
const UDP4_PROTOCOL_GUID: uefi::Guid = uefi::guid!("3ad9df29-4501-478d-b1f8-7f7fe70e50f3");

/// EFI_UDP4_CONFIG_DATA
#[cfg(target_os = "uefi")]
#[repr(C)]
struct Udp4ConfigData {
    accept_broadcast: Boolean,
    accept_promiscuous: Boolean,
    accept_any_port: Boolean,
    allow_duplicate_port: Boolean,
    type_of_service: u8,
    time_to_live: u8,
    do_not_fragment: Boolean,
    receive_timeout: u32,
    transmit_timeout: u32,
    use_default_address: Boolean,
    station_address: Ipv4Address,
    subnet_mask: Ipv4Address,
    station_port: u16,
    remote_address: Ipv4Address,
    remote_port: u16,
}

/// EFI_UDP4_SESSION_DATA
#[cfg(target_os = "uefi")]
#[repr(C)]
struct Udp4SessionData {
    source_address: Ipv4Address,
    source_port: u16,
    destination_address: Ipv4Address,
    destination_port: u16,
}

/// EFI_UDP4_FRAGMENT_DATA
#[cfg(target_os = "uefi")]
#[repr(C)]
struct Udp4FragmentData {
    fragment_length: u32,
    fragment_buffer: *mut core::ffi::c_void,
}

/// EFI_UDP4_TRANSMIT_DATA
#[cfg(target_os = "uefi")]
#[repr(C)]
struct Udp4TransmitData {
    udp_session_data: *mut Udp4SessionData,
    gateway_address: *mut Ipv4Address,
    data_length: u32,
    fragment_count: u32,
    fragment_table: [Udp4FragmentData; 1],
}

/// EFI_UDP4_RECEIVE_DATA
#[cfg(target_os = "uefi")]
#[repr(C)]
struct Udp4ReceiveData {
    timestamp: [u8; 16],             // EFI_TIME = 16 bytes
    recycle_signal: Event,
    udp_session: Udp4SessionData,
    data_length: u32,
    fragment_count: u32,
    fragment_table: [Udp4FragmentData; 1],
}

/// EFI_UDP4_COMPLETION_TOKEN
#[cfg(target_os = "uefi")]
#[repr(C)]
struct Udp4CompletionToken {
    event: Event,
    status: RawStatus,
    // Union: RxData or TxData pointer
    packet: *mut core::ffi::c_void,
}

/// EFI_UDP4_PROTOCOL function table
#[cfg(target_os = "uefi")]
#[repr(C)]
struct Udp4Protocol {
    get_mode_data: unsafe extern "efiapi" fn(
        this: *mut Self,
        config: *mut Udp4ConfigData,
        ip4_mode: *mut core::ffi::c_void,
        mnp_config: *mut core::ffi::c_void,
        snp_mode: *mut core::ffi::c_void,
    ) -> RawStatus,
    configure: unsafe extern "efiapi" fn(
        this: *mut Self,
        config: *mut Udp4ConfigData,
    ) -> RawStatus,
    groups: unsafe extern "efiapi" fn(
        this: *mut Self,
        join_flag: Boolean,
        multicast: *mut Ipv4Address,
    ) -> RawStatus,
    routes: unsafe extern "efiapi" fn(
        this: *mut Self,
        delete: Boolean,
        subnet: *mut Ipv4Address,
        mask: *mut Ipv4Address,
        gateway: *mut Ipv4Address,
    ) -> RawStatus,
    transmit: unsafe extern "efiapi" fn(
        this: *mut Self,
        token: *mut Udp4CompletionToken,
    ) -> RawStatus,
    receive: unsafe extern "efiapi" fn(
        this: *mut Self,
        token: *mut Udp4CompletionToken,
    ) -> RawStatus,
    cancel: unsafe extern "efiapi" fn(
        this: *mut Self,
        token: *mut Udp4CompletionToken,
    ) -> RawStatus,
    poll: unsafe extern "efiapi" fn(
        this: *mut Self,
    ) -> RawStatus,
}

/// ServiceBindingProtocol — same structure as TCP4
#[cfg(target_os = "uefi")]
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

/// Set the DNS server address (called after DHCP completes).
/// The address is obtained from Ip4Config2 DataType::DNS_SERVER.
#[cfg(target_os = "uefi")]
pub fn set_dns_server(ip: [u8; 4]) {
    unsafe {
        DNS_SERVER = Some(ip);
    }
    info!("DNS: server set to {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
}

/// Try to discover DNS server from Ip4Config2.
/// Should be called after DHCP completes.
#[cfg(target_os = "uefi")]
pub fn discover_dns_server() {
    use uefi::Identify;
    use uefi::proto::network::ip4config2::Ip4Config2;
    use uefi_raw::protocol::network::ip4_config2::Ip4Config2DataType;

    let handles = match boot::locate_handle_buffer(
        boot::SearchType::ByProtocol(&Ip4Config2::GUID)
    ) {
        Ok(h) => h,
        Err(_) => {
            warn!("DNS: No Ip4Config2 handles found");
            return;
        }
    };

    for handle in handles.iter() {
        if let Ok(mut ip4cfg) = Ip4Config2::new(*handle) {
            match ip4cfg.get_data(Ip4Config2DataType::DNS_SERVER) {
                Ok(data) => {
                    // Data is an array of EFI_IPv4_ADDRESS (4 bytes each)
                    if data.len() >= 4 {
                        let ip = [data[0], data[1], data[2], data[3]];
                        if ip != [0, 0, 0, 0] {
                            set_dns_server(ip);
                            return;
                        }
                    }
                    debug!("DNS: Ip4Config2 returned empty/zero DNS server");
                }
                Err(e) => {
                    debug!("DNS: Ip4Config2 get DNS_SERVER failed: {:?}", e);
                }
            }
        }
    }
    warn!("DNS: Could not discover DNS server from DHCP");
}

/// Resolve a hostname to an IPv4 address.
/// Returns the cached result if available, otherwise performs a UDP DNS query.
/// Returns None if resolution fails.
#[cfg(target_os = "uefi")]
pub fn dns_resolve(hostname: &str) -> Option<[u8; 4]> {
    // Fast path: already an IP address
    if is_ipv4_address(hostname) {
        let parts: Vec<&str> = hostname.split('.').collect();
        return Some([
            parts[0].parse().ok()?,
            parts[1].parse().ok()?,
            parts[2].parse().ok()?,
            parts[3].parse().ok()?,
        ]);
    }

    // Check cache
    unsafe {
        if let Some(ref cache) = DNS_CACHE {
            for entry in cache.iter() {
                if entry.hostname == hostname {
                    debug!("DNS: cache hit for {} → {}.{}.{}.{}",
                        hostname, entry.ip[0], entry.ip[1], entry.ip[2], entry.ip[3]);
                    return Some(entry.ip);
                }
            }
        }
    }

    // Need to query — get the DNS server
    let dns_server = unsafe { DNS_SERVER }?;

    info!("DNS: resolving {} via {}.{}.{}.{}",
        hostname, dns_server[0], dns_server[1], dns_server[2], dns_server[3]);

    let tx_id = DNS_TX_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let query = build_dns_query(hostname, tx_id);

    // Send query via UDP4 and get response
    let response = udp4_dns_query(&query, dns_server)?;

    // Parse response
    let ip = parse_dns_response(&response, tx_id)?;

    info!("DNS: {} → {}.{}.{}.{}",
        hostname, ip[0], ip[1], ip[2], ip[3]);

    // Cache the result
    unsafe {
        if DNS_CACHE.is_none() {
            DNS_CACHE = Some(Vec::new());
        }
        if let Some(ref mut cache) = DNS_CACHE {
            if cache.len() >= MAX_CACHE_ENTRIES {
                cache.remove(0); // Evict oldest
            }
            cache.push(DnsCacheEntry {
                hostname: String::from(hostname),
                ip,
            });
        }
    }

    Some(ip)
}

/// Perform a DNS query over UDP4 and return the raw response bytes.
#[cfg(target_os = "uefi")]
fn udp4_dns_query(query: &[u8], dns_server: [u8; 4]) -> Option<Vec<u8>> {
    // Find UDP4 ServiceBinding handles
    let sb_handles = match boot::locate_handle_buffer(
        boot::SearchType::ByProtocol(&UDP4_SB_GUID)
    ) {
        Ok(h) => h.to_vec(),
        Err(e) => {
            error!("DNS: No UDP4 ServiceBinding handles: {:?}", e);
            return None;
        }
    };
    debug!("DNS: Found {} UDP4 SB handle(s)", sb_handles.len());

    // Try each handle
    for (idx, sb_handle) in sb_handles.iter().enumerate() {
        match udp4_dns_query_on_handle(*sb_handle, query, dns_server) {
            Some(resp) => return Some(resp),
            None => {
                debug!("DNS: UDP4 SB handle #{} failed, trying next", idx);
            }
        }
    }

    error!("DNS: All UDP4 handles exhausted");
    None
}

/// Create a basic UEFI event via raw boot services (same pattern as TCP4).
#[cfg(target_os = "uefi")]
unsafe fn create_raw_event() -> Option<Event> {
    use uefi_raw::table::boot::{EventType, Tpl};

    let st = uefi::table::system_table_raw().expect("no system table");
    let bs = (*st.as_ptr()).boot_services;
    let mut event: Event = core::ptr::null_mut();

    let status = ((*bs).create_event)(
        EventType::empty(),
        Tpl::APPLICATION,
        None,
        core::ptr::null_mut(),
        &mut event,
    );
    if status != uefi::Status::SUCCESS {
        error!("DNS: CreateEvent failed: {:?}", status);
        return None;
    }
    Some(event)
}

/// Open ServiceBinding protocol on a handle using raw boot services.
#[cfg(target_os = "uefi")]
unsafe fn open_udp4_sb(sb_handle: uefi::Handle) -> Option<*mut ServiceBindingProtocol> {
    let mut sb_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
    let st = uefi::table::system_table_raw().expect("no system table");
    let bs = (*st.as_ptr()).boot_services;

    let status = ((*bs).open_protocol)(
        sb_handle.as_ptr(),
        &UDP4_SB_GUID,
        &mut sb_ptr,
        boot::image_handle().as_ptr(),
        core::ptr::null_mut(),
        0x02, // EFI_OPEN_PROTOCOL_GET_PROTOCOL
    );
    if status != uefi::Status::SUCCESS {
        error!("DNS: Failed to open UDP4 ServiceBinding: {:?}", status);
        return None;
    }
    Some(sb_ptr.cast::<ServiceBindingProtocol>())
}

/// Open UDP4 protocol on a child handle using raw boot services.
#[cfg(target_os = "uefi")]
unsafe fn open_udp4_protocol(child_handle: uefi_raw::Handle) -> Option<*mut Udp4Protocol> {
    let mut proto_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
    let st = uefi::table::system_table_raw().expect("no system table");
    let bs = (*st.as_ptr()).boot_services;

    let status = ((*bs).open_protocol)(
        child_handle,
        &UDP4_PROTOCOL_GUID,
        &mut proto_ptr,
        boot::image_handle().as_ptr(),
        core::ptr::null_mut(),
        0x02,
    );
    if status != uefi::Status::SUCCESS {
        error!("DNS: Failed to open UDP4 protocol: {:?}", status);
        return None;
    }
    Some(proto_ptr.cast::<Udp4Protocol>())
}

/// Try a DNS query on a specific UDP4 ServiceBinding handle.
#[cfg(target_os = "uefi")]
fn udp4_dns_query_on_handle(
    sb_handle: uefi::Handle,
    query: &[u8],
    dns_server: [u8; 4],
) -> Option<Vec<u8>> {
    use core::ptr;

    // Open ServiceBinding protocol
    let sb_ptr = unsafe { open_udp4_sb(sb_handle)? };

    // Create child handle
    let mut child_handle: uefi_raw::Handle = ptr::null_mut();
    let status = unsafe { ((*sb_ptr).create_child)(sb_ptr, &mut child_handle) };
    if status != RawStatus::SUCCESS {
        error!("DNS: CreateChild failed: {:?}", status);
        return None;
    }
    debug!("DNS: Created UDP4 child handle");

    // Open UDP4 protocol on child
    let udp4_ptr = match unsafe { open_udp4_protocol(child_handle) } {
        Some(p) => p,
        None => {
            unsafe { ((*sb_ptr).destroy_child)(sb_ptr, child_handle); }
            return None;
        }
    };

    // Configure: use default address, target DNS server on port 53
    let mut config = Udp4ConfigData {
        accept_broadcast: Boolean::FALSE,
        accept_promiscuous: Boolean::FALSE,
        accept_any_port: Boolean::FALSE,
        allow_duplicate_port: Boolean::TRUE,
        type_of_service: 0,
        time_to_live: 64,
        do_not_fragment: Boolean::FALSE,
        receive_timeout: DNS_TIMEOUT_US,
        transmit_timeout: DNS_TIMEOUT_US,
        use_default_address: Boolean::TRUE,
        station_address: Ipv4Address([0, 0, 0, 0]),
        subnet_mask: Ipv4Address([0, 0, 0, 0]),
        station_port: 0, // Ephemeral
        remote_address: Ipv4Address(dns_server),
        remote_port: DNS_PORT,
    };

    let status = unsafe { ((*udp4_ptr).configure)(udp4_ptr, &mut config) };
    if status != RawStatus::SUCCESS {
        error!("DNS: UDP4 Configure failed: {:?}", status);
        unsafe { ((*sb_ptr).destroy_child)(sb_ptr, child_handle); }
        return None;
    }
    debug!("DNS: UDP4 configured for {}.{}.{}.{}:{}", 
        dns_server[0], dns_server[1], dns_server[2], dns_server[3], DNS_PORT);

    // Create events for transmit and receive (raw boot services)
    let tx_event = match unsafe { create_raw_event() } {
        Some(e) => e,
        None => {
            error!("DNS: Failed to create TX event");
            unsafe { ((*sb_ptr).destroy_child)(sb_ptr, child_handle); }
            return None;
        }
    };

    let rx_event = match unsafe { create_raw_event() } {
        Some(e) => e,
        None => {
            error!("DNS: Failed to create RX event");
            unsafe { ((*sb_ptr).destroy_child)(sb_ptr, child_handle); }
            return None;
        }
    };

    // Prepare transmit data
    let mut tx_buf = query.to_vec();
    let mut tx_data = Udp4TransmitData {
        udp_session_data: ptr::null_mut(),  // Use configured remote
        gateway_address: ptr::null_mut(),
        data_length: tx_buf.len() as u32,
        fragment_count: 1,
        fragment_table: [Udp4FragmentData {
            fragment_length: tx_buf.len() as u32,
            fragment_buffer: tx_buf.as_mut_ptr() as *mut core::ffi::c_void,
        }],
    };

    let mut tx_token = Udp4CompletionToken {
        event: tx_event,
        status: RawStatus::NOT_READY,
        packet: &mut tx_data as *mut Udp4TransmitData as *mut core::ffi::c_void,
    };

    // Send the query
    let status = unsafe { ((*udp4_ptr).transmit)(udp4_ptr, &mut tx_token) };
    if status != RawStatus::SUCCESS {
        error!("DNS: UDP4 Transmit failed: {:?}", status);
        unsafe { ((*sb_ptr).destroy_child)(sb_ptr, child_handle); }
        return None;
    }

    // Poll until transmit completes
    for _ in 0..100 {
        unsafe { ((*udp4_ptr).poll)(udp4_ptr); }
        if tx_token.status != RawStatus::NOT_READY {
            break;
        }
        boot::stall(core::time::Duration::from_millis(10));
    }

    if tx_token.status != RawStatus::SUCCESS {
        error!("DNS: Transmit did not complete: {:?}", tx_token.status);
        unsafe { ((*sb_ptr).destroy_child)(sb_ptr, child_handle); }
        return None;
    }
    debug!("DNS: Query sent ({} bytes)", query.len());

    // Set up receive
    let mut rx_token = Udp4CompletionToken {
        event: rx_event,
        status: RawStatus::NOT_READY,
        packet: ptr::null_mut(),
    };

    let status = unsafe { ((*udp4_ptr).receive)(udp4_ptr, &mut rx_token) };
    if status != RawStatus::SUCCESS {
        error!("DNS: UDP4 Receive queue failed: {:?}", status);
        unsafe { ((*sb_ptr).destroy_child)(sb_ptr, child_handle); }
        return None;
    }

    // Poll until response arrives (with timeout)
    let mut received = false;
    for _ in 0..300 {  // 300 × 10ms = 3s timeout
        unsafe { ((*udp4_ptr).poll)(udp4_ptr); }
        if rx_token.status != RawStatus::NOT_READY {
            received = true;
            break;
        }
        boot::stall(core::time::Duration::from_millis(10));
    }

    let result = if received && rx_token.status == RawStatus::SUCCESS && !rx_token.packet.is_null() {
        // Extract response data from RxData
        let rx_data = rx_token.packet as *const Udp4ReceiveData;
        let data_len = unsafe { (*rx_data).data_length } as usize;
        let frag_count = unsafe { (*rx_data).fragment_count } as usize;

        if frag_count > 0 && data_len > 0 && data_len <= MAX_DNS_RESPONSE {
            let mut response = Vec::with_capacity(data_len);
            // Collect all fragments
            let frag_base = unsafe { &(*rx_data).fragment_table[0] };
            // For simplicity, handle the common case of single fragment
            if frag_count == 1 {
                let frag_len = frag_base.fragment_length as usize;
                let frag_ptr = frag_base.fragment_buffer as *const u8;
                if frag_len > 0 && frag_len <= MAX_DNS_RESPONSE {
                    unsafe {
                        response.extend_from_slice(
                            core::slice::from_raw_parts(frag_ptr, frag_len)
                        );
                    }
                }
            } else {
                // Multiple fragments — walk the variable-length array
                let frags = unsafe {
                    core::slice::from_raw_parts(
                        frag_base as *const Udp4FragmentData,
                        frag_count,
                    )
                };
                for frag in frags {
                    let flen = frag.fragment_length as usize;
                    if flen > 0 {
                        unsafe {
                            response.extend_from_slice(
                                core::slice::from_raw_parts(
                                    frag.fragment_buffer as *const u8,
                                    flen,
                                )
                            );
                        }
                    }
                }
            }

            debug!("DNS: Received {} bytes response", response.len());

            // Signal RecycleSignal via raw boot services
            let recycle = unsafe { (*rx_data).recycle_signal };
            if !recycle.is_null() {
                unsafe {
                    let st = uefi::table::system_table_raw().expect("no system table");
                    let bs = (*st.as_ptr()).boot_services;
                    let _ = ((*bs).signal_event)(recycle);
                }
            }

            Some(response)
        } else {
            warn!("DNS: Empty or oversized response (len={}, frags={})", data_len, frag_count);
            None
        }
    } else {
        if !received {
            warn!("DNS: Timeout waiting for response");
            // Cancel the pending receive
            unsafe { ((*udp4_ptr).cancel)(udp4_ptr, &mut rx_token); }
        } else {
            warn!("DNS: Receive failed: {:?}", rx_token.status);
        }
        None
    };

    // Cleanup: reconfigure to reset, then destroy child
    unsafe {
        ((*udp4_ptr).configure)(udp4_ptr, ptr::null_mut());
        ((*sb_ptr).destroy_child)(sb_ptr, child_handle);
    }

    result
}

// ─── Unit Tests ───

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_dns_name_basic() {
        let encoded = encode_dns_name("www.example.com");
        assert_eq!(encoded, b"\x03www\x07example\x03com\x00");
    }

    #[test]
    fn test_encode_dns_name_single_label() {
        let encoded = encode_dns_name("localhost");
        assert_eq!(encoded, b"\x09localhost\x00");
    }

    #[test]
    fn test_encode_dns_name_trailing_dot() {
        // "example.com." — trailing dot produces empty label which is skipped
        let encoded = encode_dns_name("example.com.");
        assert_eq!(encoded, b"\x07example\x03com\x00");
    }

    #[test]
    fn test_build_dns_query() {
        let pkt = build_dns_query("example.com", 0x1234);
        assert_eq!(pkt.len(), 12 + 13 + 4); // header + name + type/class
        // Check header
        assert_eq!(pkt[0..2], [0x12, 0x34]); // ID
        assert_eq!(pkt[2..4], [0x01, 0x00]); // Flags: RD
        assert_eq!(pkt[4..6], [0x00, 0x01]); // QDCOUNT = 1
        assert_eq!(pkt[6..8], [0x00, 0x00]); // ANCOUNT = 0
        // Check question
        assert_eq!(pkt[12], 7); // "example" length
        assert_eq!(&pkt[13..20], b"example");
        assert_eq!(pkt[20], 3); // "com" length
        assert_eq!(&pkt[21..24], b"com");
        assert_eq!(pkt[24], 0); // Root
        // QTYPE=A, QCLASS=IN
        assert_eq!(pkt[25..27], [0x00, 0x01]);
        assert_eq!(pkt[27..29], [0x00, 0x01]);
    }

    #[test]
    fn test_parse_dns_response_basic() {
        // Build a minimal valid DNS response for "example.com" → 93.184.216.34
        let mut resp = Vec::new();
        // Header
        resp.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        resp.extend_from_slice(&0x8180u16.to_be_bytes()); // Flags: QR=1, RD=1, RA=1
        resp.extend_from_slice(&1u16.to_be_bytes());      // QDCOUNT = 1
        resp.extend_from_slice(&1u16.to_be_bytes());      // ANCOUNT = 1
        resp.extend_from_slice(&0u16.to_be_bytes());      // NSCOUNT = 0
        resp.extend_from_slice(&0u16.to_be_bytes());      // ARCOUNT = 0
        // Question section
        resp.extend_from_slice(b"\x07example\x03com\x00");
        resp.extend_from_slice(&1u16.to_be_bytes());      // QTYPE = A
        resp.extend_from_slice(&1u16.to_be_bytes());      // QCLASS = IN
        // Answer section
        resp.extend_from_slice(&[0xC0, 0x0C]); // Name pointer to offset 12
        resp.extend_from_slice(&1u16.to_be_bytes());      // TYPE = A
        resp.extend_from_slice(&1u16.to_be_bytes());      // CLASS = IN
        resp.extend_from_slice(&300u32.to_be_bytes());     // TTL = 300
        resp.extend_from_slice(&4u16.to_be_bytes());       // RDLENGTH = 4
        resp.extend_from_slice(&[93, 184, 216, 34]);       // RDATA

        let ip = parse_dns_response(&resp, 0x1234);
        assert_eq!(ip, Some([93, 184, 216, 34]));
    }

    #[test]
    fn test_parse_dns_response_wrong_id() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&0x5678u16.to_be_bytes()); // Wrong ID
        resp.extend_from_slice(&0x8180u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        // Answer
        resp.extend_from_slice(b"\x04test\x00");
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&60u32.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&[10, 0, 0, 1]);

        assert_eq!(parse_dns_response(&resp, 0x1234), None);
    }

    #[test]
    fn test_parse_dns_response_nxdomain() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&0x1234u16.to_be_bytes());
        resp.extend_from_slice(&0x8183u16.to_be_bytes()); // RCODE = 3 (NXDOMAIN)
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        // Question only
        resp.extend_from_slice(b"\x07missing\x03com\x00");
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());

        assert_eq!(parse_dns_response(&resp, 0x1234), None);
    }

    #[test]
    fn test_parse_dns_response_too_short() {
        assert_eq!(parse_dns_response(&[0u8; 6], 0x1234), None);
    }

    #[test]
    fn test_parse_dns_response_no_qr_flag() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&0x1234u16.to_be_bytes());
        resp.extend_from_slice(&0x0100u16.to_be_bytes()); // QR=0 (this is a query, not response)
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());

        assert_eq!(parse_dns_response(&resp, 0x1234), None);
    }

    #[test]
    fn test_parse_dns_response_cname_then_a() {
        // Response with a CNAME record followed by an A record
        let mut resp = Vec::new();
        // Header
        resp.extend_from_slice(&0x1234u16.to_be_bytes());
        resp.extend_from_slice(&0x8180u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());  // QDCOUNT
        resp.extend_from_slice(&2u16.to_be_bytes());  // ANCOUNT = 2 (CNAME + A)
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        // Question
        resp.extend_from_slice(b"\x03www\x07example\x03com\x00");
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        // Answer 1: CNAME
        resp.extend_from_slice(&[0xC0, 0x0C]); // Name pointer
        resp.extend_from_slice(&5u16.to_be_bytes());   // TYPE = CNAME
        resp.extend_from_slice(&1u16.to_be_bytes());   // CLASS = IN
        resp.extend_from_slice(&300u32.to_be_bytes());
        let cname = b"\x07example\x03com\x00";
        resp.extend_from_slice(&(cname.len() as u16).to_be_bytes());
        resp.extend_from_slice(cname);
        // Answer 2: A record
        resp.extend_from_slice(b"\x07example\x03com\x00"); // Full name (not compressed here)
        resp.extend_from_slice(&1u16.to_be_bytes());   // TYPE = A
        resp.extend_from_slice(&1u16.to_be_bytes());   // CLASS = IN
        resp.extend_from_slice(&300u32.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&[93, 184, 216, 34]);

        let ip = parse_dns_response(&resp, 0x1234);
        assert_eq!(ip, Some([93, 184, 216, 34]));
    }

    #[test]
    fn test_is_ipv4_address() {
        assert!(is_ipv4_address("10.0.2.2"));
        assert!(is_ipv4_address("192.168.1.1"));
        assert!(is_ipv4_address("0.0.0.0"));
        assert!(is_ipv4_address("255.255.255.255"));
        assert!(!is_ipv4_address("example.com"));
        assert!(!is_ipv4_address("10.0.2"));
        assert!(!is_ipv4_address("10.0.2.2.1"));
        assert!(!is_ipv4_address("256.0.0.1"));
        assert!(!is_ipv4_address(""));
        assert!(!is_ipv4_address("abc.def.ghi.jkl"));
    }

    #[test]
    fn test_encode_dns_name_empty() {
        let encoded = encode_dns_name("");
        assert_eq!(encoded, b"\x00"); // Just the root terminator
    }

    #[test]
    fn test_parse_dns_response_multiple_questions() {
        // Technically unusual but valid: response with multiple questions
        let mut resp = Vec::new();
        resp.extend_from_slice(&0x1234u16.to_be_bytes());
        resp.extend_from_slice(&0x8180u16.to_be_bytes());
        resp.extend_from_slice(&2u16.to_be_bytes());  // QDCOUNT = 2
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        // Question 1
        resp.extend_from_slice(b"\x03foo\x03com\x00");
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        // Question 2
        resp.extend_from_slice(b"\x03bar\x03com\x00");
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        // Answer for question 1
        resp.extend_from_slice(b"\x03foo\x03com\x00");
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&60u32.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&[1, 2, 3, 4]);

        let ip = parse_dns_response(&resp, 0x1234);
        assert_eq!(ip, Some([1, 2, 3, 4]));
    }
}
