// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// FDO Device Initialization Protocol Implementation
//
// Minimal implementation for UEFI. Performs:
// 1. Create DAK (Device Attestation Key) in TPM
// 2. Create HMAC key in TPM
// 3. Generate CSR signed by TPM
// 4. Send DIAppStart with DeviceMfgInfo
// 5. Receive DISetCredentials with OVHeader
// 6. Compute HMAC over OVHeader
// 7. Send DISetHMAC
// 8. Receive DIDone
// 9. Write DCTPM to TPM NV index

use alloc::string::String;
use alloc::vec::Vec;
use alloc::vec;
use alloc::format;
use log::{info, error, warn};
use uefi::Status;

use crate::http_api::{http_post_with_session, HttpPostResponse};
use crate::tpm;
use super::mfginfo::{DeviceMfgInfo, KEY_TYPE_SECP256R1};

/// DI protocol message types (FDO 2.0)
const MSG_TYPE_DI_APP_START: u8 = 10;
const MSG_TYPE_DI_SET_CREDENTIALS: u8 = 11;
const MSG_TYPE_DI_SET_HMAC: u8 = 12;
const MSG_TYPE_DI_DONE: u8 = 13;

/// FDO 2.0 capability flags
const CAPABILITY_FLAGS_FDO20: u32 = 0x0001;

/// Default TPM persistent handles for DI key creation (per securing-fdo-in-tpm.bs).
/// These are recorded in DCTPM after creation. The TO2 path reads the actual
/// handles from DCTPM.DeviceKeyHandle / DCTPM.HMACKeyHandle — never hardcoded.
const FDO_DAK_HANDLE: u32 = 0x81020002;
const FDO_HMAC_HANDLE: u32 = 0x81020003;

/// TPM NV index for DCTPM (per securing-fdo-in-tpm.bs)
const FDO_NV_INDEX_DCTPM: u32 = 0x01D10001;

/// Run the Device Initialization protocol
/// If `cli_url` is Some, use that as the DI server URL (from -di flag).
/// Otherwise, try well-known DNS names.
pub fn run_di_protocol(cli_url: Option<&str>) -> Status {
    info!("===========================================");
    info!("  FDO Device Initialization (DI) Protocol");
    info!("===========================================");
    
    // 1. Get manufacturing server URL
    let mfg_server_url = match get_di_server_url(cli_url) {
        Some(url) => {
            info!("Manufacturing server: {}", url);
            url
        }
        None => {
            error!("No manufacturing server URL available");
            error!("  Use: fdo-uefi.efi -di http://server:port");
            return Status::NOT_FOUND;
        }
    };
    
    // 2. Create device key (DAK) in TPM and persist it in the same session
    info!("Creating and persisting device key in TPM...");
    let (dak_handle, public_x, public_y) = match tpm::tpm_create_and_persist_signing_key(FDO_DAK_HANDLE) {
        Some(key) => {
            info!("DAK created and persisted: handle=0x{:08x}", key.handle);
            (key.handle, key.public_x, key.public_y)
        }
        None => {
            error!("Failed to create device key in TPM");
            return Status::DEVICE_ERROR;
        }
    };
    
    // 3. HMAC key will be created later (must stay in same TCG2 session as HMAC computation)
    // The UEFI firmware resource manager flushes transient handles when the protocol is closed.
    
    // 4. Generate CSR using TPM-based signing
    info!("Generating CSR...");
    let serial_number = get_device_serial();
    let model = get_device_model();
    let csr_der = match generate_csr(&serial_number, &public_x, &public_y, dak_handle) {
        Some(csr) => {
            info!("CSR generated: {} bytes", csr.len());
            csr
        }
        None => {
            error!("Failed to generate CSR");
            tpm::tpm_flush_context(dak_handle);
            return Status::DEVICE_ERROR;
        }
    };
    
    // 5. Build DeviceMfgInfo
    let device_mfg_info = DeviceMfgInfo::new(serial_number.clone(), model.clone(), csr_der);
    let mfg_info_cbor = device_mfg_info.to_cbor();
    info!("DeviceMfgInfo: {} bytes", mfg_info_cbor.len());
    
    // 6. Send DIAppStart
    info!("Sending DIAppStart...");
    let app_start_msg = build_di_app_start(&mfg_info_cbor);
    let (set_credentials_response, session_token) = match send_di_message(&mfg_server_url, MSG_TYPE_DI_APP_START, &app_start_msg, None) {
        Some((msg_type, payload, token)) => {
            if msg_type != MSG_TYPE_DI_SET_CREDENTIALS {
                error!("Expected DISetCredentials ({}), got {}", MSG_TYPE_DI_SET_CREDENTIALS, msg_type);
                return Status::PROTOCOL_ERROR;
            }
            info!("Received DISetCredentials: {} bytes", payload.len());
            if let Some(ref t) = token {
                info!("Session token: {}...", &t[..t.len().min(20)]);
            }
            (payload, token)
        }
        None => {
            error!("Failed to send DIAppStart");
            return Status::PROTOCOL_ERROR;
        }
    };
    
    // 7. Parse DISetCredentials to get OVHeader
    let ov_header = match parse_di_set_credentials(&set_credentials_response) {
        Some(header) => {
            info!("OVHeader parsed: GUID={:02x?}", &header.guid);
            header
        }
        None => {
            error!("Failed to parse DISetCredentials");
            return Status::PROTOCOL_ERROR;
        }
    };
    
    // 8. Create HMAC key, compute HMAC, and persist — all in a SINGLE TCG2 session.
    // The UEFI firmware resource manager flushes transient handles when the
    // TCG2 protocol is closed, so CreatePrimary + HMAC + EvictControl must share one session.
    // CRITICAL: Use raw_cbor (exact bytes from server) so HMAC matches
    info!("Computing HMAC over OVHeader ({} bytes)...", ov_header.raw_cbor.len());
    let (hmac_handle, hmac_value) = match tpm::tpm_create_hmac_and_persist(&ov_header.raw_cbor, FDO_HMAC_HANDLE) {
        Some((handle, hmac)) => {
            info!("HMAC key created, HMAC computed, and key persisted: handle=0x{:08x}, {} bytes", handle, hmac.len());
            (handle, hmac)
        }
        None => {
            error!("Failed to compute HMAC");
            return Status::DEVICE_ERROR;
        }
    };
    
    // 9. Send DISetHMAC (with session token from step 6)
    info!("Sending DISetHMAC...");
    let set_hmac_msg = build_di_set_hmac(&hmac_value);
    match send_di_message(&mfg_server_url, MSG_TYPE_DI_SET_HMAC, &set_hmac_msg, session_token.as_deref()) {
        Some((msg_type, _payload, _token)) => {
            if msg_type != MSG_TYPE_DI_DONE {
                error!("Expected DIDone ({}), got {}", MSG_TYPE_DI_DONE, msg_type);
                return Status::PROTOCOL_ERROR;
            }
            info!("Received DIDone");
        }
        None => {
            error!("Failed to send DISetHMAC");
            return Status::PROTOCOL_ERROR;
        }
    };
    
    // 10. Keys already persisted in steps 2 and 8 (same TCG2 sessions)
    
    // 11. Write DCTPM to NV index
    info!("Writing DCTPM to TPM NV...");
    let dctpm = build_dctpm(&ov_header, FDO_DAK_HANDLE, FDO_HMAC_HANDLE);
    if !tpm::tpm_nv_write(FDO_NV_INDEX_DCTPM, &dctpm) {
        error!("Failed to write DCTPM to NV");
        return Status::DEVICE_ERROR;
    }
    
    info!("===========================================");
    info!("  Device Initialization COMPLETE");
    info!("  GUID: {:02x?}", ov_header.guid);
    info!("===========================================");
    
    Status::SUCCESS
}

/// Get DI (manufacturing) server URL.
/// Priority: 1) CLI flag, 2) well-known DNS names.
///
/// Well-known DNS names per fdo-appnote-device-mfg-info.bs:
///   _fdo._tcp   — DNS-SD style service discovery
///   fdo-mfg     — simple well-known hostname
///
/// TODO: Add UEFI variable "FdoMfgServerUrl" as additional source.
/// TODO: Actually attempt DNS resolution and connectivity test for each
///       well-known name before returning it (currently returns first name
///       without verification — the HTTP POST will fail if unreachable).
fn get_di_server_url(cli_url: Option<&str>) -> Option<String> {
    // 1) Explicit CLI override
    if let Some(url) = cli_url {
        info!("DI server: using CLI-provided URL");
        return Some(String::from(url));
    }

    // 2) Try well-known DNS names
    // NOTE: UEFI DNS resolution is not yet implemented, so these will
    // only work if a local DNS server resolves them. For now, log them
    // and return the first one. In practice, users should use -di flag.
    const WELL_KNOWN_DI_NAMES: &[&str] = &[
        "_fdo._tcp",
        "fdo-mfg",
    ];
    const DEFAULT_DI_PORT: u16 = 8080;

    for name in WELL_KNOWN_DI_NAMES {
        let url = format!("http://{}:{}", name, DEFAULT_DI_PORT);
        info!("DI server: will try well-known name: {}", url);
        return Some(url);
    }

    None
}

/// Get device serial number (placeholder)
fn get_device_serial() -> String {
    // TODO: Read from SMBIOS or UEFI variable
    String::from("UEFI-DI-TEST-001")
}

/// Get device model (placeholder)
fn get_device_model() -> String {
    // TODO: Read from SMBIOS or UEFI variable
    String::from("FDO UEFI Reference Device")
}

/// Build DIAppStart message (FDO 2.0)
/// go-fdo expects: [Info_bstr_or_null, CapabilityFlags]
/// where CapabilityFlags = [flags_bstr] (1-element array)
fn build_di_app_start(device_mfg_info: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(device_mfg_info.len() + 16);
    
    // Array of 2 elements: [Info, CapabilityFlags]
    buf.push(0x82);
    
    // Info: bstr .cbor DeviceMfgInfo (already bstr-wrapped)
    buf.extend_from_slice(device_mfg_info);
    
    // CapabilityFlags: [flags_bstr] = 1-element array
    buf.push(0x81); // array(1)
    // flags_bstr: single byte 0x04 = bit 2 set = FDO 2.0
    buf.push(0x41); // bstr(1)
    buf.push(0x04);
    
    buf
}

/// Build DISetHMAC message
/// Format: [Hash] where Hash = [hashType, hashValue]
fn build_di_set_hmac(hmac: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(hmac.len() + 8);
    
    // Array of 1 element (the Hash)
    buf.push(0x81);
    
    // Hash = [hashType, hashValue]
    buf.push(0x82);  // array(2)
    
    // hashType: -16 for HMAC-SHA256 (per FDO spec, negative = HMAC)
    buf.push(0x2F);  // negative(-16) = -1 - 15 = 0x20 | 0x0F
    
    // hashValue as bstr
    let len = hmac.len();
    if len < 24 {
        buf.push(0x40 | len as u8);
    } else if len < 256 {
        buf.push(0x58);
        buf.push(len as u8);
    } else {
        buf.push(0x59);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
    buf.extend_from_slice(hmac);
    
    buf
}

/// FDO error message type
const MSG_TYPE_ERROR: u8 = 255;

/// Send DI message with session token support
/// Returns (actual_message_type, body, auth_token)
fn send_di_message(server_url: &str, msg_type: u8, payload: &[u8], auth_token: Option<&str>) -> Option<(u8, Vec<u8>, Option<String>)> {
    let url = format!("{}/fdo/200/msg/{}", server_url, msg_type);
    
    match http_post_with_session(&url, payload, msg_type, auth_token) {
        Some(resp) => {
            // Use actual Message-Type header if available, otherwise assume msg_type + 1
            let response_type = resp.message_type.unwrap_or(msg_type + 1);
            
            // Check for error response
            if response_type == MSG_TYPE_ERROR {
                error!("Server returned error (Message-Type 255)");
                decode_fdo_error(&resp.body);
                return None;
            }
            
            Some((response_type, resp.body, resp.auth_token))
        }
        None => None,
    }
}

/// Decode and log FDO error response body
/// Error format: CBOR array [error_code, prev_msg_type, error_string, timestamp, correlation_id]
fn decode_fdo_error(body: &[u8]) {
    if body.is_empty() {
        error!("  (empty error body)");
        return;
    }
    
    let mut pos = 0;
    
    // Expect array of 5 elements
    if pos >= body.len() { return; }
    let first = body[pos];
    if (first >> 5) != 4 {
        error!("  Error body not a CBOR array (first byte: 0x{:02x})", first);
        return;
    }
    pos += 1;
    
    // [0] error_code (uint)
    let error_code = if pos < body.len() {
        let (val, consumed) = cbor_decode_uint(&body[pos..]);
        pos += consumed;
        val
    } else { 0 };
    
    // [1] prev_msg_type (uint)
    let prev_msg = if pos < body.len() {
        let (val, consumed) = cbor_decode_uint(&body[pos..]);
        pos += consumed;
        val
    } else { 0 };
    
    // [2] error_string (tstr)
    let error_str = if pos < body.len() {
        let major = body[pos] >> 5;
        if major == 3 {
            // text string
            let (s, consumed) = cbor_decode_tstr(&body[pos..]);
            pos += consumed;
            s
        } else {
            pos += 1;
            String::from("(not a text string)")
        }
    } else {
        String::from("(missing)")
    };
    
    error!("  FDO Error {}: msg_type={}, \"{}\"", error_code, prev_msg, error_str);
}

/// Decode a CBOR unsigned integer, returning (value, bytes_consumed)
fn cbor_decode_uint(data: &[u8]) -> (u32, usize) {
    if data.is_empty() { return (0, 0); }
    let additional = data[0] & 0x1f;
    match additional {
        0..=23 => (additional as u32, 1),
        24 => {
            if data.len() < 2 { return (0, 1); }
            (data[1] as u32, 2)
        }
        25 => {
            if data.len() < 3 { return (0, 1); }
            (((data[1] as u32) << 8) | data[2] as u32, 3)
        }
        26 => {
            if data.len() < 5 { return (0, 1); }
            (((data[1] as u32) << 24) | ((data[2] as u32) << 16) | ((data[3] as u32) << 8) | data[4] as u32, 5)
        }
        _ => (0, 1),
    }
}

/// Decode a CBOR text string, returning (string, bytes_consumed)
fn cbor_decode_tstr(data: &[u8]) -> (String, usize) {
    if data.is_empty() { return (String::new(), 0); }
    let additional = data[0] & 0x1f;
    let (str_len, header_len) = match additional {
        0..=23 => (additional as usize, 1usize),
        24 => {
            if data.len() < 2 { return (String::new(), 1); }
            (data[1] as usize, 2)
        }
        25 => {
            if data.len() < 3 { return (String::new(), 1); }
            (((data[1] as usize) << 8) | data[2] as usize, 3)
        }
        _ => return (String::new(), 1),
    };
    let end = header_len + str_len;
    if data.len() < end {
        return (String::new(), data.len());
    }
    let s = core::str::from_utf8(&data[header_len..end])
        .unwrap_or("(invalid utf8)");
    (String::from(s), end)
}

/// Parsed OVHeader from DISetCredentials
pub struct OVHeader {
    pub guid: [u8; 16],
    pub rv_info: Vec<u8>,
    pub device_info: String,
    pub pub_key: Vec<u8>,
    pub cert_chain_hash: Vec<u8>,
    /// Raw CBOR bytes as received from server (for HMAC computation)
    pub raw_cbor: Vec<u8>,
}

impl OVHeader {
    /// Encode OVHeader as CBOR for HMAC computation
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        
        // OVHeader is a CBOR array
        buf.push(0x85); // array(5)
        
        // [0] OVProtVer (200 for FDO 2.0)
        buf.push(0x18); // uint8
        buf.push(200);
        
        // [1] OVGuid (bstr)
        buf.push(0x50); // bstr(16)
        buf.extend_from_slice(&self.guid);
        
        // [2] OVRVInfo (bstr, pre-encoded)
        let rv_len = self.rv_info.len();
        if rv_len < 24 {
            buf.push(0x40 | rv_len as u8);
        } else if rv_len < 256 {
            buf.push(0x58);
            buf.push(rv_len as u8);
        } else {
            buf.push(0x59);
            buf.push((rv_len >> 8) as u8);
            buf.push(rv_len as u8);
        }
        buf.extend_from_slice(&self.rv_info);
        
        // [3] OVDeviceInfo (tstr)
        let info_len = self.device_info.len();
        if info_len < 24 {
            buf.push(0x60 | info_len as u8);
        } else if info_len < 256 {
            buf.push(0x78);
            buf.push(info_len as u8);
        } else {
            buf.push(0x79);
            buf.push((info_len >> 8) as u8);
            buf.push(info_len as u8);
        }
        buf.extend_from_slice(self.device_info.as_bytes());
        
        // [4] OVPublicKey (bstr, pre-encoded)
        let pk_len = self.pub_key.len();
        if pk_len < 24 {
            buf.push(0x40 | pk_len as u8);
        } else if pk_len < 256 {
            buf.push(0x58);
            buf.push(pk_len as u8);
        } else {
            buf.push(0x59);
            buf.push((pk_len >> 8) as u8);
            buf.push(pk_len as u8);
        }
        buf.extend_from_slice(&self.pub_key);
        
        // [5] OVCertChainHash (bstr)
        let hash_len = self.cert_chain_hash.len();
        if hash_len < 24 {
            buf.push(0x40 | hash_len as u8);
        } else if hash_len < 256 {
            buf.push(0x58);
            buf.push(hash_len as u8);
        } else {
            buf.push(0x59);
            buf.push((hash_len >> 8) as u8);
            buf.push(hash_len as u8);
        }
        buf.extend_from_slice(&self.cert_chain_hash);
        
        buf
    }
}

/// Parse DISetCredentials response to extract OVHeader
/// Wire format: CBOR array [bstr .cbor OVHeader]
/// OVHeader = [OVHProtVer, OVGuid, OVRVInfo, OVDeviceInfo, OVPubKey, OVDevCertChainHash]
fn parse_di_set_credentials(data: &[u8]) -> Option<OVHeader> {
    if data.is_empty() {
        error!("DISetCredentials: empty response");
        return None;
    }
    
    info!("DISetCredentials: parsing {} bytes", data.len());
    info!("DISetCredentials: first bytes: {:02x?}", &data[..data.len().min(32)]);
    
    let mut pos: usize = 0;
    
    // Outer wrapper: 1-element CBOR array [bstr]
    let outer_initial = data[pos];
    pos += 1;
    let outer_major = outer_initial >> 5;
    let outer_additional = outer_initial & 0x1f;
    
    if outer_major == 4 {
        // Array wrapper - read count (should be 1)
        let _count = if outer_additional < 24 {
            outer_additional as usize
        } else if outer_additional == 24 {
            let n = data[pos] as usize;
            pos += 1;
            n
        } else {
            error!("DISetCredentials: unsupported array size encoding");
            return None;
        };
        info!("DISetCredentials: outer array with {} element(s)", _count);
    } else {
        // No array wrapper, reset - the data might be just the bstr directly
        pos = 0;
    }
    
    // Read bstr containing OVHeader CBOR
    let ov_header_raw = cbor_read_bstr(data, &mut pos)?;
    info!("DISetCredentials: OVHeader bstr = {} bytes", ov_header_raw.len());
    
    // Parse the OVHeader array from inside the bstr
    parse_ov_header_cbor(&ov_header_raw)
}

/// Read a CBOR bstr value at the given position, advancing pos
fn cbor_read_bstr(data: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    if *pos >= data.len() {
        return None;
    }
    let initial = data[*pos];
    *pos += 1;
    let major = initial >> 5;
    let additional = initial & 0x1f;
    
    if major != 2 {
        error!("cbor_read_bstr: expected bstr (major 2), got major {}", major);
        return None;
    }
    
    let len = cbor_decode_additional(data, pos, additional)?;
    if *pos + len > data.len() {
        error!("cbor_read_bstr: length {} exceeds data ({})", len, data.len() - *pos);
        return None;
    }
    let result = data[*pos..*pos + len].to_vec();
    *pos += len;
    Some(result)
}

/// Read a CBOR tstr value at the given position, advancing pos
fn cbor_read_tstr(data: &[u8], pos: &mut usize) -> Option<String> {
    if *pos >= data.len() {
        return None;
    }
    let initial = data[*pos];
    *pos += 1;
    let major = initial >> 5;
    let additional = initial & 0x1f;
    
    if major != 3 {
        error!("cbor_read_tstr: expected tstr (major 3), got major {}", major);
        return None;
    }
    
    let len = cbor_decode_additional(data, pos, additional)?;
    if *pos + len > data.len() {
        return None;
    }
    let s = core::str::from_utf8(&data[*pos..*pos + len]).ok()?;
    *pos += len;
    Some(String::from(s))
}

/// Read a CBOR uint value at the given position, advancing pos
fn cbor_read_uint(data: &[u8], pos: &mut usize) -> Option<u64> {
    if *pos >= data.len() {
        return None;
    }
    let initial = data[*pos];
    *pos += 1;
    let major = initial >> 5;
    let additional = initial & 0x1f;
    
    if major != 0 {
        error!("cbor_read_uint: expected uint (major 0), got major {}", major);
        return None;
    }
    
    let val = cbor_decode_additional(data, pos, additional)?;
    Some(val as u64)
}

/// Decode CBOR additional info to get length/value
fn cbor_decode_additional(data: &[u8], pos: &mut usize, additional: u8) -> Option<usize> {
    match additional {
        n if n < 24 => Some(n as usize),
        24 => {
            if *pos >= data.len() { return None; }
            let v = data[*pos] as usize;
            *pos += 1;
            Some(v)
        }
        25 => {
            if *pos + 1 >= data.len() { return None; }
            let v = ((data[*pos] as usize) << 8) | (data[*pos + 1] as usize);
            *pos += 2;
            Some(v)
        }
        26 => {
            if *pos + 3 >= data.len() { return None; }
            let v = ((data[*pos] as usize) << 24) | ((data[*pos+1] as usize) << 16)
                  | ((data[*pos+2] as usize) << 8) | (data[*pos+3] as usize);
            *pos += 4;
            Some(v)
        }
        _ => {
            error!("cbor_decode_additional: unsupported additional {}", additional);
            None
        }
    }
}

/// Skip one CBOR value, advancing pos
fn cbor_skip_value(data: &[u8], pos: &mut usize) -> Option<()> {
    if *pos >= data.len() {
        return None;
    }
    let initial = data[*pos];
    *pos += 1;
    let major = initial >> 5;
    let additional = initial & 0x1f;
    
    let arg = cbor_decode_additional(data, pos, additional)?;
    
    match major {
        0 | 1 => { /* uint/negint - already consumed */ }
        2 | 3 => { *pos += arg; } // bstr/tstr
        4 => { // array
            for _ in 0..arg {
                cbor_skip_value(data, pos)?;
            }
        }
        5 => { // map
            for _ in 0..arg {
                cbor_skip_value(data, pos)?; // key
                cbor_skip_value(data, pos)?; // value
            }
        }
        6 => { cbor_skip_value(data, pos)?; } // tag
        7 => { /* simple/float */ }
        _ => return None,
    }
    Some(())
}

/// Capture raw bytes of a CBOR value without consuming
fn cbor_capture_value(data: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let start = *pos;
    cbor_skip_value(data, pos)?;
    Some(data[start..*pos].to_vec())
}

/// Parse OVHeader from CBOR bytes
/// OVHeader = [OVHProtVer, OVGuid, OVRVInfo, OVDeviceInfo, OVPubKey, OVDevCertChainHash]
fn parse_ov_header_cbor(data: &[u8]) -> Option<OVHeader> {
    let mut pos: usize = 0;
    
    // Read array header
    if pos >= data.len() { return None; }
    let initial = data[pos];
    pos += 1;
    let major = initial >> 5;
    let additional = initial & 0x1f;
    
    if major != 4 {
        error!("parse_ov_header: expected array (major 4), got {}", major);
        return None;
    }
    let count = cbor_decode_additional(data, &mut pos, additional)?;
    if count < 5 {
        error!("parse_ov_header: expected >= 5 elements, got {}", count);
        return None;
    }
    info!("parse_ov_header: {} elements", count);
    
    // [0] OVHProtVer (uint)
    let prot_ver = cbor_read_uint(data, &mut pos)?;
    info!("  OVHProtVer: {}", prot_ver);
    
    // [1] OVGuid (bstr, 16 bytes)
    let guid_bytes = cbor_read_bstr(data, &mut pos)?;
    if guid_bytes.len() != 16 {
        error!("parse_ov_header: GUID expected 16 bytes, got {}", guid_bytes.len());
        return None;
    }
    let mut guid = [0u8; 16];
    guid.copy_from_slice(&guid_bytes);
    info!("  OVGuid: {:02x?}", guid);
    
    // [2] OVRVInfo (RendezvousInfo - complex CBOR, capture raw)
    let rv_info = cbor_capture_value(data, &mut pos)?;
    info!("  OVRVInfo: {} bytes", rv_info.len());
    
    // [3] OVDeviceInfo (tstr)
    let device_info = cbor_read_tstr(data, &mut pos)?;
    info!("  OVDeviceInfo: {}", device_info);
    
    // [4] OVPubKey (PublicKey - complex CBOR, capture raw)
    let pub_key = cbor_capture_value(data, &mut pos)?;
    info!("  OVPubKey: {} bytes", pub_key.len());
    
    // [5] OVDevCertChainHash (Hash or null, capture raw)
    let cert_chain_hash = if count >= 6 {
        // Check for null
        if pos < data.len() && data[pos] == 0xf6 {
            pos += 1;
            info!("  OVDevCertChainHash: null");
            vec![0xf6] // preserve null encoding
        } else {
            let h = cbor_capture_value(data, &mut pos)?;
            info!("  OVDevCertChainHash: {} bytes", h.len());
            h
        }
    } else {
        vec![]
    };
    
    Some(OVHeader {
        guid,
        rv_info,
        device_info,
        pub_key,
        cert_chain_hash,
        raw_cbor: data.to_vec(),
    })
}

/// Build DCTPM structure for TPM NV storage
/// Per securing-fdo-in-tpm.bs
fn build_dctpm(ov_header: &OVHeader, dak_handle: u32, hmac_handle: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    
    // DCTPM = [DCTPMMagic, DCActive, ProtVer, DeviceInfo, GUID, RVInfo, PubKeyHash, 
    //          DeviceKeyType, DeviceKeyHandle, HMACKeyHandle]
    buf.push(0x8a); // array(10)
    
    // DCTPMMagic = 0x46444F31 ("FDO1")
    buf.push(0x1a); // uint32
    buf.extend_from_slice(&[0x46, 0x44, 0x4F, 0x31]);
    
    // DCActive = true
    buf.push(0xf5); // true
    
    // ProtVer = 200 (FDO 2.0)
    buf.push(0x18);
    buf.push(200);
    
    // DeviceInfo (tstr)
    let info = &ov_header.device_info;
    let len = info.len();
    if len < 24 {
        buf.push(0x60 | len as u8);
    } else {
        buf.push(0x78);
        buf.push(len as u8);
    }
    buf.extend_from_slice(info.as_bytes());
    
    // GUID (bstr)
    buf.push(0x50); // bstr(16)
    buf.extend_from_slice(&ov_header.guid);
    
    // RVInfo (bstr)
    let rv_len = ov_header.rv_info.len();
    if rv_len < 24 {
        buf.push(0x40 | rv_len as u8);
    } else {
        buf.push(0x58);
        buf.push(rv_len as u8);
    }
    buf.extend_from_slice(&ov_header.rv_info);
    
    // PubKeyHash (bstr) - hash of owner public key
    let hash_len = ov_header.cert_chain_hash.len();
    if hash_len < 24 {
        buf.push(0x40 | hash_len as u8);
    } else {
        buf.push(0x58);
        buf.push(hash_len as u8);
    }
    buf.extend_from_slice(&ov_header.cert_chain_hash);
    
    // DeviceKeyType = 0 (DAK)
    buf.push(0x00);
    
    // DeviceKeyHandle (uint32)
    buf.push(0x1a);
    buf.push((dak_handle >> 24) as u8);
    buf.push((dak_handle >> 16) as u8);
    buf.push((dak_handle >> 8) as u8);
    buf.push(dak_handle as u8);
    
    // HMACKeyHandle (uint32)
    buf.push(0x1a);
    buf.push((hmac_handle >> 24) as u8);
    buf.push((hmac_handle >> 16) as u8);
    buf.push((hmac_handle >> 8) as u8);
    buf.push(hmac_handle as u8);
    
    buf
}

/// Generate CSR (Certificate Signing Request) using TPM for signing
/// Returns DER-encoded PKCS#10 CSR
fn generate_csr(subject_cn: &str, public_x: &[u8], public_y: &[u8], sign_handle: u32) -> Option<Vec<u8>> {
    // Build CertificationRequestInfo (to-be-signed)
    let tbs = build_csr_tbs(subject_cn, public_x, public_y);
    
    // Hash TBS with SHA-256
    let tbs_hash = sha256(&tbs);
    
    // Sign with TPM using ECDSA
    let signature = tpm::tpm_sign_ecdsa(sign_handle, &tbs_hash)?;
    
    // Assemble complete CSR
    Some(assemble_csr_der(&tbs, &signature))
}

/// Build CertificationRequestInfo (to-be-signed portion of CSR)
fn build_csr_tbs(subject_cn: &str, public_x: &[u8], public_y: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    
    // CertificationRequestInfo ::= SEQUENCE
    let seq_start = buf.len();
    buf.push(0x30); // SEQUENCE
    buf.push(0x00); // length placeholder
    
    // version INTEGER (0)
    buf.extend_from_slice(&[0x02, 0x01, 0x00]);
    
    // subject Name (SEQUENCE of SET of AttributeTypeAndValue)
    // CN=<subject_cn>
    let subject = build_x509_name_cn(subject_cn);
    buf.extend_from_slice(&subject);
    
    // subjectPKInfo SubjectPublicKeyInfo for EC P-256
    let spki = build_ec_spki(public_x, public_y);
    buf.extend_from_slice(&spki);
    
    // attributes [0] (empty)
    buf.extend_from_slice(&[0xa0, 0x00]);
    
    // Update sequence length (may need long-form encoding)
    let seq_len = buf.len() - seq_start - 2;
    if seq_len < 128 {
        buf[seq_start + 1] = seq_len as u8;
    } else {
        // Need long-form: rebuild with correct length prefix
        let content = buf[seq_start + 2..].to_vec();
        buf.truncate(seq_start);
        buf.push(0x30);
        buf.push(0x81); // long-form, 1 length byte
        buf.push(seq_len as u8);
        buf.extend_from_slice(&content);
    }
    
    buf
}

/// Build X.509 Name with CN attribute
fn build_x509_name_cn(cn: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    
    // Name ::= SEQUENCE OF RelativeDistinguishedName
    buf.push(0x30); // SEQUENCE
    
    // RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
    let mut rdn = Vec::new();
    rdn.push(0x31); // SET
    
    // AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
    let mut atv = Vec::new();
    atv.push(0x30); // SEQUENCE
    atv.push(0x00); // length placeholder
    
    // type = id-at-commonName (2.5.4.3)
    atv.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03]);
    
    // value = UTF8String
    atv.push(0x0c); // UTF8String
    atv.push(cn.len() as u8);
    atv.extend_from_slice(cn.as_bytes());
    
    // Update ATV length
    let atv_len = atv.len() - 2;
    atv[1] = atv_len as u8;
    
    rdn.push(atv.len() as u8);
    rdn.extend_from_slice(&atv);
    
    buf.push(rdn.len() as u8);
    buf.extend_from_slice(&rdn);
    
    buf
}

/// Build SubjectPublicKeyInfo for EC P-256 key
fn build_ec_spki(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    
    // SubjectPublicKeyInfo ::= SEQUENCE
    buf.push(0x30); // SEQUENCE
    
    // AlgorithmIdentifier for EC P-256
    // SEQUENCE { algorithm = ecPublicKey (1.2.840.10045.2.1), parameters = secp256r1 (1.2.840.10045.3.1.7) }
    let alg_id: [u8; 21] = [
        0x30, 0x13,             // SEQUENCE (19 bytes)
        0x06, 0x07,             // OID (7 bytes)
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,  // 1.2.840.10045.2.1 (ecPublicKey)
        0x06, 0x08,             // OID (8 bytes)
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,  // 1.2.840.10045.3.1.7 (secp256r1)
    ];
    
    // subjectPublicKey BIT STRING containing uncompressed point (04 || x || y)
    let point_len = 1 + x.len() + y.len(); // 04 + x + y
    let bit_string_len = 1 + point_len;    // unused bits (0) + point
    
    // Calculate total SPKI length
    let spki_len = alg_id.len() + 2 + bit_string_len;
    buf.push(spki_len as u8);
    
    buf.extend_from_slice(&alg_id);
    
    // BIT STRING
    buf.push(0x03); // BIT STRING
    buf.push(bit_string_len as u8);
    buf.push(0x00); // unused bits
    buf.push(0x04); // uncompressed point
    buf.extend_from_slice(x);
    buf.extend_from_slice(y);
    
    buf
}

/// Assemble complete CSR DER from TBS and signature
fn assemble_csr_der(tbs: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(tbs.len() + signature.len() + 32);
    
    // CertificationRequest ::= SEQUENCE
    buf.push(0x30); // SEQUENCE
    
    // Will update length at end
    let len_pos = buf.len();
    buf.push(0x00); // placeholder
    
    // certificationRequestInfo
    buf.extend_from_slice(tbs);
    
    // signatureAlgorithm (ecdsa-with-SHA256 = 1.2.840.10045.4.3.2)
    let sig_alg: [u8; 12] = [
        0x30, 0x0a,             // SEQUENCE (10 bytes)
        0x06, 0x08,             // OID (8 bytes)
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,  // 1.2.840.10045.4.3.2
    ];
    buf.extend_from_slice(&sig_alg);
    
    // signature BIT STRING
    // ECDSA signature is DER-encoded SEQUENCE { r INTEGER, s INTEGER }
    let sig_der = encode_ecdsa_signature(signature);
    buf.push(0x03); // BIT STRING
    buf.push((sig_der.len() + 1) as u8);
    buf.push(0x00); // unused bits
    buf.extend_from_slice(&sig_der);
    
    // Update total length
    let total_len = buf.len() - len_pos - 1;
    if total_len < 128 {
        buf[len_pos] = total_len as u8;
    } else if total_len < 256 {
        // Long-form: 0x81 <len>
        let mut new_buf = Vec::with_capacity(buf.len() + 1);
        new_buf.push(0x30);
        new_buf.push(0x81);
        new_buf.push(total_len as u8);
        new_buf.extend_from_slice(&buf[len_pos + 1..]);
        return new_buf;
    } else {
        // Long-form: 0x82 <hi> <lo>
        let mut new_buf = Vec::with_capacity(buf.len() + 2);
        new_buf.push(0x30);
        new_buf.push(0x82);
        new_buf.push((total_len >> 8) as u8);
        new_buf.push(total_len as u8);
        new_buf.extend_from_slice(&buf[len_pos + 1..]);
        return new_buf;
    }
    
    buf
}

/// Encode ECDSA signature (r || s) as DER SEQUENCE { INTEGER r, INTEGER s }
fn encode_ecdsa_signature(sig: &[u8]) -> Vec<u8> {
    let half = sig.len() / 2;
    let r = &sig[..half];
    let s = &sig[half..];
    
    let r_der = encode_integer(r);
    let s_der = encode_integer(s);
    
    let mut buf = Vec::with_capacity(r_der.len() + s_der.len() + 4);
    buf.push(0x30); // SEQUENCE
    buf.push((r_der.len() + s_der.len()) as u8);
    buf.extend_from_slice(&r_der);
    buf.extend_from_slice(&s_der);
    
    buf
}

/// Encode bytes as DER INTEGER (handling sign bit)
fn encode_integer(bytes: &[u8]) -> Vec<u8> {
    // Skip leading zeros but keep at least one byte
    let mut start = 0;
    while start < bytes.len() - 1 && bytes[start] == 0 {
        start += 1;
    }
    
    let need_pad = bytes[start] & 0x80 != 0;
    let len = bytes.len() - start + if need_pad { 1 } else { 0 };
    
    let mut buf = Vec::with_capacity(len + 2);
    buf.push(0x02); // INTEGER
    buf.push(len as u8);
    if need_pad {
        buf.push(0x00);
    }
    buf.extend_from_slice(&bytes[start..]);
    
    buf
}

/// Compute SHA-256 hash
fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}
