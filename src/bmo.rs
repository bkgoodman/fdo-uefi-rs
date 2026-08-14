// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// BMO (Bare Metal Onboarding) FSIM Client Implementation
//
// This module implements the device-side handling of the fdo.bmo Service Info Module
// for receiving and booting firmware images during FDO TO2 onboarding.

use log::{info, warn, error};
use alloc::vec::Vec;
use alloc::string::{String, ToString};

use crate::fdo::{CborDecoder, CborEncoder};

/// BMO delivery modes
pub const BMO_DELIVERY_INLINE: u8 = 0;   // Chunked transfer over FDO channel
pub const BMO_DELIVERY_URL: u8 = 1;      // Device fetches from URL
pub const BMO_DELIVERY_META_URL: u8 = 2; // Device fetches signed meta-payload

/// BMO error codes per fdo.bmo.md
pub const BMO_ERROR_UNKNOWN_IMAGE_TYPE: u8 = 1;
pub const BMO_ERROR_INVALID_FORMAT: u8 = 2;
pub const BMO_ERROR_SIZE_EXCEEDED: u8 = 3;
pub const BMO_ERROR_BOOT_FAILED: u8 = 4;
pub const BMO_ERROR_TRANSFER_ERROR: u8 = 5;
pub const BMO_ERROR_SECURE_BOOT_VIOLATION: u8 = 6;
pub const BMO_ERROR_URL_FETCH_FAILED: u8 = 9;
pub const BMO_ERROR_HASH_MISMATCH: u8 = 11;
pub const BMO_ERROR_DELIVERY_MODE_NOT_SUPPORTED: u8 = 14;

/// BMO result status codes
pub const BMO_STATUS_SUCCESS: u8 = 0;
pub const BMO_STATUS_WARNING: u8 = 1;
pub const BMO_STATUS_ERROR: u8 = 2;

/// BMO ServiceInfo key names
pub const BMO_KEY_IMAGE_BEGIN: &str = "fdo.bmo:image-begin";
pub const BMO_KEY_IMAGE_DATA: &str = "fdo.bmo:image-data-";
pub const BMO_KEY_IMAGE_END: &str = "fdo.bmo:image-end";
pub const BMO_KEY_IMAGE_RESULT: &str = "fdo.bmo:image-result";
pub const BMO_KEY_IMAGE_ACK: &str = "fdo.bmo:image-ack";
pub const BMO_KEY_SET: &str = "fdo.bmo:set";
pub const BMO_KEY_SET_RESPONSE: &str = "fdo.bmo:set-response";

/// BMO BeginMessage field keys (negative integers for FSIM-specific)
pub const BMO_FIELD_IMAGE_TYPE: i8 = -1;    // MIME type (required)
pub const BMO_FIELD_BOOT_ARGS: i8 = -2;     // Kernel arguments (optional)
pub const BMO_FIELD_NAME: i8 = -3;          // Image name (optional)
pub const BMO_FIELD_HASH_EXPECTED: i8 = -4; // Expected hash (optional)
pub const BMO_FIELD_HASH_ALG: i8 = -5;      // Hash algorithm (optional)
pub const BMO_FIELD_DELIVERY_MODE: i8 = -6; // Delivery mode (optional, default 0)
pub const BMO_FIELD_URL: i8 = -7;           // URL for mode 1 (optional)
pub const BMO_FIELD_TLS_CA: i8 = -8;        // TLS CA cert for URL (optional)
pub const BMO_FIELD_META_URL: i8 = -9;      // Meta-URL for mode 2 (optional)
pub const BMO_FIELD_SIGNER_KEY: i8 = -10;   // Signer key for mode 2 (optional)

/// Generic chunking field keys (non-negative)
pub const CHUNK_FIELD_TOTAL_SIZE: u8 = 0;   // Total bytes
pub const CHUNK_FIELD_HASH_ALG: u8 = 1;     // Hash algorithm
pub const CHUNK_FIELD_METADATA: u8 = 2;     // Optional metadata
pub const CHUNK_FIELD_REQUIRE_ACK: u8 = 3;  // Require acknowledgment

/// Parsed BMO image-begin message
#[derive(Debug, Default)]
pub struct BmoImageBegin {
    // Generic chunking fields
    pub total_size: u64,
    pub hash_alg: Option<String>,
    pub require_ack: bool,
    
    // BMO-specific fields
    pub image_type: Option<String>,
    pub boot_args: Option<String>,
    pub name: Option<String>,
    pub expected_hash: Option<Vec<u8>>,
    pub delivery_mode: u8,
    pub url: Option<String>,
    pub tls_ca: Option<Vec<u8>>,
    pub meta_url: Option<String>,
    pub signer_key: Option<Vec<u8>>,
}

/// BMO session state
#[derive(Debug)]
pub struct BmoSession {
    pub state: BmoState,
    pub begin: Option<BmoImageBegin>,
    pub image_buffer: Vec<u8>,
    pub chunks_received: u32,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BmoState {
    Idle,
    AwaitingData,
    AwaitingEnd,
    Complete,
    Error,
}

impl BmoSession {
    pub fn new() -> Self {
        BmoSession {
            state: BmoState::Idle,
            begin: None,
            image_buffer: Vec::new(),
            chunks_received: 0,
            bytes_received: 0,
        }
    }
    
    pub fn reset(&mut self) {
        self.state = BmoState::Idle;
        self.begin = None;
        self.image_buffer.clear();
        self.chunks_received = 0;
        self.bytes_received = 0;
    }
}

/// Parse a ServiceInfo key/value pair from CBOR
/// ServiceInfo format: [key_string, value_bytes]
pub fn parse_service_info_kv(data: &[u8]) -> Option<(String, Vec<u8>)> {
    let mut dec = CborDecoder::new(data);
    
    // ServiceInfo is an array of [key, value]
    let arr_len = dec.read_array_header().ok()?;
    if arr_len != 2 {
        return None;
    }
    
    let key = dec.read_text().ok()?;
    let value = dec.read_bytes().ok()?;
    
    Some((key, value))
}

/// Parse BMO image-begin message body
/// Format: CBOR map with integer keys
pub fn parse_bmo_image_begin(data: &[u8]) -> Option<BmoImageBegin> {
    info!("BMO: Parsing image-begin ({} bytes)", data.len());
    
    let mut dec = CborDecoder::new(data);
    let mut begin = BmoImageBegin::default();
    
    // Read map header
    let map_len = dec.read_map_header().ok()?;
    info!("BMO: image-begin has {} map entries", map_len);
    
    for i in 0..map_len {
        // Read key (can be positive or negative integer)
        let key = match dec.read_int() {
            Ok(k) => {
                info!("BMO: map entry {} key = {}", i, k);
                k
            }
            Err(e) => {
                error!("BMO: failed to read key for entry {}: {:?}", i, e);
                return None;
            }
        };
        
        match key {
            // Generic chunking fields (non-negative)
            0 => {
                // total_size
                begin.total_size = dec.read_uint().ok()? as u64;
                info!("BMO: total_size = {}", begin.total_size);
            }
            1 => {
                // hash_alg
                begin.hash_alg = Some(dec.read_text().ok()?);
                info!("BMO: hash_alg = {:?}", begin.hash_alg);
            }
            3 => {
                // require_ack
                begin.require_ack = dec.read_bool().ok()?;
                info!("BMO: require_ack = {}", begin.require_ack);
            }
            
            // BMO-specific fields (negative keys)
            -1 => {
                // image_type (required)
                begin.image_type = Some(dec.read_text().ok()?);
                info!("BMO: image_type = {:?}", begin.image_type);
            }
            -2 => {
                // boot_args
                begin.boot_args = Some(dec.read_text().ok()?);
                info!("BMO: boot_args = {:?}", begin.boot_args);
            }
            -3 => {
                // name
                begin.name = Some(dec.read_text().ok()?);
                info!("BMO: name = {:?}", begin.name);
            }
            -4 => {
                // expected_hash
                begin.expected_hash = Some(dec.read_bytes().ok()?);
                info!("BMO: expected_hash = {} bytes", begin.expected_hash.as_ref().map(|h| h.len()).unwrap_or(0));
            }
            -5 => {
                // hash_alg (FSIM-specific, overrides generic)
                begin.hash_alg = Some(dec.read_text().ok()?);
            }
            -6 => {
                // delivery_mode
                begin.delivery_mode = dec.read_uint().ok()? as u8;
                info!("BMO: delivery_mode = {}", begin.delivery_mode);
            }
            -7 => {
                // url (for mode 1)
                begin.url = Some(dec.read_text().ok()?);
                info!("BMO: url = {:?}", begin.url);
            }
            -8 => {
                // tls_ca
                begin.tls_ca = Some(dec.read_bytes().ok()?);
            }
            -9 => {
                // meta_url (for mode 2)
                begin.meta_url = Some(dec.read_text().ok()?);
                info!("BMO: meta_url = {:?}", begin.meta_url);
            }
            -10 => {
                // signer_key
                begin.signer_key = Some(dec.read_bytes().ok()?);
            }
            _ => {
                // Skip unknown fields
                dec.skip_value().ok()?;
            }
        }
    }
    
    Some(begin)
}

/// Build BMO image-result message
/// Format: [status_code] or [status_code, message]
pub fn build_bmo_image_result(status: u8, message: Option<&str>) -> Vec<u8> {
    let mut enc = CborEncoder::new();
    
    if let Some(msg) = message {
        enc.array(2);
        enc.uint(status as u16);
        enc.text(msg);
    } else {
        enc.array(1);
        enc.uint(status as u16);
    }
    
    enc.into_bytes()
}

/// Build BMO image-ack message (for RequireAck=true)
/// Format: [accepted, ?reason_code, ?message]
pub fn build_bmo_image_ack(accepted: bool, reason_code: Option<u8>, message: Option<&str>) -> Vec<u8> {
    let mut enc = CborEncoder::new();
    
    if accepted {
        enc.array(1);
        enc.bool_val(true);
    } else {
        if let Some(msg) = message {
            enc.array(3);
            enc.bool_val(false);
            enc.uint(reason_code.unwrap_or(0) as u16);
            enc.text(msg);
        } else if let Some(code) = reason_code {
            enc.array(2);
            enc.bool_val(false);
            enc.uint(code as u16);
        } else {
            enc.array(1);
            enc.bool_val(false);
        }
    }
    
    enc.into_bytes()
}

/// Build a ServiceInfo key/value response
/// Format: [key_string, value_bytes]
pub fn build_service_info_kv(key: &str, value: &[u8]) -> Vec<u8> {
    let mut enc = CborEncoder::new();
    enc.array(2);
    enc.text(key);
    enc.bytes(value);
    enc.into_bytes()
}

/// Process BMO ServiceInfo message from owner
/// Returns optional response ServiceInfo to send back
pub fn process_bmo_message(
    session: &mut BmoSession,
    key: &str,
    value: &[u8],
) -> Option<(String, Vec<u8>)> {
    info!("BMO: Processing message key='{}', value={} bytes", key, value.len());
    
    match key {
        BMO_KEY_IMAGE_BEGIN => {
            // Parse the image-begin message
            if let Some(begin) = parse_bmo_image_begin(value) {
                info!("BMO: Received image-begin");
                info!("  image_type: {:?}", begin.image_type);
                info!("  delivery_mode: {}", begin.delivery_mode);
                info!("  total_size: {}", begin.total_size);
                info!("  require_ack: {}", begin.require_ack);
                
                // Store begin info
                session.begin = Some(begin);
                session.state = BmoState::AwaitingData;
                session.image_buffer.clear();
                session.chunks_received = 0;
                session.bytes_received = 0;
                
                // If require_ack, send ack response
                if session.begin.as_ref().map(|b| b.require_ack).unwrap_or(false) {
                    let ack = build_bmo_image_ack(true, None, None);
                    return Some((BMO_KEY_IMAGE_ACK.to_string(), ack));
                }
            } else {
                error!("BMO: Failed to parse image-begin");
                session.state = BmoState::Error;
            }
            None
        }
        
        k if k.starts_with(BMO_KEY_IMAGE_DATA) => {
            // image-data-N message - append to buffer
            // The chunk value is CBOR bstr-encoded by the server's chunking layer,
            // so we need to decode it to get the raw image bytes.
            if session.state != BmoState::AwaitingData {
                warn!("BMO: Unexpected image-data in state {:?}", session.state);
                return None;
            }
            
            // Try CBOR bstr decode; fall back to raw if it fails
            let chunk_data = if !value.is_empty() && (value[0] & 0xe0) == 0x40 {
                // CBOR major type 2 (byte string) — decode inner bytes
                match CborDecoder::new(value).read_bytes() {
                    Ok(inner) => {
                        info!("BMO: Decoded CBOR bstr chunk: {} -> {} bytes", value.len(), inner.len());
                        inner
                    }
                    Err(_) => {
                        warn!("BMO: CBOR bstr decode failed, using raw value");
                        value.to_vec()
                    }
                }
            } else {
                value.to_vec()
            };
            
            session.image_buffer.extend_from_slice(&chunk_data);
            session.chunks_received += 1;
            session.bytes_received += chunk_data.len() as u64;
            
            info!("BMO: Received chunk {}, {} bytes (total: {} bytes)", 
                  session.chunks_received, chunk_data.len(), session.bytes_received);
            
            None
        }
        
        BMO_KEY_IMAGE_END => {
            // Transfer complete
            if session.state != BmoState::AwaitingData {
                warn!("BMO: Unexpected image-end in state {:?}", session.state);
                let result = build_bmo_image_result(BMO_STATUS_ERROR, Some("Unexpected image-end"));
                return Some((BMO_KEY_IMAGE_RESULT.to_string(), result));
            }
            
            session.state = BmoState::Complete;
            
            info!("BMO: Transfer complete!");
            info!("  Total chunks: {}", session.chunks_received);
            info!("  Total bytes: {}", session.bytes_received);
            
            // Verify size if specified
            if let Some(ref begin) = session.begin {
                if begin.total_size > 0 && session.bytes_received != begin.total_size {
                    error!("BMO: Size mismatch! Expected {}, got {}", 
                           begin.total_size, session.bytes_received);
                    let result = build_bmo_image_result(BMO_STATUS_ERROR, Some("Size mismatch"));
                    return Some((BMO_KEY_IMAGE_RESULT.to_string(), result));
                }
            }
            
            // TODO: Hash verification
            // TODO: Chainload the image
            
            info!("BMO: Image ready for boot ({} bytes)", session.image_buffer.len());
            
            // Send success result
            let result = build_bmo_image_result(BMO_STATUS_SUCCESS, Some("Image received"));
            Some((BMO_KEY_IMAGE_RESULT.to_string(), result))
        }
        
        BMO_KEY_SET => {
            // BIOS parameter setting
            info!("BMO: Received set message ({} bytes)", value.len());
            // TODO: Parse and handle BIOS parameters
            None
        }
        
        _ => {
            info!("BMO: Unknown key '{}', ignoring", key);
            None
        }
    }
}

/// Test BMO state machine with mock data
/// This can be called to verify BMO handling without a real server
pub fn test_bmo_handling() {
    info!("=== BMO Test: Starting mock BMO message test ===");
    
    let mut session = BmoSession::new();
    
    // Simulate fdo.bmo:active
    info!("Test 1: Processing fdo.bmo:active");
    let active_value = alloc::vec![0xf5]; // CBOR true
    let result = process_bmo_message(&mut session, "fdo.bmo:active", &active_value);
    info!("  Result: {:?}", result.is_some());
    
    // Simulate fdo.bmo:image-begin with inline delivery
    info!("Test 2: Processing fdo.bmo:image-begin");
    let mut begin_msg = Vec::new();
    // CBOR map: {-1: "application/x-uefi-image", -6: 0, 0: 100}
    // Key 0 = total_size (generic chunking), Key -1 = image_type, Key -6 = delivery_mode
    begin_msg.push(0xa3); // map(3)
    begin_msg.push(0x20); // -1 (image type)
    begin_msg.extend_from_slice(b"\x78\x18application/x-uefi-image"); // text(24)
    begin_msg.push(0x25); // -6 (delivery mode)
    begin_msg.push(0x00); // 0 (inline)
    begin_msg.push(0x00); // 0 (total_size key - generic chunking field)
    begin_msg.push(0x18); // uint8
    begin_msg.push(0x64); // 100 bytes
    
    let result = process_bmo_message(&mut session, BMO_KEY_IMAGE_BEGIN, &begin_msg);
    info!("  Result: {:?}", result.is_some());
    info!("  State: {:?}", session.state);
    
    // Simulate image data chunks
    info!("Test 3: Processing fdo.bmo:image-data chunks");
    let chunk_data: Vec<u8> = (0u8..50).collect();
    let result = process_bmo_message(&mut session, "fdo.bmo:image-data-0", &chunk_data);
    info!("  Chunk 0 result: {:?}, bytes_received: {}", result.is_some(), session.bytes_received);
    
    let chunk_data: Vec<u8> = (50u8..100).collect();
    let result = process_bmo_message(&mut session, "fdo.bmo:image-data-1", &chunk_data);
    info!("  Chunk 1 result: {:?}, bytes_received: {}", result.is_some(), session.bytes_received);
    
    // Simulate image-end
    info!("Test 4: Processing fdo.bmo:image-end");
    let end_msg = alloc::vec![0xf6]; // CBOR null
    let result = process_bmo_message(&mut session, BMO_KEY_IMAGE_END, &end_msg);
    info!("  Result: {:?}", result.is_some());
    info!("  Final state: {:?}", session.state);
    info!("  Image buffer size: {} bytes", session.image_buffer.len());
    
    info!("=== BMO Test: Complete ===");
}
