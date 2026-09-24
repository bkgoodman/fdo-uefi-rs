// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// BMO (Bare Metal Onboarding) FSIM Client Implementation
//
// This module implements the device-side handling of the fdo.bmo Service Info Module
// for receiving and booting firmware images during FDO TO2 onboarding.

use log::{info, warn, error, debug};
use alloc::vec::Vec;
use alloc::format;
use alloc::string::{String, ToString};
use sha2::{Sha256, Digest};

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
pub const BMO_KEY_SET_RESPONSE: &str = "fdo.bmo:response";

/// BMO ImageBegin field keys (negative integers for FSIM-specific).
///
/// These MUST match the "ImageBegin Schema Extensions" table in
/// fdo-sim/fsim-repository/fdo.bmo.md and `FSIMFields[...]` in
/// go-fdo/fsim/bmo_owner.go. They are `i32` so they can be used directly as
/// match patterns in `parse_bmo_image_begin`, which is what keeps the parser
/// and this table from drifting apart.
pub const BMO_FIELD_IMAGE_TYPE: i32 = -1;     // MIME type (required)
pub const BMO_FIELD_BOOT_ARGS: i32 = -2;      // Kernel arguments (optional)
pub const BMO_FIELD_NAME: i32 = -3;           // Image name (optional, informational)
pub const BMO_FIELD_VERSION: i32 = -4;        // Version string (optional, informational)
pub const BMO_FIELD_DESCRIPTION: i32 = -5;    // Description (optional, informational)
pub const BMO_FIELD_DELIVERY_MODE: i32 = -6;  // Delivery mode (optional, default 0)
pub const BMO_FIELD_URL: i32 = -7;            // URL for modes 1 and 2 (optional)
pub const BMO_FIELD_TLS_CA: i32 = -8;         // Single DER CA cert for TLS (optional)
pub const BMO_FIELD_EXPECTED_HASH: i32 = -9;  // Expected hash of final image (optional)
pub const BMO_FIELD_META_SIGNER: i32 = -10;   // COSE_Key for meta-payload sig (optional)

/// Generic chunking field keys (non-negative), per chunking-strategy.md
pub const CHUNK_FIELD_TOTAL_SIZE: i32 = 0;   // Total bytes
pub const CHUNK_FIELD_HASH_ALG: i32 = 1;     // Hash algorithm
pub const CHUNK_FIELD_METADATA: i32 = 2;     // Optional metadata
pub const CHUNK_FIELD_REQUIRE_ACK: i32 = 3;  // Require acknowledgment
pub const CHUNK_FIELD_EST_DURATION: i32 = 4; // Advisory: estimated transfer+apply time (seconds)

/// Parsed BMO image-begin message
#[derive(Debug, Default)]
pub struct BmoImageBegin {
    // Generic chunking fields
    pub total_size: u64,
    pub hash_alg: Option<String>,
    pub require_ack: bool,
    pub estimated_duration: u64, // Advisory: seconds for transfer+apply (0 = unset)
    
    // BMO-specific fields
    pub image_type: Option<String>,
    pub boot_args: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    /// Expected hash of the final image (key -9). This is the field that binds
    /// image content to the authorising `image-begin`; the hash optionally
    /// carried in the unsigned `image-end` is transport integrity only.
    pub expected_hash: Option<Vec<u8>>,
    pub delivery_mode: u8,
    /// URL for delivery mode 1 (image) and mode 2 (meta-payload) — key -7 in both.
    pub url: Option<String>,
    pub tls_ca: Option<Vec<u8>>,
    pub meta_signer: Option<Vec<u8>>,
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
    debug!("BMO: Parsing image-begin ({} bytes)", data.len());
    
    let mut dec = CborDecoder::new(data);
    let mut begin = BmoImageBegin::default();
    
    // Read map header
    let map_len = dec.read_map_header().ok()?;
    debug!("BMO: image-begin has {} map entries", map_len);
    
    for i in 0..map_len {
        // Read key (can be positive or negative integer)
        let key = match dec.read_int() {
            Ok(k) => {
                debug!("BMO: map entry {} key = {}", i, k);
                k
            }
            Err(e) => {
                error!("BMO: failed to read key for entry {}: {:?}", i, e);
                return None;
            }
        };
        
        match key {
            // Generic chunking fields (non-negative), per chunking-strategy.md
            CHUNK_FIELD_TOTAL_SIZE => {
                begin.total_size = dec.read_uint().ok()? as u64;
                debug!("BMO: total_size = {}", begin.total_size);
            }
            CHUNK_FIELD_HASH_ALG => {
                begin.hash_alg = Some(dec.read_text().ok()?);
                debug!("BMO: hash_alg = {:?}", begin.hash_alg);
            }
            CHUNK_FIELD_REQUIRE_ACK => {
                begin.require_ack = dec.read_bool().ok()?;
                debug!("BMO: require_ack = {}", begin.require_ack);
            }
            CHUNK_FIELD_EST_DURATION => {
                begin.estimated_duration = dec.read_uint().ok()? as u64;
                debug!("BMO: estimated_duration = {}s", begin.estimated_duration);
            }

            // BMO-specific fields (negative keys), per fdo.bmo.md
            BMO_FIELD_IMAGE_TYPE => {
                begin.image_type = Some(dec.read_text().ok()?);
                debug!("BMO: image_type = {:?}", begin.image_type);
            }
            BMO_FIELD_BOOT_ARGS => {
                begin.boot_args = Some(dec.read_text().ok()?);
                debug!("BMO: boot_args = {:?}", begin.boot_args);
            }
            BMO_FIELD_NAME => {
                begin.name = Some(dec.read_text().ok()?);
                debug!("BMO: name = {:?}", begin.name);
            }
            BMO_FIELD_VERSION => {
                begin.version = Some(dec.read_text().ok()?);
                debug!("BMO: version = {:?}", begin.version);
            }
            BMO_FIELD_DESCRIPTION => {
                begin.description = Some(dec.read_text().ok()?);
                debug!("BMO: description = {:?}", begin.description);
            }
            BMO_FIELD_DELIVERY_MODE => {
                begin.delivery_mode = dec.read_uint().ok()? as u8;
                debug!("BMO: delivery_mode = {}", begin.delivery_mode);
            }
            BMO_FIELD_URL => {
                begin.url = Some(dec.read_text().ok()?);
                debug!("BMO: url = {:?}", begin.url);
            }
            BMO_FIELD_TLS_CA => {
                begin.tls_ca = Some(dec.read_bytes().ok()?);
            }
            BMO_FIELD_EXPECTED_HASH => {
                begin.expected_hash = Some(dec.read_bytes().ok()?);
                debug!("BMO: expected_hash = {} bytes",
                       begin.expected_hash.as_ref().map(|h| h.len()).unwrap_or(0));
            }
            BMO_FIELD_META_SIGNER => {
                begin.meta_signer = Some(dec.read_bytes().ok()?);
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

/// Build BMO set-response message
/// Format: [status_code] or [status_code, message]
pub fn build_bmo_set_response(status: u8, message: Option<&str>) -> Vec<u8> {
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

/// Parse BMO set message — CBOR array of [name, value] pairs.
/// Returns the first parameter as (name, value). The EFI client doesn't
/// have a BIOS configuration interface, so we only log the parameters.
fn parse_bmo_set(data: &[u8]) -> Option<(String, String)> {
    let mut dec = CborDecoder::new(data);

    // The set body is a CBOR array of [name, value] pairs
    let outer_len = dec.read_array_header().ok()?;
    if outer_len == 0 {
        return None;
    }

    // Each element is a 2-element array [name, value]
    let inner_len = dec.read_array_header().ok()?;
    if inner_len < 2 {
        return None;
    }
    let name = dec.read_text().ok()?;
    let value = dec.read_text().ok()?;
    Some((name, value))
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

/// Returns true if `data` starts with CBOR tag 18 (0xD2 = major 6, value 18).
fn is_cbor_tag18(data: &[u8]) -> bool {
    // CBOR tag 18: major type 6 (0xC0), additional info 18 → 0xD2
    data.first() == Some(&0xD2)
}

/// Attempt to unwrap a signed BMO provisioning envelope (COSE_Sign1 tag 18).
///
/// Returns `Some(inner_payload_bytes)` if the body was tag 18, signature verified,
/// and content_type matched. Returns `None` if the body is not tag 18 (caller
/// should treat it as a bare map) or if verification failed (caller checks
/// `is_cbor_tag18` to distinguish).
fn unwrap_bmo_signed(data: &[u8], owner_key_point: Option<&[u8]>, expected_ct: &str, device_guid: Option<&[u8]>) -> Option<Vec<u8>> {
    if !is_cbor_tag18(data) {
        return None; // Not signed — bare map
    }

    info!("BMO: Detected COSE_Sign1 (tag 18) — artifact authority");

    let owner_point = match owner_key_point {
        Some(p) => p,
        None => {
            error!("BMO: Signed envelope received but no Owner key available for verification");
            return None;
        }
    };

    match crate::cose::verify_bmo_signed(data, owner_point, expected_ct, device_guid) {
        Some(payload) => {
            info!("BMO: Provisioning signature VERIFIED ({} byte payload)", payload.len());
            Some(payload.to_vec())
        }
        None => {
            error!("BMO: Provisioning signature verification FAILED");
            None
        }
    }
}

/// Result of BMO authorization check.
#[derive(Debug, PartialEq)]
pub enum BmoAuthResult {
    /// Signed payload verified — inner bytes returned by caller from unwrap_bmo_signed
    SignedOk,
    /// Signed payload failed verification
    SignedFailed,
    /// Unsigned accepted via Model 1 (Owner-direct channel authority)
    UnsignedModel1,
    /// Unsigned accepted via Model 2 (delegate channel authority with PERM.7)
    UnsignedModel2,
    /// Unsigned accepted — legacy/test mode (no Owner key)
    UnsignedLegacy,
}

/// Check whether a BMO provisioning payload should be accepted.
///
/// This is the pure authorization logic extracted from `process_bmo_message`.
/// It handles the full security model matrix:
///
/// - **Model 1:** Owner-direct channel authority. Owner proved identity via TO2.
///   Unsigned payloads accepted when `owner_key_point` is `Some` and
///   `delegate_has_provision` is false.
/// - **Model 2:** Delegate channel authority. Delegate with PERM.7.
///   Unsigned payloads accepted when `delegate_has_provision` is true.
/// - **Model 3:** Owner artifact authority. Payload is COSE_Sign1 (tag 18)
///   signed by Owner key.
/// - **Model 4:** Delegate artifact authority. Payload is COSE_Sign1 with
///   x5chain, verified against delegate chain rooted in Owner key.
/// - **Legacy/test:** No Owner key available. Unsigned payloads accepted.
pub fn check_bmo_authorization(
    data: &[u8],
    owner_key_point: Option<&[u8]>,
    delegate_has_provision: bool,
    expected_ct: &str,
    device_guid: Option<&[u8]>,
) -> (BmoAuthResult, Option<Vec<u8>>) {
    if is_cbor_tag18(data) {
        // Signed envelope — try to verify
        let inner = unwrap_bmo_signed(data, owner_key_point, expected_ct, device_guid);
        if inner.is_some() {
            (BmoAuthResult::SignedOk, inner)
        } else {
            (BmoAuthResult::SignedFailed, None)
        }
    } else {
        // Unsigned — check channel authority
        if owner_key_point.is_some() && !delegate_has_provision {
            info!("BMO: accepting unsigned image-begin via Owner channel authority (Model 1)");
            (BmoAuthResult::UnsignedModel1, None)
        } else if delegate_has_provision {
            info!("BMO: accepting unsigned image-begin via delegate channel authority (Model 2)");
            (BmoAuthResult::UnsignedModel2, None)
        } else {
            debug!("BMO: image-begin is unsigned (no Owner key — legacy/test mode)");
            (BmoAuthResult::UnsignedLegacy, None)
        }
    }
}

/// Process BMO ServiceInfo message from owner.
///
/// `owner_key_point` is the TO2-proven Owner public key (P-256, 65 bytes).
/// When present, signed provisioning envelopes (CBOR tag 18 / COSE_Sign1) are
/// verified against it. When `None`, only unsigned (channel-authority) messages
/// are accepted.
///
/// `delegate_has_provision` is true when the TO2 peer authenticated as a
/// delegate with OIDPermitProvision (PERM.7). In that case, unsigned
/// provisioning messages are acceptable via channel authority (Model 2).
///
#[cfg(target_os = "uefi")]
/// Returns optional response ServiceInfo to send back.
pub fn process_bmo_message(
    session: &mut BmoSession,
    key: &str,
    value: &[u8],
    owner_key_point: Option<&[u8]>,
    delegate_has_provision: bool,
    device_guid: Option<&[u8]>,
) -> Option<(String, Vec<u8>)> {
    debug!("BMO: Processing message key='{}', value={} bytes", key, value.len());
    
    match key {
        BMO_KEY_IMAGE_BEGIN => {
            // Check if the body is a signed COSE_Sign1 (tag 18 = 0xD2 first byte)
            // or a bare CBOR map.
            let inner_data = unwrap_bmo_signed(value, owner_key_point,
                crate::cose::BMO_CONTENT_TYPE_IMAGE_BEGIN, device_guid);
            let parse_data = match &inner_data {
                Some(d) => d.as_slice(),
                None if is_cbor_tag18(value) => {
                    // It was tag 18 but verification failed — reject
                    error!("BMO: image-begin was signed but verification FAILED — rejecting");
                    session.state = BmoState::Error;
                    let result = build_bmo_image_result(BMO_STATUS_ERROR,
                        Some("Provisioning signature verification failed"));
                    return Some((BMO_KEY_IMAGE_RESULT.to_string(), result));
                }
                None => {
                    // Bare map — unsigned provisioning.
                    // Model 1: Owner-direct channel authority — Owner proved identity
                    //   via TO2 voucher chain. Unsigned payloads are trusted.
                    // Model 2: Delegate channel authority — delegate has PERM.7,
                    //   so unsigned payloads are trusted through the delegate.
                    // Reject ONLY when a delegate is the TO2 peer and lacks PERM.7.
                    if owner_key_point.is_some() && delegate_has_provision == false {
                        // This is Model 1: Owner-direct. Owner proved identity via TO2.
                        // Unsigned payloads are acceptable via channel authority.
                        info!("BMO: accepting unsigned image-begin via Owner channel authority (Model 1)");
                    } else if delegate_has_provision {
                        info!("BMO: accepting unsigned image-begin via delegate channel authority (Model 2)");
                    } else {
                        debug!("BMO: image-begin is unsigned (no Owner key — legacy/test mode)");
                    }
                    value
                }
            };

            // Parse the image-begin message
            if let Some(mut begin) = parse_bmo_image_begin(parse_data) {
                debug!("BMO: Received image-begin");
                debug!("  image_type: {:?}", begin.image_type);
                debug!("  delivery_mode: {}", begin.delivery_mode);
                debug!("  total_size: {}", begin.total_size);
                debug!("  require_ack: {}", begin.require_ack);
                
                // If server provided an estimated duration, double it for safety
                // and re-arm the watchdog IF it exceeds the current default.
                if begin.estimated_duration > 0 {
                    let watchdog_secs = (begin.estimated_duration * 2) as usize;
                    if watchdog_secs > crate::WATCHDOG_TIMEOUT_SECS {
                        info!("BMO: Server estimated_duration={}s, extending watchdog to {}s (2x, was {}s)",
                              begin.estimated_duration, watchdog_secs, crate::WATCHDOG_TIMEOUT_SECS);
                        match uefi::boot::set_watchdog_timer(watchdog_secs, 0x10000, None) {
                            Ok(_) => info!("BMO: Watchdog extended to {}s", watchdog_secs),
                            Err(e) => warn!("BMO: Failed to extend watchdog: {:?}", e.status()),
                        }
                    } else {
                        info!("BMO: Server estimated_duration={}s (2x={}s <= default {}s, keeping current watchdog)",
                              begin.estimated_duration, watchdog_secs, crate::WATCHDOG_TIMEOUT_SECS);
                    }
                }
                
                // Handle delivery mode
                match begin.delivery_mode {
                    BMO_DELIVERY_INLINE => {
                        // Mode 0: Chunked transfer over FDO channel
                        debug!("BMO: Using inline delivery mode (chunked)");
                        session.state = BmoState::AwaitingData;
                        session.image_buffer.clear();
                        // Pre-allocate if total_size known to avoid repeated reallocation
                        if begin.total_size > 0 {
                            session.image_buffer.reserve(begin.total_size as usize);
                        }
                        session.begin = Some(begin);
                        session.chunks_received = 0;
                        session.bytes_received = 0;
                    }
                    BMO_DELIVERY_URL => {
                        // Mode 1: Device fetches from URL
                        debug!("BMO: Using URL delivery mode");
                        if let Some(url) = &begin.url {
                            debug!("BMO: Fetching image from URL: {}", url);
                            match process_bmo_url_delivery(session, &mut begin) {
                                Ok(()) => {
                                    debug!("BMO: URL fetch successful, {} bytes received", session.image_buffer.len());
                                    session.begin = Some(begin);
                                    session.state = BmoState::Complete;
                                    // Send success result immediately
                                    let result = build_bmo_image_result(BMO_STATUS_SUCCESS, Some("Image fetched from URL"));
                                    return Some((BMO_KEY_IMAGE_RESULT.to_string(), result));
                                }
                                Err(error_code) => {
                                    error!("BMO: URL fetch failed with error code {}", error_code);
                                    session.state = BmoState::Error;
                                    let result = build_bmo_image_result(BMO_STATUS_ERROR, Some("URL fetch failed"));
                                    return Some((BMO_KEY_IMAGE_RESULT.to_string(), result));
                                }
                            }
                        } else {
                            error!("BMO: URL delivery mode requested but no URL provided");
                            session.state = BmoState::Error;
                            let result = build_bmo_image_result(BMO_STATUS_ERROR, Some("URL delivery mode but no URL"));
                            return Some((BMO_KEY_IMAGE_RESULT.to_string(), result));
                        }
                    }
                    BMO_DELIVERY_META_URL => {
                        // Mode 2: Device fetches signed meta-payload
                        error!("BMO: Meta-URL delivery mode not yet supported");
                        session.state = BmoState::Error;
                        let result = build_bmo_image_result(BMO_STATUS_ERROR, Some("Meta-URL mode not supported"));
                        return Some((BMO_KEY_IMAGE_RESULT.to_string(), result));
                    }
                    _ => {
                        error!("BMO: Unknown delivery mode: {}", begin.delivery_mode);
                        session.state = BmoState::Error;
                        let result = build_bmo_image_result(BMO_STATUS_ERROR, Some("Unknown delivery mode"));
                        return Some((BMO_KEY_IMAGE_RESULT.to_string(), result));
                    }
                }
                
                // If require_ack, send ack response (for inline mode only)
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
                        debug!("BMO: Decoded CBOR bstr chunk: {} -> {} bytes", value.len(), inner.len());
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
            
            debug!("BMO: Received chunk {}, {} bytes (total: {} bytes)", 
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
            
            info!("BMO: Transfer complete!");
            debug!("  Total chunks: {}", session.chunks_received);
            debug!("  Total bytes: {}", session.bytes_received);
            
            // Verify size if specified
            if let Some(ref begin) = session.begin {
                if begin.total_size > 0 && session.bytes_received != begin.total_size {
                    error!("BMO: Size mismatch! Expected {}, got {}", 
                           begin.total_size, session.bytes_received);
                    session.state = BmoState::Error;
                    let result = build_bmo_image_result(BMO_STATUS_ERROR, Some("Size mismatch"));
                    return Some((BMO_KEY_IMAGE_RESULT.to_string(), result));
                }
            }
            
            // Parse image-end message for SHA256 hash (CBOR map, key 1 = hash value)
            let end_hash = parse_image_end_hash(value);

            // Choose which hash to verify against.
            //
            // `expected_hash` (key -9) arrives in `image-begin`, which is the
            // message that carries provisioning authority; a hash in the
            // unsigned `image-end` is transport integrity only and grants no
            // authorisation over content. So image-begin wins, and if both are
            // present they must agree — a disagreement means the sender is
            // trying to substitute content after the authorising message.
            let begin_hash = session.begin.as_ref().and_then(|b| b.expected_hash.clone());
            if let (Some(bh), Some(eh)) = (&begin_hash, &end_hash) {
                if bh != eh {
                    error!("BMO: image-begin expected_hash disagrees with image-end hash_value.");
                    error!("BMO: REFUSING to chainload — content does not match what was authorised.");
                    session.state = BmoState::Error;
                    let result = build_bmo_image_result(
                        BMO_STATUS_ERROR, Some("image-begin/image-end hash disagreement"));
                    return Some((BMO_KEY_IMAGE_RESULT.to_string(), result));
                }
            }
            let from_begin = begin_hash.is_some();
            let authoritative_hash = begin_hash.or(end_hash);
            if authoritative_hash.is_some() && !from_begin {
                warn!("BMO: image-begin carried no expected_hash (key -9); verifying against the");
                warn!("BMO: unsigned image-end hash. This checks transport integrity but does NOT");
                warn!("BMO: bind the image to an authorising message.");
            }

            // Verify SHA256 hash of reassembled image buffer
            if let Some(expected_hash) = &authoritative_hash {
                let mut hasher = Sha256::new();
                hasher.update(&session.image_buffer);
                let computed = hasher.finalize();
                let computed_bytes = computed.as_slice();
                
                debug!("BMO: SHA256 verification:");
                debug!("  Expected: {:02x?}", &expected_hash[..core::cmp::min(16, expected_hash.len())]);
                debug!("  Computed: {:02x?}", &computed_bytes[..16]);
                
                if computed_bytes != expected_hash.as_slice() {
                    error!("BMO: SHA256 MISMATCH! Image data is CORRUPTED.");
                    error!("BMO: REFUSING to chainload — data integrity check FAILED.");
                    session.state = BmoState::Error;
                    let result = build_bmo_image_result(BMO_STATUS_ERROR, Some("SHA256 hash mismatch"));
                    return Some((BMO_KEY_IMAGE_RESULT.to_string(), result));
                }
                debug!("BMO: SHA256 verified OK");
            } else {
                warn!("BMO: No hash in image-begin (key -9) or image-end — cannot verify integrity");
                warn!("BMO: Proceeding without hash verification (server should send a hash)");
            }
            
            session.state = BmoState::Complete;
            info!("BMO: Image ready for boot ({} bytes, integrity verified)", session.image_buffer.len());
            
            // Send success result
            let result = build_bmo_image_result(BMO_STATUS_SUCCESS, Some("Image received"));
            Some((BMO_KEY_IMAGE_RESULT.to_string(), result))
        }
        
        BMO_KEY_SET => {
            // BIOS parameter setting — same signed/unsigned gate as image-begin
            debug!("BMO: Received set message ({} bytes)", value.len());

            let inner_data = unwrap_bmo_signed(value, owner_key_point,
                crate::cose::BMO_CONTENT_TYPE_SET, device_guid);
            let parse_data = match &inner_data {
                Some(d) => d.as_slice(),
                None if is_cbor_tag18(value) => {
                    error!("BMO: set was signed but verification FAILED — rejecting");
                    session.state = BmoState::Error;
                    let result = build_bmo_set_response(BMO_STATUS_ERROR,
                        Some("Provisioning signature verification failed"));
                    return Some((BMO_KEY_SET_RESPONSE.to_string(), result));
                }
                None => {
                    // Bare map — unsigned set. Same policy as image-begin:
                    // Model 1 (Owner-direct) and Model 2 (delegate w/ PERM.7)
                    // both accept unsigned payloads via channel authority.
                    if owner_key_point.is_some() && !delegate_has_provision {
                        info!("BMO: accepting unsigned set via Owner channel authority (Model 1)");
                    } else if delegate_has_provision {
                        info!("BMO: accepting unsigned set via delegate channel authority (Model 2)");
                    }
                    value
                }
            };

            // Parse the set message — CBOR map with "name" and "value" text keys
            if let Some((name, val)) = parse_bmo_set(parse_data) {
                info!("BMO: BIOS set: {}={}", name, val);
                // EFI client logs the parameter but doesn't apply it
                // (no BIOS configuration interface in UEFI firmware)
                let result = build_bmo_set_response(BMO_STATUS_SUCCESS,
                    Some(&format!("Parameter {} acknowledged", name)));
                Some((BMO_KEY_SET_RESPONSE.to_string(), result))
            } else {
                error!("BMO: Failed to parse set message");
                let result = build_bmo_set_response(BMO_STATUS_ERROR,
                    Some("Failed to parse BIOS set parameters"));
                Some((BMO_KEY_SET_RESPONSE.to_string(), result))
            }
        }
        
        _ => {
            debug!("BMO: Unknown key '{}', ignoring", key);
            None
        }
    }
}

/// Process BMO URL delivery mode (delivery_mode = 1)
/// Fetches the image from the provided URL and stores it in the session buffer.
/// Returns Ok(()) on success, or Err(error_code) on failure.
#[cfg(target_os = "uefi")]
fn process_bmo_url_delivery(session: &mut BmoSession, begin: &mut BmoImageBegin) -> Result<(), u8> {
    let url = match &begin.url {
        Some(u) => u,
        None => {
            error!("BMO: URL delivery requested but no URL provided");
            return Err(BMO_ERROR_URL_FETCH_FAILED);
        }
    };
    
    debug!("BMO: Fetching image from URL: {}", url);
    
    // Fetch the image from the URL
    let image_data = match crate::http_api::http_get(url) {
        Some(data) => {
            debug!("BMO: Downloaded {} bytes from URL", data.len());
            data
        }
        None => {
            error!("BMO: HTTP GET failed for URL: {}", url);
            return Err(BMO_ERROR_URL_FETCH_FAILED);
        }
    };
    
    // Check size limits if specified
    if begin.total_size > 0 && image_data.len() as u64 != begin.total_size {
        error!("BMO: Size mismatch! Expected {}, got {}", 
               begin.total_size, image_data.len());
        return Err(BMO_ERROR_SIZE_EXCEEDED);
    }
    
    // Verify hash if provided
    if let Some(expected_hash) = &begin.expected_hash {
        let mut hasher = Sha256::new();
        hasher.update(&image_data);
        let computed = hasher.finalize();
        let computed_bytes = computed.as_slice();
        
        debug!("BMO: SHA256 verification (URL mode):");
        debug!("  Expected: {:02x?}", &expected_hash[..core::cmp::min(16, expected_hash.len())]);
        debug!("  Computed: {:02x?}", &computed_bytes[..16]);
        
        if computed_bytes != expected_hash.as_slice() {
            error!("BMO: SHA256 MISMATCH! Downloaded image is CORRUPTED.");
            error!("BMO: REFUSING to chainload — data integrity check FAILED.");
            return Err(BMO_ERROR_HASH_MISMATCH);
        }
        debug!("BMO: SHA256 verified OK");
    } else {
        warn!("BMO: No expected hash provided for URL delivery — cannot verify integrity");
        warn!("BMO: Proceeding without hash verification (server should provide hash)");
    }
    
    // Store the image data in the session buffer
    session.image_buffer = image_data;
    session.bytes_received = session.image_buffer.len() as u64;
    
    info!("BMO: Image ready for boot ({} bytes, integrity verified)", session.image_buffer.len());
    
    Ok(())
}

/// Parse the SHA256 hash from an image-end message.
/// The image-end message is a CBOR map where:
///   key 0 = status (int), key 1 = hash_value (bstr), key 2 = message (tstr)
/// Returns the hash bytes if present, or None.
fn parse_image_end_hash(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }
    
    // Try to decode as CBOR map
    let mut dec = CborDecoder::new(data);
    let map_len = match dec.read_map_header() {
        Ok(n) => n,
        Err(_) => {
            debug!("BMO: image-end is not a CBOR map, no hash available");
            return None;
        }
    };
    
    for _ in 0..map_len {
        let key = match dec.read_int() {
            Ok(k) => k,
            Err(_) => return None,
        };
        
        if key == 1 {
            // Key 1 = hash value (byte string)
            match dec.read_bytes() {
                Ok(hash) => {
                    debug!("BMO: Found SHA256 hash in image-end ({} bytes)", hash.len());
                    return Some(hash);
                }
                Err(_) => {
                    warn!("BMO: Key 1 in image-end is not a byte string");
                    return None;
                }
            }
        } else {
            // Skip this value
            if dec.skip_value().is_err() {
                return None;
            }
        }
    }
    
    None
}

/// Test BMO state machine with mock data
/// This can be called to verify BMO handling without a real server
#[cfg(target_os = "uefi")]
pub fn test_bmo_handling() {
    debug!("=== BMO Test: Starting mock BMO message test ===");
    
    let mut session = BmoSession::new();
    
    // Simulate fdo.bmo:active
    debug!("Test 1: Processing fdo.bmo:active");
    let active_value = alloc::vec![0xf5]; // CBOR true
    let result = process_bmo_message(&mut session, "fdo.bmo:active", &active_value, None, false, None);
    debug!("  Result: {:?}", result.is_some());
    
    // Simulate fdo.bmo:image-begin with inline delivery
    debug!("Test 2: Processing fdo.bmo:image-begin");
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
    
    let result = process_bmo_message(&mut session, BMO_KEY_IMAGE_BEGIN, &begin_msg, None, false, None);
    debug!("  Result: {:?}", result.is_some());
    debug!("  State: {:?}", session.state);
    
    // Simulate image data chunks
    debug!("Test 3: Processing fdo.bmo:image-data chunks");
    let chunk_data: Vec<u8> = (0u8..50).collect();
    let result = process_bmo_message(&mut session, "fdo.bmo:image-data-0", &chunk_data, None, false, None);
    debug!("  Chunk 0 result: {:?}, bytes_received: {}", result.is_some(), session.bytes_received);
    
    let chunk_data: Vec<u8> = (50u8..100).collect();
    let result = process_bmo_message(&mut session, "fdo.bmo:image-data-1", &chunk_data, None, false, None);
    debug!("  Chunk 1 result: {:?}, bytes_received: {}", result.is_some(), session.bytes_received);
    
    // Simulate image-end
    debug!("Test 4: Processing fdo.bmo:image-end");
    let end_msg = alloc::vec![0xf6]; // CBOR null
    let result = process_bmo_message(&mut session, BMO_KEY_IMAGE_END, &end_msg, None, false, None);
    debug!("  Result: {:?}", result.is_some());
    debug!("  Final state: {:?}", session.state);
    debug!("  Image buffer size: {} bytes", session.image_buffer.len());
    
    debug!("=== BMO Test: Complete ===");
}

// =========================================================================
// Unit tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_service_info_kv ---

    #[test]
    fn test_parse_service_info_kv() {
        let data = build_service_info_kv("fdo.bmo:image-begin", &[0xa0]); // key + empty map
        let (key, value) = parse_service_info_kv(&data).expect("should parse");
        assert_eq!(key, "fdo.bmo:image-begin");
        assert_eq!(value, &[0xa0]);
    }

    #[test]
    fn test_parse_service_info_kv_roundtrip() {
        let payload = vec![0x01, 0x02, 0x03, 0x04];
        let data = build_service_info_kv("test:key", &payload);
        let (key, value) = parse_service_info_kv(&data).unwrap();
        assert_eq!(key, "test:key");
        assert_eq!(value, payload);
    }

    // --- parse_bmo_image_begin ---

    fn build_image_begin_cbor(total_size: u64, image_type: &str, delivery_mode: u8) -> Vec<u8> {
        let mut enc = CborEncoder::new();
        enc.encode_map(3);
        // key 0 = total_size
        enc.uint(CHUNK_FIELD_TOTAL_SIZE as u16);
        enc.uint(total_size as u16);
        // key -1 = image_type
        enc.neg_int(BMO_FIELD_IMAGE_TYPE as i8);
        enc.text(image_type);
        // key -6 = delivery_mode
        enc.neg_int(BMO_FIELD_DELIVERY_MODE as i8);
        enc.uint(delivery_mode as u16);
        enc.into_bytes()
    }

    #[test]
    fn test_parse_image_begin_basic() {
        let data = build_image_begin_cbor(1024, "application/x-uefi-image", BMO_DELIVERY_INLINE);
        let begin = parse_bmo_image_begin(&data).expect("should parse");
        assert_eq!(begin.total_size, 1024);
        assert_eq!(begin.image_type.as_deref(), Some("application/x-uefi-image"));
        assert_eq!(begin.delivery_mode, BMO_DELIVERY_INLINE);
    }

    #[test]
    fn test_parse_image_begin_with_all_fields() {
        let mut enc = CborEncoder::new();
        enc.encode_map(8);
        // total_size
        enc.uint(0); enc.uint(2048);
        // hash_alg
        enc.uint(1); enc.text("SHA-256");
        // require_ack
        enc.uint(3); enc.bool_val(true);
        // est_duration
        enc.uint(4); enc.uint(300);
        // image_type
        enc.neg_int(-1); enc.text("application/efi");
        // boot_args
        enc.neg_int(-2); enc.text("console=ttyS0");
        // name
        enc.neg_int(-3); enc.text("test-image");
        // delivery_mode
        enc.neg_int(-6); enc.uint(0);
        let data = enc.into_bytes();

        let begin = parse_bmo_image_begin(&data).unwrap();
        assert_eq!(begin.total_size, 2048);
        assert_eq!(begin.hash_alg.as_deref(), Some("SHA-256"));
        assert!(begin.require_ack);
        assert_eq!(begin.estimated_duration, 300);
        assert_eq!(begin.image_type.as_deref(), Some("application/efi"));
        assert_eq!(begin.boot_args.as_deref(), Some("console=ttyS0"));
        assert_eq!(begin.name.as_deref(), Some("test-image"));
        assert_eq!(begin.delivery_mode, 0);
    }

    #[test]
    fn test_parse_image_begin_url_delivery() {
        let mut enc = CborEncoder::new();
        enc.encode_map(3);
        enc.uint(0); enc.uint(0); // total_size unknown
        enc.neg_int(-1); enc.text("application/x-uefi-image");
        enc.neg_int(-6); enc.uint(BMO_DELIVERY_URL as u16);
        let data = enc.into_bytes();

        let begin = parse_bmo_image_begin(&data).unwrap();
        assert_eq!(begin.delivery_mode, BMO_DELIVERY_URL);
    }

    #[test]
    fn test_parse_image_begin_empty_map() {
        let data = [0xa0]; // empty map
        let begin = parse_bmo_image_begin(&data).unwrap();
        assert_eq!(begin.total_size, 0);
        assert!(begin.image_type.is_none());
    }

    // --- build_bmo_image_result ---

    #[test]
    fn test_build_image_result_success() {
        let result = build_bmo_image_result(BMO_STATUS_SUCCESS, None);
        let mut dec = CborDecoder::new(&result);
        assert_eq!(dec.read_array_header().unwrap(), 1);
        assert_eq!(dec.read_uint().unwrap(), 0);
    }

    #[test]
    fn test_build_image_result_error_with_message() {
        let result = build_bmo_image_result(BMO_STATUS_ERROR, Some("bad image"));
        let mut dec = CborDecoder::new(&result);
        assert_eq!(dec.read_array_header().unwrap(), 2);
        assert_eq!(dec.read_uint().unwrap(), BMO_STATUS_ERROR as u64);
        assert_eq!(dec.read_text().unwrap(), "bad image");
    }

    // --- build_bmo_image_ack ---

    #[test]
    fn test_build_image_ack_accepted() {
        let ack = build_bmo_image_ack(true, None, None);
        let mut dec = CborDecoder::new(&ack);
        assert_eq!(dec.read_array_header().unwrap(), 1);
        assert_eq!(dec.read_bool().unwrap(), true);
    }

    #[test]
    fn test_build_image_ack_rejected_with_reason() {
        let ack = build_bmo_image_ack(false, Some(3), Some("size exceeded"));
        let mut dec = CborDecoder::new(&ack);
        assert_eq!(dec.read_array_header().unwrap(), 3);
        assert_eq!(dec.read_bool().unwrap(), false);
        assert_eq!(dec.read_uint().unwrap(), 3);
        assert_eq!(dec.read_text().unwrap(), "size exceeded");
    }

    // --- build_bmo_set_response ---

    #[test]
    fn test_build_set_response() {
        let resp = build_bmo_set_response(BMO_STATUS_SUCCESS, None);
        let mut dec = CborDecoder::new(&resp);
        assert_eq!(dec.read_array_header().unwrap(), 1);
        assert_eq!(dec.read_uint().unwrap(), 0);
    }

    // --- is_cbor_tag18 ---

    #[test]
    fn test_is_cbor_tag18() {
        assert!(is_cbor_tag18(&[0xD2, 0x84])); // tag(18) array(4)
        assert!(!is_cbor_tag18(&[0xa1]));       // map(1) — not tagged
        assert!(!is_cbor_tag18(&[]));            // empty
    }

    // --- unwrap_bmo_signed ---

    #[test]
    fn test_unwrap_bmo_signed_valid_model3() {
        use crate::cose::{gen_test_keypair, build_test_cose_sign1, build_test_protected_header,
                         domain_aad, AAD_TAG_BMO_PROVISION, BMO_CONTENT_TYPE_IMAGE_BEGIN};

        let (sk, point) = gen_test_keypair();
        let protected = build_test_protected_header(Some(BMO_CONTENT_TYPE_IMAGE_BEGIN));
        let payload = b"\xa1\x00\x0a"; // map(1) { 0: 10 }
        let aad = domain_aad(AAD_TAG_BMO_PROVISION, 200);
        let envelope = build_test_cose_sign1(&protected, payload, &aad, &[0xa0], &sk);

        let result = unwrap_bmo_signed(&envelope, Some(&point), BMO_CONTENT_TYPE_IMAGE_BEGIN, None);
        assert!(result.is_some(), "valid signed BMO should unwrap");
        assert_eq!(result.unwrap(), payload);
    }

    #[test]
    fn test_unwrap_bmo_signed_no_tag18() {
        // Bare map — not signed
        let data = [0xa1, 0x00, 0x0a]; // map(1) { 0: 10 }
        let result = unwrap_bmo_signed(&data, None, "x", None);
        assert!(result.is_none(), "bare map should return None (not signed)");
    }

    #[test]
    fn test_unwrap_bmo_signed_no_owner_key() {
        use crate::cose::{gen_test_keypair, build_test_cose_sign1, build_test_protected_header,
                         domain_aad, AAD_TAG_BMO_PROVISION, BMO_CONTENT_TYPE_IMAGE_BEGIN};

        let (sk, _) = gen_test_keypair();
        let protected = build_test_protected_header(Some(BMO_CONTENT_TYPE_IMAGE_BEGIN));
        let aad = domain_aad(AAD_TAG_BMO_PROVISION, 200);
        let envelope = build_test_cose_sign1(&protected, b"\xa0", &aad, &[0xa0], &sk);

        // No owner key → must reject
        let result = unwrap_bmo_signed(&envelope, None, BMO_CONTENT_TYPE_IMAGE_BEGIN, None);
        assert!(result.is_none(), "no owner key must reject signed BMO");
    }

    // --- BmoSession ---

    #[test]
    fn test_bmo_session_reset() {
        let mut session = BmoSession::new();
        session.state = BmoState::AwaitingData;
        session.bytes_received = 1000;
        session.chunks_received = 5;
        session.image_buffer = vec![0u8; 100];
        session.reset();

        assert_eq!(session.state, BmoState::Idle);
        assert_eq!(session.bytes_received, 0);
        assert_eq!(session.chunks_received, 0);
        assert!(session.image_buffer.is_empty());
    }

    // --- parse_bmo_set ---

    #[test]
    fn test_parse_bmo_set() {
        // array(1) [ array(2) ["param_name", "param_value"] ]
        let mut enc = CborEncoder::new();
        enc.array(1);
        enc.array(2);
        enc.text("bios_setting");
        enc.text("enabled");
        let data = enc.into_bytes();

        let (name, value) = parse_bmo_set(&data).expect("should parse set");
        assert_eq!(name, "bios_setting");
        assert_eq!(value, "enabled");
    }

    // ===== BMO authorization policy matrix (Go: bmo_provision_test.go) =====

    use crate::cose::{gen_test_keypair, gen_test_keypair_b,
        build_test_cose_sign1, build_test_protected_header, domain_aad,
        BMO_CONTENT_TYPE_IMAGE_BEGIN, BMO_CONTENT_TYPE_SET,
        AAD_TAG_BMO_PROVISION};

    /// Build a minimal unsigned image-begin (bare CBOR map, no tag 18).
    fn build_unsigned_image_begin() -> Vec<u8> {
        let mut enc = CborEncoder::new();
        enc.encode_map(2);
        enc.uint(0); enc.uint(52);   // total_size = 52
        enc.uint(3); enc.uint(0);    // delivery_mode = inline
        enc.into_bytes()
    }

    /// Build a signed image-begin (COSE_Sign1 tag 18) with the given key.
    fn build_signed_image_begin(sk: &p256::ecdsa::SigningKey) -> Vec<u8> {
        let ct = BMO_CONTENT_TYPE_IMAGE_BEGIN;
        let protected = build_test_protected_header(Some(ct));
        let payload = b"\xa1\x00\x18\x34"; // map(1) { 0: 52 }
        let aad = domain_aad(AAD_TAG_BMO_PROVISION, 200);
        build_test_cose_sign1(&protected, payload, &aad, &[0xa0], sk)
    }

    // --- Model 1: Owner-direct, unsigned ---

    #[test]
    fn test_bmo_auth_unsigned_owner_direct_model1() {
        let (_, owner_point) = gen_test_keypair();
        let data = build_unsigned_image_begin();
        let (result, inner) = check_bmo_authorization(
            &data, Some(&owner_point), false, BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
        );
        assert_eq!(result, BmoAuthResult::UnsignedModel1);
        assert!(inner.is_none(), "unsigned returns no inner payload");
    }

    // --- Model 2: Delegate with PERM.7, unsigned ---

    #[test]
    fn test_bmo_auth_unsigned_delegate_model2() {
        let (_, owner_point) = gen_test_keypair();
        let data = build_unsigned_image_begin();
        let (result, _) = check_bmo_authorization(
            &data, Some(&owner_point), true, BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
        );
        assert_eq!(result, BmoAuthResult::UnsignedModel2);
    }

    // --- Unsigned with no owner key (legacy/test mode) ---

    #[test]
    fn test_bmo_auth_unsigned_no_owner_key() {
        let data = build_unsigned_image_begin();
        let (result, _) = check_bmo_authorization(
            &data, None, false, BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
        );
        assert_eq!(result, BmoAuthResult::UnsignedLegacy);
    }

    // --- Model 3: Owner-signed, correct key ---

    #[test]
    fn test_bmo_auth_signed_owner_key_valid() {
        let (sk, owner_point) = gen_test_keypair();
        let data = build_signed_image_begin(&sk);
        let (result, inner) = check_bmo_authorization(
            &data, Some(&owner_point), false, BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
        );
        assert_eq!(result, BmoAuthResult::SignedOk);
        assert!(inner.is_some(), "signed OK must return inner payload");
    }

    // --- Model 3: Owner-signed, wrong key ---

    #[test]
    fn test_bmo_auth_signed_wrong_key() {
        let (sk, _) = gen_test_keypair();
        let (_, wrong_point) = gen_test_keypair_b();
        let data = build_signed_image_begin(&sk);
        let (result, inner) = check_bmo_authorization(
            &data, Some(&wrong_point), false, BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
        );
        assert_eq!(result, BmoAuthResult::SignedFailed);
        assert!(inner.is_none());
    }

    // --- Model 3: Signed but no owner key available ---

    #[test]
    fn test_bmo_auth_signed_no_owner_key() {
        let (sk, _) = gen_test_keypair();
        let data = build_signed_image_begin(&sk);
        let (result, inner) = check_bmo_authorization(
            &data, None, false, BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
        );
        assert_eq!(result, BmoAuthResult::SignedFailed);
        assert!(inner.is_none());
    }

    // --- Signed with wrong content-type ---

    #[test]
    fn test_bmo_auth_signed_wrong_content_type() {
        let (sk, owner_point) = gen_test_keypair();
        let data = build_signed_image_begin(&sk);
        // Expect BMO_CONTENT_TYPE_SET but got IMAGE_BEGIN
        let (result, _) = check_bmo_authorization(
            &data, Some(&owner_point), false, BMO_CONTENT_TYPE_SET, None,
        );
        assert_eq!(result, BmoAuthResult::SignedFailed);
    }

    // --- Signed with tampered payload ---

    #[test]
    fn test_bmo_auth_signed_tampered() {
        let (sk, owner_point) = gen_test_keypair();
        let mut data = build_signed_image_begin(&sk);
        let last = data.len() - 1;
        data[last] ^= 0x01; // flip last byte (signature)
        let (result, _) = check_bmo_authorization(
            &data, Some(&owner_point), false, BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
        );
        assert_eq!(result, BmoAuthResult::SignedFailed);
    }

    // --- Model 4: Delegate-signed with x5chain ---

    #[test]
    fn test_bmo_auth_delegate_signed_model4() {
        use crate::delegate::{build_test_cert, OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED};
        let (owner_sk, owner_point) = gen_test_keypair();
        let (delegate_sk, delegate_point) = gen_test_keypair_b();

        // Build delegate cert signed by owner
        let cert_der = build_test_cert(
            &owner_sk, &delegate_point,
            &[OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED],
        );

        // Build COSE_Sign1 with x5chain in unprotected header
        let ct = BMO_CONTENT_TYPE_IMAGE_BEGIN;
        let protected = build_test_protected_header(Some(ct));
        let payload = b"\xa1\x00\x18\x34"; // map(1) { 0: 52 }
        let aad = domain_aad(AAD_TAG_BMO_PROVISION, 200);

        // Build unprotected header: map(1) { 33: [cert_der] }
        let mut unhdr = Vec::new();
        unhdr.push(0xa1); // map(1)
        unhdr.push(0x18); unhdr.push(33); // label 33 (x5chain)
        // Single cert as bstr (not wrapped in array since go-fdo sends bare bstr for 1-cert)
        crate::cose::encode_bstr(&mut unhdr, &cert_der);

        let data = build_test_cose_sign1(
            &protected, payload, &aad, &unhdr, &delegate_sk,
        );

        let (result, inner) = check_bmo_authorization(
            &data, Some(&owner_point), false, BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
        );
        assert_eq!(result, BmoAuthResult::SignedOk,
            "delegate-signed Model 4 with x5chain must verify");
        assert!(inner.is_some());
    }

    // --- Model 4 negative: delegate chain not rooted in owner ---

    #[test]
    fn test_bmo_auth_delegate_signed_wrong_owner() {
        use crate::delegate::{build_test_cert, OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED};
        let (_, owner_point) = gen_test_keypair();
        let (attacker_sk, _) = gen_test_keypair_b();
        // Third key for delegate leaf
        let delegate_secret = p256::SecretKey::from_bytes(
            &[0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
              0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
              0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
              0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01].into(),
        ).unwrap();
        let delegate_sk = p256::ecdsa::SigningKey::from(delegate_secret.clone());
        let delegate_point = {
            let pk = delegate_secret.public_key();
            p256::EncodedPoint::from(pk).as_bytes().to_vec()
        };

        // Cert signed by ATTACKER, not owner
        let cert_der = build_test_cert(
            &attacker_sk, &delegate_point,
            &[OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED],
        );

        let ct = BMO_CONTENT_TYPE_IMAGE_BEGIN;
        let protected = build_test_protected_header(Some(ct));
        let payload = b"\xa1\x00\x18\x34";
        let aad = domain_aad(AAD_TAG_BMO_PROVISION, 200);

        let mut unhdr = Vec::new();
        unhdr.push(0xa1);
        unhdr.push(0x18); unhdr.push(33);
        crate::cose::encode_bstr(&mut unhdr, &cert_der);

        let data = build_test_cose_sign1(
            &protected, payload, &aad, &unhdr, &delegate_sk,
        );

        let (result, _) = check_bmo_authorization(
            &data, Some(&owner_point), false, BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
        );
        assert_eq!(result, BmoAuthResult::SignedFailed,
            "delegate chain not rooted in owner must be rejected");
    }
}
