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
pub const BMO_ERROR_META_SIGNATURE_INVALID: u8 = 12;
pub const BMO_ERROR_META_PARSE_ERROR: u8 = 13;
pub const BMO_ERROR_DELIVERY_MODE_NOT_SUPPORTED: u8 = 14;
// Generic transfer error codes 15-19 (chunking-strategy.md "Transfer Error Codes").
pub use crate::chunking::{
    ERR_NOT_AUTHORIZED as BMO_ERROR_NOT_AUTHORIZED, ERR_SCOPE_MISMATCH as BMO_ERROR_SCOPE_MISMATCH,
    ERR_SUPERSEDED as BMO_ERROR_SUPERSEDED, ERR_UNAUTHENTICATED_SOURCE as BMO_ERROR_UNAUTHENTICATED_SOURCE,
    ERR_VALIDITY_FAILED as BMO_ERROR_VALIDITY_FAILED,
};

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

/// Generic chunking field keys (non-negative), per chunking-strategy.md
/// "Begin Message Fields". Delivery keys 5-9 are generic so any FSIM can use
/// them; fdo.bmo formerly numbered them -6..-10 (see `LEGACY_*` below).
pub const CHUNK_FIELD_TOTAL_SIZE: i32 = 0;    // Total bytes
pub const CHUNK_FIELD_HASH_ALG: i32 = 1;      // Hash algorithm
pub const CHUNK_FIELD_METADATA: i32 = 2;      // Optional metadata
pub const CHUNK_FIELD_REQUIRE_ACK: i32 = 3;   // Require acknowledgment
pub const CHUNK_FIELD_EST_DURATION: i32 = 4;  // Advisory: estimated transfer+apply time (seconds)
pub const CHUNK_FIELD_DELIVERY_MODE: i32 = 5; // 0=inline, 1=url, 2=meta-url
pub const CHUNK_FIELD_URL: i32 = 6;           // URL of image (mode 1) or meta-payload (mode 2)
pub const CHUNK_FIELD_TLS_CA: i32 = 7;        // Single DER CA cert used as TLS trust anchor
pub const CHUNK_FIELD_EXPECTED_HASH: i32 = 8; // Expected hash of final image
pub const CHUNK_FIELD_META_SIGNER: i32 = 9;   // COSE_Key of a third-party meta-payload publisher

/// Legacy fdo.bmo aliases for keys 5-9. Accepted on receipt; a message that
/// carries a generic key and its alias with different values is rejected
/// (chunking-strategy.md "Reserved Key Policy").
pub const LEGACY_BMO_FIELD_DELIVERY_MODE: i32 = -6;
pub const LEGACY_BMO_FIELD_URL: i32 = -7;
pub const LEGACY_BMO_FIELD_TLS_CA: i32 = -8;
pub const LEGACY_BMO_FIELD_EXPECTED_HASH: i32 = -9;
pub const LEGACY_BMO_FIELD_META_SIGNER: i32 = -10;

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


/// Who the TO2 peer proved itself to be in `ProveOVHdr`.
///
/// This must be stated explicitly. The Owner key is known whether or not a
/// delegate signed `ProveOVHdr` (it comes from the voucher), so "Owner key
/// present" cannot distinguish the Owner from an onboard-only delegate —
/// conflating the two once let a PERM.2-only delegate supply unsigned
/// provisioning payloads under Owner channel authority.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PeerAuthority {
    /// `ProveOVHdr` verified directly against the Owner key.
    OwnerDirect,
    /// `ProveOVHdr` verified against a delegate leaf whose chain roots in the
    /// Owner key. `provision` is PERM.7 across the whole chain.
    Delegate { provision: bool },
    /// No TO2-proven peer (legacy/test paths only).
    Unauthenticated,
}

impl PeerAuthority {
    /// Whether this peer may supply unsigned provisioning payloads (channel
    /// authority). An onboard-only delegate may not — it must deliver an
    /// artifact signed by the Owner or by a PERM.7 holder.
    pub fn has_channel_provision_authority(&self) -> bool {
        matches!(self, PeerAuthority::OwnerDirect | PeerAuthority::Delegate { provision: true })
    }
}

/// BMO session state
#[derive(Debug)]
pub struct BmoSession {
    pub state: BmoState,
    pub begin: Option<BmoImageBegin>,
    pub image_buffer: Vec<u8>,
    pub chunks_received: u32,
    pub bytes_received: u64,
    /// Authority under which the current `image-begin` was accepted.
    pub authority: BmoAuthority,
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
            authority: BmoAuthority::Unauthenticated,
        }
    }
    
    pub fn reset(&mut self) {
        self.state = BmoState::Idle;
        self.begin = None;
        self.image_buffer.clear();
        self.chunks_received = 0;
        self.bytes_received = 0;
        self.authority = BmoAuthority::Unauthenticated;
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
    let mut generic = DeliveryKeys::default();
    let mut legacy = DeliveryKeys::default();
    
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
            // Delivery fields: generic keys 5-9, or their legacy aliases.
            CHUNK_FIELD_DELIVERY_MODE => generic.mode = Some(dec.read_uint().ok()? as u64),
            LEGACY_BMO_FIELD_DELIVERY_MODE => legacy.mode = Some(dec.read_uint().ok()? as u64),
            CHUNK_FIELD_URL => generic.url = Some(dec.read_text().ok()?),
            LEGACY_BMO_FIELD_URL => legacy.url = Some(dec.read_text().ok()?),
            CHUNK_FIELD_TLS_CA => generic.tls_ca = Some(dec.read_bytes().ok()?),
            LEGACY_BMO_FIELD_TLS_CA => legacy.tls_ca = Some(dec.read_bytes().ok()?),
            CHUNK_FIELD_EXPECTED_HASH => generic.hash = Some(dec.read_bytes().ok()?),
            LEGACY_BMO_FIELD_EXPECTED_HASH => legacy.hash = Some(dec.read_bytes().ok()?),
            CHUNK_FIELD_META_SIGNER => generic.signer = Some(dec.read_bytes().ok()?),
            LEGACY_BMO_FIELD_META_SIGNER => legacy.signer = Some(dec.read_bytes().ok()?),
            _ => {
                // Skip unknown fields
                dec.skip_value().ok()?;
            }
        }
    }

    // Fold legacy aliases into the generic fields; a conflicting pair is a
    // malformed message.
    let mode = merge_alias("delivery_mode", generic.mode, legacy.mode)?;
    begin.delivery_mode = match mode {
        Some(m) if m > u8::MAX as u64 => u8::MAX, // unknown mode → rejected later as unsupported
        Some(m) => m as u8,
        None => 0,
    };
    begin.url = merge_alias("url", generic.url, legacy.url)?;
    begin.tls_ca = merge_alias("tls_ca", generic.tls_ca, legacy.tls_ca)?;
    begin.expected_hash = merge_alias("expected_hash", generic.hash, legacy.hash)?;
    begin.meta_signer = merge_alias("meta_signer", generic.signer, legacy.signer)?;
    debug!("BMO: delivery_mode={} url={:?} expected_hash={} bytes",
           begin.delivery_mode, begin.url, begin.expected_hash.as_ref().map(|h| h.len()).unwrap_or(0));

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

use crate::chunking::is_cbor_tag18;

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

// Generic delivery logic (meta-payload, fetched-content evidence, hash
// decisions, legacy-key merging) lives in `crate::chunking`, mirroring
// chunking-strategy.md. Re-exported here so `bmo::...` paths keep working.
pub use crate::chunking::{
    check_unauthenticated_meta, inline_hash_decision, meta_hash_decision, parse_cose_key_p256,
    parse_meta_payload, url_hash_decision, verify_and_extract_meta, HashPolicyError,
    MetaHashPlan, MetaPayload, Authority as BmoAuthority,
};
use crate::chunking::{merge_alias, DeliveryKeys};

/// At `image-begin` time: a signed (Artifact) **inline** image-begin MUST
/// carry `expected_hash` (key 8). `image-end` is never signed, so without it
/// the signature authorises only metadata. Refusing here — rather than in
/// `inline_hash_decision` at image-end — avoids accepting a whole transfer
/// that can never be used. (URL/meta-URL modes are governed by their own
/// decisions, where the hash may come from a signed meta-payload.)
pub fn signed_begin_binds_content(authority: BmoAuthority, begin: &BmoImageBegin) -> Result<(), HashPolicyError> {
    if authority == BmoAuthority::Artifact
        && begin.delivery_mode == BMO_DELIVERY_INLINE
        && begin.expected_hash.is_none()
    {
        return Err(HashPolicyError::SignedWithoutHash);
    }
    Ok(())
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
    /// Unsigned refused — the TO2 peer lacks provisioning authority (e.g. a
    /// delegate holding only onboard permissions), so only a signed artifact
    /// is acceptable from it.
    UnsignedRefused,
}

impl BmoAuthResult {
    /// Map an authorization outcome to the authority the hash policy must
    /// apply. Keeping this next to the outcome enum means the two cannot
    /// drift: a new `BmoAuthResult` variant will not compile until its
    /// hash-policy consequence has been decided.
    pub fn to_authority(&self) -> BmoAuthority {
        match self {
            // A verified signature is artifact authority — and therefore
            // obliges the signed message to carry the image hash.
            BmoAuthResult::SignedOk => BmoAuthority::Artifact,
            // Rejected outright by the caller; value here is irrelevant but
            // must be the strictest thing we have.
            BmoAuthResult::SignedFailed => BmoAuthority::Artifact,
            BmoAuthResult::UnsignedRefused => BmoAuthority::Artifact,
            // Models 1 and 2: the TO2 session is bound to the Owner, so
            // anything arriving over it carries the Owner's authority.
            BmoAuthResult::UnsignedModel1 => BmoAuthority::Channel,
            BmoAuthResult::UnsignedModel2 => BmoAuthority::Channel,
            // No Owner key at all.
            BmoAuthResult::UnsignedLegacy => BmoAuthority::Unauthenticated,
        }
    }

    /// True when the payload is authorised and processing should continue.
    pub fn is_authorized(&self) -> bool {
        !matches!(self, BmoAuthResult::SignedFailed | BmoAuthResult::UnsignedRefused)
    }

    /// Human-readable reason for a refusal (sent back in the result message).
    pub fn rejection_reason(&self) -> &'static str {
        match self {
            BmoAuthResult::UnsignedRefused =>
                "Provisioning not authorized: unsigned payload from peer without provision permission",
            _ => "Provisioning artifact rejected: signature, content type, signer authority or scope check failed",
        }
    }
}

/// Check whether a BMO provisioning payload should be accepted.
///
/// This is the pure authorization logic extracted from `process_bmo_message`.
/// It handles the full security model matrix:
///
/// - **Model 1:** Owner-direct channel authority. Peer is `OwnerDirect`;
///   unsigned payloads accepted.
/// - **Model 2:** Delegate channel authority. Peer is a delegate with PERM.7;
///   unsigned payloads accepted.
/// - **Onboard-only delegate:** peer is a delegate without PERM.7; unsigned
///   payloads REFUSED. It may only relay a Model 3/4 artifact.
/// - **Model 3:** Owner artifact authority. Payload is COSE_Sign1 (tag 18)
///   signed by Owner key. Accepted from any peer.
/// - **Model 4:** Delegate artifact authority. Payload is COSE_Sign1 with
///   x5chain, verified against delegate chain rooted in Owner key, leaf PERM.7.
///   Accepted from any peer.
/// - **Legacy/test:** No TO2-proven peer and no Owner key. Unsigned accepted.
pub fn check_bmo_authorization(
    data: &[u8],
    owner_key_point: Option<&[u8]>,
    peer: PeerAuthority,
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
        match peer {
            PeerAuthority::OwnerDirect => {
                info!("BMO: accepting unsigned payload via Owner channel authority (Model 1)");
                (BmoAuthResult::UnsignedModel1, None)
            }
            PeerAuthority::Delegate { provision: true } => {
                info!("BMO: accepting unsigned payload via delegate channel authority (Model 2)");
                (BmoAuthResult::UnsignedModel2, None)
            }
            PeerAuthority::Delegate { provision: false } => {
                error!("BMO: unsigned payload from delegate lacking PERM.7 — REFUSED");
                error!("BMO: an onboard-only delegate may only relay a signed artifact");
                (BmoAuthResult::UnsignedRefused, None)
            }
            // An Owner key with no stated peer is an inconsistent caller
            // state; fail closed rather than guess which model applies.
            PeerAuthority::Unauthenticated if owner_key_point.is_some() => {
                error!("BMO: unsigned payload with Owner key but no proven TO2 peer — REFUSED");
                (BmoAuthResult::UnsignedRefused, None)
            }
            PeerAuthority::Unauthenticated => {
                debug!("BMO: payload is unsigned (no Owner key — legacy/test mode)");
                (BmoAuthResult::UnsignedLegacy, None)
            }
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
/// `peer` is who the TO2 peer proved itself to be. Unsigned provisioning
/// messages are acceptable only from the Owner or a PERM.7 delegate.
///
#[cfg(target_os = "uefi")]
/// Returns optional response ServiceInfo to send back.
pub fn process_bmo_message(
    session: &mut BmoSession,
    key: &str,
    value: &[u8],
    owner_key_point: Option<&[u8]>,
    peer: PeerAuthority,
    device_guid: Option<&[u8]>,
) -> Option<(String, Vec<u8>)> {
    debug!("BMO: Processing message key='{}', value={} bytes", key, value.len());
    
    match key {
        BMO_KEY_IMAGE_BEGIN => {
            // Authorisation runs through the same pure function the unit
            // tests exercise (`check_bmo_authorization`). This used to be a
            // second, hand-written copy of the Model 1-4 matrix living here
            // in UEFI-only code, so the tested implementation and the
            // shipped implementation were different code that could drift.
            let (auth, inner_data) = check_bmo_authorization(
                value, owner_key_point, peer,
                crate::cose::BMO_CONTENT_TYPE_IMAGE_BEGIN, device_guid);

            if !auth.is_authorized() {
                // Signed-but-unverified is never retried as unsigned (that
                // would be a downgrade); unsigned from a peer without
                // provisioning authority is refused outright.
                error!("BMO: image-begin REJECTED: {}", auth.rejection_reason());
                session.state = BmoState::Error;
                let result = build_bmo_image_result(BMO_STATUS_ERROR,
                    Some(auth.rejection_reason()));
                return Some((BMO_KEY_IMAGE_RESULT.to_string(), result));
            }

            // Authority drives the image-hash policy applied at image-end /
            // URL fetch time.
            session.authority = auth.to_authority();
            let parse_data = match &inner_data {
                Some(d) => d.as_slice(),
                None => value,
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
                
                // A signed inline image-begin must commit to the image now,
                // not after the whole transfer (chunking-strategy.md "Hash
                // Handling"): refuse before any image-data is accepted.
                if let Err(e) = signed_begin_binds_content(session.authority, &begin) {
                    error!("BMO: image-begin REJECTED: {} (error {})", e.message(), e.code());
                    session.state = BmoState::Error;
                    let result = build_bmo_image_result(BMO_STATUS_ERROR, Some(e.message()));
                    return Some((BMO_KEY_IMAGE_RESULT.to_string(), result));
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
                                    error!("BMO: URL delivery failed with error code {}", error_code);
                                    session.state = BmoState::Error;
                                    let msg = match error_code {
                                        BMO_ERROR_UNAUTHENTICATED_SOURCE =>
                                            "Unauthenticated source: URL delivery requires expected_hash (key 8)",
                                        BMO_ERROR_HASH_MISMATCH => "Image hash mismatch",
                                        _ => "URL fetch failed",
                                    };
                                    let result = build_bmo_image_result(BMO_STATUS_ERROR, Some(msg));
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
                        // Mode 2: Device fetches signed meta-payload, then actual image
                        debug!("BMO: Using meta-URL delivery mode");
                        if let Some(meta_url) = &begin.url {
                            info!("BMO: Meta-URL delivery: {}", meta_url);
                            match process_bmo_meta_url_delivery(session, &mut begin, owner_key_point) {
                                Ok(()) => {
                                    session.begin = Some(begin);
                                    session.state = BmoState::Complete;
                                    let result = build_bmo_image_result(
                                        BMO_STATUS_SUCCESS,
                                        Some("Meta-payload resolved, image fetched"),
                                    );
                                    return Some((BMO_KEY_IMAGE_RESULT.to_string(), result));
                                }
                                Err(error_code) => {
                                    session.state = BmoState::Error;
                                    let msg = match error_code {
                                        BMO_ERROR_URL_FETCH_FAILED => "Meta-payload fetch failed",
                                        BMO_ERROR_META_SIGNATURE_INVALID => "Meta-payload signature invalid",
                                        BMO_ERROR_META_PARSE_ERROR => "Meta-payload parse error",
                                        BMO_ERROR_HASH_MISMATCH => "Image hash mismatch",
                                        BMO_ERROR_NOT_AUTHORIZED => "Provisioning not authorized: unauthenticated meta-payload carries instruction fields",
                                        BMO_ERROR_UNAUTHENTICATED_SOURCE => "Unauthenticated source: no hash, signature, or validated TLS covers the content",
                                        _ => "Meta-URL delivery failed",
                                    };
                                    let result = build_bmo_image_result(BMO_STATUS_ERROR, Some(msg));
                                    return Some((BMO_KEY_IMAGE_RESULT.to_string(), result));
                                }
                            }
                        } else {
                            error!("BMO: Meta-URL delivery mode requested but no URL (-7) provided");
                            session.state = BmoState::Error;
                            let result = build_bmo_image_result(BMO_STATUS_ERROR, Some("Meta-URL mode but no URL"));
                            return Some((BMO_KEY_IMAGE_RESULT.to_string(), result));
                        }
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
            let begin_hash = session.begin.as_ref().and_then(|b| b.expected_hash.clone());

            // Decide what must be verified. This fails closed: there is no
            // longer a path where a missing hash means "proceed anyway".
            let expected_hash = match inline_hash_decision(
                session.authority,
                begin_hash.as_deref(),
                end_hash.as_deref(),
            ) {
                Ok(h) => h,
                Err(e) => {
                    error!("BMO: {}", e.message());
                    error!("BMO: REFUSING to chainload — nothing authenticated covers these bytes.");
                    session.state = BmoState::Error;
                    let result = build_bmo_image_result(BMO_STATUS_ERROR, Some(e.message()));
                    return Some((BMO_KEY_IMAGE_RESULT.to_string(), result));
                }
            };

            // Verify SHA256 hash of reassembled image buffer
            {
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

            // Same authorisation gate as image-begin, via the same pure
            // function, for the same reason.
            let (auth, inner_data) = check_bmo_authorization(
                value, owner_key_point, peer,
                crate::cose::BMO_CONTENT_TYPE_SET, device_guid);

            if !auth.is_authorized() {
                error!("BMO: set REJECTED: {}", auth.rejection_reason());
                session.state = BmoState::Error;
                let result = build_bmo_set_response(BMO_STATUS_ERROR,
                    Some(auth.rejection_reason()));
                return Some((BMO_KEY_SET_RESPONSE.to_string(), result));
            }

            let parse_data = match &inner_data {
                Some(d) => d.as_slice(),
                None => value,
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
    
    // The image comes over plain HTTP, outside the TO2 session, and this
    // firmware has no validated TLS, so expected_hash (key 8) in image-begin
    // is the only thing that can speak for these bytes. Decide BEFORE
    // downloading, so an unverifiable configuration fetches nothing.
    let expected_hash = match url_hash_decision(session.authority, begin.expected_hash.as_deref()) {
        Ok(h) => h,
        Err(e) => {
            error!("BMO: {}", e.message());
            error!("BMO: URL delivery fetches the image outside the authenticated TO2");
            error!("BMO: channel. Without expected_hash (key 8) in image-begin, anyone on");
            error!("BMO: the path chooses what this device executes. REFUSING (error 19).");
            return Err(e.code());
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
    

    {
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
    }
    
    // Store the image data in the session buffer
    session.image_buffer = image_data;
    session.bytes_received = session.image_buffer.len() as u64;
    
    info!("BMO: Image ready for boot ({} bytes, integrity verified)", session.image_buffer.len());
    
    Ok(())
}

/// Process BMO meta-URL delivery mode (delivery_mode = 2).
///
/// 1. Fetch the meta-payload from the URL in `begin.url`.
/// 2. If `begin.meta_signer` is set, verify the COSE_Sign1 signature.
/// 3. Parse the inner MetaPayload CBOR to get the actual image URL and hash.
/// 4. Fetch the actual image from `meta.url`.
/// 5. Verify the SHA-256 hash if `meta.expected_hash` is present.
/// 6. Store the image in `session.image_buffer`.
#[cfg(target_os = "uefi")]
fn process_bmo_meta_url_delivery(
    session: &mut BmoSession,
    begin: &mut BmoImageBegin,
    owner_key_point: Option<&[u8]>,
) -> Result<(), u8> {
    let meta_url = match &begin.url {
        Some(u) => u.clone(),
        None => {
            error!("BMO meta: No meta-payload URL (-7) provided");
            return Err(BMO_ERROR_URL_FETCH_FAILED);
        }
    };

    // Step 1: Fetch meta-payload
    info!("BMO meta: Fetching meta-payload from {}", meta_url);
    let meta_data = match crate::http_api::http_get(&meta_url) {
        Some(data) => {
            info!("BMO meta: Downloaded {} bytes of meta-payload", data.len());
            data
        }
        None => {
            error!("BMO meta: HTTP GET failed for meta-payload URL: {}", meta_url);
            return Err(BMO_ERROR_URL_FETCH_FAILED);
        }
    };

    // Step 2: Authenticate the meta-payload by signature: named publisher
    // (meta_signer, key 9), or — with no meta_signer — the Owner key or a
    // PERM.7 delegate x5chain. This firmware has no validated TLS, so an
    // unsigned meta-payload is unauthenticated and may only be a pointer.
    let (meta_cbor, meta_authenticated) = verify_and_extract_meta(
        &meta_data,
        begin.meta_signer.as_deref(),
        owner_key_point,
    )?;
    if !meta_authenticated {
        warn!("BMO meta: meta-payload is UNSIGNED — usable only as a pointer to an image");
        warn!("BMO meta: pinned by expected_hash (key 8) in image-begin.");
    }

    // Step 3: Parse MetaPayload
    let meta = parse_meta_payload(&meta_cbor).ok_or_else(|| {
        error!("BMO meta: Failed to parse MetaPayload CBOR");
        BMO_ERROR_META_PARSE_ERROR
    })?;

    info!("BMO meta: Resolved → mime={}, url={}", meta.mime_type, meta.url);
    if let Some(ref name) = meta.name {
        info!("BMO meta: name={}", name);
    }
    if let Some(ref version) = meta.version {
        info!("BMO meta: version={}", version);
    }
    if meta.expected_hash.is_some() {
        info!("BMO meta: hash_alg={}, hash present",
            meta.hash_alg.as_deref().unwrap_or("sha256"));
    }

    // Step 3a: An unauthenticated meta-payload is only a pointer: it needs a
    // pinned image hash and may not carry instruction fields.
    if let Err(e) = check_unauthenticated_meta(&meta, meta_authenticated, begin.expected_hash.as_deref()) {
        error!("BMO meta: {} — REFUSING (error {})", e.message(), e.code());
        return Err(e.code());
    }

    // Step 3b: Work out what must cover the image BEFORE downloading it.
    // Deciding here rather than after the fetch means an unverifiable
    // configuration is refused without pulling an image we could never trust.
    let plan = match meta_hash_decision(
        session.authority,
        begin.expected_hash.as_deref(),
        meta_authenticated,
        meta.expected_hash.as_deref(),
    ) {
        Ok(p) => p,
        Err(e) => {
            error!("BMO meta: {}", e.message());
            error!("BMO meta: meta-URL delivery fetches both the meta-payload and the image");
            error!("BMO meta: outside the authenticated TO2 channel. Either sign the");
            error!("BMO meta: meta-payload, or put expected_hash (key 8) in image-begin.");
            error!("BMO meta: REFUSING (error {}).", e.code());
            return Err(e.code());
        }
    };

    // Step 4: Fetch actual image
    info!("BMO meta: Fetching actual image from {}", meta.url);
    let image_data = match crate::http_api::http_get(&meta.url) {
        Some(data) => {
            info!("BMO meta: Downloaded {} bytes of actual image", data.len());
            data
        }
        None => {
            error!("BMO meta: HTTP GET failed for image URL: {}", meta.url);
            return Err(BMO_ERROR_URL_FETCH_FAILED);
        }
    };

    // Step 5: Verify every hash the plan requires. When both image-begin and
    // a signed meta-payload carry one, both must match — that also catches a
    // signed meta-payload pointing somewhere image-begin did not authorise.
    {
        let mut hasher = Sha256::new();
        hasher.update(&image_data);
        let computed = hasher.finalize();
        let computed_bytes = computed.as_slice();

        for (i, expected_hash) in plan.required.iter().enumerate() {
            debug!("BMO meta: SHA256 verification {}/{}:", i + 1, plan.required.len());
            debug!("  Expected: {:02x?}", &expected_hash[..core::cmp::min(16, expected_hash.len())]);
            debug!("  Computed: {:02x?}", &computed_bytes[..16]);

            if computed_bytes != expected_hash.as_slice() {
                error!("BMO meta: SHA256 MISMATCH! Downloaded image is CORRUPTED.");
                error!("BMO meta: REFUSING to chainload — data integrity check FAILED.");
                return Err(BMO_ERROR_HASH_MISMATCH);
            }
        }
        info!("BMO meta: Image hash VERIFIED ({} hash(es) checked)", plan.required.len());
    }

    // Step 6: Store in session buffer
    session.image_buffer = image_data;
    session.bytes_received = session.image_buffer.len() as u64;

    info!("BMO meta: Image ready for boot ({} bytes)", session.image_buffer.len());

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
    let result = process_bmo_message(&mut session, "fdo.bmo:active", &active_value, None, PeerAuthority::Unauthenticated, None);
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
    
    let result = process_bmo_message(&mut session, BMO_KEY_IMAGE_BEGIN, &begin_msg, None, PeerAuthority::Unauthenticated, None);
    debug!("  Result: {:?}", result.is_some());
    debug!("  State: {:?}", session.state);
    
    // Simulate image data chunks
    debug!("Test 3: Processing fdo.bmo:image-data chunks");
    let chunk_data: Vec<u8> = (0u8..50).collect();
    let result = process_bmo_message(&mut session, "fdo.bmo:image-data-0", &chunk_data, None, PeerAuthority::Unauthenticated, None);
    debug!("  Chunk 0 result: {:?}, bytes_received: {}", result.is_some(), session.bytes_received);
    
    let chunk_data: Vec<u8> = (50u8..100).collect();
    let result = process_bmo_message(&mut session, "fdo.bmo:image-data-1", &chunk_data, None, PeerAuthority::Unauthenticated, None);
    debug!("  Chunk 1 result: {:?}, bytes_received: {}", result.is_some(), session.bytes_received);
    
    // Simulate image-end
    debug!("Test 4: Processing fdo.bmo:image-end");
    let end_msg = alloc::vec![0xf6]; // CBOR null
    let result = process_bmo_message(&mut session, BMO_KEY_IMAGE_END, &end_msg, None, PeerAuthority::Unauthenticated, None);
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
        // key 5 = delivery_mode (generic)
        enc.uint(CHUNK_FIELD_DELIVERY_MODE as u16);
        enc.uint(delivery_mode as u16);
        enc.into_bytes()
    }

    // --- delivery keys 5..9 and legacy aliases -6..-10 ---

    #[test]
    fn test_parse_image_begin_generic_delivery_keys() {
        let mut enc = CborEncoder::new();
        enc.encode_map(5);
        enc.neg_int(-1); enc.text("application/efi");
        enc.uint(5); enc.uint(2);
        enc.uint(6); enc.text("https://x/meta");
        enc.uint(8); enc.bytes(&[0xAA; 32]);
        enc.uint(9); enc.bytes(&[0x01]);
        let b = parse_bmo_image_begin(&enc.into_bytes()).expect("generic keys should parse");
        assert_eq!(b.delivery_mode, 2);
        assert_eq!(b.url.as_deref(), Some("https://x/meta"));
        assert_eq!(b.expected_hash.as_deref(), Some(&[0xAA; 32][..]));
        assert_eq!(b.meta_signer.as_deref(), Some(&[0x01][..]));
    }

    #[test]
    fn test_parse_image_begin_legacy_aliases_accepted() {
        let mut enc = CborEncoder::new();
        enc.encode_map(4);
        enc.neg_int(-1); enc.text("application/efi");
        enc.neg_int(-6); enc.uint(1);
        enc.neg_int(-7); enc.text("https://x/img");
        enc.neg_int(-9); enc.bytes(&[0xBB; 32]);
        let b = parse_bmo_image_begin(&enc.into_bytes()).expect("legacy aliases should parse");
        assert_eq!(b.delivery_mode, 1);
        assert_eq!(b.url.as_deref(), Some("https://x/img"));
        assert_eq!(b.expected_hash.as_deref(), Some(&[0xBB; 32][..]));
    }

    #[test]
    fn test_parse_image_begin_alias_conflict_rejected() {
        let mut enc = CborEncoder::new();
        enc.encode_map(3);
        enc.neg_int(-1); enc.text("application/efi");
        enc.uint(8); enc.bytes(&[0xAA; 32]);
        enc.neg_int(-9); enc.bytes(&[0xBB; 32]);
        assert!(parse_bmo_image_begin(&enc.into_bytes()).is_none(),
            "generic key and legacy alias with different values must be rejected");

        let mut same = CborEncoder::new();
        same.encode_map(3);
        same.neg_int(-1); same.text("application/efi");
        same.uint(6); same.text("https://x");
        same.neg_int(-7); same.text("https://x");
        assert!(parse_bmo_image_begin(&same.into_bytes()).is_some(),
            "identical values under both keys are accepted");
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
            &data, Some(&owner_point), PeerAuthority::OwnerDirect, BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
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
            &data, Some(&owner_point), PeerAuthority::Delegate { provision: true }, BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
        );
        assert_eq!(result, BmoAuthResult::UnsignedModel2);
    }

    // --- Unsigned with no owner key (legacy/test mode) ---

    #[test]
    fn test_bmo_auth_unsigned_no_owner_key() {
        let data = build_unsigned_image_begin();
        let (result, _) = check_bmo_authorization(
            &data, None, PeerAuthority::Unauthenticated, BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
        );
        assert_eq!(result, BmoAuthResult::UnsignedLegacy);
    }

    // --- Onboard-only delegate (no PERM.7) ---
    //
    // Regression: before PeerAuthority existed, the caller passed
    // (Some(owner_key), delegate_has_provision=false) for BOTH the Owner and
    // an onboard-only delegate, and both were accepted as Model 1. That let a
    // delegate the Owner had explicitly *not* granted provisioning choose the
    // image (and its hash) to install.

    #[test]
    fn test_bmo_auth_unsigned_onboard_only_delegate_refused() {
        let (_, owner_point) = gen_test_keypair();
        for (ct, data) in [
            (BMO_CONTENT_TYPE_IMAGE_BEGIN, build_unsigned_image_begin()),
            (BMO_CONTENT_TYPE_SET, alloc::vec![0x80]), // empty array
        ] {
            let (result, inner) = check_bmo_authorization(
                &data, Some(&owner_point), PeerAuthority::Delegate { provision: false }, ct, None,
            );
            assert_eq!(result, BmoAuthResult::UnsignedRefused, "ct={}", ct);
            assert!(!result.is_authorized());
            assert!(inner.is_none());
        }
    }

    /// Control for the test above: identical input, only the peer differs.
    /// Proves the refusal is attributable to the missing PERM.7.
    #[test]
    fn test_bmo_auth_unsigned_peer_matrix() {
        let (_, owner_point) = gen_test_keypair();
        let data = build_unsigned_image_begin();
        let cases = [
            (PeerAuthority::OwnerDirect, BmoAuthResult::UnsignedModel1),
            (PeerAuthority::Delegate { provision: true }, BmoAuthResult::UnsignedModel2),
            (PeerAuthority::Delegate { provision: false }, BmoAuthResult::UnsignedRefused),
            // Owner key known but no proven peer: inconsistent, fail closed.
            (PeerAuthority::Unauthenticated, BmoAuthResult::UnsignedRefused),
        ];
        for (peer, expected) in cases {
            let (result, _) = check_bmo_authorization(
                &data, Some(&owner_point), peer, BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
            );
            assert_eq!(result, expected, "peer={:?}", peer);
            assert_eq!(result.is_authorized(), peer.has_channel_provision_authority(),
                "peer={:?}", peer);
        }
    }

    /// The whole point of onboard-only delegation: the delegate operates the
    /// service, the Owner decides what is installed. An Owner-signed artifact
    /// relayed by an onboard-only delegate must be accepted.
    #[test]
    fn test_bmo_auth_onboard_only_delegate_relays_owner_signed() {
        let (sk, owner_point) = gen_test_keypair();
        let data = build_signed_image_begin(&sk);
        let (result, inner) = check_bmo_authorization(
            &data, Some(&owner_point), PeerAuthority::Delegate { provision: false },
            BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
        );
        assert_eq!(result, BmoAuthResult::SignedOk);
        assert!(inner.is_some());
        assert_eq!(result.to_authority(), BmoAuthority::Artifact);
    }

    #[test]
    fn test_bmo_auth_onboard_only_delegate_relays_owner_signed_tampered() {
        let (sk, owner_point) = gen_test_keypair();
        let mut data = build_signed_image_begin(&sk);
        let last = data.len() - 1;
        data[last] ^= 0x01;
        let (result, _) = check_bmo_authorization(
            &data, Some(&owner_point), PeerAuthority::Delegate { provision: false },
            BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
        );
        assert_eq!(result, BmoAuthResult::SignedFailed);
    }

    #[test]
    fn test_refused_maps_to_strictest_authority() {
        assert_eq!(BmoAuthResult::UnsignedRefused.to_authority(), BmoAuthority::Artifact);
        assert!(!BmoAuthResult::UnsignedRefused.is_authorized());
        assert_ne!(BmoAuthResult::UnsignedRefused.rejection_reason(),
                   BmoAuthResult::SignedFailed.rejection_reason());
    }

    // --- Model 3: Owner-signed, correct key ---

    #[test]
    fn test_bmo_auth_signed_owner_key_valid() {
        let (sk, owner_point) = gen_test_keypair();
        let data = build_signed_image_begin(&sk);
        let (result, inner) = check_bmo_authorization(
            &data, Some(&owner_point), PeerAuthority::OwnerDirect, BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
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
            &data, Some(&wrong_point), PeerAuthority::OwnerDirect, BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
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
            &data, None, PeerAuthority::Unauthenticated, BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
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
            &data, Some(&owner_point), PeerAuthority::OwnerDirect, BMO_CONTENT_TYPE_SET, None,
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
            &data, Some(&owner_point), PeerAuthority::OwnerDirect, BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
        );
        assert_eq!(result, BmoAuthResult::SignedFailed);
    }

    // =====================================================================
    // Security audit 2026-09-29 — H1: image hash policy.
    //
    // Every one of these "must reject" cases was ACCEPTED before the policy
    // existed: the old code warned and chainloaded anyway. The device
    // executes whatever comes out of BMO, so a missing hash has to be fatal.
    // =====================================================================

    const H_A: &[u8] = &[0xAAu8; 32];
    const H_B: &[u8] = &[0xBBu8; 32];

    // ---- authority mapping ----
    //
    // `process_bmo_message` is UEFI-only, so the wiring from "how was this
    // authorised" to "how strict is the hash rule" cannot be exercised
    // natively end-to-end. It is routed through these two pure functions
    // precisely so the decision itself can be tested here.

    #[test]
    fn test_auth_result_maps_to_authority() {
        // A verified signature must produce Artifact authority — this is
        // what forces key -9 to be present. Getting this mapping wrong
        // would silently downgrade Model 3/4 to the permissive rules while
        // every hash-policy test still passed.
        assert_eq!(BmoAuthResult::SignedOk.to_authority(), BmoAuthority::Artifact);
        assert_eq!(BmoAuthResult::UnsignedModel1.to_authority(), BmoAuthority::Channel);
        assert_eq!(BmoAuthResult::UnsignedModel2.to_authority(), BmoAuthority::Channel);
        assert_eq!(BmoAuthResult::UnsignedLegacy.to_authority(), BmoAuthority::Unauthenticated);
        // Strictest available for the rejected case.
        assert_eq!(BmoAuthResult::SignedFailed.to_authority(), BmoAuthority::Artifact);
    }

    #[test]
    fn test_only_signed_failure_is_unauthorized() {
        assert!(!BmoAuthResult::SignedFailed.is_authorized());
        assert!(BmoAuthResult::SignedOk.is_authorized());
        assert!(BmoAuthResult::UnsignedModel1.is_authorized());
        assert!(BmoAuthResult::UnsignedModel2.is_authorized());
        assert!(BmoAuthResult::UnsignedLegacy.is_authorized());
    }

    /// The composition that actually matters: a signed image-begin ends up
    /// under Artifact authority, which then rejects a missing key -9. This
    /// is the H1 chain minus the UEFI-only plumbing between the two halves.
    #[test]
    fn test_signed_begin_composes_to_hash_requirement() {
        let (auth, _) = check_bmo_authorization(
            &[0xA1, 0x00, 0x01],           // bare CBOR map — unsigned
            Some(&[0u8; 65]), PeerAuthority::OwnerDirect,
            crate::cose::BMO_CONTENT_TYPE_IMAGE_BEGIN, None);
        assert_eq!(auth.to_authority(), BmoAuthority::Channel);
        // Channel authority: an image-end hash suffices.
        assert!(inline_hash_decision(auth.to_authority(), None, Some(H_A)).is_ok());

        // Artifact authority (what a verified tag-18 body yields) does not.
        let artifact = BmoAuthResult::SignedOk.to_authority();
        assert_eq!(
            inline_hash_decision(artifact, None, Some(H_A)).unwrap_err(),
            HashPolicyError::SignedWithoutHash);
    }

    // ---- inline (mode 0) ----

    #[test]
    fn test_inline_signed_begin_without_hash_rejected() {
        // Model 3/4: image-begin verified, but carries no key -9. The
        // signature then covers only metadata, so an image-end hash from the
        // same stream proves nothing about what was authorised.
        let r = inline_hash_decision(BmoAuthority::Artifact, None, Some(H_A));
        assert_eq!(r.unwrap_err(), HashPolicyError::SignedWithoutHash);

        // ...and with no hash at all.
        let r = inline_hash_decision(BmoAuthority::Artifact, None, None);
        assert_eq!(r.unwrap_err(), HashPolicyError::SignedWithoutHash);
    }

    #[test]
    fn test_inline_signed_begin_with_hash_accepted() {
        // Control: the same case with key -9 present must verify, proving the
        // rejections above come from the missing hash and nothing else.
        let r = inline_hash_decision(BmoAuthority::Artifact, Some(H_A), None).unwrap();
        assert_eq!(r, H_A);
        let r = inline_hash_decision(BmoAuthority::Artifact, Some(H_A), Some(H_A)).unwrap();
        assert_eq!(r, H_A);
    }

    #[test]
    fn test_inline_no_hash_anywhere_rejected() {
        // Channel authority still needs *a* hash — the Owner is authenticated
        // but nothing commits to the bytes.
        assert_eq!(
            inline_hash_decision(BmoAuthority::Channel, None, None).unwrap_err(),
            HashPolicyError::NoHash);
        assert_eq!(
            inline_hash_decision(BmoAuthority::Unauthenticated, None, None).unwrap_err(),
            HashPolicyError::NoHash);
    }

    #[test]
    fn test_inline_channel_authority_accepts_image_end_hash() {
        // image-end arrives inside the Owner-bound TO2 session, so under
        // channel authority it carries the Owner's word. This is the one
        // place an image-end hash is sufficient.
        let r = inline_hash_decision(BmoAuthority::Channel, None, Some(H_A)).unwrap();
        assert_eq!(r, H_A);
    }

    #[test]
    fn test_inline_begin_end_disagreement_rejected() {
        assert_eq!(
            inline_hash_decision(BmoAuthority::Channel, Some(H_A), Some(H_B)).unwrap_err(),
            HashPolicyError::BeginEndDisagree);
        assert_eq!(
            inline_hash_decision(BmoAuthority::Artifact, Some(H_A), Some(H_B)).unwrap_err(),
            HashPolicyError::BeginEndDisagree);
    }

    // ---- URL delivery (mode 1) ----

    #[test]
    fn test_url_delivery_without_hash_rejected() {
        // The image is fetched over plain HTTP, outside the authenticated
        // channel. No authority level makes that acceptable without key -9.
        for authority in [BmoAuthority::Artifact, BmoAuthority::Channel,
                          BmoAuthority::Unauthenticated] {
            assert_eq!(
                url_hash_decision(authority, None).unwrap_err(),
                HashPolicyError::UnauthenticatedSource,
                "URL delivery with no expected_hash must be refused ({:?})", authority);
        }
    }

    #[test]
    fn test_url_delivery_with_hash_accepted() {
        let r = url_hash_decision(BmoAuthority::Channel, Some(H_A)).unwrap();
        assert_eq!(r, H_A);
    }

    // ---- meta-URL delivery (mode 2) ----

    #[test]
    fn test_meta_unsigned_without_begin_hash_rejected() {
        // Unsigned meta-payload: its url AND its hash are attacker-chosen, so
        // checking the image against meta.expected_hash is checking the
        // attacker's bytes against the attacker's hash.
        assert_eq!(
            meta_hash_decision(BmoAuthority::Channel, None, false, Some(H_A)).unwrap_err(),
            HashPolicyError::UnauthenticatedSource);
        assert_eq!(
            meta_hash_decision(BmoAuthority::Artifact, None, false, Some(H_A)).unwrap_err(),
            HashPolicyError::UnauthenticatedSource);
        assert_eq!(
            meta_hash_decision(BmoAuthority::Channel, None, false, None).unwrap_err(),
            HashPolicyError::UnauthenticatedSource);
    }

    #[test]
    fn test_meta_unsigned_with_begin_hash_accepted() {
        // key -9 came over the TO2 channel, so it can stand in for a
        // signature on the meta-payload.
        let plan = meta_hash_decision(BmoAuthority::Artifact, Some(H_A), false, Some(H_B)).unwrap();
        // Changed 2026-10-02: the unauthenticated meta-payload's hash is still
        // ENFORCED (it can only make acceptance stricter) — it just does not
        // count as evidence. Previously it was ignored.
        assert_eq!(plan.required, alloc::vec![H_A.to_vec(), H_B.to_vec()]);
    }

    #[test]
    fn test_meta_signed_uses_meta_hash() {
        let plan = meta_hash_decision(BmoAuthority::Channel, None, true, Some(H_A)).unwrap();
        assert_eq!(plan.required, alloc::vec![H_A.to_vec()]);
    }

    #[test]
    fn test_meta_signed_without_any_hash_rejected() {
        // A signed meta-payload that commits to no hash still leaves the
        // image bytes uncovered.
        assert_eq!(
            meta_hash_decision(BmoAuthority::Channel, None, true, None).unwrap_err(),
            HashPolicyError::UnauthenticatedSource);
    }

    #[test]
    fn test_meta_both_hashes_enforced() {
        // When image-begin and a signed meta-payload both commit to a hash,
        // both are checked — a signed meta-payload cannot redirect to content
        // image-begin did not authorise.
        let plan = meta_hash_decision(BmoAuthority::Artifact, Some(H_A), true, Some(H_B)).unwrap();
        assert_eq!(plan.required.len(), 2);
        assert!(plan.required.contains(&H_A.to_vec()));
        assert!(plan.required.contains(&H_B.to_vec()));
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
            &data, Some(&owner_point), PeerAuthority::OwnerDirect, BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
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
            &data, Some(&owner_point), PeerAuthority::OwnerDirect, BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
        );
        assert_eq!(result, BmoAuthResult::SignedFailed,
            "delegate chain not rooted in owner must be rejected");
    }

    /// Build a delegate-signed (x5chain) image-begin whose single leaf cert is
    /// issued by `owner_sk` with the given permission OIDs.
    fn build_delegate_signed_image_begin(
        owner_sk: &p256::ecdsa::SigningKey, perms: &[&[u8]],
    ) -> Vec<u8> {
        let (delegate_sk, delegate_point) = gen_test_keypair_b();
        let cert_der = crate::delegate::build_test_cert(owner_sk, &delegate_point, perms);
        let protected = build_test_protected_header(Some(BMO_CONTENT_TYPE_IMAGE_BEGIN));
        let aad = domain_aad(AAD_TAG_BMO_PROVISION, 200);
        let mut unhdr = alloc::vec![0xa1, 0x18, 33];
        crate::cose::encode_bstr(&mut unhdr, &cert_der);
        build_test_cose_sign1(&protected, b"\xa1\x00\x18\x34", &aad, &unhdr, &delegate_sk)
    }

    /// Model 4 relayed by an onboard-only peer: the TO2 peer and the artifact
    /// signer are different parties. Accepted because the *signer* has PERM.7.
    #[test]
    fn test_bmo_auth_onboard_only_delegate_relays_model4() {
        use crate::delegate::{OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED};
        let (owner_sk, owner_point) = gen_test_keypair();
        let data = build_delegate_signed_image_begin(
            &owner_sk, &[OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED]);
        let (result, inner) = check_bmo_authorization(
            &data, Some(&owner_point), PeerAuthority::Delegate { provision: false },
            BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
        );
        assert_eq!(result, BmoAuthResult::SignedOk);
        assert!(inner.is_some());
    }

    /// Device-side Model 4 negative: the signer's chain is validly rooted in
    /// the Owner but lacks PERM.7. Previously only covered by the server
    /// refusing to start (`start9 --no-provision`), so the device never saw it.
    /// Checked from every peer type — a PERM.7 *peer* must not lend its
    /// permission to a signer that lacks it.
    #[test]
    fn test_bmo_auth_model4_signer_without_provision_rejected() {
        use crate::delegate::OID_PERMIT_ONBOARD_NEWCRED;
        let (owner_sk, owner_point) = gen_test_keypair();
        let data = build_delegate_signed_image_begin(&owner_sk, &[OID_PERMIT_ONBOARD_NEWCRED]);
        for peer in [PeerAuthority::OwnerDirect,
                     PeerAuthority::Delegate { provision: true },
                     PeerAuthority::Delegate { provision: false }] {
            let (result, inner) = check_bmo_authorization(
                &data, Some(&owner_point), peer, BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
            );
            assert_eq!(result, BmoAuthResult::SignedFailed, "peer={:?}", peer);
            assert!(inner.is_none());
        }
    }

    // ===== Meta-payload tests =====

    /// Build a MetaPayload CBOR map from the given fields.
    fn build_test_meta_payload(
        mime: &str,
        url: &str,
        hash_alg: Option<&str>,
        expected_hash: Option<&[u8]>,
        name: Option<&str>,
    ) -> Vec<u8> {
        let mut count = 2u8; // mime + url are required
        if hash_alg.is_some() { count += 1; }
        if expected_hash.is_some() { count += 1; }
        if name.is_some() { count += 1; }

        let mut enc = CborEncoder::new();
        enc.encode_map(count as usize);
        enc.uint(0); enc.text(mime);
        enc.uint(1); enc.text(url);
        if let Some(ha) = hash_alg {
            enc.uint(3); enc.text(ha);
        }
        if let Some(eh) = expected_hash {
            enc.uint(4); enc.bytes(eh);
        }
        if let Some(n) = name {
            enc.uint(6); enc.text(n);
        }
        enc.into_bytes()
    }

    /// Build a COSE_Key CBOR map for a P-256 public key (uncompressed point).
    fn build_test_cose_key(point: &[u8]) -> Vec<u8> {
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 0x04);
        let x = &point[1..33];
        let y = &point[33..65];

        let mut enc = CborEncoder::new();
        // COSE_Key map: { 1: 2 (kty=EC2), -1: 1 (crv=P-256), -2: x, -3: y }
        enc.encode_map(4);
        enc.uint(1); enc.uint(2);            // kty = EC2
        enc.neg_int(-1); enc.uint(1);        // crv = P-256
        enc.neg_int(-2); enc.bytes(x);       // x coordinate
        enc.neg_int(-3); enc.bytes(y);       // y coordinate
        enc.into_bytes()
    }

    #[test]
    fn test_parse_meta_payload_basic() {
        let cbor = build_test_meta_payload(
            "application/efi",
            "http://10.0.0.1/image.efi",
            None, None, None,
        );
        let meta = parse_meta_payload(&cbor).expect("should parse");
        assert_eq!(meta.mime_type, "application/efi");
        assert_eq!(meta.url, "http://10.0.0.1/image.efi");
        assert!(meta.expected_hash.is_none());
        assert!(meta.name.is_none());
    }

    #[test]
    fn test_parse_meta_payload_all_fields() {
        let hash = [0xAA; 32];
        let cbor = build_test_meta_payload(
            "application/x-raw-disk-image",
            "http://cdn.example.com/image.dd.gz",
            Some("sha256"),
            Some(&hash),
            Some("test-image"),
        );
        let meta = parse_meta_payload(&cbor).expect("should parse");
        assert_eq!(meta.mime_type, "application/x-raw-disk-image");
        assert_eq!(meta.url, "http://cdn.example.com/image.dd.gz");
        assert_eq!(meta.hash_alg.as_deref(), Some("sha256"));
        assert_eq!(meta.expected_hash.as_deref(), Some(&hash[..]));
        assert_eq!(meta.name.as_deref(), Some("test-image"));
    }

    #[test]
    fn test_parse_meta_payload_missing_mime() {
        // Map with only key 1 (url), missing key 0 (mime)
        let mut enc = CborEncoder::new();
        enc.encode_map(1);
        enc.uint(1); enc.text("http://example.com/img");
        let result = parse_meta_payload(&enc.into_bytes());
        assert!(result.is_none(), "missing mime_type must fail");
    }

    #[test]
    fn test_parse_meta_payload_missing_url() {
        let mut enc = CborEncoder::new();
        enc.encode_map(1);
        enc.uint(0); enc.text("application/efi");
        let result = parse_meta_payload(&enc.into_bytes());
        assert!(result.is_none(), "missing url must fail");
    }

    #[test]
    fn test_parse_meta_payload_empty_map() {
        let result = parse_meta_payload(&[0xa0]); // map(0)
        assert!(result.is_none(), "empty map must fail");
    }

    #[test]
    fn test_parse_meta_payload_garbage() {
        let result = parse_meta_payload(&[0xFF, 0x00, 0x01]);
        assert!(result.is_none(), "garbage must fail");
    }

    #[test]
    fn test_parse_meta_payload_unknown_fields_ignored() {
        // Keys 0, 1, 99 — key 99 should be skipped
        let mut enc = CborEncoder::new();
        enc.encode_map(3);
        enc.uint(0); enc.text("application/efi");
        enc.uint(1); enc.text("http://example.com/img");
        enc.uint(99); enc.text("unknown value");
        let meta = parse_meta_payload(&enc.into_bytes()).expect("should parse");
        assert_eq!(meta.mime_type, "application/efi");
        assert_eq!(meta.url, "http://example.com/img");
    }

    // --- COSE_Key parsing ---

    #[test]
    fn test_parse_cose_key_p256_valid() {
        let (_, point) = gen_test_keypair();
        let cose_key = build_test_cose_key(&point);
        let parsed = parse_cose_key_p256(&cose_key).expect("should parse");
        assert_eq!(parsed, point);
    }

    #[test]
    fn test_parse_cose_key_p256_garbage() {
        let result = parse_cose_key_p256(&[0xFF, 0x00]);
        assert!(result.is_none(), "garbage must fail");
    }

    #[test]
    fn test_parse_cose_key_p256_empty() {
        let result = parse_cose_key_p256(&[]);
        assert!(result.is_none(), "empty must fail");
    }

    #[test]
    fn test_parse_cose_key_p256_not_a_map() {
        let result = parse_cose_key_p256(&[0x83, 0x01, 0x02, 0x03]); // array
        assert!(result.is_none(), "array must fail");
    }

    // --- Signed meta-payload verification ---

    #[test]
    fn test_verify_and_extract_meta_unsigned() {
        let cbor = build_test_meta_payload(
            "application/efi", "http://10.0.0.1/img.efi", None, None, None,
        );
        let (result, signed) = verify_and_extract_meta(&cbor, None, None).expect("unsigned should pass");
        assert_eq!(result, cbor);
        assert!(!signed, "unsigned meta-payload must be reported as unauthenticated");
    }

    #[test]
    fn test_verify_and_extract_meta_signed_valid() {
        let (sk, point) = gen_test_keypair();
        let cose_key = build_test_cose_key(&point);

        let meta_cbor = build_test_meta_payload(
            "application/efi", "http://cdn.example.com/img.efi",
            Some("sha256"), Some(&[0xBB; 32]), Some("signed-test"),
        );

        // Sign with meta-payload AAD
        let protected = build_test_protected_header(None);
        let aad = crate::cose::domain_aad(
            crate::cose::AAD_TAG_META_PAYLOAD,
            crate::cose::FDO_VERSION_200,
        );
        let envelope = build_test_cose_sign1(
            &protected, &meta_cbor, &aad, &[0xa0], &sk,
        );

        let (result, signed) = verify_and_extract_meta(&envelope, Some(&cose_key), None)
            .expect("valid signature should pass");
        assert!(signed);
        assert_eq!(result, meta_cbor);

        // Parse the extracted payload to confirm it's intact
        let meta = parse_meta_payload(&result).expect("should parse");
        assert_eq!(meta.url, "http://cdn.example.com/img.efi");
        assert_eq!(meta.name.as_deref(), Some("signed-test"));
    }

    #[test]
    fn test_verify_and_extract_meta_signed_wrong_key() {
        let (sk, _) = gen_test_keypair();
        let (_, wrong_point) = gen_test_keypair_b();
        let wrong_cose_key = build_test_cose_key(&wrong_point);

        let meta_cbor = build_test_meta_payload(
            "application/efi", "http://example.com/img", None, None, None,
        );
        let protected = build_test_protected_header(None);
        let aad = crate::cose::domain_aad(
            crate::cose::AAD_TAG_META_PAYLOAD,
            crate::cose::FDO_VERSION_200,
        );
        let envelope = build_test_cose_sign1(
            &protected, &meta_cbor, &aad, &[0xa0], &sk,
        );

        let result = verify_and_extract_meta(&envelope, Some(&wrong_cose_key), None);
        assert_eq!(result.unwrap_err(), BMO_ERROR_META_SIGNATURE_INVALID,
            "wrong signer key must fail");
    }

    #[test]
    fn test_verify_and_extract_meta_signed_tampered() {
        let (sk, point) = gen_test_keypair();
        let cose_key = build_test_cose_key(&point);

        let meta_cbor = build_test_meta_payload(
            "application/efi", "http://example.com/img", None, None, None,
        );
        let protected = build_test_protected_header(None);
        let aad = crate::cose::domain_aad(
            crate::cose::AAD_TAG_META_PAYLOAD,
            crate::cose::FDO_VERSION_200,
        );
        let mut envelope = build_test_cose_sign1(
            &protected, &meta_cbor, &aad, &[0xa0], &sk,
        );
        // Tamper with the last byte (in the signature)
        let last = envelope.len() - 1;
        envelope[last] ^= 0xFF;

        let result = verify_and_extract_meta(&envelope, Some(&cose_key), None);
        assert_eq!(result.unwrap_err(), BMO_ERROR_META_SIGNATURE_INVALID,
            "tampered signature must fail");
    }

    #[test]
    fn test_verify_and_extract_meta_signed_wrong_aad() {
        // Sign with BMO_PROVISION AAD instead of META_PAYLOAD AAD
        let (sk, point) = gen_test_keypair();
        let cose_key = build_test_cose_key(&point);

        let meta_cbor = build_test_meta_payload(
            "application/efi", "http://example.com/img", None, None, None,
        );
        let protected = build_test_protected_header(None);
        let wrong_aad = crate::cose::domain_aad(
            crate::cose::AAD_TAG_BMO_PROVISION,
            crate::cose::FDO_VERSION_200,
        );
        let envelope = build_test_cose_sign1(
            &protected, &meta_cbor, &wrong_aad, &[0xa0], &sk,
        );

        let result = verify_and_extract_meta(&envelope, Some(&cose_key), None);
        assert_eq!(result.unwrap_err(), BMO_ERROR_META_SIGNATURE_INVALID,
            "wrong domain AAD must fail");
    }

    #[test]
    fn test_verify_and_extract_meta_bad_cose_key() {
        // Garbage COSE_Key
        let result = verify_and_extract_meta(&[0xD2, 0x83, 0x40, 0xa0, 0x40], Some(&[0xFF, 0x00]), None);
        assert_eq!(result.unwrap_err(), BMO_ERROR_META_SIGNATURE_INVALID,
            "garbage COSE_Key must fail");
    }

    #[test]
    fn test_verify_and_extract_meta_not_cose_sign1() {
        // Raw CBOR map (not COSE_Sign1) when signer is expected
        let (_, point) = gen_test_keypair();
        let cose_key = build_test_cose_key(&point);
        let meta_cbor = build_test_meta_payload(
            "application/efi", "http://example.com/img", None, None, None,
        );
        let result = verify_and_extract_meta(&meta_cbor, Some(&cose_key), None);
        assert_eq!(result.unwrap_err(), BMO_ERROR_META_SIGNATURE_INVALID,
            "raw CBOR when signed expected must fail");
    }

    #[test]
    fn test_verify_meta_with_real_go_fdo_bytes() {
        // Actual wire bytes captured from go-fdo start15-meta-url.sh signed test.
        // This validates cross-implementation interop: go-fdo signs with
        // cose.AADMetaPayload, we verify with domain_aad(AAD_TAG_META_PAYLOAD).
        let meta_hex = "d28443a10126a05885a50078186170706c69636174696f6e2f782d756566692d696d616765017823687474703a2f2f31302e302e322e323a393039302f746573742d696d6167652e65666903667368613235360458202500aaa08a09c4bb1e02746842626ba8bc95bd9cfc9202fb9ef791fc3d23392f06766d6574612d746573742d696d6167652d7369676e6564584096d12d5fc8556add5aec81573f6bdb44b76cffa1a09f0bf58cd255a9254515699fe0571171dca6512993a171e23bbfae5c6020eab61f69152274d023d6dec6a1";
        let signer_hex = "a4010220012158203d28dc249ca429ea5340a6ab935447715067651a1958e8235695b972dd97213b2258201541a8871e240806c0a23276c3057937ab86b5bc16552f3e3a8cbc960d404e4e";

        let meta_data: Vec<u8> = (0..meta_hex.len()).step_by(2)
            .map(|i| u8::from_str_radix(&meta_hex[i..i+2], 16).unwrap())
            .collect();
        let signer_data: Vec<u8> = (0..signer_hex.len()).step_by(2)
            .map(|i| u8::from_str_radix(&signer_hex[i..i+2], 16).unwrap())
            .collect();

        // Verify COSE_Key parses correctly
        let point = parse_cose_key_p256(&signer_data);
        assert!(point.is_some(), "COSE_Key must parse: got None");
        assert_eq!(point.unwrap().len(), 65, "P-256 uncompressed point must be 65 bytes");

        // Verify the meta-payload signature
        let result = verify_and_extract_meta(&meta_data, Some(&signer_data), None);
        assert!(result.is_ok(), "go-fdo signed meta-payload must verify: {:?}", result.err());
    }
    // ===== Meta-payload rules (chunking-strategy.md, 2026-10-02) =====

    fn meta_with(extra: impl FnOnce(&mut CborEncoder), n_extra: usize) -> Vec<u8> {
        let mut enc = CborEncoder::new();
        enc.encode_map(2 + n_extra);
        enc.uint(0); enc.text("application/efi");
        enc.uint(1); enc.text("https://cdn/img.efi");
        extra(&mut enc);
        enc.into_bytes()
    }

    #[test]
    fn test_meta_instruction_fields_detected() {
        let plain = parse_meta_payload(&meta_with(|e| { e.uint(6); e.text("name"); }, 1)).unwrap();
        assert!(plain.instruction_fields().is_empty(), "pointer + informational fields are not instructions");

        let boot = parse_meta_payload(&meta_with(|e| { e.uint(5); e.text("init=/bin/sh"); }, 1)).unwrap();
        assert_eq!(boot.instruction_fields(), alloc::vec![String::from("boot_args")]);

        let ca = parse_meta_payload(&meta_with(|e| { e.uint(2); e.bytes(&[1, 2]); }, 1)).unwrap();
        assert_eq!(ca.instruction_fields(), alloc::vec![String::from("tls_ca")]);

        // A negative (FSIM-defined) key used to make the whole parse fail;
        // now it parses and is classified as an instruction.
        let fsim = parse_meta_payload(&meta_with(|e| { e.neg_int(-1); e.text("x"); }, 1))
            .expect("meta-payload with an FSIM-defined negative key must parse");
        assert_eq!(fsim.instruction_fields(), alloc::vec![String::from("key -1")]);
    }

    #[test]
    fn test_check_unauthenticated_meta_matrix() {
        let pointer = parse_meta_payload(&meta_with(|e| { e.uint(4); e.bytes(H_B); }, 1)).unwrap();
        let boot = parse_meta_payload(&meta_with(|e| { e.uint(5); e.text("init=/bin/sh"); }, 1)).unwrap();

        // Authenticated meta-payloads may carry anything.
        assert!(check_unauthenticated_meta(&boot, true, None).is_ok());
        // Unauthenticated, no pinned image hash: nothing authenticates the image.
        assert_eq!(check_unauthenticated_meta(&pointer, false, None).unwrap_err(),
            HashPolicyError::UnauthenticatedSource);
        // Unauthenticated pointer with pinned hash: allowed.
        assert!(check_unauthenticated_meta(&pointer, false, Some(H_A)).is_ok());
        // Unauthenticated with boot_args: refused even with a pinned hash.
        let e = check_unauthenticated_meta(&boot, false, Some(H_A)).unwrap_err();
        assert_eq!(e, HashPolicyError::InstructionFromUnauthenticatedMeta);
        assert_eq!(e.code(), BMO_ERROR_NOT_AUTHORIZED);
        assert_eq!(HashPolicyError::UnauthenticatedSource.code(), BMO_ERROR_UNAUTHENTICATED_SOURCE);
    }

    fn sign_meta(sk: &p256::ecdsa::SigningKey, meta: &[u8], unprotected: &[u8]) -> Vec<u8> {
        let protected = build_test_protected_header(None);
        let aad = domain_aad(crate::cose::AAD_TAG_META_PAYLOAD, 200);
        build_test_cose_sign1(&protected, meta, &aad, unprotected, sk)
    }

    fn x5chain_hdr(cert_der: &[u8]) -> Vec<u8> {
        let mut h = alloc::vec![0xa1, 0x18, 33];
        crate::cose::encode_bstr(&mut h, cert_der);
        h
    }

    #[test]
    fn test_meta_signed_by_owner_without_meta_signer() {
        let (owner_sk, owner_point) = gen_test_keypair();
        let meta = meta_with(|_| {}, 0);
        let signed = sign_meta(&owner_sk, &meta, &[0xa0]);

        let (inner, ok) = verify_and_extract_meta(&signed, None, Some(&owner_point))
            .expect("Owner-signed meta-payload must verify against the Owner key");
        assert!(ok && inner == meta);

        let (_, other_point) = gen_test_keypair_b();
        assert_eq!(verify_and_extract_meta(&signed, None, Some(&other_point)).unwrap_err(),
            BMO_ERROR_META_SIGNATURE_INVALID, "wrong Owner key must be rejected");
        assert_eq!(verify_and_extract_meta(&signed, None, None).unwrap_err(),
            BMO_ERROR_META_SIGNATURE_INVALID, "signed meta with no meta_signer and no Owner key must be rejected");
    }

    #[test]
    fn test_meta_signed_by_delegate_x5chain() {
        use crate::delegate::{build_test_cert, OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED};
        let (owner_sk, owner_point) = gen_test_keypair();
        let (delegate_sk, delegate_point) = gen_test_keypair_b();
        let meta = meta_with(|_| {}, 0);

        let good = build_test_cert(&owner_sk, &delegate_point, &[OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED]);
        let signed = sign_meta(&delegate_sk, &meta, &x5chain_hdr(&good));
        let (_, ok) = verify_and_extract_meta(&signed, None, Some(&owner_point))
            .expect("PERM.7 delegate-signed meta-payload must verify");
        assert!(ok);

        let no_perm = build_test_cert(&owner_sk, &delegate_point, &[OID_PERMIT_ONBOARD_NEWCRED]);
        let signed = sign_meta(&delegate_sk, &meta, &x5chain_hdr(&no_perm));
        assert_eq!(verify_and_extract_meta(&signed, None, Some(&owner_point)).unwrap_err(),
            BMO_ERROR_META_SIGNATURE_INVALID, "delegate without PERM.7 must be rejected");
    }

    #[test]
    fn test_meta_signer_named_but_unsigned_rejected() {
        let (_, point) = gen_test_keypair();
        let key = build_test_cose_key(&point);
        assert_eq!(verify_and_extract_meta(&meta_with(|_| {}, 0), Some(&key), None).unwrap_err(),
            BMO_ERROR_META_SIGNATURE_INVALID, "never downgraded to unsigned when meta_signer is named");
    }

    #[test]
    fn test_signed_begin_binds_content() {
        let mut b = BmoImageBegin::default();
        b.delivery_mode = BMO_DELIVERY_INLINE;
        assert_eq!(signed_begin_binds_content(BmoAuthority::Artifact, &b).unwrap_err(),
            HashPolicyError::SignedWithoutHash, "signed inline begin without key 8 refused at begin");
        assert!(signed_begin_binds_content(BmoAuthority::Channel, &b).is_ok(),
            "channel authority: image-end hash is acceptable, decided later");
        b.expected_hash = Some(H_A.to_vec());
        assert!(signed_begin_binds_content(BmoAuthority::Artifact, &b).is_ok());
        let mut m = BmoImageBegin::default();
        m.delivery_mode = BMO_DELIVERY_META_URL;
        assert!(signed_begin_binds_content(BmoAuthority::Artifact, &m).is_ok(),
            "meta-URL: the hash may come from a signed meta-payload");
    }
}
