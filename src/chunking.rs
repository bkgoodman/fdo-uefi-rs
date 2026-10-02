// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// Generic delivery and fetched-content rules, mirroring
// fdo-sim/fsim-repository/chunking-strategy.md:
//   - legacy begin-key alias merging ("Reserved Key Policy")
//   - meta-payload structure, field classes and signing ("Meta-Payload")
//   - evidence decisions for inline / URL / meta-URL content
//     ("Hash Handling", "Authenticating Fetched Content")
//   - transfer error codes 9-19
//
// Nothing here is BMO-specific; `bmo.rs` re-exports these for its paths.
// This firmware has no validated TLS, so TLS never counts as evidence here.

use log::{info, error, debug};
use alloc::vec::Vec;
use alloc::string::String;

use crate::fdo::CborDecoder;

/// Transfer error codes (chunking-strategy.md "Transfer Error Codes").
pub const ERR_URL_FETCH_FAILED: u8 = 9;
pub const ERR_TLS_VALIDATION_FAILED: u8 = 10;
pub const ERR_HASH_MISMATCH: u8 = 11;
pub const ERR_META_SIGNATURE_INVALID: u8 = 12;
pub const ERR_META_PARSE_ERROR: u8 = 13;
pub const ERR_DELIVERY_MODE_NOT_SUPPORTED: u8 = 14;
pub const ERR_NOT_AUTHORIZED: u8 = 15;
pub const ERR_SCOPE_MISMATCH: u8 = 16;
pub const ERR_VALIDITY_FAILED: u8 = 17;
pub const ERR_SUPERSEDED: u8 = 18;
pub const ERR_UNAUTHENTICATED_SOURCE: u8 = 19;

/// Returns true if `data` starts with CBOR tag 18 (0xD2 = major 6, value 18):
/// a tagged COSE_Sign1, i.e. artifact authority.
pub fn is_cbor_tag18(data: &[u8]) -> bool {
    data.first() == Some(&0xD2)
}

/// How a `*-begin` was authorised (chunking-strategy.md "Authorization").
/// How the `image-begin` that authorised the current transfer was established.
///
/// This decides how strict the image-hash policy has to be, so it is recorded
/// on the session at `image-begin` time and consulted again at `image-end`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Authority {
    /// Model 3/4 — `image-begin` was a COSE_Sign1 whose signature verified.
    /// The signature is only worth something if it covers the image bytes,
    /// so an authorising hash is mandatory.
    Artifact,
    /// Model 1/2 — `image-begin` was unsigned and accepted because the TO2
    /// session itself is bound to the Owner (ProveOVHdr signs xB, which the
    /// session keys derive from). Anything arriving over that channel carries
    /// the Owner's authority, including a hash in `image-end`.
    Channel,
    /// No Owner key was available at all (legacy/test paths only).
    Unauthenticated,
}

/// Delivery fields as read under one key numbering (generic or legacy).
#[derive(Default)]
pub(crate) struct DeliveryKeys {
    pub mode: Option<u64>,
    pub url: Option<String>,
    pub tls_ca: Option<Vec<u8>>,
    pub hash: Option<Vec<u8>>,
    pub signer: Option<Vec<u8>>,
}

/// Merge a generic delivery field with its legacy alias. Returns `None`
/// (malformed) if both are present with different values.
pub(crate) fn merge_alias<T: PartialEq>(name: &str, generic: Option<T>, legacy: Option<T>) -> Option<Option<T>> {
    match (generic, legacy) {
        (Some(g), Some(l)) if g != l => {
            error!("chunking: *-begin carries {} under both its generic key and legacy alias with different values — rejecting", name);
            None
        }
        (Some(g), _) => Some(Some(g)),
        (None, l) => Some(l),
    }
}


// ===== Meta-payload support (delivery_mode 2) =====

/// Parsed meta-payload descriptor.
///
/// CBOR map with integer keys per `fdo.bmo.md` MetaPayload CDDL:
/// ```text
/// MetaPayload = {
///   0: tstr,          ; mime_type (required)
///   1: tstr,          ; url       (required)
///   ? 2: bstr,        ; tls_ca
///   ? 3: tstr,        ; hash_alg
///   ? 4: bstr,        ; expected_hash
///   ? 5: tstr,        ; boot_args
///   ? 6: tstr,        ; name
///   ? 7: tstr,        ; version
///   ? 8: tstr,        ; description
/// }
/// ```
#[derive(Debug)]
pub struct MetaPayload {
    pub mime_type: String,
    pub url: String,
    pub tls_ca: Option<Vec<u8>>,
    pub hash_alg: Option<String>,
    pub expected_hash: Option<Vec<u8>>,
    pub boot_args: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    /// Keys this implementation does not define (FSIM-defined negative keys,
    /// or unknown generic keys). Instruction-class: an unauthenticated
    /// meta-payload carrying any of them is rejected.
    pub extra_keys: Vec<i32>,
}

impl MetaPayload {
    /// Instruction-class fields present (chunking-strategy.md "Meta-Payload
    /// Structure"): these change what the device trusts or does, so they may
    /// only come from an authenticated meta-payload. Pointer (mime_type,
    /// url), constraint (hash_alg, expected_hash) and informational (name,
    /// version, description) fields are not included.
    pub fn instruction_fields(&self) -> Vec<String> {
        let mut f = Vec::new();
        if self.tls_ca.is_some() {
            f.push(String::from("tls_ca"));
        }
        if self.boot_args.is_some() {
            f.push(String::from("boot_args"));
        }
        for k in &self.extra_keys {
            f.push(alloc::format!("key {}", k));
        }
        f
    }
}

/// Parse a MetaPayload CBOR map from raw bytes.
///
/// Returns `None` if the bytes are not a valid CBOR map or if the required
/// fields (0: mime_type, 1: url) are missing.
pub fn parse_meta_payload(data: &[u8]) -> Option<MetaPayload> {
    let mut dec = CborDecoder::new(data);

    let map_len = dec.read_map_header().ok()?;

    let mut mime_type: Option<String> = None;
    let mut url: Option<String> = None;
    let mut tls_ca: Option<Vec<u8>> = None;
    let mut hash_alg: Option<String> = None;
    let mut expected_hash: Option<Vec<u8>> = None;
    let mut boot_args: Option<String> = None;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut description: Option<String> = None;
    let mut extra_keys: Vec<i32> = Vec::new();

    for _ in 0..map_len {
        // Keys may be negative (FSIM-defined), so read as signed.
        let key = dec.read_int().ok()?;
        match key {
            0 => mime_type = Some(dec.read_text().ok()?),
            1 => url = Some(dec.read_text().ok()?),
            2 => tls_ca = Some(dec.read_bytes().ok()?),
            3 => hash_alg = Some(dec.read_text().ok()?),
            4 => expected_hash = Some(dec.read_bytes().ok()?),
            5 => boot_args = Some(dec.read_text().ok()?),
            6 => name = Some(dec.read_text().ok()?),
            7 => version = Some(dec.read_text().ok()?),
            8 => description = Some(dec.read_text().ok()?),
            other => {
                extra_keys.push(other);
                dec.skip_value().ok()?;
            }
        }
    }

    Some(MetaPayload {
        mime_type: mime_type?,
        url: url?,
        tls_ca,
        hash_alg,
        expected_hash,
        boot_args,
        name,
        version,
        description,
        extra_keys,
    })
}

/// Extract an uncompressed P-256 point (65 bytes: 0x04 || x || y) from a
/// standalone COSE_Key CBOR byte slice.
///
/// The COSE_Key is a CBOR map with labels -2 (x) and -3 (y), each 32 bytes.
/// This is the format used for `image-begin[-10]` (meta_signer).
pub fn parse_cose_key_p256(data: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0usize;
    let b = *data.get(pos)?;
    pos += 1;
    if (b >> 5) != 5 {
        return None; // not a CBOR map
    }
    let map_len = crate::cose::cbor_read_uint_arg(data, &mut pos, b & 0x1f)?;

    let mut x: Option<&[u8]> = None;
    let mut y: Option<&[u8]> = None;
    for _ in 0..map_len {
        let key = crate::cose::cbor_read_int_value(data, &mut pos)?;
        match key {
            -2 => x = crate::cose::cbor_read_bstr(data, &mut pos),
            -3 => y = crate::cose::cbor_read_bstr(data, &mut pos),
            _ => { crate::cose::cbor_skip(data, &mut pos)?; }
        }
    }

    match (x, y) {
        (Some(xb), Some(yb)) if xb.len() == 32 && yb.len() == 32 => {
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(xb);
            point.extend_from_slice(yb);
            Some(point)
        }
        _ => None,
    }
}

/// Authenticate a fetched meta-payload by signature and extract the inner
/// MetaPayload CBOR (chunking-strategy.md "Meta-Payload Signing").
///
/// - `meta_signer` present (begin key 9): the meta-payload MUST be a COSE_Sign1
///   verifying against that COSE_Key (third-party publisher). Any x5chain is
///   ignored. Unsigned ⇒ rejected, never downgraded.
/// - `meta_signer` absent and the meta-payload is signed: it MUST verify
///   against the TO2-proven Owner key, or an x5chain that validates to it and
///   grants PERM.7 (the Owner's own release process).
/// - `meta_signer` absent and unsigned: returned with `signed = false`; it may
///   then only be used as a pointer (see `check_unauthenticated_meta`).
///
/// Returns `(inner_cbor, signed)` or error code 12.
pub fn verify_and_extract_meta(
    data: &[u8],
    meta_signer: Option<&[u8]>,
    owner_point: Option<&[u8]>,
) -> Result<(Vec<u8>, bool), u8> {
    let tagged = is_cbor_tag18(data);
    match meta_signer {
        Some(signer_cose_key) => {
            if !tagged {
                error!("BMO meta: meta_signer named but meta-payload is not signed — rejecting");
                return Err(ERR_META_SIGNATURE_INVALID);
            }
            let point = parse_cose_key_p256(signer_cose_key).ok_or_else(|| {
                error!("BMO meta: failed to parse meta_signer COSE_Key");
                ERR_META_SIGNATURE_INVALID
            })?;
            let s1 = crate::cose::parse_cose_sign1(data).ok_or_else(|| {
                error!("BMO meta: downloaded meta-payload is not a valid COSE_Sign1");
                ERR_META_SIGNATURE_INVALID
            })?;
            let aad = crate::cose::domain_aad(
                crate::cose::AAD_TAG_META_PAYLOAD,
                crate::cose::FDO_VERSION_200,
            );
            if !crate::cose::verify_sign1(&s1, &aad, &point) {
                error!("BMO meta: COSE_Sign1 signature verification FAILED (meta_signer)");
                return Err(ERR_META_SIGNATURE_INVALID);
            }
            info!("BMO meta: meta-payload signature VERIFIED (named publisher)");
            Ok((s1.payload.to_vec(), true))
        }
        None if tagged => {
            let owner = owner_point.ok_or_else(|| {
                error!("BMO meta: signed meta-payload without meta_signer, and no Owner key");
                ERR_META_SIGNATURE_INVALID
            })?;
            let inner = crate::cose::verify_meta_signed(data, owner).ok_or_else(|| {
                error!("BMO meta: meta-payload not signed by the Owner or a PERM.7 delegate — rejecting");
                ERR_META_SIGNATURE_INVALID
            })?;
            info!("BMO meta: meta-payload signature VERIFIED (Owner / PERM.7 delegate)");
            Ok((inner.to_vec(), true))
        }
        None => {
            debug!("BMO meta: unsigned meta-payload (pointer only)");
            Ok((data.to_vec(), false))
        }
    }
}

/// Rules for a meta-payload that is NOT authenticated (unsigned, and — this
/// firmware having no TLS — never fetched over validated TLS):
/// chunking-strategy.md "Authenticating Fetched Content".
///
/// - `image-begin` must pin the image hash (key 8); otherwise nothing
///   authenticates the image (error 19).
/// - It may contribute only pointer fields: any instruction field
///   (`tls_ca`, `boot_args`, FSIM-defined keys) is rejected (error 15).
///   A kernel command line takes over the device without changing the
///   image, so a pinned hash does not make it safe.
pub fn check_unauthenticated_meta(
    meta: &MetaPayload,
    meta_authenticated: bool,
    begin_hash: Option<&[u8]>,
) -> Result<(), HashPolicyError> {
    if meta_authenticated {
        return Ok(());
    }
    if begin_hash.is_none() {
        return Err(HashPolicyError::UnauthenticatedSource);
    }
    let instr = meta.instruction_fields();
    if !instr.is_empty() {
        error!("BMO meta: unauthenticated meta-payload carries instruction fields {:?}", instr);
        return Err(HashPolicyError::InstructionFromUnauthenticatedMeta);
    }
    Ok(())
}


// =========================================================================
// Image hash policy
//
// The device chainloads whatever comes out of BMO, so nothing may be
// executed unless some authenticated statement covers the exact bytes.
// Before 2026-09-29 every one of these checks was "verify if a hash happens
// to be present, otherwise warn and continue", which let the sender opt out
// of integrity entirely simply by omitting a field.
//
// The three rules, by delivery mode:
//
//   0 inline    — bytes arrive inside the TO2 session. Under Artifact
//                 authority the signed image-begin MUST carry key -9, else
//                 the signature covers only metadata. Under Channel
//                 authority an image-end hash is acceptable, because
//                 image-end arrives over the same Owner-bound channel.
//                 No hash at all is never acceptable.
//
//   1 URL       — bytes arrive over plain HTTP, outside the authenticated
//                 channel. Key -9 is mandatory regardless of authority.
//
//   2 meta-URL  — both the meta-payload and the image arrive outside the
//                 channel. Either the meta-payload is signed (key -10, so
//                 its hash is authenticated) or image-begin carries key -9.
//                 With neither, nothing authenticated covers the bytes.
// =========================================================================

/// Why a BMO transfer was refused on integrity grounds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashPolicyError {
    /// image-begin and image-end disagree about the hash.
    BeginEndDisagree,
    /// A signed (Model 3/4) image-begin carried no expected_hash (key -9).
    SignedWithoutHash,
    /// No hash was available from any source.
    NoHash,
    /// Delivery outside the authenticated channel with no authenticated hash.
    UnauthenticatedSource,
    /// An unauthenticated meta-payload carried instruction-class fields.
    InstructionFromUnauthenticatedMeta,
}

impl HashPolicyError {
    pub fn message(self) -> &'static str {
        match self {
            HashPolicyError::BeginEndDisagree => "image-begin/image-end hash disagreement",
            HashPolicyError::SignedWithoutHash => "signed image-begin has no expected_hash (-9)",
            HashPolicyError::NoHash => "no image hash available — refusing to chainload",
            HashPolicyError::UnauthenticatedSource => "no authenticated hash for out-of-band image",
            HashPolicyError::InstructionFromUnauthenticatedMeta =>
                "unauthenticated meta-payload carries instruction fields (boot_args/tls_ca/...)",
        }
    }

    /// Transfer error code (chunking-strategy.md "Transfer Error Codes").
    pub fn code(self) -> u8 {
        match self {
            HashPolicyError::BeginEndDisagree => ERR_HASH_MISMATCH,
            HashPolicyError::SignedWithoutHash => ERR_NOT_AUTHORIZED,
            HashPolicyError::NoHash | HashPolicyError::UnauthenticatedSource => ERR_UNAUTHENTICATED_SOURCE,
            HashPolicyError::InstructionFromUnauthenticatedMeta => ERR_NOT_AUTHORIZED,
        }
    }
}

/// Decide which hash an **inline** (mode 0) transfer must be checked against.
///
/// Returns the hash to compare the reassembled buffer with, or the reason the
/// transfer must be refused.
pub fn inline_hash_decision(
    authority: Authority,
    begin_hash: Option<&[u8]>,
    end_hash: Option<&[u8]>,
) -> Result<Vec<u8>, HashPolicyError> {
    // If both are present they must agree: a disagreement means the sender
    // is trying to substitute content after the authorising message.
    if let (Some(bh), Some(eh)) = (begin_hash, end_hash) {
        if bh != eh {
            return Err(HashPolicyError::BeginEndDisagree);
        }
    }

    // A signature over image-begin only means something if image-begin
    // commits to the bytes.
    if authority == Authority::Artifact && begin_hash.is_none() {
        return Err(HashPolicyError::SignedWithoutHash);
    }

    match begin_hash.or(end_hash) {
        Some(h) => Ok(h.to_vec()),
        None => Err(HashPolicyError::NoHash),
    }
}

/// Decide which hash a **URL** (mode 1) transfer must be checked against.
///
/// The image is fetched over plain HTTP, entirely outside the TO2 session, so
/// only `image-begin`'s key -9 can speak for it.
pub fn url_hash_decision(
    _authority: Authority,
    begin_hash: Option<&[u8]>,
) -> Result<Vec<u8>, HashPolicyError> {
    match begin_hash {
        Some(h) => Ok(h.to_vec()),
        None => Err(HashPolicyError::UnauthenticatedSource),
    }
}

/// Which hashes a **meta-URL** (mode 2) transfer must be checked against.
#[derive(Debug)]
pub struct MetaHashPlan {
    /// Every hash that must match the downloaded image. Never empty.
    pub required: Vec<Vec<u8>>,
}

/// Decide the hash requirements for meta-URL delivery, after the meta-payload
/// has been fetched and authenticated (or not), and BEFORE downloading the
/// image.
///
/// - Every hash present is enforced — image-begin's (key 8) and the
///   meta-payload's (key 4) — even one from an unauthenticated meta-payload:
///   an extra hash can only make acceptance stricter.
/// - At least one must be *evidence*: image-begin's hash (it came over the
///   TO2 session), or the meta-payload's hash when the meta-payload itself is
///   authenticated. This firmware has no validated TLS, so with neither the
///   image is refused (error 19).
pub fn meta_hash_decision(
    _authority: Authority,
    begin_hash: Option<&[u8]>,
    meta_authenticated: bool,
    meta_hash: Option<&[u8]>,
) -> Result<MetaHashPlan, HashPolicyError> {
    let evidence = begin_hash.is_some() || (meta_authenticated && meta_hash.is_some());
    if !evidence {
        return Err(HashPolicyError::UnauthenticatedSource);
    }
    let mut required: Vec<Vec<u8>> = Vec::new();
    if let Some(bh) = begin_hash {
        required.push(bh.to_vec());
    }
    if let Some(mh) = meta_hash {
        required.push(mh.to_vec());
    }
    Ok(MetaHashPlan { required })
}

