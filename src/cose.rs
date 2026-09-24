// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// Shared COSE_Sign1 (RFC 9052) parsing and ES256 signature verification.
//
// This is the single place where a COSE_Sign1 signature is checked. It is used
// for TO1.RVRedirect (to1d), TO2.ProveOVHdr, Ownership Voucher entries, and
// (later) BMO provisioning envelopes.
//
// Domain separation: FDO 2.0 feeds a per-context tag into the COSE
// `external_aad` field (see FDO spec "COSE Domain Separation", and
// go-fdo/cose/aad.go). FDO 1.01 uses an empty external_aad. The tag is NOT
// transmitted — both sides construct it independently from context, so getting
// it wrong shows up as a signature failure and nothing else.

use alloc::vec::Vec;
use log::{debug, error, info, warn};

/// COSE Algorithm identifiers (RFC 9053)
pub const COSE_ALG_ES256: i32 = -7;
pub const COSE_ALG_ES384: i32 = -35;

/// COSE header label for a full public key in the unprotected header.
/// go-fdo places the delegate PublicKey here in to1d and ProveOVHdr.
pub const COSE_LABEL_DELEGATE_KEY: i64 = 258;
/// COSE header label 33 (RFC 9360) — x5chain, DER certs, leaf first.
pub const COSE_LABEL_X5CHAIN: i64 = 33;

// Domain separation tags. Must match go-fdo/cose/aad.go exactly.
pub const AAD_TAG_OWNER_SIGN: &str = "FDO-TO0-OwnerSign-v1";
pub const AAD_TAG_PROVE_TO_RV: &str = "FDO-TO1-ProveToRV-v1";
pub const AAD_TAG_PROVE_DEVICE: &str = "FDO-TO2-ProveDevice-v1";
pub const AAD_TAG_PROVE_OV_HDR: &str = "FDO-TO2-ProveOVHdr-v1";
pub const AAD_TAG_OV_ENTRY: &str = "FDO-OVEntry-v1";

// BMO provisioning domain separation. Must match go-fdo/fsim/bmo_provision.go.
pub const AAD_TAG_BMO_PROVISION: &str = "FDO-FSIM-BmoProvision-v1";

// BMO COSE protected header content_type values (label 3).
pub const BMO_CONTENT_TYPE_IMAGE_BEGIN: &str = "application/cbor+fdo.bmo.image-begin";
pub const BMO_CONTENT_TYPE_SET: &str = "application/cbor+fdo.bmo.set";

/// FDO protocol version values (protver).
pub const FDO_VERSION_101: u16 = 101;
pub const FDO_VERSION_200: u16 = 200;

/// Build the CBOR encoding of `FDOExternalAAD = [tag]`.
///
/// This is the value placed in the Sig_structure `external_aad` slot. Returns
/// an empty vector for pre-2.0 protocol versions, which use no external_aad.
pub fn domain_aad(tag: &str, version: u16) -> Vec<u8> {
    if version < FDO_VERSION_200 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(tag.len() + 3);
    out.push(0x81); // array(1)
    encode_tstr(&mut out, tag);
    out
}

/// Parsed COSE_Sign1 with slices referencing the original buffer.
///
/// `protected_header` and `payload` are the exact bstr contents as they appear
/// on the wire; they must be fed into the Sig_structure verbatim, since
/// re-encoding could produce different bytes and break the signature.
pub struct CoseSign1<'a> {
    pub algorithm: i32,
    pub protected_header: &'a [u8],
    pub unprotected_header: &'a [u8],
    pub payload: &'a [u8],
    pub signature: &'a [u8],
}

/// Parse a COSE_Sign1 envelope, with or without CBOR tag 18.
pub fn parse_cose_sign1(data: &[u8]) -> Option<CoseSign1<'_>> {
    let mut pos = 0usize;

    // Optional CBOR tag 18
    let b = *data.get(pos)?;
    if (b >> 5) == 6 {
        pos += 1;
        let tag = cbor_read_uint_arg(data, &mut pos, b & 0x1f)?;
        if tag != 18 {
            warn!("COSE: expected tag 18 (COSE_Sign1), got {}", tag);
            return None;
        }
    }

    // 4-element array
    let b = *data.get(pos)?;
    pos += 1;
    if (b >> 5) != 4 {
        error!("COSE: expected array, got major type {}", b >> 5);
        return None;
    }
    let arr_len = cbor_read_uint_arg(data, &mut pos, b & 0x1f)?;
    if arr_len != 4 {
        error!("COSE: expected 4-element array, got {}", arr_len);
        return None;
    }

    // [0] protected header (bstr)
    let protected_header = cbor_read_bstr(data, &mut pos)?;
    let algorithm = parse_protected_alg(protected_header);

    // [1] unprotected header (map) — capture its span so callers can look for
    // a delegate key / x5chain without re-walking the envelope.
    let unprot_start = pos;
    cbor_skip(data, &mut pos)?;
    let unprotected_header = data.get(unprot_start..pos)?;

    // [2] payload (bstr or nil)
    let payload = if *data.get(pos)? == 0xf6 {
        pos += 1;
        &data[0..0]
    } else {
        cbor_read_bstr(data, &mut pos)?
    };

    // [3] signature (bstr)
    let signature = cbor_read_bstr(data, &mut pos)?;

    Some(CoseSign1 {
        algorithm,
        protected_header,
        unprotected_header,
        payload,
        signature,
    })
}

/// Build `Sig_structure = ["Signature1", protected, external_aad, payload]`.
///
/// `external_aad` is the raw CBOR of the domain AAD array (or empty); it is
/// wrapped as a bstr here.
pub fn build_sig_structure(protected: &[u8], external_aad: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(protected.len() + external_aad.len() + payload.len() + 24);
    out.push(0x84); // array(4)
    out.push(0x6a); // tstr(10)
    out.extend_from_slice(b"Signature1");
    encode_bstr(&mut out, protected);
    encode_bstr(&mut out, external_aad);
    encode_bstr(&mut out, payload);
    out
}

/// Verify an ES256 signature over `msg` using an uncompressed P-256 point
/// (`0x04 || X || Y`, 65 bytes).
///
/// `signature` is the COSE fixed-width form: r || s, 32 bytes each.
pub fn verify_es256(msg: &[u8], signature: &[u8], point: &[u8]) -> bool {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use p256::EncodedPoint;

    if signature.len() != 64 {
        error!("COSE: ES256 signature length {} != 64", signature.len());
        return false;
    }
    let encoded = match EncodedPoint::from_bytes(point) {
        Ok(p) => p,
        Err(_) => {
            error!("COSE: public key is not a valid P-256 point ({} bytes)", point.len());
            return false;
        }
    };
    let vk = match VerifyingKey::from_encoded_point(&encoded) {
        Ok(k) => k,
        Err(_) => {
            error!("COSE: could not build P-256 verifying key");
            return false;
        }
    };
    let sig = match Signature::from_slice(signature) {
        Ok(s) => s,
        Err(_) => {
            error!("COSE: malformed ECDSA r||s signature");
            return false;
        }
    };
    // verify() hashes with SHA-256 internally, per ES256.
    vk.verify(msg, &sig).is_ok()
}

/// Verify a parsed COSE_Sign1 against a P-256 public key point and a domain AAD.
pub fn verify_sign1(s1: &CoseSign1, external_aad: &[u8], point: &[u8]) -> bool {
    if s1.algorithm != COSE_ALG_ES256 {
        error!(
            "COSE: unsupported algorithm {} (only ES256 {} is implemented)",
            s1.algorithm, COSE_ALG_ES256
        );
        return false;
    }
    let sig_structure = build_sig_structure(s1.protected_header, external_aad, s1.payload);
    debug!(
        "COSE: verifying ES256 over Sig_structure ({} bytes, aad {} bytes)",
        sig_structure.len(),
        external_aad.len()
    );
    verify_es256(&sig_structure, s1.signature, point)
}

/// Verify a BMO provisioning COSE_Sign1 envelope (tag 18).
///
/// Checks:
/// 1. Parses the COSE_Sign1 (expects tag 18 to already be present)
/// 2. Verifies content_type in protected header matches `expected_ct`
/// 3. Evaluates fdo.bmo.scope if present (guid, not_before, not_after, generation)
/// 4. Builds external_aad = CBOR(["FDO-FSIM-BmoProvision-v1"])
/// 5. If x5chain (label 33) is present in unprotected header:
///    - Validates certificate chain to `owner_point`
///    - Checks PERM.7 (OIDPermitProvision) on leaf certificate
///    - Verifies signature against delegate leaf key (Model 4)
/// 6. Otherwise verifies signature against `owner_point` directly (Model 3)
///
/// `device_guid` is the 16-byte voucher GUID proven in TO2 (for scope.guid check).
///
/// Returns the inner payload bytes on success, or None on failure.
pub fn verify_bmo_signed<'a>(data: &'a [u8], owner_point: &[u8], expected_ct: &str, device_guid: Option<&[u8]>) -> Option<&'a [u8]> {
    let s1 = parse_cose_sign1(data)?;

    // Check content_type (label 3) in protected header
    let ct = parse_protected_tstr(&s1.protected_header, 3);
    match ct {
        Some(ct_val) if ct_val == expected_ct => {
            debug!("BMO COSE: content_type OK: {}", ct_val);
        }
        Some(ct_val) => {
            error!("BMO COSE: content_type mismatch: got '{}', expected '{}'", ct_val, expected_ct);
            return None;
        }
        None => {
            error!("BMO COSE: no content_type (label 3) in protected header");
            return None;
        }
    }

    // Evaluate fdo.bmo.scope if present in the protected header.
    if !evaluate_bmo_scope(s1.protected_header, device_guid) {
        error!("BMO COSE: scope evaluation FAILED — rejecting artifact");
        return None;
    }

    // Build external_aad = CBOR(["FDO-FSIM-BmoProvision-v1"])
    let mut aad = Vec::with_capacity(AAD_TAG_BMO_PROVISION.len() + 3);
    aad.push(0x81); // array(1)
    encode_tstr(&mut aad, AAD_TAG_BMO_PROVISION);

    // Determine the verification key: Owner-direct (Model 3) or delegate x5chain (Model 4).
    if has_delegate_header(s1.unprotected_header) {
        // Model 4: Delegate-signed provisioning artifact.
        // Extract the x5chain, validate the certificate chain against the Owner key,
        // check that the leaf has PERM.7, and verify the signature with the leaf key.
        info!("BMO COSE: x5chain present — delegate-signed artifact (Model 4)");

        let cert_ders = match crate::delegate::extract_x5chain_from_unprotected(s1.unprotected_header) {
            Some(c) => c,
            None => {
                error!("BMO COSE: failed to extract x5chain from unprotected header");
                return None;
            }
        };

        let cert_refs: Vec<&[u8]> = cert_ders.iter().map(|c| c.as_slice()).collect();
        let chain_result = match crate::delegate::verify_delegate_chain(&cert_refs, owner_point) {
            Some(r) => r,
            None => {
                error!("BMO COSE: delegate x5chain verification FAILED");
                return None;
            }
        };

        if !chain_result.has_provision {
            error!("BMO COSE: delegate leaf certificate lacks OIDPermitProvision (PERM.7)");
            error!("BMO COSE: a delegate signing provisioning artifacts MUST have PERM.7");
            return None;
        }

        info!("BMO COSE: delegate chain verified, leaf has PERM.7");

        // Verify signature against the delegate leaf key
        let sig_structure = build_sig_structure(s1.protected_header, &aad, s1.payload);
        if !verify_es256(&sig_structure, s1.signature, &chain_result.leaf_key_point) {
            error!("BMO COSE: SIGNATURE VERIFICATION FAILED against delegate leaf key");
            return None;
        }

        info!("BMO COSE: delegate-signed artifact verified OK (content_type={})", expected_ct);
    } else {
        // Model 3: Owner-direct signed provisioning artifact.
        let sig_structure = build_sig_structure(s1.protected_header, &aad, s1.payload);
        if !verify_es256(&sig_structure, s1.signature, owner_point) {
            error!("BMO COSE: SIGNATURE VERIFICATION FAILED against Owner key");
            return None;
        }

        info!("BMO COSE: Owner-signed artifact verified OK (content_type={})", expected_ct);
    }

    Some(s1.payload)
}

/// Label for the scope field in the protected header.
const BMO_SCOPE_LABEL: &str = "fdo.bmo.scope";

/// Evaluate fdo.bmo.scope from the protected header.
///
/// Returns `true` if scope is absent (no constraint) or all constraints pass.
/// Returns `false` if any constraint fails (caller should reject the artifact).
fn evaluate_bmo_scope(protected_header: &[u8], device_guid: Option<&[u8]>) -> bool {
    // Find the scope bytes in the protected header (text-keyed map entry)
    let scope_bytes = match extract_tstr_keyed_value(protected_header, BMO_SCOPE_LABEL) {
        Some(b) => b,
        None => return true, // No scope → no constraints
    };

    info!("BMO COSE: evaluating fdo.bmo.scope ({} bytes)", scope_bytes.len());

    // Parse scope as a CBOR map with text keys
    let mut pos = 0usize;
    let b = match scope_bytes.get(pos) {
        Some(&b) => b,
        None => return true,
    };
    pos += 1;
    if (b >> 5) != 5 {
        error!("BMO COSE: scope is not a CBOR map");
        return false; // Unevaluable → fail closed
    }
    let map_len = match cbor_read_uint_arg(scope_bytes, &mut pos, b & 0x1f) {
        Some(n) => n,
        None => { error!("BMO COSE: scope map length parse error"); return false; }
    };

    for _ in 0..map_len {
        // Read text key
        let key_start = pos;
        let kb = match scope_bytes.get(pos) {
            Some(&b) => b,
            None => { error!("BMO COSE: scope key truncated"); return false; }
        };
        pos += 1;
        if (kb >> 5) != 3 {
            // Not a text key — skip key+value
            pos = key_start;
            if cbor_skip(scope_bytes, &mut pos).is_none() { return false; }
            if cbor_skip(scope_bytes, &mut pos).is_none() { return false; }
            continue;
        }
        let key_len = match cbor_read_uint_arg(scope_bytes, &mut pos, kb & 0x1f) {
            Some(n) => n,
            None => { error!("BMO COSE: scope key length parse error"); return false; }
        };
        let key_str = match scope_bytes.get(pos..pos + key_len).and_then(|s| core::str::from_utf8(s).ok()) {
            Some(s) => s,
            None => { error!("BMO COSE: scope key not valid UTF-8"); return false; }
        };
        pos += key_len;

        match key_str {
            "guid" => {
                // guid may be a single bstr (16 bytes) or an array of bstr
                let guid_ok = evaluate_scope_guid(scope_bytes, &mut pos, device_guid);
                if !guid_ok {
                    return false;
                }
            }
            "not_before" => {
                let ts = match read_scope_uint(scope_bytes, &mut pos) {
                    Some(v) => v,
                    None => { error!("BMO COSE: scope not_before parse error"); return false; }
                };
                info!("BMO COSE: scope not_before={}", ts);
                // Clock evaluation: log but do not enforce (no trusted clock in UEFI)
                warn!("BMO COSE: not_before enforcement skipped (no trusted clock)");
            }
            "not_after" => {
                let ts = match read_scope_uint(scope_bytes, &mut pos) {
                    Some(v) => v,
                    None => { error!("BMO COSE: scope not_after parse error"); return false; }
                };
                info!("BMO COSE: scope not_after={}", ts);
                warn!("BMO COSE: not_after enforcement skipped (no trusted clock)");
            }
            "generation" => {
                let gen = match read_scope_uint(scope_bytes, &mut pos) {
                    Some(v) => v,
                    None => { error!("BMO COSE: scope generation parse error"); return false; }
                };
                info!("BMO COSE: scope generation={}", gen);
                // Generation enforcement: log but do not enforce (no rollback storage yet)
                warn!("BMO COSE: generation enforcement skipped (no rollback storage)");
            }
            _ => {
                // Unknown scope field — fail closed per spec
                error!("BMO COSE: unknown scope field '{}' — fail closed", key_str);
                return false;
            }
        }
    }

    info!("BMO COSE: scope evaluation PASSED");
    true
}

/// Evaluate scope.guid constraint.
/// Returns true if the GUID matches the device GUID (or if no device GUID provided).
fn evaluate_scope_guid(data: &[u8], pos: &mut usize, device_guid: Option<&[u8]>) -> bool {
    let b = match data.get(*pos) {
        Some(&b) => b,
        None => { error!("BMO COSE: scope guid truncated"); return false; }
    };

    let major = b >> 5;

    if major == 2 {
        // Single bstr (16-byte GUID)
        *pos += 1;
        let len = match cbor_read_uint_arg(data, pos, b & 0x1f) {
            Some(n) => n,
            None => { error!("BMO COSE: scope guid bstr length error"); return false; }
        };
        let guid = match data.get(*pos..*pos + len) {
            Some(g) => g,
            None => { error!("BMO COSE: scope guid bstr truncated"); return false; }
        };
        *pos += len;

        if let Some(dev_guid) = device_guid {
            if guid == dev_guid {
                info!("BMO COSE: scope guid matches device GUID");
                return true;
            } else {
                error!("BMO COSE: scope guid MISMATCH — artifact not for this device");
                return false;
            }
        }
        info!("BMO COSE: scope guid present but no device GUID to check against");
        return true;
    }

    if major == 4 {
        // Array of bstr (multiple GUIDs — any must match)
        *pos += 1;
        let arr_len = match cbor_read_uint_arg(data, pos, b & 0x1f) {
            Some(n) => n,
            None => { error!("BMO COSE: scope guid array length error"); return false; }
        };
        for _ in 0..arr_len {
            let gb = match data.get(*pos) {
                Some(&b) => b,
                None => { error!("BMO COSE: scope guid array entry truncated"); return false; }
            };
            *pos += 1;
            if (gb >> 5) != 2 {
                error!("BMO COSE: scope guid array entry not a bstr");
                return false;
            }
            let glen = match cbor_read_uint_arg(data, pos, gb & 0x1f) {
                Some(n) => n,
                None => return false,
            };
            let guid = match data.get(*pos..*pos + glen) {
                Some(g) => g,
                None => return false,
            };
            *pos += glen;

            if let Some(dev_guid) = device_guid {
                if guid == dev_guid {
                    info!("BMO COSE: scope guid matches device GUID (from array)");
                    return true;
                }
            }
        }
        if device_guid.is_some() {
            error!("BMO COSE: scope guid array — no entry matches device GUID");
            return false;
        }
        return true;
    }

    error!("BMO COSE: scope guid is not a bstr or array");
    false
}

/// Read a uint value from CBOR at position.
fn read_scope_uint(data: &[u8], pos: &mut usize) -> Option<u64> {
    let b = *data.get(*pos)?;
    *pos += 1;
    if (b >> 5) != 0 {
        return None; // not a uint
    }
    let val = cbor_read_uint_arg(data, pos, b & 0x1f)? as u64;
    Some(val)
}

/// Extract a raw CBOR value from a protected header map for a given text key.
/// Returns the bytes of the value (not decoded), positioned right after the value.
fn extract_tstr_keyed_value<'a>(header: &'a [u8], target_key: &str) -> Option<&'a [u8]> {
    if header.is_empty() {
        return None;
    }
    let mut pos = 0usize;
    let b = *header.get(pos)?;
    pos += 1;
    if (b >> 5) != 5 {
        return None; // not a map
    }
    let map_len = cbor_read_uint_arg(header, &mut pos, b & 0x1f)?;
    for _ in 0..map_len {
        // Read key — may be int or tstr
        let key_byte = *header.get(pos)?;
        let key_major = key_byte >> 5;
        if key_major == 3 {
            // Text string key
            pos += 1;
            let key_len = cbor_read_uint_arg(header, &mut pos, key_byte & 0x1f)?;
            let key_str = core::str::from_utf8(header.get(pos..pos + key_len)?).ok()?;
            pos += key_len;
            if key_str == target_key {
                // Return from here to end of this value
                let value_start = pos;
                cbor_skip(header, &mut pos)?;
                return Some(&header[value_start..pos]);
            }
            // Skip value
            cbor_skip(header, &mut pos)?;
        } else {
            // Integer or other key type — skip key + value
            cbor_skip(header, &mut pos)?;
            cbor_skip(header, &mut pos)?;
        }
    }
    None
}

/// Extract a text string value for a given integer label from a protected header map.
fn parse_protected_tstr<'a>(header: &'a [u8], target_label: i64) -> Option<&'a str> {
    if header.is_empty() {
        return None;
    }
    let mut pos = 0usize;
    let b = *header.get(pos)?;
    pos += 1;
    if (b >> 5) != 5 {
        return None; // not a map
    }
    let map_len = cbor_read_uint_arg(header, &mut pos, b & 0x1f)?;
    for _ in 0..map_len {
        let key = cbor_read_int_value(header, &mut pos)?;
        if key == target_label {
            // Read tstr value
            let b2 = *header.get(pos)?;
            pos += 1;
            if (b2 >> 5) != 3 {
                return None; // not a tstr
            }
            let len = cbor_read_uint_arg(header, &mut pos, b2 & 0x1f)?;
            let s = header.get(pos..pos + len)?;
            return core::str::from_utf8(s).ok();
        }
        // Skip this value
        cbor_skip(header, &mut pos)?;
    }
    None
}

/// True if the unprotected header carries a delegate key (label 258) or an
/// x5chain (label 33). Used to detect delegation we do not yet support, so it
/// can be refused loudly rather than ignored.
pub fn has_delegate_header(unprotected: &[u8]) -> bool {
    let mut pos = 0usize;
    let b = match unprotected.first() {
        Some(&b) => b,
        None => return false,
    };
    if (b >> 5) != 5 {
        return false; // not a map
    }
    pos += 1;
    let map_len = match cbor_read_uint_arg(unprotected, &mut pos, b & 0x1f) {
        Some(n) => n,
        None => return false,
    };
    for _ in 0..map_len {
        let key = cbor_read_int_value(unprotected, &mut pos);
        if cbor_skip(unprotected, &mut pos).is_none() {
            return false;
        }
        match key {
            Some(k) if k == COSE_LABEL_DELEGATE_KEY || k == COSE_LABEL_X5CHAIN => return true,
            Some(_) => {}
            None => return false,
        }
    }
    false
}

/// Extract the `alg` (label 1) value from a serialised protected header.
fn parse_protected_alg(header: &[u8]) -> i32 {
    if header.is_empty() {
        return 0;
    }
    let mut pos = 0usize;
    let b = match header.first() {
        Some(&b) => b,
        None => return 0,
    };
    pos += 1;
    if (b >> 5) != 5 {
        return 0; // not a map
    }
    let map_len = match cbor_read_uint_arg(header, &mut pos, b & 0x1f) {
        Some(n) => n,
        None => return 0,
    };
    for _ in 0..map_len {
        let key = cbor_read_int_value(header, &mut pos);
        if key == Some(1) {
            return cbor_read_int_value(header, &mut pos).unwrap_or(0) as i32;
        }
        if cbor_skip(header, &mut pos).is_none() {
            return 0;
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Minimal slice-based CBOR helpers.
//
// These operate on raw slices (rather than the CborDecoder in fdo.rs) because
// signature verification needs exact byte spans of the protected header and
// payload, which a value-oriented decoder does not preserve.
// ---------------------------------------------------------------------------

/// Read the argument of a CBOR head byte whose additional-info bits are `additional`.
pub fn cbor_read_uint_arg(data: &[u8], pos: &mut usize, additional: u8) -> Option<usize> {
    match additional {
        0..=23 => Some(additional as usize),
        24 => {
            let v = *data.get(*pos)? as usize;
            *pos += 1;
            Some(v)
        }
        25 => {
            let b = data.get(*pos..*pos + 2)?;
            *pos += 2;
            Some(((b[0] as usize) << 8) | b[1] as usize)
        }
        26 => {
            let b = data.get(*pos..*pos + 4)?;
            *pos += 4;
            Some(((b[0] as usize) << 24) | ((b[1] as usize) << 16) | ((b[2] as usize) << 8) | b[3] as usize)
        }
        _ => None,
    }
}

/// Read an unsigned integer value (major type 0).
pub fn cbor_read_uint_value(data: &[u8], pos: &mut usize) -> Option<usize> {
    let b = *data.get(*pos)?;
    *pos += 1;
    if (b >> 5) != 0 {
        return None;
    }
    cbor_read_uint_arg(data, pos, b & 0x1f)
}

/// Read a signed integer value (major type 0 or 1).
pub fn cbor_read_int_value(data: &[u8], pos: &mut usize) -> Option<i64> {
    let b = *data.get(*pos)?;
    *pos += 1;
    let major = b >> 5;
    let arg = cbor_read_uint_arg(data, pos, b & 0x1f)?;
    match major {
        0 => Some(arg as i64),
        1 => Some(-1 - (arg as i64)),
        _ => None,
    }
}

/// Read a byte string (major type 2), returning a slice into `data`.
pub fn cbor_read_bstr<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let b = *data.get(*pos)?;
    *pos += 1;
    if (b >> 5) != 2 {
        return None;
    }
    let len = cbor_read_uint_arg(data, pos, b & 0x1f)?;
    let out = data.get(*pos..*pos + len)?;
    *pos += len;
    Some(out)
}

/// Skip one complete CBOR item, including nested containers.
pub fn cbor_skip(data: &[u8], pos: &mut usize) -> Option<()> {
    let b = *data.get(*pos)?;
    *pos += 1;
    let major = b >> 5;
    let additional = b & 0x1f;

    match major {
        0 | 1 => {
            cbor_read_uint_arg(data, pos, additional)?;
            Some(())
        }
        2 | 3 => {
            let len = cbor_read_uint_arg(data, pos, additional)?;
            if *pos + len > data.len() {
                return None;
            }
            *pos += len;
            Some(())
        }
        4 => {
            let len = cbor_read_uint_arg(data, pos, additional)?;
            for _ in 0..len {
                cbor_skip(data, pos)?;
            }
            Some(())
        }
        5 => {
            let len = cbor_read_uint_arg(data, pos, additional)?;
            for _ in 0..len {
                cbor_skip(data, pos)?; // key
                cbor_skip(data, pos)?; // value
            }
            Some(())
        }
        6 => {
            cbor_read_uint_arg(data, pos, additional)?;
            cbor_skip(data, pos)
        }
        7 => {
            match additional {
                24 => *pos += 1,
                25 => *pos += 2,
                26 => *pos += 4,
                27 => *pos += 8,
                _ => {}
            }
            Some(())
        }
        _ => None,
    }
}

pub fn encode_bstr(out: &mut Vec<u8>, data: &[u8]) {
    encode_head(out, 2, data.len());
    out.extend_from_slice(data);
}

pub fn encode_tstr(out: &mut Vec<u8>, s: &str) {
    encode_head(out, 3, s.len());
    out.extend_from_slice(s.as_bytes());
}

pub fn encode_head(out: &mut Vec<u8>, major: u8, len: usize) {
    let m = major << 5;
    if len < 24 {
        out.push(m | len as u8);
    } else if len < 256 {
        out.push(m | 24);
        out.push(len as u8);
    } else if len < 65536 {
        out.push(m | 25);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(m | 26);
        out.push((len >> 24) as u8);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

// -------------------------------------------------------------------------
// Test helpers (available to other test modules via `pub(crate)`)
// -------------------------------------------------------------------------

/// Build a minimal COSE_Sign1 envelope, signed with the given P-256 key.
///
/// `protected_cbor` is the serialised protected header map.
/// `payload` is the inner payload bytes.
/// `external_aad` is the domain AAD bytes.
/// `unprotected_cbor` is the serialised unprotected header map (may be empty map `a0`).
///
/// Returns the full COSE_Sign1 bytes (with CBOR tag 18).
#[cfg(test)]
pub(crate) fn build_test_cose_sign1(
    protected_cbor: &[u8],
    payload: &[u8],
    external_aad: &[u8],
    unprotected_cbor: &[u8],
    signing_key: &p256::ecdsa::SigningKey,
) -> Vec<u8> {
    use p256::ecdsa::{signature::Signer, Signature};

    let sig_structure = build_sig_structure(protected_cbor, external_aad, payload);
    let sig: Signature = signing_key.sign(&sig_structure);
    let sig_bytes = sig.to_bytes();

    let mut out = Vec::new();
    // CBOR tag 18 (COSE_Sign1) — shortest encoding: major 6 (0xC0) | 18 = 0xD2
    out.push(0xd2);
    out.push(0x84); // array(4)
    encode_bstr(&mut out, protected_cbor);      // [0] protected
    out.extend_from_slice(unprotected_cbor);     // [1] unprotected (pre-encoded map)
    encode_bstr(&mut out, payload);              // [2] payload
    encode_bstr(&mut out, sig_bytes.as_slice()); // [3] signature
    out
}

/// Build the "standard" protected header for ES256 + optional content_type.
#[cfg(test)]
pub(crate) fn build_test_protected_header(content_type: Option<&str>) -> Vec<u8> {
    let mut hdr = Vec::new();
    let count = 1 + if content_type.is_some() { 1 } else { 0 };
    encode_head(&mut hdr, 5, count); // map(count)
    // alg = 1, ES256 = -7
    hdr.push(0x01); // key 1
    hdr.push(0x26); // value -7 (= 0x20 | 6)
    if let Some(ct) = content_type {
        hdr.push(0x03); // key 3 (content_type)
        encode_tstr(&mut hdr, ct);
    }
    hdr
}

/// Generate a fresh P-256 key pair for testing. Returns (signing_key, uncompressed_point).
#[cfg(test)]
pub(crate) fn gen_test_keypair() -> (p256::ecdsa::SigningKey, Vec<u8>) {
    use p256::ecdsa::SigningKey;
    use p256::EncodedPoint;

    // Deterministic key from a fixed seed (for reproducible tests)
    let secret = p256::SecretKey::from_bytes(
        &[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ].into(),
    ).unwrap();
    let sk = SigningKey::from(secret.clone());
    let pk = secret.public_key();
    let point = EncodedPoint::from(pk);
    (sk, point.as_bytes().to_vec())
}

/// Generate a SECOND distinct P-256 key pair (for "wrong key" tests).
#[cfg(test)]
pub(crate) fn gen_test_keypair_b() -> (p256::ecdsa::SigningKey, Vec<u8>) {
    use p256::ecdsa::SigningKey;
    use p256::EncodedPoint;

    let secret = p256::SecretKey::from_bytes(
        &[
            0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
            0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
            0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8,
            0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0,
        ].into(),
    ).unwrap();
    let sk = SigningKey::from(secret.clone());
    let pk = secret.public_key();
    let point = EncodedPoint::from(pk);
    (sk, point.as_bytes().to_vec())
}

// =========================================================================
// Unit tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- domain_aad ---

    #[test]
    fn test_domain_aad_v200() {
        let aad = domain_aad(AAD_TAG_PROVE_OV_HDR, FDO_VERSION_200);
        assert!(!aad.is_empty(), "FDO 2.0 must produce non-empty AAD");
        // First byte = 0x81 (array of 1)
        assert_eq!(aad[0], 0x81);
        // Followed by the text string
        let tag_bytes = AAD_TAG_PROVE_OV_HDR.as_bytes();
        assert!(aad[2..].starts_with(tag_bytes));
    }

    #[test]
    fn test_domain_aad_v101_empty() {
        let aad = domain_aad(AAD_TAG_PROVE_OV_HDR, FDO_VERSION_101);
        assert!(aad.is_empty(), "FDO 1.01 must produce empty AAD");
    }

    #[test]
    fn test_domain_aad_all_tags() {
        // Every tag must produce distinct AADs
        let tags = [
            AAD_TAG_OWNER_SIGN, AAD_TAG_PROVE_TO_RV, AAD_TAG_PROVE_DEVICE,
            AAD_TAG_PROVE_OV_HDR, AAD_TAG_OV_ENTRY, AAD_TAG_BMO_PROVISION,
        ];
        let aads: Vec<Vec<u8>> = tags.iter().map(|t| domain_aad(t, 200)).collect();
        for i in 0..aads.len() {
            for j in (i+1)..aads.len() {
                assert_ne!(aads[i], aads[j], "AAD tags must be distinct: {} vs {}", tags[i], tags[j]);
            }
        }
    }

    // --- parse_cose_sign1 ---

    #[test]
    fn test_parse_cose_sign1_roundtrip() {
        let (sk, point) = gen_test_keypair();
        let protected = build_test_protected_header(None);
        let payload = b"test payload";
        let aad = domain_aad(AAD_TAG_PROVE_OV_HDR, 200);
        let unprotected = vec![0xa0]; // empty map

        let envelope = build_test_cose_sign1(&protected, payload, &aad, &unprotected, &sk);

        let s1 = parse_cose_sign1(&envelope).expect("parse should succeed");
        assert_eq!(s1.algorithm, COSE_ALG_ES256);
        assert_eq!(s1.payload, payload);
        assert_eq!(s1.signature.len(), 64);
        assert_eq!(s1.protected_header, &protected[..]);
    }

    #[test]
    fn test_parse_cose_sign1_no_tag() {
        // COSE_Sign1 without CBOR tag 18 should still parse
        let (sk, _) = gen_test_keypair();
        let protected = build_test_protected_header(None);
        let payload = b"no tag";
        let aad = vec![];
        let unprotected = vec![0xa0];

        let full = build_test_cose_sign1(&protected, payload, &aad, &unprotected, &sk);
        // Strip the first byte (0xd2 = tag 18, shortest encoding)
        let no_tag = &full[1..];
        let s1 = parse_cose_sign1(no_tag).expect("should parse without tag");
        assert_eq!(s1.payload, payload);
    }

    #[test]
    fn test_parse_cose_sign1_truncated() {
        let (sk, _) = gen_test_keypair();
        let protected = build_test_protected_header(None);
        let envelope = build_test_cose_sign1(&protected, b"x", &[], &[0xa0], &sk);
        // Truncate at various points
        for len in [0, 1, 2, 5, 10] {
            if len < envelope.len() {
                assert!(parse_cose_sign1(&envelope[..len]).is_none(),
                    "truncated at {} should fail", len);
            }
        }
    }

    // --- verify_es256 / verify_sign1 ---

    #[test]
    fn test_verify_es256_valid() {
        let (sk, point) = gen_test_keypair();
        let msg = b"hello FDO";
        let sig: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(&sk, msg);
        assert!(verify_es256(msg, sig.to_bytes().as_slice(), &point));
    }

    #[test]
    fn test_verify_es256_wrong_key() {
        let (sk, _point_a) = gen_test_keypair();
        let (_sk_b, point_b) = gen_test_keypair_b();
        let msg = b"signed by A";
        let sig: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(&sk, msg);
        // Verify with key B — must fail
        assert!(!verify_es256(msg, sig.to_bytes().as_slice(), &point_b),
            "signature must not verify with wrong key");
    }

    #[test]
    fn test_verify_es256_tampered_payload() {
        let (sk, point) = gen_test_keypair();
        let msg = b"original";
        let sig: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(&sk, msg);
        assert!(!verify_es256(b"tampered", sig.to_bytes().as_slice(), &point),
            "signature must not verify with tampered payload");
    }

    #[test]
    fn test_verify_es256_tampered_signature() {
        let (sk, point) = gen_test_keypair();
        let msg = b"original";
        let sig: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(&sk, msg);
        let mut bad_sig = sig.to_bytes().to_vec();
        bad_sig[63] ^= 0x01; // flip last bit
        assert!(!verify_es256(msg, &bad_sig, &point),
            "tampered signature must not verify");
    }

    #[test]
    fn test_verify_es256_short_signature() {
        let (_, point) = gen_test_keypair();
        assert!(!verify_es256(b"x", &[0u8; 32], &point), "short signature must fail");
    }

    #[test]
    fn test_verify_es256_bad_point() {
        let (sk, _) = gen_test_keypair();
        let msg = b"x";
        let sig: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(&sk, msg);
        assert!(!verify_es256(msg, sig.to_bytes().as_slice(), &[0u8; 65]),
            "invalid point must fail");
    }

    #[test]
    fn test_verify_sign1_roundtrip() {
        let (sk, point) = gen_test_keypair();
        let protected = build_test_protected_header(None);
        let payload = b"signed payload";
        let aad = domain_aad(AAD_TAG_PROVE_OV_HDR, 200);
        let envelope = build_test_cose_sign1(&protected, payload, &aad, &[0xa0], &sk);

        let s1 = parse_cose_sign1(&envelope).unwrap();
        assert!(verify_sign1(&s1, &aad, &point), "valid COSE_Sign1 must verify");
    }

    #[test]
    fn test_verify_sign1_wrong_aad() {
        let (sk, point) = gen_test_keypair();
        let protected = build_test_protected_header(None);
        let payload = b"aad test";
        let aad = domain_aad(AAD_TAG_PROVE_OV_HDR, 200);
        let envelope = build_test_cose_sign1(&protected, payload, &aad, &[0xa0], &sk);

        let s1 = parse_cose_sign1(&envelope).unwrap();
        let wrong_aad = domain_aad(AAD_TAG_OV_ENTRY, 200); // different tag
        assert!(!verify_sign1(&s1, &wrong_aad, &point),
            "wrong domain AAD must fail verification");
    }

    // --- verify_bmo_signed ---

    #[test]
    fn test_verify_bmo_signed_model3_valid() {
        let (sk, point) = gen_test_keypair();
        let ct = BMO_CONTENT_TYPE_IMAGE_BEGIN;
        let protected = build_test_protected_header(Some(ct));
        let payload = b"\xa2\x01\x18\x0a\x02\x18\x0a"; // some CBOR
        let aad = domain_aad(AAD_TAG_BMO_PROVISION, 200);
        let envelope = build_test_cose_sign1(&protected, payload, &aad, &[0xa0], &sk);

        let result = verify_bmo_signed(&envelope, &point, ct, None);
        assert!(result.is_some(), "valid Model 3 BMO must verify");
        assert_eq!(result.unwrap(), payload);
    }

    #[test]
    fn test_verify_bmo_signed_wrong_content_type() {
        let (sk, point) = gen_test_keypair();
        let ct = BMO_CONTENT_TYPE_IMAGE_BEGIN;
        let protected = build_test_protected_header(Some(ct));
        let payload = b"\xa0";
        let aad = domain_aad(AAD_TAG_BMO_PROVISION, 200);
        let envelope = build_test_cose_sign1(&protected, payload, &aad, &[0xa0], &sk);

        // Expect a different content_type
        let result = verify_bmo_signed(&envelope, &point, BMO_CONTENT_TYPE_SET, None);
        assert!(result.is_none(), "wrong content_type must be rejected");
    }

    #[test]
    fn test_verify_bmo_signed_wrong_key() {
        let (sk, _point_a) = gen_test_keypair();
        let (_sk_b, point_b) = gen_test_keypair_b();
        let ct = BMO_CONTENT_TYPE_IMAGE_BEGIN;
        let protected = build_test_protected_header(Some(ct));
        let payload = b"\xa0";
        let aad = domain_aad(AAD_TAG_BMO_PROVISION, 200);
        let envelope = build_test_cose_sign1(&protected, payload, &aad, &[0xa0], &sk);

        let result = verify_bmo_signed(&envelope, &point_b, ct, None);
        assert!(result.is_none(), "BMO signed with key A must not verify with key B");
    }

    // --- scope evaluation ---

    #[test]
    fn test_scope_guid_match() {
        let device_guid = [0x01u8; 16];
        // Build scope map: { "guid": h'0101...01' }
        let mut scope_cbor = Vec::new();
        scope_cbor.push(0xa1); // map(1)
        encode_tstr(&mut scope_cbor, "guid");
        encode_bstr(&mut scope_cbor, &device_guid);

        // Build protected header with scope
        let mut hdr = Vec::new();
        hdr.push(0xa2); // map(2)
        hdr.push(0x01); hdr.push(0x26); // alg = -7
        encode_tstr(&mut hdr, BMO_SCOPE_LABEL);
        // scope value is a CBOR map, encoded as raw bytes
        hdr.extend_from_slice(&scope_cbor);

        assert!(evaluate_bmo_scope(&hdr, Some(&device_guid)));
    }

    #[test]
    fn test_scope_guid_mismatch() {
        let device_guid = [0x01u8; 16];
        let wrong_guid = [0x02u8; 16];
        let mut scope_cbor = Vec::new();
        scope_cbor.push(0xa1); // map(1)
        encode_tstr(&mut scope_cbor, "guid");
        encode_bstr(&mut scope_cbor, &wrong_guid);

        let mut hdr = Vec::new();
        hdr.push(0xa2); // map(2)
        hdr.push(0x01); hdr.push(0x26);
        encode_tstr(&mut hdr, BMO_SCOPE_LABEL);
        hdr.extend_from_slice(&scope_cbor);

        assert!(!evaluate_bmo_scope(&hdr, Some(&device_guid)),
            "GUID mismatch must fail");
    }

    #[test]
    fn test_scope_guid_array_any_match() {
        let device_guid = [0x02u8; 16];
        let guid_a = [0x01u8; 16];
        let guid_b = [0x02u8; 16]; // matches
        let guid_c = [0x03u8; 16];

        let mut scope_cbor = Vec::new();
        scope_cbor.push(0xa1); // map(1)
        encode_tstr(&mut scope_cbor, "guid");
        scope_cbor.push(0x83); // array(3)
        encode_bstr(&mut scope_cbor, &guid_a);
        encode_bstr(&mut scope_cbor, &guid_b);
        encode_bstr(&mut scope_cbor, &guid_c);

        let mut hdr = Vec::new();
        hdr.push(0xa2);
        hdr.push(0x01); hdr.push(0x26);
        encode_tstr(&mut hdr, BMO_SCOPE_LABEL);
        hdr.extend_from_slice(&scope_cbor);

        assert!(evaluate_bmo_scope(&hdr, Some(&device_guid)),
            "any-match in GUID array must pass");
    }

    #[test]
    fn test_scope_guid_array_none_match() {
        let device_guid = [0x99u8; 16];
        let guid_a = [0x01u8; 16];
        let guid_b = [0x02u8; 16];

        let mut scope_cbor = Vec::new();
        scope_cbor.push(0xa1);
        encode_tstr(&mut scope_cbor, "guid");
        scope_cbor.push(0x82); // array(2)
        encode_bstr(&mut scope_cbor, &guid_a);
        encode_bstr(&mut scope_cbor, &guid_b);

        let mut hdr = Vec::new();
        hdr.push(0xa2);
        hdr.push(0x01); hdr.push(0x26);
        encode_tstr(&mut hdr, BMO_SCOPE_LABEL);
        hdr.extend_from_slice(&scope_cbor);

        assert!(!evaluate_bmo_scope(&hdr, Some(&device_guid)),
            "no match in GUID array must fail");
    }

    #[test]
    fn test_scope_no_scope_passes() {
        // Protected header with just alg, no scope → passes
        let hdr = build_test_protected_header(None);
        assert!(evaluate_bmo_scope(&hdr, Some(&[0x01u8; 16])));
    }

    #[test]
    fn test_scope_unknown_field_fails_closed() {
        let mut scope_cbor = Vec::new();
        scope_cbor.push(0xa1); // map(1)
        encode_tstr(&mut scope_cbor, "evil_field");
        scope_cbor.push(0x00); // uint(0)

        let mut hdr = Vec::new();
        hdr.push(0xa2);
        hdr.push(0x01); hdr.push(0x26);
        encode_tstr(&mut hdr, BMO_SCOPE_LABEL);
        hdr.extend_from_slice(&scope_cbor);

        assert!(!evaluate_bmo_scope(&hdr, None),
            "unknown scope field must fail closed");
    }

    // --- CBOR helpers ---

    #[test]
    fn test_cbor_read_uint_arg_small() {
        let data = [];
        let mut pos = 0;
        assert_eq!(cbor_read_uint_arg(&data, &mut pos, 5), Some(5));
    }

    #[test]
    fn test_cbor_read_uint_arg_one_byte() {
        let data = [0x42];
        let mut pos = 0;
        assert_eq!(cbor_read_uint_arg(&data, &mut pos, 24), Some(0x42));
        assert_eq!(pos, 1);
    }

    #[test]
    fn test_cbor_read_uint_arg_two_bytes() {
        let data = [0x01, 0x00];
        let mut pos = 0;
        assert_eq!(cbor_read_uint_arg(&data, &mut pos, 25), Some(256));
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_cbor_skip_nested() {
        // array(2) [ uint(1), bstr(3) "abc" ]
        let data = [0x82, 0x01, 0x43, 0x61, 0x62, 0x63];
        let mut pos = 0;
        assert!(cbor_skip(&data, &mut pos).is_some());
        assert_eq!(pos, data.len());
    }

    #[test]
    fn test_has_delegate_header_empty_map() {
        assert!(!has_delegate_header(&[0xa0])); // empty map
    }

    #[test]
    fn test_has_delegate_header_with_x5chain() {
        // map(1) { 33: h'' }
        let data = [0xa1, 0x18, 33, 0x40]; // label 33 (x5chain), empty bstr
        assert!(has_delegate_header(&data));
    }

    #[test]
    fn test_has_delegate_header_with_label_258() {
        // map(1) { 258: h'' }
        let data = [0xa1, 0x19, 0x01, 0x02, 0x40]; // label 258, empty bstr
        assert!(has_delegate_header(&data));
    }

    #[test]
    fn test_has_delegate_header_no_delegate() {
        // map(1) { 1: -7 }  (alg header, not a delegate label)
        let data = [0xa1, 0x01, 0x26];
        assert!(!has_delegate_header(&data));
    }

    // --- Malformed input tests (Go: TestCoseSign1Verifier_Invalid*) ---

    #[test]
    fn test_verify_es256_empty_key() {
        let (sk, _) = gen_test_keypair();
        let msg = b"test";
        let sig: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(&sk, msg);
        assert!(!verify_es256(msg, sig.to_bytes().as_slice(), &[]),
            "empty key must fail");
    }

    #[test]
    fn test_verify_es256_garbage_key() {
        let (sk, _) = gen_test_keypair();
        let msg = b"test";
        let sig: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(&sk, msg);
        assert!(!verify_es256(msg, sig.to_bytes().as_slice(), &[0xDE, 0xAD, 0xBE, 0xEF]),
            "garbage key must fail");
    }

    #[test]
    fn test_parse_cose_sign1_empty() {
        assert!(parse_cose_sign1(&[]).is_none(), "empty input must fail");
    }

    #[test]
    fn test_parse_cose_sign1_garbage() {
        assert!(parse_cose_sign1(&[0xDE, 0xAD, 0xBE, 0xEF]).is_none(),
            "garbage bytes must fail");
    }

    #[test]
    fn test_parse_cose_sign1_cbor_not_sign1() {
        // Valid CBOR text string, but not a COSE_Sign1
        let data = [0x65, b'h', b'e', b'l', b'l', b'o']; // text(5) "hello"
        assert!(parse_cose_sign1(&data).is_none(),
            "valid CBOR but not Sign1 must fail");
    }

    #[test]
    fn test_verify_bmo_signed_empty_envelope() {
        let (_, point) = gen_test_keypair();
        let result = verify_bmo_signed(&[], &point, BMO_CONTENT_TYPE_IMAGE_BEGIN, None);
        assert!(result.is_none(), "empty envelope must fail");
    }

    #[test]
    fn test_verify_bmo_signed_garbage_envelope() {
        let (_, point) = gen_test_keypair();
        let result = verify_bmo_signed(
            &[0xD2, 0xDE, 0xAD, 0xBE, 0xEF], // tag 18 + garbage
            &point, BMO_CONTENT_TYPE_IMAGE_BEGIN, None,
        );
        assert!(result.is_none(), "garbage after tag 18 must fail");
    }

    #[test]
    fn test_verify_bmo_signed_tampered_payload() {
        let (sk, point) = gen_test_keypair();
        let ct = BMO_CONTENT_TYPE_IMAGE_BEGIN;
        let protected = build_test_protected_header(Some(ct));
        let payload = b"\xa1\x00\x0a"; // map(1) { 0: 10 }
        let aad = domain_aad(AAD_TAG_BMO_PROVISION, 200);
        let mut envelope = build_test_cose_sign1(&protected, payload, &aad, &[0xa0], &sk);

        // Tamper the payload bytes inside the COSE structure
        // Find the payload byte 0x0a and flip it
        if let Some(pos) = envelope.windows(3).position(|w| w == [0xa1, 0x00, 0x0a]) {
            envelope[pos + 2] ^= 0xFF;
        }

        let result = verify_bmo_signed(&envelope, &point, ct, None);
        assert!(result.is_none(), "tampered payload must fail verification");
    }

    #[test]
    fn test_verify_bmo_signed_tampered_signature() {
        let (sk, point) = gen_test_keypair();
        let ct = BMO_CONTENT_TYPE_IMAGE_BEGIN;
        let protected = build_test_protected_header(Some(ct));
        let payload = b"\xa0";
        let aad = domain_aad(AAD_TAG_BMO_PROVISION, 200);
        let mut envelope = build_test_cose_sign1(&protected, payload, &aad, &[0xa0], &sk);

        // Flip the last byte (inside the signature)
        let last = envelope.len() - 1;
        envelope[last] ^= 0x01;

        let result = verify_bmo_signed(&envelope, &point, ct, None);
        assert!(result.is_none(), "tampered signature must fail verification");
    }

    // --- Scope: combined fields, edge cases ---

    #[test]
    fn test_scope_combined_fields_all_valid() {
        // Scope with guid + not_before + not_after + generation — all valid
        let device_guid = [0x01u8; 16];
        let mut scope_cbor = Vec::new();
        scope_cbor.push(0xa4); // map(4)
        encode_tstr(&mut scope_cbor, "guid");
        encode_bstr(&mut scope_cbor, &device_guid);
        encode_tstr(&mut scope_cbor, "not_before");
        // uint 1735689600 (2025-01-01)
        scope_cbor.push(0x1a);
        scope_cbor.extend_from_slice(&1735689600u32.to_be_bytes());
        encode_tstr(&mut scope_cbor, "not_after");
        // uint 1893456000 (2030-01-01)
        scope_cbor.push(0x1a);
        scope_cbor.extend_from_slice(&1893456000u32.to_be_bytes());
        encode_tstr(&mut scope_cbor, "generation");
        scope_cbor.push(0x01); // uint 1

        let mut hdr = Vec::new();
        hdr.push(0xa2); // map(2)
        hdr.push(0x01); hdr.push(0x26); // alg = -7
        encode_tstr(&mut hdr, BMO_SCOPE_LABEL);
        hdr.extend_from_slice(&scope_cbor);

        assert!(evaluate_bmo_scope(&hdr, Some(&device_guid)),
            "all valid scope fields must pass");
    }

    #[test]
    fn test_scope_combined_guid_mismatch_fails_everything() {
        // Even with valid time/generation, a GUID mismatch must fail
        let device_guid = [0x01u8; 16];
        let wrong_guid = [0x02u8; 16];
        let mut scope_cbor = Vec::new();
        scope_cbor.push(0xa3); // map(3)
        encode_tstr(&mut scope_cbor, "generation");
        scope_cbor.push(0x01);
        encode_tstr(&mut scope_cbor, "not_before");
        scope_cbor.push(0x1a);
        scope_cbor.extend_from_slice(&1735689600u32.to_be_bytes());
        encode_tstr(&mut scope_cbor, "guid");
        encode_bstr(&mut scope_cbor, &wrong_guid);

        let mut hdr = Vec::new();
        hdr.push(0xa2);
        hdr.push(0x01); hdr.push(0x26);
        encode_tstr(&mut hdr, BMO_SCOPE_LABEL);
        hdr.extend_from_slice(&scope_cbor);

        assert!(!evaluate_bmo_scope(&hdr, Some(&device_guid)),
            "GUID mismatch must fail even with valid other fields");
    }

    #[test]
    fn test_scope_guid_no_device_guid_skips() {
        // When device_guid is None, guid check is skipped (device doesn't know its GUID yet)
        let scope_guid = [0xAA; 16];
        let mut scope_cbor = Vec::new();
        scope_cbor.push(0xa1);
        encode_tstr(&mut scope_cbor, "guid");
        encode_bstr(&mut scope_cbor, &scope_guid);

        let mut hdr = Vec::new();
        hdr.push(0xa2);
        hdr.push(0x01); hdr.push(0x26);
        encode_tstr(&mut hdr, BMO_SCOPE_LABEL);
        hdr.extend_from_slice(&scope_cbor);

        assert!(evaluate_bmo_scope(&hdr, None),
            "no device GUID → guid check skipped → pass");
    }

    #[test]
    fn test_scope_empty_map_passes() {
        // Empty scope map {} — no constraints
        let mut hdr = Vec::new();
        hdr.push(0xa2);
        hdr.push(0x01); hdr.push(0x26);
        encode_tstr(&mut hdr, BMO_SCOPE_LABEL);
        hdr.push(0xa0); // map(0)

        assert!(evaluate_bmo_scope(&hdr, Some(&[0x01u8; 16])),
            "empty scope map must pass");
    }

    #[test]
    fn test_scope_multiple_unknown_fields_fail_closed() {
        let mut scope_cbor = Vec::new();
        scope_cbor.push(0xa2); // map(2)
        encode_tstr(&mut scope_cbor, "generation");
        scope_cbor.push(0x01);
        encode_tstr(&mut scope_cbor, "evil_extension");
        scope_cbor.push(0x00);

        let mut hdr = Vec::new();
        hdr.push(0xa2);
        hdr.push(0x01); hdr.push(0x26);
        encode_tstr(&mut hdr, BMO_SCOPE_LABEL);
        hdr.extend_from_slice(&scope_cbor);

        assert!(!evaluate_bmo_scope(&hdr, None),
            "unknown field after valid field must still fail closed");
    }

    // --- Domain AAD cross-version ---

    #[test]
    fn test_domain_aad_v101_vs_v200() {
        // v1.01 proof signed with empty AAD must fail when verified with v2.0 AAD
        let (sk, point) = gen_test_keypair();
        let protected = build_test_protected_header(None);
        let payload = b"cross-version test";

        // Sign with v1.01 AAD (empty)
        let aad_v101 = domain_aad(AAD_TAG_PROVE_OV_HDR, FDO_VERSION_101);
        assert!(aad_v101.is_empty());
        let envelope = build_test_cose_sign1(&protected, payload, &aad_v101, &[0xa0], &sk);

        let s1 = parse_cose_sign1(&envelope).unwrap();

        // Verify with same empty AAD → must pass
        assert!(verify_sign1(&s1, &aad_v101, &point),
            "v1.01 proof with empty AAD must verify with empty AAD");

        // Verify with v2.0 AAD → must FAIL
        let aad_v200 = domain_aad(AAD_TAG_PROVE_OV_HDR, FDO_VERSION_200);
        assert!(!aad_v200.is_empty());
        assert!(!verify_sign1(&s1, &aad_v200, &point),
            "v1.01 proof must fail when verified with v2.0 AAD");
    }

    #[test]
    fn test_domain_aad_different_tags_not_interchangeable() {
        // A proof signed with one tag must not verify with a different tag
        let (sk, point) = gen_test_keypair();
        let protected = build_test_protected_header(None);
        let payload = b"tag test";

        let aad_prove = domain_aad(AAD_TAG_PROVE_OV_HDR, FDO_VERSION_200);
        let envelope = build_test_cose_sign1(&protected, payload, &aad_prove, &[0xa0], &sk);
        let s1 = parse_cose_sign1(&envelope).unwrap();

        // Correct AAD → pass
        assert!(verify_sign1(&s1, &aad_prove, &point));

        // Wrong AAD tag → fail
        let aad_device = domain_aad(AAD_TAG_PROVE_DEVICE, FDO_VERSION_200);
        assert!(!verify_sign1(&s1, &aad_device, &point),
            "proof with PROVE_OV_HDR AAD must fail when verified with PROVE_DEVICE AAD");

        let aad_bmo = domain_aad(AAD_TAG_BMO_PROVISION, FDO_VERSION_200);
        assert!(!verify_sign1(&s1, &aad_bmo, &point),
            "proof with PROVE_OV_HDR AAD must fail when verified with BMO_PROVISION AAD");
    }

    // --- COSE_Sign1: missing content_type ---

    #[test]
    fn test_verify_bmo_signed_no_content_type() {
        // Protected header with alg but NO content_type
        let (sk, point) = gen_test_keypair();
        let protected = build_test_protected_header(None); // no content_type
        let payload = b"\xa0";
        let aad = domain_aad(AAD_TAG_BMO_PROVISION, 200);
        let envelope = build_test_cose_sign1(&protected, payload, &aad, &[0xa0], &sk);

        let result = verify_bmo_signed(&envelope, &point, BMO_CONTENT_TYPE_IMAGE_BEGIN, None);
        assert!(result.is_none(),
            "BMO without content_type in protected header must be rejected");
    }

    // --- Delegate-signed BMO without PERM.7 ---

    #[test]
    fn test_verify_bmo_delegate_signed_missing_perm7() {
        use crate::delegate::{build_test_cert, OID_PERMIT_ONBOARD_NEWCRED};
        let (owner_sk, owner_point) = gen_test_keypair();
        let (delegate_sk, delegate_point) = gen_test_keypair_b();

        // Cert with onboard but NOT provision (PERM.7)
        let cert_der = build_test_cert(
            &owner_sk, &delegate_point,
            &[OID_PERMIT_ONBOARD_NEWCRED],
        );

        let ct = BMO_CONTENT_TYPE_IMAGE_BEGIN;
        let protected = build_test_protected_header(Some(ct));
        let payload = b"\xa1\x00\x18\x34";
        let aad = domain_aad(AAD_TAG_BMO_PROVISION, 200);

        let mut unhdr = Vec::new();
        unhdr.push(0xa1);
        unhdr.push(0x18); unhdr.push(33); // x5chain label
        encode_bstr(&mut unhdr, &cert_der);

        let envelope = build_test_cose_sign1(
            &protected, payload, &aad, &unhdr, &delegate_sk,
        );

        let result = verify_bmo_signed(&envelope, &owner_point, ct, None);
        assert!(result.is_none(),
            "delegate without PERM.7 must be rejected for BMO signing");
    }
}
