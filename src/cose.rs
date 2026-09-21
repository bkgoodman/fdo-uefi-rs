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
/// 3. Builds external_aad = CBOR(["FDO-FSIM-BmoProvision-v1"])
/// 4. Verifies signature against `owner_point` (P-256, 65 bytes)
/// 5. If x5chain (label 33) is present in unprotected header, logs it
///    (full delegate chain validation is a future item)
///
/// Returns the inner payload bytes on success, or None on failure.
pub fn verify_bmo_signed<'a>(data: &'a [u8], owner_point: &[u8], expected_ct: &str) -> Option<&'a [u8]> {
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

    // Check for delegate x5chain in unprotected header
    if has_delegate_header(s1.unprotected_header) {
        // For now, we only support Owner-signed (Case 3).
        // Delegate-signed (Case 4) requires x509 cert chain validation.
        warn!("BMO COSE: x5chain/delegate header present — delegate verification not yet implemented");
        warn!("BMO COSE: falling back to direct Owner key verification");
        // TODO: extract leaf cert from x5chain, verify chain to owner_point,
        // check OIDPermitProvision, and verify signature with leaf key.
    }

    // Build external_aad = CBOR(["FDO-FSIM-BmoProvision-v1"])
    // This is always used (no version gating like FDO protocol AAD).
    let mut aad = Vec::with_capacity(AAD_TAG_BMO_PROVISION.len() + 3);
    aad.push(0x81); // array(1)
    encode_tstr(&mut aad, AAD_TAG_BMO_PROVISION);

    // Verify signature
    let sig_structure = build_sig_structure(s1.protected_header, &aad, s1.payload);
    if !verify_es256(&sig_structure, s1.signature, owner_point) {
        error!("BMO COSE: SIGNATURE VERIFICATION FAILED");
        return None;
    }

    info!("BMO COSE: signature verified OK (content_type={})", expected_ct);
    Some(s1.payload)
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

fn encode_bstr(out: &mut Vec<u8>, data: &[u8]) {
    encode_head(out, 2, data.len());
    out.extend_from_slice(data);
}

fn encode_tstr(out: &mut Vec<u8>, s: &str) {
    encode_head(out, 3, s.len());
    out.extend_from_slice(s.as_bytes());
}

fn encode_head(out: &mut Vec<u8>, major: u8, len: usize) {
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
