// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// Minimal X.509 DER parsing for FDO delegate certificate chains.
//
// This module validates that a delegate chain presented in TO2.ProveOVHdr
// (COSE unprotected header label 258) is rooted in the Owner key and that
// the leaf certificate carries the required FDO permissions.
//
// Design constraints:
// - no_std (UEFI environment, no x509-parser or similar crate)
// - Only P-256/ES256 certificates (matching the rest of fdo-uefi-rs)
// - Minimal parsing: we extract TBS, SPKI, signature, and specific OIDs
//
// Reference: go-fdo/delegate.go VerifyDelegateChain / processDelegateChain

use alloc::vec::Vec;
use log::{debug, error, info};

use crate::cose;

// ---------------------------------------------------------------------------
// OID constants (DER encoded, without the tag/length)
// ---------------------------------------------------------------------------

/// OIDPermitProvision = 1.3.6.1.4.1.45724.3.1.7 (PERM.7)
/// DER encoding: 06 0C 2B 06 01 04 01 82 E5 1C 03 01 07
/// The raw OID bytes (after the 06 0C tag+length):
const OID_PERMIT_PROVISION: &[u8] = &[
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x1C, 0x03, 0x01, 0x07,
];

/// OIDPermitOnboardNewCred = 1.3.6.1.4.1.45724.3.1.1
const OID_PERMIT_ONBOARD_NEWCRED: &[u8] = &[
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x1C, 0x03, 0x01, 0x01,
];

/// OIDPermitOnboardReuseCred = 1.3.6.1.4.1.45724.3.1.2
const OID_PERMIT_ONBOARD_REUSECRED: &[u8] = &[
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x1C, 0x03, 0x01, 0x02,
];

/// OIDPermitOnboardFdoDisable = 1.3.6.1.4.1.45724.3.1.3
const OID_PERMIT_ONBOARD_FDODISABLE: &[u8] = &[
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x1C, 0x03, 0x01, 0x03,
];

/// ExtendedKeyUsage extension OID = 2.5.29.37
const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x25];

// ---------------------------------------------------------------------------
// Parsed certificate
// ---------------------------------------------------------------------------

/// Minimal parsed X.509 certificate — just what we need for chain validation.
pub struct ParsedCert<'a> {
    /// Raw TBS (to-be-signed) section, including its SEQUENCE wrapper.
    /// This is what gets hashed and signature-checked.
    pub tbs_raw: &'a [u8],
    /// P-256 uncompressed public key point (65 bytes: 04 || X || Y)
    pub public_key_point: Vec<u8>,
    /// Signature bytes (r || s, 64 bytes for ES256)
    pub signature_rs: Vec<u8>,
    /// Whether this certificate has OIDPermitProvision (PERM.7)
    pub has_permit_provision: bool,
    /// Whether this certificate has any fdo-ekt-permit-onboard-* permission
    pub has_permit_onboard: bool,
}

/// Result of delegate chain validation.
pub struct DelegateChainResult {
    /// The leaf certificate's P-256 public key point (for verifying ProveOVHdr).
    pub leaf_key_point: Vec<u8>,
    /// Whether the leaf certificate has OIDPermitProvision (PERM.7).
    pub has_provision: bool,
    /// Whether the leaf certificate has any onboard permission.
    pub has_onboard: bool,
}

// ---------------------------------------------------------------------------
// Chain validation
// ---------------------------------------------------------------------------

/// Validate a delegate certificate chain against the Owner public key.
///
/// `cert_ders` is leaf-first (i.e. `[leaf, ..., root]`).
/// `owner_key_point` is the TO2-proven Owner key (P-256, 65 bytes).
///
/// Verification:
/// 1. Parse every certificate
/// 2. Verify root cert's signature against `owner_key_point`
/// 3. Walk from root to leaf, verifying each cert is signed by its parent
/// 4. Extract leaf key and permissions
///
/// Returns the leaf key and its permissions on success.
pub fn verify_delegate_chain(
    cert_ders: &[&[u8]],
    owner_key_point: &[u8],
) -> Option<DelegateChainResult> {
    if cert_ders.is_empty() {
        error!("delegate: empty certificate chain");
        return None;
    }

    // Parse all certs
    let mut parsed: Vec<ParsedCert> = Vec::with_capacity(cert_ders.len());
    for (i, der) in cert_ders.iter().enumerate() {
        match parse_x509_cert(der) {
            Some(cert) => {
                debug!("delegate: cert[{}]: {} bytes, key={} bytes, sig={} bytes, prov={}, onboard={}",
                    i, der.len(), cert.public_key_point.len(), cert.signature_rs.len(),
                    cert.has_permit_provision, cert.has_permit_onboard);
                parsed.push(cert);
            }
            None => {
                error!("delegate: failed to parse certificate {} ({} bytes)", i, der.len());
                return None;
            }
        }
    }

    // Verify chain from root → leaf.
    // Root = parsed[last], verified against owner_key_point.
    let root_idx = parsed.len() - 1;

    // Step 1: verify root cert was signed by Owner key
    // verify_es256 hashes its input with SHA-256 internally, so pass raw TBS.
    if !cose::verify_es256(parsed[root_idx].tbs_raw, &parsed[root_idx].signature_rs, owner_key_point) {
        error!("delegate: root certificate (idx {}) NOT signed by Owner key", root_idx);
        return None;
    }
    info!("delegate: root certificate verified against Owner key");

    // Step 2: walk from root toward leaf, verifying each cert is signed by its parent
    if parsed.len() > 1 {
        for i in (0..root_idx).rev() {
            let issuer_point = &parsed[i + 1].public_key_point;
            if !cose::verify_es256(parsed[i].tbs_raw, &parsed[i].signature_rs, issuer_point) {
                error!("delegate: certificate {} NOT signed by certificate {}", i, i + 1);
                return None;
            }
            debug!("delegate: certificate {} verified against certificate {}", i, i + 1);
        }
    }

    info!("delegate: chain verified ({} cert(s)), leaf has provision={}, onboard={}",
        parsed.len(), parsed[0].has_permit_provision, parsed[0].has_permit_onboard);

    Some(DelegateChainResult {
        leaf_key_point: parsed[0].public_key_point.clone(),
        has_provision: parsed[0].has_permit_provision,
        has_onboard: parsed[0].has_permit_onboard,
    })
}



// ---------------------------------------------------------------------------
// X.509 DER parsing
// ---------------------------------------------------------------------------

/// Parse a DER-encoded X.509 certificate.
///
/// Certificate ::= SEQUENCE {
///     tbsCertificate      TBSCertificate,    -- SEQUENCE
///     signatureAlgorithm  AlgorithmIdentifier,
///     signatureValue      BIT STRING
/// }
fn parse_x509_cert(der: &[u8]) -> Option<ParsedCert<'_>> {
    let mut pos = 0usize;

    // Outer SEQUENCE
    let (_, outer_end) = read_sequence_header(der, &mut pos)?;
    if outer_end > der.len() {
        error!("x509: outer SEQUENCE extends past certificate ({} > {})", outer_end, der.len());
        return None;
    }

    // TBS is the first element — capture its raw bytes (including SEQUENCE header)
    let tbs_start = pos;
    let (_, tbs_end) = read_sequence_header(der, &mut pos)?;
    // tbs_raw = everything from tbs_start through the end of the TBS content
    let tbs_raw = der.get(tbs_start..tbs_end)?;
    pos = tbs_end; // skip past TBS content

    // signatureAlgorithm (SEQUENCE) — skip it
    skip_der_element(der, &mut pos)?;

    // signatureValue (BIT STRING)
    let sig_raw = read_bit_string(der, &mut pos)?;
    // For ECDSA, this is a DER-encoded SEQUENCE { INTEGER r, INTEGER s }
    let signature_rs = ecdsa_der_to_rs(sig_raw)?;

    // Now parse inside TBS to extract the public key and extensions
    let mut tbs_pos = tbs_start;
    let (_, _tbs_content_end) = read_sequence_header(der, &mut tbs_pos)?;

    // TBSCertificate fields:
    // [0] version (EXPLICIT, optional) — tag 0xA0
    // serialNumber
    // signature (AlgId)
    // issuer
    // validity
    // subject
    // subjectPublicKeyInfo
    // [3] extensions (EXPLICIT, optional) — tag 0xA3

    // Skip version if present (context tag [0] = 0xA0)
    if der.get(tbs_pos) == Some(&0xA0) {
        skip_der_element(der, &mut tbs_pos)?;
    }

    // serialNumber (INTEGER)
    skip_der_element(der, &mut tbs_pos)?;
    // signature (AlgId SEQUENCE)
    skip_der_element(der, &mut tbs_pos)?;
    // issuer (Name SEQUENCE)
    skip_der_element(der, &mut tbs_pos)?;
    // validity (SEQUENCE)
    skip_der_element(der, &mut tbs_pos)?;
    // subject (Name SEQUENCE)
    skip_der_element(der, &mut tbs_pos)?;

    // subjectPublicKeyInfo (SEQUENCE)
    let spki_start = tbs_pos;
    let (_, spki_end) = read_sequence_header(der, &mut tbs_pos)?;
    let spki_data = der.get(spki_start..spki_end)?;
    let public_key_point = extract_p256_point(spki_data)?;
    tbs_pos = spki_end;

    // Extensions — look for [3] (tag 0xA3)
    let mut has_permit_provision = false;
    let mut has_permit_onboard = false;

    // There might be issuerUniqueID [1] or subjectUniqueID [2] before extensions
    while tbs_pos < tbs_raw.len() + tbs_start {
        let tag = *der.get(tbs_pos)?;
        if tag == 0xA3 {
            // Extensions [3] EXPLICIT
            tbs_pos += 1;
            let ext_wrapper_len = read_der_length(der, &mut tbs_pos)?;
            let ext_wrapper_end = tbs_pos + ext_wrapper_len;

            // Inner SEQUENCE of Extension entries
            let (_, ext_seq_end) = read_sequence_header(der, &mut tbs_pos)?;
            let _ = ext_seq_end; // just for clarity
            let mut ext_pos = tbs_pos;

            while ext_pos < ext_wrapper_end {
                let ext_start = ext_pos;
                let (_, ext_end) = match read_sequence_header(der, &mut ext_pos) {
                    Some(v) => v,
                    None => break,
                };

                // Extension ::= SEQUENCE { extnID OID, critical BOOL?, extnValue OCTET STRING }
                if let Some(oid) = read_oid(der, &mut ext_pos) {
                    if oid == OID_EXT_KEY_USAGE {
                        // Parse the ExtendedKeyUsage value
                        // Skip optional critical BOOLEAN
                        if der.get(ext_pos) == Some(&0x01) {
                            skip_der_element(der, &mut ext_pos)?;
                        }
                        // OCTET STRING wrapping the EKU SEQUENCE
                        let eku_wrapper = read_octet_string(der, &mut ext_pos)?;
                        check_eku_oids(eku_wrapper, &mut has_permit_provision, &mut has_permit_onboard);
                    }
                }
                ext_pos = ext_end;
                let _ = ext_start; // used for debug if needed
            }
            break;
        } else if tag == 0xA1 || tag == 0xA2 {
            // issuerUniqueID [1] or subjectUniqueID [2] — skip
            skip_der_element(der, &mut tbs_pos)?;
        } else {
            break;
        }
    }

    Some(ParsedCert {
        tbs_raw,
        public_key_point,
        signature_rs,
        has_permit_provision,
        has_permit_onboard,
    })
}

/// Check an ExtendedKeyUsage SEQUENCE for FDO permission OIDs.
fn check_eku_oids(data: &[u8], has_provision: &mut bool, has_onboard: &mut bool) {
    let mut pos = 0usize;
    // SEQUENCE of OIDs
    let (_, seq_end) = match read_sequence_header(data, &mut pos) {
        Some(v) => v,
        None => return,
    };
    while pos < seq_end {
        if let Some(oid) = read_oid(data, &mut pos) {
            if oid == OID_PERMIT_PROVISION {
                *has_provision = true;
                debug!("delegate: found OIDPermitProvision (PERM.7)");
            } else if oid == OID_PERMIT_ONBOARD_NEWCRED
                || oid == OID_PERMIT_ONBOARD_REUSECRED
                || oid == OID_PERMIT_ONBOARD_FDODISABLE
            {
                *has_onboard = true;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ASN.1 DER helpers
// ---------------------------------------------------------------------------

/// Read a SEQUENCE header, returning (content_start, content_end).
fn read_sequence_header(data: &[u8], pos: &mut usize) -> Option<(usize, usize)> {
    let tag = *data.get(*pos)?;
    if tag != 0x30 {
        // Not a SEQUENCE
        return None;
    }
    *pos += 1;
    let len = read_der_length(data, pos)?;
    let content_start = *pos;
    let content_end = content_start + len;
    if content_end > data.len() {
        return None;
    }
    Some((content_start, content_end))
}

/// Read a DER length field.
fn read_der_length(data: &[u8], pos: &mut usize) -> Option<usize> {
    let b = *data.get(*pos)?;
    *pos += 1;
    if b < 0x80 {
        Some(b as usize)
    } else {
        let num_bytes = (b & 0x7F) as usize;
        if num_bytes > 4 || num_bytes == 0 {
            return None;
        }
        let mut len = 0usize;
        for _ in 0..num_bytes {
            len = (len << 8) | (*data.get(*pos)? as usize);
            *pos += 1;
        }
        Some(len)
    }
}

/// Skip one DER element (tag + length + content).
fn skip_der_element(data: &[u8], pos: &mut usize) -> Option<()> {
    let _tag = *data.get(*pos)?;
    *pos += 1;
    let len = read_der_length(data, pos)?;
    if *pos + len > data.len() {
        return None;
    }
    *pos += len;
    Some(())
}

/// Read a BIT STRING, returning the content bytes (after the unused-bits octet).
fn read_bit_string<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let tag = *data.get(*pos)?;
    if tag != 0x03 {
        return None;
    }
    *pos += 1;
    let len = read_der_length(data, pos)?;
    if len == 0 {
        return None;
    }
    let _unused_bits = *data.get(*pos)?;
    *pos += 1;
    let content = data.get(*pos..*pos + len - 1)?;
    *pos += len - 1;
    Some(content)
}

/// Read an OCTET STRING, returning its content.
fn read_octet_string<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let tag = *data.get(*pos)?;
    if tag != 0x04 {
        return None;
    }
    *pos += 1;
    let len = read_der_length(data, pos)?;
    let content = data.get(*pos..*pos + len)?;
    *pos += len;
    Some(content)
}

/// Read an OID, returning just the OID value bytes (no tag/length).
fn read_oid<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let tag = *data.get(*pos)?;
    if tag != 0x06 {
        return None;
    }
    *pos += 1;
    let len = read_der_length(data, pos)?;
    let oid = data.get(*pos..*pos + len)?;
    *pos += len;
    Some(oid)
}

/// Extract an uncompressed P-256 point from a SubjectPublicKeyInfo.
/// Re-uses the same pattern search as voucher.rs but is self-contained.
fn extract_p256_point(spki: &[u8]) -> Option<Vec<u8>> {
    // Look for BIT STRING containing 0x04 (uncompressed point marker)
    // Pattern: 03 42 00 04 (BIT STRING, len 66, 0 unused bits, uncompressed)
    const PATTERN: [u8; 4] = [0x03, 0x42, 0x00, 0x04];
    for i in 0..spki.len().saturating_sub(PATTERN.len()) {
        if spki.get(i..i + 4)? == &PATTERN {
            let start = i + 3; // at the 0x04 marker
            let point = spki.get(start..start + 65)?;
            return Some(point.to_vec());
        }
    }
    // Try P-384: 03 62 00 04 (BIT STRING, len 98, 0 unused bits, uncompressed)
    // We don't support P-384 for verification, but log it.
    const P384_PATTERN: [u8; 4] = [0x03, 0x62, 0x00, 0x04];
    for i in 0..spki.len().saturating_sub(P384_PATTERN.len()) {
        if spki.get(i..i + 4) == Some(&P384_PATTERN[..]) {
            error!("delegate: P-384 key detected but only P-256 is supported");
            return None;
        }
    }
    error!("delegate: no P-256 uncompressed point in SPKI ({} bytes)", spki.len());
    None
}

/// Convert an ECDSA DER-encoded signature to fixed-width r||s (64 bytes for P-256).
///
/// Input:  SEQUENCE { INTEGER r, INTEGER s }
/// Output: r[32] || s[32]  (zero-padded, no leading-zero trimming)
fn ecdsa_der_to_rs(der_sig: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0usize;
    // SEQUENCE
    let tag = *der_sig.get(pos)?;
    if tag != 0x30 {
        error!("delegate: ECDSA signature is not a SEQUENCE (tag=0x{:02x})", tag);
        return None;
    }
    pos += 1;
    let _seq_len = read_der_length(der_sig, &mut pos)?;

    // INTEGER r
    let r_bytes = read_der_integer(der_sig, &mut pos)?;
    // INTEGER s
    let s_bytes = read_der_integer(der_sig, &mut pos)?;

    // Pad/trim to 32 bytes each
    let mut rs = alloc::vec![0u8; 64];
    copy_integer_to_fixed(&r_bytes, &mut rs[0..32]);
    copy_integer_to_fixed(&s_bytes, &mut rs[32..64]);
    Some(rs)
}

/// Read a DER INTEGER, returning its value bytes.
fn read_der_integer<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let tag = *data.get(*pos)?;
    if tag != 0x02 {
        return None;
    }
    *pos += 1;
    let len = read_der_length(data, pos)?;
    let val = data.get(*pos..*pos + len)?;
    *pos += len;
    Some(val)
}

/// Copy an integer (possibly with leading zero or shorter than target) into a
/// fixed-width buffer, right-aligned.
fn copy_integer_to_fixed(src: &[u8], dst: &mut [u8]) {
    let target_len = dst.len();
    // Strip leading zeros
    let trimmed = match src.iter().position(|&b| b != 0) {
        Some(i) => &src[i..],
        None => &[0u8],
    };
    if trimmed.len() > target_len {
        // Shouldn't happen for P-256, but truncate from the left
        let excess = trimmed.len() - target_len;
        dst.copy_from_slice(&trimmed[excess..]);
    } else {
        let offset = target_len - trimmed.len();
        dst[offset..].copy_from_slice(trimmed);
    }
}

// ---------------------------------------------------------------------------
// CBOR helpers for parsing the delegate PublicKey from unprotected header
// ---------------------------------------------------------------------------

/// Extract the delegate certificate DER bytes from a COSE unprotected header.
///
/// Looks for label 258 (CUPHDelegateChain), which carries an FDO `PublicKey`
/// structure `[pkType, pkEnc, pkBody]`. For delegates, `pkEnc` is `X5CHAIN (2)`
/// and `pkBody` is a CBOR array of DER cert bstrs (leaf first).
///
/// Returns the raw DER bytes for each certificate, leaf first.
pub fn extract_delegate_chain_from_unprotected(unprotected: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut pos = 0usize;
    let b = *unprotected.get(pos)?;
    if (b >> 5) != 5 {
        return None; // not a map
    }
    pos += 1;
    let map_len = cose::cbor_read_uint_arg(unprotected, &mut pos, b & 0x1f)?;

    for _ in 0..map_len {
        let key = cose::cbor_read_int_value(unprotected, &mut pos)?;
        if key == cose::COSE_LABEL_DELEGATE_KEY {
            // Value is [pkType, pkEnc, pkBody]
            return parse_fdo_public_key_x5chain(unprotected, &mut pos);
        }
        // Not our key, skip value
        cose::cbor_skip(unprotected, &mut pos)?;
    }
    None
}

/// Extract the x5chain certificate DER bytes from a COSE unprotected header.
///
/// Looks for label 33 (x5chain, RFC 9360), which carries either:
/// - A CBOR array of DER cert bstrs (leaf first), or
/// - A single DER cert bstr (single-cert chain)
///
/// This is the format used for BMO provisioning delegate signatures (Model 4),
/// as opposed to label 258 which is used for the TO2 delegate chain.
///
/// Returns the raw DER bytes for each certificate, leaf first.
pub fn extract_x5chain_from_unprotected(unprotected: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut pos = 0usize;
    let b = *unprotected.get(pos)?;
    if (b >> 5) != 5 {
        return None; // not a map
    }
    pos += 1;
    let map_len = cose::cbor_read_uint_arg(unprotected, &mut pos, b & 0x1f)?;

    for _ in 0..map_len {
        let key = cose::cbor_read_int_value(unprotected, &mut pos)?;
        if key == cose::COSE_LABEL_X5CHAIN {
            // Value is a CBOR array of DER cert bstrs, or a single bstr
            return parse_x5chain_value(unprotected, &mut pos);
        }
        // Not our key, skip value
        cose::cbor_skip(unprotected, &mut pos)?;
    }
    None
}

/// Parse an x5chain value (label 33): array of DER bstrs or single bstr.
fn parse_x5chain_value(data: &[u8], pos: &mut usize) -> Option<Vec<Vec<u8>>> {
    let b = *data.get(*pos)?;
    *pos += 1;
    let major = b >> 5;

    if major == 4 {
        // Array of bstrs (leaf first)
        let cert_count = cose::cbor_read_uint_arg(data, pos, b & 0x1f)?;
        let mut certs = Vec::with_capacity(cert_count);
        for i in 0..cert_count {
            let der = cose::cbor_read_bstr(data, pos)?;
            debug!("x5chain: cert[{}] = {} bytes DER", i, der.len());
            certs.push(der.to_vec());
        }
        Some(certs)
    } else if major == 2 {
        // Single cert as bare bstr
        let len = cose::cbor_read_uint_arg(data, pos, b & 0x1f)?;
        let der = data.get(*pos..*pos + len)?;
        *pos += len;
        debug!("x5chain: single cert = {} bytes DER", der.len());
        Some(alloc::vec![der.to_vec()])
    } else {
        error!("x5chain: value is neither array nor bstr (major={})", major);
        None
    }
}

/// Parse an FDO PublicKey as X5CHAIN and return the DER cert bytes.
fn parse_fdo_public_key_x5chain(data: &[u8], pos: &mut usize) -> Option<Vec<Vec<u8>>> {
    // [pkType, pkEnc, pkBody]
    let b = *data.get(*pos)?;
    *pos += 1;
    if (b >> 5) != 4 {
        error!("delegate: PublicKey is not a CBOR array");
        return None;
    }
    let arr_len = cose::cbor_read_uint_arg(data, pos, b & 0x1f)?;
    if arr_len < 3 {
        error!("delegate: PublicKey array too short ({})", arr_len);
        return None;
    }

    let pk_type = cose::cbor_read_int_value(data, pos)?;
    let pk_enc = cose::cbor_read_int_value(data, pos)?;

    debug!("delegate: PublicKey pkType={}, pkEnc={}", pk_type, pk_enc);

    // We only handle X5CHAIN (pkEnc=2) for delegates
    if pk_enc != 2 {
        error!("delegate: expected pkEnc=X5CHAIN(2), got {}", pk_enc);
        return None;
    }

    // pkBody: CBOR array of DER cert bstrs (leaf first)
    // go-fdo encodes this as cbor.RawBytes — the third element is a raw CBOR
    // array directly, not wrapped in a bstr.
    let b = *data.get(*pos)?;
    *pos += 1;
    let major = b >> 5;

    if major == 4 {
        // Array of bstrs
        let cert_count = cose::cbor_read_uint_arg(data, pos, b & 0x1f)?;
        let mut certs = Vec::with_capacity(cert_count);
        for i in 0..cert_count {
            let der = cose::cbor_read_bstr(data, pos)?;
            debug!("delegate: cert[{}] = {} bytes DER", i, der.len());
            certs.push(der.to_vec());
        }
        Some(certs)
    } else if major == 2 {
        // Single cert as bare bstr
        let len = cose::cbor_read_uint_arg(data, pos, b & 0x1f)?;
        let der = data.get(*pos..*pos + len)?;
        *pos += len;
        debug!("delegate: single cert = {} bytes DER", der.len());
        Some(alloc::vec![der.to_vec()])
    } else {
        error!("delegate: X5CHAIN pkBody is neither array nor bstr (major={})", major);
        None
    }
}
