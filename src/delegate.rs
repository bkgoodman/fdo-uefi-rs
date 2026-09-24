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

/// OIDPermitRedirect = 1.3.6.1.4.1.45724.3.1.1 (PERM.1)
/// Required for TO0/TO1 redirect operations.
pub(crate) const OID_PERMIT_REDIRECT: &[u8] = &[
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x1C, 0x03, 0x01, 0x01,
];

/// OIDPermitOnboardNewCred = 1.3.6.1.4.1.45724.3.1.2 (PERM.2)
/// Allows onboarding with new credentials.
pub(crate) const OID_PERMIT_ONBOARD_NEWCRED: &[u8] = &[
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x1C, 0x03, 0x01, 0x02,
];

/// OIDPermitOnboardReuseCred = 1.3.6.1.4.1.45724.3.1.3 (PERM.3)
/// Allows onboarding with credential reuse.
pub(crate) const OID_PERMIT_ONBOARD_REUSECRED: &[u8] = &[
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x1C, 0x03, 0x01, 0x03,
];

/// OIDPermitOnboardFdoDisable = 1.3.6.1.4.1.45724.3.1.4 (PERM.4)
/// Allows FDO disable during onboarding.
pub(crate) const OID_PERMIT_ONBOARD_FDODISABLE: &[u8] = &[
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x1C, 0x03, 0x01, 0x04,
];

/// OIDPermitProvision = 1.3.6.1.4.1.45724.3.1.7 (PERM.7)
/// Allows signing BMO provisioning payloads.
pub(crate) const OID_PERMIT_PROVISION: &[u8] = &[
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x1C, 0x03, 0x01, 0x07,
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
    /// PERM.1 — OIDPermitRedirect (required for TO0/TO1)
    pub has_permit_redirect: bool,
    /// PERM.7 — OIDPermitProvision (required for BMO signing)
    pub has_permit_provision: bool,
    /// Whether this certificate has any fdo-ekt-permit-onboard-* permission
    /// (PERM.2 new-cred, PERM.3 reuse-cred, PERM.4 fdo-disable)
    pub has_permit_onboard: bool,
    /// PERM.3 — OIDPermitOnboardReuseCred (credential reuse specifically)
    pub has_permit_reuse_cred: bool,
}

/// Result of delegate chain validation.
///
/// Permissions are the **intersection** of all certificates in the chain.
/// A leaf cannot claim a permission that any certificate above it lacks.
pub struct DelegateChainResult {
    /// The leaf certificate's P-256 public key point (for verifying ProveOVHdr).
    pub leaf_key_point: Vec<u8>,
    /// PERM.1 — redirect permission (all certs in chain must carry it).
    pub has_redirect: bool,
    /// PERM.7 — provision permission (all certs in chain must carry it).
    pub has_provision: bool,
    /// Any onboard permission (PERM.2/3/4) — all certs must carry at least one.
    pub has_onboard: bool,
    /// PERM.3 — credential reuse (all certs must carry it).
    pub has_reuse_cred: bool,
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

    // Step 3: compute permission intersection across all certs in the chain.
    // A leaf cannot claim a permission that any certificate above it lacks.
    let mut chain_redirect = true;
    let mut chain_provision = true;
    let mut chain_onboard = true;
    let mut chain_reuse_cred = true;
    for cert in &parsed {
        chain_redirect &= cert.has_permit_redirect;
        chain_provision &= cert.has_permit_provision;
        chain_onboard &= cert.has_permit_onboard;
        chain_reuse_cred &= cert.has_permit_reuse_cred;
    }

    info!("delegate: chain verified ({} cert(s)), intersection: redirect={}, provision={}, onboard={}, reuse_cred={}",
        parsed.len(), chain_redirect, chain_provision, chain_onboard, chain_reuse_cred);

    Some(DelegateChainResult {
        leaf_key_point: parsed[0].public_key_point.clone(),
        has_redirect: chain_redirect,
        has_provision: chain_provision,
        has_onboard: chain_onboard,
        has_reuse_cred: chain_reuse_cred,
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
    let mut eku = EkuFlags { redirect: false, onboard: false, reuse_cred: false, provision: false };

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
                        eku = check_eku_oids(eku_wrapper);
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
        has_permit_redirect: eku.redirect,
        has_permit_provision: eku.provision,
        has_permit_onboard: eku.onboard,
        has_permit_reuse_cred: eku.reuse_cred,
    })
}

/// Parsed EKU permission flags from a single certificate.
struct EkuFlags {
    redirect: bool,
    onboard: bool,
    reuse_cred: bool,
    provision: bool,
}

/// Check an ExtendedKeyUsage SEQUENCE for FDO permission OIDs.
fn check_eku_oids(data: &[u8]) -> EkuFlags {
    let mut flags = EkuFlags {
        redirect: false, onboard: false, reuse_cred: false, provision: false,
    };
    let mut pos = 0usize;
    // SEQUENCE of OIDs
    let (_, seq_end) = match read_sequence_header(data, &mut pos) {
        Some(v) => v,
        None => return flags,
    };
    while pos < seq_end {
        if let Some(oid) = read_oid(data, &mut pos) {
            if oid == OID_PERMIT_PROVISION {
                flags.provision = true;
                debug!("delegate: found OIDPermitProvision (PERM.7)");
            } else if oid == OID_PERMIT_REDIRECT {
                flags.redirect = true;
                debug!("delegate: found OIDPermitRedirect (PERM.1)");
            } else if oid == OID_PERMIT_ONBOARD_NEWCRED {
                flags.onboard = true;
                debug!("delegate: found OIDPermitOnboardNewCred (PERM.2)");
            } else if oid == OID_PERMIT_ONBOARD_REUSECRED {
                flags.reuse_cred = true;
                flags.onboard = true;
                debug!("delegate: found OIDPermitOnboardReuseCred (PERM.3)");
            } else if oid == OID_PERMIT_ONBOARD_FDODISABLE {
                flags.onboard = true;
                debug!("delegate: found OIDPermitOnboardFdoDisable (PERM.4)");
            }
        }
    }
    flags
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

/// Build a minimal self-signed X.509 certificate for testing.
///
/// The cert is signed by `issuer_sk` and contains the public key from `subject_pk_point`.
/// `eku_oids` is a list of OID raw bytes to place in the ExtendedKeyUsage extension.
#[cfg(test)]
pub(crate) fn build_test_cert(
    issuer_sk: &p256::ecdsa::SigningKey,
    subject_pk_point: &[u8],
    eku_oids: &[&[u8]],
) -> Vec<u8> {
    use p256::ecdsa::{signature::Signer, Signature};

    // Build TBS certificate
    let tbs = build_test_tbs(subject_pk_point, eku_oids);

    // Sign TBS with issuer key
    let sig: Signature = issuer_sk.sign(&tbs);
    let sig_der = ecdsa_rs_to_der(sig.to_bytes().as_slice());

    // Certificate = SEQUENCE { tbs, signatureAlgorithm, signatureValue }
    let mut cert = Vec::new();

    // signatureAlgorithm = ecdsaWithSHA256 (1.2.840.10045.4.3.2)
    let sig_alg = &[
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x04, 0x03, 0x02,
    ];

    // signatureValue BIT STRING
    let mut sig_bs = Vec::new();
    sig_bs.push(0x03); // BIT STRING tag
    der_write_length(&mut sig_bs, sig_der.len() + 1);
    sig_bs.push(0x00); // unused bits
    sig_bs.extend_from_slice(&sig_der);

    let inner_len = tbs.len() + sig_alg.len() + sig_bs.len();
    cert.push(0x30); // SEQUENCE
    der_write_length(&mut cert, inner_len);
    cert.extend_from_slice(&tbs);
    cert.extend_from_slice(sig_alg);
    cert.extend_from_slice(&sig_bs);

    cert
}

/// Build a minimal TBS certificate for testing.
#[cfg(test)]
fn build_test_tbs(subject_pk_point: &[u8], eku_oids: &[&[u8]]) -> Vec<u8> {
    let mut tbs_inner = Vec::new();

    // version [0] EXPLICIT INTEGER 2 (v3)
    tbs_inner.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x02]);

    // serialNumber INTEGER 1
    tbs_inner.extend_from_slice(&[0x02, 0x01, 0x01]);

    // signature algorithm (ecdsaWithSHA256)
    tbs_inner.extend_from_slice(&[
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x04, 0x03, 0x02,
    ]);

    // issuer: CN=test
    let issuer_name = &[
        0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03,
        0x55, 0x04, 0x03, 0x0c, 0x04, 0x74, 0x65, 0x73, 0x74,
    ];
    tbs_inner.extend_from_slice(issuer_name);

    // validity: not before/after (generous)
    let validity = &[
        0x30, 0x1e,
        0x17, 0x0d, 0x32, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
        0x17, 0x0d, 0x33, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
    ];
    tbs_inner.extend_from_slice(validity);

    // subject: CN=test
    tbs_inner.extend_from_slice(issuer_name);

    // subjectPublicKeyInfo for P-256
    let mut spki = Vec::new();
    // algorithm: ecPublicKey + prime256v1
    let spki_alg = &[
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x03, 0x01, 0x07,
    ];
    spki.extend_from_slice(spki_alg);
    // BIT STRING containing the uncompressed point
    spki.push(0x03); // BIT STRING
    der_write_length(&mut spki, subject_pk_point.len() + 1);
    spki.push(0x00); // unused bits
    spki.extend_from_slice(subject_pk_point);

    let mut spki_seq = Vec::new();
    spki_seq.push(0x30);
    der_write_length(&mut spki_seq, spki.len());
    spki_seq.extend_from_slice(&spki);
    tbs_inner.extend_from_slice(&spki_seq);

    // Extensions [3] EXPLICIT { SEQUENCE { ... } }
    if !eku_oids.is_empty() {
        let mut eku_inner = Vec::new();
        for oid in eku_oids {
            eku_inner.push(0x06); // OID tag
            der_write_length(&mut eku_inner, oid.len());
            eku_inner.extend_from_slice(oid);
        }

        let mut eku_seq = Vec::new();
        eku_seq.push(0x30); // SEQUENCE
        der_write_length(&mut eku_seq, eku_inner.len());
        eku_seq.extend_from_slice(&eku_inner);

        let mut eku_os = Vec::new();
        eku_os.push(0x04); // OCTET STRING
        der_write_length(&mut eku_os, eku_seq.len());
        eku_os.extend_from_slice(&eku_seq);

        let mut ext_entry = Vec::new();
        ext_entry.push(0x30); // SEQUENCE (Extension)
        // extnID = 2.5.29.37 (EKU)
        let eku_oid_tlv = &[0x06, 0x03, 0x55, 0x1d, 0x25];
        der_write_length(&mut ext_entry, eku_oid_tlv.len() + eku_os.len());
        ext_entry.extend_from_slice(eku_oid_tlv);
        ext_entry.extend_from_slice(&eku_os);

        let mut ext_seq = Vec::new();
        ext_seq.push(0x30); // SEQUENCE of extensions
        der_write_length(&mut ext_seq, ext_entry.len());
        ext_seq.extend_from_slice(&ext_entry);

        // [3] EXPLICIT
        tbs_inner.push(0xa3);
        der_write_length(&mut tbs_inner, ext_seq.len());
        tbs_inner.extend_from_slice(&ext_seq);
    }

    // Wrap in SEQUENCE
    let mut tbs = Vec::new();
    tbs.push(0x30);
    der_write_length(&mut tbs, tbs_inner.len());
    tbs.extend_from_slice(&tbs_inner);
    tbs
}

/// Write a DER length.
#[cfg(test)]
fn der_write_length(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

/// Convert fixed-width r||s (64 bytes) to DER SEQUENCE { INTEGER r, INTEGER s }.
#[cfg(test)]
fn ecdsa_rs_to_der(rs: &[u8]) -> Vec<u8> {
    fn der_integer(val: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0x02); // INTEGER
        // Trim leading zeros but keep at least one byte
        let trimmed = match val.iter().position(|&b| b != 0) {
            Some(i) => &val[i..],
            None => &[0u8],
        };
        // Add leading zero if high bit set (to keep positive)
        if trimmed[0] & 0x80 != 0 {
            out.push((trimmed.len() + 1) as u8);
            out.push(0x00);
        } else {
            out.push(trimmed.len() as u8);
        }
        out.extend_from_slice(trimmed);
        out
    }

    let r = der_integer(&rs[..32]);
    let s = der_integer(&rs[32..]);
    let mut seq = Vec::new();
    seq.push(0x30); // SEQUENCE
    seq.push((r.len() + s.len()) as u8);
    seq.extend_from_slice(&r);
    seq.extend_from_slice(&s);
    seq
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

// =========================================================================
// Unit tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose::{gen_test_keypair, gen_test_keypair_b};

    /// Third deterministic key pair for 3-cert chain tests.
    fn gen_test_keypair_c() -> (p256::ecdsa::SigningKey, Vec<u8>) {
        use p256::ecdsa::SigningKey;
        use p256::EncodedPoint;
        let secret = p256::SecretKey::from_bytes(
            &[
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
                0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
                0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            ].into(),
        ).unwrap();
        let sk = SigningKey::from(secret.clone());
        let pk = secret.public_key();
        let point = EncodedPoint::from(pk);
        (sk, point.as_bytes().to_vec())
    }

    // ===== Single-cert chain =====

    #[test]
    fn test_single_cert_chain_with_provision() {
        let (owner_sk, owner_point) = gen_test_keypair();
        let (_delegate_sk, delegate_point) = gen_test_keypair_b();

        let cert_der = build_test_cert(
            &owner_sk, &delegate_point,
            &[OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED],
        );

        let certs = [cert_der.as_slice()];
        let result = verify_delegate_chain(&certs, &owner_point)
            .expect("1-cert chain should verify");

        assert!(result.has_provision, "must have provision");
        assert!(result.has_onboard, "must have onboard");
        assert_eq!(result.leaf_key_point, delegate_point);
    }

    #[test]
    fn test_single_cert_chain_no_provision() {
        let (owner_sk, owner_point) = gen_test_keypair();
        let (_delegate_sk, delegate_point) = gen_test_keypair_b();

        let cert_der = build_test_cert(
            &owner_sk, &delegate_point,
            &[OID_PERMIT_ONBOARD_NEWCRED],
        );

        let certs = [cert_der.as_slice()];
        let result = verify_delegate_chain(&certs, &owner_point)
            .expect("chain should verify (permissions checked by caller)");

        assert!(!result.has_provision, "must NOT have provision");
        assert!(result.has_onboard, "must have onboard");
    }

    // ===== Negative: wrong signer =====

    #[test]
    fn test_chain_wrong_signer_rejected() {
        let (_owner_sk, owner_point) = gen_test_keypair();
        let (attacker_sk, _) = gen_test_keypair_b();

        let cert_der = build_test_cert(
            &attacker_sk, &owner_point, &[OID_PERMIT_PROVISION],
        );

        let certs = [cert_der.as_slice()];
        assert!(verify_delegate_chain(&certs, &owner_point).is_none(),
            "cert signed by unrelated key must be rejected");
    }

    // ===== Self-signed delegate rejected (Go: TestSelfSignedDelegateRejected) =====

    #[test]
    fn test_self_signed_delegate_rejected() {
        let (_owner_sk, owner_point) = gen_test_keypair();
        let (attacker_sk, attacker_point) = gen_test_keypair_b();

        // Attacker creates a cert signing their own key — self-signed root
        let cert_der = build_test_cert(
            &attacker_sk, &attacker_point,
            &[OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED, OID_PERMIT_REDIRECT],
        );

        let certs = [cert_der.as_slice()];
        assert!(verify_delegate_chain(&certs, &owner_point).is_none(),
            "self-signed delegate must be rejected when verified against legitimate owner");
    }

    // ===== Empty chain =====

    #[test]
    fn test_empty_chain_rejected() {
        let (_, owner_point) = gen_test_keypair();
        let certs: [&[u8]; 0] = [];
        assert!(verify_delegate_chain(&certs, &owner_point).is_none(),
            "empty chain must be rejected");
    }

    // ===== 2-cert chain =====

    #[test]
    fn test_two_cert_chain() {
        let (owner_sk, owner_point) = gen_test_keypair();
        let (intermediate_sk, intermediate_point) = gen_test_keypair_b();
        let (_leaf_sk, leaf_point) = gen_test_keypair_c();

        let root_cert = build_test_cert(
            &owner_sk, &intermediate_point,
            &[OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED],
        );
        let leaf_cert = build_test_cert(
            &intermediate_sk, &leaf_point,
            &[OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED],
        );

        let certs = [leaf_cert.as_slice(), root_cert.as_slice()];
        let result = verify_delegate_chain(&certs, &owner_point)
            .expect("2-cert chain should verify");

        assert!(result.has_provision);
        assert!(result.has_onboard);
        assert_eq!(result.leaf_key_point, leaf_point);
    }

    #[test]
    fn test_two_cert_chain_broken_middle() {
        let (owner_sk, owner_point) = gen_test_keypair();
        let (_intermediate_sk, intermediate_point) = gen_test_keypair_b();
        let (attacker_sk, _) = gen_test_keypair_c();

        let root_cert = build_test_cert(
            &owner_sk, &intermediate_point, &[OID_PERMIT_PROVISION],
        );
        // Leaf signed by attacker, not intermediate
        let leaf_cert = build_test_cert(
            &attacker_sk, &intermediate_point, &[OID_PERMIT_PROVISION],
        );

        let certs = [leaf_cert.as_slice(), root_cert.as_slice()];
        assert!(verify_delegate_chain(&certs, &owner_point).is_none(),
            "broken chain must be rejected");
    }

    // ===== 3-cert chain =====

    #[test]
    fn test_three_cert_chain_valid() {
        let (owner_sk, owner_point) = gen_test_keypair();
        let (root_sk, root_point) = gen_test_keypair_b();
        let (intermediate_sk, intermediate_point) = gen_test_keypair_c();
        // Fourth key for leaf
        let leaf_secret = p256::SecretKey::from_bytes(
            &[0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
              0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
              0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
              0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01].into(),
        ).unwrap();
        let leaf_point = {
            let pk = leaf_secret.public_key();
            p256::EncodedPoint::from(pk).as_bytes().to_vec()
        };

        let root_cert = build_test_cert(
            &owner_sk, &root_point,
            &[OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED, OID_PERMIT_REDIRECT],
        );
        let inter_cert = build_test_cert(
            &root_sk, &intermediate_point,
            &[OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED, OID_PERMIT_REDIRECT],
        );
        let leaf_cert = build_test_cert(
            &intermediate_sk, &leaf_point,
            &[OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED, OID_PERMIT_REDIRECT],
        );

        // Leaf-first: [leaf, intermediate, root]
        let certs = [leaf_cert.as_slice(), inter_cert.as_slice(), root_cert.as_slice()];
        let result = verify_delegate_chain(&certs, &owner_point)
            .expect("3-cert chain should verify");

        assert!(result.has_provision);
        assert!(result.has_onboard);
        assert!(result.has_redirect);
        assert_eq!(result.leaf_key_point, leaf_point);
    }

    // ===== Permission inheritance (Go: TestDelegateChainIntermediateMissingPermission) =====

    #[test]
    fn test_intermediate_missing_permission() {
        let (owner_sk, owner_point) = gen_test_keypair();
        let (intermediate_sk, intermediate_point) = gen_test_keypair_b();
        let (_leaf_sk, leaf_point) = gen_test_keypair_c();

        // Root has onboard + redirect + provision
        let root_cert = build_test_cert(
            &owner_sk, &intermediate_point,
            &[OID_PERMIT_ONBOARD_NEWCRED, OID_PERMIT_REDIRECT, OID_PERMIT_PROVISION],
        );
        // Intermediate has ONLY redirect (no onboard, no provision)
        let leaf_cert = build_test_cert(
            &intermediate_sk, &leaf_point,
            &[OID_PERMIT_ONBOARD_NEWCRED, OID_PERMIT_REDIRECT, OID_PERMIT_PROVISION],
        );

        let certs = [leaf_cert.as_slice(), root_cert.as_slice()];
        let result = verify_delegate_chain(&certs, &owner_point)
            .expect("chain verifies (permissions are intersected, not rejected)");

        // Leaf claims onboard+provision but root has them too, so intersection passes.
        // Now test the ACTUAL intermediate-missing case:
        // Root: redirect only. Leaf: onboard + redirect.
        let root_redirect_only = build_test_cert(
            &owner_sk, &intermediate_point,
            &[OID_PERMIT_REDIRECT],
        );
        let leaf_onboard_redirect = build_test_cert(
            &intermediate_sk, &leaf_point,
            &[OID_PERMIT_ONBOARD_NEWCRED, OID_PERMIT_REDIRECT],
        );

        let certs2 = [leaf_onboard_redirect.as_slice(), root_redirect_only.as_slice()];
        let result2 = verify_delegate_chain(&certs2, &owner_point)
            .expect("chain verifies structurally");

        // Intersection: redirect passes (both have it), onboard fails (root lacks it)
        assert!(result2.has_redirect, "redirect must pass (both have it)");
        assert!(!result2.has_onboard, "onboard must fail (root lacks it)");
        assert!(!result2.has_provision, "provision must fail (neither has it)");
    }

    // ===== Root missing permission (Go: TestDelegateChainRootMissingPermission) =====

    #[test]
    fn test_root_missing_permission() {
        let (owner_sk, owner_point) = gen_test_keypair();
        let (root_sk, root_point) = gen_test_keypair_b();
        let (intermediate_sk, intermediate_point) = gen_test_keypair_c();
        let leaf_secret = p256::SecretKey::from_bytes(
            &[0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
              0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
              0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
              0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01].into(),
        ).unwrap();
        let leaf_point = {
            let pk = leaf_secret.public_key();
            p256::EncodedPoint::from(pk).as_bytes().to_vec()
        };

        // Root: redirect only (no onboard, no provision)
        let root_cert = build_test_cert(
            &owner_sk, &root_point, &[OID_PERMIT_REDIRECT],
        );
        // Intermediate: onboard + redirect
        let inter_cert = build_test_cert(
            &root_sk, &intermediate_point,
            &[OID_PERMIT_ONBOARD_NEWCRED, OID_PERMIT_REDIRECT],
        );
        // Leaf: onboard + redirect + provision
        let leaf_cert = build_test_cert(
            &intermediate_sk, &leaf_point,
            &[OID_PERMIT_ONBOARD_NEWCRED, OID_PERMIT_REDIRECT, OID_PERMIT_PROVISION],
        );

        let certs = [leaf_cert.as_slice(), inter_cert.as_slice(), root_cert.as_slice()];
        let result = verify_delegate_chain(&certs, &owner_point)
            .expect("chain verifies structurally");

        // Intersection across all 3:
        assert!(result.has_redirect, "redirect: all 3 have it");
        assert!(!result.has_onboard, "onboard: root lacks it → false");
        assert!(!result.has_provision, "provision: root+intermediate lack it → false");
    }

    // ===== Redirect-only cannot onboard (Go: TestDelegateCannotOnboardWithRedirectOnly) =====

    #[test]
    fn test_redirect_only_cannot_onboard() {
        let (owner_sk, owner_point) = gen_test_keypair();
        let (_delegate_sk, delegate_point) = gen_test_keypair_b();

        let cert_der = build_test_cert(
            &owner_sk, &delegate_point, &[OID_PERMIT_REDIRECT],
        );

        let certs = [cert_der.as_slice()];
        let result = verify_delegate_chain(&certs, &owner_point).unwrap();

        assert!(result.has_redirect, "redirect must be true");
        assert!(!result.has_onboard, "onboard must be false");
        assert!(!result.has_provision, "provision must be false");
    }

    // ===== Onboard-only cannot redirect (Go: TestDelegateCannotRedirectWithOnboardOnly) =====

    #[test]
    fn test_onboard_only_cannot_redirect() {
        let (owner_sk, owner_point) = gen_test_keypair();
        let (_delegate_sk, delegate_point) = gen_test_keypair_b();

        let cert_der = build_test_cert(
            &owner_sk, &delegate_point, &[OID_PERMIT_ONBOARD_NEWCRED],
        );

        let certs = [cert_der.as_slice()];
        let result = verify_delegate_chain(&certs, &owner_point).unwrap();

        assert!(!result.has_redirect, "redirect must be false");
        assert!(result.has_onboard, "onboard must be true");
    }

    // ===== Reuse-credential vs new-credential (Go: TestDelegateCannotReuseCred/WithReuseCred) =====

    #[test]
    fn test_new_cred_cannot_reuse() {
        let (owner_sk, owner_point) = gen_test_keypair();
        let (_, delegate_point) = gen_test_keypair_b();

        // PERM.2 only (onboard-new-cred)
        let cert_der = build_test_cert(
            &owner_sk, &delegate_point, &[OID_PERMIT_ONBOARD_NEWCRED],
        );

        let certs = [cert_der.as_slice()];
        let result = verify_delegate_chain(&certs, &owner_point).unwrap();

        assert!(result.has_onboard, "onboard true (new-cred implies onboard)");
        assert!(!result.has_reuse_cred, "reuse_cred must be false");
    }

    #[test]
    fn test_reuse_cred_implies_onboard() {
        let (owner_sk, owner_point) = gen_test_keypair();
        let (_, delegate_point) = gen_test_keypair_b();

        // PERM.3 (onboard-reuse-cred)
        let cert_der = build_test_cert(
            &owner_sk, &delegate_point, &[OID_PERMIT_ONBOARD_REUSECRED],
        );

        let certs = [cert_der.as_slice()];
        let result = verify_delegate_chain(&certs, &owner_point).unwrap();

        assert!(result.has_onboard, "onboard true (reuse-cred implies onboard)");
        assert!(result.has_reuse_cred, "reuse_cred must be true");
    }

    // ===== All permissions (Go: TestDelegateWithAllPermissions) =====

    #[test]
    fn test_all_permissions() {
        let (owner_sk, owner_point) = gen_test_keypair();
        let (_, delegate_point) = gen_test_keypair_b();

        let cert_der = build_test_cert(
            &owner_sk, &delegate_point,
            &[OID_PERMIT_REDIRECT, OID_PERMIT_ONBOARD_NEWCRED,
              OID_PERMIT_ONBOARD_REUSECRED, OID_PERMIT_PROVISION],
        );

        let certs = [cert_der.as_slice()];
        let result = verify_delegate_chain(&certs, &owner_point).unwrap();

        assert!(result.has_redirect);
        assert!(result.has_onboard);
        assert!(result.has_reuse_cred);
        assert!(result.has_provision);
    }

    // ===== DER parsing =====

    #[test]
    fn test_parse_x509_cert_extracts_key() {
        let (owner_sk, _) = gen_test_keypair();
        let (_, delegate_point) = gen_test_keypair_b();

        let cert_der = build_test_cert(&owner_sk, &delegate_point, &[]);
        let parsed = parse_x509_cert(&cert_der)
            .expect("should parse generated cert");

        assert_eq!(parsed.public_key_point, delegate_point);
        assert_eq!(parsed.signature_rs.len(), 64);
    }

    #[test]
    fn test_parse_x509_cert_eku_flags() {
        let (sk, _) = gen_test_keypair();
        let (_, point) = gen_test_keypair_b();

        // Provision only
        let cert = build_test_cert(&sk, &point, &[OID_PERMIT_PROVISION]);
        let parsed = parse_x509_cert(&cert).unwrap();
        assert!(parsed.has_permit_provision);
        assert!(!parsed.has_permit_onboard);
        assert!(!parsed.has_permit_redirect);

        // Onboard-reuse only
        let cert2 = build_test_cert(&sk, &point, &[OID_PERMIT_ONBOARD_REUSECRED]);
        let parsed2 = parse_x509_cert(&cert2).unwrap();
        assert!(!parsed2.has_permit_provision);
        assert!(parsed2.has_permit_onboard);
        assert!(parsed2.has_permit_reuse_cred);
        assert!(!parsed2.has_permit_redirect);

        // Redirect only
        let cert3 = build_test_cert(&sk, &point, &[OID_PERMIT_REDIRECT]);
        let parsed3 = parse_x509_cert(&cert3).unwrap();
        assert!(!parsed3.has_permit_provision);
        assert!(!parsed3.has_permit_onboard);
        assert!(parsed3.has_permit_redirect);

        // All permissions
        let cert4 = build_test_cert(&sk, &point,
            &[OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED,
              OID_PERMIT_ONBOARD_REUSECRED, OID_PERMIT_ONBOARD_FDODISABLE,
              OID_PERMIT_REDIRECT]);
        let parsed4 = parse_x509_cert(&cert4).unwrap();
        assert!(parsed4.has_permit_provision);
        assert!(parsed4.has_permit_onboard);
        assert!(parsed4.has_permit_reuse_cred);
        assert!(parsed4.has_permit_redirect);
    }

    #[test]
    fn test_parse_x509_cert_garbage() {
        let result = parse_x509_cert(&[0x00, 0x01, 0x02]);
        assert!(result.is_none(), "garbage input must fail");
    }

    #[test]
    fn test_ecdsa_der_to_rs() {
        let der = &[
            0x30, 0x06,
            0x02, 0x01, 0x01, // INTEGER 1
            0x02, 0x01, 0x02, // INTEGER 2
        ];
        let rs = ecdsa_der_to_rs(der).expect("should parse");
        assert_eq!(rs.len(), 64);
        assert_eq!(rs[31], 1);
        assert_eq!(rs[63], 2);
    }
}
