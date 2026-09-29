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

/// BasicConstraints extension OID = 2.5.29.19
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];

/// id-ecPublicKey = 1.2.840.10045.2.1
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

/// prime256v1 (secp256r1 / P-256) = 1.2.840.10045.3.1.7
const OID_PRIME256V1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// ecdsa-with-SHA256 = 1.2.840.10045.4.3.2
const OID_ECDSA_WITH_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

/// Maximum number of certificates accepted in a delegate chain.
///
/// A bound is required: the chain arrives in a COSE *unprotected* header, so
/// it is attacker-controlled input parsed before any signature over it has
/// been checked. Without a cap, the peer chooses how much work and how much
/// allocation the device performs.
pub const MAX_DELEGATE_CHAIN_LEN: usize = 8;

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
    /// BasicConstraints cA. Required on any certificate used as an issuer.
    pub is_ca: bool,
    /// BasicConstraints pathLenConstraint, if present.
    pub path_len: Option<usize>,
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
/// 4. Require BasicConstraints cA on every certificate used as an issuer,
///    and honour pathLenConstraint where present
/// 5. Extract leaf key and permissions
///
/// **Not checked: certificate validity dates.** `notBefore`/`notAfter` are
/// deliberately not enforced — see the "Clock policy" item in TODO.md. UEFI
/// `GetTime()` is not a trustworthy source on the platforms this runs on, and
/// a validity check driven by an untrusted clock is worse than none: it turns
/// a wrong RTC into either a permissive accept or an unbootable device.
/// Delegate expiry therefore cannot be relied upon for revocation today.
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
    if cert_ders.len() > MAX_DELEGATE_CHAIN_LEN {
        error!("delegate: chain of {} certificates exceeds the maximum of {}",
            cert_ders.len(), MAX_DELEGATE_CHAIN_LEN);
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
            let issuer = &parsed[i + 1];

            // A certificate that issues another certificate MUST be a CA.
            // Without this, any delegate — including a leaf whose only job is
            // to sign BMO artifacts — can mint further certificates and hand
            // its own permissions to anyone, indefinitely.
            if !issuer.is_ca {
                error!("delegate: certificate {} issues certificate {} but is not a CA", i + 1, i);
                error!("delegate: BasicConstraints cA is required on every issuing certificate");
                return None;
            }

            // pathLenConstraint on the issuer bounds how many intermediates
            // may appear below it. The issuer is index `i + 1`, so indices
            // `0..=i` sit beneath it — that is `i + 1` certificates, of which
            // index 0 is the end-entity leaf, leaving `i` intermediates.
            if let Some(max_intermediates) = issuer.path_len {
                let intermediates_below = i;
                if intermediates_below > max_intermediates {
                    error!("delegate: certificate {} has pathLenConstraint {} but {} intermediate(s) follow it",
                        i + 1, max_intermediates, intermediates_below);
                    return None;
                }
            }

            if !cose::verify_es256(parsed[i].tbs_raw, &parsed[i].signature_rs, &issuer.public_key_point) {
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

/// Verify that an X5CHAIN is internally consistent and return the leaf key.
///
/// `cert_ders` is leaf-first. Each certificate must be signed by the next one
/// up; the topmost certificate has no issuer present in the chain, so it can
/// only be checked by whatever anchors the chain externally (for an Ownership
/// Voucher, that is the OVEntry signature over the key itself).
///
/// This exists because an X5CHAIN carries *certificates*, and taking the leaf
/// key while ignoring the rest of the chain means the chain structure is
/// decorative — a caller cannot tell a real chain from an arbitrary pile of
/// DER. Same date caveat as [`verify_delegate_chain`]: validity periods are
/// not enforced.
pub(crate) fn verify_x5chain_internal(cert_ders: &[&[u8]]) -> Option<Vec<u8>> {
    if cert_ders.is_empty() {
        error!("x5chain: empty certificate chain");
        return None;
    }
    if cert_ders.len() > MAX_DELEGATE_CHAIN_LEN {
        error!("x5chain: chain of {} certificates exceeds the maximum of {}",
            cert_ders.len(), MAX_DELEGATE_CHAIN_LEN);
        return None;
    }

    let mut parsed: Vec<ParsedCert> = Vec::with_capacity(cert_ders.len());
    for (i, der) in cert_ders.iter().enumerate() {
        match parse_x509_cert(der) {
            Some(c) => parsed.push(c),
            None => {
                error!("x5chain: failed to parse certificate {} ({} bytes)", i, der.len());
                return None;
            }
        }
    }

    for i in 0..parsed.len() - 1 {
        let issuer = &parsed[i + 1];
        if !issuer.is_ca {
            error!("x5chain: certificate {} issues certificate {} but is not a CA", i + 1, i);
            return None;
        }
        if let Some(max_intermediates) = issuer.path_len {
            if i > max_intermediates {
                error!("x5chain: certificate {} pathLenConstraint {} exceeded", i + 1, max_intermediates);
                return None;
            }
        }
        if !cose::verify_es256(parsed[i].tbs_raw, &parsed[i].signature_rs, &issuer.public_key_point) {
            error!("x5chain: certificate {} NOT signed by certificate {}", i, i + 1);
            return None;
        }
    }

    debug!("x5chain: {} certificate(s), internal linkage verified", parsed.len());
    Some(parsed[0].public_key_point.clone())
}

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

    // signatureAlgorithm (AlgorithmIdentifier SEQUENCE). We verify every
    // certificate as ES256, so the certificate must actually say ES256 —
    // otherwise the declared algorithm and the one we apply disagree.
    let outer_sig_alg = read_alg_identifier_oid(der, &mut pos)?;
    if outer_sig_alg != OID_ECDSA_WITH_SHA256 {
        error!("x509: signatureAlgorithm is not ecdsa-with-SHA256; only ES256 is implemented");
        return None;
    }

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
    // signature (AlgId SEQUENCE). RFC 5280 4.1.1.2: this MUST equal the outer
    // signatureAlgorithm. They are separately encoded, and only the inner one
    // is covered by the signature, so a mismatch means someone edited the
    // unsigned copy.
    let inner_sig_alg = read_alg_identifier_oid(der, &mut tbs_pos)?;
    if inner_sig_alg != outer_sig_alg {
        error!("x509: tbsCertificate.signature does not match signatureAlgorithm");
        return None;
    }
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
    let public_key_point = parse_spki_p256_point(spki_data)?;
    tbs_pos = spki_end;

    // Extensions — look for [3] (tag 0xA3)
    let mut eku = EkuFlags { redirect: false, onboard: false, reuse_cred: false, provision: false };
    let mut is_ca = false;
    let mut path_len: Option<usize> = None;

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
                    let is_eku = oid == OID_EXT_KEY_USAGE;
                    let is_bc = oid == OID_BASIC_CONSTRAINTS;
                    if is_eku || is_bc {
                        // Skip optional critical BOOLEAN
                        if der.get(ext_pos) == Some(&0x01) {
                            skip_der_element(der, &mut ext_pos)?;
                        }
                        // OCTET STRING wrapping the extension value
                        let wrapper = read_octet_string(der, &mut ext_pos)?;
                        if is_eku {
                            eku = check_eku_oids(wrapper);
                        } else {
                            let (ca, plen) = parse_basic_constraints(wrapper);
                            is_ca = ca;
                            path_len = plen;
                        }
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
        is_ca,
        path_len,
    })
}

/// Read an `AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY }`
/// and return the algorithm OID bytes. Advances `pos` past the whole SEQUENCE.
fn read_alg_identifier_oid<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let (_, seq_end) = read_sequence_header(data, pos)?;
    let oid = read_oid(data, pos)?;
    *pos = seq_end;
    Some(oid)
}

/// Parse a `BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE,
/// pathLenConstraint INTEGER OPTIONAL }` extension value.
///
/// Returns `(is_ca, path_len)`. Both DER defaults mean absence is `false`/`None`,
/// so an unparseable or empty extension yields "not a CA" — fail closed.
fn parse_basic_constraints(data: &[u8]) -> (bool, Option<usize>) {
    let mut pos = 0usize;
    let (_, seq_end) = match read_sequence_header(data, &mut pos) {
        Some(v) => v,
        None => return (false, None),
    };

    let mut is_ca = false;
    let mut path_len = None;

    // cA BOOLEAN DEFAULT FALSE — present only when TRUE in strict DER, but
    // accept an explicit FALSE too.
    if pos < seq_end && data.get(pos) == Some(&0x01) {
        pos += 1;
        let len = match read_der_length(data, &mut pos) {
            Some(l) => l,
            None => return (false, None),
        };
        if len != 1 {
            return (false, None);
        }
        is_ca = data.get(pos).copied().unwrap_or(0) != 0;
        pos += 1;
    }

    // pathLenConstraint INTEGER OPTIONAL
    if pos < seq_end && data.get(pos) == Some(&0x02) {
        if let Some(int_bytes) = read_der_integer(data, &mut pos) {
            // Only small, non-negative path lengths are meaningful here.
            if int_bytes.len() <= 2 && int_bytes.first().map_or(false, |b| b & 0x80 == 0) {
                let mut v = 0usize;
                for b in int_bytes {
                    v = (v << 8) | (*b as usize);
                }
                path_len = Some(v);
            }
        }
    }

    (is_ca, path_len)
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
        // `read_oid` leaves `pos` untouched when the element is not an OID,
        // so the skip below is what guarantees forward progress. Without it a
        // single non-OID element in this SEQUENCE spins forever — and this
        // data arrives in a COSE *unprotected* header, i.e. unauthenticated.
        let Some(oid) = read_oid(data, &mut pos) else {
            if skip_der_element(data, &mut pos).is_none() {
                error!("delegate: malformed element in ExtendedKeyUsage — stopping");
                break;
            }
            continue;
        };
        {
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

/// Parse a `SubjectPublicKeyInfo` and return the uncompressed P-256 point.
///
/// ```text
/// SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm         AlgorithmIdentifier ::= SEQUENCE {
///         algorithm     OBJECT IDENTIFIER,   -- id-ecPublicKey
///         parameters    OBJECT IDENTIFIER }, -- prime256v1
///     subjectPublicKey  BIT STRING }
/// ```
///
/// This walks the structure and checks both OIDs. It deliberately does **not**
/// search for a byte pattern: a scan for `03 42 00 04` will happily match
/// inside a subject name, an extension, or a signature, and when the input is
/// a whole certificate rather than just its SPKI the first such match wins
/// over the real key.
pub(crate) fn parse_spki_p256_point(spki: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0usize;
    let (_, spki_end) = read_sequence_header(spki, &mut pos)?;

    // algorithm AlgorithmIdentifier
    let (_, alg_end) = read_sequence_header(spki, &mut pos)?;
    let alg_oid = read_oid(spki, &mut pos)?;
    if alg_oid != OID_EC_PUBLIC_KEY {
        error!("x509: SPKI algorithm is not id-ecPublicKey");
        return None;
    }
    let curve_oid = read_oid(spki, &mut pos)?;
    if curve_oid != OID_PRIME256V1 {
        error!("x509: SPKI curve is not prime256v1 (P-256); only P-256 is implemented");
        return None;
    }
    if pos > alg_end {
        return None;
    }
    pos = alg_end;

    // subjectPublicKey BIT STRING
    let bits = read_bit_string(spki, &mut pos)?;
    if pos > spki_end {
        return None;
    }
    if bits.len() != 65 || bits[0] != 0x04 {
        error!("x509: SPKI key is not a 65-byte uncompressed P-256 point ({} bytes)", bits.len());
        return None;
    }
    Some(bits.to_vec())
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
    build_test_cert_full(issuer_sk, subject_pk_point, eku_oids, None)
}

/// Build a test CA certificate: same as [`build_test_cert`] but with a
/// `BasicConstraints` extension carrying `cA = TRUE` and an optional
/// `pathLenConstraint`. Any certificate used as an issuer needs this.
#[cfg(test)]
pub(crate) fn build_test_ca_cert(
    issuer_sk: &p256::ecdsa::SigningKey,
    subject_pk_point: &[u8],
    eku_oids: &[&[u8]],
    path_len: Option<usize>,
) -> Vec<u8> {
    build_test_cert_full(issuer_sk, subject_pk_point, eku_oids, Some(path_len))
}

/// `basic_constraints`: `None` = omit the extension entirely (not a CA);
/// `Some(path_len)` = include it with `cA = TRUE`.
#[cfg(test)]
fn build_test_cert_full(
    issuer_sk: &p256::ecdsa::SigningKey,
    subject_pk_point: &[u8],
    eku_oids: &[&[u8]],
    basic_constraints: Option<Option<usize>>,
) -> Vec<u8> {
    use p256::ecdsa::{signature::Signer, Signature};

    // Build TBS certificate
    let tbs = build_test_tbs(subject_pk_point, eku_oids, basic_constraints);

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
fn build_test_tbs(
    subject_pk_point: &[u8],
    eku_oids: &[&[u8]],
    basic_constraints: Option<Option<usize>>,
) -> Vec<u8> {
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
    let mut extensions = Vec::new();

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

        extensions.extend_from_slice(&ext_entry);
    }

    if let Some(path_len) = basic_constraints {
        // BasicConstraints ::= SEQUENCE { cA BOOLEAN, pathLenConstraint INTEGER OPTIONAL }
        let mut bc_inner = Vec::new();
        bc_inner.extend_from_slice(&[0x01, 0x01, 0xFF]); // cA = TRUE
        if let Some(pl) = path_len {
            bc_inner.extend_from_slice(&[0x02, 0x01, pl as u8]);
        }

        let mut bc_seq = Vec::new();
        bc_seq.push(0x30);
        der_write_length(&mut bc_seq, bc_inner.len());
        bc_seq.extend_from_slice(&bc_inner);

        let mut bc_os = Vec::new();
        bc_os.push(0x04); // OCTET STRING
        der_write_length(&mut bc_os, bc_seq.len());
        bc_os.extend_from_slice(&bc_seq);

        let mut ext_entry = Vec::new();
        ext_entry.push(0x30);
        // extnID = 2.5.29.19 (basicConstraints)
        let bc_oid_tlv = &[0x06, 0x03, 0x55, 0x1d, 0x13];
        der_write_length(&mut ext_entry, bc_oid_tlv.len() + bc_os.len());
        ext_entry.extend_from_slice(bc_oid_tlv);
        ext_entry.extend_from_slice(&bc_os);

        extensions.extend_from_slice(&ext_entry);
    }

    if !extensions.is_empty() {
        let mut ext_seq = Vec::new();
        ext_seq.push(0x30); // SEQUENCE of extensions
        der_write_length(&mut ext_seq, extensions.len());
        ext_seq.extend_from_slice(&extensions);

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

        let root_cert = build_test_ca_cert(
            &owner_sk, &intermediate_point,
            &[OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED],
            None,
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

        let root_cert = build_test_ca_cert(
            &owner_sk, &intermediate_point, &[OID_PERMIT_PROVISION], None,
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

        let root_cert = build_test_ca_cert(
            &owner_sk, &root_point,
            &[OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED, OID_PERMIT_REDIRECT],
            None,
        );
        let inter_cert = build_test_ca_cert(
            &root_sk, &intermediate_point,
            &[OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED, OID_PERMIT_REDIRECT],
            None,
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
        let root_cert = build_test_ca_cert(
            &owner_sk, &intermediate_point,
            &[OID_PERMIT_ONBOARD_NEWCRED, OID_PERMIT_REDIRECT, OID_PERMIT_PROVISION],
            None,
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
        let root_redirect_only = build_test_ca_cert(
            &owner_sk, &intermediate_point,
            &[OID_PERMIT_REDIRECT],
            None,
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
        let root_cert = build_test_ca_cert(
            &owner_sk, &root_point, &[OID_PERMIT_REDIRECT], None,
        );
        // Intermediate: onboard + redirect
        let inter_cert = build_test_ca_cert(
            &root_sk, &intermediate_point,
            &[OID_PERMIT_ONBOARD_NEWCRED, OID_PERMIT_REDIRECT],
            None,
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

    // =====================================================================
    // Security audit 2026-09-29 — negative tests for the new chain rules.
    // Each of these passed before the corresponding check existed.
    // =====================================================================

    /// H2: a non-OID element inside the EKU SEQUENCE used to spin forever.
    /// `read_oid` does not advance `pos` when the tag is not 0x06, and the
    /// loop had no other advance. This test simply has to terminate.
    #[test]
    fn test_eku_non_oid_element_terminates() {
        // SEQUENCE { NULL }
        let flags = check_eku_oids(&[0x30, 0x02, 0x05, 0x00]);
        assert!(!flags.provision && !flags.onboard && !flags.redirect);

        // SEQUENCE { NULL, OID(PERM.7) } — must skip the NULL and still find
        // the OID that follows it.
        let mut data = alloc::vec![0x30, 0x00, 0x05, 0x00, 0x06, OID_PERMIT_PROVISION.len() as u8];
        data.extend_from_slice(OID_PERMIT_PROVISION);
        data[1] = (data.len() - 2) as u8;
        let flags = check_eku_oids(&data);
        assert!(flags.provision, "OID after a non-OID element must still be seen");
    }

    /// H3: a delegate that is not a CA must not be able to issue a
    /// sub-delegate. Without BasicConstraints, any leaf holding PERM.7 could
    /// mint further certificates and pass its permissions on indefinitely.
    #[test]
    fn test_non_ca_issuer_rejected() {
        let (owner_sk, owner_point) = gen_test_keypair();
        let (intermediate_sk, intermediate_point) = gen_test_keypair_b();
        let (_leaf_sk, leaf_point) = gen_test_keypair_c();

        // Issuer deliberately built WITHOUT basicConstraints.
        let non_ca_issuer = build_test_cert(
            &owner_sk, &intermediate_point,
            &[OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED],
        );
        let leaf_cert = build_test_cert(
            &intermediate_sk, &leaf_point,
            &[OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED],
        );

        let certs = [leaf_cert.as_slice(), non_ca_issuer.as_slice()];
        assert!(verify_delegate_chain(&certs, &owner_point).is_none(),
            "a non-CA certificate must not be accepted as an issuer");

        // Same chain, issuer marked as a CA, must verify — proves the
        // rejection above is caused by the CA bit and nothing else.
        let ca_issuer = build_test_ca_cert(
            &owner_sk, &intermediate_point,
            &[OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED],
            None,
        );
        let certs_ok = [leaf_cert.as_slice(), ca_issuer.as_slice()];
        assert!(verify_delegate_chain(&certs_ok, &owner_point).is_some(),
            "control: same chain with a CA issuer must verify");
    }

    /// A single end-entity certificate issued directly by the Owner does not
    /// need the CA bit — it issues nothing.
    #[test]
    fn test_single_leaf_needs_no_ca_bit() {
        let (owner_sk, owner_point) = gen_test_keypair();
        let (_delegate_sk, delegate_point) = gen_test_keypair_b();

        let cert_der = build_test_cert(&owner_sk, &delegate_point, &[OID_PERMIT_PROVISION]);
        assert!(verify_delegate_chain(&[cert_der.as_slice()], &owner_point).is_some(),
            "a 1-cert chain must not require basicConstraints");
    }

    /// H3: pathLenConstraint must bound the number of intermediates below.
    #[test]
    fn test_path_len_constraint_enforced() {
        let (owner_sk, owner_point) = gen_test_keypair();
        let (root_sk, root_point) = gen_test_keypair_b();
        let (intermediate_sk, intermediate_point) = gen_test_keypair_c();
        let leaf_secret = p256::SecretKey::from_bytes(
            &[0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
              0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
              0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
              0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01].into(),
        ).unwrap();
        let leaf_point = p256::EncodedPoint::from(leaf_secret.public_key()).as_bytes().to_vec();

        let eku: &[&[u8]] = &[OID_PERMIT_PROVISION, OID_PERMIT_ONBOARD_NEWCRED];

        // Root with pathLen=0 => no intermediates may appear below it.
        let root_pl0 = build_test_ca_cert(&owner_sk, &root_point, eku, Some(0));
        let inter_cert = build_test_ca_cert(&root_sk, &intermediate_point, eku, None);
        let leaf_cert = build_test_cert(&intermediate_sk, &leaf_point, eku);

        let certs = [leaf_cert.as_slice(), inter_cert.as_slice(), root_pl0.as_slice()];
        assert!(verify_delegate_chain(&certs, &owner_point).is_none(),
            "pathLenConstraint=0 must reject an intermediate below the root");

        // pathLen=1 permits exactly this depth.
        let root_pl1 = build_test_ca_cert(&owner_sk, &root_point, eku, Some(1));
        let certs_ok = [leaf_cert.as_slice(), inter_cert.as_slice(), root_pl1.as_slice()];
        assert!(verify_delegate_chain(&certs_ok, &owner_point).is_some(),
            "control: pathLenConstraint=1 must allow one intermediate");
    }

    /// H3: chain length is bounded — the chain arrives unauthenticated.
    #[test]
    fn test_chain_length_cap() {
        let (owner_sk, owner_point) = gen_test_keypair();
        let (_, point) = gen_test_keypair_b();
        let cert = build_test_ca_cert(&owner_sk, &point, &[OID_PERMIT_PROVISION], None);

        let refs: alloc::vec::Vec<&[u8]> =
            (0..MAX_DELEGATE_CHAIN_LEN + 1).map(|_| cert.as_slice()).collect();
        assert!(verify_delegate_chain(&refs, &owner_point).is_none(),
            "a chain longer than MAX_DELEGATE_CHAIN_LEN must be refused");
    }

    /// H3b: the certificate must declare ecdsa-with-SHA256, and the outer
    /// `signatureAlgorithm` must equal `tbsCertificate.signature`
    /// (RFC 5280 4.1.1.2). Only the inner copy is covered by the signature,
    /// so a mismatch means the unsigned copy was edited. Both were skipped
    /// entirely before this fix and ES256 was simply assumed.
    #[test]
    fn test_signature_algorithm_binding() {
        let (owner_sk, _) = gen_test_keypair();
        let (_, point) = gen_test_keypair_b();
        let good = build_test_cert(&owner_sk, &point, &[OID_PERMIT_PROVISION]);
        assert!(parse_x509_cert(&good).is_some(), "control: well-formed cert must parse");

        // ecdsa-with-SHA256 is 1.2.840.10045.4.3.2, encoded ...04 03 02.
        // ecdsa-with-SHA384 is 1.2.840.10045.4.3.3 — same length, so we can
        // flip the final byte in place without disturbing any DER lengths.
        let sha256_tail: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

        // Find both occurrences: tbsCertificate.signature and the outer
        // signatureAlgorithm.
        let positions: Vec<usize> = good
            .windows(sha256_tail.len())
            .enumerate()
            .filter(|(_, w)| *w == sha256_tail)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(positions.len(), 2,
            "test cert should carry the algorithm OID exactly twice");

        // Change ONLY the outer signatureAlgorithm -> now it disagrees with
        // the inner one AND is no longer ES256.
        let mut outer_changed = good.clone();
        let last = positions[1];
        outer_changed[last + 7] = 0x03; // ...04 03 03 = ecdsa-with-SHA384
        assert!(parse_x509_cert(&outer_changed).is_none(),
            "a non-ES256 signatureAlgorithm must be refused");

        // Change ONLY the inner tbsCertificate.signature -> outer still says
        // ES256, but the two no longer agree.
        let mut inner_changed = good.clone();
        let first = positions[0];
        inner_changed[first + 7] = 0x03;
        assert!(parse_x509_cert(&inner_changed).is_none(),
            "tbsCertificate.signature must match the outer signatureAlgorithm");
    }

    /// M5: an X5CHAIN must be internally consistent — each certificate
    /// signed by the one above it. Previously the leaf key was taken and the
    /// rest of the chain was discarded unexamined, so the chain structure
    /// was decorative and an arbitrary pile of DER passed.
    #[test]
    fn test_x5chain_internal_linkage() {
        let (root_sk, root_point) = gen_test_keypair();
        let (leaf_sk, leaf_point) = gen_test_keypair_b();
        let (attacker_sk, _) = gen_test_keypair_c();

        // Self-signed root marked as a CA, then a leaf it issues.
        let root_cert = build_test_ca_cert(&root_sk, &root_point, &[OID_PERMIT_PROVISION], None);
        let leaf_cert = build_test_cert(&root_sk, &leaf_point, &[OID_PERMIT_PROVISION]);

        let ok = verify_x5chain_internal(&[leaf_cert.as_slice(), root_cert.as_slice()])
            .expect("a correctly linked chain must verify");
        assert_eq!(ok, leaf_point, "must return the LEAF key, not the root's");

        // Leaf signed by someone who is not the cert above it.
        let forged_leaf = build_test_cert(&attacker_sk, &leaf_point, &[OID_PERMIT_PROVISION]);
        assert!(verify_x5chain_internal(&[forged_leaf.as_slice(), root_cert.as_slice()]).is_none(),
            "a leaf not signed by the next certificate must be refused");

        // Issuer without the CA bit.
        let non_ca_root = build_test_cert(&root_sk, &root_point, &[OID_PERMIT_PROVISION]);
        assert!(verify_x5chain_internal(&[leaf_cert.as_slice(), non_ca_root.as_slice()]).is_none(),
            "a non-CA issuer must be refused in an x5chain too");

        // A single certificate has nothing above it to check against; its
        // key is returned and the caller's own signature check anchors it.
        let single = verify_x5chain_internal(&[leaf_cert.as_slice()])
            .expect("a 1-cert chain must yield its key");
        assert_eq!(single, leaf_point);

        assert!(verify_x5chain_internal(&[]).is_none(), "empty chain must be refused");
        let _ = leaf_sk;
    }

    /// M5: the public key must come from a structurally parsed SPKI with the
    /// right algorithm OIDs, not from a byte-pattern scan.
    #[test]
    fn test_spki_requires_correct_oids() {
        let (_, point) = gen_test_keypair();

        // Correct SPKI: SEQUENCE { SEQUENCE { ecPublicKey, prime256v1 }, BIT STRING }
        let mut good = alloc::vec![
            0x30, 0x59,
            0x30, 0x13,
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
            0x03, 0x42, 0x00,
        ];
        good.extend_from_slice(&point);
        assert_eq!(parse_spki_p256_point(&good).as_deref(), Some(point.as_slice()));

        // Same bytes but the curve OID changed to secp384r1 (1.3.132.0.34).
        // The old pattern scan ignored the OIDs entirely and accepted this.
        let mut wrong_curve = good.clone();
        wrong_curve[13..23].copy_from_slice(&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x05, 0x00, 0x00]);
        assert!(parse_spki_p256_point(&wrong_curve).is_none(),
            "a non-P-256 curve OID must be refused");

        // A buffer that merely *contains* the 03 42 00 04 pattern, with no
        // valid SPKI structure around it, must not yield a key.
        let mut junk = alloc::vec![0x30, 0x04, 0x02, 0x01, 0x01, 0x05, 0x00];
        junk.extend_from_slice(&[0x03, 0x42, 0x00]);
        junk.extend_from_slice(&point);
        assert!(parse_spki_p256_point(&junk).is_none(),
            "a stray BIT STRING pattern must not be mistaken for the SPKI key");
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
