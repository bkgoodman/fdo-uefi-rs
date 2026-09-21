// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// Ownership Voucher verification: derives the TO2-proven Owner public key.
//
// This is the device's root of trust for everything an Owner (or Delegate)
// subsequently tells it. The chain is:
//
//   1. HMAC(DCHmacSecret, OVHeader) == the HMAC in TO2.ProveOVHdr
//        -> OVHeader is authentic AND belongs to THIS device, because only
//           this device's TPM holds DCHmacSecret. This also authenticates
//           everything inside the header, including the manufacturer key.
//   2. OVEntry[0] is signed by OVHeader.OVPubKey (the manufacturer key)
//   3. OVEntry[i] is signed by OVEntry[i-1].OVEPubKey
//   4. Owner key = last entry's OVEPubKey (or the manufacturer key if the
//      voucher was never extended)
//
// Each entry additionally carries two hashes that must match: hashHdrInfo
// (binding the entry to this header's GUID+DeviceInfo) and hashPrevEntry
// (chaining to the preceding entry), which together prevent entries being
// reordered, substituted between vouchers, or dropped.
//
// Reference: FDO spec "Ownership Voucher Persisted Type" and
// go-fdo/voucher.go VerifyEntries/validateNextEntry.

use alloc::string::String;
use alloc::vec::Vec;
use log::{debug, error, info, warn};
use sha2::{Digest, Sha256};

use crate::cose;

/// FDO Hash algorithm identifiers (go-fdo protocol/hash.go)
const HASH_ALG_SHA256: i64 = -16;
const HASH_ALG_SHA384: i64 = -43;

/// FDO pkType values
const PK_TYPE_SECP256R1: i64 = 10;
const PK_TYPE_SECP384R1: i64 = 11;

/// FDO pkEnc values
const PK_ENC_CRYPTO: i64 = 0;
const PK_ENC_X509: i64 = 1;
const PK_ENC_X5CHAIN: i64 = 2;
const PK_ENC_COSEKEY: i64 = 3;

#[derive(Debug)]
pub enum VoucherError {
    /// OVHeader could not be parsed
    HeaderParse(&'static str),
    /// The GUID in the voucher header is not this device's GUID
    GuidMismatch,
    /// The TPM could not compute an HMAC (hardware/handle problem)
    HmacUnavailable,
    /// HMAC over OVHeader did not match — voucher is not ours, or was altered
    HmacMismatch,
    /// A voucher entry could not be parsed
    EntryParse(usize),
    /// A voucher entry's signature did not verify against the previous key
    EntrySignatureInvalid(usize),
    /// An entry's hashPrevEntry did not match the preceding entry
    PrevHashMismatch(usize),
    /// An entry's hashHdrInfo did not match GUID||DeviceInfo
    HeaderHashMismatch(usize),
    /// A public key used an encoding or curve we do not implement
    UnsupportedKey(&'static str),
    /// A hash algorithm we cannot compute
    UnsupportedHash(i64),
    /// Delegation was present but is not implemented
    DelegateNotSupported,
}

/// Parsed, authenticated Ownership Voucher header fields we need downstream.
pub struct OvHeaderInfo {
    pub protver: u16,
    pub guid: [u8; 16],
    pub device_info: String,
    /// Manufacturer public key, uncompressed P-256 point (0x04 || X || Y)
    pub mfg_key_point: Vec<u8>,
}

/// One voucher entry payload.
struct OvEntryPayload {
    hash_prev_alg: i64,
    hash_prev: Vec<u8>,
    hash_hdr_alg: i64,
    hash_hdr: Vec<u8>,
    pub_key_point: Vec<u8>,
}

/// Parse an FDO `PublicKey = [pkType, pkEnc, pkBody]` into an uncompressed
/// P-256 point.
///
/// Note that `pkEnc = X509 (1)` does NOT mean a certificate: the FDO spec
/// states that for this encoding `pkBody` *is* the ASN.1 `SubjectPublicKeyInfo`
/// — an algorithm OID plus a public key bit string. No certificate parsing is
/// involved. `X5CHAIN (2)` is the encoding that carries real certificates, and
/// it is not implemented here.
pub fn parse_fdo_public_key(data: &[u8]) -> Result<Vec<u8>, VoucherError> {
    let mut pos = 0usize;

    let b = *data.get(pos).ok_or(VoucherError::UnsupportedKey("empty PublicKey"))?;
    pos += 1;
    if (b >> 5) != 4 {
        return Err(VoucherError::UnsupportedKey("PublicKey is not an array"));
    }
    let arr_len = cose::cbor_read_uint_arg(data, &mut pos, b & 0x1f)
        .ok_or(VoucherError::UnsupportedKey("bad PublicKey array header"))?;
    if arr_len < 3 {
        return Err(VoucherError::UnsupportedKey("PublicKey array too short"));
    }

    let pk_type = cose::cbor_read_int_value(data, &mut pos)
        .ok_or(VoucherError::UnsupportedKey("bad pkType"))?;
    let pk_enc = cose::cbor_read_int_value(data, &mut pos)
        .ok_or(VoucherError::UnsupportedKey("bad pkEnc"))?;

    if pk_type == PK_TYPE_SECP384R1 {
        error!("Voucher: key is SECP384R1; only SECP256R1 (ES256) is implemented");
        return Err(VoucherError::UnsupportedKey("SECP384R1 not implemented"));
    }
    if pk_type != PK_TYPE_SECP256R1 {
        error!("Voucher: unsupported pkType {} (RSA is not implemented)", pk_type);
        return Err(VoucherError::UnsupportedKey("non-EC pkType"));
    }

    match pk_enc {
        PK_ENC_X509 => {
            let der = cose::cbor_read_bstr(data, &mut pos)
                .ok_or(VoucherError::UnsupportedKey("pkBody is not a bstr"))?;
            spki_p256_point(der)
        }
        PK_ENC_COSEKEY => cose_key_p256_point(data, &mut pos),
        PK_ENC_X5CHAIN => {
            // go-fdo stores pkBody as cbor.RawBytes, so for X5CHAIN the
            // third element of [pkType, pkEnc, pkBody] is a CBOR array of
            // cert bstrs embedded directly — NOT a bstr wrapping a CBOR
            // array. We read from `data` at the current `pos`.
            let leaf_der = x5chain_leaf_der(&data[pos..])?;
            debug!("Voucher: X5CHAIN leaf cert: {} bytes DER", leaf_der.len());
            spki_p256_point(leaf_der)
        }
        PK_ENC_CRYPTO => {
            error!("Voucher: pkEnc=Crypto is not implemented");
            Err(VoucherError::UnsupportedKey("Crypto encoding"))
        }
        other => {
            error!("Voucher: unknown pkEnc {}", other);
            Err(VoucherError::UnsupportedKey("unknown pkEnc"))
        }
    }
}

/// Extract the uncompressed point from a P-256 `SubjectPublicKeyInfo` DER.
///
/// Rather than hardcode an offset, locate the BIT STRING that holds the key:
/// `03 42 00 04` — BIT STRING, length 0x42 (66 = 1 unused-bits octet + 65
/// point octets), 0 unused bits, then the 0x04 uncompressed-point marker.
fn spki_p256_point(der: &[u8]) -> Result<Vec<u8>, VoucherError> {
    const PATTERN: [u8; 4] = [0x03, 0x42, 0x00, 0x04];
    if der.len() < 65 {
        return Err(VoucherError::UnsupportedKey("SPKI too short"));
    }
    for i in 0..der.len().saturating_sub(PATTERN.len() - 1) {
        if der[i..i + 4] == PATTERN {
            let start = i + 3; // at the 0x04 marker
            let point = der
                .get(start..start + 65)
                .ok_or(VoucherError::UnsupportedKey("SPKI BIT STRING truncated"))?;
            return Ok(point.to_vec());
        }
    }
    error!("Voucher: no uncompressed P-256 BIT STRING found in SPKI ({} bytes)", der.len());
    Err(VoucherError::UnsupportedKey("SPKI not P-256 uncompressed"))
}

/// Extract the leaf (first) certificate DER from an X5CHAIN pkBody.
///
/// The wire format is a CBOR array of bstrs: `[leaf_cert_der, *issuer_der]`.
/// We only need the leaf to extract the public key; chain validation (if
/// needed) is a separate concern.
fn x5chain_leaf_der(cbor: &[u8]) -> Result<&[u8], VoucherError> {
    use crate::cose;
    let mut pos = 0usize;
    let b = *cbor.get(pos).ok_or(VoucherError::UnsupportedKey("X5CHAIN empty"))?;
    pos += 1;
    let major = b >> 5;
    if major != 4 {
        // Not an array — some implementations encode a single cert as a bare
        // bstr (no wrapping array). Try that.
        if major == 2 {
            pos = 0;
            let der = cose::cbor_read_bstr(cbor, &mut pos)
                .ok_or(VoucherError::UnsupportedKey("X5CHAIN bare bstr unreadable"))?;
            return Ok(der);
        }
        return Err(VoucherError::UnsupportedKey("X5CHAIN pkBody is not array or bstr"));
    }
    let arr_len = cose::cbor_read_uint_arg(cbor, &mut pos, b & 0x1f)
        .ok_or(VoucherError::UnsupportedKey("X5CHAIN bad array header"))?;
    if arr_len == 0 {
        return Err(VoucherError::UnsupportedKey("X5CHAIN empty certificate array"));
    }
    // Read the first (leaf) certificate bstr
    let leaf = cose::cbor_read_bstr(cbor, &mut pos)
        .ok_or(VoucherError::UnsupportedKey("X5CHAIN leaf cert not a bstr"))?;
    Ok(leaf)
}

/// Extract X/Y from a COSE_Key map (`-2` => x, `-3` => y) and build a point.
///
/// Like X5CHAIN, go-fdo embeds pkBody as `cbor.RawBytes`, so the third
/// element of `[pkType, pkEnc, pkBody]` is a raw CBOR map — not a bstr
/// wrapping one.
fn cose_key_p256_point(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, VoucherError> {
    let body = &data[*pos..];

    let mut p = 0usize;
    let b = *body.get(p).ok_or(VoucherError::UnsupportedKey("empty COSE_Key"))?;
    p += 1;
    if (b >> 5) != 5 {
        return Err(VoucherError::UnsupportedKey("COSE_Key is not a map"));
    }
    let map_len = cose::cbor_read_uint_arg(body, &mut p, b & 0x1f)
        .ok_or(VoucherError::UnsupportedKey("bad COSE_Key map header"))?;

    let mut x: Option<Vec<u8>> = None;
    let mut y: Option<Vec<u8>> = None;
    for _ in 0..map_len {
        let key = cose::cbor_read_int_value(body, &mut p)
            .ok_or(VoucherError::UnsupportedKey("bad COSE_Key label"))?;
        match key {
            -2 => {
                x = cose::cbor_read_bstr(body, &mut p).map(|s| s.to_vec());
            }
            -3 => {
                y = cose::cbor_read_bstr(body, &mut p).map(|s| s.to_vec());
            }
            _ => {
                cose::cbor_skip(body, &mut p)
                    .ok_or(VoucherError::UnsupportedKey("bad COSE_Key value"))?;
            }
        }
    }

    match (x, y) {
        (Some(x), Some(y)) if x.len() == 32 && y.len() == 32 => {
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            Ok(point)
        }
        _ => Err(VoucherError::UnsupportedKey("COSE_Key missing 32-byte x/y")),
    }
}

/// Parse `OVHeader = [protver, guid, rvinfo, deviceinfo, pubkey, devcertchainhash]`.
///
/// `data` is the *contents* of the OVHeader bstr (the CBOR array itself), which
/// is what TO2.ProveOVHdr delivers and what the HMAC is computed over.
pub fn parse_ov_header(data: &[u8]) -> Result<OvHeaderInfo, VoucherError> {
    let mut pos = 0usize;

    let b = *data.get(pos).ok_or(VoucherError::HeaderParse("empty OVHeader"))?;
    pos += 1;
    if (b >> 5) != 4 {
        return Err(VoucherError::HeaderParse("OVHeader is not an array"));
    }
    let arr_len = cose::cbor_read_uint_arg(data, &mut pos, b & 0x1f)
        .ok_or(VoucherError::HeaderParse("bad OVHeader array header"))?;
    if arr_len < 5 {
        return Err(VoucherError::HeaderParse("OVHeader array too short"));
    }

    // [0] OVHProtVer
    let protver = cose::cbor_read_uint_value(data, &mut pos)
        .ok_or(VoucherError::HeaderParse("bad OVHProtVer"))? as u16;

    // [1] OVGuid
    let guid_bytes = cose::cbor_read_bstr(data, &mut pos)
        .ok_or(VoucherError::HeaderParse("bad OVGuid"))?;
    if guid_bytes.len() != 16 {
        return Err(VoucherError::HeaderParse("OVGuid is not 16 bytes"));
    }
    let mut guid = [0u8; 16];
    guid.copy_from_slice(guid_bytes);

    // [2] OVRVInfo — skipped
    cose::cbor_skip(data, &mut pos).ok_or(VoucherError::HeaderParse("bad OVRVInfo"))?;

    // [3] OVDeviceInfo (tstr) — needed verbatim for hashHdrInfo
    let di_start = pos;
    cose::cbor_skip(data, &mut pos).ok_or(VoucherError::HeaderParse("bad OVDeviceInfo"))?;
    let device_info = decode_tstr(data.get(di_start..pos).unwrap_or(&[]))
        .ok_or(VoucherError::HeaderParse("OVDeviceInfo is not a tstr"))?;

    // [4] OVPubKey — the manufacturer key
    let pk_start = pos;
    cose::cbor_skip(data, &mut pos).ok_or(VoucherError::HeaderParse("bad OVPubKey"))?;
    let pk_slice = data
        .get(pk_start..pos)
        .ok_or(VoucherError::HeaderParse("OVPubKey span out of range"))?;
    let mfg_key_point = parse_fdo_public_key(pk_slice)?;

    Ok(OvHeaderInfo {
        protver,
        guid,
        device_info,
        mfg_key_point,
    })
}

fn decode_tstr(data: &[u8]) -> Option<String> {
    let mut pos = 0usize;
    let b = *data.first()?;
    pos += 1;
    if (b >> 5) != 3 {
        return None;
    }
    let len = cose::cbor_read_uint_arg(data, &mut pos, b & 0x1f)?;
    let s = core::str::from_utf8(data.get(pos..pos + len)?).ok()?;
    Some(String::from(s))
}

/// Parse `OVEntryPayload = [hashPrevEntry, hashHdrInfo, extra, pubKey]`.
/// Hash values are `[alg, bstr]`.
fn parse_ov_entry_payload(data: &[u8]) -> Option<OvEntryPayload> {
    let mut pos = 0usize;

    let b = *data.first()?;
    pos += 1;
    if (b >> 5) != 4 {
        return None;
    }
    let arr_len = cose::cbor_read_uint_arg(data, &mut pos, b & 0x1f)?;
    if arr_len < 4 {
        warn!("Voucher: OVEntryPayload has {} elements, expected 4", arr_len);
        return None;
    }

    let (hash_prev_alg, hash_prev) = read_hash(data, &mut pos)?;
    let (hash_hdr_alg, hash_hdr) = read_hash(data, &mut pos)?;

    // OVEExtra: null or bstr — skipped
    cose::cbor_skip(data, &mut pos)?;

    let pk_start = pos;
    cose::cbor_skip(data, &mut pos)?;
    let pub_key_point = parse_fdo_public_key(data.get(pk_start..pos)?).ok()?;

    Some(OvEntryPayload {
        hash_prev_alg,
        hash_prev,
        hash_hdr_alg,
        hash_hdr,
        pub_key_point,
    })
}

/// Read a `Hash = [alg, bstr]`.
fn read_hash(data: &[u8], pos: &mut usize) -> Option<(i64, Vec<u8>)> {
    let b = *data.get(*pos)?;
    *pos += 1;
    if (b >> 5) != 4 {
        return None;
    }
    let n = cose::cbor_read_uint_arg(data, pos, b & 0x1f)?;
    if n < 2 {
        return None;
    }
    let alg = cose::cbor_read_int_value(data, pos)?;
    let value = cose::cbor_read_bstr(data, pos)?.to_vec();
    for _ in 2..n {
        cose::cbor_skip(data, pos)?;
    }
    Some((alg, value))
}

/// Verify the Ownership Voucher and return the Owner public key point.
///
/// * `ov_header_cbor` — contents of the OVHeader bstr from TO2.ProveOVHdr
/// * `hmac_raw_cbor` — the raw CBOR bytes of the `HMac` structure, needed
///   verbatim because entry 0's hashPrevEntry is computed over
///   `OVHeader || HMac` as encoded, not over re-serialised values
/// * `hmac_value` — the HMAC digest extracted from that structure
/// * `entries` — tag-18 COSE_Sign1 bytes for each entry, in order
///
/// On success the returned point is the key that TO2.ProveOVHdr must verify
/// against, and the trust anchor for BMO provisioning signatures.
pub fn verify_voucher(
    ov_header_cbor: &[u8],
    hmac_raw_cbor: &[u8],
    hmac_value: &[u8],
    hmac_key_handle: u32,
    device_guid: &[u8; 16],
    entries: &[Vec<u8>],
) -> Result<Vec<u8>, VoucherError> {
    let header = parse_ov_header(ov_header_cbor)?;
    info!(
        "Voucher: header protver={} entries={} device_info={:?}",
        header.protver,
        entries.len(),
        header.device_info
    );

    // The GUID in the voucher must be the GUID we are onboarding as.
    if &header.guid != device_guid {
        error!("Voucher: GUID mismatch");
        error!("  voucher: {:02x?}", header.guid);
        error!("  device:  {:02x?}", device_guid);
        return Err(VoucherError::GuidMismatch);
    }

    // Step 1: the HMAC binds this header to THIS device. Without it, an
    // attacker could present any well-formed voucher, including one for a
    // device it legitimately owns.
    let computed = crate::tpm::tpm_hmac(hmac_key_handle, ov_header_cbor)
        .ok_or(VoucherError::HmacUnavailable)?;
    if computed.as_slice() != hmac_value {
        error!("Voucher: OVHeader HMAC MISMATCH — this voucher does not belong to this device");
        error!("  expected (from server): {:02x?}", &hmac_value[..hmac_value.len().min(16)]);
        error!("  computed (TPM):         {:02x?}", &computed[..computed.len().min(16)]);
        return Err(VoucherError::HmacMismatch);
    }
    info!("Voucher: OVHeader HMAC verified against TPM key — header is authentic for this device");

    // A voucher never extended past manufacturing has no entries; the
    // manufacturer key is the Owner key.
    if entries.is_empty() {
        info!("Voucher: no entries — Owner key is the manufacturer key");
        return Ok(header.mfg_key_point);
    }

    let aad = cose::domain_aad(cose::AAD_TAG_OV_ENTRY, header.protver);

    // hashHdrInfo = SHA256(GUID || DeviceInfo), identical for every entry.
    let mut hasher = Sha256::new();
    hasher.update(header.guid);
    hasher.update(header.device_info.as_bytes());
    let header_info_hash = hasher.finalize().to_vec();

    // Entry 0's hashPrevEntry is over OVHeader || HMac, as encoded.
    let mut hasher = Sha256::new();
    hasher.update(ov_header_cbor);
    hasher.update(hmac_raw_cbor);
    let mut prev_hash = hasher.finalize().to_vec();

    let mut prev_key = header.mfg_key_point;

    for (i, entry_bytes) in entries.iter().enumerate() {
        let s1 = cose::parse_cose_sign1(entry_bytes).ok_or(VoucherError::EntryParse(i))?;

        if cose::has_delegate_header(s1.unprotected_header) {
            error!("Voucher: entry {} carries a delegate key/x5chain header; not implemented", i);
            return Err(VoucherError::DelegateNotSupported);
        }

        // Signature must verify against the previous owner's key.
        if !cose::verify_sign1(&s1, &aad, &prev_key) {
            error!("Voucher: entry {} signature did NOT verify against the previous owner key", i);
            return Err(VoucherError::EntrySignatureInvalid(i));
        }

        let payload = parse_ov_entry_payload(s1.payload).ok_or(VoucherError::EntryParse(i))?;

        if payload.hash_prev_alg != HASH_ALG_SHA256 || payload.hash_hdr_alg != HASH_ALG_SHA256 {
            let bad = if payload.hash_prev_alg != HASH_ALG_SHA256 {
                payload.hash_prev_alg
            } else {
                payload.hash_hdr_alg
            };
            if bad == HASH_ALG_SHA384 {
                error!("Voucher: entry {} uses SHA-384; only SHA-256 is implemented", i);
            }
            return Err(VoucherError::UnsupportedHash(bad));
        }

        // Binds the entry to this specific header (GUID + DeviceInfo), so an
        // entry cannot be lifted from another device's voucher.
        if payload.hash_hdr != header_info_hash {
            error!("Voucher: entry {} hashHdrInfo does not match this header", i);
            return Err(VoucherError::HeaderHashMismatch(i));
        }

        // Binds the entry to its predecessor, so entries cannot be reordered,
        // replaced, or removed.
        if payload.hash_prev != prev_hash {
            error!("Voucher: entry {} hashPrevEntry does not match the preceding entry", i);
            return Err(VoucherError::PrevHashMismatch(i));
        }

        debug!("Voucher: entry {} verified (sig + hashHdrInfo + hashPrevEntry)", i);

        // Advance the chain.
        prev_key = payload.pub_key_point;
        let mut hasher = Sha256::new();
        hasher.update(entry_bytes);
        prev_hash = hasher.finalize().to_vec();
    }

    info!(
        "Voucher: all {} entries verified; Owner key established",
        entries.len()
    );
    Ok(prev_key)
}
