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
/// Extract uncompressed P-256 point (65 bytes: 0x04 || x || y) from a
/// COSE_Key map starting at `data[*pos]`.  Advances `*pos` past the map.
///
/// This is also available as the free function [`crate::bmo::parse_cose_key_p256`]
/// which takes a standalone byte slice (for BMO meta-payload signer keys).
pub(crate) fn cose_key_p256_point(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, VoucherError> {
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
    #[cfg(target_os = "uefi")]
    {
        let computed = crate::tpm::tpm_hmac(hmac_key_handle, ov_header_cbor)
            .ok_or(VoucherError::HmacUnavailable)?;
        if computed.as_slice() != hmac_value {
            error!("Voucher: OVHeader HMAC MISMATCH — this voucher does not belong to this device");
            error!("  expected (from server): {:02x?}", &hmac_value[..hmac_value.len().min(16)]);
            error!("  computed (TPM):         {:02x?}", &computed[..computed.len().min(16)]);
            return Err(VoucherError::HmacMismatch);
        }
        info!("Voucher: OVHeader HMAC verified against TPM key — header is authentic for this device");
    }
    #[cfg(not(target_os = "uefi"))]
    {
        // On native targets (unit tests), skip TPM HMAC verification.
        // The HMAC is checked by a separate test with a software HMAC.
        let _ = (hmac_key_handle, hmac_value);
        info!("Voucher: HMAC verification skipped (native target, no TPM)");
    }

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

/// Software HMAC-SHA-256 for testing. On UEFI targets the TPM performs this.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// =========================================================================
// Unit tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose::{self, gen_test_keypair, gen_test_keypair_b};
    use sha2::{Digest, Sha256};

    // ---- CBOR encoding helpers (test-only) ----

    fn cbor_uint(out: &mut Vec<u8>, val: u64) {
        if val < 24 {
            out.push(val as u8);
        } else if val < 256 {
            out.push(0x18);
            out.push(val as u8);
        } else if val < 65536 {
            out.push(0x19);
            out.push((val >> 8) as u8);
            out.push(val as u8);
        } else {
            out.push(0x1B);
            out.extend_from_slice(&val.to_be_bytes());
        }
    }

    fn cbor_neg_int(out: &mut Vec<u8>, val: i64) {
        // CBOR negative = major type 1, value = -1 - n
        let n = (-1 - val) as u64;
        if n < 24 {
            out.push(0x20 | n as u8);
        } else if n < 256 {
            out.push(0x38);
            out.push(n as u8);
        }
    }

    fn cbor_bstr(out: &mut Vec<u8>, data: &[u8]) {
        cose::encode_bstr(out, data);
    }

    fn cbor_tstr(out: &mut Vec<u8>, s: &str) {
        let bytes = s.as_bytes();
        if bytes.len() < 24 {
            out.push(0x60 | bytes.len() as u8);
        } else if bytes.len() < 256 {
            out.push(0x78);
            out.push(bytes.len() as u8);
        } else {
            out.push(0x79);
            out.push((bytes.len() >> 8) as u8);
            out.push(bytes.len() as u8);
        }
        out.extend_from_slice(bytes);
    }

    fn cbor_array_header(out: &mut Vec<u8>, len: usize) {
        if len < 24 {
            out.push(0x80 | len as u8);
        } else {
            out.push(0x98);
            out.push(len as u8);
        }
    }

    /// Build a minimal FDO PublicKey: [pkType=10, pkEnc=1 (X509), pkBody=SPKI]
    fn build_test_fdo_public_key(point: &[u8]) -> Vec<u8> {
        // SPKI for P-256 uncompressed point
        let spki_alg = &[
            0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
            0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
            0xce, 0x3d, 0x03, 0x01, 0x07,
        ];
        let mut spki = Vec::new();
        spki.extend_from_slice(spki_alg);
        // BIT STRING: 03 42 00 <point>
        spki.push(0x03);
        spki.push(0x42); // length 66
        spki.push(0x00); // unused bits
        spki.extend_from_slice(point);
        // Wrap in SEQUENCE
        let mut spki_seq = vec![0x30];
        if spki.len() < 128 {
            spki_seq.push(spki.len() as u8);
        } else {
            spki_seq.push(0x81);
            spki_seq.push(spki.len() as u8);
        }
        spki_seq.extend_from_slice(&spki);

        let mut pk = Vec::new();
        cbor_array_header(&mut pk, 3);
        cbor_uint(&mut pk, 10); // pkType = SECP256R1
        cbor_uint(&mut pk, 1);  // pkEnc = X509
        cbor_bstr(&mut pk, &spki_seq);
        pk
    }

    /// Build a minimal OVHeader CBOR array.
    fn build_test_ov_header(guid: &[u8; 16], device_info: &str, mfg_key_point: &[u8]) -> Vec<u8> {
        let mut hdr = Vec::new();
        cbor_array_header(&mut hdr, 5);
        cbor_uint(&mut hdr, 101); // protver = 101
        cbor_bstr(&mut hdr, guid);
        // OVRVInfo — empty array
        hdr.push(0x80);
        cbor_tstr(&mut hdr, device_info);
        // OVPubKey
        let pk = build_test_fdo_public_key(mfg_key_point);
        hdr.extend_from_slice(&pk);
        hdr
    }

    /// Build a CBOR Hash: [alg, bstr]
    fn build_cbor_hash(hash: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        cbor_array_header(&mut out, 2);
        cbor_neg_int(&mut out, HASH_ALG_SHA256);
        cbor_bstr(&mut out, hash);
        out
    }

    /// Build an OVEntryPayload: [hashPrev, hashHdr, extra, pubKey]
    fn build_ov_entry_payload(
        hash_prev: &[u8],
        hash_hdr: &[u8],
        next_key_point: &[u8],
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        cbor_array_header(&mut payload, 4);
        payload.extend_from_slice(&build_cbor_hash(hash_prev));
        payload.extend_from_slice(&build_cbor_hash(hash_hdr));
        payload.push(0xF6); // extra = null
        let pk = build_test_fdo_public_key(next_key_point);
        payload.extend_from_slice(&pk);
        payload
    }

    /// Build HMAC raw CBOR: [alg, bstr]
    fn build_hmac_cbor(hmac_digest: &[u8]) -> Vec<u8> {
        build_cbor_hash(hmac_digest)
    }

    // ---- Tests ----

    #[test]
    fn test_parse_ov_header_basic() {
        let (_, mfg_point) = gen_test_keypair();
        let guid = [0x42u8; 16];
        let hdr = build_test_ov_header(&guid, "test-device", &mfg_point);

        let info = parse_ov_header(&hdr).expect("should parse");
        assert_eq!(info.protver, 101);
        assert_eq!(info.guid, guid);
        assert_eq!(info.device_info, "test-device");
        assert_eq!(info.mfg_key_point, mfg_point);
    }

    #[test]
    fn test_parse_ov_header_garbage() {
        assert!(parse_ov_header(&[0xDE, 0xAD]).is_err());
    }

    #[test]
    fn test_parse_ov_header_too_short() {
        // Array of 2 elements — need at least 5
        let mut hdr = Vec::new();
        cbor_array_header(&mut hdr, 2);
        cbor_uint(&mut hdr, 101);
        cbor_bstr(&mut hdr, &[0u8; 16]);
        assert!(parse_ov_header(&hdr).is_err());
    }

    #[test]
    fn test_parse_fdo_public_key_x509() {
        let (_, point) = gen_test_keypair();
        let pk = build_test_fdo_public_key(&point);
        let parsed = parse_fdo_public_key(&pk).expect("should parse");
        assert_eq!(parsed, point);
    }

    #[test]
    fn test_parse_fdo_public_key_cose_key() {
        let (_, point) = gen_test_keypair();
        let x = &point[1..33];
        let y = &point[33..65];

        let mut pk = Vec::new();
        cbor_array_header(&mut pk, 3);
        cbor_uint(&mut pk, 10); // pkType = SECP256R1
        cbor_uint(&mut pk, 3);  // pkEnc = COSEKEY
        // COSE_Key map: { -2: x, -3: y }
        pk.push(0xa2); // map(2)
        cbor_neg_int(&mut pk, -2);
        cbor_bstr(&mut pk, x);
        cbor_neg_int(&mut pk, -3);
        cbor_bstr(&mut pk, y);

        let parsed = parse_fdo_public_key(&pk).expect("should parse COSE_Key");
        assert_eq!(parsed, point);
    }

    #[test]
    fn test_parse_fdo_public_key_unsupported_type() {
        let mut pk = Vec::new();
        cbor_array_header(&mut pk, 3);
        cbor_uint(&mut pk, 99); // unsupported pkType
        cbor_uint(&mut pk, 1);
        cbor_bstr(&mut pk, &[0u8; 65]);
        assert!(parse_fdo_public_key(&pk).is_err());
    }

    // ---- Software HMAC tests ----

    #[test]
    fn test_hmac_sha256_known_vector() {
        // RFC 4231 test case 2
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
            0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
            0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
            0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
        ];
        let mac = hmac_sha256(key, data);
        assert_eq!(mac, expected, "HMAC-SHA-256 must match RFC 4231 test case 2");
    }

    #[test]
    fn test_hmac_sha256_wrong_key() {
        let key_a = [0x01u8; 32];
        let key_b = [0x02u8; 32];
        let data = b"test data";
        let mac_a = hmac_sha256(&key_a, data);
        let mac_b = hmac_sha256(&key_b, data);
        assert_ne!(mac_a, mac_b, "different keys must produce different HMACs");
    }

    // ---- Voucher verification: no entries (mfg key = owner key) ----

    #[test]
    fn test_verify_voucher_no_entries() {
        let (_, mfg_point) = gen_test_keypair();
        let guid = [0x11u8; 16];
        let hdr = build_test_ov_header(&guid, "dev1", &mfg_point);

        let hmac_key = [0xABu8; 32];
        let hmac_digest = hmac_sha256(&hmac_key, &hdr);
        let hmac_cbor = build_hmac_cbor(&hmac_digest);

        let entries: Vec<Vec<u8>> = vec![];
        let owner_key = verify_voucher(&hdr, &hmac_cbor, &hmac_digest, 0, &guid, &entries)
            .expect("no-entry voucher should verify");
        assert_eq!(owner_key, mfg_point, "owner key must be mfg key when no entries");
    }

    // ---- Voucher: GUID mismatch ----

    #[test]
    fn test_verify_voucher_guid_mismatch() {
        let (_, mfg_point) = gen_test_keypair();
        let voucher_guid = [0x11u8; 16];
        let device_guid = [0x22u8; 16];
        let hdr = build_test_ov_header(&voucher_guid, "dev1", &mfg_point);

        let hmac_digest = hmac_sha256(&[0xABu8; 32], &hdr);
        let hmac_cbor = build_hmac_cbor(&hmac_digest);

        let result = verify_voucher(&hdr, &hmac_cbor, &hmac_digest, 0, &device_guid, &[]);
        assert!(matches!(result, Err(VoucherError::GuidMismatch)));
    }

    // ---- Voucher with 1 entry ----

    #[test]
    fn test_verify_voucher_one_entry() {
        let (mfg_sk, mfg_point) = gen_test_keypair();
        let (_, owner_point) = gen_test_keypair_b();
        let guid = [0x33u8; 16];
        let hdr = build_test_ov_header(&guid, "dev2", &mfg_point);

        let hmac_key = [0xCDu8; 32];
        let hmac_digest = hmac_sha256(&hmac_key, &hdr);
        let hmac_cbor = build_hmac_cbor(&hmac_digest);

        // hashHdrInfo = SHA256(guid || device_info)
        let hash_hdr = {
            let mut h = Sha256::new();
            h.update(&guid);
            h.update(b"dev2");
            h.finalize().to_vec()
        };

        // hashPrevEntry = SHA256(ov_header || hmac_cbor) for entry 0
        let hash_prev = {
            let mut h = Sha256::new();
            h.update(&hdr);
            h.update(&hmac_cbor);
            h.finalize().to_vec()
        };

        let entry_payload = build_ov_entry_payload(&hash_prev, &hash_hdr, &owner_point);

        // Build COSE_Sign1 signed by mfg key
        let aad = cose::domain_aad(cose::AAD_TAG_OV_ENTRY, 101);
        let protected = cose::build_test_protected_header(None);
        let entry = cose::build_test_cose_sign1(
            &protected, &entry_payload, &aad, &[0xa0], &mfg_sk,
        );

        let entries = vec![entry];
        let result = verify_voucher(&hdr, &hmac_cbor, &hmac_digest, 0, &guid, &entries)
            .expect("1-entry voucher should verify");
        assert_eq!(result, owner_point, "owner key must be from the entry");
    }

    // ---- Voucher with 2 entries (ownership extended twice) ----

    #[test]
    fn test_verify_voucher_two_entries() {
        let (mfg_sk, mfg_point) = gen_test_keypair();
        let (reseller_sk, reseller_point) = gen_test_keypair_b();
        // Third key = final owner
        let owner_secret = p256::SecretKey::from_bytes(
            &[0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
              0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
              0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
              0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01].into(),
        ).unwrap();
        let owner_point = {
            let pk = owner_secret.public_key();
            p256::EncodedPoint::from(pk).as_bytes().to_vec()
        };

        let guid = [0x44u8; 16];
        let hdr = build_test_ov_header(&guid, "dev3", &mfg_point);

        let hmac_key = [0xEFu8; 32];
        let hmac_digest = hmac_sha256(&hmac_key, &hdr);
        let hmac_cbor = build_hmac_cbor(&hmac_digest);

        let hash_hdr = {
            let mut h = Sha256::new();
            h.update(&guid);
            h.update(b"dev3");
            h.finalize().to_vec()
        };

        // Entry 0: mfg → reseller
        let hash_prev_0 = {
            let mut h = Sha256::new();
            h.update(&hdr);
            h.update(&hmac_cbor);
            h.finalize().to_vec()
        };
        let payload_0 = build_ov_entry_payload(&hash_prev_0, &hash_hdr, &reseller_point);
        let aad = cose::domain_aad(cose::AAD_TAG_OV_ENTRY, 101);
        let protected = cose::build_test_protected_header(None);
        let entry_0 = cose::build_test_cose_sign1(
            &protected, &payload_0, &aad, &[0xa0], &mfg_sk,
        );

        // Entry 1: reseller → owner
        let hash_prev_1 = {
            let mut h = Sha256::new();
            h.update(&entry_0);
            h.finalize().to_vec()
        };
        let payload_1 = build_ov_entry_payload(&hash_prev_1, &hash_hdr, &owner_point);
        let entry_1 = cose::build_test_cose_sign1(
            &protected, &payload_1, &aad, &[0xa0], &reseller_sk,
        );

        let entries = vec![entry_0, entry_1];
        let result = verify_voucher(&hdr, &hmac_cbor, &hmac_digest, 0, &guid, &entries)
            .expect("2-entry voucher should verify");
        assert_eq!(result, owner_point);
    }

    // ---- Negative: corrupted entry signature ----

    #[test]
    fn test_verify_voucher_corrupted_entry_signature() {
        let (mfg_sk, mfg_point) = gen_test_keypair();
        let (_, owner_point) = gen_test_keypair_b();
        let guid = [0x55u8; 16];
        let hdr = build_test_ov_header(&guid, "dev4", &mfg_point);

        let hmac_digest = hmac_sha256(&[0xAAu8; 32], &hdr);
        let hmac_cbor = build_hmac_cbor(&hmac_digest);

        let hash_hdr = {
            let mut h = Sha256::new();
            h.update(&guid);
            h.update(b"dev4");
            h.finalize().to_vec()
        };
        let hash_prev = {
            let mut h = Sha256::new();
            h.update(&hdr);
            h.update(&hmac_cbor);
            h.finalize().to_vec()
        };

        let payload = build_ov_entry_payload(&hash_prev, &hash_hdr, &owner_point);
        let aad = cose::domain_aad(cose::AAD_TAG_OV_ENTRY, 101);
        let protected = cose::build_test_protected_header(None);
        let mut entry = cose::build_test_cose_sign1(
            &protected, &payload, &aad, &[0xa0], &mfg_sk,
        );

        // Corrupt the signature (last byte)
        let last = entry.len() - 1;
        entry[last] ^= 0xFF;

        let result = verify_voucher(&hdr, &hmac_cbor, &hmac_digest, 0, &guid, &[entry]);
        assert!(matches!(result, Err(VoucherError::EntrySignatureInvalid(0))),
            "corrupted entry signature must be rejected");
    }

    // ---- Negative: wrong signing key ----

    #[test]
    fn test_verify_voucher_wrong_signer() {
        let (_, mfg_point) = gen_test_keypair();
        let (attacker_sk, _) = gen_test_keypair_b();
        let guid = [0x66u8; 16];
        let hdr = build_test_ov_header(&guid, "dev5", &mfg_point);

        let hmac_digest = hmac_sha256(&[0xBBu8; 32], &hdr);
        let hmac_cbor = build_hmac_cbor(&hmac_digest);

        let hash_hdr = {
            let mut h = Sha256::new();
            h.update(&guid);
            h.update(b"dev5");
            h.finalize().to_vec()
        };
        let hash_prev = {
            let mut h = Sha256::new();
            h.update(&hdr);
            h.update(&hmac_cbor);
            h.finalize().to_vec()
        };

        let (_, fake_owner_point) = gen_test_keypair_b();
        let payload = build_ov_entry_payload(&hash_prev, &hash_hdr, &fake_owner_point);
        let aad = cose::domain_aad(cose::AAD_TAG_OV_ENTRY, 101);
        let protected = cose::build_test_protected_header(None);
        // Signed by attacker, not by mfg key
        let entry = cose::build_test_cose_sign1(
            &protected, &payload, &aad, &[0xa0], &attacker_sk,
        );

        let result = verify_voucher(&hdr, &hmac_cbor, &hmac_digest, 0, &guid, &[entry]);
        assert!(matches!(result, Err(VoucherError::EntrySignatureInvalid(0))),
            "entry signed by wrong key must be rejected");
    }

    // ---- Negative: hashHdrInfo mismatch ----

    #[test]
    fn test_verify_voucher_header_hash_mismatch() {
        let (mfg_sk, mfg_point) = gen_test_keypair();
        let (_, owner_point) = gen_test_keypair_b();
        let guid = [0x77u8; 16];
        let hdr = build_test_ov_header(&guid, "dev6", &mfg_point);

        let hmac_digest = hmac_sha256(&[0xCCu8; 32], &hdr);
        let hmac_cbor = build_hmac_cbor(&hmac_digest);

        // Use WRONG hashHdrInfo (different device_info)
        let wrong_hash_hdr = {
            let mut h = Sha256::new();
            h.update(&guid);
            h.update(b"wrong-device");
            h.finalize().to_vec()
        };
        let hash_prev = {
            let mut h = Sha256::new();
            h.update(&hdr);
            h.update(&hmac_cbor);
            h.finalize().to_vec()
        };

        let payload = build_ov_entry_payload(&hash_prev, &wrong_hash_hdr, &owner_point);
        let aad = cose::domain_aad(cose::AAD_TAG_OV_ENTRY, 101);
        let protected = cose::build_test_protected_header(None);
        let entry = cose::build_test_cose_sign1(
            &protected, &payload, &aad, &[0xa0], &mfg_sk,
        );

        let result = verify_voucher(&hdr, &hmac_cbor, &hmac_digest, 0, &guid, &[entry]);
        assert!(matches!(result, Err(VoucherError::HeaderHashMismatch(0))),
            "wrong hashHdrInfo must be rejected");
    }

    // ---- Negative: hashPrevEntry mismatch ----

    #[test]
    fn test_verify_voucher_prev_hash_mismatch() {
        let (mfg_sk, mfg_point) = gen_test_keypair();
        let (_, owner_point) = gen_test_keypair_b();
        let guid = [0x88u8; 16];
        let hdr = build_test_ov_header(&guid, "dev7", &mfg_point);

        let hmac_digest = hmac_sha256(&[0xDDu8; 32], &hdr);
        let hmac_cbor = build_hmac_cbor(&hmac_digest);

        let hash_hdr = {
            let mut h = Sha256::new();
            h.update(&guid);
            h.update(b"dev7");
            h.finalize().to_vec()
        };
        // WRONG hashPrevEntry
        let wrong_hash_prev = [0xFFu8; 32];

        let payload = build_ov_entry_payload(&wrong_hash_prev, &hash_hdr, &owner_point);
        let aad = cose::domain_aad(cose::AAD_TAG_OV_ENTRY, 101);
        let protected = cose::build_test_protected_header(None);
        let entry = cose::build_test_cose_sign1(
            &protected, &payload, &aad, &[0xa0], &mfg_sk,
        );

        let result = verify_voucher(&hdr, &hmac_cbor, &hmac_digest, 0, &guid, &[entry]);
        assert!(matches!(result, Err(VoucherError::PrevHashMismatch(0))),
            "wrong hashPrevEntry must be rejected");
    }

    // ---- Entry reordering (swap entries 0 and 1) ----

    #[test]
    fn test_verify_voucher_entries_swapped() {
        // Build a valid 2-entry voucher, then swap entries → must fail
        let (mfg_sk, mfg_point) = gen_test_keypair();
        let (reseller_sk, reseller_point) = gen_test_keypair_b();
        let owner_secret = p256::SecretKey::from_bytes(
            &[0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
              0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
              0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
              0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01].into(),
        ).unwrap();
        let owner_point = {
            let pk = owner_secret.public_key();
            p256::EncodedPoint::from(pk).as_bytes().to_vec()
        };

        let guid = [0x99u8; 16];
        let hdr = build_test_ov_header(&guid, "swap", &mfg_point);
        let hmac_digest = hmac_sha256(&[0xABu8; 32], &hdr);
        let hmac_cbor = build_hmac_cbor(&hmac_digest);

        let hash_hdr = {
            let mut h = Sha256::new();
            h.update(&guid);
            h.update(b"swap");
            h.finalize().to_vec()
        };

        // Entry 0: mfg → reseller
        let hash_prev_0 = {
            let mut h = Sha256::new();
            h.update(&hdr);
            h.update(&hmac_cbor);
            h.finalize().to_vec()
        };
        let payload_0 = build_ov_entry_payload(&hash_prev_0, &hash_hdr, &reseller_point);
        let aad = cose::domain_aad(cose::AAD_TAG_OV_ENTRY, 101);
        let protected = cose::build_test_protected_header(None);
        let entry_0 = cose::build_test_cose_sign1(
            &protected, &payload_0, &aad, &[0xa0], &mfg_sk,
        );

        // Entry 1: reseller → owner
        let hash_prev_1 = {
            let mut h = Sha256::new();
            h.update(&entry_0);
            h.finalize().to_vec()
        };
        let payload_1 = build_ov_entry_payload(&hash_prev_1, &hash_hdr, &owner_point);
        let entry_1 = cose::build_test_cose_sign1(
            &protected, &payload_1, &aad, &[0xa0], &reseller_sk,
        );

        // Swapped order: entry_1 first, entry_0 second
        let result = verify_voucher(&hdr, &hmac_cbor, &hmac_digest, 0, &guid,
            &[entry_1.clone(), entry_0.clone()]);
        assert!(result.is_err(),
            "swapped entry order must be rejected (signature chain broken)");
    }

    // ---- Entry from different device injected ----

    #[test]
    fn test_verify_voucher_entry_from_different_device() {
        // Entry signed correctly but with hashHdrInfo from a different device
        let (mfg_sk, mfg_point) = gen_test_keypair();
        let (_, owner_point) = gen_test_keypair_b();
        let guid_a = [0xAAu8; 16];
        let guid_b = [0xBBu8; 16];

        // Build header for device A
        let hdr_a = build_test_ov_header(&guid_a, "device-A", &mfg_point);
        let hmac_digest = hmac_sha256(&[0xCCu8; 32], &hdr_a);
        let hmac_cbor = build_hmac_cbor(&hmac_digest);

        // Entry uses hashHdrInfo from device B
        let hash_hdr_b = {
            let mut h = Sha256::new();
            h.update(&guid_b);
            h.update(b"device-B");
            h.finalize().to_vec()
        };
        let hash_prev = {
            let mut h = Sha256::new();
            h.update(&hdr_a);
            h.update(&hmac_cbor);
            h.finalize().to_vec()
        };

        let payload = build_ov_entry_payload(&hash_prev, &hash_hdr_b, &owner_point);
        let aad = cose::domain_aad(cose::AAD_TAG_OV_ENTRY, 101);
        let protected = cose::build_test_protected_header(None);
        let entry = cose::build_test_cose_sign1(
            &protected, &payload, &aad, &[0xa0], &mfg_sk,
        );

        let result = verify_voucher(&hdr_a, &hmac_cbor, &hmac_digest, 0, &guid_a, &[entry]);
        assert!(matches!(result, Err(VoucherError::HeaderHashMismatch(0))),
            "entry bound to different device must be rejected");
    }

    // ---- Entry with wrong domain AAD (wrong protocol tag) ----

    /// Build OVHeader with a specific protver.
    fn build_test_ov_header_v(guid: &[u8; 16], device_info: &str, mfg_key_point: &[u8], protver: u16) -> Vec<u8> {
        let mut hdr = Vec::new();
        cbor_array_header(&mut hdr, 5);
        cbor_uint(&mut hdr, protver as u64);
        cbor_bstr(&mut hdr, guid);
        hdr.push(0x80); // OVRVInfo = empty array
        cbor_tstr(&mut hdr, device_info);
        let pk = build_test_fdo_public_key(mfg_key_point);
        hdr.extend_from_slice(&pk);
        hdr
    }

    #[test]
    fn test_verify_voucher_wrong_domain_aad() {
        // FDO 2.0 uses domain AAD. Entry signed with BMO_PROVISION AAD
        // instead of OV_ENTRY AAD must fail.
        let (mfg_sk, mfg_point) = gen_test_keypair();
        let (_, owner_point) = gen_test_keypair_b();
        let guid = [0xDDu8; 16];
        // protver=200 so domain AAD is active
        let hdr = build_test_ov_header_v(&guid, "aad-test", &mfg_point, 200);
        let hmac_digest = hmac_sha256(&[0xEEu8; 32], &hdr);
        let hmac_cbor = build_hmac_cbor(&hmac_digest);

        let hash_hdr = {
            let mut h = Sha256::new();
            h.update(&guid);
            h.update(b"aad-test");
            h.finalize().to_vec()
        };
        let hash_prev = {
            let mut h = Sha256::new();
            h.update(&hdr);
            h.update(&hmac_cbor);
            h.finalize().to_vec()
        };

        let payload = build_ov_entry_payload(&hash_prev, &hash_hdr, &owner_point);
        let protected = cose::build_test_protected_header(None);
        // Sign with WRONG AAD (BMO tag instead of OV_ENTRY)
        let wrong_aad = cose::domain_aad(cose::AAD_TAG_BMO_PROVISION, 200);
        let entry = cose::build_test_cose_sign1(
            &protected, &payload, &wrong_aad, &[0xa0], &mfg_sk,
        );

        let result = verify_voucher(&hdr, &hmac_cbor, &hmac_digest, 0, &guid, &[entry]);
        assert!(matches!(result, Err(VoucherError::EntrySignatureInvalid(0))),
            "entry signed with wrong domain AAD must fail signature verification");
    }

    // ---- 2-entry chain: second entry signed by wrong key ----

    #[test]
    fn test_verify_voucher_chain_break_at_entry_1() {
        let (mfg_sk, mfg_point) = gen_test_keypair();
        let (_, reseller_point) = gen_test_keypair_b();
        // Attacker signs entry 1 instead of reseller
        let attacker_secret = p256::SecretKey::from_bytes(
            &[0xAA; 32].into(),
        ).unwrap();
        let attacker_sk = p256::ecdsa::SigningKey::from(attacker_secret.clone());
        let owner_point = {
            let pk = attacker_secret.public_key();
            p256::EncodedPoint::from(pk).as_bytes().to_vec()
        };

        let guid = [0xEEu8; 16];
        let hdr = build_test_ov_header(&guid, "chain-break", &mfg_point);
        let hmac_digest = hmac_sha256(&[0xFFu8; 32], &hdr);
        let hmac_cbor = build_hmac_cbor(&hmac_digest);

        let hash_hdr = {
            let mut h = Sha256::new();
            h.update(&guid);
            h.update(b"chain-break");
            h.finalize().to_vec()
        };

        // Entry 0: valid (mfg → reseller)
        let hash_prev_0 = {
            let mut h = Sha256::new();
            h.update(&hdr);
            h.update(&hmac_cbor);
            h.finalize().to_vec()
        };
        let payload_0 = build_ov_entry_payload(&hash_prev_0, &hash_hdr, &reseller_point);
        let aad = cose::domain_aad(cose::AAD_TAG_OV_ENTRY, 101);
        let protected = cose::build_test_protected_header(None);
        let entry_0 = cose::build_test_cose_sign1(
            &protected, &payload_0, &aad, &[0xa0], &mfg_sk,
        );

        // Entry 1: signed by ATTACKER, not reseller
        let hash_prev_1 = {
            let mut h = Sha256::new();
            h.update(&entry_0);
            h.finalize().to_vec()
        };
        let payload_1 = build_ov_entry_payload(&hash_prev_1, &hash_hdr, &owner_point);
        let entry_1 = cose::build_test_cose_sign1(
            &protected, &payload_1, &aad, &[0xa0], &attacker_sk,
        );

        let result = verify_voucher(&hdr, &hmac_cbor, &hmac_digest, 0, &guid,
            &[entry_0, entry_1]);
        assert!(matches!(result, Err(VoucherError::EntrySignatureInvalid(1))),
            "entry 1 signed by attacker (not reseller) must fail at index 1");
    }
}
