// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// COSE_Sign1 Signature Verification for RV-Based Firmware Delivery
//
// Parses COSE_Sign1 (RFC 9052) envelopes and verifies ECDSA P-256 (ES256)
// signatures using the `p256` crate. Extracts the FDO FirmwarePayload
// from verified envelopes.

use alloc::string::String;
use alloc::vec::Vec;
use log::{info, warn, error};
use sha2::{Sha256, Sha384, Digest};

use super::platform_key;

/// COSE Algorithm identifiers (RFC 9053)
const COSE_ALG_ES256: i32 = -7;

/// COSE hash algorithm identifiers (IANA COSE Algorithms registry)
const COSE_ALG_SHA256: i32 = -16;
const COSE_ALG_SHA384: i32 = -43;

/// FDO Firmware payload magic number ("FDOF")
const FW_MAGIC: u32 = 0x46444F46;

/// Parsed COSE_Sign1 structure (references into original data)
struct CoseSign1<'a> {
    algorithm: i32,
    protected_header: &'a [u8],
    payload: &'a [u8],
    signature: &'a [u8],
}

/// Parsed FDO firmware payload
#[derive(Debug)]
pub struct FirmwarePayload {
    pub magic: u32,
    pub version: u32,
    pub platform_type: String,
    pub architecture: String,
    pub image_type: u32,
    pub timestamp: u64,
    pub firmware_rev: u64,
    pub build_id: Option<String>,
    pub image_hash: Vec<u8>,
    pub image_hash_type: i32,
    pub image_offset: usize,
    pub image_size: usize,
}

/// Result of firmware verification and extraction
pub enum VerifyResult {
    /// Verification succeeded, firmware image extracted
    Ok(FirmwarePayload, Vec<u8>),
    /// Parse error
    ParseError(&'static str),
    /// Signature verification failed
    SignatureInvalid,
    /// Algorithm not supported
    UnsupportedAlgorithm(i32),
    /// Architecture mismatch
    ArchitectureMismatch(String),
    /// FWImageHash did not match the extracted image bytes
    ImageHashMismatch,
    /// FWImageHash used a hash algorithm we cannot compute
    UnsupportedHashAlgorithm(i32),
}

/// Verify and extract firmware from a COSE_Sign1 signed image.
/// This is the high-level API combining parse, verify, and payload extraction.
pub fn verify_firmware(signed_data: &[u8]) -> VerifyResult {
    // 1. Parse COSE_Sign1 envelope
    let sign1 = match parse_cose_sign1(signed_data) {
        Some(s) => s,
        None => return VerifyResult::ParseError("Failed to parse COSE_Sign1"),
    };

    info!("COSE: Parsed Sign1: alg={}, protected={} bytes, payload={} bytes, sig={} bytes",
          sign1.algorithm, sign1.protected_header.len(), sign1.payload.len(), sign1.signature.len());

    // 2. Check algorithm
    if sign1.algorithm != COSE_ALG_ES256 {
        return VerifyResult::UnsupportedAlgorithm(sign1.algorithm);
    }

    // 3. Verify signature
    if !verify_signature(&sign1) {
        return VerifyResult::SignatureInvalid;
    }
    info!("COSE: Signature VALID");

    // 4. Parse firmware payload
    let payload = match parse_firmware_payload(sign1.payload) {
        Some(p) => p,
        None => return VerifyResult::ParseError("Failed to parse firmware payload"),
    };

    info!("COSE: Firmware: platform={}, arch={}, rev={}, image={} bytes",
          payload.platform_type, payload.architecture, payload.firmware_rev, payload.image_size);

    // 5. Check architecture
    if payload.architecture != "x86_64" {
        return VerifyResult::ArchitectureMismatch(payload.architecture.clone());
    }

    // 6. Extract image data
    if payload.image_offset + payload.image_size > sign1.payload.len() {
        return VerifyResult::ParseError("Image extends beyond payload");
    }
    let image_data = sign1.payload[payload.image_offset..payload.image_offset + payload.image_size].to_vec();

    // 7. Verify FWImageHash against the extracted image bytes.
    //
    // The COSE signature already covers these bytes, so this is a defence-in-depth
    // check: it catches a mis-parsed image_offset/image_size (which would extract
    // authentic-but-wrong bytes) and a producer whose declared hash disagrees with
    // what it actually embedded. Chainloading a mis-sliced PE is exactly how you
    // get a wild jump into garbage, so refuse rather than guess.
    match verify_image_hash(&payload, &image_data) {
        HashCheck::Ok => info!("COSE: FWImageHash verified OK ({} bytes)", image_data.len()),
        HashCheck::Mismatch => {
            error!("COSE: FWImageHash MISMATCH — extracted image does not match declared hash");
            error!("COSE: REFUSING to chainload (image would be untrustworthy)");
            return VerifyResult::ImageHashMismatch;
        }
        HashCheck::Unsupported(alg) => {
            error!("COSE: Unsupported FWImageHash algorithm {} — cannot verify image", alg);
            return VerifyResult::UnsupportedHashAlgorithm(alg);
        }
    }

    VerifyResult::Ok(payload, image_data)
}

/// Outcome of the FWImageHash check
enum HashCheck {
    Ok,
    Mismatch,
    Unsupported(i32),
}

/// Compute the digest of `image` per the payload's declared hash algorithm and
/// compare it to the declared FWImageHash.
///
/// A missing (empty) hash is treated as a mismatch: the payload format requires
/// FWImageHash, so its absence means we cannot establish image integrity and we
/// must not chainload.
fn verify_image_hash(payload: &FirmwarePayload, image: &[u8]) -> HashCheck {
    if payload.image_hash.is_empty() {
        error!("COSE: FWImageHash is empty — cannot verify image integrity");
        return HashCheck::Mismatch;
    }

    let computed: Vec<u8> = match payload.image_hash_type {
        COSE_ALG_SHA256 => {
            let mut h = Sha256::new();
            h.update(image);
            h.finalize().to_vec()
        }
        COSE_ALG_SHA384 => {
            let mut h = Sha384::new();
            h.update(image);
            h.finalize().to_vec()
        }
        other => return HashCheck::Unsupported(other),
    };

    if computed.len() != payload.image_hash.len() {
        error!("COSE: FWImageHash length mismatch: declared {} bytes, computed {} bytes",
               payload.image_hash.len(), computed.len());
        return HashCheck::Mismatch;
    }

    if computed != payload.image_hash {
        error!("COSE: Declared: {:02x?}", &payload.image_hash[..core::cmp::min(16, payload.image_hash.len())]);
        error!("COSE: Computed: {:02x?}", &computed[..core::cmp::min(16, computed.len())]);
        return HashCheck::Mismatch;
    }

    HashCheck::Ok
}

/// Parse a COSE_Sign1 envelope from CBOR data.
/// COSE_Sign1 = [ protected: bstr, unprotected: map, payload: bstr/nil, signature: bstr ]
/// Optionally wrapped in CBOR tag 18.
fn parse_cose_sign1(data: &[u8]) -> Option<CoseSign1<'_>> {
    let mut pos = 0;

    // Check for optional COSE_Sign1 tag (18)
    let b = *data.get(pos)?;
    if (b >> 5) == 6 {
        // Tag — consume the initial byte and read the tag number
        pos += 1;
        let tag_val = cbor_read_uint_arg(data, &mut pos, b & 0x1f)?;
        if tag_val != 18 {
            warn!("COSE: Expected tag 18, got {}", tag_val);
        }
    }

    // Must be a 4-element array
    let b = *data.get(pos)?;
    pos += 1;
    if (b >> 5) != 4 {
        warn!("COSE: Expected array, got major {}", b >> 5);
        return None;
    }
    let arr_len = cbor_read_uint_arg(data, &mut pos, b & 0x1f)?;
    if arr_len != 4 {
        warn!("COSE: Expected 4-element array, got {}", arr_len);
        return None;
    }

    // Element 0: protected header (bstr)
    let protected_header = cbor_read_bstr(data, &mut pos)?;

    // Parse algorithm from protected header
    let algorithm = parse_protected_header_alg(protected_header);

    // Element 1: unprotected header (map) — skip
    cbor_skip(data, &mut pos)?;

    // Element 2: payload (bstr or nil)
    let payload_byte = *data.get(pos)?;
    let payload = if payload_byte == 0xf6 {
        // nil (CBOR simple value 22)
        pos += 1;
        &data[0..0] // empty slice
    } else {
        cbor_read_bstr(data, &mut pos)?
    };

    // Element 3: signature (bstr)
    let signature = cbor_read_bstr(data, &mut pos)?;

    Some(CoseSign1 {
        algorithm,
        protected_header,
        payload,
        signature,
    })
}

/// Extract algorithm from protected header (CBOR map with key 1 = alg)
fn parse_protected_header_alg(header: &[u8]) -> i32 {
    if header.is_empty() {
        return 0;
    }
    let mut pos = 0;
    let b = match header.get(pos) {
        Some(&b) => b,
        None => return 0,
    };
    pos += 1;

    if (b >> 5) != 5 {
        return 0; // Not a map
    }
    let map_len = match cbor_read_uint_arg(header, &mut pos, b & 0x1f) {
        Some(n) => n,
        None => return 0,
    };

    for _ in 0..map_len {
        // Read key
        let key = cbor_read_int_value(header, &mut pos);
        // Read value
        let val = cbor_read_int_value(header, &mut pos);

        if let (Some(k), Some(v)) = (key, val) {
            if k == 1 {
                // Algorithm header label
                return v as i32;
            }
        }
    }

    0
}

/// Verify COSE_Sign1 signature using P-256 ECDSA.
/// Builds the Sig_structure as raw CBOR bytes and passes to ECDSA verify
/// (which internally hashes with SHA-256 per ES256).
fn verify_signature(sign1: &CoseSign1) -> bool {
    // Build Sig_structure = ["Signature1", protected, external_aad, payload]
    // as raw CBOR bytes. ECDSA verify() hashes internally with SHA-256.
    let mut sig_structure = Vec::new();

    // CBOR: 4-element array header
    sig_structure.push(0x84);

    // context: "Signature1" (text string, 10 bytes)
    sig_structure.push(0x6A); // tstr(10)
    sig_structure.extend_from_slice(b"Signature1");

    // body_protected: bstr wrapping the protected header
    cbor_encode_bstr_header(&mut sig_structure, sign1.protected_header.len());
    sig_structure.extend_from_slice(sign1.protected_header);

    // external_aad: empty bstr
    sig_structure.push(0x40);

    // payload: bstr
    cbor_encode_bstr_header(&mut sig_structure, sign1.payload.len());
    sig_structure.extend_from_slice(sign1.payload);

    // Verify with P-256 ECDSA (verify() does SHA-256 internally)
    verify_ecdsa_p256(&sig_structure, sign1.signature)
}

/// Encode a CBOR bstr length header into a buffer
fn cbor_encode_bstr_header(buf: &mut Vec<u8>, len: usize) {
    if len < 24 {
        buf.push(0x40 | (len as u8));
    } else if len < 256 {
        buf.push(0x58);
        buf.push(len as u8);
    } else if len < 65536 {
        buf.push(0x59);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else {
        buf.push(0x5A);
        buf.push((len >> 24) as u8);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

/// Verify ECDSA P-256 signature against the hardcoded platform key.
/// `message` is the raw CBOR-encoded Sig_structure bytes (verify() hashes internally).
fn verify_ecdsa_p256(message: &[u8], signature: &[u8]) -> bool {
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    use p256::EncodedPoint;

    if signature.len() != 64 {
        error!("COSE: Signature length {} != 64", signature.len());
        return false;
    }

    // Build uncompressed point: 0x04 || X || Y
    let point = EncodedPoint::from_affine_coordinates(
        p256::FieldBytes::from_slice(&platform_key::PLATFORM_KEY_X),
        p256::FieldBytes::from_slice(&platform_key::PLATFORM_KEY_Y),
        false, // uncompressed
    );

    let verifying_key = match VerifyingKey::from_encoded_point(&point) {
        Ok(k) => k,
        Err(e) => {
            error!("COSE: Invalid platform key: {:?}", e);
            return false;
        }
    };

    // Signature is r || s (32 bytes each for P-256)
    let sig = match Signature::from_slice(signature) {
        Ok(s) => s,
        Err(e) => {
            error!("COSE: Invalid signature format: {:?}", e);
            return false;
        }
    };

    match verifying_key.verify(message, &sig) {
        Ok(()) => true,
        Err(_) => {
            warn!("COSE: Signature verification failed");
            false
        }
    }
}

/// Parse FDO FirmwarePayload from CBOR.
/// FirmwarePayload is a 10-element array:
/// [Magic, Version, PlatformType, Architecture, ImageType, Timestamp,
///  FirmwareRev, BuildId, ImageHash, Image]
fn parse_firmware_payload(data: &[u8]) -> Option<FirmwarePayload> {
    let mut pos = 0;

    // Array header
    let b = *data.get(pos)?;
    pos += 1;
    if (b >> 5) != 4 {
        warn!("COSE: Payload not an array");
        return None;
    }
    let arr_len = cbor_read_uint_arg(data, &mut pos, b & 0x1f)?;
    if arr_len != 10 {
        warn!("COSE: Expected 10-element payload array, got {}", arr_len);
        return None;
    }

    // [0] Magic (uint)
    let magic = cbor_read_uint_value(data, &mut pos)? as u32;
    if magic != FW_MAGIC {
        warn!("COSE: Invalid magic 0x{:08x}", magic);
        return None;
    }

    // [1] Version (uint)
    let version = cbor_read_uint_value(data, &mut pos)? as u32;

    // [2] PlatformType (tstr)
    let platform_type = cbor_read_tstr(data, &mut pos)?;

    // [3] Architecture (tstr)
    let architecture = cbor_read_tstr(data, &mut pos)?;

    // [4] ImageType (uint)
    let image_type = cbor_read_uint_value(data, &mut pos)? as u32;

    // [5] Timestamp (uint)
    let timestamp = cbor_read_uint_value(data, &mut pos)? as u64;

    // [6] FirmwareRev (uint)
    let firmware_rev = cbor_read_uint_value(data, &mut pos)? as u64;

    // [7] BuildId (tstr or null)
    let build_id = {
        let b = *data.get(pos)?;
        if b == 0xf6 {
            pos += 1;
            None
        } else {
            Some(cbor_read_tstr(data, &mut pos)?)
        }
    };

    // [8] ImageHash: [hashtype: int, hash: bstr]
    let (image_hash_type, image_hash) = {
        let b = *data.get(pos)?;
        pos += 1;
        if (b >> 5) != 4 {
            return None;
        }
        let hl = cbor_read_uint_arg(data, &mut pos, b & 0x1f)?;
        if hl != 2 {
            return None;
        }
        let ht = cbor_read_int_value(data, &mut pos)? as i32;
        let hv = cbor_read_bstr(data, &mut pos)?.to_vec();
        (ht, hv)
    };

    // [9] Image (bstr) — record offset and size, don't copy
    let b = *data.get(pos)?;
    pos += 1;
    if (b >> 5) != 2 {
        return None;
    }
    let image_size = cbor_read_uint_arg(data, &mut pos, b & 0x1f)?;
    let image_offset = pos;

    Some(FirmwarePayload {
        magic,
        version,
        platform_type,
        architecture,
        image_type,
        timestamp,
        firmware_rev,
        build_id,
        image_hash,
        image_hash_type,
        image_offset,
        image_size,
    })
}

// --- CBOR helpers ---

fn cbor_read_uint_arg(data: &[u8], pos: &mut usize, additional: u8) -> Option<usize> {
    if additional < 24 {
        Some(additional as usize)
    } else if additional == 24 {
        let v = *data.get(*pos)? as usize;
        *pos += 1;
        Some(v)
    } else if additional == 25 {
        let hi = *data.get(*pos)? as usize;
        let lo = *data.get(*pos + 1)? as usize;
        *pos += 2;
        Some((hi << 8) | lo)
    } else if additional == 26 {
        let b0 = *data.get(*pos)? as usize;
        let b1 = *data.get(*pos + 1)? as usize;
        let b2 = *data.get(*pos + 2)? as usize;
        let b3 = *data.get(*pos + 3)? as usize;
        *pos += 4;
        Some((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
    } else if additional == 27 {
        let mut v: usize = 0;
        for i in 0..8 {
            v = (v << 8) | (*data.get(*pos + i)? as usize);
        }
        *pos += 8;
        Some(v)
    } else {
        None
    }
}

fn cbor_read_uint_value(data: &[u8], pos: &mut usize) -> Option<usize> {
    let b = *data.get(*pos)?;
    *pos += 1;
    let major = b >> 5;
    if major == 6 {
        // Tag — read tag value then recurse
        let _tag = cbor_read_uint_arg(data, pos, b & 0x1f)?;
        return cbor_read_uint_value(data, pos);
    }
    if major != 0 {
        return None;
    }
    cbor_read_uint_arg(data, pos, b & 0x1f)
}

fn cbor_read_int_value(data: &[u8], pos: &mut usize) -> Option<i64> {
    let b = *data.get(*pos)?;
    *pos += 1;
    let major = b >> 5;
    let val = cbor_read_uint_arg(data, pos, b & 0x1f)? as i64;
    match major {
        0 => Some(val),
        1 => Some(-1 - val),
        _ => None,
    }
}

fn cbor_read_bstr<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let b = *data.get(*pos)?;
    *pos += 1;
    if (b >> 5) != 2 {
        return None;
    }
    let len = cbor_read_uint_arg(data, pos, b & 0x1f)?;
    if *pos + len > data.len() {
        return None;
    }
    let result = &data[*pos..*pos + len];
    *pos += len;
    Some(result)
}

fn cbor_read_tstr(data: &[u8], pos: &mut usize) -> Option<String> {
    let b = *data.get(*pos)?;
    *pos += 1;
    if (b >> 5) != 3 {
        return None;
    }
    let len = cbor_read_uint_arg(data, pos, b & 0x1f)?;
    if *pos + len > data.len() {
        return None;
    }
    let s = core::str::from_utf8(&data[*pos..*pos + len]).ok()?;
    *pos += len;
    Some(String::from(s))
}

fn cbor_skip(data: &[u8], pos: &mut usize) -> Option<()> {
    let b = *data.get(*pos)?;
    *pos += 1;
    let major = b >> 5;
    let arg = cbor_read_uint_arg(data, pos, b & 0x1f)?;

    match major {
        0 | 1 | 7 => {} // uint, negint, simple
        2 | 3 => {
            // bstr, tstr
            if *pos + arg > data.len() {
                return None;
            }
            *pos += arg;
        }
        4 => {
            for _ in 0..arg {
                cbor_skip(data, pos)?;
            }
        }
        5 => {
            for _ in 0..arg * 2 {
                cbor_skip(data, pos)?;
            }
        }
        6 => {
            cbor_skip(data, pos)?;
        }
        _ => return None,
    }
    Some(())
}
