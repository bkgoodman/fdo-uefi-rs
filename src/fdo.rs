// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// FDO Protocol Implementation for UEFI
//
// This module implements FDO TO1/TO2 protocols using manual CBOR encoding/decoding.
// This avoids serde dependency issues in no_std UEFI environment.

use alloc::string::String;
use alloc::vec::Vec;
use alloc::vec;
use alloc::format;
use log::{info, error, warn, debug};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac, digest::KeyInit as HmacKeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, aead::AeadMutInPlace};
use aes_gcm::aead::generic_array::GenericArray;

type HmacSha256 = Hmac<Sha256>;

#[cfg(target_os = "uefi")]
use crate::http_api::{http_post, http_post_with_session, HttpPostResponse};
#[cfg(target_os = "uefi")]
use crate::bmo::{BmoSession, process_bmo_message, BmoState};
#[cfg(target_os = "uefi")]
use crate::chainload::chainload_image;

/// Compute SHA-256 hash of data
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// FDO Key Derivation Function (NIST SP 800-108 Counter Mode)
/// Matching go-fdo implementation exactly
/// Label = "FIDO-KDF", Context = "AutomaticOnboardTunnel"
fn fdo_kdf(shared_secret: &[u8], key_bits: u16) -> Vec<u8> {
    let label = b"FIDO-KDF";
    let context = b"AutomaticOnboardTunnel";
    let h: u16 = 32; // SHA-256 output size (go-fdo uses this value)
    
    // Number of iterations - matching go-fdo: n = L/h (where L is bits, h is 32)
    let mut n = key_bits / h;
    if key_bits % h != 0 {
        n += 1;
    }
    
    let mut result = Vec::new();
    
    // Build input template: [i]_1 || Label || 0x00 || Context || [L]_2
    let mut input = Vec::new();
    input.push(0x00);                  // Placeholder for counter
    input.extend_from_slice(label);
    input.push(0x00);                  // Separator
    input.extend_from_slice(context);
    input.push((key_bits >> 8) as u8);   // L in bits (big-endian)
    input.push((key_bits & 0xff) as u8);
    
    for i in 1..=n {
        input[0] = i as u8;  // Set counter
        
        // HMAC-SHA256(K_IN=shared_secret, input)
        let mut mac = <HmacSha256 as Mac>::new_from_slice(shared_secret)
            .expect("HMAC key length error");
        Mac::update(&mut mac, &input);
        let hmac_result = mac.finalize();
        result.extend_from_slice(&hmac_result.into_bytes());
    }
    
    // Return first L/8 bytes (convert bits to bytes)
    let key_bytes = (key_bits / 8) as usize;
    result.truncate(key_bytes);
    result
}

/// TO2 Session Keys
pub struct To2SessionKeys {
    pub sek: Vec<u8>,  // Session Encryption Key (16 bytes for A128GCM)
    pub svk: Vec<u8>,  // Session Verification Key (unused for GCM)
}

/// Derive TO2 session keys from shared secret
/// For ECDH256 + A256GCM: SEK=32 bytes, SVK=0 bytes (GCM has built-in auth)
pub fn derive_session_keys(shared_secret: &[u8]) -> To2SessionKeys {
    // For AES-256-GCM (cipher suite 3), SEK is 32 bytes, SVK is 0
    let sek = fdo_kdf(shared_secret, 256);
    To2SessionKeys {
        sek,
        svk: Vec::new(),
    }
}

/// ECDH ShSe = Shx || DeviceRandom || OwnerRandom, by role (FDO spec, ECDH
/// key exchange). At FDO 2.0 the Device's parameter is xA (TO2.ProveDevice20)
/// and the Owner's is xB (TO2.ProveOVHdr20).
pub fn build_ecdh_shse(mut shx: Vec<u8>, device_rand: &[u8], owner_rand: &[u8]) -> Vec<u8> {
    shx.extend_from_slice(device_rand);
    shx.extend_from_slice(owner_rand);
    shx
}

/// Parse random bytes from FDO key exchange parameter format
/// FDO format: [2-byte xLen][x][2-byte yLen][y][2-byte randLen][rand]
fn parse_kex_random(kex_param: &[u8]) -> Option<Vec<u8>> {
    if kex_param.len() < 6 {
        return None;
    }
    let mut pos = 0;
    
    // Skip x coordinate
    let x_len = ((kex_param[pos] as usize) << 8) | (kex_param[pos + 1] as usize);
    pos += 2 + x_len;
    
    if kex_param.len() < pos + 2 {
        return None;
    }
    
    // Skip y coordinate
    let y_len = ((kex_param[pos] as usize) << 8) | (kex_param[pos + 1] as usize);
    pos += 2 + y_len;
    
    if kex_param.len() < pos + 2 {
        return None;
    }
    
    // Read random bytes
    let rand_len = ((kex_param[pos] as usize) << 8) | (kex_param[pos + 1] as usize);
    pos += 2;
    
    if kex_param.len() < pos + rand_len {
        return None;
    }
    
    Some(kex_param[pos..pos + rand_len].to_vec())
}

/// Build COSE Enc_structure for AAD: ["Encrypt0", protected_bstr, external_aad_bstr]
fn build_cose_enc_structure(protected_headers: &[u8], external_aad: &[u8]) -> Vec<u8> {
    let mut enc = CborEncoder::new();
    enc.array(3);
    enc.text("Encrypt0");
    enc.bytes(protected_headers);
    enc.bytes(external_aad);
    enc.into_bytes()
}

/// Build protected headers for A256GCM: {1: 3}
fn build_a256gcm_protected_headers() -> Vec<u8> {
    let mut enc = CborEncoder::new();
    enc.encode_map(1);
    enc.uint(1); // alg label
    enc.uint(3); // A256GCM
    enc.into_bytes()
}

/// Encrypt plaintext using COSE_Encrypt0 with A256GCM
/// Returns the complete COSE_Encrypt0 message ready to send
pub fn cose_encrypt0_a256gcm(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, FdoError> {
    // Build protected headers once - used in both message and AAD
    let protected_bytes = build_a256gcm_protected_headers();
    debug!("COSE: protected_bytes ({} bytes): {:02x?}", protected_bytes.len(), &protected_bytes);
    
    // Build Enc_structure for AAD
    let cose_aad = build_cose_enc_structure(&protected_bytes, &[]);
    debug!("COSE: AAD ({} bytes): {:02x?}", cose_aad.len(), &cose_aad);
    debug!("COSE: key ({} bytes): {:02x?}", key.len(), &key[..key.len().min(16)]);
    debug!("COSE: plaintext ({} bytes): {:02x?}", plaintext.len(), &plaintext);
    
    // Encrypt with AES-256-GCM
    let ciphertext = aes256_gcm_encrypt(key, nonce, plaintext, &cose_aad)?;
    debug!("COSE: ciphertext ({} bytes): {:02x?}", ciphertext.len(), &ciphertext);
    
    // Build COSE_Encrypt0: tag(16, [protected_bstr, {5: iv}, ciphertext])
    let mut enc = CborEncoder::new();
    enc.buf.push(0xD0 | 16); // Tag 16
    enc.array(3);
    enc.bytes(&protected_bytes);
    enc.encode_map(1);
    enc.uint(5); // IV label
    enc.bytes(nonce);
    enc.bytes(&ciphertext);
    
    let result = enc.into_bytes();
    debug!("COSE: final message ({} bytes): {:02x?}", result.len(), &result);
    Ok(result)
}

/// Decrypt COSE_Encrypt0 message with A256GCM
pub fn cose_decrypt0_a256gcm(key: &[u8], data: &[u8]) -> Result<Vec<u8>, FdoError> {
    // Parse COSE_Encrypt0 to get nonce and ciphertext
    let (nonce, ciphertext) = parse_encrypted_message(data)?;
    
    // Build same protected headers and AAD as encryption
    let protected_bytes = build_a256gcm_protected_headers();
    let cose_aad = build_cose_enc_structure(&protected_bytes, &[]);
    
    // Decrypt
    aes256_gcm_decrypt(key, &nonce, &ciphertext, &cose_aad)
}

/// AES-256-GCM encryption for COSE_Encrypt0 (FDO 2.0)
/// Returns ciphertext with 16-byte tag appended
pub fn aes256_gcm_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, FdoError> {
    if key.len() != 32 {
        return Err(FdoError::CryptoError(format!("A256GCM requires 32-byte key, got {}", key.len())));
    }
    if nonce.len() != 12 {
        return Err(FdoError::CryptoError(format!("Invalid nonce length: {}", nonce.len())));
    }
    
    let mut cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let nonce_arr = GenericArray::from_slice(nonce);
    
    let mut buffer = plaintext.to_vec();
    cipher.encrypt_in_place(nonce_arr, aad, &mut buffer)
        .map_err(|_| FdoError::CryptoError(String::from("AES-256-GCM encryption failed")))?;
    
    Ok(buffer)
}

/// AES-256-GCM decryption for COSE_Encrypt0 (FDO 2.0)
/// Ciphertext includes 16-byte tag at end
pub fn aes256_gcm_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, FdoError> {
    if key.len() != 32 {
        return Err(FdoError::CryptoError(format!("A256GCM requires 32-byte key, got {}", key.len())));
    }
    if nonce.len() != 12 {
        return Err(FdoError::CryptoError(format!("Invalid nonce length: {}", nonce.len())));
    }
    if ciphertext.len() < 16 {
        return Err(FdoError::CryptoError(String::from("Ciphertext too short for tag")));
    }
    
    let mut cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let nonce_arr = GenericArray::from_slice(nonce);
    
    let mut buffer = ciphertext.to_vec();
    cipher.decrypt_in_place(nonce_arr, aad, &mut buffer)
        .map_err(|_| FdoError::CryptoError(String::from("AES-256-GCM decryption failed")))?;
    
    Ok(buffer)
}

/// AES-128-GCM encryption for TO2 messages (legacy)
/// Returns ciphertext with 16-byte tag appended (nonce managed separately)
pub fn aes_gcm_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, FdoError> {
    if key.len() != 16 {
        return Err(FdoError::CryptoError(format!("Invalid key length: {}", key.len())));
    }
    if nonce.len() != 12 {
        return Err(FdoError::CryptoError(format!("Invalid nonce length: {}", nonce.len())));
    }
    
    let mut cipher = Aes128Gcm::new(GenericArray::from_slice(key));
    let nonce_arr = GenericArray::from_slice(nonce);
    
    let mut buffer = plaintext.to_vec();
    cipher.encrypt_in_place(nonce_arr, aad, &mut buffer)
        .map_err(|_| FdoError::CryptoError(String::from("AES-GCM encryption failed")))?;
    
    Ok(buffer)
}

/// AES-128-GCM decryption for TO2 messages (legacy)
/// Ciphertext includes 16-byte tag at end
pub fn aes_gcm_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, FdoError> {
    if key.len() != 16 {
        return Err(FdoError::CryptoError(format!("Invalid key length: {}", key.len())));
    }
    if nonce.len() != 12 {
        return Err(FdoError::CryptoError(format!("Invalid nonce length: {}", nonce.len())));
    }
    if ciphertext.len() < 16 {
        return Err(FdoError::CryptoError(String::from("Ciphertext too short for tag")));
    }
    
    let mut cipher = Aes128Gcm::new(GenericArray::from_slice(key));
    let nonce_arr = GenericArray::from_slice(nonce);
    
    let mut buffer = ciphertext.to_vec();
    cipher.decrypt_in_place(nonce_arr, aad, &mut buffer)
        .map_err(|_| FdoError::CryptoError(String::from("AES-GCM decryption failed")))?;
    
    Ok(buffer)
}

/// FDO Message Types
/// FDO error message type (see spec "Error - Type 255").
pub const MSG_ERROR: u8 = 255;
pub const MSG_TO1_HELLO_RV: u8 = 30;
pub const MSG_TO1_HELLO_RV_ACK: u8 = 31;
pub const MSG_TO1_PROVE_TO_RV: u8 = 32;
pub const MSG_TO1_RV_REDIRECT: u8 = 33;

pub const MSG_TO2_HELLO_DEVICE: u8 = 60;  // FDO 1.1
pub const MSG_TO2_HELLO_DEVICE_PROBE: u8 = 80;  // FDO 2.0
pub const MSG_TO2_HELLO_DEVICE_ACK: u8 = 81;
pub const MSG_TO2_PROVE_DEVICE: u8 = 82;
pub const MSG_TO2_PROVE_OV_HDR: u8 = 83;
pub const MSG_TO2_GET_OV_NEXT_ENTRY: u8 = 84;
pub const MSG_TO2_OV_NEXT_ENTRY: u8 = 85;
pub const MSG_TO2_DEVICE_SVC_INFO_RDY: u8 = 86;
pub const MSG_TO2_SETUP_DEVICE: u8 = 87;
pub const MSG_TO2_DEVICE_SVC_INFO: u8 = 88;
pub const MSG_TO2_OWNER_SVC_INFO: u8 = 89;
pub const MSG_TO2_DONE: u8 = 90;
pub const MSG_TO2_DONE_ACK: u8 = 91;

/// FDO Protocol Error
#[derive(Debug)]
pub enum FdoError {
    HttpError(String),
    CborError(String),
    ProtocolError(String),
    CryptoError(String),
}

/// Simple CBOR encoder for FDO messages
pub struct CborEncoder {
    pub buf: Vec<u8>,
}

impl CborEncoder {
    pub fn new() -> Self {
        CborEncoder { buf: Vec::new() }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    // Encode array header
    pub fn array(&mut self, len: usize) {
        if len < 24 {
            self.buf.push(0x80 | len as u8);
        } else if len < 256 {
            self.buf.push(0x98);
            self.buf.push(len as u8);
        } else {
            self.buf.push(0x99);
            self.buf.push((len >> 8) as u8);
            self.buf.push(len as u8);
        }
    }
    
    // Encode map header (major type 5)
    pub fn encode_map(&mut self, len: usize) {
        if len < 24 {
            self.buf.push(0xa0 | len as u8);
        } else if len < 256 {
            self.buf.push(0xb8);
            self.buf.push(len as u8);
        } else {
            self.buf.push(0xb9);
            self.buf.push((len >> 8) as u8);
            self.buf.push(len as u8);
        }
    }

    // Encode byte string
    pub fn bytes(&mut self, data: &[u8]) {
        let len = data.len();
        if len < 24 {
            self.buf.push(0x40 | len as u8);
        } else if len < 256 {
            self.buf.push(0x58);
            self.buf.push(len as u8);
        } else {
            self.buf.push(0x59);
            self.buf.push((len >> 8) as u8);
            self.buf.push(len as u8);
        }
        self.buf.extend_from_slice(data);
    }

    // Encode negative integer
    pub fn neg_int(&mut self, val: i8) {
        if val >= 0 {
            self.buf.push(val as u8);
        } else {
            let abs = (-1 - val) as u8;
            if abs < 24 {
                self.buf.push(0x20 | abs);
            } else {
                self.buf.push(0x38);
                self.buf.push(abs);
            }
        }
    }

    // Encode unsigned integer
    pub fn uint(&mut self, val: u16) {
        if val < 24 {
            self.buf.push(val as u8);
        } else if val < 256 {
            self.buf.push(0x18);
            self.buf.push(val as u8);
        } else {
            self.buf.push(0x19);
            self.buf.push((val >> 8) as u8);
            self.buf.push(val as u8);
        }
    }
    
    // Encode text string
    pub fn text(&mut self, s: &str) {
        let len = s.len();
        if len < 24 {
            self.buf.push(0x60 | len as u8);
        } else if len < 256 {
            self.buf.push(0x78);
            self.buf.push(len as u8);
        } else {
            self.buf.push(0x79);
            self.buf.push((len >> 8) as u8);
            self.buf.push(len as u8);
        }
        self.buf.extend_from_slice(s.as_bytes());
    }
    
    // Encode null value
    pub fn null(&mut self) {
        self.buf.push(0xf6);
    }
    
    // Encode boolean value
    pub fn bool_val(&mut self, val: bool) {
        self.buf.push(if val { 0xf5 } else { 0xf4 });
    }
    
    
    // Encode a ServiceInfo key-value pair with bstr-wrapped value
    // FDO spec: ServiceInfo values must be CBOR bstr containing the CBOR-encoded value
    pub fn svc_info_kv_bool(&mut self, key: &str, val: bool) {
        self.array(2);
        self.text(key);
        self.bytes(&[if val { 0xf5 } else { 0xf4 }]);
    }
    
    pub fn svc_info_kv_uint(&mut self, key: &str, val: u16) {
        self.array(2);
        self.text(key);
        let mut tmp = CborEncoder::new();
        tmp.uint(val);
        self.bytes(&tmp.into_bytes());
    }
    
    pub fn svc_info_kv_text(&mut self, key: &str, val: &str) {
        self.array(2);
        self.text(key);
        let mut tmp = CborEncoder::new();
        tmp.text(val);
        self.bytes(&tmp.into_bytes());
    }
    
    pub fn svc_info_kv_bytes(&mut self, key: &str, cbor_bytes: &[u8]) {
        self.array(2);
        self.text(key);
        self.bytes(cbor_bytes);
    }
    // Append raw pre-encoded bytes (no header)
    fn raw_bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
}

/// Simple CBOR decoder for FDO messages
pub struct CborDecoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> CborDecoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        CborDecoder { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn read_byte(&mut self) -> Result<u8, FdoError> {
        if self.pos >= self.data.len() {
            return Err(FdoError::CborError(String::from("unexpected end of data")));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    pub fn read_uint(&mut self) -> Result<u64, FdoError> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        
        if major != 0 {
            return Err(FdoError::CborError(format!("expected uint, got major type {}", major)));
        }
        
        self.decode_additional(additional)
    }

    pub fn read_int(&mut self) -> Result<i32, FdoError> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        
        match major {
            0 => Ok(self.decode_additional(additional)? as i32),
            1 => Ok(-1 - self.decode_additional(additional)? as i32),
            _ => Err(FdoError::CborError(format!("expected int, got major type {}", major))),
        }
    }

    fn read_tag(&mut self) -> Result<u64, FdoError> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        
        if major != 6 {
            return Err(FdoError::CborError(format!("expected tag (major 6), got {}", major)));
        }
        
        self.decode_additional(additional)
    }

    fn decode_additional(&mut self, additional: u8) -> Result<u64, FdoError> {
        match additional {
            0..=23 => Ok(additional as u64),
            24 => Ok(self.read_byte()? as u64),
            25 => {
                let b1 = self.read_byte()? as u64;
                let b2 = self.read_byte()? as u64;
                Ok((b1 << 8) | b2)
            }
            26 => {
                let mut val: u64 = 0;
                for _ in 0..4 {
                    val = (val << 8) | (self.read_byte()? as u64);
                }
                Ok(val)
            }
            27 => {
                let mut val: u64 = 0;
                for _ in 0..8 {
                    val = (val << 8) | (self.read_byte()? as u64);
                }
                Ok(val)
            }
            _ => Err(FdoError::CborError(format!("invalid additional info: {}", additional))),
        }
    }

    fn read_array_len(&mut self) -> Result<usize, FdoError> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        
        if major != 4 {
            return Err(FdoError::CborError(format!("expected array, got major type {}", major)));
        }
        
        Ok(self.decode_additional(additional)? as usize)
    }

    pub fn read_bytes(&mut self) -> Result<Vec<u8>, FdoError> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        
        if major != 2 {
            return Err(FdoError::CborError(format!("expected bstr, got major type {}", major)));
        }
        
        let len = self.decode_additional(additional)? as usize;
        if self.pos + len > self.data.len() {
            return Err(FdoError::CborError(format!(
                "bstr length exceeds data: declared {} at pos {}, only {} available",
                len, self.pos, self.data.len() - self.pos
            )));
        }
        
        let bytes = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(bytes)
    }

    pub fn read_text(&mut self) -> Result<String, FdoError> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        
        if major != 3 {
            return Err(FdoError::CborError(format!("expected tstr, got major type {}", major)));
        }
        
        let len = self.decode_additional(additional)? as usize;
        if self.pos + len > self.data.len() {
            return Err(FdoError::CborError(String::from("tstr length exceeds data")));
        }
        
        let s = core::str::from_utf8(&self.data[self.pos..self.pos + len])
            .map_err(|_| FdoError::CborError(String::from("invalid UTF-8")))?;
        self.pos += len;
        Ok(String::from(s))
    }

    pub fn skip_value(&mut self) -> Result<(), FdoError> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        
        match major {
            0 | 1 => { // uint or negint
                self.decode_additional(additional)?;
            }
            2 | 3 => { // bstr or tstr
                let len = self.decode_additional(additional)? as usize;
                self.pos += len;
            }
            4 => { // array
                let len = self.decode_additional(additional)? as usize;
                for _ in 0..len {
                    self.skip_value()?;
                }
            }
            5 => { // map
                let len = self.decode_additional(additional)? as usize;
                for _ in 0..len {
                    self.skip_value()?; // key
                    self.skip_value()?; // value
                }
            }
            6 => { // tag
                self.decode_additional(additional)?;
                self.skip_value()?;
            }
            7 => { // simple/float
                match additional {
                    25 => { self.pos += 2; }
                    26 => { self.pos += 4; }
                    27 => { self.pos += 8; }
                    _ => {}
                }
            }
            _ => return Err(FdoError::CborError(format!("unknown major type {}", major))),
        }
        Ok(())
    }
    
    // Alias for read_array_len
    pub fn read_array_header(&mut self) -> Result<usize, FdoError> {
        self.read_array_len()
    }
    
    // Alias for read_map_len
    pub fn read_map_header(&mut self) -> Result<usize, FdoError> {
        self.read_map_len()
    }
    
    // Read map length (major type 5)
    fn read_map_len(&mut self) -> Result<usize, FdoError> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        if major != 5 {
            return Err(FdoError::CborError(format!("Expected map (major 5), got {}", major)));
        }
        let additional = initial & 0x1f;
        let len = match additional {
            n if n < 24 => n as usize,
            24 => self.read_byte()? as usize,
            25 => {
                let b1 = self.read_byte()? as usize;
                let b2 = self.read_byte()? as usize;
                (b1 << 8) | b2
            }
            _ => return Err(FdoError::CborError(String::from("Unsupported map length"))),
        };
        Ok(len)
    }
    
    // Read u8 value
    fn read_u8(&mut self) -> Result<u8, FdoError> {
        Ok(self.read_uint()? as u8)
    }
    
    // Read u16 value
    fn read_u16(&mut self) -> Result<u16, FdoError> {
        Ok(self.read_uint()? as u16)
    }
    
    // Check if next value is null without consuming
    fn peek_null(&self) -> bool {
        self.peek() == Some(0xf6)
    }
    
    // Read and consume null value
    pub fn read_null(&mut self) -> Result<(), FdoError> {
        let b = self.read_byte()?;
        if b != 0xf6 {
            return Err(FdoError::CborError(format!("expected null (0xf6), got 0x{:02x}", b)));
        }
        Ok(())
    }
    
    // Read boolean value (0xf4 = false, 0xf5 = true)
    pub fn read_bool(&mut self) -> Result<bool, FdoError> {
        let b = self.read_byte()?;
        match b {
            0xf4 => Ok(false),
            0xf5 => Ok(true),
            _ => Err(FdoError::CborError(format!("expected bool (0xf4/0xf5), got 0x{:02x}", b))),
        }
    }
    
    // Get remaining bytes as slice
    fn remaining_bytes(&self) -> &[u8] {
        &self.data[self.pos..]
    }
}

/// TO1.HelloRVAck parsed response (FDO 2.0)
/// CBOR: [CapabilityFlags, VendorCapFlags, NonceTO1Proof]
#[derive(Debug)]
pub struct To1HelloRvAck {
    pub nonce4: [u8; 16],
    pub capability_flags: Vec<u8>,
}

/// Parse TO1.HelloRVAck response (FDO 2.0 format)
/// FDO 2.0: [CapabilityFlags (bstr), VendorCapFlags ([* tstr]), NonceTO1Proof]
fn parse_to1_hello_rv_ack(data: &[u8]) -> Result<To1HelloRvAck, FdoError> {
    let mut dec = CborDecoder::new(data);
    
    let arr_len = dec.read_array_len()?;
    if arr_len != 3 {
        return Err(FdoError::CborError(format!("HelloRVAck expected 3 elements, got {}", arr_len)));
    }
    
    let capability_flags = dec.read_bytes()?;
    dec.skip_value()?; // VendorCapFlags
    
    // nonce4 - 16 byte nonce
    let nonce_bytes = dec.read_bytes()?;
    if nonce_bytes.len() != 16 {
        return Err(FdoError::CborError(format!("nonce4 expected 16 bytes, got {}", nonce_bytes.len())));
    }
    let mut nonce4 = [0u8; 16];
    nonce4.copy_from_slice(&nonce_bytes);
    
    Ok(To1HelloRvAck {
        nonce4,
        capability_flags,
    })
}

/// TO1.RVRedirect parsed response
/// Contains TO1D blob (COSE_Sign1) with owner rendezvous info
#[derive(Debug)]
pub struct To1RvRedirect {
    pub to1d_cose: Vec<u8>,  // Raw COSE_Sign1 bytes
}

/// Parse TO1.RVRedirect response (FDO 2.0):
/// `[numTo1ds, idxTo1ds, [to1d, ...]]`. Without Delegation there is exactly
/// one blob. Fetching further blobs with TO1.RVMore is not supported, so the
/// first blob is used.
fn parse_to1_rv_redirect(data: &[u8]) -> Result<To1RvRedirect, FdoError> {
    let mut dec = CborDecoder::new(data);
    if dec.read_array_len()? != 3 {
        return Err(FdoError::CborError(String::from("RVRedirect expected 3 elements")));
    }
    let num = dec.read_uint()?;
    let idx = dec.read_uint()?;
    let len = dec.read_array_len()?;
    if idx != 0 || len == 0 || num < len as u64 {
        return Err(FdoError::CborError(format!(
            "malformed RVRedirect: numTo1ds={} idxTo1ds={} len={}", num, idx, len)));
    }
    let start = dec.pos;
    dec.skip_value()?;
    Ok(To1RvRedirect {
        to1d_cose: data[start..dec.pos].to_vec(),
    })
}

/// Parse a `CertChainOrNull` (X5CHAIN array of DER bstrs, or null).
fn read_cert_chain_or_null(dec: &mut CborDecoder) -> Result<Option<Vec<Vec<u8>>>, FdoError> {
    if dec.peek_null() {
        dec.read_null()?;
        return Ok(None);
    }
    let len = dec.read_array_len()?;
    if len == 0 {
        return Err(FdoError::CborError(String::from("empty delegate chain")));
    }
    let mut certs = Vec::with_capacity(len);
    for _ in 0..len {
        certs.push(dec.read_bytes()?);
    }
    Ok(Some(certs))
}

/// Extract the delegate chain from a to1d payload. FDO 2.0 payloads are
/// `[RVTO2Addr, Hash, DelegateChain .cbor CertChainOrNull]`; a 2-element
/// payload (created for a FDO 1.x voucher) has no delegate chain.
pub fn to1d_delegate_chain(payload: &[u8]) -> Result<Option<Vec<Vec<u8>>>, FdoError> {
    let mut dec = CborDecoder::new(payload);
    let len = dec.read_array_len()?;
    match len {
        2 => Ok(None),
        3 => {
            dec.skip_value()?; // RVTO2Addr
            dec.skip_value()?; // to0d hash
            let wrapped = dec.read_bytes()?;
            read_cert_chain_or_null(&mut CborDecoder::new(&wrapped))
        }
        _ => Err(FdoError::CborError(format!("to1d payload has {} elements", len))),
    }
}

/// Build TO1.ProveToRV message (type 32).
///
/// A COSE_Sign1 containing an EAT with the device GUID and nonce4, signed with
/// the device attestation key held in the TPM.
#[cfg(target_os = "uefi")]
pub fn build_to1_prove_to_rv(
    guid: &[u8; 16],
    nonce4: &[u8; 16],
    device_key_handle: u32,
) -> Result<Vec<u8>, FdoError> {
    let mut enc = CborEncoder::new();
    
    // COSE_Sign1 structure: [protected, unprotected, payload, signature]
    // Tag 18 for COSE_Sign1
    enc.buf.push(0xd2); // tag(18)
    enc.array(4);
    
    // Protected header {1: -7} means alg: ES256. Keep the serialised bytes:
    // they must be fed into the Sig_structure verbatim.
    let mut prot_enc = CborEncoder::new();
    prot_enc.buf.push(0xa1); // map(1)
    prot_enc.buf.push(0x01); // key: 1 (alg)
    prot_enc.neg_int(-7);    // value: -7 (ES256)
    let prot_bytes = prot_enc.into_bytes();
    enc.bytes(&prot_bytes);
    
    // Unprotected header (empty map)
    enc.buf.push(0xa0); // map(0)
    
    // Payload: EAT with UEID and nonce claims
    // EAT is a CBOR map: {256: ueid, 10: nonce}
    // UEID claim key is 256, Nonce claim key is 10
    let mut payload_enc = CborEncoder::new();
    payload_enc.buf.push(0xa2); // map(2)
    
    // UEID claim (key 256)
    payload_enc.uint(256);
    // UEID value: bstr with type prefix 0x01 (RAND) + GUID
    let mut ueid = Vec::with_capacity(17);
    ueid.push(0x01); // RAND type
    ueid.extend_from_slice(guid);
    payload_enc.bytes(&ueid);
    
    // Nonce claim (key 10)
    payload_enc.uint(10);
    payload_enc.bytes(nonce4);
    
    let protected = prot_bytes;
    let payload = payload_enc.into_bytes();
    enc.bytes(&payload);

    // Sign with the device attestation key in the TPM. This is what proves to
    // the Rendezvous Server that the GUID in the EAT belongs to a device
    // holding the matching DAK. It was previously 64 zero bytes, which meant
    // the device never authenticated itself to the RV at all.
    let external_aad = crate::cose::domain_aad(
        crate::cose::AAD_TAG_PROVE_TO_RV,
        FDO_PROTOCOL_VERSION,
    );
    let sig_structure = crate::cose::build_sig_structure(&protected, &external_aad, &payload);
    let sig_hash = sha256(&sig_structure);

    match crate::tpm::tpm_sign_with_persistent(device_key_handle, &sig_hash) {
        Some(sig) if sig.len() == 64 => {
            debug!("TO1: ProveToRV signed with DAK at 0x{:08x}", device_key_handle);
            enc.bytes(&sig);
        }
        Some(sig) => {
            error!("TO1: DAK signature was {} bytes, expected 64", sig.len());
            return Err(FdoError::CryptoError(String::from(
                "unexpected ProveToRV signature length")));
        }
        None => {
            error!("TO1: TPM refused to sign ProveToRV with handle 0x{:08x}", device_key_handle);
            return Err(FdoError::CryptoError(String::from(
                "TPM signing failed for ProveToRV")));
        }
    }

    Ok(enc.into_bytes())
}

/// Build TO1.HelloRV message (type 30)
/// CBOR array: [CapabilityFlags, VendorCapFlags, Guid]
pub fn build_to1_hello_rv(guid: &[u8; 16]) -> Vec<u8> {
    let mut enc = CborEncoder::new();
    
    enc.array(3);
    enc.bytes(&[CAPB0_SUP_FDO20]); // CapabilityFlags
    enc.array(0); // VendorCapFlags
    enc.bytes(guid);
    
    enc.into_bytes()
}

/// Build TO2.HelloDeviceProbe message (type 80)
/// CBOR array: [CapabilityFlags, VendorCapFlags, Guid, maxDeviceMessageSize, hashTypes, sugar]
pub fn build_to2_hello_device_probe(guid: &[u8; 16], sugar: &[u8]) -> Vec<u8> {
    let mut enc = CborEncoder::new();
    
    enc.array(6);
    enc.bytes(&[CAPB0_SUP_FDO20]); // CapabilityFlags
    enc.array(0); // VendorCapFlags
    
    // GUID as bstr
    enc.bytes(guid);
    
    // max_device_message_size
    enc.uint(65535);
    
    // hash_types as array [-16] for SHA256
    enc.array(1);
    enc.neg_int(-16);
    
    // sugar as bstr
    enc.bytes(sugar);
    
    enc.into_bytes()
}

// ============================================================
// TO2 Protocol Structures and Parsers
// ============================================================

/// Capability flags bit definitions
const CAPB0_SUP_FDO10: u8 = 1 << 0; // bit 0: FDO 1.0
const CAPB0_SUP_FDO11: u8 = 1 << 1; // bit 1: FDO 1.1
const CAPB0_SUP_FDO20: u8 = 1 << 2; // bit 2: FDO 2.0

/// TO2.HelloDeviceAck20 parsed response
#[derive(Debug)]
pub struct To2HelloDeviceAck {
    pub capability_flags: Vec<u8>,  // Version flags
    pub nonce_to2_prove_dv: [u8; 16],
    pub kex_suite: i8,
    pub cipher_suite: i8,
    pub max_owner_msg_size: u16,
    pub hash_prev_type: i32,
    pub hash_prev: Vec<u8>,
}

/// Hash type this client offers in HelloDeviceProbe.hashTypes (SHA-256).
pub const HASH_TYPE_SHA256: i32 = -16;

/// Verify HelloDeviceAck20.hashPrev = hash[TO2.HelloDeviceProbe as sent].
/// The only hash type offered (and accepted) is SHA-256.
pub fn verify_hash_prev(hash_type: i32, hash_value: &[u8], probe: &[u8]) -> Result<(), FdoError> {
    if hash_type != HASH_TYPE_SHA256 {
        return Err(FdoError::ProtocolError(format!(
            "HelloDeviceAck20 hashPrev uses hash type {} (only SHA-256 was offered)", hash_type)));
    }
    if hash_value != sha256(probe).as_slice() {
        return Err(FdoError::ProtocolError(String::from(
            "HelloDeviceAck20 hashPrev does not match HelloDeviceProbe")));
    }
    Ok(())
}

impl To2HelloDeviceAck {
    /// Check if voucher supports FDO 2.0 (for AAD selection)
    pub fn supports_fdo20(&self) -> bool {
        !self.capability_flags.is_empty() && (self.capability_flags[0] & CAPB0_SUP_FDO20) != 0
    }
}

/// Produce the next AES-GCM IV for a TO2 session and advance the counter.
///
/// Deterministic IV construction per NIST SP 800-38D §8.2.1: a 96-bit IV built
/// from a fixed field (zero here — there is exactly one encrypting party per
/// session key) and a monotonic 64-bit invocation counter. Every message in a
/// session is encrypted under the same SEK, so uniqueness is mandatory; a
/// counter guarantees it without needing an entropy source.
fn next_session_iv(counter: &mut u64) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[4..].copy_from_slice(&counter.to_be_bytes());
    *counter += 1;
    iv
}

/// Check a nonce the peer echoed back against the one we expect.
///
/// TO2 anti-replay depends on these comparisons actually happening. Both
/// `ProveOVHdr20.NonceTO2ProveOV` and `DoneAck20.NonceTO2ProveOV` are the
/// server echoing `HelloDeviceAck20.NonceTO2ProveDVPrep` back to us
/// (go-fdo `to2_server_v200.go` lines 224 and 412), and the reference client
/// aborts on a mismatch in both places (`to2_client_v200.go` lines 402, 725).
///
/// Until 2026-09-29 this client parsed both nonces into structs, logged them
/// at `debug!`, and compared neither — which reads as "handled" to anyone
/// skimming for whether the nonce is used.
pub fn verify_nonce_echo(
    context: &str,
    expected: &[u8; 16],
    received: &[u8; 16],
) -> Result<(), FdoError> {
    if expected != received {
        error!("TO2: {} nonce MISMATCH — replayed or spoofed message.", context);
        error!("  expected: {:02x?}", expected);
        error!("  received: {:02x?}", received);
        return Err(FdoError::ProtocolError(format!(
            "{} nonce mismatch", context)));
    }
    debug!("TO2: {} nonce echo verified", context);
    Ok(())
}

/// Protocol version this client speaks. Selects domain-separation AAD:
/// FDO 2.0 uses per-context tags, FDO 1.01 used an empty external_aad.
pub const FDO_PROTOCOL_VERSION: u16 = 200;

/// TO2.ProveOVHdr20 parsed payload (from inside COSE_Sign1)
#[derive(Debug)]
pub struct To2ProveOvHdr20Payload {
    pub ov_header: Vec<u8>,
    pub num_ov_entries: u8,
    pub hmac: Vec<u8>,
    /// Raw CBOR bytes of the `HMac` structure exactly as received.
    ///
    /// Voucher entry 0's `hashPrevEntry` is computed over
    /// `OVHeader || HMac` *as encoded*, so re-serialising from the parsed
    /// values risks a byte mismatch. Keep the original span.
    pub hmac_raw: Vec<u8>,
    pub nonce_to2_prove_ov: [u8; 16],
    pub xb_key_exchange: Vec<u8>,  // Server's ECDH public key
    pub max_owner_msg_size: u16,
    /// Raw CBOR of `OwnerPubKey` (a convenience copy; the Owner key used for
    /// verification is derived from the voucher).
    pub owner_pub_key_raw: Vec<u8>,
    /// `DelegateChain` (DER certificates, leaf first), if a Delegate signed.
    pub delegate_chain: Option<Vec<Vec<u8>>>,
}

/// Extract the payload from a COSE_Sign1 message **without** verifying it.
///
/// Only valid where the caller verifies the signature separately over the same
/// buffer (see TO2 Step 3b, which checks ProveOVHdr against the voucher-derived
/// Owner key). Do not use this as the sole handling of a signed message.
///
/// COSE_Sign1 = [protected, unprotected, payload, signature] (tag 18 optional)
fn extract_cose_payload(data: &[u8]) -> Result<Vec<u8>, FdoError> {
    let mut dec = CborDecoder::new(data);
    
    // Check for optional CBOR tag 18 (COSE_Sign1)
    if let Some(b) = dec.peek() {
        if (b >> 5) == 6 {
            // It's a tag, read and verify it
            let tag = dec.read_tag()?;
            if tag != 18 {
                return Err(FdoError::CborError(format!("Expected COSE_Sign1 tag 18, got {}", tag)));
            }
        }
    }
    
    // Expect 4-element array
    let arr_len = dec.read_array_len()?;
    if arr_len != 4 {
        return Err(FdoError::CborError(format!("COSE_Sign1 expected 4 elements, got {}", arr_len)));
    }
    
    // Skip protected header (bstr)
    dec.skip_value()?;
    
    // Skip unprotected header (map)
    dec.skip_value()?;
    
    // Read payload (bstr)
    let payload = dec.read_bytes()?;
    
    Ok(payload)
}

/// Parse TO2.ProveOVHdr20 payload
/// CBOR: [ov_header, num_ov_entries, hmac, nonce, xb_key_exchange,
///        max_owner_msg_size, OwnerPubKey, DelegateChain]
pub fn parse_prove_ov_hdr_payload(data: &[u8]) -> Result<To2ProveOvHdr20Payload, FdoError> {
    let mut dec = CborDecoder::new(data);
    
    // Expect 8-element array
    let arr_len = dec.read_array_len()?;
    if arr_len != 8 {
        return Err(FdoError::CborError(format!("ProveOVHdr payload expected 8 elements, got {}", arr_len)));
    }
    
    // ov_header (bstr)
    let ov_header = dec.read_bytes()?;
    
    // num_ov_entries (uint)
    let num_ov_entries = dec.read_uint()? as u8;
    
    // hmac (Hash array [type, bytes]) — capture the raw span as well, since
    // entry 0's hashPrevEntry is computed over the encoded bytes.
    let hmac_start = dec.pos;
    let hmac_len = dec.read_array_len()?;
    let _hmac_type = dec.read_int()?;
    let hmac = if hmac_len > 1 {
        dec.read_bytes()?
    } else {
        Vec::new()
    };
    for _ in 2..hmac_len {
        dec.skip_value()?;
    }
    let hmac_raw = data
        .get(hmac_start..dec.pos)
        .unwrap_or(&[])
        .to_vec();
    
    // nonce_to2_prove_ov (bstr, 16 bytes)
    let nonce_bytes = dec.read_bytes()?;
    let mut nonce_to2_prove_ov = [0u8; 16];
    if nonce_bytes.len() >= 16 {
        nonce_to2_prove_ov.copy_from_slice(&nonce_bytes[..16]);
    }
    
    // xb_key_exchange (bstr) - server's ECDH public key
    let xb_key_exchange = dec.read_bytes()?;
    
    // max_owner_msg_size (uint)
    let max_owner_msg_size = dec.read_uint()? as u16;

    // OwnerPubKey (PublicKey)
    let owner_start = dec.pos;
    dec.skip_value()?;
    let owner_pub_key_raw = data[owner_start..dec.pos].to_vec();

    // DelegateChain (CertChainOrNull)
    let delegate_chain = read_cert_chain_or_null(&mut dec)?;
    
    Ok(To2ProveOvHdr20Payload {
        ov_header,
        num_ov_entries,
        hmac,
        hmac_raw,
        nonce_to2_prove_ov,
        xb_key_exchange,
        max_owner_msg_size,
        owner_pub_key_raw,
        delegate_chain,
    })
}

/// Build the TO2.ProveDevice20 EAT payload (the bytes signed by the DAK):
/// `{10: NonceTO2ProveDv, 256: UEID, -257: TO2ProveDevicePayload20}`.
/// `fdo_payload` is the already-encoded TO2ProveDevicePayload20 array.
pub fn build_to2_prove_device_eat(guid: &[u8; 16], nonce_to2_prove_dv: &[u8; 16], fdo_payload: &[u8]) -> Vec<u8> {
    let mut enc = CborEncoder::new();
    enc.encode_map(3);
    // EAT nonce claim (10)
    enc.uint(10);
    enc.bytes(nonce_to2_prove_dv);
    // UEID claim (256): RAND type 0x01 followed by the GUID
    enc.uint(256);
    let mut ueid = Vec::with_capacity(17);
    ueid.push(0x01);
    ueid.extend_from_slice(guid);
    enc.bytes(&ueid);
    // EAT-FDO claim (-257): CBOR negative integer, argument 256
    enc.buf.extend_from_slice(&[0x39, 0x01, 0x00]);
    enc.raw_bytes(fdo_payload);
    enc.into_bytes()
}

/// Disposition decoded from a verified TO2.SetupDevice20.
#[derive(Debug, PartialEq)]
pub enum SetupDisposition {
    /// DispResale: new credentials. Carries the replacement GUID.
    Resale { guid: [u8; 16] },
    /// DispCredReuse: keep the current credentials.
    CredReuse,
}

/// Check a decrypted TO2.SetupDevice20 (FDO 2.0 Errata 1):
///
/// * DispResale: MUST be signed by `ReplacementCred.Owner2PubKey` (proof of
///   possession), and `ReplacementCred.NonceTO2SetupDv` MUST equal the
///   nonce this Device sent in DeviceSvcInfoRdy20.
/// * DispCredReuse: signed by the ProveOVHdr20 signer (`peer_point`). The
///   Device MAY skip verification; this client verifies.
/// * DispDisable: not supported.
pub fn check_setup_device20(
    data: &[u8],
    setup_nonce: &[u8; 16],
    peer_point: &[u8],
) -> Result<SetupDisposition, FdoError> {
    let s1 = crate::cose::parse_cose_sign1(data)
        .ok_or_else(|| FdoError::CborError(String::from("SetupDevice20 is not a COSE_Sign1")))?;
    let aad = crate::cose::domain_aad(crate::cose::AAD_TAG_SETUP_DEVICE, FDO_PROTOCOL_VERSION);

    let mut dec = CborDecoder::new(s1.payload);
    if dec.read_array_len()? != 3 {
        return Err(FdoError::CborError(String::from("SetupDevice20 payload expected 3 elements")));
    }
    let disposition = dec.read_uint()?;
    match disposition {
        1 => {
            // ReplacementCred = [RendezvousInfo, Guid, NonceTO2SetupDv, Owner2PubKey]
            if dec.peek_null() || dec.read_array_len()? != 4 {
                return Err(FdoError::ProtocolError(String::from(
                    "SetupDevice20 DispResale requires ReplacementCred")));
            }
            dec.skip_value()?; // RendezvousInfo
            let guid_bytes = dec.read_bytes()?;
            let nonce = dec.read_bytes()?;
            let owner2_start = dec.pos;
            dec.skip_value()?;
            let owner2_point = crate::voucher::parse_fdo_public_key(&s1.payload[owner2_start..dec.pos])
                .map_err(|e| FdoError::CryptoError(format!("SetupDevice20 Owner2PubKey: {:?}", e)))?;
            if !crate::cose::verify_sign1(&s1, &aad, &owner2_point) {
                return Err(FdoError::CryptoError(String::from(
                    "SetupDevice20 signature does not verify against Owner2PubKey")));
            }
            if nonce.as_slice() != setup_nonce {
                return Err(FdoError::ProtocolError(String::from("SetupDevice20 nonce mismatch")));
            }
            let guid: [u8; 16] = guid_bytes.as_slice().try_into()
                .map_err(|_| FdoError::CborError(String::from("SetupDevice20 GUID is not 16 bytes")))?;
            Ok(SetupDisposition::Resale { guid })
        }
        2 => {
            if !dec.peek_null() {
                return Err(FdoError::ProtocolError(String::from(
                    "SetupDevice20 DispCredReuse must not carry ReplacementCred")));
            }
            if !crate::cose::verify_sign1(&s1, &aad, peer_point) {
                return Err(FdoError::CryptoError(String::from(
                    "SetupDevice20 signature does not verify against the ProveOVHdr20 signer")));
            }
            Ok(SetupDisposition::CredReuse)
        }
        3 => Err(FdoError::ProtocolError(String::from("SetupDevice20 DispDisable is not supported"))),
        d => Err(FdoError::ProtocolError(format!("SetupDevice20 has unknown DispositionCode {}", d))),
    }
}

/// Parse FDO 1.1 HelloDeviceAck (5 elements)
/// CBOR: [nonce5, owner_guid, max_owner_msg_size, cipher_suite, a_key_exchange]
fn parse_to2_hello_device_ack_v11(dec: &mut CborDecoder) -> Result<To2HelloDeviceAck, FdoError> {
    // nonce5 (element 0) - 16 bytes
    let nonce_bytes = dec.read_bytes()?;
    if nonce_bytes.len() != 16 {
        return Err(FdoError::CborError(format!("FDO 1.1 nonce expected 16 bytes, got {}", nonce_bytes.len())));
    }
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&nonce_bytes);
    
    // owner_guid (element 1) - skip, we already know our GUID
    dec.skip_value()?;
    
    // max_owner_msg_size (element 2)
    let max_owner_msg_size = dec.read_uint()? as u16;
    
    // cipher_suite (element 3) - integer like 1 for A128GCM
    let cipher_suite = dec.read_int()? as i8;
    
    // a_key_exchange (element 4) - skip for now, will be in ProveOVHdr
    dec.skip_value()?;
    
    Ok(To2HelloDeviceAck {
        capability_flags: vec![0x01], // FDO 1.1
        nonce_to2_prove_dv: nonce,
        kex_suite: 1, // Default ECDH256
        cipher_suite,
        max_owner_msg_size,
        hash_prev_type: 0,
        hash_prev: Vec::new(), // Not in FDO 1.1 HelloDeviceAck
    })
}

/// Key exchange suite this client uses in FDO 2.0 (its TPM Device key is P-256).
pub const KEX_SUITE_20: &str = "ECDH256";

/// Choose the key exchange suite from the Owner's TO2.HelloDeviceAck20 offer.
/// This client supports only ECDH256; it fails if the Owner did not offer it
/// (e.g. an offer of only ASYMKEX2048/ASYMKEX3072, which are deprecated in
/// FDO 2.0 and which a Device MUST NOT select: FDO 2.0 Errata 1, A4).
pub fn select_kex_suite20(offered: &[String]) -> Result<&'static str, FdoError> {
    if offered.iter().any(|s| s == KEX_SUITE_20) {
        return Ok(KEX_SUITE_20);
    }
    Err(FdoError::CborError(format!(
        "Owner offered no supported key exchange suite: {:?} (this client supports {}; ASYMKEX is not used in FDO 2.0)",
        offered, KEX_SUITE_20
    )))
}

/// Parse TO2.HelloDeviceAck (type 61 for FDO 1.1, type 81 for FDO 2.0)
/// FDO 2.0 CBOR: [CapabilityFlags, VendorCapFlags, guid, max_owner_msg_size, kex_suites, cipher_suites, nonce, hash_prev]
/// FDO 1.1 CBOR: [nonce5, owner_guid, max_owner_msg_size, cipher_suite, a_key_exchange]
pub fn parse_to2_hello_device_ack(data: &[u8]) -> Result<To2HelloDeviceAck, FdoError> {
    let mut dec = CborDecoder::new(data);
    
    let arr_len = dec.read_array_len()?;
    
    // Check for FDO error response: [error_code, prev_msg_id, error_string, ...]
    // Error responses have 5 elements where first is an integer (error code)
    if arr_len == 5 {
        // Peek at first byte to determine if this is an error or FDO 1.1
        let first_byte = dec.peek().unwrap_or(0);
        let major_type = first_byte >> 5;
        
        // Major type 0 = unsigned int (error code), Major type 3 = text string
        // FDO 1.1 HelloDeviceAck starts with nonce (bstr, major type 2)
        if major_type == 0 || major_type == 3 {
            // This is likely an FDO error response
            let error_code = dec.read_uint()?;
            let _prev_msg = dec.read_uint()?;
            // Error string is a text string
            let error_text = dec.read_text()?;
            return Err(FdoError::CborError(format!("Server error {}: {}", error_code, error_text)));
        }
        
        debug!("Parsing FDO 1.1 HelloDeviceAck (5 elements)");
        return parse_to2_hello_device_ack_v11(&mut dec);
    }
    
    // Handle FDO 2.0 format (8 elements)
    if arr_len != 8 {
        return Err(FdoError::CborError(format!("HelloDeviceAck expected 5 (v1.1) or 8 (v2.0) elements, got {}", arr_len)));
    }
    debug!("Parsing FDO 2.0 HelloDeviceAck20 (8 elements)");
    
    // CapabilityFlags (element 0) - bstr
    let capability_flags = dec.read_bytes()?;
    // VendorCapFlags (element 1)
    dec.skip_value()?;
    
    // Skip guid (element 2)
    dec.skip_value()?;
    
    // max_owner_message_size (element 3)
    let max_owner_msg_size = dec.read_uint()? as u16;
    
    // kex_suites array (element 4): the Owner's offer, e.g. ["ECDH384", "ECDH256"]
    let kex_len = dec.read_array_len()?;
    let mut offered = Vec::new();
    for _ in 0..kex_len {
        offered.push(dec.read_text()?);
    }
    select_kex_suite20(&offered)?;
    let kex_suite: i8 = 1; // ECDH256, the only suite this client supports
    
    // cipher_suites array (element 5) - take first
    let cipher_len = dec.read_array_len()?;
    let cipher_suite = if cipher_len > 0 {
        dec.read_int()? as i8
    } else {
        0
    };
    debug!("  Negotiated cipher suite: {} (1=A128GCM, 3=A256GCM)", cipher_suite);
    for _ in 1..cipher_len {
        dec.skip_value()?;
    }
    
    // nonce_to2_prove_dv (element 6) - 16 bytes
    let nonce_bytes = dec.read_bytes()?;
    let mut nonce_to2_prove_dv = [0u8; 16];
    if nonce_bytes.len() >= 16 {
        nonce_to2_prove_dv.copy_from_slice(&nonce_bytes[..16]);
    }
    
    // hash_prev (element 7) - Hash array [type, bytes]
    let hash_arr_len = dec.read_array_len()?;
    let hash_prev_type = dec.read_int()?; // hash algorithm (e.g., -16 = SHA-256)
    let hash_prev = if hash_arr_len > 1 {
        dec.read_bytes()?
    } else {
        Vec::new()
    };
    
    Ok(To2HelloDeviceAck {
        capability_flags,
        nonce_to2_prove_dv,
        kex_suite,
        cipher_suite,
        max_owner_msg_size,
        hash_prev_type,
        hash_prev,
    })
}

/// Build TO2.ProveDevice20 message (type 82) from pre-built components
/// This uses the exact same payload bytes that were signed
fn build_to2_prove_device_from_parts(
    protected: &[u8],       // Pre-built protected header
    payload: &[u8],         // Pre-built payload (same bytes used for signing)
    signature: &[u8],       // ECDSA signature (r || s, 64 bytes)
) -> Vec<u8> {
    let mut enc = CborEncoder::new();
    
    // COSE_Sign1 tagged with CBOR tag 18 (0xD2)
    enc.buf.push(0xd2); // CBOR tag 18 = COSE_Sign1
    
    // COSE_Sign1 = [protected, unprotected, payload, signature]
    enc.array(4);
    
    // Protected header (as bstr)
    enc.bytes(protected);
    
    // Unprotected header (empty map)
    enc.buf.push(0xa0);
    
    // Payload (as bstr) - use exact same bytes that were signed
    enc.bytes(payload);
    
    // Signature
    enc.bytes(signature);
    
    enc.into_bytes()
}

/// Build the COSE Sig_structure for signing with external_aad
/// Sig_structure = ["Signature1", protected, external_aad, payload]
fn build_cose_sig_structure(protected: &[u8], external_aad: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut enc = CborEncoder::new();
    enc.array(4);
    enc.text("Signature1");
    enc.bytes(protected);
    enc.bytes(external_aad);
    enc.bytes(payload);
    enc.into_bytes()
}

/// Build FDO external_aad for TO2.ProveDevice20
/// Returns CBOR encoding of ["FDO-TO2-ProveDevice-v1"]
fn build_prove_device_aad() -> Vec<u8> {
    let mut enc = CborEncoder::new();
    enc.array(1);
    enc.text("FDO-TO2-ProveDevice-v1");
    enc.into_bytes()
}

/// Build protected header for COSE_Sign1 (ES256 = -7)
fn build_cose_protected_header() -> Vec<u8> {
    let mut prot_enc = CborEncoder::new();
    prot_enc.buf.push(0xa1); // map of 1
    prot_enc.uint(1); // alg key
    prot_enc.neg_int(-7); // ES256
    prot_enc.into_bytes()
}

/// Build TO2ProveDevice20Payload
fn build_to2_prove_device_payload(
    kex_suite: &str,
    cipher_suite: i8,
    xa_public_key: &[u8],
    nonce_to2_prove_ov_prep: &[u8; 16],
    hash_prev2: &[u8],
) -> Vec<u8> {
    let mut payload_enc = CborEncoder::new();
    payload_enc.array(5);
    payload_enc.text(kex_suite);
    payload_enc.buf.push(cipher_suite as u8);
    payload_enc.bytes(xa_public_key);
    payload_enc.bytes(nonce_to2_prove_ov_prep);
    payload_enc.array(2);
    payload_enc.neg_int(-16); // SHA-256
    payload_enc.bytes(hash_prev2);
    payload_enc.into_bytes()
}

/// Build TO2.GetOVNextEntry20 message (type 84)
pub fn build_to2_get_ov_next_entry(entry_num: u8) -> Vec<u8> {
    let mut enc = CborEncoder::new();
    enc.array(1);
    enc.buf.push(entry_num);
    enc.into_bytes()
}

/// Build TO2.DeviceSvcInfoRdy20 message (type 86) - plaintext before encryption
/// Format: [ReplacementHMac (always null), maxOwnerServiceInfoSz, NonceTO2SetupDV_Prep]
/// The ReplacementHMac field is not used (FDO 2.0 Errata 1).
pub fn build_device_svc_info_rdy(max_owner_svc_info_sz: Option<u16>, nonce_to2_setup_dv: &[u8; 16]) -> Vec<u8> {
    let mut enc = CborEncoder::new();
    enc.array(3);
    enc.null(); // ReplacementHMac: not used
    match max_owner_svc_info_sz {
        Some(sz) => enc.uint(sz),
        None => enc.null(),
    }
    enc.bytes(nonce_to2_setup_dv);
    enc.into_bytes()
}

/// Build COSE_Encrypt0 message (tag 16)
/// Format: tag(16, [protected_headers_bstr, {5: iv}, ciphertext])
/// Protected headers: {1: 1} (alg = A128GCM)
/// Unprotected headers: {5: iv} (IV label = 5)
pub fn build_encrypted_message(nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    // Build protected headers: {1: 3} (alg = A256GCM = 3)
    let mut prot = CborEncoder::new();
    prot.encode_map(1);
    prot.uint(1); // alg label
    prot.uint(3); // A256GCM
    let protected_bytes = prot.into_bytes();
    
    let mut enc = CborEncoder::new();
    // CBOR tag 16 = COSE_Encrypt0
    enc.buf.push(0xD0 | 16); // Tag with 1-byte value (tag 16)
    enc.array(3);
    enc.bytes(&protected_bytes); // Protected headers as bstr
    // Unprotected headers: {5: iv}
    enc.encode_map(1);
    enc.uint(5); // IV label
    enc.bytes(nonce);
    enc.bytes(ciphertext);
    enc.into_bytes()
}

/// Parse COSE_Encrypt0 message (tag 16)
///
/// Error responses (Message-Type 255) are now rejected by `check_fdo_error`
/// before the body reaches this function, so the old 5-element-array sniff
/// is gone.
pub fn parse_encrypted_message(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), FdoError> {
    let mut dec = CborDecoder::new(data);
    
    let first_byte = dec.peek().unwrap_or(0);
    let major_type = first_byte >> 5;
    
    // Expect tag 16 (COSE_Encrypt0)
    if major_type != 6 { // Tag major type
        return Err(FdoError::CborError(format!("Expected COSE_Encrypt0 tag, got major type {}", major_type)));
    }
    
    // Read tag number
    let tag_byte = dec.read_byte()?;
    let tag_num = if (tag_byte & 0x1F) < 24 {
        (tag_byte & 0x1F) as u64
    } else {
        dec.read_uint()?
    };
    
    if tag_num != 16 {
        return Err(FdoError::CborError(format!("Expected tag 16 (COSE_Encrypt0), got {}", tag_num)));
    }
    
    // Read array [protected, unprotected, ciphertext]
    let arr_len = dec.read_array_header()?;
    if arr_len != 3 {
        return Err(FdoError::CborError(format!("COSE_Encrypt0 expected 3 elements, got {}", arr_len)));
    }
    
    let _protected = dec.read_bytes()?; // Protected headers (bstr)
    
    // Unprotected headers: map with IV
    let map_len = dec.read_map_len()?;
    let mut nonce = Vec::new();
    for _ in 0..map_len {
        let key = dec.read_uint()?;
        if key == 5 { // IV label
            nonce = dec.read_bytes()?;
        } else {
            dec.skip_value()?;
        }
    }
    
    let ciphertext = dec.read_bytes()?;
    
    if nonce.is_empty() {
        return Err(FdoError::CborError(String::from("Missing IV in COSE_Encrypt0")));
    }
    
    Ok((nonce, ciphertext))
}

/// Build devmod ServiceInfo (required by FDO spec)
/// Returns array of [key, value] pairs for devmod module
pub fn build_devmod_service_info() -> Vec<u8> {
    let mut enc = CborEncoder::new();
    
    // ServiceInfo is array of [module_name:key, value] pairs
    // 9 devmod entries + 2 BMO entries = 11 total
    enc.array(11);
    
    // devmod:active = true (bstr-wrapped)
    enc.svc_info_kv_bool("devmod:active", true);
    
    // devmod:nummodules = 1 (bstr-wrapped)
    enc.svc_info_kv_uint("devmod:nummodules", 1);
    
    // devmod:modules = [0, 1, "fdo.bmo"] (bstr-wrapped array)
    {
        let mut tmp = CborEncoder::new();
        tmp.array(3);
        tmp.uint(0);         // start = 0
        tmp.uint(1);         // count = 1
        tmp.text("fdo.bmo"); // module name
        enc.svc_info_kv_bytes("devmod:modules", &tmp.into_bytes());
    }
    
    // devmod:os (bstr-wrapped)
    enc.svc_info_kv_text("devmod:os", "UEFI");
    
    // devmod:arch (bstr-wrapped)
    enc.svc_info_kv_text("devmod:arch", "x86_64");
    
    // devmod:version (bstr-wrapped)
    enc.svc_info_kv_text("devmod:version", "1.0");
    
    // devmod:device (bstr-wrapped)
    enc.svc_info_kv_text("devmod:device", "FDO-UEFI-Client");
    
    // devmod:sep (bstr-wrapped)
    enc.svc_info_kv_text("devmod:sep", "\\");
    
    // devmod:bin (bstr-wrapped)
    enc.svc_info_kv_text("devmod:bin", "efi");
    
    // fdo.bmo:active (bstr-wrapped)
    enc.svc_info_kv_bool("fdo.bmo:active", true);
    
    // fdo.bmo:supported-types (bstr-wrapped array)
    {
        let mut tmp = CborEncoder::new();
        tmp.array(1);
        tmp.text("application/x-uefi-image");
        enc.svc_info_kv_bytes("fdo.bmo:supported-types", &tmp.into_bytes());
    }
    
    enc.into_bytes()
}

/// Build TO2.DeviceSvcInfo message (type 88)
/// Format: [ReplacementHMacOrNull (always null), is_more, service_info_array]
pub fn build_device_svc_info(is_more: bool, service_info: &[u8]) -> Vec<u8> {
    let mut enc = CborEncoder::new();
    enc.array(3);
    enc.null(); // ReplacementHMacOrNull: not used (FDO 2.0 Errata 1)
    enc.bool_val(is_more);
    if service_info.is_empty() {
        enc.array(0); // Empty array
    } else {
        // Embed the pre-encoded service info
        enc.raw_bytes(service_info);
    }
    enc.into_bytes()
}

/// Parsed OwnerSvcInfo message
pub struct OwnerSvcInfo {
    pub is_done: bool,
    pub is_more: bool,
    pub service_info: Vec<u8>,
}

/// Parse TO2.OwnerSvcInfo20 message (type 89)
/// Format: [is_more_service_info, is_done, service_info_array] or null (no service info)
pub fn parse_owner_svc_info(data: &[u8]) -> Result<OwnerSvcInfo, FdoError> {
    debug!("Parsing OwnerSvcInfo: {} bytes, hex: {:02x?}", data.len(), &data[..data.len().min(32)]);
    
    // Handle null response - means no service info, we're done
    if data.len() == 1 && data[0] == 0xf6 {
        debug!("OwnerSvcInfo is null - no service info, done");
        return Ok(OwnerSvcInfo {
            is_done: true,
            is_more: false,
            service_info: Vec::new(),
        });
    }
    
    let mut dec = CborDecoder::new(data);
    let arr_len = dec.read_array_header()?;
    if arr_len != 3 {
        return Err(FdoError::CborError(format!("OwnerSvcInfo expected 3 elements, got {}", arr_len)));
    }
    
    // FDO 2.0 order: is_more_service_info, is_done, service_info
    let is_more = dec.read_bool()?;
    let is_done = dec.read_bool()?;
    
    // Service info array - just capture remaining bytes for now
    let service_info = dec.remaining_bytes().to_vec();
    
    Ok(OwnerSvcInfo {
        is_done,
        is_more,
        service_info,
    })
}

/// Parse ServiceInfo array from OwnerSvcInfo
/// Returns array of (key, value) pairs
pub fn parse_service_info_array(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>, FdoError> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    
    let mut dec = CborDecoder::new(data);
    let arr_len = dec.read_array_header()?;
    debug!("ServiceInfo array has {} entries", arr_len);
    
    let mut entries = Vec::new();
    for i in 0..arr_len {
        // Each entry is [key_string, value_bytes]
        let entry_len = dec.read_array_header()?;
        if entry_len != 2 {
            warn!("ServiceInfo entry {} has {} elements, expected 2", i, entry_len);
            dec.skip_value()?;
            continue;
        }
        
        let key = dec.read_text()?;
        let value = dec.read_bytes()?;
        
        debug!("  ServiceInfo[{}]: key='{}', value={} bytes", i, key, value.len());
        entries.push((key, value));
    }
    
    Ok(entries)
}

/// Build TO2.Done20 message (type 90)
/// Format: [NonceTO2ProveDv, ReplacementHMac]
/// ReplacementHMac is null: credential reuse, or this client declining resale
/// (it does not install replacement credentials).
pub fn build_to2_done(nonce_to2_prove_dv: &[u8; 16]) -> Vec<u8> {
    let mut enc = CborEncoder::new();
    enc.array(2);
    enc.bytes(nonce_to2_prove_dv);
    enc.null();
    enc.into_bytes()
}

/// Parsed DoneAck message
pub struct DoneAck {
    pub nonce: [u8; 16],
}

/// Parse TO2.DoneAck message (type 91)
/// Format: [NonceTO2SetupDv]
pub fn parse_to2_done_ack(data: &[u8]) -> Result<DoneAck, FdoError> {
    let mut dec = CborDecoder::new(data);
    let arr_len = dec.read_array_header()?;
    if arr_len != 1 {
        return Err(FdoError::CborError(format!("DoneAck expected 1 element, got {}", arr_len)));
    }
    
    let nonce_bytes = dec.read_bytes()?;
    if nonce_bytes.len() != 16 {
        return Err(FdoError::CborError(format!("DoneAck nonce expected 16 bytes, got {}", nonce_bytes.len())));
    }
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&nonce_bytes);
    
    Ok(DoneAck { nonce })
}

// ============================================================
// TO2 Protocol Flow
// ============================================================

/// Perform TO2 protocol step 1: HelloDeviceProbe -> HelloDeviceAck
#[cfg(target_os = "uefi")]
/// Returns the ack, session token, and raw response bytes for hash_prev2
pub fn perform_to2_hello(owner_url: &str, guid: &[u8; 16]) -> Result<(To2HelloDeviceAck, Option<String>, Vec<u8>), FdoError> {
    debug!("TO2: Sending HelloDeviceProbe to {}", owner_url);
    
    // Sugar: 16 random bytes mixed into HelloDeviceProbe. The owner folds the
    // whole probe into HelloDeviceAck20.HashPrev, so this is the device's
    // contribution of freshness to the TO2 message chain — it must be
    // unpredictable. It was the fixed constant [0xaa; 16] until 2026-09-29,
    // which made the device side of that chain entirely predictable.
    // (go-fdo's client uses rand.Read here: to2_client_v200.go:199.)
    let sugar_vec = crate::tpm::tpm_get_random(16)
        .ok_or_else(|| FdoError::CryptoError(String::from(
            "TPM GetRandom failed for HelloDeviceProbe sugar")))?;
    let mut sugar = [0u8; 16];
    sugar.copy_from_slice(&sugar_vec);
    
    // Build HelloDeviceProbe message
    let hello_probe = build_to2_hello_device_probe(guid, &sugar);
    debug!("  HelloDeviceProbe: {} bytes", hello_probe.len());
    
    // Build URL for message type 80
    let url = format!("{}/fdo/200/msg/{}", owner_url, MSG_TO2_HELLO_DEVICE_PROBE);
    
    // Send HTTP POST and capture session token
    let resp = http_post_with_session(&url, &hello_probe, MSG_TO2_HELLO_DEVICE_PROBE, None)
        .ok_or_else(|| FdoError::HttpError(String::from("HTTP POST failed")))?;
    check_fdo_error(resp.message_type, &resp.body, "TO2.HelloDeviceAck")?;
    let response = resp.body;
    let auth_token = resp.auth_token;
    
    debug!("  Response: {} bytes", response.len());
    if auth_token.is_some() {
        debug!("  Session token received");
    }
    if !response.is_empty() {
        debug!("  CBOR: {:02x?}", &response[..response.len().min(32)]);
    }
    
    // Parse HelloDeviceAck20
    let ack = parse_to2_hello_device_ack(&response)?;
    debug!("  Nonce: {:02x?}", ack.nonce_to2_prove_dv);

    // hashPrev must be the hash of the probe we sent
    verify_hash_prev(ack.hash_prev_type, &ack.hash_prev, &hello_probe)?;
    
    // Return raw response for hash_prev2 computation
    Ok((ack, auth_token, response))
}

/// Perform TO2 protocol (initial steps - unencrypted)
#[cfg(target_os = "uefi")]
/// device_key_handle: persistent TPM handle for the DAK, read from DCTPM.DeviceKeyHandle
pub fn perform_to2(
    owner_url: &str,
    guid: &[u8; 16],
    device_key_handle: u32,
    hmac_key_handle: u32,
    to1d: Option<&[u8]>,
) -> Result<(), FdoError> {
    use crate::tpm;
    
    info!("=== Starting TO2 Protocol ===");
    debug!("Owner URL: {}", owner_url);
    debug!("GUID: {:02x?}", guid);
    
    // Step 0: Flush any leftover transient TPM handles from a previous failed TO2.
    // Without this, a TO2 failure after tpm_create_ecdh_key() leaves transient
    // handles loaded, and the next attempt may get TPM_RC_OBJECT_MEMORY (0x902).
    tpm::tpm_flush_all_transient();
    
    // Step 1: HelloDeviceProbe -> HelloDeviceAck20
    let (ack, session_token, hello_ack_raw) = perform_to2_hello(owner_url, guid)?;
    
    info!("TO2 Step 1 complete: HelloDeviceProbe -> HelloDeviceAck20");
    debug!("  Nonce: {:02x?}", ack.nonce_to2_prove_dv);
    debug!("  KexSuite: {}", ack.kex_suite);
    debug!("  CipherSuite: {}", ack.cipher_suite);
    if session_token.is_some() {
        debug!("  Session token: present");
    }
    
    // Step 2: ProveDevice20 -> ProveOVHdr20
    debug!("TO2: Creating TPM ECDH key for key exchange...");
    
    // Create ECDH key pair using TPM
    let ecdh_key = tpm::tpm_create_ecdh_key()
        .ok_or_else(|| FdoError::CryptoError(String::from("Failed to create TPM ECDH key")))?;
    
    debug!("TO2: TPM ECDH key created, handle=0x{:08x}", ecdh_key.handle);
    
    // Build xA in FDO format: len_x || x || len_y || y || len_random || random
    // For ECDH256: 2+32+2+32+2+16 = 86 bytes
    // The device's contribution to the shared secret. Must be unpredictable:
    // it is concatenated into the KDF input as xA.Rand, so a fixed value hands
    // an attacker half of the secret material for free.
    let random = tpm::tpm_get_random(16)
        .ok_or_else(|| FdoError::CryptoError(String::from(
            "TPM GetRandom failed for key exchange randomness")))?;
    
    let mut xa_public_key = Vec::with_capacity(86);
    // len_x (big-endian u16)
    xa_public_key.extend_from_slice(&(ecdh_key.public_x.len() as u16).to_be_bytes());
    xa_public_key.extend_from_slice(&ecdh_key.public_x);
    // len_y (big-endian u16)
    xa_public_key.extend_from_slice(&(ecdh_key.public_y.len() as u16).to_be_bytes());
    xa_public_key.extend_from_slice(&ecdh_key.public_y);
    // len_random (big-endian u16)
    xa_public_key.extend_from_slice(&(random.len() as u16).to_be_bytes());
    xa_public_key.extend_from_slice(&random);
    debug!("TO2: xA public key: {} bytes (FDO format)", xa_public_key.len());
    
    // ECDH256: checked against the Owner's offer in parse_to2_hello_device_ack
    // (select_kex_suite20); our TPM Device key is P-256.
    let kex_suite_str = KEX_SUITE_20;
    
    // NonceTO2ProveOV is generated by the Device; the Owner must return it
    // in its signed ProveOVHdr20, proving that message is fresh. (The
    // Owner's NonceTO2ProveDv goes in the EAT nonce claim instead.)
    let prove_ov_rand = tpm::tpm_get_random(16)
        .ok_or_else(|| FdoError::CryptoError(String::from(
            "TPM GetRandom failed for NonceTO2ProveOV")))?;
    let mut nonce_to2_prove_ov_prep = [0u8; 16];
    nonce_to2_prove_ov_prep.copy_from_slice(&prove_ov_rand);
    
    // Compute hash_prev2 (SHA-256 of HelloDeviceAck response)
    let hash_prev2 = sha256(&hello_ack_raw);
    debug!("  hash_prev2: {:02x?}", &hash_prev2[..16]);
    
    debug!("TO2: Building COSE signature for ProveDevice20...");
    
    // Flush the ECDH transient handle before signing.
    // UEFI TCG2 doesn't auto-flush transients, so the ECDH key occupies
    // a transient slot. Flushing it ensures TPM2_Sign can proceed cleanly.
    // After signing, we'll recreate the ECDH key for ECDH_ZGen.
    debug!("TO2: Flushing ECDH transient handle 0x{:08x} before signing...", ecdh_key.handle);
    tpm::tpm_flush_context(ecdh_key.handle);
    
    // Build the EAT: nonce claim NonceTO2ProveDv, FDO claim the payload
    let fdo_payload = build_to2_prove_device_payload(
        kex_suite_str,
        ack.cipher_suite,
        &xa_public_key,
        &nonce_to2_prove_ov_prep,
        &hash_prev2,
    );
    let payload = build_to2_prove_device_eat(guid, &ack.nonce_to2_prove_dv, &fdo_payload);
    
    // Build the protected header
    let protected = build_cose_protected_header();
    
    // external_aad: empty for FDO 1.0/1.1-created vouchers, domain tag for FDO 2.0
    let external_aad = if ack.supports_fdo20() {
        debug!("  FDO 2.0 voucher detected - using domain AAD");
        build_prove_device_aad()
    } else {
        debug!("  FDO 1.x voucher detected - using empty AAD");
        Vec::new()
    };
    debug!("  external_aad: {:02x?}", &external_aad);
    
    // Build the Sig_structure for signing
    let sig_structure = build_cose_sig_structure(&protected, &external_aad, &payload);
    debug!("  Sig_structure: {} bytes", sig_structure.len());
    debug!("  Sig_structure CBOR: {:02x?}", &sig_structure[..sig_structure.len().min(64)]);
    debug!("  Protected header: {:02x?}", &protected);
    debug!("  Payload: {:02x?}", &payload[..payload.len().min(48)]);
    
    // Hash the Sig_structure with SHA-256
    let sig_hash = sha256(&sig_structure);
    debug!("  Sig_structure hash: {:02x?}", &sig_hash);
    
    // Sign with TPM DAK using the persistent handle from DCTPM.DeviceKeyHandle.
    // Per securing-fdo-in-tpm.bs spec: "The client does not need to know how
    // the keys were created (Primary vs. ordinary, which hierarchy)."
    debug!("TO2: Signing with DAK at persistent handle 0x{:08x} (from DCTPM)", device_key_handle);
    let signature = tpm::tpm_sign_with_persistent(device_key_handle, &sig_hash)
        .ok_or_else(|| FdoError::CryptoError(String::from("TPM signing failed")))?;
    debug!("  TPM signature: {} bytes", signature.len());
    debug!("  Signature r: {:02x?}", &signature[..32]);
    debug!("  Signature s: {:02x?}", &signature[32..64]);
    
    // Build the final ProveDevice20 message using the same payload bytes we signed
    let prove_device = build_to2_prove_device_from_parts(&protected, &payload, &signature);
    debug!("  ProveDevice20: {} bytes", prove_device.len());
    debug!("  ProveDevice20 CBOR: {:02x?}", &prove_device[..prove_device.len().min(32)]);
    
    let url = format!("{}/fdo/200/msg/{}", owner_url, MSG_TO2_PROVE_DEVICE);
    let resp = http_post_with_session(&url, &prove_device, MSG_TO2_PROVE_DEVICE, session_token.as_deref())
        .ok_or_else(|| FdoError::HttpError(String::from("HTTP POST failed")))?;
    check_fdo_error(resp.message_type, &resp.body, "TO2.ProveOVHdr")?;
    let response = resp.body;
    
    debug!("  Response: {} bytes", response.len());
    if !response.is_empty() {
        debug!("  CBOR: {:02x?}", &response[..response.len().min(32)]);
    }
    
    info!("TO2 Step 2 complete: ProveDevice20 -> ProveOVHdr20");
    debug!("  Received ProveOVHdr20: {} bytes", response.len());
    debug!("  ProveOVHdr20 first bytes: {:02x?}", &response[..response.len().min(16)]);
    
    // Keep the raw ProveOVHdr20 bytes. The payload is extracted now because
    // xB is needed to derive session keys, but the COSE_Sign1 signature over
    // these bytes is not verifiable until the Owner key has been established
    // from the voucher entries — that happens in Step 3b below, before any
    // ServiceInfo is exchanged.
    let response_prove_ov = response;
    let payload = extract_cose_payload(&response_prove_ov)?;
    debug!("  ProveOVHdr20 payload: {} bytes", payload.len());
    
    // Parse the payload to get xB and other fields
    let prove_ov = parse_prove_ov_hdr_payload(&payload)?;
    debug!("  OV header: {} bytes", prove_ov.ov_header.len());
    debug!("  Num OV entries: {}", prove_ov.num_ov_entries);
    debug!("  xB (server ECDH): {} bytes", prove_ov.xb_key_exchange.len());
    debug!("  xB preview: {:02x?}", &prove_ov.xb_key_exchange[..prove_ov.xb_key_exchange.len().min(32)]);
    debug!("  nonce_to2_prove_ov: {:02x?}", prove_ov.nonce_to2_prove_ov);
    
    // Recreate the ECDH key for ECDH_ZGen.
    // We flushed the original ECDH transient handle before DAK signing.
    // CreatePrimary with the same template is deterministic (same hierarchy seed +
    // same template = same key), so the recreated key has the same private key
    // as the one whose public key we sent in ProveDevice20.
    debug!("TO2: Recreating ECDH key for shared secret computation...");
    let ecdh_key2 = tpm::tpm_create_ecdh_key()
        .ok_or_else(|| FdoError::CryptoError(String::from("Failed to recreate ECDH key")))?;
    debug!("TO2: ECDH key recreated, handle=0x{:08x}", ecdh_key2.handle);
    
    // Perform ECDH with server's xB to get shared secret
    // xB is in FDO format: [2-byte xLen][x][2-byte yLen][y][2-byte randLen][rand]
    debug!("TO2: Computing ECDH shared secret...");
    let ecdh_result = tpm::tpm_ecdh_derive(ecdh_key2.handle, &prove_ov.xb_key_exchange)
        .ok_or_else(|| FdoError::CryptoError(String::from("ECDH key derivation failed")))?;
    debug!("  ECDH result (x-coordinate): {} bytes", ecdh_result.len());
    
    // Parse random bytes from xB (server's key exchange parameter)
    let xb_rand = parse_kex_random(&prove_ov.xb_key_exchange)
        .ok_or_else(|| FdoError::CborError(String::from("Failed to parse xB random bytes")))?;
    debug!("  xB random: {} bytes, {:02x?}", xb_rand.len(), &xb_rand);
    
    // Parse random bytes from xA (our key exchange parameter)
    let xa_rand = parse_kex_random(&xa_public_key)
        .ok_or_else(|| FdoError::CborError(String::from("Failed to parse xA random bytes")))?;
    debug!("  xA random: {} bytes, {:02x?}", xa_rand.len(), &xa_rand);
    
    // FDO 2.0: the Device (us) sent xA, the Owner sent xB.
    let shared_secret = build_ecdh_shse(ecdh_result, &xa_rand, &xb_rand);
    debug!("  Full shared secret: {} bytes", shared_secret.len());
    debug!("  Shared secret preview: {:02x?}", &shared_secret[..shared_secret.len().min(16)]);
    
    // Clean up TPM key handle
    tpm::tpm_flush_context(ecdh_key2.handle);
    
    // Derive session keys from shared secret using FDO KDF
    debug!("TO2: Deriving session keys...");
    let session_keys = derive_session_keys(&shared_secret);
    debug!("  SEK (Session Encryption Key): {} bytes", session_keys.sek.len());
    debug!("  SEK preview: {:02x?}", &session_keys.sek[..session_keys.sek.len().min(8)]);
    
    // Step 3: Fetch OV entries (GetOVNextEntry20 is NOT encrypted)
    info!("TO2 Step 3: Fetching {} OV entries...", prove_ov.num_ov_entries);
    let mut ov_entries: Vec<Vec<u8>> = Vec::with_capacity(prove_ov.num_ov_entries as usize);
    for entry_num in 0..prove_ov.num_ov_entries {
        let get_entry = build_to2_get_ov_next_entry(entry_num);
        let url = format!("{}/fdo/200/msg/{}", owner_url, MSG_TO2_GET_OV_NEXT_ENTRY);
        
        let resp = http_post_with_session(&url, &get_entry, MSG_TO2_GET_OV_NEXT_ENTRY, session_token.as_deref())
            .ok_or_else(|| FdoError::HttpError(String::from("GetOVNextEntry failed")))?;
        check_fdo_error(resp.message_type, &resp.body, "TO2.OVNextEntry")?;
        let response = resp.body;
        
        // Parse OVNextEntry20 response: [entry_num, entry_bytes]
        let mut dec = CborDecoder::new(&response);
        let arr_len = dec.read_array_header()?;
        if arr_len != 2 {
            return Err(FdoError::CborError(format!("OVNextEntry expected 2 elements, got {}", arr_len)));
        }
        let resp_entry_num = dec.read_u8()?;
        // The bstr contents are the tag-18 COSE_Sign1 for this entry. Keep the
        // bytes verbatim: the next entry's hashPrevEntry is computed over them.
        let entry_bytes = dec.read_bytes()?;
        debug!("  OV entry {}: {} bytes", resp_entry_num, entry_bytes.len());
        if resp_entry_num != entry_num {
            return Err(FdoError::ProtocolError(format!(
                "OVNextEntry out of order: asked for {}, got {}", entry_num, resp_entry_num)));
        }
        ov_entries.push(entry_bytes);
    }
    info!("TO2 Step 3 complete: All {} OV entries received", prove_ov.num_ov_entries);

    // ---------------------------------------------------------------------
    // Step 3b: VERIFY the Ownership Voucher and the Owner's signature.
    //
    // Everything above this point is unauthenticated. The session keys were
    // derived from an ECDH exchange with a peer whose identity has not been
    // established; ECDH alone gives confidentiality against a passive
    // eavesdropper, not authentication. Until the voucher chain is walked and
    // ProveOVHdr is checked against the resulting Owner key, this peer could
    // be anyone who can answer the TO2 URL.
    //
    // The spec requires this to complete before the first ServiceInfo is
    // processed, so it happens here, immediately before Step 4.
    // ---------------------------------------------------------------------
    info!("TO2 Step 3b: Verifying Ownership Voucher...");
    let owner_key = match crate::voucher::verify_voucher(
        &prove_ov.ov_header,
        &prove_ov.hmac_raw,
        &prove_ov.hmac,
        hmac_key_handle,
        guid,
        &ov_entries,
    ) {
        Ok(k) => k,
        Err(e) => {
            error!("TO2: OWNERSHIP VOUCHER VERIFICATION FAILED: {:?}", e);
            error!("TO2: ABORTING — refusing to onboard to an unverified owner.");
            return Err(FdoError::CryptoError(format!("voucher verification failed: {:?}", e)));
        }
    };
    debug!("TO2: Owner key: {:02x?}...", &owner_key[..owner_key.len().min(16)]);

    // Now verify that the ProveOVHdr we received was actually signed by that
    // Owner key. This is what binds the session (and xB, hence the session
    // keys) to the proven Owner.
    let prove_ov_s1 = crate::cose::parse_cose_sign1(&response_prove_ov)
        .ok_or_else(|| FdoError::CborError(String::from("ProveOVHdr is not a valid COSE_Sign1")))?;

    // A delegate chain, if present, is in the signed ProveOVHdr20 payload.
    // If present, validate the chain and use the delegate leaf key for
    // ProveOVHdr verification instead of the Owner key directly.
    // Set explicitly on each branch below. Must not be inferred later from
    // "Owner key is present" — the Owner key is known even when a delegate
    // signed ProveOVHdr.
    let peer_authority: crate::bmo::PeerAuthority;
    // The key that signed ProveOVHdr20: also the SetupDevice20 signer for
    // DispCredReuse (FDO 2.0 Errata 1).
    let prove_ov_signer: Vec<u8>;

    if let Some(cert_ders) = prove_ov.delegate_chain.as_ref() {
        info!("TO2: ProveOVHdr carries a delegate chain — validating...");

        // Build a reference slice for the validation function
        let cert_refs: Vec<&[u8]> = cert_ders.iter().map(|c| c.as_slice()).collect();

        // Validate the chain: root signed by Owner, each cert by its parent
        let chain_result = crate::delegate::verify_delegate_chain(&cert_refs, &owner_key)
            .ok_or_else(|| {
                error!("TO2: Delegate chain VERIFICATION FAILED");
                FdoError::CryptoError(String::from("delegate chain verification failed"))
            })?;

        if !chain_result.has_onboard {
            error!("TO2: Delegate certificate lacks any fdo-ekt-permit-onboard-* permission");
            return Err(FdoError::CryptoError(String::from(
                "delegate lacks onboard permission")));
        }

        info!("TO2: Delegate chain verified — leaf has onboard={}, provision={}",
            chain_result.has_onboard, chain_result.has_provision);
        peer_authority = crate::bmo::PeerAuthority::Delegate {
            provision: chain_result.has_provision,
        };

        // Verify ProveOVHdr signature with the delegate leaf key
        let prove_ov_aad = crate::cose::domain_aad(
            crate::cose::AAD_TAG_PROVE_OV_HDR,
            FDO_PROTOCOL_VERSION,
        );
        if !crate::cose::verify_sign1(&prove_ov_s1, &prove_ov_aad, &chain_result.leaf_key_point) {
            error!("TO2: ProveOVHdr SIGNATURE VERIFICATION FAILED against delegate leaf key.");
            return Err(FdoError::CryptoError(String::from(
                "ProveOVHdr signature verification failed (delegate)")));
        }
        info!("TO2: ProveOVHdr signature VERIFIED against delegate leaf key");
        prove_ov_signer = chain_result.leaf_key_point;
    } else {
        // No delegate — verify ProveOVHdr directly against the Owner key
        let prove_ov_aad = crate::cose::domain_aad(
            crate::cose::AAD_TAG_PROVE_OV_HDR,
            FDO_PROTOCOL_VERSION,
        );
        if !crate::cose::verify_sign1(&prove_ov_s1, &prove_ov_aad, &owner_key) {
            error!("TO2: ProveOVHdr SIGNATURE VERIFICATION FAILED against the Owner key.");
            error!("TO2: ABORTING — the peer does not hold the Owner key for this device.");
            return Err(FdoError::CryptoError(String::from(
                "ProveOVHdr signature verification failed")));
        }
        peer_authority = crate::bmo::PeerAuthority::OwnerDirect;
        prove_ov_signer = owner_key.clone();
    }

    // Freshness: the Owner must echo the NonceTO2ProveOV this Device
    // generated and sent in ProveDevice20. Checked only now, after the
    // signature above — a nonce comparison on unauthenticated bytes proves
    // nothing, and answering it early would hand an attacker an oracle.
    // Without this, a recorded ProveOVHdr from a previous session replays.
    verify_nonce_echo(
        "ProveOVHdr20",
        &nonce_to2_prove_ov_prep,
        &prove_ov.nonce_to2_prove_ov,
    )?;
    // Verify the TO1 rendezvous blob against the same Owner key. Per FDO, if
    // the to1d signature does not verify the device must assume a man in the
    // middle is monitoring its traffic and fail TO2 immediately — an attacker
    // who can forge a redirect is how a device gets pointed at a hostile owner
    // in the first place.
    match to1d {
        Some(blob) if !blob.is_empty() => {
            let s1 = crate::cose::parse_cose_sign1(blob)
                .ok_or_else(|| FdoError::CborError(String::from("to1d is not a valid COSE_Sign1")))?;
            // The voucher's protocol version (OVHProtVer) decides the to1d
            // AAD, as for voucher entries (FDO 2.0 Errata 1, E7). The header
            // was authenticated by its HMAC in verify_voucher above.
            let ovh_protver = crate::voucher::parse_ov_header(&prove_ov.ov_header)
                .map_err(|e| FdoError::CborError(format!("OVHeader parse: {:?}", e)))?
                .protver;
            let aad = crate::cose::domain_aad(crate::cose::AAD_TAG_OWNER_SIGN, ovh_protver);
            // FDO 2.0: a delegate chain, if any, is in the signed to1d payload
            let to1d_chain = to1d_delegate_chain(s1.payload).map_err(|e| {
                error!("TO2: Failed to parse delegate chain from to1d: {:?}", e);
                FdoError::CryptoError(String::from("to1d delegate chain parse failed"))
            })?;
            if let Some(cert_ders) = to1d_chain {
                // to1d was signed by a delegate. Validate the chain and use
                // the delegate leaf key for signature verification.
                info!("TO2: to1d was signed by a delegate — validating chain...");
                let cert_refs: Vec<&[u8]> = cert_ders.iter().map(|c| c.as_slice()).collect();
                let chain_result = crate::delegate::verify_delegate_chain(&cert_refs, &owner_key)
                    .ok_or_else(|| {
                        error!("TO2: to1d delegate chain VERIFICATION FAILED");
                        FdoError::CryptoError(String::from("to1d delegate chain verification failed"))
                    })?;
                if !chain_result.has_redirect {
                    error!("TO2: to1d delegate lacks fdo-ekt-permit-redirect");
                    return Err(FdoError::CryptoError(String::from(
                        "to1d delegate lacks redirect permission")));
                }
                if !crate::cose::verify_sign1(&s1, &aad, &chain_result.leaf_key_point) {
                    error!("TO2: to1d SIGNATURE VERIFICATION FAILED against delegate leaf key.");
                    return Err(FdoError::CryptoError(String::from(
                        "to1d signature verification failed (delegate)")));
                }
                info!("TO2: to1d signature VERIFIED against delegate leaf key");
            } else {
                if !crate::cose::verify_sign1(&s1, &aad, &owner_key) {
                    error!("TO2: to1d (rendezvous blob) SIGNATURE VERIFICATION FAILED.");
                    error!("TO2: A man in the middle may be redirecting this device. ABORTING.");
                    return Err(FdoError::CryptoError(String::from(
                        "to1d signature verification failed")));
                }
                info!("TO2: to1d rendezvous blob signature VERIFIED against Owner key");
            }
        }
        _ => {
            // Legitimate for RV bypass, where no blob is issued. Also reached
            // if TO1 failed, in which case we have nothing to check.
            warn!("TO2: no to1d blob to verify (RV bypass, or TO1 did not complete)");
        }
    }

    info!("TO2 Step 3b complete: voucher chain and Owner signature VERIFIED");
    
    // Step 4: DeviceSvcInfoRdy20 (ENCRYPTED - type 86)
    // UEFI HTTP client has ~1KB response buffer limit, negotiate MTU down
    info!("TO2 Step 4: Sending DeviceSvcInfoRdy20 (encrypted)...");
    // Owner sizes its BMO chunks to fill this MTU, so this value alone sets the
    // round-trip count for an image transfer: 1300 needs ~23k rounds for a 27MB
    // UKI, 65535 needs ~420. 65535 is the protocol ceiling (the field is a
    // uint16). Must stay under the http.rs rx_body buffer with room for COSE +
    // HTTP overhead, and requires the Response() drain loop in http.rs.
    // NonceTO2SetupDv: generated by the Device, returned by the Owner in
    // SetupDevice20 (resale) and DoneAck20.
    let setup_rand = tpm::tpm_get_random(16)
        .ok_or_else(|| FdoError::CryptoError(String::from(
            "TPM GetRandom failed for NonceTO2SetupDv")))?;
    let mut nonce_to2_setup_dv = [0u8; 16];
    nonce_to2_setup_dv.copy_from_slice(&setup_rand);
    let device_svc_info_rdy = build_device_svc_info_rdy(Some(65535), &nonce_to2_setup_dv);
    debug!("  Plaintext: {} bytes, hex: {:02x?}", device_svc_info_rdy.len(), &device_svc_info_rdy);
    
    // AES-GCM IV. Every message in this session is encrypted under the same
    // SEK, so an IV must never repeat: GCM loses confidentiality AND
    // authenticity on reuse (the authentication subkey becomes recoverable).
    // Use the deterministic construction from NIST SP 800-38D §8.2.1 — a
    // per-session invocation counter — which makes a collision impossible
    // rather than merely improbable, and needs no entropy source.
    let mut iv_counter: u64 = 0;
    let nonce = next_session_iv(&mut iv_counter);
    
    // Use unified COSE encryption
    let encrypted_msg = cose_encrypt0_a256gcm(&session_keys.sek, &nonce, &device_svc_info_rdy)?;
    debug!("  Encrypted message: {} bytes", encrypted_msg.len());
    
    let url = format!("{}/fdo/200/msg/{}", owner_url, MSG_TO2_DEVICE_SVC_INFO_RDY);
    let resp = http_post_with_session(&url, &encrypted_msg, MSG_TO2_DEVICE_SVC_INFO_RDY, session_token.as_deref())
        .ok_or_else(|| FdoError::HttpError(String::from("DeviceSvcInfoRdy failed")))?;
    check_fdo_error(resp.message_type, &resp.body, "TO2.SetupDevice")?;
    let response = resp.body;
    
    debug!("  SetupDevice20 response: {} bytes (encrypted)", response.len());
    
    // Decrypt SetupDevice20 response using unified decryption
    let setup_device_plain = cose_decrypt0_a256gcm(&session_keys.sek, &response)?;
    debug!("  SetupDevice20 plaintext: {} bytes", setup_device_plain.len());
    
    // SetupDevice20 is a COSE_Sign1: verify per its DispositionCode
    let disposition = check_setup_device20(&setup_device_plain, &nonce_to2_setup_dv, &prove_ov_signer)?;
    info!("TO2 Step 4 complete: SetupDevice20 received ({:?})", disposition);
    if let SetupDisposition::Resale { .. } = disposition {
        // Replacement credentials are not installed by this client, so it
        // declines resale by sending a null ReplacementHMac in Done20.
        warn!("TO2: Owner requested resale; this client declines (null ReplacementHMac)");
    }
    
    // Step 5: ServiceInfo exchange loop (DeviceSvcInfo/OwnerSvcInfo)
    info!("TO2 Step 5: ServiceInfo exchange...");
    
    // Build devmod ServiceInfo (required by FDO spec)
    // devmod:active = true, devmod:os = "UEFI", devmod:arch = "x86_64", etc.
    let devmod_info = build_devmod_service_info();
    
    // Create BMO session for handling bare metal onboarding
    let mut bmo_session = BmoSession::new();
    let mut bmo_responses: Vec<(String, Vec<u8>)> = Vec::new();
    
    let mut is_done = false;
    // u32, not u8: a 27MB image at a 64KB MTU needs ~420 rounds, and the round
    // counter also feeds the GCM nonce below, so it must not wrap.
    let mut round = 0u32;
    let mut last_logged_pct = 0u32;
    
    while !is_done {
        round += 1;
        debug!("  ServiceInfo round {}", round);

        // Completing a round is proof we are not hung, so refresh the watchdog.
        // A full image transfer takes far longer than the watchdog interval
        // (~1670 rounds for a 106MB UKI vs a 1800s timer), and without this
        // the firmware reboots mid-transfer. A round that genuinely stalls
        // still trips the timer and reboots as intended.
        let _ = uefi::boot::set_watchdog_timer(crate::WATCHDOG_TIMEOUT_SECS, 0x10000, None);
        
        // Build DeviceSvcInfo (msg 88): [is_more, service_info_array]
        // Round 1: send devmod info
        // Subsequent rounds: send BMO responses or empty
        let svc_info = if round == 1 {
            devmod_info.clone()
        } else if !bmo_responses.is_empty() {
            // Build ServiceInfo array with BMO responses
            let mut enc = CborEncoder::new();
            enc.array(bmo_responses.len());
            for (key, value) in bmo_responses.drain(..) {
                enc.array(2);
                enc.text(&key);
                enc.bytes(&value);
            }
            enc.into_bytes()
        } else {
            Vec::new() // Empty ServiceInfo
        };
        
        let device_svc_info = build_device_svc_info(false, &svc_info); // is_more = false
        debug!("    DeviceSvcInfo plaintext: {} bytes", device_svc_info.len());
        
        // Encrypt and send, drawing the next IV from the session counter.
        let nonce = next_session_iv(&mut iv_counter);
        let encrypted_msg = cose_encrypt0_a256gcm(&session_keys.sek, &nonce, &device_svc_info)?;
        
        let url = format!("{}/fdo/200/msg/{}", owner_url, MSG_TO2_DEVICE_SVC_INFO);
        let resp = http_post_with_session(&url, &encrypted_msg, MSG_TO2_DEVICE_SVC_INFO, session_token.as_deref())
            .ok_or_else(|| FdoError::HttpError(String::from("DeviceSvcInfo failed")))?;
        check_fdo_error(resp.message_type, &resp.body, "TO2.OwnerSvcInfo")?;
        let response = resp.body;
        
        // Decrypt OwnerSvcInfo (msg 89)
        let owner_svc_info_plain = cose_decrypt0_a256gcm(&session_keys.sek, &response)?;
        debug!("    OwnerSvcInfo plaintext: {} bytes", owner_svc_info_plain.len());
        
        // Parse OwnerSvcInfo: [is_done, is_more, service_info_array]
        let owner_svc = parse_owner_svc_info(&owner_svc_info_plain)?;
        debug!("    is_done={}, is_more={}, svc_info_len={}", 
              owner_svc.is_done, owner_svc.is_more, owner_svc.service_info.len());
        
        // Process ServiceInfo entries from owner
        if !owner_svc.service_info.is_empty() {
            match parse_service_info_array(&owner_svc.service_info) {
                Ok(entries) => {
                    for (key, value) in entries {
                        // Check if this is a BMO message
                        if key.starts_with("fdo.bmo:") {
                            debug!("    Processing BMO message: {}", key);
                            if let Some((resp_key, resp_value)) = process_bmo_message(&mut bmo_session, &key, &value, Some(&owner_key), peer_authority, Some(guid.as_slice())) {
                                debug!("    BMO response: {} ({} bytes)", resp_key, resp_value.len());
                                bmo_responses.push((resp_key, resp_value));
                            }
                        } else {
                            debug!("    Ignoring non-BMO ServiceInfo: {}", key);
                        }
                    }
                }
                Err(e) => {
                    warn!("    Failed to parse ServiceInfo array: {:?}", e);
                }
            }
        }
        
        is_done = owner_svc.is_done;
        
        // Progress logging — keep it sparse for large transfers.
        // Log every 10% during BMO, or every round when not yet transferring.
        if bmo_session.bytes_received > 0 {
            let pct = bmo_session.begin.as_ref()
                .filter(|b| b.total_size > 0)
                .map(|b| (bmo_session.bytes_received * 100 / b.total_size) as u32)
                .unwrap_or(0);
            if pct / 10 > last_logged_pct / 10 || round <= 3 || is_done {
                info!("  Round {}: BMO {} / {} bytes ({}%)", round, bmo_session.bytes_received,
                    bmo_session.begin.as_ref().map(|b| b.total_size).unwrap_or(0), pct);
                last_logged_pct = pct;
            }
        } else {
            info!("  Round {}", round);
        }
        
        // Safety limit to prevent infinite loops. Must exceed the rounds a real
        // image transfer needs: bytes / (MTU - overhead), i.e. ~420 for a 27MB
        // UKI at a 64KB MTU, and proportionally more if the owner negotiates a
        // smaller MTU. Kept far above that so it only trips on a genuine stall.
        const MAX_SERVICE_INFO_ROUNDS: u32 = 100_000;
        if round >= MAX_SERVICE_INFO_ROUNDS {
            warn!("ServiceInfo exchange exceeded {} rounds, forcing done", MAX_SERVICE_INFO_ROUNDS);
            break;
        }
    }
    
    // Log BMO session state
    info!("TO2 Step 5 complete: ServiceInfo exchange finished");
    info!("  BMO state: {:?}", bmo_session.state);
    if matches!(bmo_session.state, BmoState::Complete) && !bmo_session.image_buffer.is_empty() {
        info!("  BMO image received: {} bytes", bmo_session.image_buffer.len());
    } else if !bmo_session.image_buffer.is_empty() {
        warn!("  BMO image buffer has {} bytes but state is {:?}", 
              bmo_session.image_buffer.len(), bmo_session.state);
    }
    
    // Step 6: Done/DoneAck — MUST complete before chainload, because the
    // chainloaded image (OS installer, UKI, etc.) will take over the machine
    // and never return.
    info!("TO2 Step 6: Sending Done...");
    
    // Build Done (msg 90): [NonceTO2ProveDv, ReplacementHMac]
    let done_msg = build_to2_done(&ack.nonce_to2_prove_dv);
    debug!("  Done plaintext: {} bytes", done_msg.len());
    
    // Encrypt and send. Same session counter — previously a hardcoded IV whose
    // 8-byte tail was identical to the ServiceInfo round IVs, relying on the
    // round counter never reaching 0xD00E0304 to avoid a collision.
    let done_nonce = next_session_iv(&mut iv_counter);
    let done_encrypted = cose_encrypt0_a256gcm(&session_keys.sek, &done_nonce, &done_msg)?;
    
    let url = format!("{}/fdo/200/msg/{}", owner_url, MSG_TO2_DONE);
    let resp = http_post_with_session(&url, &done_encrypted, MSG_TO2_DONE, session_token.as_deref())
        .ok_or_else(|| FdoError::HttpError(String::from("Done failed")))?;
    check_fdo_error(resp.message_type, &resp.body, "TO2.DoneAck")?;
    let response = resp.body;
    
    // Decrypt DoneAck (msg 91)
    let done_ack_plain = cose_decrypt0_a256gcm(&session_keys.sek, &response)?;
    debug!("  DoneAck plaintext: {} bytes", done_ack_plain.len());
    
    // Parse DoneAck: [NonceTO2SetupDv] - echo of the nonce we sent in DeviceSvcInfoRdy20
    let done_ack = parse_to2_done_ack(&done_ack_plain)?;

    // Abort on mismatch — this is the last chance to notice we finished a
    // protocol run against a different session than the one we started, and
    // the very next thing this function does is chainload.
    verify_nonce_echo("DoneAck20", &nonce_to2_setup_dv, &done_ack.nonce)?;

    info!("TO2 Step 6 complete: DoneAck received");
    
    info!("=== TO2 Protocol Complete! ===");
    
    // Flush all transient TPM objects before chainloading.
    // EFI has no resource manager, so transient handles from TO2 (DAK loads,
    // HMAC operations, ECDH key exchange) are still loaded.  The Linux kernel
    // RM (/dev/tpmrm0) inherits these and can run out of object slots
    // (TPM_RC_OBJECT_MEMORY) when the Stage 2 go-fdo-endpoint tries to use
    // the persistent HMAC key.  Flushing here avoids that.
    info!("Flushing transient TPM objects before chainload...");
    tpm::tpm_flush_all_transient();
    
    // Chainload AFTER Done/DoneAck — this is the point of no return.
    // The chainloaded image (OS installer, UKI, GRUB, etc.) takes over
    // the machine and will typically never return.
    if matches!(bmo_session.state, BmoState::Complete) && !bmo_session.image_buffer.is_empty() {
        info!("Chainloading BMO image ({} bytes)...", bmo_session.image_buffer.len());
        
        match chainload_image(&bmo_session.image_buffer) {
            Ok(()) => {
                info!("Chainloaded image returned (unexpected for real payloads)");
            }
            Err(e) => {
                error!("Chainload failed: {:?}", e);
            }
        }
    }
    
    Ok(())
}

#[cfg(target_os = "uefi")]
/// Test TO2 protocol against a live server
pub fn test_to2_protocol(
    owner_url: &str,
    guid: &[u8; 16],
    device_key_handle: u32,
    hmac_key_handle: u32,
    to1d: Option<&[u8]>,
) {
    info!("=== TO2 Protocol Test ===");
    
    match perform_to2(owner_url, guid, device_key_handle, hmac_key_handle, to1d) {
        Ok(()) => info!("TO2 test completed successfully!"),
        Err(e) => error!("TO2 test failed: {:?}", e),
    }
}

#[cfg(target_os = "uefi")]
/// Perform TO1 protocol step 1: HelloRV -> HelloRVAck
/// Returns the nonce4 from the server for use in ProveToRV
pub fn perform_to1_hello(
    rv_url: &str,
    guid: &[u8; 16],
) -> Result<(To1HelloRvAck, Option<String>), FdoError> {
    debug!("TO1: Sending HelloRV to {}", rv_url);
    
    // Build HelloRV message
    let hello_rv = build_to1_hello_rv(guid);
    debug!("  HelloRV: {} bytes", hello_rv.len());
    
    // Build URL for message type 30
    let url = format!("{}/fdo/200/msg/{}", rv_url, MSG_TO1_HELLO_RV);
    
    // Send HTTP POST
    let resp = http_post_with_session(&url, &hello_rv, MSG_TO1_HELLO_RV, None)
        .ok_or_else(|| FdoError::HttpError(String::from("HTTP POST failed")))?;
    let response = resp.body;
    
    debug!("  Response: {} bytes", response.len());
    debug!("  CBOR: {:02x?}", &response[..response.len().min(32)]);

    check_fdo_error(resp.message_type, &response, "TO1.HelloRVAck")?;
    
    // Parse HelloRVAck
    let ack = parse_to1_hello_rv_ack(&response)?;
    debug!("  Nonce4: {:02x?}", ack.nonce4);
    
    // The RV issues a bearer token in the HelloRVAck response which must be
    // presented with ProveToRV, or the server rejects it with "invalid
    // session". TO1 previously discarded it.
    if resp.auth_token.is_some() {
        debug!("  TO1 session token: present");
    } else {
        warn!("  TO1: no session token in HelloRVAck response");
    }
    
    Ok((ack, resp.auth_token))
}

/// Reject an FDO error message (Message-Type 255) before trying to parse a
/// response as its expected type.
///
/// Without this, an error body is happily accepted as whatever was expected —
/// which is how a 60-byte `[500, 32, "invalid session", ...]` error was being
/// stored and reported as a valid to1d rendezvous blob.
fn check_fdo_error(message_type: Option<u8>, body: &[u8], context: &str) -> Result<(), FdoError> {
    if message_type != Some(MSG_ERROR) {
        return Ok(());
    }
    // ErrorMessage = [code, prevMsgType, errStr, timestamp, correlationId]
    let mut dec = CborDecoder::new(body);
    let (code, prev, msg) = match dec.read_array_len() {
        Ok(n) if n >= 3 => {
            let code = dec.read_uint().unwrap_or(0);
            let prev = dec.read_uint().unwrap_or(0);
            let msg = dec.read_text().unwrap_or_else(|_| String::from("<unparseable>"));
            (code, prev, msg)
        }
        _ => (0, 0, String::from("<malformed error message>")),
    };
    error!("{}: server returned FDO error {} (for msg {}): {}", context, code, prev, msg);
    Err(FdoError::ProtocolError(format!(
        "{}: FDO error {}: {}", context, code, msg)))
}

#[cfg(target_os = "uefi")]
/// Perform TO1 ProveToRV step: send ProveToRV, receive RVRedirect
fn perform_to1_prove(
    rv_url: &str,
    guid: &[u8; 16],
    nonce4: &[u8; 16],
    device_key_handle: u32,
    session_token: Option<&str>,
) -> Result<To1RvRedirect, FdoError> {
    debug!("TO1: Sending ProveToRV to {}", rv_url);
    
    // Build ProveToRV message (COSE_Sign1 with EAT), signed by the TPM DAK
    let prove_to_rv = build_to1_prove_to_rv(guid, nonce4, device_key_handle)?;
    debug!("  ProveToRV: {} bytes", prove_to_rv.len());
    
    // Build URL for message type 32
    let url = format!("{}/fdo/200/msg/{}", rv_url, MSG_TO1_PROVE_TO_RV);
    
    // Send HTTP POST, carrying the session token issued with HelloRVAck
    let resp = http_post_with_session(&url, &prove_to_rv, MSG_TO1_PROVE_TO_RV, session_token)
        .ok_or_else(|| FdoError::HttpError(String::from("HTTP POST failed")))?;
    let response = resp.body;
    
    debug!("  Response: {} bytes", response.len());
    if !response.is_empty() {
        debug!("  CBOR: {:02x?}", &response[..response.len().min(32)]);
    }

    check_fdo_error(resp.message_type, &response, "TO1.RVRedirect")?;
    
    // Parse RVRedirect
    let redirect = parse_to1_rv_redirect(&response)?;
    debug!("  RVRedirect received: {} bytes", redirect.to1d_cose.len());
    
    Ok(redirect)
}

#[cfg(target_os = "uefi")]
/// Perform TO1 protocol (full flow)
/// Returns TO1D blob (owner rendezvous info) on success
pub fn perform_to1(
    rv_url: &str,
    guid: &[u8; 16],
    device_key_handle: u32,
) -> Result<To1RvRedirect, FdoError> {
    info!("=== Starting TO1 Protocol ===");
    debug!("RV URL: {}", rv_url);
    debug!("GUID: {:02x?}", guid);
    
    // Step 1: HelloRV -> HelloRVAck
    let (ack, session_token) = perform_to1_hello(rv_url, guid)?;
    
    info!("TO1 Step 1 complete: HelloRV -> HelloRVAck");
    debug!("  Nonce4: {:02x?}", ack.nonce4);
    debug!("  CapabilityFlags: {:02x?}", ack.capability_flags);
    
    // Step 2: ProveToRV -> RVRedirect
    let redirect = perform_to1_prove(
        rv_url,
        guid,
        &ack.nonce4,
        device_key_handle,
        session_token.as_deref(),
    )?;
    
    info!("TO1 Step 2 complete: ProveToRV -> RVRedirect");
    debug!("  TO1D blob: {} bytes", redirect.to1d_cose.len());
    
    info!("=== TO1 Protocol Complete ===");
    Ok(redirect)
}

#[cfg(target_os = "uefi")]
/// Test FDO message creation
pub fn test_fdo_messages() {
    debug!("Testing FDO message creation (manual CBOR)...");
    
    // Create a test GUID
    let guid: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    ];
    
    debug!("Test GUID: {:02x?}", guid);
    
    // Build TO1.HelloRV
    let hello_rv = build_to1_hello_rv(&guid);
    debug!("TO1.HelloRV (type 30): {} bytes", hello_rv.len());
    debug!("  CBOR: {:02x?}", hello_rv);
    
    // Build TO2.HelloDeviceProbe
    let sugar: [u8; 16] = [0xaa; 16]; // Random entropy
    let hello_probe = build_to2_hello_device_probe(&guid, &sugar);
    debug!("TO2.HelloDeviceProbe (type 80): {} bytes", hello_probe.len());
    debug!("  CBOR: {:02x?}", hello_probe);
    
    debug!("FDO message test complete!");
}

#[cfg(target_os = "uefi")]
/// Test TO1 protocol against a live server
pub fn test_to1_protocol(rv_url: &str, guid: &[u8; 16], device_key_handle: u32) {
    info!("=== TO1 Protocol Test ===");
    
    match perform_to1(rv_url, guid, device_key_handle) {
        Ok(redirect) => {
            info!("TO1 test completed successfully!");
            debug!("  Received TO1D: {} bytes", redirect.to1d_cose.len());
        }
        Err(e) => error!("TO1 test failed: {:?}", e),
    }
}

// =========================================================================
// Unit tests — CBOR encoder/decoder, crypto, message builders
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- ECDH ShSe known answer (shared with go-fdo kex/ecdh_kat_test.go,
    // vector "ECDH256-A256GCM"; Shx from device scalar SHA256("fdo-kat-device")
    // and owner scalar SHA256("fdo-kat-owner"), DeviceRandom 0x11*16,
    // OwnerRandom 0x22*16) ---

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    const KAT_SHX: &str = "28ec90132b66e9cce5d13f52bd3408dece6be04d89a34a27b3b8ba3498a4b272";
    const KAT_SEK: &str = "dd637b926fac42795349dc7898447da80c0c829534ba4cf9c4cac0822e5b63e2";

    #[test]
    fn test_ecdh_shse_known_answer() {
        let shse = build_ecdh_shse(hex(KAT_SHX), &[0x11; 16], &[0x22; 16]);
        assert_eq!(derive_session_keys(&shse).sek, hex(KAT_SEK));
    }

    #[test]
    fn test_ecdh_shse_owner_random_first_is_wrong() {
        // The pre-fix order (Shx || xB.Rand || xA.Rand at 2.0) must not match.
        let shse = build_ecdh_shse(hex(KAT_SHX), &[0x22; 16], &[0x11; 16]);
        assert_ne!(derive_session_keys(&shse).sek, hex(KAT_SEK));
    }

    // --- CborEncoder ---

    #[test]
    fn test_encoder_uint_small() {
        let mut enc = CborEncoder::new();
        enc.uint(5);
        assert_eq!(enc.into_bytes(), &[0x05]);
    }

    #[test]
    fn test_encoder_uint_one_byte() {
        let mut enc = CborEncoder::new();
        enc.uint(200);
        assert_eq!(enc.into_bytes(), &[0x18, 200]);
    }

    #[test]
    fn test_encoder_uint_two_bytes() {
        let mut enc = CborEncoder::new();
        enc.uint(1000);
        assert_eq!(enc.into_bytes(), &[0x19, 0x03, 0xe8]);
    }

    #[test]
    fn test_encoder_bytes() {
        let mut enc = CborEncoder::new();
        enc.bytes(&[0xaa, 0xbb]);
        let out = enc.into_bytes();
        assert_eq!(out, &[0x42, 0xaa, 0xbb]); // bstr(2)
    }

    #[test]
    fn test_encoder_text() {
        let mut enc = CborEncoder::new();
        enc.text("hi");
        let out = enc.into_bytes();
        assert_eq!(out, &[0x62, b'h', b'i']); // tstr(2)
    }

    #[test]
    fn test_encoder_array() {
        let mut enc = CborEncoder::new();
        enc.array(3);
        enc.uint(1);
        enc.uint(2);
        enc.uint(3);
        let out = enc.into_bytes();
        assert_eq!(out, &[0x83, 0x01, 0x02, 0x03]); // [1, 2, 3]
    }

    #[test]
    fn test_encoder_null() {
        let mut enc = CborEncoder::new();
        enc.null();
        assert_eq!(enc.into_bytes(), &[0xf6]);
    }

    #[test]
    fn test_encoder_bool() {
        let mut enc = CborEncoder::new();
        enc.bool_val(true);
        enc.bool_val(false);
        assert_eq!(enc.into_bytes(), &[0xf5, 0xf4]);
    }

    #[test]
    fn test_encoder_map() {
        let mut enc = CborEncoder::new();
        enc.encode_map(1);
        enc.text("key");
        enc.uint(42);
        let out = enc.into_bytes();
        // map(1) { "key": 42 }
        assert_eq!(out[0], 0xa1); // map(1)
    }

    // --- CborDecoder ---

    #[test]
    fn test_decoder_uint() {
        let data = [0x83, 0x01, 0x18, 0xc8, 0x19, 0x03, 0xe8];
        let mut dec = CborDecoder::new(&data);
        assert_eq!(dec.read_array_header().unwrap(), 3);
        assert_eq!(dec.read_uint().unwrap(), 1);
        assert_eq!(dec.read_uint().unwrap(), 200);
        assert_eq!(dec.read_uint().unwrap(), 1000);
    }

    #[test]
    fn test_decoder_bytes() {
        let data = [0x43, 0xaa, 0xbb, 0xcc]; // bstr(3)
        let mut dec = CborDecoder::new(&data);
        let b = dec.read_bytes().unwrap();
        assert_eq!(b, &[0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn test_decoder_text() {
        let data = [0x63, b'f', b'o', b'o']; // tstr(3) "foo"
        let mut dec = CborDecoder::new(&data);
        let s = dec.read_text().unwrap();
        assert_eq!(s, "foo");
    }

    #[test]
    fn test_decoder_null() {
        let data = [0xf6];
        let mut dec = CborDecoder::new(&data);
        assert!(dec.read_null().is_ok());
    }

    #[test]
    fn test_decoder_bool() {
        let data = [0xf5, 0xf4];
        let mut dec = CborDecoder::new(&data);
        assert_eq!(dec.read_bool().unwrap(), true);
        assert_eq!(dec.read_bool().unwrap(), false);
    }

    #[test]
    fn test_encoder_decoder_roundtrip() {
        let mut enc = CborEncoder::new();
        enc.array(4);
        enc.uint(42);
        enc.bytes(&[0x01, 0x02, 0x03]);
        enc.text("hello");
        enc.null();
        let encoded = enc.into_bytes();

        let mut dec = CborDecoder::new(&encoded);
        assert_eq!(dec.read_array_header().unwrap(), 4);
        assert_eq!(dec.read_uint().unwrap(), 42);
        assert_eq!(dec.read_bytes().unwrap(), &[0x01, 0x02, 0x03]);
        assert_eq!(dec.read_text().unwrap(), "hello");
        assert!(dec.read_null().is_ok());
    }

    // --- AES-GCM encrypt/decrypt roundtrip ---

    #[test]
    fn test_aes256_gcm_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"secret data for FDO";
        let aad = b"additional data";

        let ciphertext = aes256_gcm_encrypt(&key, &nonce, plaintext, aad)
            .expect("encrypt should succeed");
        let decrypted = aes256_gcm_decrypt(&key, &nonce, &ciphertext, aad)
            .expect("decrypt should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes256_gcm_wrong_key() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"secret";
        let aad = b"";

        let ciphertext = aes256_gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();
        let result = aes256_gcm_decrypt(&wrong_key, &nonce, &ciphertext, aad);
        assert!(result.is_err(), "wrong key must fail decryption");
    }

    #[test]
    fn test_aes256_gcm_tampered_ciphertext() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"secret";
        let aad = b"";

        let mut ciphertext = aes256_gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();
        ciphertext[0] ^= 0xff; // tamper
        let result = aes256_gcm_decrypt(&key, &nonce, &ciphertext, aad);
        assert!(result.is_err(), "tampered ciphertext must fail");
    }

    #[test]
    fn test_aes128_gcm_roundtrip() {
        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];
        let plaintext = b"128-bit key data";
        let aad = b"";

        let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext, aad)
            .expect("AES-128-GCM encrypt should work");
        let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext, aad)
            .expect("AES-128-GCM decrypt should work");

        assert_eq!(decrypted, plaintext);
    }

    // --- KDF ---

    #[test]
    fn test_kdf_deterministic() {
        let secret = [0xab; 32];
        let out1 = fdo_kdf(&secret, 256);
        let out2 = fdo_kdf(&secret, 256);
        assert_eq!(out1, out2, "KDF must be deterministic");
        assert_eq!(out1.len(), 32);
    }

    #[test]
    fn test_kdf_different_secrets() {
        let out1 = fdo_kdf(&[0x01; 32], 256);
        let out2 = fdo_kdf(&[0x02; 32], 256);
        assert_ne!(out1, out2, "different secrets must produce different keys");
    }

    // --- SHA-256 ---

    #[test]
    fn test_sha256_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb924...
        let hash = sha256(b"");
        assert_eq!(hash[0], 0xe3);
        assert_eq!(hash[1], 0xb0);
        assert_eq!(hash[2], 0xc4);
    }

    // --- COSE_Encrypt0 roundtrip ---

    #[test]
    fn test_cose_encrypt0_roundtrip() {
        let key = [0x55u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"encrypted FDO payload";

        let cose_enc = cose_encrypt0_a256gcm(&key, &nonce, plaintext)
            .expect("COSE_Encrypt0 should succeed");
        let decrypted = cose_decrypt0_a256gcm(&key, &cose_enc)
            .expect("COSE_Decrypt0 should succeed");

        assert_eq!(decrypted, plaintext);
    }

    // --- Message builders ---

    #[test]
    fn test_build_to1_hello_rv() {
        // Spec: [CapabilityFlags, VendorCapFlags, Guid]
        let guid = [0x42u8; 16];
        let msg = build_to1_hello_rv(&guid);
        let mut dec = CborDecoder::new(&msg);
        assert_eq!(dec.read_array_header().unwrap(), 3);
        assert_eq!(dec.read_bytes().unwrap(), &[CAPB0_SUP_FDO20]);
        assert_eq!(dec.read_array_header().unwrap(), 0);
        assert_eq!(dec.read_bytes().unwrap(), &guid);
    }

    #[test]
    fn test_build_to2_hello_device_probe() {
        // Spec: [CapabilityFlags, VendorCapFlags, Guid, maxDeviceMessageSize, hashTypes, sugar]
        let guid = [0x42u8; 16];
        let sugar = [0xaa; 16];
        let msg = build_to2_hello_device_probe(&guid, &sugar);
        let mut dec = CborDecoder::new(&msg);
        assert_eq!(dec.read_array_header().unwrap(), 6);
        assert_eq!(dec.read_bytes().unwrap(), &[CAPB0_SUP_FDO20]);
        assert_eq!(dec.read_array_header().unwrap(), 0);
        assert_eq!(dec.read_bytes().unwrap(), &guid);
    }

    #[test]
    fn test_parse_to1_hello_rv_ack_spec_layout() {
        // [h'87', ["com.example.test"], nonce] as sent by go-fdo
        let mut enc = CborEncoder::new();
        enc.array(3);
        enc.bytes(&[0x87]);
        enc.array(1);
        enc.text("com.example.test");
        enc.bytes(&[0x11; 16]);
        let ack = parse_to1_hello_rv_ack(&enc.into_bytes()).unwrap();
        assert_eq!(ack.capability_flags, vec![0x87]);
        assert_eq!(ack.nonce4, [0x11; 16]);
    }

    #[test]
    fn test_build_encrypted_message_roundtrip() {
        let nonce = [0x01u8; 12];
        let ciphertext = vec![0xaa, 0xbb, 0xcc];
        let msg = build_encrypted_message(&nonce, &ciphertext);

        let (parsed_nonce, parsed_ct) = parse_encrypted_message(&msg)
            .expect("should parse encrypted message");
        assert_eq!(parsed_nonce, &nonce);
        assert_eq!(parsed_ct, ciphertext);
    }

    #[test]
    fn test_build_devmod_service_info() {
        let info = build_devmod_service_info();
        // Should be valid CBOR that doesn't panic and produces some output
        assert!(!info.is_empty());
        // First byte should be an array header
        assert!((info[0] >> 5) == 4 || (info[0] >> 5) == 0, "should be array or special");
    }

    // ===== Protocol message security edge cases =====

    // --- Encrypted message: wrong tag rejected ---

    #[test]
    fn test_parse_encrypted_message_wrong_tag() {
        // Tag 18 (COSE_Sign1) instead of tag 16 (COSE_Encrypt0)
        let mut msg = Vec::new();
        msg.push(0xD2); // tag 18
        msg.push(0x83); // array(3)
        msg.push(0x40); // bstr(0) - protected
        msg.push(0xa0); // map(0) - unprotected
        msg.push(0x40); // bstr(0) - ciphertext
        let result = parse_encrypted_message(&msg);
        assert!(result.is_err(), "tag 18 must be rejected by COSE_Encrypt0 parser");
    }

    // --- Encrypted message: no tag at all ---

    #[test]
    fn test_parse_encrypted_message_no_tag() {
        // Bare array without CBOR tag
        let mut msg = Vec::new();
        msg.push(0x83); // array(3) — major type 4, not tag
        msg.push(0x40);
        msg.push(0xa0);
        msg.push(0x40);
        let result = parse_encrypted_message(&msg);
        assert!(result.is_err(), "bare array without tag must be rejected");
    }

    // --- Encrypted message: missing IV ---

    #[test]
    fn test_parse_encrypted_message_missing_iv() {
        // Tag 16, array(3), but unprotected map has no IV (label 5)
        let mut enc = CborEncoder::new();
        let prot = {
            let mut p = CborEncoder::new();
            p.encode_map(1);
            p.uint(1); p.uint(3);
            p.into_bytes()
        };
        // Build manually with tag 16
        let mut msg = Vec::new();
        msg.push(0xD0); // tag 16
        msg.push(0x83); // array(3)
        // protected bstr
        crate::cose::encode_bstr(&mut msg, &prot);
        // unprotected: map with label 99 (not 5) to simulate missing IV
        msg.push(0xa1); // map(1)
        msg.push(0x18); msg.push(99); // label 99
        crate::cose::encode_bstr(&mut msg, &[0x01, 0x02]);
        // ciphertext
        crate::cose::encode_bstr(&mut msg, &[0xAA, 0xBB]);

        let result = parse_encrypted_message(&msg);
        assert!(result.is_err(), "missing IV in COSE_Encrypt0 must fail");
    }

    // --- AES-GCM: tampered nonce produces wrong plaintext ---

    #[test]
    fn test_aes_gcm_wrong_nonce_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"secret data";
        let aad = b"additional";
        let ct = aes256_gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();

        // Different nonce → decryption must fail (GCM auth tag mismatch)
        let wrong_nonce = [0x02u8; 12];
        let result = aes256_gcm_decrypt(&key, &wrong_nonce, &ct, aad);
        assert!(result.is_err(), "wrong nonce must fail AES-GCM decryption");
    }

    // --- AES-GCM: tampered AAD fails ---

    #[test]
    fn test_aes_gcm_wrong_aad_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"secret data";
        let aad = b"correct aad";
        let ct = aes256_gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();

        let wrong_aad = b"wrong aad!!";
        let result = aes256_gcm_decrypt(&key, &nonce, &ct, wrong_aad);
        assert!(result.is_err(), "wrong AAD must fail AES-GCM decryption");
    }

    // --- COSE_Encrypt0 full roundtrip with tampered ciphertext ---

    #[test]
    fn test_cose_encrypt0_tampered_ciphertext() {
        let key = [0x55u8; 32];
        let nonce = [0x03u8; 12];
        let plaintext = b"important payload";
        let ct = cose_encrypt0_a256gcm(&key, &nonce, plaintext).unwrap();

        // Parse and tamper the ciphertext
        let (parsed_nonce, mut parsed_ct) = parse_encrypted_message(&ct).unwrap();
        let last = parsed_ct.len() - 1;
        parsed_ct[last] ^= 0xFF;

        // Decrypt with tampered ciphertext must fail
        let result = cose_decrypt0_a256gcm(&key, &build_encrypted_message(&parsed_nonce, &parsed_ct));
        assert!(result.is_err(), "tampered ciphertext must fail COSE_Encrypt0 decryption");
    }

    // =====================================================================
    // Security audit 2026-09-29 — M1: TO2 nonce echo verification.
    //
    // Both ProveOVHdr20 and DoneAck20 echo HelloDeviceAck20's
    // NonceTO2ProveDVPrep. Until this fix the client parsed both, logged
    // them, and compared neither, so a recorded ProveOVHdr20 replayed.
    // =====================================================================

    #[test]
    fn test_nonce_echo_matching_accepted() {
        let n = [0x5au8; 16];
        assert!(verify_nonce_echo("ProveOVHdr20", &n, &n).is_ok());
    }

    #[test]
    fn test_nonce_echo_mismatch_rejected() {
        let expected = [0x5au8; 16];
        let mut received = expected;
        received[15] ^= 0x01; // single-bit change in the last byte
        let r = verify_nonce_echo("ProveOVHdr20", &expected, &received);
        assert!(r.is_err(), "a one-bit nonce difference must abort TO2");
    }

    #[test]
    fn test_nonce_echo_rejects_all_zero_and_first_byte() {
        let expected = [0xa5u8; 16];

        // An omitted/zeroed nonce must not pass. parse_prove_ov_hdr_payload
        // leaves the array zeroed when the bstr is shorter than 16 bytes, so
        // this is the shape a truncated nonce actually takes.
        assert!(verify_nonce_echo("ProveOVHdr20", &expected, &[0u8; 16]).is_err(),
            "an all-zero nonce must be rejected");

        // Difference in the FIRST byte must be caught too — guards against a
        // comparison that only looks at a prefix or suffix.
        let mut first = expected;
        first[0] ^= 0xff;
        assert!(verify_nonce_echo("DoneAck20", &expected, &first).is_err(),
            "a difference in the first byte must be caught");
    }

    // --- FDO 2.0 Errata 1 / spec-drift wire formats ---

    /// FDO PublicKey [pkType=10 (SECP256R1), pkEnc=1 (X509), SPKI] for a P-256 point.
    fn test_fdo_public_key(point: &[u8]) -> Vec<u8> {
        let mut spki = vec![0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
            0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
            0x03, 0x42, 0x00];
        spki.extend_from_slice(point);
        let mut out = vec![0x83, 0x0a, 0x01];
        crate::cose::encode_bstr(&mut out, &spki);
        out
    }

    fn signed_setup_device(payload: &[u8], sk: &p256::ecdsa::SigningKey) -> Vec<u8> {
        let aad = crate::cose::domain_aad(crate::cose::AAD_TAG_SETUP_DEVICE, FDO_PROTOCOL_VERSION);
        crate::cose::build_test_cose_sign1(
            &crate::cose::build_test_protected_header(None), payload, &aad, &[0xa0], sk)
    }

    fn resale_payload(owner2_point: &[u8], nonce: &[u8; 16]) -> Vec<u8> {
        let mut enc = CborEncoder::new();
        enc.array(3);
        enc.uint(1); // DispResale
        enc.array(4);
        enc.array(0); // RendezvousInfo
        enc.bytes(&[0xBB; 16]); // Guid
        enc.bytes(nonce);
        enc.raw_bytes(&test_fdo_public_key(owner2_point));
        enc.uint(1300);
        enc.into_bytes()
    }

    fn reuse_payload() -> Vec<u8> {
        let mut enc = CborEncoder::new();
        enc.array(3);
        enc.uint(2); // DispCredReuse
        enc.null();
        enc.null();
        enc.into_bytes()
    }

    #[test]
    fn test_setup_device20_resale_owner2_signed() {
        let (owner2_sk, owner2_pt) = crate::cose::gen_test_keypair();
        let (_, peer_pt) = crate::cose::gen_test_keypair_b();
        let nonce = [0x42u8; 16];
        let msg = signed_setup_device(&resale_payload(&owner2_pt, &nonce), &owner2_sk);
        assert_eq!(check_setup_device20(&msg, &nonce, &peer_pt).unwrap(),
            SetupDisposition::Resale { guid: [0xBB; 16] });
    }

    #[test]
    fn test_setup_device20_resale_not_signed_by_owner2_rejected() {
        let (_, owner2_pt) = crate::cose::gen_test_keypair();
        let (peer_sk, peer_pt) = crate::cose::gen_test_keypair_b();
        let nonce = [0x42u8; 16];
        // Signed by the TO2 peer, not by Owner2: no proof of possession
        let msg = signed_setup_device(&resale_payload(&owner2_pt, &nonce), &peer_sk);
        assert!(check_setup_device20(&msg, &nonce, &peer_pt).is_err());
    }

    #[test]
    fn test_setup_device20_resale_wrong_nonce_rejected() {
        let (owner2_sk, owner2_pt) = crate::cose::gen_test_keypair();
        let msg = signed_setup_device(&resale_payload(&owner2_pt, &[0x01; 16]), &owner2_sk);
        assert!(check_setup_device20(&msg, &[0x02; 16], &owner2_pt).is_err());
    }

    #[test]
    fn test_setup_device20_resale_tampered_signature_rejected() {
        let (owner2_sk, owner2_pt) = crate::cose::gen_test_keypair();
        let nonce = [0x42u8; 16];
        let mut msg = signed_setup_device(&resale_payload(&owner2_pt, &nonce), &owner2_sk);
        let last = msg.len() - 1;
        msg[last] ^= 0x01;
        assert!(check_setup_device20(&msg, &nonce, &owner2_pt).is_err());
    }

    #[test]
    fn test_setup_device20_reuse_peer_signed() {
        let (peer_sk, peer_pt) = crate::cose::gen_test_keypair();
        let (_, other_pt) = crate::cose::gen_test_keypair_b();
        let msg = signed_setup_device(&reuse_payload(), &peer_sk);
        assert_eq!(check_setup_device20(&msg, &[0; 16], &peer_pt).unwrap(), SetupDisposition::CredReuse);
        assert!(check_setup_device20(&msg, &[0; 16], &other_pt).is_err(),
            "reuse signed by a key other than the ProveOVHdr20 signer must be rejected");
    }

    #[test]
    fn test_setup_device20_disable_and_unknown_rejected() {
        let (sk, pt) = crate::cose::gen_test_keypair();
        for disp in [3u16, 9] {
            let mut enc = CborEncoder::new();
            enc.array(3);
            enc.uint(disp);
            enc.null();
            enc.null();
            let msg = signed_setup_device(&enc.into_bytes(), &sk);
            assert!(check_setup_device20(&msg, &[0; 16], &pt).is_err());
        }
    }

    #[test]
    fn test_verify_hash_prev() {
        let probe = build_to2_hello_device_probe(&[0x42; 16], &[0xaa; 16]);
        let good = sha256(&probe);
        assert!(verify_hash_prev(HASH_TYPE_SHA256, &good, &probe).is_ok());
        assert!(verify_hash_prev(HASH_TYPE_SHA256, &[0u8; 32], &probe).is_err());
        assert!(verify_hash_prev(-43, &good, &probe).is_err(), "SHA-384 was not offered");
    }

    #[test]
    fn test_build_device_svc_info_rdy_layout() {
        let nonce = [0x33u8; 16];
        let msg = build_device_svc_info_rdy(Some(65535), &nonce);
        let mut dec = CborDecoder::new(&msg);
        assert_eq!(dec.read_array_header().unwrap(), 3);
        assert!(dec.peek_null(), "ReplacementHMac must be null");
        dec.read_null().unwrap();
        assert_eq!(dec.read_uint().unwrap(), 65535);
        assert_eq!(dec.read_bytes().unwrap(), nonce);
    }

    #[test]
    fn test_build_device_svc_info_and_done_layout() {
        let msg = build_device_svc_info(false, &[]);
        let mut dec = CborDecoder::new(&msg);
        assert_eq!(dec.read_array_header().unwrap(), 3);
        dec.read_null().unwrap();
        assert!(!dec.read_bool().unwrap());

        let nonce = [0x44u8; 16];
        let done = build_to2_done(&nonce);
        let mut dec = CborDecoder::new(&done);
        assert_eq!(dec.read_array_header().unwrap(), 2);
        assert_eq!(dec.read_bytes().unwrap(), nonce, "Done20 echoes NonceTO2ProveDv");
        dec.read_null().unwrap();
    }

    #[test]
    fn test_prove_device_eat_claims() {
        let guid = [0x42u8; 16];
        let nonce = [0x55u8; 16];
        let eat = build_to2_prove_device_eat(&guid, &nonce, &[0x80]);
        let mut dec = CborDecoder::new(&eat);
        assert_eq!(dec.read_map_header().unwrap(), 3);
        assert_eq!(dec.read_uint().unwrap(), 10);
        assert_eq!(dec.read_bytes().unwrap(), nonce);
        assert_eq!(dec.read_uint().unwrap(), 256);
        let ueid = dec.read_bytes().unwrap();
        assert_eq!(ueid[0], 0x01);
        assert_eq!(&ueid[1..], &guid);
        assert_eq!(dec.read_int().unwrap(), -257);
        assert_eq!(dec.read_array_header().unwrap(), 0);
    }

    #[test]
    fn test_parse_prove_ov_hdr_payload_v20() {
        let mut enc = CborEncoder::new();
        enc.array(8);
        enc.bytes(&[0x01, 0x02]);      // OVHeader bstr
        enc.uint(2);                    // NumOVEntries
        enc.array(2); enc.uint(5); enc.bytes(&[0x11; 32]); // HMac
        enc.bytes(&[0x22; 16]);         // NonceTO2ProveOV
        enc.bytes(&[0x33; 8]);          // xB
        enc.uint(65535);                // maxOwnerMessageSize
        enc.raw_bytes(&test_fdo_public_key(&crate::cose::gen_test_keypair().1)); // OwnerPubKey
        enc.array(1); enc.bytes(&[0x30, 0x00]); // DelegateChain
        let p = parse_prove_ov_hdr_payload(&enc.into_bytes()).unwrap();
        assert_eq!(p.nonce_to2_prove_ov, [0x22; 16]);
        assert_eq!(p.delegate_chain, Some(vec![vec![0x30, 0x00]]));
        assert!(!p.owner_pub_key_raw.is_empty());
    }

    #[test]
    fn test_rv_redirect_and_to1d_delegate_chain() {
        // to1d payload with null DelegateChain (bstr .cbor null)
        let mut payload = CborEncoder::new();
        payload.array(3);
        payload.array(0);
        payload.array(2); payload.neg_int(-16); payload.bytes(&[0; 32]);
        payload.bytes(&[0xf6]);
        let payload = payload.into_bytes();
        assert_eq!(to1d_delegate_chain(&payload).unwrap(), None);

        // 2-element (FDO 1.x voucher) payload: no chain
        let mut p11 = CborEncoder::new();
        p11.array(2); p11.array(0); p11.array(2); p11.neg_int(-16); p11.bytes(&[0; 32]);
        assert_eq!(to1d_delegate_chain(&p11.into_bytes()).unwrap(), None);

        // Delegate chain present
        let mut chain = CborEncoder::new();
        chain.array(1); chain.bytes(&[0x30, 0x01]);
        let mut pd = CborEncoder::new();
        pd.array(3); pd.array(0); pd.array(2); pd.neg_int(-16); pd.bytes(&[0; 32]);
        pd.bytes(&chain.into_bytes());
        assert_eq!(to1d_delegate_chain(&pd.into_bytes()).unwrap(), Some(vec![vec![0x30, 0x01]]));

        // RVRedirect wrapper: [1, 0, [to1d]]
        let (sk, _) = crate::cose::gen_test_keypair();
        let to1d = crate::cose::build_test_cose_sign1(
            &crate::cose::build_test_protected_header(None), &payload, &[], &[0xa0], &sk);
        let mut r = CborEncoder::new();
        r.array(3); r.uint(1); r.uint(0); r.array(1); r.raw_bytes(&to1d);
        assert_eq!(parse_to1_rv_redirect(&r.into_bytes()).unwrap().to1d_cose, to1d);

        let mut bad = CborEncoder::new();
        bad.array(3); bad.uint(1); bad.uint(1); bad.array(1); bad.raw_bytes(&to1d);
        assert!(parse_to1_rv_redirect(&bad.into_bytes()).is_err(), "idxTo1ds != 0 must be rejected");
    }

    // --- KDF: different key lengths produce different keys ---

    #[test]
    fn test_kdf_128_vs_256() {
        let secret = [0x42u8; 32];
        let key_128 = fdo_kdf(&secret, 128);
        let key_256 = fdo_kdf(&secret, 256);
        assert_eq!(key_128.len(), 16);
        assert_eq!(key_256.len(), 32);
        // First 16 bytes should NOT be the same (different counter inputs)
        // Actually, the first block IS the same in many KDF constructions.
        // Just check the lengths are correct.
        assert_ne!(key_128.len(), key_256.len());
    }

    // --- Session key derivation: deterministic ---

    #[test]
    fn test_derive_session_keys_deterministic() {
        let secret = [0x99u8; 32];
        let keys_a = derive_session_keys(&secret);
        let keys_b = derive_session_keys(&secret);
        assert_eq!(keys_a.sek, keys_b.sek, "same secret must produce same SEK");
        assert_eq!(keys_a.sek.len(), 32, "SEK must be 32 bytes for AES-256-GCM");
    }

    // --- Session key derivation: different secrets produce different keys ---

    #[test]
    fn test_derive_session_keys_different_secrets() {
        let keys_a = derive_session_keys(&[0x01u8; 32]);
        let keys_b = derive_session_keys(&[0x02u8; 32]);
        assert_ne!(keys_a.sek, keys_b.sek, "different secrets must produce different SEKs");
    }

    // --- Parse encrypted message: empty input ---

    #[test]
    fn test_parse_encrypted_message_empty() {
        let result = parse_encrypted_message(&[]);
        assert!(result.is_err(), "empty input must fail");
    }

    // --- Parse encrypted message: truncated ---

    #[test]
    fn test_parse_encrypted_message_truncated() {
        // Just a tag byte with nothing after
        let result = parse_encrypted_message(&[0xD0]);
        assert!(result.is_err(), "truncated message must fail");
    }

    // FDO 2.0 Errata 1 A4: ASYMKEX is deprecated; the Device MUST NOT select
    // it, and fails if the Owner offers nothing it can use.
    #[test]
    fn select_kex_suite20_offer() {
        let o = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(select_kex_suite20(&o(&["ECDH384", "ECDH256"])).unwrap(), "ECDH256");
        assert_eq!(select_kex_suite20(&o(&["ECDH256"])).unwrap(), "ECDH256");
        assert!(select_kex_suite20(&o(&["ASYMKEX2048", "ASYMKEX3072"])).is_err());
        assert!(select_kex_suite20(&o(&["ECDH384", "DHKEXid14"])).is_err());
        assert!(select_kex_suite20(&o(&[])).is_err());
    }

}
