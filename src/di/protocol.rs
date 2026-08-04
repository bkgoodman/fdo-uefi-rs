// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// FDO Device Initialization Protocol Implementation
//
// Minimal implementation for UEFI. Performs:
// 1. Create DAK (Device Attestation Key) in TPM
// 2. Create HMAC key in TPM
// 3. Generate CSR signed by TPM
// 4. Send DIAppStart with DeviceMfgInfo
// 5. Receive DISetCredentials with OVHeader
// 6. Compute HMAC over OVHeader
// 7. Send DISetHMAC
// 8. Receive DIDone
// 9. Write DCTPM to TPM NV index

use alloc::string::String;
use alloc::vec::Vec;
use alloc::vec;
use alloc::format;
use log::{info, error, warn};
use uefi::Status;

use crate::http::http_post;
use crate::tpm;
use super::mfginfo::{DeviceMfgInfo, KEY_TYPE_SECP256R1};

/// DI protocol message types (FDO 2.0)
const MSG_TYPE_DI_APP_START: u8 = 10;
const MSG_TYPE_DI_SET_CREDENTIALS: u8 = 11;
const MSG_TYPE_DI_SET_HMAC: u8 = 12;
const MSG_TYPE_DI_DONE: u8 = 13;

/// FDO 2.0 capability flags
const CAPABILITY_FLAGS_FDO20: u32 = 0x0001;

/// TPM persistent handles (per securing-fdo-in-tpm.bs)
const FDO_DAK_HANDLE: u32 = 0x81020002;
const FDO_HMAC_HANDLE: u32 = 0x81020003;

/// TPM NV index for DCTPM (per securing-fdo-in-tpm.bs)
const FDO_NV_INDEX_DCTPM: u32 = 0x01D10001;

/// Run the Device Initialization protocol
pub fn run_di_protocol() -> Status {
    info!("===========================================");
    info!("  FDO Device Initialization (DI) Protocol");
    info!("===========================================");
    
    // 1. Get manufacturing server URL
    let mfg_server_url = match get_manufacturing_server_url() {
        Some(url) => {
            info!("Manufacturing server: {}", url);
            url
        }
        None => {
            error!("No manufacturing server URL configured");
            return Status::NOT_FOUND;
        }
    };
    
    // 2. Create or retrieve device key (DAK) in TPM
    info!("Creating device key in TPM...");
    let (dak_handle, public_x, public_y) = match tpm::tpm_create_signing_key() {
        Some(key) => {
            info!("DAK created: handle=0x{:08x}", key.handle);
            (key.handle, key.public_x, key.public_y)
        }
        None => {
            error!("Failed to create device key in TPM");
            return Status::DEVICE_ERROR;
        }
    };
    
    // 3. Create HMAC key in TPM
    info!("Creating HMAC key in TPM...");
    let hmac_handle = match tpm::tpm_create_hmac_key() {
        Some(handle) => {
            info!("HMAC key created: handle=0x{:08x}", handle);
            handle
        }
        None => {
            error!("Failed to create HMAC key in TPM");
            tpm::tpm_flush_context(dak_handle);
            return Status::DEVICE_ERROR;
        }
    };
    
    // 4. Generate CSR using TPM-based signing
    info!("Generating CSR...");
    let serial_number = get_device_serial();
    let model = get_device_model();
    let csr_der = match generate_csr(&serial_number, &public_x, &public_y, dak_handle) {
        Some(csr) => {
            info!("CSR generated: {} bytes", csr.len());
            csr
        }
        None => {
            error!("Failed to generate CSR");
            tpm::tpm_flush_context(dak_handle);
            tpm::tpm_flush_context(hmac_handle);
            return Status::DEVICE_ERROR;
        }
    };
    
    // 5. Build DeviceMfgInfo
    let device_mfg_info = DeviceMfgInfo::new(serial_number.clone(), model.clone(), csr_der);
    let mfg_info_cbor = device_mfg_info.to_cbor();
    info!("DeviceMfgInfo: {} bytes", mfg_info_cbor.len());
    
    // 6. Send DIAppStart
    info!("Sending DIAppStart...");
    let app_start_msg = build_di_app_start(&mfg_info_cbor);
    let set_credentials_response = match send_di_message(&mfg_server_url, MSG_TYPE_DI_APP_START, &app_start_msg) {
        Some((msg_type, payload)) => {
            if msg_type != MSG_TYPE_DI_SET_CREDENTIALS {
                error!("Expected DISetCredentials ({}), got {}", MSG_TYPE_DI_SET_CREDENTIALS, msg_type);
                return Status::PROTOCOL_ERROR;
            }
            info!("Received DISetCredentials: {} bytes", payload.len());
            payload
        }
        None => {
            error!("Failed to send DIAppStart");
            return Status::PROTOCOL_ERROR;
        }
    };
    
    // 7. Parse DISetCredentials to get OVHeader
    let ov_header = match parse_di_set_credentials(&set_credentials_response) {
        Some(header) => {
            info!("OVHeader parsed: GUID={:02x?}", &header.guid);
            header
        }
        None => {
            error!("Failed to parse DISetCredentials");
            return Status::PROTOCOL_ERROR;
        }
    };
    
    // 8. Compute HMAC over OVHeader using TPM
    info!("Computing HMAC over OVHeader...");
    let ov_header_cbor = ov_header.to_cbor();
    let hmac_value = match tpm::tpm_hmac(hmac_handle, &ov_header_cbor) {
        Some(hmac) => {
            info!("HMAC computed: {} bytes", hmac.len());
            hmac
        }
        None => {
            error!("Failed to compute HMAC");
            return Status::DEVICE_ERROR;
        }
    };
    
    // 9. Send DISetHMAC
    info!("Sending DISetHMAC...");
    let set_hmac_msg = build_di_set_hmac(&hmac_value);
    match send_di_message(&mfg_server_url, MSG_TYPE_DI_SET_HMAC, &set_hmac_msg) {
        Some((msg_type, _payload)) => {
            if msg_type != MSG_TYPE_DI_DONE {
                error!("Expected DIDone ({}), got {}", MSG_TYPE_DI_DONE, msg_type);
                return Status::PROTOCOL_ERROR;
            }
            info!("Received DIDone");
        }
        None => {
            error!("Failed to send DISetHMAC");
            return Status::PROTOCOL_ERROR;
        }
    };
    
    // 10. Persist keys to TPM (EvictControl)
    info!("Persisting keys to TPM...");
    if !tpm::tpm_evict_control(dak_handle, FDO_DAK_HANDLE) {
        warn!("Failed to persist DAK (may already exist)");
    }
    if !tpm::tpm_evict_control(hmac_handle, FDO_HMAC_HANDLE) {
        warn!("Failed to persist HMAC key (may already exist)");
    }
    
    // 11. Write DCTPM to NV index
    info!("Writing DCTPM to TPM NV...");
    let dctpm = build_dctpm(&ov_header, FDO_DAK_HANDLE, FDO_HMAC_HANDLE);
    if !tpm::tpm_nv_write(FDO_NV_INDEX_DCTPM, &dctpm) {
        error!("Failed to write DCTPM to NV");
        return Status::DEVICE_ERROR;
    }
    
    info!("===========================================");
    info!("  Device Initialization COMPLETE");
    info!("  GUID: {:02x?}", ov_header.guid);
    info!("===========================================");
    
    Status::SUCCESS
}

/// Get manufacturing server URL from UEFI variable
/// Per fdo-appnote-device-mfg-info.bs §mfg-server-discovery
fn get_manufacturing_server_url() -> Option<String> {
    // TODO: Read from UEFI variable "FdoMfgServerUrl"
    // For minimal testing, use hardcoded URL (QEMU user-mode networking)
    Some(String::from("http://10.0.2.2:8080"))
}

/// Get device serial number (placeholder)
fn get_device_serial() -> String {
    // TODO: Read from SMBIOS or UEFI variable
    String::from("UEFI-DI-TEST-001")
}

/// Get device model (placeholder)
fn get_device_model() -> String {
    // TODO: Read from SMBIOS or UEFI variable
    String::from("FDO UEFI Reference Device")
}

/// Build DIAppStart message (FDO 2.0)
/// Format: [CapabilityFlags, VendorCapFlags, DeviceMfgInfo]
fn build_di_app_start(device_mfg_info: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(device_mfg_info.len() + 16);
    
    // Array of 3 elements
    buf.push(0x83);
    
    // CapabilityFlags: uint (FDO 2.0 = 0x0001)
    buf.push(0x19); // uint16
    buf.push((CAPABILITY_FLAGS_FDO20 >> 8) as u8);
    buf.push((CAPABILITY_FLAGS_FDO20 & 0xFF) as u8);
    
    // VendorCapFlags: uint (0 = none)
    buf.push(0x00);
    
    // DeviceMfgInfo: bstr (already bstr-wrapped)
    buf.extend_from_slice(device_mfg_info);
    
    buf
}

/// Build DISetHMAC message
/// Format: [Hash] where Hash = [hashType, hashValue]
fn build_di_set_hmac(hmac: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(hmac.len() + 8);
    
    // Array of 1 element (the Hash)
    buf.push(0x81);
    
    // Hash = [hashType, hashValue]
    buf.push(0x82);  // array(2)
    
    // hashType: -16 for HMAC-SHA256 (per FDO spec, negative = HMAC)
    buf.push(0x2F);  // negative(-16) = -1 - 15 = 0x20 | 0x0F
    
    // hashValue as bstr
    let len = hmac.len();
    if len < 24 {
        buf.push(0x40 | len as u8);
    } else if len < 256 {
        buf.push(0x58);
        buf.push(len as u8);
    } else {
        buf.push(0x59);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
    buf.extend_from_slice(hmac);
    
    buf
}

/// Send DI message (simple HTTP POST)
fn send_di_message(server_url: &str, msg_type: u8, payload: &[u8]) -> Option<(u8, Vec<u8>)> {
    let url = format!("{}/fdo/101/msg/{}", server_url, msg_type);
    
    match http_post(&url, payload, msg_type) {
        Some(response) => {
            // Response message type is always request + 1 in DI protocol
            let response_type = msg_type + 1;
            Some((response_type, response))
        }
        None => None,
    }
}

/// Parsed OVHeader from DISetCredentials
pub struct OVHeader {
    pub guid: [u8; 16],
    pub rv_info: Vec<u8>,
    pub device_info: String,
    pub pub_key: Vec<u8>,
    pub cert_chain_hash: Vec<u8>,
}

impl OVHeader {
    /// Encode OVHeader as CBOR for HMAC computation
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        
        // OVHeader is a CBOR array
        buf.push(0x85); // array(5)
        
        // [0] OVProtVer (200 for FDO 2.0)
        buf.push(0x18); // uint8
        buf.push(200);
        
        // [1] OVGuid (bstr)
        buf.push(0x50); // bstr(16)
        buf.extend_from_slice(&self.guid);
        
        // [2] OVRVInfo (bstr, pre-encoded)
        let rv_len = self.rv_info.len();
        if rv_len < 24 {
            buf.push(0x40 | rv_len as u8);
        } else if rv_len < 256 {
            buf.push(0x58);
            buf.push(rv_len as u8);
        } else {
            buf.push(0x59);
            buf.push((rv_len >> 8) as u8);
            buf.push(rv_len as u8);
        }
        buf.extend_from_slice(&self.rv_info);
        
        // [3] OVDeviceInfo (tstr)
        let info_len = self.device_info.len();
        if info_len < 24 {
            buf.push(0x60 | info_len as u8);
        } else if info_len < 256 {
            buf.push(0x78);
            buf.push(info_len as u8);
        } else {
            buf.push(0x79);
            buf.push((info_len >> 8) as u8);
            buf.push(info_len as u8);
        }
        buf.extend_from_slice(self.device_info.as_bytes());
        
        // [4] OVPublicKey (bstr, pre-encoded)
        let pk_len = self.pub_key.len();
        if pk_len < 24 {
            buf.push(0x40 | pk_len as u8);
        } else if pk_len < 256 {
            buf.push(0x58);
            buf.push(pk_len as u8);
        } else {
            buf.push(0x59);
            buf.push((pk_len >> 8) as u8);
            buf.push(pk_len as u8);
        }
        buf.extend_from_slice(&self.pub_key);
        
        // [5] OVCertChainHash (bstr)
        let hash_len = self.cert_chain_hash.len();
        if hash_len < 24 {
            buf.push(0x40 | hash_len as u8);
        } else if hash_len < 256 {
            buf.push(0x58);
            buf.push(hash_len as u8);
        } else {
            buf.push(0x59);
            buf.push((hash_len >> 8) as u8);
            buf.push(hash_len as u8);
        }
        buf.extend_from_slice(&self.cert_chain_hash);
        
        buf
    }
}

/// Parse DISetCredentials response to extract OVHeader
fn parse_di_set_credentials(data: &[u8]) -> Option<OVHeader> {
    // DISetCredentials = [OVHeader, ServerCapabilityFlags]
    // OVHeader = [OVProtVer, OVGuid, OVRVInfo, OVDeviceInfo, OVPublicKey, OVCertChainHash]
    
    if data.is_empty() {
        return None;
    }
    
    // TODO: Proper CBOR parsing
    // For now, return a placeholder
    warn!("DISetCredentials parsing not fully implemented - using placeholder");
    
    Some(OVHeader {
        guid: [0u8; 16],
        rv_info: vec![],
        device_info: String::from("placeholder"),
        pub_key: vec![],
        cert_chain_hash: vec![],
    })
}

/// Build DCTPM structure for TPM NV storage
/// Per securing-fdo-in-tpm.bs
fn build_dctpm(ov_header: &OVHeader, dak_handle: u32, hmac_handle: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    
    // DCTPM = [DCTPMMagic, DCActive, ProtVer, DeviceInfo, GUID, RVInfo, PubKeyHash, 
    //          DeviceKeyType, DeviceKeyHandle, HMACKeyHandle]
    buf.push(0x8a); // array(10)
    
    // DCTPMMagic = 0x46444F31 ("FDO1")
    buf.push(0x1a); // uint32
    buf.extend_from_slice(&[0x46, 0x44, 0x4F, 0x31]);
    
    // DCActive = true
    buf.push(0xf5); // true
    
    // ProtVer = 200 (FDO 2.0)
    buf.push(0x18);
    buf.push(200);
    
    // DeviceInfo (tstr)
    let info = &ov_header.device_info;
    let len = info.len();
    if len < 24 {
        buf.push(0x60 | len as u8);
    } else {
        buf.push(0x78);
        buf.push(len as u8);
    }
    buf.extend_from_slice(info.as_bytes());
    
    // GUID (bstr)
    buf.push(0x50); // bstr(16)
    buf.extend_from_slice(&ov_header.guid);
    
    // RVInfo (bstr)
    let rv_len = ov_header.rv_info.len();
    if rv_len < 24 {
        buf.push(0x40 | rv_len as u8);
    } else {
        buf.push(0x58);
        buf.push(rv_len as u8);
    }
    buf.extend_from_slice(&ov_header.rv_info);
    
    // PubKeyHash (bstr) - hash of owner public key
    let hash_len = ov_header.cert_chain_hash.len();
    if hash_len < 24 {
        buf.push(0x40 | hash_len as u8);
    } else {
        buf.push(0x58);
        buf.push(hash_len as u8);
    }
    buf.extend_from_slice(&ov_header.cert_chain_hash);
    
    // DeviceKeyType = 0 (DAK)
    buf.push(0x00);
    
    // DeviceKeyHandle (uint32)
    buf.push(0x1a);
    buf.push((dak_handle >> 24) as u8);
    buf.push((dak_handle >> 16) as u8);
    buf.push((dak_handle >> 8) as u8);
    buf.push(dak_handle as u8);
    
    // HMACKeyHandle (uint32)
    buf.push(0x1a);
    buf.push((hmac_handle >> 24) as u8);
    buf.push((hmac_handle >> 16) as u8);
    buf.push((hmac_handle >> 8) as u8);
    buf.push(hmac_handle as u8);
    
    buf
}

/// Generate CSR (Certificate Signing Request) using TPM for signing
/// Returns DER-encoded PKCS#10 CSR
fn generate_csr(subject_cn: &str, public_x: &[u8], public_y: &[u8], sign_handle: u32) -> Option<Vec<u8>> {
    // Build CertificationRequestInfo (to-be-signed)
    let tbs = build_csr_tbs(subject_cn, public_x, public_y);
    
    // Hash TBS with SHA-256
    let tbs_hash = sha256(&tbs);
    
    // Sign with TPM using ECDSA
    let signature = tpm::tpm_sign_ecdsa(sign_handle, &tbs_hash)?;
    
    // Assemble complete CSR
    Some(assemble_csr_der(&tbs, &signature))
}

/// Build CertificationRequestInfo (to-be-signed portion of CSR)
fn build_csr_tbs(subject_cn: &str, public_x: &[u8], public_y: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    
    // CertificationRequestInfo ::= SEQUENCE
    let seq_start = buf.len();
    buf.push(0x30); // SEQUENCE
    buf.push(0x00); // length placeholder
    
    // version INTEGER (0)
    buf.extend_from_slice(&[0x02, 0x01, 0x00]);
    
    // subject Name (SEQUENCE of SET of AttributeTypeAndValue)
    // CN=<subject_cn>
    let subject = build_x509_name_cn(subject_cn);
    buf.extend_from_slice(&subject);
    
    // subjectPKInfo SubjectPublicKeyInfo for EC P-256
    let spki = build_ec_spki(public_x, public_y);
    buf.extend_from_slice(&spki);
    
    // attributes [0] (empty)
    buf.extend_from_slice(&[0xa0, 0x00]);
    
    // Update sequence length
    let seq_len = buf.len() - seq_start - 2;
    buf[seq_start + 1] = seq_len as u8;
    
    buf
}

/// Build X.509 Name with CN attribute
fn build_x509_name_cn(cn: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    
    // Name ::= SEQUENCE OF RelativeDistinguishedName
    buf.push(0x30); // SEQUENCE
    
    // RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
    let mut rdn = Vec::new();
    rdn.push(0x31); // SET
    
    // AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
    let mut atv = Vec::new();
    atv.push(0x30); // SEQUENCE
    
    // type = id-at-commonName (2.5.4.3)
    atv.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03]);
    
    // value = UTF8String
    atv.push(0x0c); // UTF8String
    atv.push(cn.len() as u8);
    atv.extend_from_slice(cn.as_bytes());
    
    // Update ATV length
    let atv_len = atv.len() - 2;
    atv[1] = atv_len as u8;
    
    rdn.push(atv.len() as u8);
    rdn.extend_from_slice(&atv);
    
    buf.push(rdn.len() as u8);
    buf.extend_from_slice(&rdn);
    
    buf
}

/// Build SubjectPublicKeyInfo for EC P-256 key
fn build_ec_spki(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    
    // SubjectPublicKeyInfo ::= SEQUENCE
    buf.push(0x30); // SEQUENCE
    
    // AlgorithmIdentifier for EC P-256
    // SEQUENCE { algorithm = ecPublicKey (1.2.840.10045.2.1), parameters = secp256r1 (1.2.840.10045.3.1.7) }
    let alg_id: [u8; 21] = [
        0x30, 0x13,             // SEQUENCE (19 bytes)
        0x06, 0x07,             // OID (7 bytes)
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,  // 1.2.840.10045.2.1 (ecPublicKey)
        0x06, 0x08,             // OID (8 bytes)
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,  // 1.2.840.10045.3.1.7 (secp256r1)
    ];
    
    // subjectPublicKey BIT STRING containing uncompressed point (04 || x || y)
    let point_len = 1 + x.len() + y.len(); // 04 + x + y
    let bit_string_len = 1 + point_len;    // unused bits (0) + point
    
    // Calculate total SPKI length
    let spki_len = alg_id.len() + 2 + bit_string_len;
    buf.push(spki_len as u8);
    
    buf.extend_from_slice(&alg_id);
    
    // BIT STRING
    buf.push(0x03); // BIT STRING
    buf.push(bit_string_len as u8);
    buf.push(0x00); // unused bits
    buf.push(0x04); // uncompressed point
    buf.extend_from_slice(x);
    buf.extend_from_slice(y);
    
    buf
}

/// Assemble complete CSR DER from TBS and signature
fn assemble_csr_der(tbs: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(tbs.len() + signature.len() + 32);
    
    // CertificationRequest ::= SEQUENCE
    buf.push(0x30); // SEQUENCE
    
    // Will update length at end
    let len_pos = buf.len();
    buf.push(0x00); // placeholder
    
    // certificationRequestInfo
    buf.extend_from_slice(tbs);
    
    // signatureAlgorithm (ecdsa-with-SHA256 = 1.2.840.10045.4.3.2)
    let sig_alg: [u8; 12] = [
        0x30, 0x0a,             // SEQUENCE (10 bytes)
        0x06, 0x08,             // OID (8 bytes)
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,  // 1.2.840.10045.4.3.2
    ];
    buf.extend_from_slice(&sig_alg);
    
    // signature BIT STRING
    // ECDSA signature is DER-encoded SEQUENCE { r INTEGER, s INTEGER }
    let sig_der = encode_ecdsa_signature(signature);
    buf.push(0x03); // BIT STRING
    buf.push((sig_der.len() + 1) as u8);
    buf.push(0x00); // unused bits
    buf.extend_from_slice(&sig_der);
    
    // Update total length
    let total_len = buf.len() - len_pos - 1;
    if total_len < 128 {
        buf[len_pos] = total_len as u8;
    } else {
        // Need to expand length field - shift everything
        let mut new_buf = Vec::with_capacity(buf.len() + 2);
        new_buf.push(0x30);
        new_buf.push(0x82);
        new_buf.push((total_len >> 8) as u8);
        new_buf.push(total_len as u8);
        new_buf.extend_from_slice(&buf[len_pos + 1..]);
        return new_buf;
    }
    
    buf
}

/// Encode ECDSA signature (r || s) as DER SEQUENCE { INTEGER r, INTEGER s }
fn encode_ecdsa_signature(sig: &[u8]) -> Vec<u8> {
    let half = sig.len() / 2;
    let r = &sig[..half];
    let s = &sig[half..];
    
    let r_der = encode_integer(r);
    let s_der = encode_integer(s);
    
    let mut buf = Vec::with_capacity(r_der.len() + s_der.len() + 4);
    buf.push(0x30); // SEQUENCE
    buf.push((r_der.len() + s_der.len()) as u8);
    buf.extend_from_slice(&r_der);
    buf.extend_from_slice(&s_der);
    
    buf
}

/// Encode bytes as DER INTEGER (handling sign bit)
fn encode_integer(bytes: &[u8]) -> Vec<u8> {
    // Skip leading zeros but keep at least one byte
    let mut start = 0;
    while start < bytes.len() - 1 && bytes[start] == 0 {
        start += 1;
    }
    
    let need_pad = bytes[start] & 0x80 != 0;
    let len = bytes.len() - start + if need_pad { 1 } else { 0 };
    
    let mut buf = Vec::with_capacity(len + 2);
    buf.push(0x02); // INTEGER
    buf.push(len as u8);
    if need_pad {
        buf.push(0x00);
    }
    buf.extend_from_slice(&bytes[start..]);
    
    buf
}

/// Compute SHA-256 hash
fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}
