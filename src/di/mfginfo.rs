// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// DeviceMfgInfo structure per fdo-appnote-device-mfg-info.bs
//
// Minimal implementation using only required fields:
// - DMI_KEY_TYPE (key 0)
// - DMI_KEY_ENCODING (key 1)
// - DMI_CSR (key 2)
// - DMI_SPEC_VERSION (key 3)
// - DMI_OVE_EXTRA_REQUEST (key 4) with PT_DEVICE_SERIAL and PT_MODEL

use alloc::string::String;
use alloc::vec::Vec;

// go-fdo custom.DeviceMfgInfo struct field order (CBOR array encoding):
//   [0] KeyType:      protocol.KeyType
//   [1] KeyEncoding:  protocol.KeyEncoding
//   [2] SerialNumber: string (tstr)
//   [3] DeviceInfo:   string (tstr)
//   [4] CertInfo:     cbor.X509CertificateRequest (bstr)

/// PublicKeyType values (must match go-fdo protocol.KeyType constants)
pub const KEY_TYPE_SECP256R1: u8 = 10;
pub const KEY_TYPE_SECP384R1: u8 = 11;

/// PublicKeyEncoding values (from FDO spec)
pub const KEY_ENCODING_X509: u8 = 1;
pub const KEY_ENCODING_X5CHAIN: u8 = 2;

/// DeviceMfgInfo structure (minimal implementation)
pub struct DeviceMfgInfo {
    pub key_type: u8,
    pub key_encoding: u8,
    pub csr_der: Vec<u8>,
    pub serial_number: String,
    pub model: String,
}

impl DeviceMfgInfo {
    /// Create new DeviceMfgInfo with P-256 key type
    pub fn new(serial_number: String, model: String, csr_der: Vec<u8>) -> Self {
        DeviceMfgInfo {
            key_type: KEY_TYPE_SECP256R1,
            key_encoding: KEY_ENCODING_X5CHAIN,
            csr_der,
            serial_number,
            model,
        }
    }

    /// Encode as CBOR array matching go-fdo custom.DeviceMfgInfo struct order:
    ///   [KeyType, KeyEncoding, SerialNumber, DeviceInfo, CertInfo]
    /// Returns bstr-wrapped CBOR (as required by DI.AppStart cbor.Bstr wrapper)
    pub fn to_cbor(&self) -> Vec<u8> {
        let inner = self.encode_array();
        // Wrap in bstr (Info = bstr .cbor DeviceMfgInfo)
        encode_bstr(&inner)
    }

    /// Encode as 5-element CBOR array matching go-fdo struct field order
    fn encode_array(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        
        // 5-element array
        buf.push(0x85); // array(5)
        
        // [0] KeyType: uint (e.g. 13 = SECP256R1)
        buf.push(self.key_type);
        
        // [1] KeyEncoding: uint (e.g. 2 = X5CHAIN)
        buf.push(self.key_encoding);
        
        // [2] SerialNumber: tstr
        let sn = self.serial_number.as_bytes();
        encode_tstr_into(&mut buf, sn);
        
        // [3] DeviceInfo: tstr (model name used as device info string)
        let model = self.model.as_bytes();
        encode_tstr_into(&mut buf, model);
        
        // [4] CertInfo: bstr (DER-encoded PKCS#10 CSR)
        encode_bstr_into(&mut buf, &self.csr_der);
        
        buf
    }
}

/// Encode byte string with CBOR bstr header (returns new Vec)
fn encode_bstr(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(data.len() + 3);
    encode_bstr_into(&mut buf, data);
    buf
}

/// Encode byte string with CBOR bstr header into existing buffer
fn encode_bstr_into(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len < 24 {
        buf.push(0x40 | len as u8);
    } else if len < 256 {
        buf.push(0x58);
        buf.push(len as u8);
    } else if len < 65536 {
        buf.push(0x59);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else {
        buf.push(0x5a);
        buf.push((len >> 24) as u8);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
    buf.extend_from_slice(data);
}

/// Encode text string with CBOR tstr header into existing buffer
fn encode_tstr_into(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len < 24 {
        buf.push(0x60 | len as u8);
    } else if len < 256 {
        buf.push(0x78);
        buf.push(len as u8);
    } else if len < 65536 {
        buf.push(0x79);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
    buf.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_mfg_info_encoding() {
        let mfg_info = DeviceMfgInfo::new(
            String::from("SN-12345678"),
            String::from("TestDevice"),
            vec![0x30, 0x82, 0x01, 0x00], // Fake CSR
        );
        
        let cbor = mfg_info.to_cbor();
        assert!(!cbor.is_empty());
        // Should start with bstr header
        assert!(cbor[0] >= 0x40 && cbor[0] < 0x60 || cbor[0] == 0x58 || cbor[0] == 0x59);
    }
}
