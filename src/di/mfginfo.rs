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

/// DeviceMfgInfo map keys (per spec)
const DMI_KEY_TYPE: u8 = 0;
const DMI_KEY_ENCODING: u8 = 1;
const DMI_CSR: u8 = 2;
const DMI_SPEC_VERSION: u8 = 3;
const DMI_OVE_EXTRA_REQUEST: u8 = 4;

/// Payload type keys for OVE_EXTRA_REQUEST (per spec)
const PT_DEVICE_SERIAL: u8 = 0;
const PT_MODEL: u8 = 2;

/// PublicKeyType values (from FDO spec Table 4)
pub const KEY_TYPE_SECP256R1: u8 = 13;
pub const KEY_TYPE_SECP384R1: u8 = 14;

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

    /// Encode as CBOR map per fdo-appnote-device-mfg-info.bs
    /// Returns bstr-wrapped CBOR (as required by DI.AppStart)
    pub fn to_cbor(&self) -> Vec<u8> {
        let inner = self.encode_map();
        // Wrap in bstr (DeviceMfgInfo = bstr .cbor DeviceMfgInfoMap)
        encode_bstr(&inner)
    }

    /// Encode the inner DeviceMfgInfoMap
    fn encode_map(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        
        // Map with 5 entries: keys 0,1,2,3,4
        buf.push(0xa5); // map(5)
        
        // DMI_KEY_TYPE (key 0): uint
        buf.push(DMI_KEY_TYPE);
        buf.push(self.key_type);
        
        // DMI_KEY_ENCODING (key 1): uint
        buf.push(DMI_KEY_ENCODING);
        buf.push(self.key_encoding);
        
        // DMI_CSR (key 2): bstr (DER-encoded PKCS#10)
        buf.push(DMI_CSR);
        buf.extend_from_slice(&encode_bstr(&self.csr_der));
        
        // DMI_SPEC_VERSION (key 3): uint = 1
        buf.push(DMI_SPEC_VERSION);
        buf.push(1u8);
        
        // DMI_OVE_EXTRA_REQUEST (key 4): PayloadMap
        buf.push(DMI_OVE_EXTRA_REQUEST);
        buf.extend_from_slice(&self.encode_ove_extra_request());
        
        buf
    }

    /// Encode DMI_OVE_EXTRA_REQUEST PayloadMap
    /// Contains PT_DEVICE_SERIAL and PT_MODEL as bstr values
    fn encode_ove_extra_request(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        
        // Map with 2 entries
        buf.push(0xa2); // map(2)
        
        // PT_DEVICE_SERIAL (key 0): bstr containing UTF-8
        buf.push(PT_DEVICE_SERIAL);
        buf.extend_from_slice(&encode_bstr(self.serial_number.as_bytes()));
        
        // PT_MODEL (key 2): bstr containing UTF-8
        buf.push(PT_MODEL);
        buf.extend_from_slice(&encode_bstr(self.model.as_bytes()));
        
        buf
    }
}

/// Encode byte string with CBOR bstr header
fn encode_bstr(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let mut buf = Vec::with_capacity(len + 3);
    
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
    buf
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
