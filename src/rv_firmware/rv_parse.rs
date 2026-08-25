// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// RV Extension Tag Parser for RV-Based Firmware Delivery
//
// Extends the existing DCTPM RendezvousInfo parsing to extract firmware
// delivery extension tags (FirmwarePath, FirmwareURL, MinFirmwareRev).

use alloc::string::String;
use alloc::vec::Vec;
use log::{info, warn};

/// RV extension tag IDs (from fdo-firmware-delivery-spec)
const RV_DNS: u8 = 5;
const RV_IP_ADDRESS: u8 = 2;
const RV_DEV_PORT: u8 = 3;
const RV_PROTOCOL: u8 = 12;
const RV_FIRMWARE_PATH: u8 = 16;
const RV_FIRMWARE_URL: u8 = 17;
const RV_MIN_FIRMWARE_REV: u8 = 18;

/// RV protocol values
const RV_PROT_HTTP: u8 = 1;
const RV_PROT_HTTPS: u8 = 2;

/// Default firmware path prefix and filename
const DEFAULT_FIRMWARE_PATH: &str = "fdo-firmware";
const DEFAULT_FIRMWARE_FILENAME: &str = "payload.cose";

/// Parsed RV firmware delivery info
#[derive(Debug)]
pub struct RvFirmwareInfo {
    /// Explicit firmware URLs (from RVFirmwareURL tag 17)
    pub firmware_urls: Vec<String>,
    /// Firmware path prefix (from RVFirmwarePath tag 16)
    pub firmware_path: Option<String>,
    /// Minimum firmware revision for anti-rollback (from RVMinFirmwareRev tag 18)
    pub min_firmware_rev: Option<u64>,
    /// Base server URL (scheme://host:port) from standard RV tags
    pub server_url: Option<String>,
}

impl RvFirmwareInfo {
    /// Get the firmware download URL.
    /// Priority: 1) Explicit FirmwareURL, 2) Server URL + FirmwarePath + default filename
    pub fn firmware_url(&self) -> Option<String> {
        // Try explicit URLs first
        if let Some(url) = self.firmware_urls.first() {
            return Some(url.clone());
        }

        // Build URL from server + path
        if let Some(ref base) = self.server_url {
            let path = self.firmware_path.as_deref().unwrap_or(DEFAULT_FIRMWARE_PATH);
            return Some(alloc::format!("{}/{}/{}", base, path, DEFAULT_FIRMWARE_FILENAME));
        }

        None
    }
}

/// Parse RV firmware delivery extensions from raw DCTPM NV data.
/// This reads the DCTPM CBOR structure, navigates to the RvInfo field (key/index 5),
/// and extracts both standard RV tags (DNS, port, protocol) and firmware extensions.
pub fn parse_rv_firmware_info(dctpm_data: &[u8]) -> Option<RvFirmwareInfo> {
    if dctpm_data.is_empty() {
        return None;
    }

    let mut pos = 0;
    let initial = dctpm_data[pos];
    pos += 1;

    let major = initial >> 5;
    let additional = initial & 0x1f;

    let num_items = if additional < 24 {
        additional as usize
    } else if additional == 24 && pos < dctpm_data.len() {
        let n = dctpm_data[pos] as usize;
        pos += 1;
        n
    } else {
        return None;
    };

    if major == 4 {
        // CBOR array — RvInfo at index 5
        if num_items < 6 {
            return None;
        }
        for _ in 0..5 {
            if !skip_cbor_value(dctpm_data, &mut pos) {
                return None;
            }
        }
        return parse_rv_firmware_info_at(dctpm_data, &mut pos);
    } else if major == 5 {
        // CBOR map — find key 5
        for _ in 0..num_items {
            if pos >= dctpm_data.len() {
                break;
            }
            let key = read_cbor_uint_at(dctpm_data, &mut pos)?;
            if key == 5 {
                return parse_rv_firmware_info_at(dctpm_data, &mut pos);
            } else {
                skip_cbor_value(dctpm_data, &mut pos);
            }
        }
    }

    None
}

/// Parse RvInfo at current position, extracting firmware extension tags.
fn parse_rv_firmware_info_at(data: &[u8], pos: &mut usize) -> Option<RvFirmwareInfo> {
    if *pos >= data.len() {
        return None;
    }

    let mut info = RvFirmwareInfo {
        firmware_urls: Vec::new(),
        firmware_path: None,
        min_firmware_rev: None,
        server_url: None,
    };

    // Read outer array header (array of directives)
    let outer_initial = data[*pos];
    *pos += 1;
    if (outer_initial >> 5) != 4 {
        warn!("RV-FW: RvInfo should be array");
        return None;
    }
    let outer_len = read_cbor_uint_arg(data, pos, outer_initial & 0x1f)?;
    info!("RV-FW: RvInfo has {} directive(s)", outer_len);

    for _dir_idx in 0..outer_len {
        if *pos >= data.len() {
            break;
        }
        let dir_initial = data[*pos];
        *pos += 1;
        let dir_major = dir_initial >> 5;
        if dir_major != 4 {
            skip_cbor_value(data, pos);
            continue;
        }
        let dir_len = read_cbor_uint_arg(data, pos, dir_initial & 0x1f)?;

        let mut dns_name: Option<String> = None;
        let mut ip_addr: Option<[u8; 4]> = None;
        let mut port: u16 = 8080;
        let mut scheme = "http";

        for _ in 0..dir_len {
            if *pos >= data.len() {
                break;
            }

            // Each RvInstruction is [variable, value]
            let instr_initial = data[*pos];
            *pos += 1;
            if (instr_initial >> 5) != 4 {
                skip_cbor_value(data, pos);
                continue;
            }
            let instr_len = read_cbor_uint_arg(data, pos, instr_initial & 0x1f)?;
            if instr_len < 2 {
                for _ in 0..instr_len {
                    skip_cbor_value(data, pos);
                }
                continue;
            }

            let var_id = read_cbor_uint_at(data, pos).unwrap_or(255) as u8;
            let value_bytes = read_cbor_bstr_raw(data, pos);

            // Skip extra fields
            for _ in 2..instr_len {
                skip_cbor_value(data, pos);
            }

            let value_bytes = match value_bytes {
                Some(v) => v,
                None => continue,
            };

            match var_id {
                RV_DNS => {
                    if let Some(s) = decode_cbor_text(&value_bytes) {
                        info!("RV-FW: DNS = {}", s);
                        dns_name = Some(s);
                    }
                }
                RV_IP_ADDRESS => {
                    if let Some(ip_bytes) = decode_cbor_bstr(&value_bytes) {
                        if ip_bytes.len() == 4 {
                            let mut ip = [0u8; 4];
                            ip.copy_from_slice(&ip_bytes);
                            info!("RV-FW: IP = {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
                            ip_addr = Some(ip);
                        } else if ip_bytes.len() == 5 {
                            // Skip family byte
                            let mut ip = [0u8; 4];
                            ip.copy_from_slice(&ip_bytes[1..5]);
                            info!("RV-FW: IP = {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
                            ip_addr = Some(ip);
                        }
                    }
                }
                RV_DEV_PORT => {
                    if let Some(p) = decode_cbor_uint(&value_bytes) {
                        info!("RV-FW: DevPort = {}", p);
                        port = p as u16;
                    }
                }
                RV_PROTOCOL => {
                    if let Some(p) = decode_cbor_uint(&value_bytes) {
                        match p as u8 {
                            RV_PROT_HTTP => scheme = "http",
                            RV_PROT_HTTPS => scheme = "https",
                            _ => {}
                        }
                    }
                }
                RV_FIRMWARE_PATH => {
                    if let Some(s) = decode_cbor_text(&value_bytes) {
                        info!("RV-FW: FirmwarePath = {}", s);
                        info.firmware_path = Some(s);
                    }
                }
                RV_FIRMWARE_URL => {
                    if let Some(s) = decode_cbor_text(&value_bytes) {
                        info!("RV-FW: FirmwareURL = {}", s);
                        info.firmware_urls.push(s);
                    }
                }
                RV_MIN_FIRMWARE_REV => {
                    if let Some(rev) = decode_cbor_uint(&value_bytes) {
                        info!("RV-FW: MinFirmwareRev = {}", rev);
                        info.min_firmware_rev = Some(rev as u64);
                    }
                }
                _ => {}
            }
        }

        // Build server URL from standard tags
        if info.server_url.is_none() {
            if let Some(ref dns) = dns_name {
                info.server_url = Some(alloc::format!("{}://{}:{}", scheme, dns, port));
            } else if let Some(ip) = ip_addr {
                info.server_url = Some(alloc::format!(
                    "{}://{}.{}.{}.{}:{}",
                    scheme, ip[0], ip[1], ip[2], ip[3], port
                ));
            }
        }
    }

    if info.server_url.is_some() || !info.firmware_urls.is_empty() {
        info!("RV-FW: Parsed firmware info: url={:?}, path={:?}, min_rev={:?}",
              info.firmware_url(), info.firmware_path, info.min_firmware_rev);
        Some(info)
    } else {
        warn!("RV-FW: No usable server info found in RvInfo");
        None
    }
}

// --- CBOR helper functions (mirroring tpm.rs helpers) ---

fn read_cbor_uint_arg(data: &[u8], pos: &mut usize, additional: u8) -> Option<usize> {
    if additional < 24 {
        Some(additional as usize)
    } else if additional == 24 && *pos < data.len() {
        let n = data[*pos] as usize;
        *pos += 1;
        Some(n)
    } else if additional == 25 && *pos + 1 < data.len() {
        let n = ((data[*pos] as usize) << 8) | (data[*pos + 1] as usize);
        *pos += 2;
        Some(n)
    } else if additional == 26 && *pos + 3 < data.len() {
        let n = ((data[*pos] as usize) << 24)
            | ((data[*pos + 1] as usize) << 16)
            | ((data[*pos + 2] as usize) << 8)
            | (data[*pos + 3] as usize);
        *pos += 4;
        Some(n)
    } else {
        None
    }
}

fn read_cbor_uint_at(data: &[u8], pos: &mut usize) -> Option<usize> {
    if *pos >= data.len() {
        return None;
    }
    let b = data[*pos];
    *pos += 1;
    if (b >> 5) != 0 {
        return None;
    }
    read_cbor_uint_arg(data, pos, b & 0x1f)
}

fn read_cbor_bstr_raw(data: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    if *pos >= data.len() {
        return None;
    }
    let b = data[*pos];
    *pos += 1;
    let major = b >> 5;
    if major != 2 {
        // Not a bstr — skip value
        let additional = b & 0x1f;
        let arg = read_cbor_uint_arg(data, pos, additional)?;
        match major {
            0 | 1 => {}
            3 => { *pos += arg; }
            4 => {
                for _ in 0..arg {
                    skip_cbor_value(data, pos);
                }
            }
            5 => {
                for _ in 0..arg * 2 {
                    skip_cbor_value(data, pos);
                }
            }
            7 => {}
            _ => {}
        }
        return None;
    }
    let len = read_cbor_uint_arg(data, pos, b & 0x1f)?;
    if *pos + len > data.len() {
        return None;
    }
    let result = data[*pos..*pos + len].to_vec();
    *pos += len;
    Some(result)
}

fn decode_cbor_text(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    let mut pos = 0;
    let b = data[pos];
    pos += 1;
    if (b >> 5) != 3 {
        return None;
    }
    let len = read_cbor_uint_arg(data, &mut pos, b & 0x1f)?;
    if pos + len > data.len() {
        return None;
    }
    core::str::from_utf8(&data[pos..pos + len])
        .ok()
        .map(String::from)
}

fn decode_cbor_bstr(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }
    let mut pos = 0;
    let b = data[pos];
    pos += 1;
    if (b >> 5) != 2 {
        return None;
    }
    let len = read_cbor_uint_arg(data, &mut pos, b & 0x1f)?;
    if pos + len > data.len() {
        return None;
    }
    Some(data[pos..pos + len].to_vec())
}

fn decode_cbor_uint(data: &[u8]) -> Option<usize> {
    if data.is_empty() {
        return None;
    }
    let mut pos = 0;
    read_cbor_uint_at(data, &mut pos)
}

fn skip_cbor_value(data: &[u8], pos: &mut usize) -> bool {
    if *pos >= data.len() {
        return false;
    }
    let b = data[*pos];
    *pos += 1;
    let major = b >> 5;
    let additional = b & 0x1f;

    let arg = match read_cbor_uint_arg(data, pos, additional) {
        Some(a) => a,
        None => return false,
    };

    match major {
        0 | 1 => true, // uint / negint
        2 | 3 => {
            // bstr / tstr
            if *pos + arg > data.len() {
                return false;
            }
            *pos += arg;
            true
        }
        4 => {
            // array
            for _ in 0..arg {
                if !skip_cbor_value(data, pos) {
                    return false;
                }
            }
            true
        }
        5 => {
            // map
            for _ in 0..arg * 2 {
                if !skip_cbor_value(data, pos) {
                    return false;
                }
            }
            true
        }
        6 => {
            // tag
            skip_cbor_value(data, pos)
        }
        7 => true, // simple
        _ => false,
    }
}
