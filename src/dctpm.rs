// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// DCTPM structure helpers (securing-fdo-in-tpm.bs, "FDO Public Device
// Credentials"). Pure byte-level CBOR handling so it is unit-tested natively;
// tpm.rs / di / rv_firmware (UEFI-only) call it.
//
//   DCTPM = [DCTPMMagic, DCActive, DCProtVer, DCDeviceInfo, DCGuid, DCRVInfo,
//            DCPubKeyHash, DeviceKeyType, DeviceKeyHandle, HMACKeyHandle,
//            DCMinFirmwareRev]
//
// DCMinFirmwareRev (item 10): minimum acceptable pre-onboarding firmware
// revision, 0 = no minimum. Seeded at DI from RVMinFirmwareRev (RV tag 18),
// only ever increased, preserved on rewrite; a ten-item DCTPM reads as 0.

use alloc::vec::Vec;

/// Index of DCMinFirmwareRev in the DCTPM array.
pub const MIN_FIRMWARE_REV_ITEM: usize = 10;

/// RendezvousInfo variable RVMinFirmwareRev.
const RV_MIN_FIRMWARE_REV: u64 = 18;

/// Read a CBOR head at `pos`: (major type, argument). Indefinite lengths are
/// not used in DCTPM and are rejected.
fn head(data: &[u8], pos: &mut usize) -> Option<(u8, u64)> {
    let b = *data.get(*pos)?;
    *pos += 1;
    let (major, add) = (b >> 5, b & 0x1f);
    let n = match add {
        0..=23 => return Some((major, add as u64)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return None,
    };
    let bytes = data.get(*pos..*pos + n)?;
    *pos += n;
    Some((major, bytes.iter().fold(0u64, |acc, &x| (acc << 8) | x as u64)))
}

/// Skip one CBOR data item at `pos`.
fn skip(data: &[u8], pos: &mut usize) -> Option<()> {
    let (major, arg) = head(data, pos)?;
    match major {
        0 | 1 | 7 => Some(()),
        2 | 3 => {
            let end = pos.checked_add(arg as usize)?;
            if end > data.len() {
                return None;
            }
            *pos = end;
            Some(())
        }
        4 => (0..arg).try_for_each(|_| skip(data, pos)),
        5 => (0..arg * 2).try_for_each(|_| skip(data, pos)),
        6 => skip(data, pos),
        _ => None,
    }
}

/// CBOR encoding of an unsigned integer.
pub fn encode_uint(v: u64) -> Vec<u8> {
    encode_head(0, v)
}

fn encode_head(major: u8, v: u64) -> Vec<u8> {
    let m = major << 5;
    let mut out = Vec::with_capacity(9);
    match v {
        0..=23 => out.push(m | v as u8),
        24..=0xff => out.extend_from_slice(&[m | 24, v as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(v as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(v as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&v.to_be_bytes());
        }
    }
    out
}

/// DCMinFirmwareRev of a DCTPM structure (trailing index bytes are ignored).
/// A ten-item DCTPM yields 0. None if the bytes are not a DCTPM array.
pub fn min_firmware_rev(dctpm: &[u8]) -> Option<u64> {
    let mut pos = 0;
    let (major, n) = head(dctpm, &mut pos)?;
    if major != 4 || n < 10 {
        return None;
    }
    if (n as usize) <= MIN_FIRMWARE_REV_ITEM {
        return Some(0);
    }
    for _ in 0..MIN_FIRMWARE_REV_ITEM {
        skip(dctpm, &mut pos)?;
    }
    match head(dctpm, &mut pos)? {
        (0, v) => Some(v),
        _ => None,
    }
}

/// The DCTPM structure with DCMinFirmwareRev set to `rev` (item appended if
/// the input has only ten items). Returns the structure only, without the
/// trailing index bytes; None if the input is not a DCTPM array.
pub fn with_min_firmware_rev(dctpm: &[u8], rev: u64) -> Option<Vec<u8>> {
    let mut pos = 0;
    let (major, n) = head(dctpm, &mut pos)?;
    if major != 4 || n < 10 {
        return None;
    }
    let items_start = pos;
    for _ in 0..MIN_FIRMWARE_REV_ITEM {
        skip(dctpm, &mut pos)?;
    }
    let first_ten = items_start..pos;
    let rest = if (n as usize) > MIN_FIRMWARE_REV_ITEM {
        skip(dctpm, &mut pos)?; // old item 10
        let rest_start = pos;
        for _ in (MIN_FIRMWARE_REV_ITEM + 1)..(n as usize) {
            skip(dctpm, &mut pos)?;
        }
        rest_start..pos
    } else {
        pos..pos
    };
    let count = core::cmp::max(n, (MIN_FIRMWARE_REV_ITEM + 1) as u64);
    let mut out = encode_head(4, count);
    out.extend_from_slice(&dctpm[first_ten]);
    out.extend_from_slice(&encode_uint(rev));
    out.extend_from_slice(&dctpm[rest]);
    Some(out)
}

/// Highest RVMinFirmwareRev (RV tag 18) in a RendezvousInfo
/// ([[ [RVVariable, bstr .cbor value], ... ], ...]), or 0.
pub fn rv_min_firmware_rev(rv_info: &[u8]) -> u64 {
    fn scan(d: &[u8]) -> Option<u64> {
        let mut pos = 0;
        let mut best = 0u64;
        let (m, dirs) = head(d, &mut pos)?;
        if m != 4 {
            return None;
        }
        for _ in 0..dirs {
            let (m, instrs) = head(d, &mut pos)?;
            if m != 4 {
                return None;
            }
            for _ in 0..instrs {
                let (m, len) = head(d, &mut pos)?;
                if m != 4 || len == 0 {
                    return None;
                }
                let (vm, var) = head(d, &mut pos)?;
                if len >= 2 {
                    if vm == 0 && var == RV_MIN_FIRMWARE_REV {
                        let (bm, blen) = head(d, &mut pos)?;
                        let inner = d.get(pos..pos + blen as usize)?;
                        pos += blen as usize;
                        let mut ip = 0;
                        if let (2, Some((0, v))) = (bm, head(inner, &mut ip)) {
                            best = best.max(v);
                        }
                    } else {
                        skip(d, &mut pos)?;
                    }
                    for _ in 2..len {
                        skip(d, &mut pos)?;
                    }
                }
            }
        }
        Some(best)
    }
    scan(rv_info).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// A DCTPM-like array with `items` placeholder items (item 5 a nested array).
    fn sample(items: u8, min_rev: Option<u64>) -> Vec<u8> {
        let mut d = vec![0x80 | items];
        d.extend_from_slice(&[0x1a, 0x46, 0x44, 0x4F, 0x31]); // magic
        d.push(0xf5); // active
        d.extend_from_slice(&[0x18, 200]); // protver
        d.extend_from_slice(&[0x63, b'd', b'e', b'v']); // device info
        d.push(0x50);
        d.extend_from_slice(&[0xaa; 16]); // guid
        d.extend_from_slice(&[0x81, 0x81, 0x82, 0x0c, 0x41, 0x05]); // rvinfo [[ [12, h'05'] ]]
        d.extend_from_slice(&[0x82, 0x2f, 0x41, 0x00]); // hash
        d.push(0x00); // device key type
        d.extend_from_slice(&[0x1a, 0x81, 0x02, 0x00, 0x02]); // dak handle
        d.extend_from_slice(&[0x1a, 0x81, 0x02, 0x00, 0x03]); // hmac handle
        if let Some(r) = min_rev {
            d.extend_from_slice(&encode_uint(r));
        }
        d
    }

    #[test]
    fn reads_eleven_and_ten_items() {
        assert_eq!(min_firmware_rev(&sample(11, Some(7))), Some(7));
        assert_eq!(min_firmware_rev(&sample(11, Some(300))), Some(300));
        assert_eq!(min_firmware_rev(&sample(10, None)), Some(0));
        let mut padded = sample(11, Some(9));
        padded.resize(512, 0);
        assert_eq!(min_firmware_rev(&padded), Some(9));
        assert_eq!(min_firmware_rev(&[0xa0]), None);
    }

    #[test]
    fn sets_and_appends() {
        let up = with_min_firmware_rev(&sample(11, Some(7)), 70000).unwrap();
        assert_eq!(up, sample(11, Some(70000)));
        let appended = with_min_firmware_rev(&sample(10, None), 4).unwrap();
        assert_eq!(appended, sample(11, Some(4)));
        // Trailing index bytes are not copied.
        let mut padded = sample(11, Some(1));
        padded.resize(512, 0);
        assert_eq!(with_min_firmware_rev(&padded, 2).unwrap(), sample(11, Some(2)));
    }

    #[test]
    fn rv_tag_18() {
        // [[ [3, h'6372762e'...], [18, h'07'] ], [ [18, h'1864'] ]]  -> max(7, 100)
        let rv = [
            0x82, 0x82, 0x82, 0x0f, 0x43, 0x62, b'r', b'v', 0x82, 0x12, 0x41, 0x07, 0x81, 0x82, 0x12,
            0x42, 0x18, 0x64,
        ];
        assert_eq!(rv_min_firmware_rev(&rv), 100);
        assert_eq!(rv_min_firmware_rev(&[0x81, 0x81, 0x82, 0x0c, 0x41, 0x05]), 0);
        assert_eq!(rv_min_firmware_rev(&[0xff]), 0);
    }
}
