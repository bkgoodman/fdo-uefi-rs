// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0

use alloc::vec;
use alloc::vec::Vec;
use log::{info, warn, error};
use uefi::boot;
use uefi::proto::tcg::v2::Tcg;

/// FDO TPM NV Index for Device Credentials
/// go-fdo uses 0x01C10130 (standard) or 0x01D10001 (alternate)
const FDO_NV_INDEX_DCTPM: u32 = 0x01C10130;
const FDO_NV_INDEX_ALT: u32 = 0x01D10001;

/// TPM2 command codes
const TPM2_CC_NV_READ: u32 = 0x0000014E;
const TPM2_CC_NV_READ_PUBLIC: u32 = 0x00000169;
const TPM2_CC_CREATE_PRIMARY: u32 = 0x00000131;
const TPM2_CC_ECDH_ZGEN: u32 = 0x00000154;
const TPM2_CC_FLUSH_CONTEXT: u32 = 0x00000165;
const TPM2_CC_SIGN: u32 = 0x0000015D;

/// FDO persistent key handle for Device Attestation Key (DAK)
const FDO_DAK_HANDLE: u32 = 0x81020002;

/// TPM2 constants
const TPM2_RS_PW: u32 = 0x40000009;  // Password authorization
const TPM2_RH_OWNER: u32 = 0x40000001;  // Owner hierarchy
const TPM2_ST_NO_SESSIONS: u16 = 0x8001;
const TPM2_ST_SESSIONS: u16 = 0x8002;

/// TPM2 algorithm IDs
const TPM2_ALG_SHA256: u16 = 0x000B;
const TPM2_ALG_NULL: u16 = 0x0010;
const TPM2_ALG_ECC: u16 = 0x0023;
const TPM2_ALG_ECDH: u16 = 0x0019;
const TPM2_ALG_ECDSA: u16 = 0x0018;

/// TPM2 ECC curves
const TPM2_ECC_NIST_P256: u16 = 0x0003;

/// Pack u16 big-endian
fn pack_u16(buf: &mut [u8], val: u16) {
    buf[0] = (val >> 8) as u8;
    buf[1] = (val & 0xFF) as u8;
}

/// Pack u32 big-endian
fn pack_u32(buf: &mut [u8], val: u32) {
    buf[0] = (val >> 24) as u8;
    buf[1] = ((val >> 16) & 0xFF) as u8;
    buf[2] = ((val >> 8) & 0xFF) as u8;
    buf[3] = (val & 0xFF) as u8;
}

/// Unpack u16 big-endian
fn unpack_u16(buf: &[u8]) -> u16 {
    ((buf[0] as u16) << 8) | (buf[1] as u16)
}

/// Unpack u32 big-endian
fn unpack_u32(buf: &[u8]) -> u32 {
    ((buf[0] as u32) << 24) | ((buf[1] as u32) << 16) | 
    ((buf[2] as u32) << 8) | (buf[3] as u32)
}

/// Build TPM2_NV_ReadPublic command to get NV index size
fn build_nv_read_public_cmd(nv_index: u32) -> Vec<u8> {
    let mut cmd = vec![0u8; 14];
    
    // Header
    pack_u16(&mut cmd[0..2], TPM2_ST_NO_SESSIONS);  // tag
    pack_u32(&mut cmd[2..6], 14);                    // commandSize
    pack_u32(&mut cmd[6..10], TPM2_CC_NV_READ_PUBLIC); // commandCode
    
    // nvIndex
    pack_u32(&mut cmd[10..14], nv_index);
    
    cmd
}

/// Build TPM2_NV_Read command
fn build_nv_read_cmd(nv_index: u32, size: u16, offset: u16) -> Vec<u8> {
    // Command with password auth session
    let mut cmd = vec![0u8; 40];
    let mut pos = 0;
    
    // Header (will update size later)
    pack_u16(&mut cmd[pos..pos+2], TPM2_ST_SESSIONS);  // tag
    pos += 2;
    pos += 4;  // skip size for now
    pack_u32(&mut cmd[pos..pos+4], TPM2_CC_NV_READ);
    pos += 4;
    
    // authHandle (use NV index itself for owner read)
    pack_u32(&mut cmd[pos..pos+4], nv_index);
    pos += 4;
    
    // nvIndex
    pack_u32(&mut cmd[pos..pos+4], nv_index);
    pos += 4;
    
    // Authorization area
    let auth_start = pos;
    pos += 4;  // skip auth size for now
    
    // Session handle (password)
    pack_u32(&mut cmd[pos..pos+4], TPM2_RS_PW);
    pos += 4;
    
    // Nonce (empty)
    pack_u16(&mut cmd[pos..pos+2], 0);
    pos += 2;
    
    // Session attributes
    cmd[pos] = 0;  // continueSession = 0
    pos += 1;
    
    // Password (empty)
    pack_u16(&mut cmd[pos..pos+2], 0);
    pos += 2;
    
    // Update auth area size
    let auth_size = (pos - auth_start - 4) as u32;
    pack_u32(&mut cmd[auth_start..auth_start+4], auth_size);
    
    // Parameters: size, offset
    pack_u16(&mut cmd[pos..pos+2], size);
    pos += 2;
    pack_u16(&mut cmd[pos..pos+2], offset);
    pos += 2;
    
    // Update total command size
    pack_u32(&mut cmd[2..6], pos as u32);
    
    cmd.truncate(pos);
    cmd
}

/// Parse TPM2_NV_ReadPublic response to get data size
fn parse_nv_read_public_response(response: &[u8]) -> Option<u16> {
    if response.len() < 10 {
        return None;
    }
    
    let response_code = unpack_u32(&response[6..10]);
    if response_code != 0 {
        warn!("TPM2_NV_ReadPublic failed: 0x{:08x}", response_code);
        return None;
    }
    
    // Parse TPM2B_NV_PUBLIC
    // Skip: tag(2) + size(4) + responseCode(4) + nvPublic.size(2) + nvIndex(4) + nameAlg(2) + attributes(4)
    if response.len() < 28 {
        return None;
    }
    
    // dataSize is at offset 24 (after nvPublic structure header)
    let data_size = unpack_u16(&response[24..26]);
    Some(data_size)
}

/// Parse TPM2_NV_Read response
fn parse_nv_read_response(response: &[u8]) -> Option<Vec<u8>> {
    if response.len() < 10 {
        return None;
    }
    
    let response_code = unpack_u32(&response[6..10]);
    if response_code != 0 {
        warn!("TPM2_NV_Read failed: 0x{:08x}", response_code);
        return None;
    }
    
    // Skip header (10) + parameterSize (4)
    if response.len() < 16 {
        return None;
    }
    
    let _param_size = unpack_u32(&response[10..14]);
    let data_offset = 14usize;
    
    // TPM2B_MAX_NV_BUFFER: size(2) + data
    if response.len() < data_offset + 2 {
        return None;
    }
    
    let data_size = unpack_u16(&response[data_offset..data_offset+2]) as usize;
    let data_start = data_offset + 2;
    
    if response.len() < data_start + data_size {
        return None;
    }
    
    Some(response[data_start..data_start+data_size].to_vec())
}

/// ECDH key pair result from TPM
pub struct TpmEcdhKeyPair {
    pub handle: u32,
    pub public_x: Vec<u8>,
    pub public_y: Vec<u8>,
}

/// Build TPM2_CreatePrimary command for ECDH key (P-256)
fn build_create_primary_ecdh_cmd() -> Vec<u8> {
    let mut cmd = Vec::with_capacity(128);
    
    // Header placeholder
    cmd.extend_from_slice(&[0u8; 10]);
    pack_u16(&mut cmd[0..2], TPM2_ST_SESSIONS);
    pack_u32(&mut cmd[6..10], TPM2_CC_CREATE_PRIMARY);
    
    // primaryHandle = TPM_RH_OWNER
    let mut handle_bytes = [0u8; 4];
    pack_u32(&mut handle_bytes, TPM2_RH_OWNER);
    cmd.extend_from_slice(&handle_bytes);
    
    // Authorization area (password session, empty password)
    let auth_area_start = cmd.len();
    cmd.extend_from_slice(&[0u8; 4]); // auth size placeholder
    
    let mut session_handle = [0u8; 4];
    pack_u32(&mut session_handle, TPM2_RS_PW);
    cmd.extend_from_slice(&session_handle);
    cmd.extend_from_slice(&[0, 0]); // nonce size = 0
    cmd.push(0); // session attributes
    cmd.extend_from_slice(&[0, 0]); // password size = 0
    
    let auth_size = (cmd.len() - auth_area_start - 4) as u32;
    pack_u32(&mut cmd[auth_area_start..auth_area_start+4], auth_size);
    
    // inSensitive (TPM2B_SENSITIVE_CREATE) - empty
    cmd.extend_from_slice(&[0, 4]); // size = 4
    cmd.extend_from_slice(&[0, 0]); // userAuth size = 0
    cmd.extend_from_slice(&[0, 0]); // data size = 0
    
    // inPublic (TPMT_PUBLIC for ECC ECDH key)
    let in_public_start = cmd.len();
    cmd.extend_from_slice(&[0, 0]); // size placeholder
    
    // type = TPM_ALG_ECC
    let mut alg = [0u8; 2];
    pack_u16(&mut alg, TPM2_ALG_ECC);
    cmd.extend_from_slice(&alg);
    
    // nameAlg = TPM_ALG_SHA256
    pack_u16(&mut alg, TPM2_ALG_SHA256);
    cmd.extend_from_slice(&alg);
    
    // objectAttributes: fixedTPM | fixedParent | sensitivedataOrigin | userWithAuth | noDA | decrypt
    // 0x00020472 (NOT 0x00060472 which also sets sign bit - wrong for ECDH)
    cmd.extend_from_slice(&[0x00, 0x02, 0x04, 0x72]);
    
    // authPolicy (empty)
    cmd.extend_from_slice(&[0, 0]);
    
    // parameters.eccDetail
    // symmetric = TPM_ALG_NULL
    pack_u16(&mut alg, TPM2_ALG_NULL);
    cmd.extend_from_slice(&alg);
    
    // scheme = TPM_ALG_ECDH
    pack_u16(&mut alg, TPM2_ALG_ECDH);
    cmd.extend_from_slice(&alg);
    
    // scheme.details.ecdh.hashAlg = TPM_ALG_SHA256
    pack_u16(&mut alg, TPM2_ALG_SHA256);
    cmd.extend_from_slice(&alg);
    
    // curveID = TPM_ECC_NIST_P256
    pack_u16(&mut alg, TPM2_ECC_NIST_P256);
    cmd.extend_from_slice(&alg);
    
    // kdf.scheme = TPM_ALG_NULL
    pack_u16(&mut alg, TPM2_ALG_NULL);
    cmd.extend_from_slice(&alg);
    
    // unique (empty point)
    cmd.extend_from_slice(&[0, 0]); // x size = 0
    cmd.extend_from_slice(&[0, 0]); // y size = 0
    
    // Update inPublic size
    let in_public_size = (cmd.len() - in_public_start - 2) as u16;
    pack_u16(&mut cmd[in_public_start..in_public_start+2], in_public_size);
    
    // outsideInfo (empty)
    cmd.extend_from_slice(&[0, 0]);
    
    // creationPCR (empty)
    cmd.extend_from_slice(&[0, 0, 0, 0]); // count = 0
    
    // Update total command size
    let cmd_len = cmd.len() as u32;
    pack_u32(&mut cmd[2..6], cmd_len);
    
    cmd
}

/// Parse TPM2_CreatePrimary response to get key handle and public point
fn parse_create_primary_response(response: &[u8]) -> Option<TpmEcdhKeyPair> {
    if response.len() < 14 {
        return None;
    }
    
    let response_code = unpack_u32(&response[6..10]);
    if response_code != 0 {
        warn!("TPM2_CreatePrimary failed: 0x{:08x}", response_code);
        return None;
    }
    
    // objectHandle at offset 10
    let handle = unpack_u32(&response[10..14]);
    
    // Skip parameterSize (4 bytes) at offset 14
    let mut pos = 18;
    
    // TPM2B_PUBLIC
    if response.len() < pos + 2 {
        return None;
    }
    let public_size = unpack_u16(&response[pos..pos+2]) as usize;
    pos += 2;
    
    if response.len() < pos + public_size {
        return None;
    }
    
    // Skip type(2) + nameAlg(2) + attributes(4) + authPolicy.size(2)
    pos += 2 + 2 + 4;
    if response.len() < pos + 2 {
        return None;
    }
    let auth_policy_size = unpack_u16(&response[pos..pos+2]) as usize;
    pos += 2 + auth_policy_size;
    
    // Skip parameters: symmetric(2) + scheme(2) + scheme.hashAlg(2) + curveID(2) + kdf(2)
    pos += 2 + 2 + 2 + 2 + 2;
    
    // unique.x
    if response.len() < pos + 2 {
        return None;
    }
    let x_size = unpack_u16(&response[pos..pos+2]) as usize;
    pos += 2;
    if response.len() < pos + x_size {
        return None;
    }
    let public_x = response[pos..pos+x_size].to_vec();
    pos += x_size;
    
    // unique.y
    if response.len() < pos + 2 {
        return None;
    }
    let y_size = unpack_u16(&response[pos..pos+2]) as usize;
    pos += 2;
    if response.len() < pos + y_size {
        return None;
    }
    let public_y = response[pos..pos+y_size].to_vec();
    
    Some(TpmEcdhKeyPair {
        handle,
        public_x,
        public_y,
    })
}

/// Build TPM2_ECDH_ZGen command to compute shared secret
fn build_ecdh_zgen_cmd(key_handle: u32, peer_x: &[u8], peer_y: &[u8]) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(128);
    
    // Header placeholder
    cmd.extend_from_slice(&[0u8; 10]);
    pack_u16(&mut cmd[0..2], TPM2_ST_SESSIONS);
    pack_u32(&mut cmd[6..10], TPM2_CC_ECDH_ZGEN);
    
    // keyHandle
    let mut handle_bytes = [0u8; 4];
    pack_u32(&mut handle_bytes, key_handle);
    cmd.extend_from_slice(&handle_bytes);
    
    // Authorization area
    let auth_area_start = cmd.len();
    cmd.extend_from_slice(&[0u8; 4]); // auth size placeholder
    
    let mut session_handle = [0u8; 4];
    pack_u32(&mut session_handle, TPM2_RS_PW);
    cmd.extend_from_slice(&session_handle);
    cmd.extend_from_slice(&[0, 0]); // nonce size = 0
    cmd.push(0); // session attributes
    cmd.extend_from_slice(&[0, 0]); // password size = 0
    
    let auth_size = (cmd.len() - auth_area_start - 4) as u32;
    pack_u32(&mut cmd[auth_area_start..auth_area_start+4], auth_size);
    
    // inPoint (TPMS_ECC_POINT)
    // TPM2B_ECC_POINT size
    let point_size = 2 + peer_x.len() + 2 + peer_y.len();
    let mut size_bytes = [0u8; 2];
    pack_u16(&mut size_bytes, point_size as u16);
    cmd.extend_from_slice(&size_bytes);
    
    // x coordinate
    pack_u16(&mut size_bytes, peer_x.len() as u16);
    cmd.extend_from_slice(&size_bytes);
    cmd.extend_from_slice(peer_x);
    
    // y coordinate
    pack_u16(&mut size_bytes, peer_y.len() as u16);
    cmd.extend_from_slice(&size_bytes);
    cmd.extend_from_slice(peer_y);
    
    // Update total command size
    let cmd_len = cmd.len() as u32;
    pack_u32(&mut cmd[2..6], cmd_len);
    
    cmd
}

/// Parse TPM2_ECDH_ZGen response to get shared secret (x coordinate)
fn parse_ecdh_zgen_response(response: &[u8]) -> Option<Vec<u8>> {
    if response.len() < 14 {
        return None;
    }
    
    let response_code = unpack_u32(&response[6..10]);
    if response_code != 0 {
        warn!("TPM2_ECDH_ZGen failed: 0x{:08x}", response_code);
        return None;
    }
    
    // Skip parameterSize (4 bytes) at offset 10
    let mut pos = 14;
    
    // TPM2B_ECC_POINT
    if response.len() < pos + 2 {
        return None;
    }
    let _point_size = unpack_u16(&response[pos..pos+2]) as usize;
    pos += 2;
    
    // x coordinate (this is the shared secret Z)
    if response.len() < pos + 2 {
        return None;
    }
    let x_size = unpack_u16(&response[pos..pos+2]) as usize;
    pos += 2;
    
    if response.len() < pos + x_size {
        return None;
    }
    let shared_secret = response[pos..pos+x_size].to_vec();
    
    Some(shared_secret)
}

/// Build TPM2_FlushContext command
fn build_flush_context_cmd(handle: u32) -> Vec<u8> {
    let mut cmd = vec![0u8; 14];
    pack_u16(&mut cmd[0..2], TPM2_ST_NO_SESSIONS);
    pack_u32(&mut cmd[2..6], 14);
    pack_u32(&mut cmd[6..10], TPM2_CC_FLUSH_CONTEXT);
    pack_u32(&mut cmd[10..14], handle);
    cmd
}

/// Build TPM2_Sign command for ECDSA with SHA-256
fn build_sign_cmd(key_handle: u32, digest: &[u8]) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(128);
    
    // Header placeholder
    cmd.extend_from_slice(&[0u8; 10]);
    pack_u16(&mut cmd[0..2], TPM2_ST_SESSIONS);
    pack_u32(&mut cmd[6..10], TPM2_CC_SIGN);
    
    // keyHandle
    let mut handle_bytes = [0u8; 4];
    pack_u32(&mut handle_bytes, key_handle);
    cmd.extend_from_slice(&handle_bytes);
    
    // Authorization area (password session, empty password)
    let auth_area_start = cmd.len();
    cmd.extend_from_slice(&[0u8; 4]); // auth size placeholder
    
    let mut session_handle = [0u8; 4];
    pack_u32(&mut session_handle, TPM2_RS_PW);
    cmd.extend_from_slice(&session_handle);
    cmd.extend_from_slice(&[0, 0]); // nonce size = 0
    cmd.push(0); // session attributes
    cmd.extend_from_slice(&[0, 0]); // password size = 0
    
    let auth_size = (cmd.len() - auth_area_start - 4) as u32;
    pack_u32(&mut cmd[auth_area_start..auth_area_start+4], auth_size);
    
    // digest (TPM2B_DIGEST)
    let mut size_bytes = [0u8; 2];
    pack_u16(&mut size_bytes, digest.len() as u16);
    cmd.extend_from_slice(&size_bytes);
    cmd.extend_from_slice(digest);
    
    // inScheme (TPMT_SIG_SCHEME)
    // Explicit ECDSA with SHA-256 scheme
    let mut alg = [0u8; 2];
    pack_u16(&mut alg, TPM2_ALG_ECDSA);
    cmd.extend_from_slice(&alg);
    // hashAlg = SHA256
    pack_u16(&mut alg, TPM2_ALG_SHA256);
    cmd.extend_from_slice(&alg);
    
    // validation (TPMT_TK_HASHCHECK) - null ticket
    pack_u16(&mut alg, 0x8024); // TPM_ST_HASHCHECK
    cmd.extend_from_slice(&alg);
    pack_u32(&mut handle_bytes, 0x40000007); // TPM_RH_NULL
    cmd.extend_from_slice(&handle_bytes);
    cmd.extend_from_slice(&[0, 0]); // digest size = 0
    
    // Update total command size
    let cmd_len = cmd.len() as u32;
    pack_u32(&mut cmd[2..6], cmd_len);
    
    cmd
}

/// Parse TPM2_Sign response to get ECDSA signature (r, s)
fn parse_sign_response(response: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if response.len() < 14 {
        return None;
    }
    
    let response_code = unpack_u32(&response[6..10]);
    if response_code != 0 {
        warn!("TPM2_Sign failed: 0x{:08x}", response_code);
        return None;
    }
    
    // Skip parameterSize (4 bytes) at offset 10
    let mut pos = 14;
    
    // TPMT_SIGNATURE
    // sigAlg
    if response.len() < pos + 2 {
        return None;
    }
    let _sig_alg = unpack_u16(&response[pos..pos+2]);
    pos += 2;
    
    // hashAlg
    if response.len() < pos + 2 {
        return None;
    }
    let _hash_alg = unpack_u16(&response[pos..pos+2]);
    pos += 2;
    
    // signatureR (TPM2B_ECC_PARAMETER)
    if response.len() < pos + 2 {
        return None;
    }
    let r_size = unpack_u16(&response[pos..pos+2]) as usize;
    pos += 2;
    if response.len() < pos + r_size {
        return None;
    }
    let r = response[pos..pos+r_size].to_vec();
    pos += r_size;
    
    // signatureS (TPM2B_ECC_PARAMETER)
    if response.len() < pos + 2 {
        return None;
    }
    let s_size = unpack_u16(&response[pos..pos+2]) as usize;
    pos += 2;
    if response.len() < pos + s_size {
        return None;
    }
    let s = response[pos..pos+s_size].to_vec();
    
    Some((r, s))
}

/// Create an ECDH key pair using TPM and return public key
pub fn tpm_create_ecdh_key() -> Option<TpmEcdhKeyPair> {
    let tcg_handle = boot::get_handle_for_protocol::<Tcg>().ok()?;
    let mut tcg = boot::open_protocol_exclusive::<Tcg>(tcg_handle).ok()?;
    
    let cmd = build_create_primary_ecdh_cmd();
    let mut response = vec![0u8; 1024];
    
    info!("TPM: Creating ECDH key...");
    let result = tcg.submit_command(&cmd, &mut response);
    
    if result.is_err() {
        warn!("TPM2_CreatePrimary failed");
        return None;
    }
    
    let key_pair = parse_create_primary_response(&response)?;
    info!("TPM: ECDH key created, handle=0x{:08x}", key_pair.handle);
    info!("TPM: Public X: {} bytes", key_pair.public_x.len());
    info!("TPM: Public Y: {} bytes", key_pair.public_y.len());
    
    Some(key_pair)
}

/// Compute ECDH shared secret using TPM
pub fn tpm_ecdh_compute_secret(key_handle: u32, peer_x: &[u8], peer_y: &[u8]) -> Option<Vec<u8>> {
    let tcg_handle = boot::get_handle_for_protocol::<Tcg>().ok()?;
    let mut tcg = boot::open_protocol_exclusive::<Tcg>(tcg_handle).ok()?;
    
    let cmd = build_ecdh_zgen_cmd(key_handle, peer_x, peer_y);
    let mut response = vec![0u8; 512];
    
    info!("TPM: Computing ECDH shared secret...");
    let result = tcg.submit_command(&cmd, &mut response);
    
    if result.is_err() {
        warn!("TPM2_ECDH_ZGen failed");
        return None;
    }
    
    let secret = parse_ecdh_zgen_response(&response)?;
    info!("TPM: Shared secret computed: {} bytes", secret.len());
    
    Some(secret)
}

/// Derive ECDH shared secret from FDO-formatted peer key
/// FDO ECDH format: [2-byte xLen][x][2-byte yLen][y][2-byte randLen][rand]
/// For P-256: 2+32+2+32+2+16 = 86 bytes
pub fn tpm_ecdh_derive(key_handle: u32, peer_key_fdo: &[u8]) -> Option<Vec<u8>> {
    info!("TPM ECDH: parsing peer key, {} bytes", peer_key_fdo.len());
    info!("TPM ECDH: first 16 bytes: {:02x?}", &peer_key_fdo[..peer_key_fdo.len().min(16)]);
    
    // FDO ECDH format: [2-byte xLen][x][2-byte yLen][y][2-byte randLen][rand]
    if peer_key_fdo.len() < 6 {
        warn!("Peer key too short: {} bytes", peer_key_fdo.len());
        return None;
    }
    
    let mut pos = 0;
    
    // Read x length (big-endian u16)
    let x_len = ((peer_key_fdo[pos] as usize) << 8) | (peer_key_fdo[pos + 1] as usize);
    pos += 2;
    info!("TPM ECDH: x_len = {}", x_len);
    
    if peer_key_fdo.len() < pos + x_len + 4 {
        warn!("Peer key too short for x coordinate");
        return None;
    }
    
    let peer_x = &peer_key_fdo[pos..pos + x_len];
    pos += x_len;
    
    // Read y length (big-endian u16)
    let y_len = ((peer_key_fdo[pos] as usize) << 8) | (peer_key_fdo[pos + 1] as usize);
    pos += 2;
    info!("TPM ECDH: y_len = {}", y_len);
    
    if peer_key_fdo.len() < pos + y_len {
        warn!("Peer key too short for y coordinate");
        return None;
    }
    
    let peer_y = &peer_key_fdo[pos..pos + y_len];
    
    info!("TPM ECDH: peer X ({} bytes): {:02x?}", peer_x.len(), &peer_x[..peer_x.len().min(8)]);
    info!("TPM ECDH: peer Y ({} bytes): {:02x?}", peer_y.len(), &peer_y[..peer_y.len().min(8)]);
    
    tpm_ecdh_compute_secret(key_handle, peer_x, peer_y)
}

/// Flush a TPM transient object
pub fn tpm_flush_context(handle: u32) {
    if let Ok(tcg_handle) = boot::get_handle_for_protocol::<Tcg>() {
        if let Ok(mut tcg) = boot::open_protocol_exclusive::<Tcg>(tcg_handle) {
            let cmd = build_flush_context_cmd(handle);
            let mut response = vec![0u8; 32];
            let _ = tcg.submit_command(&cmd, &mut response);
            info!("TPM: Flushed handle 0x{:08x}", handle);
        }
    }
}

/// TPM2_CC_ReadPublic command code
const TPM2_CC_READ_PUBLIC: u32 = 0x00000173;

/// Read the public key from a persistent handle
/// Returns (x, y) coordinates for ECC keys
pub fn tpm_read_public(handle: u32) -> Option<(Vec<u8>, Vec<u8>)> {
    let tcg_handle = boot::get_handle_for_protocol::<Tcg>().ok()?;
    let mut tcg = boot::open_protocol_exclusive::<Tcg>(tcg_handle).ok()?;
    
    // Build TPM2_ReadPublic command
    let mut cmd = vec![0u8; 14];
    pack_u16(&mut cmd[0..2], TPM2_ST_NO_SESSIONS);
    pack_u32(&mut cmd[2..6], 14);
    pack_u32(&mut cmd[6..10], TPM2_CC_READ_PUBLIC);
    pack_u32(&mut cmd[10..14], handle);
    
    let mut response = vec![0u8; 512];
    
    info!("TPM: Reading public key from handle 0x{:08x}...", handle);
    let result = tcg.submit_command(&cmd, &mut response);
    
    if result.is_err() {
        warn!("TPM2_ReadPublic command failed");
        return None;
    }
    
    // Parse response
    if response.len() < 14 {
        warn!("TPM2_ReadPublic response too short: {} bytes", response.len());
        return None;
    }
    
    let response_code = unpack_u32(&response[6..10]);
    if response_code != 0 {
        warn!("TPM2_ReadPublic failed: 0x{:08x}", response_code);
        return None;
    }
    
    info!("TPM: ReadPublic response OK, {} bytes", response.len());
    
    // Skip header(10)
    let mut pos = 10;
    
    // TPM2B_PUBLIC
    if response.len() < pos + 2 {
        return None;
    }
    let public_size = unpack_u16(&response[pos..pos+2]) as usize;
    pos += 2;
    
    if response.len() < pos + public_size {
        return None;
    }
    
    // Skip type(2) + nameAlg(2) + attributes(4) + authPolicy.size(2)
    pos += 2 + 2 + 4;
    if response.len() < pos + 2 {
        return None;
    }
    let auth_policy_size = unpack_u16(&response[pos..pos+2]) as usize;
    pos += 2 + auth_policy_size;
    
    // Skip parameters: symmetric(2) + scheme(2) + scheme.hashAlg(2) + curveID(2) + kdf(2)
    pos += 2 + 2 + 2 + 2 + 2;
    
    // unique.x
    if response.len() < pos + 2 {
        return None;
    }
    let x_size = unpack_u16(&response[pos..pos+2]) as usize;
    pos += 2;
    if response.len() < pos + x_size {
        return None;
    }
    let public_x = response[pos..pos+x_size].to_vec();
    pos += x_size;
    
    // unique.y
    if response.len() < pos + 2 {
        return None;
    }
    let y_size = unpack_u16(&response[pos..pos+2]) as usize;
    pos += 2;
    if response.len() < pos + y_size {
        return None;
    }
    let public_y = response[pos..pos+y_size].to_vec();
    
    info!("TPM: Public key read: x={} bytes, y={} bytes", public_x.len(), public_y.len());
    
    Some((public_x, public_y))
}

// P-256 curve order N (for low-S normalization)
const P256_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

// Half of P-256 curve order (N/2) for low-S check
const P256_HALF_ORDER: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00,
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42,
    0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
];

/// Compare two 32-byte big-endian integers
fn compare_bytes(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    for i in 0..32 {
        match a[i].cmp(&b[i]) {
            core::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    core::cmp::Ordering::Equal
}

/// Subtract b from a (big-endian), result in out. Assumes a >= b.
fn subtract_bytes(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let diff = (a[i] as u16).wrapping_sub(b[i] as u16).wrapping_sub(borrow);
        result[i] = diff as u8;
        borrow = if diff > 0xFF { 1 } else { 0 };
    }
    result
}

/// Sign a SHA-256 digest using the FDO Device Attestation Key (DAK)
/// Returns the signature as concatenated r || s (64 bytes for P-256)
/// Applies low-S normalization per BIP-0062 / RFC 6979
pub fn tpm_sign_with_dak(digest: &[u8; 32]) -> Option<Vec<u8>> {
    let tcg_handle = boot::get_handle_for_protocol::<Tcg>().ok()?;
    let mut tcg = boot::open_protocol_exclusive::<Tcg>(tcg_handle).ok()?;
    
    let cmd = build_sign_cmd(FDO_DAK_HANDLE, digest);
    let mut response = vec![0u8; 512];
    
    info!("TPM: Signing with DAK (handle 0x{:08x})...", FDO_DAK_HANDLE);
    let result = tcg.submit_command(&cmd, &mut response);
    
    if result.is_err() {
        warn!("TPM2_Sign command failed");
        return None;
    }
    
    let (r, s) = parse_sign_response(&response)?;
    info!("TPM: Signature obtained: r={} bytes, s={} bytes", r.len(), s.len());
    
    // Pad r and s to 32 bytes each (P-256 signature)
    let mut r_padded = [0u8; 32];
    let mut s_padded = [0u8; 32];
    
    // Pad r to 32 bytes (left-pad with zeros if needed)
    let r_start = 32usize.saturating_sub(r.len());
    r_padded[r_start..].copy_from_slice(&r[r.len().saturating_sub(32)..]);
    
    // Pad s to 32 bytes
    let s_start = 32usize.saturating_sub(s.len());
    s_padded[s_start..].copy_from_slice(&s[s.len().saturating_sub(32)..]);
    
    // Low-S normalization: if s > N/2, replace s with N - s
    if compare_bytes(&s_padded, &P256_HALF_ORDER) == core::cmp::Ordering::Greater {
        info!("TPM: Applying low-S normalization");
        s_padded = subtract_bytes(&P256_ORDER, &s_padded);
    }
    
    let mut signature = Vec::with_capacity(64);
    signature.extend_from_slice(&r_padded);
    signature.extend_from_slice(&s_padded);
    
    Some(signature)
}

/// Read data from TPM NV index
pub fn tpm_nv_read(nv_index: u32) -> Option<Vec<u8>> {
    // Get TCG2 protocol
    let tcg_handle = boot::get_handle_for_protocol::<Tcg>().ok()?;
    let mut tcg = boot::open_protocol_exclusive::<Tcg>(tcg_handle).ok()?;
    
    // First, get the NV index size
    let read_public_cmd = build_nv_read_public_cmd(nv_index);
    let mut response = vec![0u8; 512];
    
    let result = tcg.submit_command(&read_public_cmd, &mut response);
    
    if result.is_err() {
        warn!("submit_command (NV_ReadPublic) failed");
        return None;
    }
    
    let data_size = parse_nv_read_public_response(&response)?;
    info!("NV index 0x{:08x} size: {} bytes", nv_index, data_size);
    
    // Now read the actual data
    let read_cmd = build_nv_read_cmd(nv_index, data_size, 0);
    let mut response = vec![0u8; 1024];
    
    let result = tcg.submit_command(&read_cmd, &mut response);
    
    if result.is_err() {
        warn!("submit_command (NV_Read) failed");
        return None;
    }
    
    parse_nv_read_response(&response)
}

/// Skip a CBOR value in data, advancing pos
fn skip_cbor_value(data: &[u8], pos: &mut usize) -> bool {
    if *pos >= data.len() {
        return false;
    }
    
    let initial = data[*pos];
    *pos += 1;
    
    let major = initial >> 5;
    let additional = initial & 0x1f;
    
    // Get the argument (length/count/value)
    let arg = if additional < 24 {
        additional as usize
    } else if additional == 24 && *pos < data.len() {
        let a = data[*pos] as usize;
        *pos += 1;
        a
    } else if additional == 25 && *pos + 1 < data.len() {
        let a = ((data[*pos] as usize) << 8) | (data[*pos + 1] as usize);
        *pos += 2;
        a
    } else if additional == 26 && *pos + 3 < data.len() {
        let a = ((data[*pos] as usize) << 24) | ((data[*pos + 1] as usize) << 16)
            | ((data[*pos + 2] as usize) << 8) | (data[*pos + 3] as usize);
        *pos += 4;
        a
    } else {
        return false;
    };
    
    match major {
        0 | 1 => {
            // Unsigned/signed int - already consumed
            true
        }
        2 | 3 => {
            // Byte string / text string - skip arg bytes
            if *pos + arg > data.len() {
                return false;
            }
            *pos += arg;
            true
        }
        4 => {
            // Array - skip arg items
            for _ in 0..arg {
                if !skip_cbor_value(data, pos) {
                    return false;
                }
            }
            true
        }
        5 => {
            // Map - skip arg*2 items (key+value pairs)
            for _ in 0..arg * 2 {
                if !skip_cbor_value(data, pos) {
                    return false;
                }
            }
            true
        }
        6 => {
            // Tag - skip the tagged value
            skip_cbor_value(data, pos)
        }
        7 => {
            // Simple/float - already consumed for simple, or skip bytes for float
            if additional == 25 {
                *pos += 2;
            } else if additional == 26 {
                *pos += 4;
            } else if additional == 27 {
                *pos += 8;
            }
            true
        }
        _ => false,
    }
}

/// Read FDO device credential GUID from TPM NV (DCTPM index)
/// DCTPM is a CBOR array or map with GUID at index/key 4
pub fn read_fdo_guid() -> Option<[u8; 16]> {
    // Try the consolidated DCTPM index (0x01D10001)
    let data = tpm_nv_read(FDO_NV_INDEX_ALT)?;
    info!("DCTPM NV data: {} bytes", data.len());
    
    // Parse CBOR map to extract GUID at key 4
    // CBOR map format: 0xA0-0xBF for small maps, or 0xB9/0xBA/0xBB for larger
    if data.is_empty() {
        warn!("DCTPM NV data is empty");
        return None;
    }
    
    let mut pos = 0;
    let initial = data[pos];
    pos += 1;
    
    // Check for CBOR array (major type 4) or map (major type 5)
    let major = initial >> 5;
    let additional = initial & 0x1f;
    
    let num_items = if additional < 24 {
        additional as usize
    } else if additional == 24 && pos < data.len() {
        let n = data[pos] as usize;
        pos += 1;
        n
    } else {
        warn!("DCTPM: unsupported size encoding");
        return None;
    };
    
    if major == 4 {
        // CBOR array - GUID is at index 4
        info!("DCTPM: CBOR array with {} items", num_items);
        if num_items < 5 {
            warn!("DCTPM: array too short for GUID at index 4");
            return None;
        }
        
        // Skip items 0-3 to get to GUID at index 4
        for idx in 0..4 {
            if pos >= data.len() {
                return None;
            }
            let skip_result = skip_cbor_value(&data, &mut pos);
            if !skip_result {
                warn!("DCTPM: failed to skip item {}", idx);
                return None;
            }
        }
        
        // Now at index 4 - should be GUID (16-byte bstr)
        if pos >= data.len() {
            return None;
        }
        let val_byte = data[pos];
        pos += 1;
        
        // Check for bstr (major type 2)
        if (val_byte >> 5) != 2 {
            warn!("DCTPM: GUID should be bstr, got major {}", val_byte >> 5);
            return None;
        }
        
        let len = (val_byte & 0x1f) as usize;
        if len != 16 {
            warn!("DCTPM: GUID should be 16 bytes, got {}", len);
            return None;
        }
        
        if pos + 16 > data.len() {
            warn!("DCTPM: not enough data for GUID");
            return None;
        }
        
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&data[pos..pos+16]);
        info!("DCTPM: Found GUID at array index 4: {:02x?}", guid);
        return Some(guid);
    } else if major == 5 {
        // CBOR map with integer keys - GUID at key 4
        info!("DCTPM: CBOR map with {} pairs", num_items);
        
        // Iterate through map looking for key 4 (GUID)
        for _ in 0..num_items {
            if pos >= data.len() {
                break;
            }
            
            // Read key (should be small unsigned int)
            let key_byte = data[pos];
            pos += 1;
            
            let key = if (key_byte >> 5) == 0 {
                let add = key_byte & 0x1f;
                if add < 24 {
                    add as u32
                } else if add == 24 && pos < data.len() {
                    let k = data[pos] as u32;
                    pos += 1;
                    k
                } else {
                    return None;
                }
            } else {
                return None;
            };
            
            if key == 4 {
                // Key 4 is GUID - should be 16-byte bstr
                if pos >= data.len() {
                    return None;
                }
                let val_byte = data[pos];
                pos += 1;
                
                if (val_byte >> 5) != 2 {
                    warn!("DCTPM: GUID should be bstr");
                    return None;
                }
                
                let len = (val_byte & 0x1f) as usize;
                if len != 16 || pos + 16 > data.len() {
                    return None;
                }
                
                let mut guid = [0u8; 16];
                guid.copy_from_slice(&data[pos..pos+16]);
                info!("DCTPM: Found GUID in map: {:02x?}", guid);
                return Some(guid);
            } else {
                // Skip this value using helper
                if !skip_cbor_value(&data, &mut pos) {
                    return None;
                }
            }
        }
        
        warn!("DCTPM: GUID (key 4) not found in map");
        return None;
    }
    
    warn!("DCTPM: unsupported major type {}", major);
    None
}

/// Read FDO RV info from TPM NV (DCTPM index)
/// Returns the RV URL string (owner server address)
pub fn read_fdo_rv_info() -> Option<alloc::string::String> {
    // For now, return hardcoded - will implement full parsing later
    // The RV info is at key 5 in the DCTPM CBOR map
    Some(alloc::string::String::from("http://10.0.2.2:8080"))
}

/// Test TPM functionality
pub fn test_tpm() {
    info!("Looking for TCG2 protocol...");
    
    match boot::get_handle_for_protocol::<Tcg>() {
        Ok(handle) => {
            info!("TCG2 protocol found!");
            
            match boot::open_protocol_exclusive::<Tcg>(handle) {
                Ok(mut tcg) => {
                    // Get capability
                    match tcg.get_capability() {
                        Ok(cap) => {
                            info!("TPM Manufacturer ID: 0x{:08x}", cap.manufacturer_id);
                            info!("Max command size: {}", cap.max_command_size);
                            info!("Max response size: {}", cap.max_response_size);
                        }
                        Err(e) => {
                            warn!("get_capability failed: {:?}", e);
                        }
                    }
                    
                    // Try reading public keys from various persistent handles
                    // quick-di uses 0x81020002 for DAK and 0x81020003 for HMAC
                    // But cert key might be at different handle
                    for handle in [0x81020001u32, 0x81020002, 0x81020003, 0x81020004, 0x81000001] {
                        info!("Checking persistent handle 0x{:08x}...", handle);
                        match tpm_read_public(handle) {
                            Some((x, y)) => {
                                info!("  Found key at 0x{:08x}: X={:02x?}", handle, &x[..x.len().min(8)]);
                            }
                            None => {
                                info!("  Handle 0x{:08x} not found", handle);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to open TCG2 protocol: {:?}", e);
                }
            }
        }
        Err(_) => {
            warn!("TCG2 protocol not available (no TPM?)");
        }
    }
}
