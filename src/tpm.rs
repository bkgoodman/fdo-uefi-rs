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
    
    // authHandle = TPM_RH_OWNER (required for OWNERREAD attribute)
    pack_u32(&mut cmd[pos..pos+4], TPM2_RH_OWNER);
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

/// Read the public key from a persistent TPM handle using TPM2_ReadPublic.
/// Per securing-fdo-in-tpm.bs spec, persistent handles are always accessible.
/// Returns (x, y) coordinates for ECC keys.
pub fn tpm_read_public(handle: u32) -> Option<(Vec<u8>, Vec<u8>)> {
    let tcg_handle = boot::get_handle_for_protocol::<Tcg>().ok()?;
    let mut tcg = boot::open_protocol_exclusive::<Tcg>(tcg_handle).ok()?;
    
    // Build TPM2_ReadPublic command (no auth session needed)
    let mut cmd = vec![0u8; 14];
    pack_u16(&mut cmd[0..2], TPM2_ST_NO_SESSIONS);
    pack_u32(&mut cmd[2..6], 14); // command size
    pack_u32(&mut cmd[6..10], TPM2_CC_READ_PUBLIC);
    pack_u32(&mut cmd[10..14], handle);
    
    let mut response = vec![0u8; 512];
    info!("TPM: ReadPublic on handle 0x{:08x}...", handle);
    if tcg.submit_command(&cmd, &mut response).is_err() {
        warn!("TPM: ReadPublic submit failed for 0x{:08x}", handle);
        return None;
    }
    
    let rc = unpack_u32(&response[6..10]);
    if rc != 0 {
        warn!("TPM: ReadPublic error 0x{:08x} for handle 0x{:08x}", rc, handle);
        return None;
    }
    
    // Parse TPM2B_PUBLIC from response
    // Response layout after header (10 bytes):
    //   TPM2B_PUBLIC: 2-byte size, then TPMT_PUBLIC
    //   TPMT_PUBLIC: type(2), nameAlg(2), objectAttributes(4), authPolicy(2+n),
    //                then parameters + unique
    let resp_size = unpack_u32(&response[2..6]) as usize;
    if resp_size < 14 {
        return None;
    }
    
    let mut pos = 10; // after header
    if pos + 2 > response.len() { return None; }
    let pub_size = unpack_u16(&response[pos..pos+2]) as usize;
    pos += 2;
    
    if pos + pub_size > response.len() || pub_size < 14 {
        return None;
    }
    
    let pub_start = pos;
    let alg_type = unpack_u16(&response[pos..pos+2]);
    pos += 2; // type
    pos += 2; // nameAlg
    pos += 4; // objectAttributes
    
    // authPolicy (TPM2B)
    if pos + 2 > response.len() { return None; }
    let auth_size = unpack_u16(&response[pos..pos+2]) as usize;
    pos += 2 + auth_size;
    
    if alg_type != TPM2_ALG_ECC {
        warn!("TPM: ReadPublic: not ECC key (type=0x{:04x})", alg_type);
        return None;
    }
    
    // ECC parameters: symmetric(2), scheme(2+2), curveID(2), kdf(2) = 10 bytes
    pos += 2; // symmetric
    let scheme_alg = unpack_u16(&response[pos..pos+2]);
    pos += 2;
    if scheme_alg != TPM2_ALG_NULL {
        pos += 2; // scheme hashAlg
    }
    pos += 2; // curveID
    pos += 2; // kdf scheme (TPM_ALG_NULL)
    
    // unique: TPMS_ECC_POINT = {TPM2B x, TPM2B y}
    if pos + 2 > pub_start + pub_size { return None; }
    let x_size = unpack_u16(&response[pos..pos+2]) as usize;
    pos += 2;
    if pos + x_size > pub_start + pub_size { return None; }
    let x = response[pos..pos+x_size].to_vec();
    pos += x_size;
    
    if pos + 2 > pub_start + pub_size { return None; }
    let y_size = unpack_u16(&response[pos..pos+2]) as usize;
    pos += 2;
    if pos + y_size > pub_start + pub_size { return None; }
    let y = response[pos..pos+y_size].to_vec();
    
    info!("TPM: ReadPublic 0x{:08x}: x={} bytes, y={} bytes", handle, x.len(), y.len());
    Some((x, y))
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

/// Sign a SHA-256 digest using a persistent TPM signing key.
/// Per securing-fdo-in-tpm.bs spec, the FDO client SHALL locate the Device key
/// by reading DCTPM.DeviceKeyHandle and sign using that persistent handle directly.
/// Returns the signature as concatenated r || s (64 bytes for P-256).
/// Applies low-S normalization per BIP-0062 / RFC 6979.
pub fn tpm_sign_with_persistent(persistent_handle: u32, digest: &[u8; 32]) -> Option<Vec<u8>> {
    let tcg_handle = boot::get_handle_for_protocol::<Tcg>().ok()?;
    let mut tcg = boot::open_protocol_exclusive::<Tcg>(tcg_handle).ok()?;
    
    // Sign directly with the persistent handle — no CreatePrimary needed.
    // Persistent handles (0x81xxxxxx) are always accessible; they are not
    // transient contexts and are not flushed by the UEFI resource manager.
    let cmd = build_sign_cmd(persistent_handle, digest);
    
    // Retry loop for TPM_RC_RETRY (0x922) — the TPM may need time to
    // become ready after flushing transient handles or other operations.
    // This matches the retry pattern used by EvictControl and NV DefineSpace.
    let mut signed = false;
    let mut response = vec![0u8; 512];
    for attempt in 0..5 {
        response = vec![0u8; 512];
        info!("TPM: Signing with persistent handle 0x{:08x} (attempt {})...", persistent_handle, attempt);
        let result = tcg.submit_command(&cmd, &mut response);
        
        if result.is_err() {
            warn!("TPM2_Sign submit failed for handle 0x{:08x} (attempt {})", persistent_handle, attempt);
            boot::stall(core::time::Duration::from_millis(200));
            continue;
        }
        
        let rc = unpack_u32(&response[6..10]);
        if rc == 0x922 {
            info!("TPM2_Sign got TPM_RC_RETRY (0x922), retrying... (attempt {})", attempt);
            boot::stall(core::time::Duration::from_millis(200));
            continue;
        }
        if rc == 0 {
            signed = true;
            break;
        }
        warn!("TPM2_Sign error: 0x{:08x} for handle 0x{:08x}", rc, persistent_handle);
        return None;
    }
    
    if !signed {
        warn!("TPM2_Sign failed after retries for handle 0x{:08x}", persistent_handle);
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
    info!("tpm_nv_read: reading index 0x{:08x}", nv_index);
    // Get TCG2 protocol
    let tcg_handle = boot::get_handle_for_protocol::<Tcg>().ok()?;
    let mut tcg = boot::open_protocol_exclusive::<Tcg>(tcg_handle).ok()?;
    
    // First, get the NV index size
    let read_public_cmd = build_nv_read_public_cmd(nv_index);
    let mut response = vec![0u8; 512];
    
    let result = tcg.submit_command(&read_public_cmd, &mut response);
    
    if result.is_err() {
        warn!("submit_command (NV_ReadPublic) failed for 0x{:08x}", nv_index);
        return None;
    }
    
    let rc = unpack_u32(&response[6..10]);
    info!("NV_ReadPublic response: rc=0x{:08x} for index 0x{:08x}", rc, nv_index);
    if rc != 0 {
        info!("NV index 0x{:08x} does not exist (rc=0x{:08x})", nv_index, rc);
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

/// FDO device credentials parsed from DCTPM NV blob.
/// Per securing-fdo-in-tpm.bs spec, the client SHALL read these handles
/// from DCTPM and use them directly — never assume hardcoded values.
pub struct FdoCredentials {
    pub guid: [u8; 16],
    pub device_key_handle: u32,
    pub hmac_key_handle: u32,
}

/// Read a CBOR unsigned integer at the current position.
/// Handles additional info values 0-23, 24 (1-byte), 25 (2-byte), 26 (4-byte).
fn read_cbor_uint(data: &[u8], pos: &mut usize) -> Option<u32> {
    if *pos >= data.len() {
        return None;
    }
    let initial = data[*pos];
    *pos += 1;
    if (initial >> 5) != 0 {
        return None; // Not major type 0 (unsigned int)
    }
    let add = initial & 0x1f;
    if add < 24 {
        Some(add as u32)
    } else if add == 24 && *pos < data.len() {
        let v = data[*pos] as u32;
        *pos += 1;
        Some(v)
    } else if add == 25 && *pos + 2 <= data.len() {
        let v = ((data[*pos] as u32) << 8) | (data[*pos + 1] as u32);
        *pos += 2;
        Some(v)
    } else if add == 26 && *pos + 4 <= data.len() {
        let v = ((data[*pos] as u32) << 24) | ((data[*pos+1] as u32) << 16)
              | ((data[*pos+2] as u32) << 8) | (data[*pos+3] as u32);
        *pos += 4;
        Some(v)
    } else {
        None
    }
}

/// Read a CBOR bstr at the current position and return its bytes.
fn read_cbor_bstr<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    if *pos >= data.len() {
        return None;
    }
    let initial = data[*pos];
    *pos += 1;
    if (initial >> 5) != 2 {
        return None; // Not major type 2 (bstr)
    }
    let add = initial & 0x1f;
    let len = if add < 24 {
        add as usize
    } else if add == 24 && *pos < data.len() {
        let n = data[*pos] as usize;
        *pos += 1;
        n
    } else if add == 25 && *pos + 2 <= data.len() {
        let n = ((data[*pos] as usize) << 8) | (data[*pos + 1] as usize);
        *pos += 2;
        n
    } else {
        return None;
    };
    if *pos + len > data.len() {
        return None;
    }
    let result = &data[*pos..*pos + len];
    *pos += len;
    Some(result)
}

/// Read FDO device credentials from TPM NV (DCTPM index).
/// Per securing-fdo-in-tpm.bs spec, the client SHALL read DCTPM to get:
///   - GUID (index/key 4)
///   - DeviceKeyHandle (index/key 8)
///   - HMACKeyHandle (index/key 9)
///
/// DCTPM layout (CBOR array or map):
///   0: Magic, 1: Active, 2: Version, 3: DeviceInfo, 4: GUID,
///   5: RvInfo, 6: PubKeyHash, 7: KeyType, 8: DeviceKeyHandle, 9: HMACKeyHandle
pub fn read_fdo_credentials() -> Option<FdoCredentials> {
    info!("Checking TPM NV for DCTPM at index 0x{:08x}...", FDO_NV_INDEX_ALT);
    let data = match tpm_nv_read(FDO_NV_INDEX_ALT) {
        Some(d) => d,
        None => {
            info!("No DCTPM found in NV (index 0x{:08x} not defined or empty)", FDO_NV_INDEX_ALT);
            return None;
        }
    };
    info!("DCTPM NV data: {} bytes, first 16: {:02x?}", data.len(), &data[..data.len().min(16)]);
    
    if data.is_empty() {
        warn!("DCTPM NV data is empty");
        return None;
    }
    
    let mut pos = 0;
    let initial = data[pos];
    pos += 1;
    
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
        // CBOR array — fields at fixed indices
        info!("DCTPM: CBOR array with {} items", num_items);
        if num_items < 10 {
            warn!("DCTPM: array needs >= 10 items (has {}), missing key handles", num_items);
            return None;
        }
        
        // Skip items 0-3 (Magic, Active, Version, DeviceInfo)
        for idx in 0..4 {
            if !skip_cbor_value(&data, &mut pos) {
                warn!("DCTPM: failed to skip item {}", idx);
                return None;
            }
        }
        
        // Item 4: GUID (16-byte bstr)
        let guid_bytes = read_cbor_bstr(&data, &mut pos)?;
        if guid_bytes.len() != 16 {
            warn!("DCTPM: GUID should be 16 bytes, got {}", guid_bytes.len());
            return None;
        }
        let mut guid = [0u8; 16];
        guid.copy_from_slice(guid_bytes);
        info!("DCTPM: GUID: {:02x?}", guid);
        
        // Skip items 5-7 (RvInfo, PubKeyHash, KeyType)
        for idx in 5..8 {
            if !skip_cbor_value(&data, &mut pos) {
                warn!("DCTPM: failed to skip item {}", idx);
                return None;
            }
        }
        
        // Item 8: DeviceKeyHandle (uint32)
        let device_key_handle = read_cbor_uint(&data, &mut pos)?;
        info!("DCTPM: DeviceKeyHandle: 0x{:08x}", device_key_handle);
        
        // Item 9: HMACKeyHandle (uint32)
        let hmac_key_handle = read_cbor_uint(&data, &mut pos)?;
        info!("DCTPM: HMACKeyHandle: 0x{:08x}", hmac_key_handle);
        
        return Some(FdoCredentials { guid, device_key_handle, hmac_key_handle });
    } else if major == 5 {
        // CBOR map — find keys 4, 8, 9
        info!("DCTPM: CBOR map with {} pairs", num_items);
        let mut guid: Option<[u8; 16]> = None;
        let mut device_key_handle: Option<u32> = None;
        let mut hmac_key_handle: Option<u32> = None;
        
        for _ in 0..num_items {
            if pos >= data.len() {
                break;
            }
            
            // Read map key (unsigned int)
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
            
            match key {
                4 => {
                    // GUID (16-byte bstr)
                    let guid_bytes = read_cbor_bstr(&data, &mut pos)?;
                    if guid_bytes.len() != 16 {
                        warn!("DCTPM: GUID should be 16 bytes, got {}", guid_bytes.len());
                        return None;
                    }
                    let mut g = [0u8; 16];
                    g.copy_from_slice(guid_bytes);
                    info!("DCTPM: GUID: {:02x?}", g);
                    guid = Some(g);
                }
                8 => {
                    // DeviceKeyHandle (uint32)
                    let h = read_cbor_uint(&data, &mut pos)?;
                    info!("DCTPM: DeviceKeyHandle: 0x{:08x}", h);
                    device_key_handle = Some(h);
                }
                9 => {
                    // HMACKeyHandle (uint32)
                    let h = read_cbor_uint(&data, &mut pos)?;
                    info!("DCTPM: HMACKeyHandle: 0x{:08x}", h);
                    hmac_key_handle = Some(h);
                }
                _ => {
                    if !skip_cbor_value(&data, &mut pos) {
                        return None;
                    }
                }
            }
        }
        
        match (guid, device_key_handle, hmac_key_handle) {
            (Some(g), Some(dk), Some(hk)) => {
                return Some(FdoCredentials { guid: g, device_key_handle: dk, hmac_key_handle: hk });
            }
            _ => {
                warn!("DCTPM: missing required fields (guid={}, dkh={}, hkh={})",
                      guid.is_some(), device_key_handle.is_some(), hmac_key_handle.is_some());
                return None;
            }
        }
    }
    
    warn!("DCTPM: unsupported major type {}", major);
    None
}

/// Read FDO device credential GUID from TPM NV (DCTPM index).
/// Convenience wrapper around read_fdo_credentials() for callers that
/// only need the GUID.
pub fn read_fdo_guid() -> Option<[u8; 16]> {
    read_fdo_credentials().map(|c| c.guid)
}

/// RV variable IDs (per FDO spec RendezvousVariable)
const RV_IP_ADDRESS: u8 = 2;
const RV_DEV_PORT: u8 = 3;
const RV_DNS: u8 = 5;
const RV_PROTOCOL: u8 = 12;

/// RV protocol values
const RV_PROT_HTTP: u8 = 1;
const RV_PROT_HTTPS: u8 = 2;

/// Read FDO RV info from TPM NV (DCTPM index)
/// Parses the DCTPM credential stored by DI and extracts the rendezvous URL.
///
/// DCTPM layout (CBOR map with integer keys):
///   0: Magic, 1: Active, 2: Version, 3: DeviceInfo, 4: GUID,
///   5: RvInfo (array of arrays of [variable, value] pairs),
///   6: PubKeyHash, 7: KeyType, 8: DeviceKeyHandle, 9: HMACKeyHandle
///
/// Each RvInstruction is a 2-element CBOR array: [variable_id, value_bytes].
/// We extract DNS/IP, DevPort, and Protocol to build a URL.
pub fn read_fdo_rv_info() -> Option<alloc::string::String> {
    use alloc::string::String;
    use alloc::format;

    // Read DCTPM NV data
    let data = match tpm_nv_read(FDO_NV_INDEX_ALT) {
        Some(d) => d,
        None => {
            info!("RV: No DCTPM found in NV");
            return None;
        }
    };
    info!("RV: DCTPM data: {} bytes", data.len());

    if data.is_empty() {
        return None;
    }

    let mut pos = 0;
    let initial = data[pos];
    pos += 1;

    let major = initial >> 5;
    let additional = initial & 0x1f;

    let num_items = if additional < 24 {
        additional as usize
    } else if additional == 24 && pos < data.len() {
        let n = data[pos] as usize;
        pos += 1;
        n
    } else {
        warn!("RV: unsupported CBOR size encoding");
        return None;
    };

    if major == 4 {
        // CBOR array — RvInfo is at index 5
        info!("RV: CBOR array with {} items", num_items);
        if num_items < 6 {
            warn!("RV: array too short for RvInfo at index 5");
            return None;
        }
        // Skip items 0–4 to get to index 5
        for idx in 0..5 {
            if !skip_cbor_value(&data, &mut pos) {
                warn!("RV: failed to skip item {}", idx);
                return None;
            }
        }
        // pos now points to RvInfo
        return parse_rv_info_at(&data, &mut pos);
    } else if major == 5 {
        // CBOR map — find key 5
        info!("RV: CBOR map with {} pairs", num_items);
        for _ in 0..num_items {
            if pos >= data.len() {
                break;
            }
            // Read key
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

            if key == 5 {
                return parse_rv_info_at(&data, &mut pos);
            } else {
                if !skip_cbor_value(&data, &mut pos) {
                    return None;
                }
            }
        }
        warn!("RV: key 5 (RvInfo) not found in map");
    }

    None
}

/// Parse RvInfo at the current position in `data`.
/// RvInfo is an array of directives, each directive is an array of RvInstructions.
/// Each RvInstruction is [variable_id, value_bytes].
/// Returns the first successfully parsed URL.
fn parse_rv_info_at(data: &[u8], pos: &mut usize) -> Option<alloc::string::String> {
    use alloc::string::String;
    use alloc::format;

    if *pos >= data.len() {
        return None;
    }

    // RvInfo may be either a bare CBOR array or bstr-wrapped (the server
    // encodes it as a CBOR byte string containing the CBOR array).
    // Unwrap bstr if present, then parse the inner array.
    let outer_initial = data[*pos];
    let outer_major = outer_initial >> 5;
    let (rv_data, mut inner_pos) = if outer_major == 2 {
        // bstr-wrapped: read the byte string, then parse its contents
        let bstr = read_cbor_bstr(data, pos)?;
        info!("RV: RvInfo is bstr-wrapped ({} bytes), unwrapping...", bstr.len());
        (bstr.to_vec(), 0usize)
    } else {
        // Direct array — copy and use from current position
        (data.to_vec(), *pos)
    };
    let rv_ref = &rv_data[..];

    let arr_initial = rv_ref[inner_pos];
    inner_pos += 1;
    let arr_major = arr_initial >> 5;
    if arr_major != 4 {
        warn!("RV: RvInfo should be array, got major {}", arr_major);
        return None;
    }
    let outer_len = read_cbor_uint_arg(rv_ref, &mut inner_pos, arr_initial & 0x1f)?;
    // Update pos to point past the bstr (for bstr case, already done by read_cbor_bstr)
    // For the direct case, we'll update pos at the end via inner_pos.
    let pos = &mut inner_pos;
    info!("RV: RvInfo has {} directive(s)", outer_len);

    for dir_idx in 0..outer_len {
        // Each directive is an array of RvInstructions
        if *pos >= rv_ref.len() {
            break;
        }
        let dir_initial = rv_ref[*pos];
        *pos += 1;
        let dir_major = dir_initial >> 5;
        if dir_major != 4 {
            warn!("RV: directive {} should be array", dir_idx);
            skip_cbor_value(rv_ref, pos);
            continue;
        }
        let dir_len = match read_cbor_uint_arg(rv_ref, pos, dir_initial & 0x1f) {
            Some(n) => n,
            None => continue,
        };

        let mut dns_name: Option<String> = None;
        let mut ip_addr: Option<[u8; 4]> = None;
        let mut port: u16 = 8080;
        let mut scheme = "http";

        for _ in 0..dir_len {
            // Each RvInstruction is [variable, value]
            if *pos >= rv_ref.len() {
                break;
            }
            let instr_initial = rv_ref[*pos];
            *pos += 1;
            let instr_major = instr_initial >> 5;
            if instr_major != 4 {
                // Not an array — skip
                skip_cbor_value(rv_ref, pos);
                continue;
            }
            let instr_len = match read_cbor_uint_arg(rv_ref, pos, instr_initial & 0x1f) {
                Some(n) => n,
                None => continue,
            };
            if instr_len < 2 {
                // Skip malformed instruction
                for _ in 0..instr_len {
                    skip_cbor_value(rv_ref, pos);
                }
                continue;
            }

            // Read variable ID (unsigned int)
            let var_id = read_cbor_small_uint(rv_ref, pos).unwrap_or(255) as u8;

            // Read value (byte string — CBOR-encoded content)
            let value_bytes = read_cbor_bstr(rv_ref, pos);
            info!("RV: instruction var_id={}, value={:?}", var_id,
                  value_bytes.as_ref().map(|v| &v[..core::cmp::min(v.len(), 20)]));

            // Skip any extra fields beyond the first 2
            for _ in 2..instr_len {
                skip_cbor_value(rv_ref, pos);
            }

            let value_bytes = match value_bytes {
                Some(v) => v,
                None => continue,
            };

            match var_id {
                RV_DNS => {
                    // Value is CBOR text string
                    if let Some(s) = decode_cbor_text(&value_bytes) {
                        info!("RV: DNS = {}", s);
                        dns_name = Some(s);
                    }
                }
                RV_IP_ADDRESS => {
                    // Value is CBOR byte string: 4 bytes (IPv4), 16 bytes
                    // (IPv4-mapped IPv6 — Go's net.IP is always 16 bytes),
                    // or 5 bytes (family byte + IPv4).
                    if let Some(ip_bytes) = decode_cbor_bstr(&value_bytes) {
                        let mut ip = [0u8; 4];
                        if ip_bytes.len() == 4 {
                            ip.copy_from_slice(&ip_bytes);
                            info!("RV: IP = {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
                            ip_addr = Some(ip);
                        } else if ip_bytes.len() == 16 {
                            // IPv4-mapped IPv6: last 4 bytes are IPv4
                            ip.copy_from_slice(&ip_bytes[12..16]);
                            info!("RV: IP (v4-mapped) = {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
                            ip_addr = Some(ip);
                        } else if ip_bytes.len() == 5 {
                            // Family byte + IPv4
                            ip.copy_from_slice(&ip_bytes[1..5]);
                            info!("RV: IP = {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
                            ip_addr = Some(ip);
                        } else {
                            info!("RV: IP address has unexpected length {}", ip_bytes.len());
                        }
                    }
                }
                RV_DEV_PORT => {
                    // Value is CBOR uint16
                    if let Some(p) = decode_cbor_uint(&value_bytes) {
                        info!("RV: DevPort = {}", p);
                        port = p as u16;
                    }
                }
                RV_PROTOCOL => {
                    // Value is CBOR uint8
                    if let Some(p) = decode_cbor_uint(&value_bytes) {
                        match p as u8 {
                            RV_PROT_HTTP => scheme = "http",
                            RV_PROT_HTTPS => scheme = "https",
                            other => info!("RV: unsupported protocol {}", other),
                        }
                    }
                }
                _ => {
                    // Ignore other RV variables (RVOwnerOnly, RVBypass, etc.)
                }
            }
        }

        // Build URL from parsed directive
        if let Some(ref dns) = dns_name {
            let url = format!("{}://{}:{}", scheme, dns, port);
            info!("RV: Resolved URL: {}", url);
            return Some(url);
        }
        if let Some(ip) = ip_addr {
            let url = format!("{}://{}.{}.{}.{}:{}", scheme, ip[0], ip[1], ip[2], ip[3], port);
            info!("RV: Resolved URL: {}", url);
            return Some(url);
        }
    }

    warn!("RV: No usable RV directive found");
    None
}

/// Read a CBOR uint argument given the additional info byte.
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
    } else {
        None
    }
}

/// Read a small unsigned integer from CBOR at pos.
fn read_cbor_small_uint(data: &[u8], pos: &mut usize) -> Option<usize> {
    if *pos >= data.len() {
        return None;
    }
    let b = data[*pos];
    *pos += 1;
    let major = b >> 5;
    if major != 0 {
        return None; // Not an unsigned int
    }
    read_cbor_uint_arg(data, pos, b & 0x1f)
}

/// Decode a CBOR text string from raw bytes.
fn decode_cbor_text(data: &[u8]) -> Option<alloc::string::String> {
    if data.is_empty() {
        return None;
    }
    let mut pos = 0;
    let b = data[pos];
    pos += 1;
    if (b >> 5) != 3 {
        return None; // Not text
    }
    let len = read_cbor_uint_arg(data, &mut pos, b & 0x1f)?;
    if pos + len > data.len() {
        return None;
    }
    core::str::from_utf8(&data[pos..pos + len])
        .ok()
        .map(alloc::string::String::from)
}

/// Decode a CBOR byte string from raw bytes.
fn decode_cbor_bstr(data: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    if data.is_empty() {
        return None;
    }
    let mut pos = 0;
    let b = data[pos];
    pos += 1;
    if (b >> 5) != 2 {
        return None; // Not bstr
    }
    let len = read_cbor_uint_arg(data, &mut pos, b & 0x1f)?;
    if pos + len > data.len() {
        return None;
    }
    Some(data[pos..pos + len].to_vec())
}

/// Decode a CBOR unsigned integer from raw bytes.
fn decode_cbor_uint(data: &[u8]) -> Option<usize> {
    if data.is_empty() {
        return None;
    }
    let mut pos = 0;
    read_cbor_small_uint(data, &mut pos)
}

/// Check if TPM (TCG2 protocol) is available in this UEFI environment
pub fn tpm_is_present() -> bool {
    match boot::get_handle_for_protocol::<Tcg>() {
        Ok(_) => true,
        Err(_) => false,
    }
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

// ============================================================================
// DI Protocol TPM Functions
// ============================================================================

/// TPM2 command codes for DI
const TPM2_CC_CREATE: u32 = 0x00000153;
const TPM2_CC_LOAD: u32 = 0x00000157;
const TPM2_CC_EVICT_CONTROL: u32 = 0x00000120;
const TPM2_CC_NV_DEFINE_SPACE: u32 = 0x0000012A;
const TPM2_CC_NV_WRITE: u32 = 0x00000137;
const TPM2_CC_HMAC: u32 = 0x00000155;

/// TPM2 algorithm for HMAC
const TPM2_ALG_KEYEDHASH: u16 = 0x0008;
const TPM2_ALG_HMAC_ALG: u16 = 0x0005;

/// Signing key result from TPM
pub struct TpmSigningKey {
    pub handle: u32,
    pub public_x: Vec<u8>,
    pub public_y: Vec<u8>,
}

/// Create an ECDSA signing key (P-256) in TPM and persist it.
/// Creates the key and runs EvictControl in the SAME TCG2 session so the
/// transient handle isn't flushed by the UEFI resource manager.
/// If a stale key exists at persistent_handle, it is evicted first.
pub fn tpm_create_and_persist_signing_key(persistent_handle: u32) -> Option<TpmSigningKey> {
    info!("TPM: tpm_create_and_persist_signing_key(0x{:08x})", persistent_handle);
    let tcg_handle = match boot::get_handle_for_protocol::<Tcg>() {
        Ok(h) => { info!("TPM: got TCG handle"); h }
        Err(e) => { error!("TPM: get_handle_for_protocol failed: {:?}", e); return None; }
    };
    let mut tcg = match boot::open_protocol_exclusive::<Tcg>(tcg_handle) {
        Ok(t) => { info!("TPM: opened TCG protocol"); t }
        Err(e) => { error!("TPM: open_protocol_exclusive failed: {:?}", e); return None; }
    };
    
    // Step 0: Evict any stale key at the persistent handle
    let evict_cmd = build_evict_control_cmd(persistent_handle, persistent_handle);
    let mut evict_resp = vec![0u8; 64];
    if tcg.submit_command(&evict_cmd, &mut evict_resp).is_ok() {
        let rc = unpack_u32(&evict_resp[6..10]);
        if rc == 0 {
            info!("TPM: Evicted stale key at 0x{:08x}", persistent_handle);
        } else {
            info!("TPM: No stale key at 0x{:08x} (rc=0x{:08x})", persistent_handle, rc);
        }
    }
    
    // Step 1: CreatePrimary signing key
    let cmd = build_create_primary_signing_cmd();
    let mut response = vec![0u8; 1024];
    
    info!("TPM: Creating signing key ({} byte cmd)...", cmd.len());
    let result = tcg.submit_command(&cmd, &mut response);
    
    if result.is_err() {
        warn!("TPM2_CreatePrimary (signing) UEFI submit failed: {:?}", result.err());
        return None;
    }
    
    if response.len() < 10 {
        warn!("TPM2_CreatePrimary response too short: {} bytes", response.len());
        return None;
    }
    
    let rc = unpack_u32(&response[6..10]);
    info!("TPM2_CreatePrimary response: rc=0x{:08x}, resp_len={}", rc, unpack_u32(&response[2..6]));
    if rc != 0 {
        warn!("TPM2_CreatePrimary error code: 0x{:08x}", rc);
        return None;
    }
    
    let key_pair = parse_create_primary_response(&response)?;
    let transient_handle = key_pair.handle;
    info!("TPM: Signing key created: transient=0x{:08x}", transient_handle);
    
    // Step 2: EvictControl to persist the transient handle (same session!)
    let persist_cmd = build_evict_control_cmd(transient_handle, persistent_handle);
    let mut persist_resp = vec![0u8; 64];
    
    let mut persisted = false;
    for attempt in 0..5 {
        let mut resp = vec![0u8; 64];
        if tcg.submit_command(&persist_cmd, &mut resp).is_err() {
            warn!("TPM: EvictControl submit failed (attempt {})", attempt);
            boot::stall(core::time::Duration::from_millis(200));
            continue;
        }
        let rc = unpack_u32(&resp[6..10]);
        info!("TPM: EvictControl(0x{:08x}->0x{:08x}) rc=0x{:08x} (attempt {})", 
              transient_handle, persistent_handle, rc, attempt);
        if rc == 0x922 {
            boot::stall(core::time::Duration::from_millis(200));
            continue;
        }
        if rc == 0 {
            persisted = true;
            break;
        }
        warn!("TPM: EvictControl error: 0x{:08x}", rc);
        break;
    }
    
    if !persisted {
        warn!("TPM: Failed to persist signing key at 0x{:08x}", persistent_handle);
        return None;
    }
    
    info!("TPM: Signing key persisted at 0x{:08x}", persistent_handle);
    Some(TpmSigningKey {
        handle: persistent_handle,
        public_x: key_pair.public_x,
        public_y: key_pair.public_y,
    })
}

/// Build TPM2_CreatePrimary command for ECDSA signing key (P-256)
fn build_create_primary_signing_cmd() -> Vec<u8> {
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
    
    // inPublic (TPMT_PUBLIC for ECC signing key)
    let in_public_start = cmd.len();
    cmd.extend_from_slice(&[0, 0]); // size placeholder
    
    // type = TPM_ALG_ECC
    let mut alg = [0u8; 2];
    pack_u16(&mut alg, TPM2_ALG_ECC);
    cmd.extend_from_slice(&alg);
    
    // nameAlg = TPM_ALG_SHA256
    pack_u16(&mut alg, TPM2_ALG_SHA256);
    cmd.extend_from_slice(&alg);
    
    // objectAttributes: fixedTPM | fixedParent | sensitivedataOrigin | userWithAuth | sign
    // 0x00040472
    cmd.extend_from_slice(&[0x00, 0x04, 0x04, 0x72]);
    
    // authPolicy (empty)
    cmd.extend_from_slice(&[0, 0]);
    
    // parameters.eccDetail
    // symmetric = TPM_ALG_NULL
    pack_u16(&mut alg, TPM2_ALG_NULL);
    cmd.extend_from_slice(&alg);
    
    // scheme = TPM_ALG_ECDSA
    pack_u16(&mut alg, TPM2_ALG_ECDSA);
    cmd.extend_from_slice(&alg);
    
    // scheme.details.ecdsa.hashAlg = TPM_ALG_SHA256
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

/// Create an HMAC key in TPM, compute HMAC over data, and persist the key.
/// All done in a single TCG2 session because the UEFI firmware's
/// resource manager flushes transient handles when the protocol is closed.
/// If a stale key exists at persistent_handle, it is evicted first.
pub fn tpm_create_hmac_and_persist(data: &[u8], persistent_handle: u32) -> Option<(u32, Vec<u8>)> {
    info!("TPM: tpm_create_hmac_and_persist() data_len={}, persist=0x{:08x}", data.len(), persistent_handle);
    let tcg_handle = boot::get_handle_for_protocol::<Tcg>().ok()?;
    let mut tcg = boot::open_protocol_exclusive::<Tcg>(tcg_handle).ok()?;
    
    // Step 0: Evict any stale key at the persistent handle
    let evict_cmd = build_evict_control_cmd(persistent_handle, persistent_handle);
    let mut evict_resp = vec![0u8; 64];
    if tcg.submit_command(&evict_cmd, &mut evict_resp).is_ok() {
        let rc = unpack_u32(&evict_resp[6..10]);
        if rc == 0 {
            info!("TPM: Evicted stale HMAC key at 0x{:08x}", persistent_handle);
        } else {
            info!("TPM: No stale HMAC key at 0x{:08x} (rc=0x{:08x})", persistent_handle, rc);
        }
    }
    
    // Step 1: CreatePrimary HMAC key
    let cmd = build_create_primary_hmac_cmd();
    let mut response = vec![0u8; 512];
    
    info!("TPM: Creating HMAC key...");
    let result = tcg.submit_command(&cmd, &mut response);
    
    if result.is_err() {
        warn!("TPM2_CreatePrimary (HMAC) failed");
        return None;
    }
    
    if response.len() < 14 {
        return None;
    }
    
    let response_code = unpack_u32(&response[6..10]);
    if response_code != 0 {
        warn!("TPM2_CreatePrimary (HMAC) error: 0x{:08x}", response_code);
        return None;
    }
    
    let hmac_handle = unpack_u32(&response[10..14]);
    info!("TPM: HMAC key created: transient=0x{:08x}", hmac_handle);
    
    // Step 2: Compute HMAC using the key (same TCG2 session — handle is still valid)
    let hmac_cmd = build_hmac_cmd(hmac_handle, data);
    info!("TPM: HMAC command: {} bytes, header+auth: {:02x?}", hmac_cmd.len(), &hmac_cmd[..hmac_cmd.len().min(30)]);
    
    let mut hmac_value = None;
    for attempt in 0..5 {
        let mut hmac_response = vec![0u8; 256];
        
        let result = tcg.submit_command(&hmac_cmd, &mut hmac_response);
        if result.is_err() {
            warn!("TPM2_HMAC submit_command failed (attempt {})", attempt);
            boot::stall(core::time::Duration::from_millis(100));
            continue;
        }
        
        let rc = unpack_u32(&hmac_response[6..10]);
        if rc == 0x922 {
            info!("TPM: HMAC got TPM_RC_RETRY (0x922), attempt {}, retrying after delay...", attempt);
            boot::stall(core::time::Duration::from_millis(200));
            continue;
        }
        
        info!("TPM: HMAC response first 14: {:02x?}", &hmac_response[..14]);
        hmac_value = parse_hmac_response(&hmac_response);
        break;
    }
    
    let hmac_value = match hmac_value {
        Some(v) => v,
        None => {
            warn!("TPM2_HMAC failed after all retries");
            return None;
        }
    };
    
    // Step 3: EvictControl to persist the HMAC key (same session!)
    let persist_cmd = build_evict_control_cmd(hmac_handle, persistent_handle);
    
    let mut persisted = false;
    for attempt in 0..5 {
        let mut resp = vec![0u8; 64];
        if tcg.submit_command(&persist_cmd, &mut resp).is_err() {
            warn!("TPM: EvictControl (HMAC) submit failed (attempt {})", attempt);
            boot::stall(core::time::Duration::from_millis(200));
            continue;
        }
        let rc = unpack_u32(&resp[6..10]);
        info!("TPM: EvictControl HMAC(0x{:08x}->0x{:08x}) rc=0x{:08x} (attempt {})",
              hmac_handle, persistent_handle, rc, attempt);
        if rc == 0x922 {
            boot::stall(core::time::Duration::from_millis(200));
            continue;
        }
        if rc == 0 {
            persisted = true;
            break;
        }
        warn!("TPM: EvictControl (HMAC) error: 0x{:08x}", rc);
        break;
    }
    
    if !persisted {
        warn!("TPM: Failed to persist HMAC key at 0x{:08x}", persistent_handle);
        // Still return the HMAC value - DI can continue, just key won't be persistent
    } else {
        info!("TPM: HMAC key persisted at 0x{:08x}", persistent_handle);
    }
    
    Some((persistent_handle, hmac_value))
}

/// Build TPM2_CreatePrimary command for HMAC key
fn build_create_primary_hmac_cmd() -> Vec<u8> {
    let mut cmd = Vec::with_capacity(128);
    
    // Header placeholder
    cmd.extend_from_slice(&[0u8; 10]);
    pack_u16(&mut cmd[0..2], TPM2_ST_SESSIONS);
    pack_u32(&mut cmd[6..10], TPM2_CC_CREATE_PRIMARY);
    
    // primaryHandle = TPM_RH_OWNER (Owner Hierarchy has empty auth on real hardware)
    // go-fdo uses TPM_RH_ENDORSEMENT but that requires policy auth on real TPMs
    let mut handle_bytes = [0u8; 4];
    pack_u32(&mut handle_bytes, 0x40000001); // TPM_RH_OWNER
    cmd.extend_from_slice(&handle_bytes);
    
    // Authorization area
    let auth_area_start = cmd.len();
    cmd.extend_from_slice(&[0u8; 4]);
    
    let mut session_handle = [0u8; 4];
    pack_u32(&mut session_handle, TPM2_RS_PW);
    cmd.extend_from_slice(&session_handle);
    cmd.extend_from_slice(&[0, 0]);
    cmd.push(0);
    cmd.extend_from_slice(&[0, 0]);
    
    let auth_size = (cmd.len() - auth_area_start - 4) as u32;
    pack_u32(&mut cmd[auth_area_start..auth_area_start+4], auth_size);
    
    // inSensitive - empty
    cmd.extend_from_slice(&[0, 4]);
    cmd.extend_from_slice(&[0, 0]);
    cmd.extend_from_slice(&[0, 0]);
    
    // inPublic for KEYEDHASH (HMAC)
    let in_public_start = cmd.len();
    cmd.extend_from_slice(&[0, 0]);
    
    // type = TPM_ALG_KEYEDHASH
    let mut alg = [0u8; 2];
    pack_u16(&mut alg, TPM2_ALG_KEYEDHASH);
    cmd.extend_from_slice(&alg);
    
    // nameAlg = SHA256
    pack_u16(&mut alg, TPM2_ALG_SHA256);
    cmd.extend_from_slice(&alg);
    
    // objectAttributes: fixedTPM | fixedParent | sensitivedataOrigin | userWithAuth | adminWithPolicy | sign
    // 0x000400F2 (per FDO TPM spec Table 11: adminWithPolicy only affects admin ops, not user ops like HMAC)
    cmd.extend_from_slice(&[0x00, 0x04, 0x00, 0xF2]);
    
    // authPolicy (empty)
    cmd.extend_from_slice(&[0, 0]);
    
    // parameters.keyedHashDetail
    // scheme = TPM_ALG_HMAC
    pack_u16(&mut alg, TPM2_ALG_HMAC_ALG);
    cmd.extend_from_slice(&alg);
    
    // hashAlg = SHA256
    pack_u16(&mut alg, TPM2_ALG_SHA256);
    cmd.extend_from_slice(&alg);
    
    // unique (empty)
    cmd.extend_from_slice(&[0, 0]);
    
    // Update inPublic size
    let in_public_size = (cmd.len() - in_public_start - 2) as u16;
    pack_u16(&mut cmd[in_public_start..in_public_start+2], in_public_size);
    
    // outsideInfo (empty)
    cmd.extend_from_slice(&[0, 0]);
    
    // creationPCR (empty)
    cmd.extend_from_slice(&[0, 0, 0, 0]);
    
    let cmd_len = cmd.len() as u32;
    pack_u32(&mut cmd[2..6], cmd_len);
    
    cmd
}

/// Compute HMAC using TPM key
pub fn tpm_hmac(key_handle: u32, data: &[u8]) -> Option<Vec<u8>> {
    info!("TPM: tpm_hmac() handle=0x{:08x}, data_len={}", key_handle, data.len());
    let tcg_handle = match boot::get_handle_for_protocol::<Tcg>() {
        Ok(h) => h,
        Err(e) => {
            error!("TPM: HMAC: get_handle_for_protocol failed: {:?}", e);
            return None;
        }
    };
    let mut tcg = match boot::open_protocol_exclusive::<Tcg>(tcg_handle) {
        Ok(t) => t,
        Err(e) => {
            error!("TPM: HMAC: open_protocol_exclusive failed: {:?}", e);
            return None;
        }
    };
    
    let cmd = build_hmac_cmd(key_handle, data);
    info!("TPM: HMAC command: {} bytes, first 20: {:02x?}", cmd.len(), &cmd[..cmd.len().min(20)]);
    let mut response = vec![0u8; 256];
    
    let result = tcg.submit_command(&cmd, &mut response);
    if result.is_err() {
        warn!("TPM2_HMAC submit_command failed");
        return None;
    }
    
    info!("TPM: HMAC response first 14: {:02x?}", &response[..14]);
    parse_hmac_response(&response)
}

/// Build TPM2_HMAC command
fn build_hmac_cmd(key_handle: u32, data: &[u8]) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(data.len() + 64);
    
    // Header
    cmd.extend_from_slice(&[0u8; 10]);
    pack_u16(&mut cmd[0..2], TPM2_ST_SESSIONS);
    pack_u32(&mut cmd[6..10], TPM2_CC_HMAC);
    
    // handle
    let mut handle_bytes = [0u8; 4];
    pack_u32(&mut handle_bytes, key_handle);
    cmd.extend_from_slice(&handle_bytes);
    
    // Auth area
    let auth_start = cmd.len();
    cmd.extend_from_slice(&[0u8; 4]);
    pack_u32(&mut handle_bytes, TPM2_RS_PW);
    cmd.extend_from_slice(&handle_bytes);
    cmd.extend_from_slice(&[0, 0, 0, 0, 0]);
    let auth_size = (cmd.len() - auth_start - 4) as u32;
    pack_u32(&mut cmd[auth_start..auth_start+4], auth_size);
    
    // buffer (TPM2B_MAX_BUFFER)
    let mut size_bytes = [0u8; 2];
    pack_u16(&mut size_bytes, data.len() as u16);
    cmd.extend_from_slice(&size_bytes);
    cmd.extend_from_slice(data);
    
    // hashAlg = SHA256
    let mut alg = [0u8; 2];
    pack_u16(&mut alg, TPM2_ALG_SHA256);
    cmd.extend_from_slice(&alg);
    
    let cmd_len = cmd.len() as u32;
    pack_u32(&mut cmd[2..6], cmd_len);
    
    cmd
}

/// Parse TPM2_HMAC response
fn parse_hmac_response(response: &[u8]) -> Option<Vec<u8>> {
    if response.len() < 14 {
        return None;
    }
    
    let response_code = unpack_u32(&response[6..10]);
    if response_code != 0 {
        warn!("TPM2_HMAC error: 0x{:08x}", response_code);
        return None;
    }
    
    // Skip parameterSize
    let mut pos = 14;
    
    // TPM2B_DIGEST
    if response.len() < pos + 2 {
        return None;
    }
    let size = unpack_u16(&response[pos..pos+2]) as usize;
    pos += 2;
    
    if response.len() < pos + size {
        return None;
    }
    
    Some(response[pos..pos+size].to_vec())
}

/// Sign a digest using ECDSA with specified handle
pub fn tpm_sign_ecdsa(key_handle: u32, digest: &[u8]) -> Option<Vec<u8>> {
    let tcg_handle = boot::get_handle_for_protocol::<Tcg>().ok()?;
    let mut tcg = boot::open_protocol_exclusive::<Tcg>(tcg_handle).ok()?;
    
    let cmd = build_sign_cmd(key_handle, digest);
    let mut response = vec![0u8; 256];
    
    let result = tcg.submit_command(&cmd, &mut response);
    if result.is_err() {
        warn!("TPM2_Sign failed");
        return None;
    }
    
    let (r, s) = parse_sign_response(&response)?;
    
    // Concatenate r || s, padding to 32 bytes each for P-256
    let mut sig = vec![0u8; 64];
    let r_offset = 32 - r.len().min(32);
    sig[r_offset..32].copy_from_slice(&r[r.len().saturating_sub(32)..]);
    let s_offset = 64 - s.len().min(32);
    sig[s_offset..64].copy_from_slice(&s[s.len().saturating_sub(32)..]);
    
    Some(sig)
}

/// Persist a transient object to a permanent handle
pub fn tpm_evict_control(transient_handle: u32, persistent_handle: u32) -> bool {
    let tcg_handle = match boot::get_handle_for_protocol::<Tcg>() {
        Ok(h) => h,
        Err(_) => return false,
    };
    let mut tcg = match boot::open_protocol_exclusive::<Tcg>(tcg_handle) {
        Ok(t) => t,
        Err(_) => return false,
    };
    
    let cmd = build_evict_control_cmd(transient_handle, persistent_handle);
    let mut response = vec![0u8; 64];
    
    if tcg.submit_command(&cmd, &mut response).is_err() {
        return false;
    }
    
    if response.len() < 10 {
        return false;
    }
    
    let response_code = unpack_u32(&response[6..10]);
    if response_code != 0 {
        warn!("TPM2_EvictControl error: 0x{:08x}", response_code);
        return false;
    }
    
    true
}

/// Build TPM2_EvictControl command
fn build_evict_control_cmd(object_handle: u32, persistent_handle: u32) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(64);
    
    cmd.extend_from_slice(&[0u8; 10]);
    pack_u16(&mut cmd[0..2], TPM2_ST_SESSIONS);
    pack_u32(&mut cmd[6..10], TPM2_CC_EVICT_CONTROL);
    
    // auth = TPM_RH_OWNER
    let mut handle_bytes = [0u8; 4];
    pack_u32(&mut handle_bytes, TPM2_RH_OWNER);
    cmd.extend_from_slice(&handle_bytes);
    
    // objectHandle
    pack_u32(&mut handle_bytes, object_handle);
    cmd.extend_from_slice(&handle_bytes);
    
    // Auth area
    let auth_start = cmd.len();
    cmd.extend_from_slice(&[0u8; 4]);
    pack_u32(&mut handle_bytes, TPM2_RS_PW);
    cmd.extend_from_slice(&handle_bytes);
    cmd.extend_from_slice(&[0, 0, 0, 0, 0]);
    let auth_size = (cmd.len() - auth_start - 4) as u32;
    pack_u32(&mut cmd[auth_start..auth_start+4], auth_size);
    
    // persistentHandle
    pack_u32(&mut handle_bytes, persistent_handle);
    cmd.extend_from_slice(&handle_bytes);
    
    let cmd_len = cmd.len() as u32;
    pack_u32(&mut cmd[2..6], cmd_len);
    
    cmd
}

/// Write data to TPM NV index (defines space if needed)
pub fn tpm_nv_write(nv_index: u32, data: &[u8]) -> bool {
    let tcg_handle = match boot::get_handle_for_protocol::<Tcg>() {
        Ok(h) => h,
        Err(_) => return false,
    };
    let mut tcg = match boot::open_protocol_exclusive::<Tcg>(tcg_handle) {
        Ok(t) => t,
        Err(_) => return false,
    };
    
    // First try to define the NV space (with retry for TPM_RC_RETRY)
    let define_cmd = build_nv_define_space_cmd(nv_index, data.len() as u16);
    info!("NV DefineSpace cmd ({} bytes) for index 0x{:08x}, size={}", define_cmd.len(), nv_index, data.len());
    
    let mut define_ok = false;
    for attempt in 0..5 {
        let mut response = vec![0u8; 64];
        if tcg.submit_command(&define_cmd, &mut response).is_ok() {
            let rc = unpack_u32(&response[6..10]);
            info!("NV DefineSpace response: rc=0x{:08x} (attempt {})", rc, attempt);
            if rc == 0x922 {
                info!("NV DefineSpace got TPM_RC_RETRY, retrying...");
                boot::stall(core::time::Duration::from_millis(200));
                continue;
            }
            if rc == 0 || rc == 0x0000014c {  // Success or "already exists"
                define_ok = true;
                break;
            }
            warn!("TPM2_NV_DefineSpace error: 0x{:08x}", rc);
            break;
        } else {
            warn!("NV DefineSpace submit_command failed (attempt {})", attempt);
            boot::stall(core::time::Duration::from_millis(200));
        }
    }
    if !define_ok {
        warn!("NV DefineSpace failed for 0x{:08x}", nv_index);
        return false;
    }
    
    // Now write the data (with retry for TPM_RC_RETRY)
    let write_cmd = build_nv_write_cmd(nv_index, data);
    info!("NV Write cmd: {} bytes of data to 0x{:08x}", data.len(), nv_index);
    
    for attempt in 0..5 {
        let mut response = vec![0u8; 64];
        
        if tcg.submit_command(&write_cmd, &mut response).is_err() {
            warn!("NV_Write submit_command failed (attempt {})", attempt);
            boot::stall(core::time::Duration::from_millis(200));
            continue;
        }
        
        if response.len() < 10 {
            warn!("NV_Write response too short");
            return false;
        }
        
        let response_code = unpack_u32(&response[6..10]);
        info!("NV_Write response: rc=0x{:08x} (attempt {})", response_code, attempt);
        
        if response_code == 0x922 {
            info!("NV_Write got TPM_RC_RETRY, retrying...");
            boot::stall(core::time::Duration::from_millis(200));
            continue;
        }
        
        if response_code != 0 {
            warn!("TPM2_NV_Write error: 0x{:08x}", response_code);
            return false;
        }
        
        return true;
    }
    
    warn!("NV_Write failed after all retries");
    false
}

/// Build TPM2_NV_DefineSpace command
fn build_nv_define_space_cmd(nv_index: u32, size: u16) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(64);
    
    cmd.extend_from_slice(&[0u8; 10]);
    pack_u16(&mut cmd[0..2], TPM2_ST_SESSIONS);
    pack_u32(&mut cmd[6..10], TPM2_CC_NV_DEFINE_SPACE);
    
    // authHandle = TPM_RH_OWNER
    let mut handle_bytes = [0u8; 4];
    pack_u32(&mut handle_bytes, TPM2_RH_OWNER);
    cmd.extend_from_slice(&handle_bytes);
    
    // Auth area
    let auth_start = cmd.len();
    cmd.extend_from_slice(&[0u8; 4]);
    pack_u32(&mut handle_bytes, TPM2_RS_PW);
    cmd.extend_from_slice(&handle_bytes);
    cmd.extend_from_slice(&[0, 0, 0, 0, 0]);
    let auth_size = (cmd.len() - auth_start - 4) as u32;
    pack_u32(&mut cmd[auth_start..auth_start+4], auth_size);
    
    // auth (TPM2B_AUTH) - empty
    cmd.extend_from_slice(&[0, 0]);
    
    // publicInfo (TPM2B_NV_PUBLIC)
    let public_start = cmd.len();
    cmd.extend_from_slice(&[0, 0]); // size placeholder
    
    // TPMS_NV_PUBLIC
    pack_u32(&mut handle_bytes, nv_index);
    cmd.extend_from_slice(&handle_bytes);
    
    // nameAlg = SHA256
    let mut alg = [0u8; 2];
    pack_u16(&mut alg, TPM2_ALG_SHA256);
    cmd.extend_from_slice(&alg);
    
    // attributes: JUST ownerwrite | ownerread (absolute minimum)
    // OWNERWRITE (bit 1) = 0x02, OWNERREAD (bit 17) = 0x20000
    // 0x00020002 in big-endian: [0x00, 0x02, 0x00, 0x02]
    cmd.extend_from_slice(&[0x00, 0x02, 0x00, 0x02]);
    
    // authPolicy (empty)
    cmd.extend_from_slice(&[0, 0]);
    
    // dataSize
    let mut size_bytes = [0u8; 2];
    pack_u16(&mut size_bytes, size);
    cmd.extend_from_slice(&size_bytes);
    
    // Update publicInfo size
    let public_size = (cmd.len() - public_start - 2) as u16;
    pack_u16(&mut cmd[public_start..public_start+2], public_size);
    
    let cmd_len = cmd.len() as u32;
    pack_u32(&mut cmd[2..6], cmd_len);
    
    cmd
}

/// Build TPM2_NV_Write command
fn build_nv_write_cmd(nv_index: u32, data: &[u8]) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(data.len() + 64);
    
    cmd.extend_from_slice(&[0u8; 10]);
    pack_u16(&mut cmd[0..2], TPM2_ST_SESSIONS);
    pack_u32(&mut cmd[6..10], TPM2_CC_NV_WRITE);
    
    // authHandle = TPM_RH_OWNER (for OWNERWRITE attribute)
    let mut handle_bytes = [0u8; 4];
    pack_u32(&mut handle_bytes, TPM2_RH_OWNER);
    cmd.extend_from_slice(&handle_bytes);
    
    // nvIndex
    pack_u32(&mut handle_bytes, nv_index);
    cmd.extend_from_slice(&handle_bytes);
    
    // Auth area
    let auth_start = cmd.len();
    cmd.extend_from_slice(&[0u8; 4]);
    pack_u32(&mut handle_bytes, TPM2_RS_PW);
    cmd.extend_from_slice(&handle_bytes);
    cmd.extend_from_slice(&[0, 0, 0, 0, 0]);
    let auth_size = (cmd.len() - auth_start - 4) as u32;
    pack_u32(&mut cmd[auth_start..auth_start+4], auth_size);
    
    // data (TPM2B_MAX_NV_BUFFER)
    let mut size_bytes = [0u8; 2];
    pack_u16(&mut size_bytes, data.len() as u16);
    cmd.extend_from_slice(&size_bytes);
    cmd.extend_from_slice(data);
    
    // offset = 0
    cmd.extend_from_slice(&[0, 0]);
    
    let cmd_len = cmd.len() as u32;
    pack_u32(&mut cmd[2..6], cmd_len);
    
    cmd
}
