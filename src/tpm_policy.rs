// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// FDO TPM spec key template values (securing-fdo-in-tpm.bs Tables 11/12).
// Pure constants so they are unit-tested natively; tpm.rs (UEFI-only) uses
// them to build TPM2_CreatePrimary commands.

/// TPMA_OBJECT bits used by the FDO key templates (TPM 2.0 Part 2, 8.3).
pub const TPMA_FIXED_TPM: u32 = 0x0000_0002;
pub const TPMA_FIXED_PARENT: u32 = 0x0000_0010;
pub const TPMA_SENSITIVE_DATA_ORIGIN: u32 = 0x0000_0020;
pub const TPMA_USER_WITH_AUTH: u32 = 0x0000_0040;
pub const TPMA_ADMIN_WITH_POLICY: u32 = 0x0000_0080;
pub const TPMA_NO_DA: u32 = 0x0000_0400;
pub const TPMA_SIGN_ENCRYPT: u32 = 0x0004_0000;

/// Device key (DAK) and HMAC key objectAttributes, spec Table 11:
/// fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth, adminWithPolicy,
/// noDA, sign.
pub const FDO_KEY_ATTRIBUTES: u32 = TPMA_FIXED_TPM
    | TPMA_FIXED_PARENT
    | TPMA_SENSITIVE_DATA_ORIGIN
    | TPMA_USER_WITH_AUTH
    | TPMA_ADMIN_WITH_POLICY
    | TPMA_NO_DA
    | TPMA_SIGN_ENCRYPT;

/// Device key authPolicy for nameAlg SHA-256, spec Table 12:
/// TPM2_PolicyCommandCode(TPM_CC_Certify) =
/// SHA256(zero digest || TPM_CC_PolicyCommandCode (0x16C) || TPM_CC_Certify (0x148)).
/// Lets any party obtain TPM2_Certify evidence that the key is in this TPM;
/// every other ADMIN-role command (e.g. TPM2_ObjectChangeAuth) fails it.
/// Signing uses the USER role (empty authValue) and never this policy.
/// The HMAC key's authPolicy stays empty.
pub const DEVICE_KEY_AUTH_POLICY_SHA256: [u8; 32] = [
    0x04, 0x8e, 0x9a, 0x3a, 0xce, 0x08, 0x58, 0x3f, 0x79, 0xf3, 0x44, 0xff, 0x78, 0x5b, 0xbe, 0xa9,
    0xf0, 0x7a, 0xc7, 0xfa, 0x33, 0x25, 0xb3, 0xd4, 0x9a, 0x21, 0xdd, 0x51, 0x94, 0xc6, 0x58, 0x50,
];

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn device_key_auth_policy_matches_policy_command_code_certify() {
        let mut h = Sha256::new();
        h.update([0u8; 32]);
        h.update(0x0000_016Cu32.to_be_bytes()); // TPM_CC_PolicyCommandCode
        h.update(0x0000_0148u32.to_be_bytes()); // TPM_CC_Certify
        assert_eq!(h.finalize().as_slice(), &DEVICE_KEY_AUTH_POLICY_SHA256);
    }

    #[test]
    fn fdo_key_attributes_value() {
        // Previously: DAK 0x00040472 (no adminWithPolicy), HMAC 0x000400F2 (no noDA).
        assert_eq!(FDO_KEY_ATTRIBUTES, 0x0004_04F2);
    }
}
