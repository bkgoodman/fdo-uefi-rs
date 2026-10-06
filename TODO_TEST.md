<!-- Copyright 2026 Dell Technologies, All Rights Reserved -->
<!-- Author: Brad Goodman <bradley.goodman@dell.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# System Test Coverage (all projects) — 2026-10-07

What is exercised end to end across go-fdo, fdo-uefi-rs and
fido-device-onboard-rs after the FDO 2.0 Errata 1 / spec-drift work, and
what is deliberately **not** tested yet.

## Tested

| Area | How | Result (2026-10-07) |
| --- | --- | --- |
| go-fdo unit tests (base, FSIM, sqlite, TPM, examples) | `go test` | pass |
| go-fdo integration (DI/TO0/TO1/TO2 at 1.1 and 2.0, delegates, FSIMs, BMO incl. multi-parameter `set`) | `./test_examples.sh all` | 52 pass (RV blob skipped by design) |
| go-fdo lint | `make lint` | clean except 4 pre-existing findings in `examples/cmd/server.go` |
| fdo-uefi-rs native unit tests | `make test` | 256 pass |
| fdo-uefi-rs ↔ go-fdo, TO1/TO2 crypto verification (QEMU + swtpm) | `start5-verify.sh` | pass |
| Negative: corrupted to1d (33), ProveOVHdr20 (83), OVNextEntry20 (85), plus control (99) | `start6-negative.sh` | tampered messages abort TO2; control completes |
| BMO Owner-signed (artifact authority) | `start7-bmo-signed.sh` | signature verified |
| BMO delegate unsigned (PERM.7 accepted, onboard-only refused) | `start8-delegate-unsigned.sh` | pass |
| BMO delegate-signed (x5chain) | `start9-delegate-signed.sh` | artifact verified (script's verdict grep is stale; see below) |
| BMO Owner unsigned (channel authority, Model 1) | `start10-unsigned-reject.sh` | pass |
| BMO wrong-key signature rejected | `start11-signed-negative.sh` | pass |
| Signed `fdo.bmo:set` (multi-parameter) | `start12-signed-set.sh` | pass |
| Scope: unevaluable time/generation rejected; GUID scope | `start13`, `start14` | pass |
| Meta-URL: unsigned+pinned, unsigned-no-hash (negative), signed | `start15-meta-url.sh all` | pass |
| **Chainload of a real EFI app** (Owner-signed BMO → verify → chainload `hello-efi.efi`) | `start7` variant using `~/bkgvm/hello-efi.efi` | "HELLO-EFI: Hello, world!" printed |
| fido-device-onboard-rs ↔ go-fdo (DI, full flow, delegate, 4 BMO modes) | `test_rust_fdo20_interop.sh all` | 7 pass |

Notes on the pe2 scripts:
- `start7`, `start11`–`start14` deliver random bytes as `test.efi`, so their
  chainload step always fails ("Missing MZ header"). They test verification,
  not booting. Chainloading is covered by the `hello-efi.efi` variant above;
  consider making that variant a permanent script.
- `start9` passes functionally but prints no verdict: it greps for
  "delegate-signed artifact verified OK", while the client now logs
  "provisioning artifact verified OK".
- `start6` and `start7` exit 0 regardless of outcome; read their output.
- `/tmp/fdo-negative*` and `/tmp/fdo-bmo-signed*` (and their voucher/firmware
  dirs) on pe2 are root-owned leftovers from 2026-09-30, so `start6` and
  `start7` fail at their first `rm -rf`. They were run from copies using
  different work directories.

## Not tested (deliberately, for now)

- **fido-device-onboard-rs security features that are not implemented**:
  delegate permission checks, signed BMO provisioning, peer authority,
  authentication of fetched content (see that repo's `TODO.md`).
- **BMO on real hardware** (K800): not run since the errata wire-format
  changes; the K800 still has a pre-errata `fdo-uefi.efi`.
- **Full OS installation** (UKI / installer ISO via BMO, `start4.sh`):
  testing stops at chainloading a hello-world EFI app.

---

# Native Unit Test Plan — fdo-uefi-rs

Run with `make test` (no UEFI, no QEMU, no swtpm).

Modeled after go-fdo unit tests (`delegate_test.go`, `voucher_test.go`,
`fsim/bmo_provision_test.go`, `fsim/bmo_cose_verifier_test.go`,
`fsim/bmo_url_test.go`, `fsim/chunking/chunking_test.go`, `cose/sign_test.go`)
and integration scripts (`test_examples.sh`).

## Current Coverage (157 tests)

| Module | Tests | Coverage |
|--------|-------|----------|
| `cose.rs` | 49 | COSE_Sign1 parse/verify, ES256 +/-, domain AAD (v101 vs v200, **different tags not interchangeable**), scope (GUID match/mismatch/array, unknown fields fail closed, **combined fields**, **empty map**, **guid-no-device-guid**, **multiple unknowns fail closed**), BMO Model 3 verify, **BMO no content_type rejected**, **delegate-signed missing PERM.7 rejected**, delegate header detection, malformed inputs |
| `delegate.rs` | 19 | 1/2/3-cert chains, wrong signer, self-signed rejected, empty chain, permission inheritance, redirect-only/onboard-only, reuse-cred vs new-cred, all permissions, EKU flags, DER parsing, ECDSA DER-to-RS |
| `fdo.rs` | 41 | CborEncoder/Decoder roundtrip, all types, AES-GCM roundtrip/wrong key/tampered/**wrong nonce**/**wrong AAD**, KDF (128 vs 256), SHA-256, COSE_Encrypt0 roundtrip/**tampered ciphertext**, **session key derivation** (deterministic + different secrets), message builders, **encrypted message parsing** (wrong tag/no tag/missing IV/empty/truncated), **SetupDevice parsing** (bad nonce/replacement GUID/null GUID) |
| `bmo.rs` | 27 | ServiceInfo KV, image-begin parse, result/ack/set builders, tag 18, signed unwrap, full policy matrix: Model 1/2/3/4, unsigned owner-direct/delegate/legacy, signed correct/wrong key/no key/wrong content-type/tampered, delegate-signed Model 4 (x5chain positive + wrong-owner negative) |
| `voucher.rs` | 20 | OVHeader parse (basic/garbage/too-short), FDO PublicKey (X509/COSE_Key/unsupported), HMAC-SHA-256 (RFC 4231 + wrong key), voucher verify (0/1/2-entry chain), **entries swapped rejected**, **entry from different device rejected**, **wrong domain AAD rejected** (v2.0), **chain break at entry 1**, corrupted sig, wrong signer, hashHdrInfo mismatch, hashPrevEntry mismatch, GUID mismatch |
| `di/mfginfo.rs` | 1 | DeviceMfgInfo encoding |

---

## Tier 1 — Security-Critical (COMPLETE)

### 1a. Delegate permission inheritance through full chain — DONE

**Go source:** `delegate_test.go` lines 176–637

Permissions MUST be checked at every certificate in the chain, not just the
leaf. A leaf cannot elevate permissions beyond its intermediate or root.

**Bug fixed:** OID constants were mislabeled (shifted by one from go-fdo).
Redirect OID was being treated as onboard. Also fixed: `verify_delegate_chain`
now intersects permissions across the entire chain, not just the leaf.

- [x] **Self-signed delegate rejected** (`test_self_signed_delegate_rejected`)
- [x] **3-cert chain valid** (`test_three_cert_chain_valid`)
- [x] **Intermediate missing permission** (`test_intermediate_missing_permission`)
- [x] **Root missing permission** (`test_root_missing_permission`)
- [x] **Redirect-only cannot onboard** (`test_redirect_only_cannot_onboard`)
- [x] **Onboard-only cannot redirect** (`test_onboard_only_cannot_redirect`)
- [x] **Reuse-credential vs new-credential** (`test_new_cred_cannot_reuse`, `test_reuse_cred_implies_onboard`)
- [x] **All permissions** (`test_all_permissions`)

### 1b. Voucher verification — DONE

**Go source:** `voucher_test.go` lines 134–320

- [x] **HMAC-SHA-256 known vector** (RFC 4231 test case 2)
- [x] **HMAC wrong key rejected** (`test_hmac_sha256_wrong_key`)
- [x] **OVHeader parse** basic/garbage/too-short
- [x] **FDO PublicKey parse** X509/COSE_Key/unsupported-type
- [x] **Unextended voucher** (0-entry, mfg key = owner key)
- [x] **1-entry voucher chain** (mfg → owner)
- [x] **2-entry voucher chain** (mfg → reseller → owner)
- [x] **Corrupted entry signature** → `EntrySignatureInvalid`
- [x] **Wrong signing key** → `EntrySignatureInvalid`
- [x] **hashHdrInfo mismatch** → `HeaderHashMismatch`
- [x] **hashPrevEntry mismatch** → `PrevHashMismatch`
- [x] **GUID mismatch** → `GuidMismatch`
- [x] **Entries swapped** (reordering attack) → `EntrySignatureInvalid`
- [x] **Entry from different device** → `HeaderHashMismatch`
- [x] **Wrong domain AAD** (v2.0, BMO tag) → `EntrySignatureInvalid`
- [x] **Chain break at entry 1** (attacker replaces signer) → `EntrySignatureInvalid(1)`

### 1c. BMO unsigned/signed policy matrix — DONE

**Go source:** `fsim/bmo_provision_test.go` lines 41–266

Extracted `check_bmo_authorization()` from UEFI-gated `process_bmo_message()`
to enable pure testing of all 4 security models.

- [x] Model 1: Owner-direct, unsigned → `UnsignedModel1`
- [x] Model 2: Delegate with PERM.7, unsigned → `UnsignedModel2`
- [x] No owner key, unsigned → `UnsignedLegacy`
- [x] Model 3: Owner-signed, correct key → `SignedOk`
- [x] Model 3: Owner-signed, wrong key → `SignedFailed`
- [x] Model 3: Signed, no owner key available → `SignedFailed`
- [x] Signed, wrong content-type → `SignedFailed`
- [x] Signed, tampered signature → `SignedFailed`
- [x] Model 4: Delegate-signed with x5chain → `SignedOk`
- [x] Model 4: Delegate chain not rooted in owner → `SignedFailed`

### 1d. COSE malformed input tests — DONE

**Go source:** `fsim/bmo_cose_verifier_test.go` lines 224–293

- [x] **Empty key bytes** (`test_verify_es256_empty_key`)
- [x] **Garbage key bytes** (`test_verify_es256_garbage_key`)
- [x] **Empty signed payload** (`test_parse_cose_sign1_empty`)
- [x] **Garbage signed payload** (`test_parse_cose_sign1_garbage`)
- [x] **Valid CBOR but not Sign1** (`test_parse_cose_sign1_cbor_not_sign1`)
- [x] **Empty BMO envelope** (`test_verify_bmo_signed_empty_envelope`)
- [x] **Garbage BMO envelope** (`test_verify_bmo_signed_garbage_envelope`)
- [x] **Tampered BMO payload** (`test_verify_bmo_signed_tampered_payload`)
- [x] **Tampered BMO signature** (`test_verify_bmo_signed_tampered_signature`)
- [x] **BMO no content_type** → rejected (`test_verify_bmo_signed_no_content_type`)
- [x] **Delegate-signed BMO missing PERM.7** → rejected (`test_verify_bmo_delegate_signed_missing_perm7`)

---

## Tier 2 — Correctness

### 2a. BMO hash verification

- [ ] **Correct hash passes** — build image-end with SHA-256 hash matching
  accumulated image data; verification succeeds.
- [ ] **Wrong hash rejected** — flip a byte in the expected hash; must reject.
- [ ] **Size mismatch rejected** — total_size in image-begin doesn't match
  actual bytes received; must reject or warn.

### 2b. Chunking message round-trips

**Go source:** `fsim/chunking/chunking_test.go`

- [ ] **Begin message encode/decode** — total_size, hash_alg, require_ack,
  estimated_duration fields roundtrip correctly.
- [ ] **End message encode/decode** — optional hash field.
- [ ] **Result message encode/decode** — status + optional message.
- [ ] **Ack message encode/decode** — accepted bool, optional reason + message.

### 2c. BMO delivery mode and NAK

- [ ] **Supported MIME type accepted** — device supports "application/efi",
  image-begin with that type → accept.
- [ ] **Unsupported MIME type NAKed** — device supports "application/efi",
  image-begin with "application/x-unsupported" → NAK/reject.
- [ ] **Multi-asset preference** — first supported type is selected from an
  ordered list of offered types.

### 2d. COSE known vectors

**Go source:** `cose/sign_test.go` lines 21–105

- [ ] **ES256 known-vector sign/verify** — use the COSE WG example key
  coordinates and external AAD; verify a fixed COSE Sign1 test vector.
- [ ] **Legacy COSE without domain AAD** — verify a legacy proof that was
  signed without AAD succeeds with empty AAD but fails with
  `AAD_TAG_PROVE_OV_HDR`. (Go: `TestSomethingThatFailedSignatureVerification...`)

---

## Tier 3 — Extended Coverage

### 3a. RV firmware metadata

- [ ] **Tags 16/17/18 encode/decode** — firmware URL, path, and min-revision
  round-trip through CBOR.
- [ ] **Anti-rollback enforcement** — generation counter rejects downgrades.

### 3b. Meta-payload

- [ ] **Meta-payload CBOR roundtrip** — URL, MIME, hash, name fields encode
  and decode correctly.
- [ ] **Signed meta-payload verify** — COSE_Sign1 wrapping a MetaPayload;
  verify with correct key, reject with wrong key.
- [ ] **Tampered meta-payload rejected** — flip a byte in signed meta-payload;
  verification MUST fail.

### 3c. Scope edge cases — DONE (fail-closed)

Scope parse/evaluate is tested (combined fields, empty map, fail-closed on
unknowns, `"fdo.scope"` + legacy `"fdo.bmo.scope"`, both-labels rejected).
Since 2026-10-02 the UEFI client **rejects** `not_before`/`not_after`/
`generation` outright — it has no trusted clock and no rollback storage, and
the spec makes unevaluable constraints a MUST-reject. `guid` with no device
GUID is rejected too. Scope is evaluated only after the signature.

- [x] **Unevaluable fields reject, each alone** (`test_scope_each_unevaluable_field_rejects_alone`)
- [x] **Combined guid + time + generation → reject** (`test_scope_combined_fields_all_valid`, inverted)
- [x] **GUID mismatch fails everything** (`test_scope_combined_guid_mismatch_fails_everything`)
- [x] **guid without device GUID → reject** (`test_scope_guid_no_device_guid_rejects`)
- [x] **QEMU**: `start13-bmo-signed-scope.sh` (now NEGATIVE: signature verifies, then scope rejected)
- [ ] If a trusted clock / rollback storage is ever added: expired, not-yet-valid
  and generation-downgrade cases, and accept-within-window.

### 3d. Protocol message tampering — PARTIALLY DONE

Transport-layer tampering (encrypted channel):

- [x] **AES-GCM wrong nonce** → decryption fails (`test_aes_gcm_wrong_nonce_fails`)
- [x] **AES-GCM wrong AAD** → decryption fails (`test_aes_gcm_wrong_aad_fails`)
- [x] **COSE_Encrypt0 tampered ciphertext** → decryption fails (`test_cose_encrypt0_tampered_ciphertext`)
- [x] **Encrypted message wrong/no tag** → rejected (`test_parse_encrypted_message_wrong_tag`, `_no_tag`)
- [x] **Encrypted message missing IV** → rejected (`test_parse_encrypted_message_missing_iv`)

Domain AAD separation (protocol-level):

- [x] **v1.01 proof vs v2.0 AAD** → rejected (`test_domain_aad_v101_vs_v200`)
- [x] **Different AAD tags not interchangeable** (`test_domain_aad_different_tags_not_interchangeable`)
- [x] **Voucher entry with wrong domain AAD** → rejected (`test_verify_voucher_wrong_domain_aad`)

Still needed (requires full protocol harness, better tested via integration/QEMU):

- [ ] **Corrupted ProveOVHdr signature** — tested via `start6-negative.sh 83`
- [ ] **Corrupted OVNextEntry signature** — tested via `start6-negative.sh 85`

---

## Test Infrastructure Notes

### Test helpers (all `#[cfg(test)]`)

- `cose.rs`: `gen_test_keypair()`, `gen_test_keypair_b()`, `build_test_cose_sign1()`,
  `build_test_protected_header()`, `domain_aad()`, `encode_bstr()`, `encode_tstr()`
- `delegate.rs`: `build_test_cert()`, `gen_test_keypair_c()`, `ecdsa_rs_to_der()`,
  `build_test_tbs()`, `der_write_length()`. OID constants are `pub(crate)`.
- `voucher.rs`: `build_test_ov_header()`, `build_test_fdo_public_key()`,
  `build_ov_entry_payload()`, `build_hmac_cbor()`, `hmac_sha256()` (pub).
  CBOR helpers: `cbor_uint()`, `cbor_neg_int()`, `cbor_bstr()`, `cbor_tstr()`,
  `cbor_array_header()`.
- `bmo.rs`: `check_bmo_authorization()` (pub), `build_unsigned_image_begin()`,
  `build_signed_image_begin()`.

### Chain order convention

Following go-fdo: chains are **leaf-first** `[leaf, intermediate, root]`.
`verify_delegate_chain` in `delegate.rs` already uses this ordering.

### Permission intersection rule (IMPLEMENTED)

`verify_delegate_chain` now intersects permissions across the entire chain.
A leaf certificate CANNOT claim a permission that any certificate above it
in the chain does not also carry.
