<!-- Copyright 2026 Dell Technologies, All Rights Reserved -->
<!-- Author: Brad Goodman <bradley.goodman@dell.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# TODO - FDO UEFI Client

## Native Unit Tests (2026-09-24)

The crate is split into `src/lib.rs` (all modules) and `src/main.rs` (UEFI entry point).
UEFI dependencies (`uefi`, `uefi-raw`) are target-conditional, and UEFI-specific code
is gated with `#[cfg(target_os = "uefi")]`. This lets `make test` / `cargo test` run
on native Linux with no QEMU or swtpm.

**175 tests** across 6 modules, ~0.15s:

| Module | Tests | Key coverage |
|--------|-------|-------------|
| `cose.rs` | 49 | COSE_Sign1 parse/verify, ES256 +/-, domain AAD (v101 vs v200, cross-tag), scope (GUID/combined/fail-closed/empty), BMO signed verify (Model 3/4, no content_type, delegate missing PERM.7), malformed inputs |
| `delegate.rs` | 19 | 1/2/3-cert chains, permission inheritance (intermediate/root missing), self-signed rejected, all 5 OID flags, redirect-only/onboard-only, reuse-cred vs new-cred |
| `fdo.rs` | 41 | CBOR encoder/decoder, AES-GCM (wrong key/nonce/AAD/tampered), KDF (128 vs 256), COSE_Encrypt0 (tampered), encrypted message parsing (wrong tag/no tag/missing IV/empty/truncated), SetupDevice parsing, session key derivation |
| `bmo.rs` | 45 | Full Model 1-4 authorization matrix, delegate-signed x5chain, meta-payload parse (basic/all-fields/missing/garbage/unknown), COSE_Key P-256 parse, signed meta verify (valid/wrong-key/tampered/wrong-AAD/bad-key/not-COSE), unsigned meta passthrough |
| `voucher.rs` | 20 | OVHeader/PublicKey parse, HMAC (RFC 4231), 0/1/2-entry chains, entry swap/reorder, cross-device injection, wrong domain AAD (v2.0), chain break at entry 1, GUID mismatch |
| `di/mfginfo.rs` | 1 | DeviceMfgInfo encoding |

See `TODO_TEST.md` for the full test plan and remaining items.

To add more tests: `#[cfg(test)] mod tests { ... }` at the bottom of the module.
Test helpers in `cose.rs` (`gen_test_keypair`, `build_test_cose_sign1`),
`delegate.rs` (`build_test_cert`), and `voucher.rs` (`build_test_ov_header`,
`build_ov_entry_payload`, `hmac_sha256`) generate P-256 keys, X.509 certs,
and voucher structures for testing.

## Meta-Payload Delivery (delivery_mode 2) — implemented 2026-09-24

BMO meta-URL delivery allows image downloads from external servers with
security anchored in the FDO trust chain:

1. Owner sends signed `image-begin` with `delivery_mode=2`, meta-URL, and
   optional vendor COSE_Key (`-10`).
2. Device fetches meta-payload from URL over HTTP.
3. If COSE_Key present: verify COSE_Sign1 with AAD `"FDO-FSIM-MetaPayload-v1"`.
4. Parse MetaPayload CBOR: `{0: mime, 1: image_url, 3: hash_alg, 4: hash, ...}`.
5. Fetch actual image from `meta.url`.
6. Verify SHA-256 hash against `meta.expected_hash`.
7. Store in session buffer; chainload after TO2 DoneAck.

**Security model:** TLS is not required — meta-payload signature binds URL +
hash to the vendor's key, and image hash covers the downloaded bytes. An
attacker on the wire can observe but not substitute content.

Key functions: `parse_meta_payload()`, `parse_cose_key_p256()`,
`verify_and_extract_meta()`, `process_bmo_meta_url_delivery()` (all in `bmo.rs`).
AAD constant `AAD_TAG_META_PAYLOAD` in `cose.rs`.

QEMU-verified: both unsigned and signed meta-payload delivery tested
end-to-end against go-fdo server (`start15-meta-url.sh` on pe2).

### Future: TLS/HTTPS and IPv6

- **TLS/HTTPS:** Not currently feasible — UEFI firmware does not readily
  support TLS in our TCP4 HTTP stack. If a UEFI TLS stack becomes available,
  the `tls_ca` field (meta key 2 / image-begin key -8) is already parsed and
  stored but unused. Security is not compromised because meta-payload signing
  and image hashing provide integrity without transport encryption.
- **IPv6:** TCP4 backend only supports literal IPv4 addresses. DNS hostname
  resolution is also not available. Both are UEFI platform limitations.
- **Streaming hash:** Currently the entire image is buffered before hashing.
  For very large images, streaming download + incremental SHA-256 would reduce
  peak memory usage.

## Current Status

### Completed

#### Device Initialization (DI) Protocol - FULLY TESTED 2026-08-10
- [x] DI module structure (src/di/)
- [x] DeviceMfgInfo CBOR encoding as array matching go-fdo custom.DeviceMfgInfo struct order
- [x] DIAppStart message builder with CapabilityFlags (FDO 2.0 URL /fdo/200/msg/)
- [x] DISetCredentials parser (OVHeader extraction, preserves raw CBOR for HMAC)
- [x] DISetHMAC message builder (Hash structure encoding)
- [x] DIDone response handling
- [x] TPM DAK (Device Attestation Key) creation - ECC P-256, handle 0x81020002
- [x] TPM HMAC key creation - SHA-256, handle 0x81020003
- [x] CSR generation with TPM signing (proper DER encoding with long-form lengths)
- [x] HMAC computation over OVHeader via TPM
- [x] TPM NV DefineSpace (index 0x01D10001, spec-defined per securing-fdo-in-tpm.bs)
- [x] TPM NV Write (DCTPM credential storage)
- [x] Auto-detection: run DI if no credentials, else TO1/TO2
- [x] HTTP session token (Authorization: Bearer) threading across DI messages
- [x] **End-to-end DI verified** against go-fdo server on pe2 QEMU+swtpm

#### Core Infrastructure
- [x] Manual CBOR encoder for no_std UEFI environment
- [x] TO1.HelloRV message builder (CBOR serialization)
- [x] TO2.HelloDeviceProbe message builder (CBOR serialization)
- [x] CBOR decoder for parsing server responses
- [x] TO1.HelloRVAck parser (FDO 2.0 format with CapabilityFlags)
- [x] TO1.ProveToRV builder (COSE_Sign1 with EAT, placeholder signature)
- [x] TO1.RVRedirect parser
- [x] Full TO1 protocol flow implementation
- [x] HTTP GET support via uefi-rs HttpHelper
- [x] HTTP POST support via raw UEFI HTTP protocol
- [x] Network configuration via DHCP
- [x] TPM 2.0 protocol detection
- [x] SNP network driver initialization

### TO2 Protocol - FULLY TESTED 2026-08-14
- [x] TO2.HelloDeviceProbe (msg 80) - sends device GUID, nonce, capabilities
- [x] TO2.HelloDeviceAck20 (msg 81) - parses server nonce, kex/cipher suites (supports both FDO 1.1 and 2.0 formats)
- [x] TO2.ProveDevice20 (msg 82) - COSE_Sign1 with TPM signature, ECDH xA public key
- [x] TO2.ProveOVHdr20 (msg 83) - parses OV header, server's xB public key
- [x] TO2.GetOVNextEntry/OVNextEntry (msg 84/85) - fetches ownership voucher entries
- [x] ECDH shared secret computation via TPM
- [x] FDO KDF for session key derivation (SEK/SVK) 
- [x] AES-256-GCM encryption/decryption (A256GCM cipher suite 3)
- [x] COSE_Encrypt0 message format (tag 16)
- [x] TO2.DeviceSvcInfoRdy20 (msg 86) - encrypted, signals ready for service info
- [x] TO2.SetupDevice20 (msg 87) - decrypts and parses server response
- [x] TO2.DeviceSvcInfo/OwnerSvcInfo loop (msg 88/89) - FSIM exchange (basic)
- [x] TO2.Done/DoneAck (msg 90/91) - protocol completion
- [x] TPM transient handle management - flush ECDH before DAK, flush DAK after sign, recreate ECDH for ZGen
- [x] FDO 2.0 URL paths (/fdo/200/msg/) for all TO1/TO2 messages
- [x] **End-to-end DI+TO2 verified** on OnLogic k800 real hardware (2026-08-14)

### RESOLVED: COSE Encryption Auth Failure

**Root Cause:** FDO shared secret includes random bytes from both key exchange parameters.
Per go-fdo kex/ecdh.go:300: `shared_secret = ECDH_x || xB.Rand || xA.Rand`

**Fix Applied:** Modified shared secret computation to append random bytes from xB and xA
to the ECDH x-coordinate result before passing to KDF.

**Additional Fixes:**
- DeviceSvcInfoRdy20: Encode as array `[null]` not just `null`
- OwnerSvcInfo20: Handle null response (no service info)
- Done20: Include 2 fields `[nonce, replacement_hmac]` (hmac=null for credential reuse)

### BMO FSIM (Bare Metal Onboarding) - INLINE TRANSFER VERIFIED 2026-08-14
- [x] BMO module structure (bmo.rs)
- [x] BMO message parsing (image-begin, image-data-N, image-end)
- [x] BMO session state machine
- [x] BMO response builders (image-result, image-ack)
- [x] ServiceInfo array parsing
- [x] BMO integration into TO2 ServiceInfo exchange loop
- [x] devmod:modules advertisement with ["fdo.bmo"]
- [x] fdo.bmo:active and fdo.bmo:supported-types advertisement
- [x] Chainload module (chainload.rs) - LoadImage/StartImage with fallback to temp file
- [x] Fix image-data chunk CBOR decoding (chunks are CBOR bstr-wrapped, inner bstr decode)
- [x] Fix server BMO chunk size check (estimatedSize +5 not +50, was double-counting overhead)
- [x] Fix client MTU (1300, was 1040 which was too small for BMO chunks)
- [x] **End-to-end inline BMO verified on OnLogic k800** - payload.efi (51KB) delivered in 51 chunks, chainloaded via LoadImage/StartImage, banner displayed, image-result=success
- [ ] URL delivery mode (mode 1) - device fetches image from URL
- [ ] Meta-URL delivery mode with COSE signature verification (mode 2)
- [ ] dd image mode - write raw disk image to storage device instead of executing EFI app
- [ ] dd image mode - Delay write of INITIAL blocks until rest of image is complete (to ihibit boot of incomplete images)
- [ ] BIOS parameter setting (fdo.bmo:set) - enroll/change BIOS config (e.g. enable Secure Boot, EFI DB keys)
- [ ] **Secure Boot + BMO** - allow unsigned BMO payloads to execute when Secure Boot is on (owner-signed via FDO = sufficient trust)
- [x] **109MB UKI inline transfer** - Ubuntu UKI (kernel+initrd) delivered in ~1,670 rounds, SHA256 verified, chainloaded into Linux 7.0.0-14 (2026-09-03)
- [x] **120MB UKI with full initrd** - Rebuilt UKI with full 91MB Ubuntu initrd + go-fdo client binary + custom init script. Custom init replaces casper (which expected squashfs on CD-ROM) with minimal boot: mounts proc/sys/dev, starts udevd, runs DHCP, drops to shell. Network working (10.0.2.15). go-fdo client available at /usr/local/bin/fdo. (2026-09-03)
- [x] **Pre-allocate image buffer** - Done for inline mode (bmo.rs reserves total_size on image-begin)
- [ ] **Transfer speed optimization** - 120MB at 65KB/round takes ~10-12 minutes. Consider larger chunks if server supports it
- [ ] **Stage 2: go-fdo-endpoint** - Run go-fdo-endpoint client inside booted UKI to receive configuration (autoinstall.yaml, ISO payload) from orchestrator via FSIMs. See go-fdo-endpoint project for hook-based FSIM processing.
- [x] **Watchdog bumped to 1800s (30 min)** for 106MB UKI transfer on k800 hardware (2026-09-15)
- [x] **SNP initialization bug fixed** - `ensure_network_configured()` had SNP start guarded by `#[cfg(not(feature = "uefi-http"))]`, meaning the default build (which includes both uefi-http and tcp4-http) never started SNP on real hardware. TCP4 Configure returned INVALID_PARAMETER on all 6 handles. Fixed by always starting SNP unconditionally. (2026-09-15)
- [ ] **K800 UKI installer test** - Full BMO + payload installer flow on real hardware (in progress, 2026-09-15). Server script: `examples/start-hw-server.sh` (also deployed to pe2).
- [x] **Hardware EFI test: Model 1 (unsigned BMO, channel authority)** — DI + TO2 on
  onlogic with real TPM. Unsigned BMO accepted via Owner channel authority. (2026-09-23)
- [x] **Hardware EFI test: Model 3 (owner-signed BMO)** — COSE_Sign1 tag 18 detected,
  Owner-signed artifact verified, payload accepted. (2026-09-23)
- [x] **Hardware EFI test: Model 3 + scope** — Signed BMO with not_before/not_after/generation
  scope constraints parsed and evaluated on real hardware. (2026-09-23)
- [x] **Hardware EFI test: GUID scope positive** — Pre-signed COSE with correct device
  GUID matched, scope evaluation PASSED. (2026-09-23)
- [x] **Hardware EFI test: GUID scope negative** — Pre-signed COSE with wrong GUID
  rejected: "scope guid MISMATCH — artifact not for this device". (2026-09-23)
- [x] **Hardware EFI test: Model 2 (delegate channel authority)** — Delegate with
  onboard+provision (PERM.7) verified, unsigned BMO accepted via delegate channel
  authority. (2026-09-23)
- [x] **Hardware EFI test: Model 4 (delegate-signed artifact authority)** — COSE_Sign1
  with x5chain detected, delegate cert chain verified against Owner key, leaf has
  PERM.7, delegate-signed artifact verified OK. (2026-09-23)
- [x] **Model 1 bug fix** — Unsigned BMO payloads were wrongly rejected when Owner key
  was present ("no signing or delegate authority"). Fixed: Owner-direct channel
  authority (Model 1) now correctly accepts unsigned payloads. (2026-09-23)
- [ ] **DI: flush TPM transient handles on network error** — If DI fails after
  `CreatePrimary` (e.g. HTTP send fails), transient handles leak. The next DI
  attempt gets `TPM_RC_OBJECT_MEMORY` (0x902) and requires a reboot. Fix: add
  cleanup in the DI error path to flush any transient handles before returning.
- [ ] **DI: retry on transient failure** — Add a wait-and-retry loop (e.g. 3
  attempts with a few seconds between) so transient network errors don't
  require manual reboot and re-run. May be a compile-time option to keep the
  minimal build small.

### RV-Based Firmware Delivery (rv-firmware feature) - E2E VERIFIED 2026-08-25
- [x] HTTP GET added to dual-stack (tcp4_http.rs + http_api.rs dispatcher)
- [x] COSE_Sign1 parsing and ECDSA P-256 (ES256) signature verification via `p256` crate
- [x] RV extension tag parsing (FirmwarePath/FirmwareURL/MinFirmwareRev from DCTPM)
- [x] Anti-rollback firmware revision counter in TPM NV (0x01D10002)
- [x] Hardcoded platform vendor public key (X/Y coordinates)
- [x] Combined binary support: RV delivery → fall-through to TO1/TO2 if no update
- [x] Feature-gated behind `rv-firmware` Cargo feature
- [x] `cargo check` passes with `--features rv-firmware`
- [x] Fix CBOR tag 18 parsing in cose_verify.rs (cbor_read_uint_value→cbor_read_uint_arg)
- [x] QEMU integration test: swtpm + quick-di + HTTP firmware server → 9/9 checks PASSED (pe2)
- [x] OnLogic k800 real hardware test: firmware download + COSE verify + chainload PASSED (2026-08-25)
- [x] `di` build feature: independent DI feature gate (replaces `rv-firmware-di`; works with `rv-firmware` or standalone)
- [x] `fdo-installer` build feature: independent TO1/TO2/BMO feature gate
- [x] Feature refactor: `di`, `fdo-installer`, `rv-firmware` are now three independent Cargo features (2026-08-27)
- [x] Modular architecture documented: `docs/modular-architecture.md`
- [x] Productization guide: `docs/productization-guide.md` (flash vs RAM, DI placement, update mechanisms)
- [ ] Full-stack test: Stage 1 (rv-firmware+DI) → chainload Stage 2 (TO2+BMO) → chainload Stage 3 (UKI)
- [ ] Single-binary flash-resident build: rv-firmware + fdo-installer in one binary. Firmware Stub checks for
  update, then falls through to Installer Image code (no chainload). Needs build + test of combined binary.
- [ ] Flash-update mode (write firmware to SPI flash, reboot) — dynamic chainload only for now
- [ ] Read platform trust anchor from EFI Secure Boot DB (db/dbx) instead of hardcoded key
- [ ] HTTPS/TLS support for firmware download
- [ ] `.fwh` header-only pre-validation (download header first, check rev, then full image)
- [ ] Replace placeholder platform key constants with real key from fdo-meta-tool

### Pending
- [ ] Credential replacement after successful TO2

## CRITICAL: Owner-side authentication (found 2026-09-18, implemented 2026-09-18)

TO2 is specified as *mutual* authentication. Only the device→owner direction was
implemented. Every check that would let the device authenticate the party it was
talking to was absent, so the shipping installer build completed TO2 with, and accepted
a bootable image from, **any** peer that could answer the TO2 URL. The `default`
feature set did not even include `p256`/`ecdsa`, so the installer image contained no
ECDSA verification code at all and was structurally incapable of checking a signature.

### Status: code complete, NOT yet tested end-to-end

| # | Check | Was | Now |
| - | ----- | --- | --- |
| 1 | `TO2.ProveOVHdr` COSE_Sign1 signature | never read | `fdo.rs` Step 3b verifies against the voucher-derived Owner key, AAD `FDO-TO2-ProveOVHdr-v1` |
| 2 | `OVHeader` HMAC vs TPM HMAC key | parsed, never compared | `voucher.rs` recomputes via `tpm_hmac()` and compares; mismatch aborts |
| 3 | `OVEntries` signature chain | fetched and dropped | `voucher.rs` walks the chain: per-entry signature, `hashHdrInfo`, `hashPrevEntry` |
| 4 | `TO1.RVRedirect` to1d signature | only `.len()` logged | threaded into TO2, verified against the Owner key, AAD `FDO-TO0-OwnerSign-v1` |
| 5 | `TO1.ProveToRV` outbound signature | 64 zero bytes | real TPM DAK signature, AAD `FDO-TO1-ProveToRV-v1` |

Supporting work:

- [x] `src/cose.rs` — single shared COSE_Sign1 parser + ES256 verifier + `Sig_structure`
  builder + domain-AAD table. Slice-based, because verification needs the exact wire
  bytes of the protected header and payload.
- [x] `src/voucher.rs` — FDO `PublicKey` parsing (SPKI and COSE_Key; X5CHAIN refused),
  `OVHeader` / `OVEntryPayload` parsing, full chain walk.
- [x] `fdo-installer` now pulls `dep:p256`/`dep:ecdsa`. Default build 300 KiB → 345 KiB.
- [x] Domain AAD is version-conditional: FDO 2.0 uses the tag, 1.01 uses empty. The
  OVEntry AAD is selected from the **voucher's** `OVHProtVer`, not the session version,
  matching `go-fdo/voucher.go`.
- [x] `prove_ov.hmac_raw` keeps the verbatim CBOR of the `HMac` structure — entry 0's
  `hashPrevEntry` is computed over `OVHeader || HMac` *as encoded*, so re-serialising
  risks a byte mismatch.
- [x] Delegate-signed `ProveOVHdr` / to1d / voucher entries are **refused** (label 258 /
  x5chain detected) rather than silently accepted, pending X.509 support.
- [x] `tpm_get_random()` added; key-exchange `xA.Rand` now comes from the TPM instead of
  the fixed sequence `01..10`.
- [x] All session AES-GCM IVs now use a single per-session invocation counter
  (`next_session_iv`, NIST SP 800-38D §8.2.1). Previously `DeviceSvcInfoRdy` and `Done`
  used hardcoded IVs and `Done`'s 8-byte tail was *identical* to the ServiceInfo round
  IVs — collision-free only because the round counter never reached `0xD00E0304`.

### Verified on pe2 QEMU + swtpm (2026-09-18)

Positive run (`~/bkgvm/start5-verify.sh`, no BMO so TO2 completes in seconds):

```
TO1 Step 1 complete: HelloRV -> HelloRVAck
TO1 Step 2 complete: ProveToRV -> RVRedirect        <- real TPM sig accepted by RV
TO1 complete: to1d blob 129 bytes (verified in TO2)
Voucher: header protver=200 entries=2 device_info="EFI-FDO-Verify"
Voucher: OVHeader HMAC verified against TPM key — header is authentic for this device
Voucher: all 2 entries verified; Owner key established
TO2: to1d rendezvous blob signature VERIFIED against Owner key
TO2 Step 3b complete: voucher chain and Owner signature VERIFIED
TO2 Step 6 complete: DoneAck received
```

Negative runs (`~/bkgvm/start6-negative.sh <msg_type>`, with
`~/bkgvm/fdo-tamper-proxy.py` on :8080 forwarding to the real server on :8081 and
flipping one byte of the chosen response):

| Tampered | Device result |
| -------- | ------------- |
| *nothing* (control: proxy in path, `msg 99` never matches) | onboarding completes, all checks VERIFIED |
| msg 85 last byte — voucher entry signature | `entry 0 signature did NOT verify` → `EntrySignatureInvalid(0)` → ABORT |
| msg 33 last byte — to1d signature | `to1d signature verification failed` → ABORT |
| msg 83 last byte — ProveOVHdr signature | `ProveOVHdr SIGNATURE VERIFICATION FAILED` → ABORT |
| msg 83 offset 320 — OVHeader HMAC value | `OVHeader HMAC MISMATCH` → `HmacMismatch` → ABORT |
| msg 83 offset 150 — OVHeader RVInfo bytes | `HeaderParse("bad OVRVInfo")` → ABORT (fails closed on malformed input) |
| msg 83 offset 60 — unprotected `OwnerPubKey` (COSE label 257) | **no effect, and that is correct**: the header is unsigned by design and the device ignores it, using the voucher-derived Owner key instead |

The control run matters: it establishes that the failures above are caused by the
tampering and not by having a proxy in the path.

### Remaining

- [ ] **TPM transient handle cleanup on network error** — if a network error occurs
  mid-protocol, transient TPM handles may leak. Needs a cleanup/flush path.
- [ ] **DI wait-and-retry** — if DI fails (e.g. server not ready), retry a few times
  before giving up. Possibly a compile-time option. Preferable to manual reboot.
- [ ] Delegate support (X.509) — see the BMO section below; currently refused loudly.
- [ ] SHA-384 / P-384 vouchers are refused, not supported.
- [ ] Re-run the full BMO path (`start4.sh`) — the verified runs above deliberately
  omit BMO to keep the cycle short, so the 109 MB UKI transfer has not been re-tested
  since these changes. `start4.sh` also currently references
  `/tmp/fdo-firmware-server/ubuntu-installer.efi` and `test-config.json`, neither of
  which exists on pe2; the UKI present is `ubuntu-26.04.1-live-server-fdo.efi`.
- [ ] Fold TO1 error-response handling into TO2 as well — TO2 still sniffs for a
  5-element CBOR array rather than checking `Message-Type: 255`.

### Bugs found while testing

- [x] **TO1 never sent its session token.** `perform_to1_hello` used `http_post`
  (no auth) and discarded the bearer token from the HelloRVAck response, so
  `ProveToRV` was rejected with `error getting TO1 proof nonce: invalid session`.
  Now threaded through via `http_post_with_session`.
- [x] **TO1 accepted FDO error messages as valid responses.** `parse_to1_rv_redirect`
  stored *any* response body as `to1d_cose`, so a 60-byte
  `[500, 32, "invalid session", ...]` error was logged as "TO1 Step 2 complete" and
  carried forward as a rendezvous blob. Added `check_fdo_error()`, which rejects
  `Message-Type: 255` and logs the server's code and message before parsing.
  This is the same class of failure as the original audit: a success path that never
  checked whether it had actually succeeded.

### Why this was invisible — and the process fix

The TO2 checklist was worded as plumbing ("**parses** OV header", "**fetches** voucher
entries"), marked `[x]`, under a heading reading "FULLY TESTED". Those words were
literally accurate but the sign-off was not: verification is a mandatory part of TO2,
not a separate feature, so "parses" was never an acceptable completion state for a
message whose whole purpose is to authenticate the owner. The QEMU and k800 runs were
real but only ever demonstrated interoperability with a *cooperative* server.

**Rule going forward: a protocol message that carries a signature is not "done" until
the negative test passes — i.e. until a bad signature is shown to fail the protocol.**
"Onboarding completed" is not evidence that anything was verified.

### Exploitability (pre-fix)

An active attacker who could answer the TO2 URL — rogue DHCP/DNS on the provisioning
LAN, ARP spoofing, a spoofed RV server (gap 4 made this the easy path, since the
redirect was unauthenticated) — completed TO2 and delivered an arbitrary EFI image,
which `chainload.rs` executes. Unsigned arbitrary code execution pre-OS. ECDH gave
confidentiality against a passive eavesdropper only; nothing bound the peer's ECDH key
to an FDO Owner.

The Phase-1 rv-firmware stub was and is unaffected: it verifies its payload against the
compiled-in platform key, so Stage 1 → Stage 2 was always signature-checked. It was
Stage 2 → Stage 3 (TO2 delivering the installer/UKI) that was unauthenticated.

## BMO Provisioning Authorization — Four Security Models

See `go-fdo/provisioning-security.md` for the high-level narrative. The four
models and their status on the EFI client:

| Model | Description | EFI status | QEMU tested? |
|---|---|---|---|
| 1 | Owner service, unsigned payloads | **Working** (channel authority) | Yes (`start4.sh`, `start5-verify.sh`) |
| 2 | Delegate service, unsigned payloads | **Working** (delegate chain validated, PERM.7 checked) | Yes (`start8-delegate-unsigned.sh`, positive + negative) |
| 3 | Owner-signed payloads (COSE_Sign1 tag 18) | **Working** (image-begin + set + scope + GUID) | Yes (`start7-bmo-signed.sh`, `start11-signed-negative.sh`, `start12-signed-set.sh`, `start13-bmo-signed-scope.sh`, `start14-scope-guid.sh`) |
| 4 | Delegate-signed payloads (x5chain) | **Working** (x5chain validated, PERM.7 checked, leaf key verified) | Yes (`start9-delegate-signed.sh`, positive + server-side negative) |

### Completed prerequisites

- [x] **ImageBegin field-numbering fix** (2026-09-18)
- [x] **Prefer the authorising hash** (2026-09-18)
- [x] **Voucher walk -> TO2-proven Owner key** — `voucher.rs` recomputes HMAC,
  walks the entry chain, verifies signatures. Owner key is established at
  `fdo.rs:1927-1943` and threaded into `process_bmo_message` at `fdo.rs:2123-2128`.
  ProveOVHdr signature verified at `fdo.rs:1945-1971`. Negative tests pass
  (start6-negative.sh: tampered entries, HMAC, ProveOVHdr, to1d all abort).
- [x] **Artifact authority, Owner-direct (Model 3, image-begin)** — `bmo.rs`
  detects CBOR tag 18 (`0xD2`), calls `cose::verify_bmo_signed()` with external
  AAD `["FDO-FSIM-BmoProvision-v1"]`, checks protected `content_type`. No-downgrade
  rule enforced: tag-18 body that fails verification is rejected, never retried as
  unsigned. Tested on QEMU with `-bmo-sign` (start7-bmo-signed.sh).
- [x] **Delegate TO2 support (Models 2 and 4 prerequisite)** (2026-09-23) —
  New `delegate.rs` module provides minimal no-std X.509 DER parsing for delegate
  certificate chain validation. Replaces the delegate rejection at `fdo.rs:1951-1960`
  with actual validation:
  - Parses delegate chain from ProveOVHdr label 258 (FDO PublicKey X5CHAIN)
  - Validates certificate chain: root signed by Owner key, each cert by its parent
  - Extracts leaf public key for ProveOVHdr signature verification
  - Checks OIDPermitProvision (PERM.7) and onboard permissions on leaf cert
  - Rejects delegates that lack any onboard permission
  - to1d delegate support also implemented (same chain validation)
  - `delegate_has_provision` flag threaded from TO2 into `process_bmo_message`
- [x] **Model 2: Delegate channel authority for unsigned BMO** (2026-09-23) —
  `bmo.rs` `process_bmo_message` now accepts unsigned image-begin when:
  (a) Owner key present, AND (b) delegate has PERM.7. Rejects unsigned when
  Owner key present and no delegate PERM.7. Tested on QEMU:
  - Positive: `start8-delegate-unsigned.sh` (delegate with onboard+provision)
  - Negative: `start8-delegate-unsigned.sh --no-provision` (onboard only, rejected)

### Remaining work — ordered by priority

#### Model 3 completion (Owner-signed)

- [x] **Signed `fdo.bmo:set` handling** (2026-09-23) — `process_bmo_message` now
  calls `unwrap_bmo_signed` for `fdo.bmo:set` with the same signed/unsigned gate
  as `image-begin`. `parse_bmo_set` extracts name/value pairs from the CBOR array.
  Device responds with `fdo.bmo:response` (matching go-fdo wire key). Tested on
  QEMU with `start12-signed-set.sh` — both signed image-begin and signed set
  verified OK. Also fixed go-fdo server bug: BIOS params were never sent due to
  early `moduleDone=true` return before BIOS sending state.
- [x] **QEMU negative test for signed BMO** (2026-09-23) — `start11-signed-negative.sh`
  uses `-bmo-presigned` with a COSE body signed by a wrong key. Device correctly
  rejects: `SIGNATURE VERIFICATION FAILED against Owner key` → `BMO state: Error`.
- [x] **`fdo.bmo.scope` evaluation** (2026-09-23) — `evaluate_bmo_scope()` in
  `cose.rs` parses the `fdo.bmo.scope` protected header field and evaluates:
  - `guid` (MUST): compare against voucher GUID proven in TO2. Single bstr or
    array of bstr (any-match). Mismatch → reject.
  - `not_before`/`not_after` (SHOULD): parsed and logged. Enforcement skipped
    (no trusted clock in UEFI — see clock policy below).
  - `generation` (MAY): parsed and logged. Enforcement skipped (no rollback
    storage yet — see anti-rollback below).
  - Unknown scope fields → fail closed.
  Tested on QEMU:
  - `start13-bmo-signed-scope.sh` — not_before/not_after/generation parsed and
    logged, artifact accepted (positive).
  - `start14-scope-guid.sh` — GUID scope enforcement tested with two legs:
    - **Positive**: correct device GUID in scope → "scope guid matches device
      GUID" → accepted, BMO state Complete.
    - **Negative**: wrong GUID (deadbeef...) → "scope guid MISMATCH — artifact
      not for this device" → rejected, BMO state Error.
  Server flags: `-bmo-scope-not-before`, `-bmo-scope-not-after`,
  `-bmo-scope-generation`. Pre-signed helper: `presign_guid` (cross-compiled).
- [ ] **Error codes 16/17/18** — Provisioning Scope Mismatch / Validity Failed /
  Superseded. Add alongside the existing 15. Currently scope failures return
  generic rejection; specific error codes would improve diagnostics.

#### Model 4: Delegate-signed BMO artifacts (x5chain)

- [x] **Delegate TO2 support** — Done (see "Completed prerequisites" above).
  `delegate.rs` provides full X.509 chain validation with no external x509 crate.
- [x] **Delegate `x5chain` in BMO artifacts (Model 4)** (2026-09-23) —
  `verify_bmo_signed` in `cose.rs` now:
  - Extracts x5chain (label 33) from BMO COSE unprotected header
  - Validates certificate chain to Owner key via `delegate::verify_delegate_chain`
  - Checks PERM.7 (`OIDPermitProvision`) on leaf certificate
  - Verifies COSE signature against delegate leaf key (not Owner key)
  - Tested on QEMU:
    - Positive: `start9-delegate-signed.sh` (delegate with PERM.7 signs BMO)
    - Negative: `start9-delegate-signed.sh --no-provision` (server refuses to start)

#### Scope infrastructure

- [ ] **Clock policy** — `not_before`/`not_after` need a trustworthy clock.
  Classify UEFI `GetTime()` as trustworthy only with working RTC and plausible
  reading (>= firmware build date). Maintain monotonic high-water mark in TPM NV.
  Fail closed otherwise.
- [ ] **`generation` anti-rollback storage** — OPTIONAL. If implemented, the
  high-water mark MUST live in rollback-protected TPM NV. A counter that can be
  rewound fails permissively, worse than not implementing it.
  `rv_firmware/anti_rollback.rs` (NV 0x01D10002) is the precedent.
- [ ] **Strict provisioning policy** (MAY) — operator switch to require artifact
  authority even from a peer that holds provisioning authority. Default off.

### Historical notes

The original TODO items for "Voucher walk -> TO2-proven Owner key" and
"Artifact authority, Owner-direct" are now completed (see above). The old text
described `perform_to2()` as never verifying ProveOVHdr — that was accurate at
the time but is no longer true. The current code at `fdo.rs:1927-1971`
implements full voucher chain verification and ProveOVHdr signature checking.

### Blocked on other repos

- [x] **`go-fdo-meta-tool`: scope encoding.** The meta-tool now supports `-guid`,
  `-not-before`, `-not-after`, `-generation` flags on `provision sign`. Scope is
  encoded into the COSE protected header. **However**, `provision verify` does not
  evaluate scope — it only checks signature validity. See `go-fdo-meta-tool/TODO.md`.
- [x] **`go-fdo`: server-side pre-signed artifact delivery.** (2026-09-23)
  `BMOOwner.AddPreSignedImage()` delivers a pre-signed COSE body as-is via
  `-bmo-presigned`. Used in negative tests and meta-tool round-trip.
- [x] **`go-fdo`: server-side scope emission from flags.** (2026-09-23)
  `-bmo-scope-not-before`, `-bmo-scope-not-after`, `-bmo-scope-generation` flags
  added to the server CLI. Scope is included in the COSE protected header when
  any scope flag is set alongside `-bmo-sign` or `-bmo-delegate-provision`.

### Recently Completed (2026-08-10)
- [x] Error response handling: Message-Type header parsing, FDO error body decoder (error_code, msg_type, error_string)
- [x] Negative test verified: intentionally wrong KeyType produces clean error log with server message
- [x] KeyType constants fixed to match go-fdo values (P-256=10, P-384=11)
- [x] Session token (Authorization: Bearer) threading across DI messages
- [x] HttpPostResponse struct with body, auth_token, and message_type fields

## Resolved Blockers

### OVMF Network Stack (RESOLVED)

**Issue:** Standard OVMF builds did not expose IP4Config2 or HTTP protocols.

**Solution:** Add `-device virtio-rng-pci` to QEMU and call `connect_controller()` to trigger driver binding.

**Result:**
- SNP driver: ✅ Found and initialized
- IP4Config2: ✅ Available after connect_controller()
- HTTP protocol: ✅ Working

### HTTP POST Support (RESOLVED)

**Issue:** uefi-rs 0.38 does not expose `HttpMethod::POST` publicly.

**Resolution:** Implemented HTTP POST using raw UEFI HTTP protocol directly, bypassing the uefi-rs HttpHelper wrapper.

## Technical Debt

- Unused warning suppressions needed for FDO message constants
- Error enum fields not fully utilized
- Some CborDecoder methods unused (will be used for TO2)
- **TPM crypto speed** - Using TPM for ECDH key exchange may be slow; consider software crypto fallback if performance is an issue
- TLS not implemented (HTTP only for now) - acceptable for initial development
- **Key exchange suite configuration** - Currently hardcoded to ECDH256 (P-256). Need config option to select/limit between key types/sizes (ECDH256 vs ECDH384). Would require TPM P-384 key creation support.

### Hacks / Hardcoded Values to Remove

- [x] **Hardcoded DI server address** - Removed. DI server URL now via `-di` CLI flag or well-known DNS names (`_fdo._tcp`, `fdo-mfg`). See README Command-Line Options. (2026-08-15)
- [ ] **Static IP fallback** - TCP4 module falls back to static IP `192.168.200.26/24` when DHCP fails (or times out). This should be removed; rely on DHCP only, or make configurable via UEFI variable.
- [x] **Hardcoded RV/owner URL fallback** - Removed. RV URL now parsed from DCTPM credential (key 5, RvInfo). CLI override via `-rv` flag. (2026-08-15)

### Network / NIC Improvements

- [x] **Skip NICs with zeroed MAC addresses** - Non-exclusive GET_PROTOCOL MAC check, skip zeroed MACs (2026-08-14)
- [x] **Cache working NIC handle** - AtomicI8 cache reuses last working ServiceBinding handle (2026-08-14)
- [x] **DHCP investigation** - Resolved. DHCP works on OnLogic k800 when using the correct NIC (Handle #3, MAC f9:bd). Added link detection via SNP `media_present` to skip NICs without cable. (2026-08-14)
- [ ] **TCP4 reconnect stuck** - On second run (after DI), TCP4 connection attempts get stuck. May be related to ServiceBinding handles not being properly cleaned up from the first connection.

### TPM Persistent Handle Limitation (Documented)

- UEFI TCG2 on OnLogic k800 cannot access persistent handles (ReadPublic returns 0x902). EvictControl succeeds (keys visible from Linux), but UEFI can't read them on next boot.
- **Workaround**: Recreate DAK/HMAC keys via `CreatePrimary` each boot (deterministic — same hierarchy + template = same key). No persistent handles needed.
- This may be OnLogic-specific or a general UEFI TCG2 limitation. Need to test on other hardware (Dell T360).

## Test Environment

- pe2 VM with QEMU, OVMF firmware
- go-fdo server for protocol testing  
- swtpm for TPM simulation
- **Use `~/bkgvm/start3.sh`** - handles swtpm dual-socket setup, DI, voucher import, and QEMU launch correctly

### swtpm/QEMU Setup Note

When starting swtpm for QEMU, you must connect to the `swtpm-server` socket first before QEMU can connect to `swtpm-ctrl`. Example:

```bash
# Start swtpm
swtpm socket --tpmstate dir=$WORKDIR \
    --server type=unixio,path=$WORKDIR/swtpm-server \
    --ctrl type=unixio,path=$WORKDIR/swtpm-ctrl \
    --tpm2 --flags startup-clear &
sleep 2

# Initialize TPM connection (required before QEMU)
echo -n "" | timeout 1 nc -U "$WORKDIR/swtpm-server" 2>/dev/null || true

# Now QEMU can connect to swtpm-ctrl
```

### Known Issues
- swtpm requires initial connection to server socket before QEMU can use ctrl socket
- Server must use correct database matching the voucher from DI
- GUID in client must match what quick-di-tpm created (reads from TPM NV automatically)

## FWImageHash Verification (2026-09-01)

- [x] **Verify `FWImageHash` against the extracted EFI image** in
  `src/rv_firmware/cose_verify.rs`. The hash was previously parsed into
  `FirmwarePayload.image_hash` and never checked. `verify_image_hash()` now
  computes SHA-256/SHA-384 over the extracted bytes and returns
  `VerifyResult::ImageHashMismatch` / `UnsupportedHashAlgorithm` on failure;
  `rv_firmware::mod` refuses to chainload in those cases.
  - Confirmed against `test-keys/signed_payload.cose`: declared and computed
    SHA-256 both `5daf1c35...20bb3529`, so extraction is byte-exact.
  - Same gap existed in `efi-fdo-bmo/src/cose_verify.c` and was fixed there too.

## Chainload Crash Investigation — corrections (2026-09-01)

- The old comment in `chainload.rs` claiming AMI firmware does not apply PE
  relocations for `FromBuffer` loads was **wrong** and has been replaced.
  Every committed version of this file used `FromBuffer`, including `7a0038e`
  ("BMO Chain loading works on K800"). The load source is a constant across the
  works->crashes transition and cannot explain it.
- `ImageBase=0x0` with an empty PE base relocation directory is normal gnu-efi
  output (verified against a fresh `efi-fdo-bmo` build), not a corrupt image.
- The payload in `test-keys/signed_payload.cose` is a **gnu-efi/C binary**
  (`LibInstallProtocolInterfaces` symbols), not a Rust hello app — worth
  confirming which binary we actually intend to be testing with.
- [ ] **Outstanding A/B test:** chainload the identical PE via BMO (proven path)
  and via Stage 1 on the K800. Isolates payload from environment in one shot.
- [ ] Re-evaluate whether the file-first load order in `chainload_image()` should
  be reverted to buffer-first, once the A/B result is known.

## Bug: teardown_network() left the session with no NIC (2026-09-01)

Found during the K800 A/B test. `chainload_image()` calls `teardown_network()`,
which does `disconnect_controller(handle, None, None)` on every SNP handle.
That unbinds ALL drivers from the NIC — including SnpDxe, which uninstalls
`SimpleNetwork` from the handle. Consequences:

- Any later run in the same UEFI session reports
  `No SNP handles found - network driver not loaded`, then
  `TCP4: No ServiceBinding handles found`, and every HTTP POST fails.
- Not just a test artefact: the real Stage 1 flow chainloads, and on
  `DeliveryResult::Chainloaded` the image RETURNS and we fall through to normal
  TO1/TO2 onboarding — with the network stack destroyed. Same for the BMO path
  if the chainloaded image returns.

- [x] Fixed: `teardown_network()` now returns the handles it disconnected and
  `chainload_image()` calls `reconnect_network()` after `StartImage` returns.
  Teardown is only safe if we never come back; we do come back.
- [ ] Revisit whether the teardown is needed at all. It was added in `405ef3b`
  as a mitigation for a crash whose cause is still unproven, and the K800
  control test (leg 0, `-chainload`, no network) passed without it mattering.

## K800 Chainload Investigation — RESULT (2026-09-01)

Both legs passed on OnLogic K800 hardware.

- **Leg 0** `-load-mode buffer -chainload \EFI\payload_image.efi` — SUCCESS.
  Proves the firmware accepts `LoadImageSource::FromBuffer`. No temp file, no
  network, no TPM.
- **Leg A** full DI/TO1/TO2 -> BMO -> chainload of the same PE, buffer mode —
  SUCCESS. Payload ran, returned, NICs reconnected, clean exit.

### Conclusion: chainloading was never broken

The "AMI firmware does not apply PE relocations for FromBuffer" theory is
disproven on hardware. Memory loading works. The `FromDevicePath` rewrite was
unnecessary and the default order is back to buffer-first.

### Still unknown

**We never reproduced the original crash in this session.** We cannot claim to
have fixed it. Remaining candidates, in order:

- [ ] `teardown_network()` is STILL running in the successful path, so we have
  not tested whether it is needed. If the original crash was DHCP timers firing
  during `StartImage`, teardown is masking it; if teardown was never needed,
  it is pure risk. Test: add a flag to skip teardown and re-run leg A.
- [ ] The payload binary in use at the time of the original crash is unknown and
  may not have been the one we tested with.
- [ ] Pre-fix, `teardown_network()` left the session with no NIC. Failures caused
  by that would have looked like a chainload problem but were not.

### Minor tech debt introduced

- [ ] `LOAD_MODE` in `chainload.rs` is a `static mut` accessed through `unsafe`.
  Fine for single-threaded UEFI boot services, but a `Cell`/`OnceCell` or an
  explicit parameter threaded through `chainload_image()` would be cleaner.

## Teardown Necessity Test (2026-09-01)

Added `-no-teardown` to skip `teardown_network()` before `StartImage`, so we can
find out whether the mitigation added in 405ef3b is load-bearing or pure risk.

```
fdo-uefi.efi -no-teardown -load-mode buffer -di http://192.168.200.30:8080 -rv http://192.168.200.30:8080
```

- Chainload still succeeds -> teardown is unnecessary. Remove it, and with it
  the disconnect/reconnect cycle and the class of bug where the session loses
  networking entirely.
- Chainload crashes -> teardown is load-bearing and the DHCP-timer theory behind
  it is confirmed. Keep it, and record the evidence here.

### Tech debt

- [ ] `SKIP_TEARDOWN` in `chainload.rs` is another `static mut` behind `unsafe`,
  same pattern as `LOAD_MODE`. If both survive, fold them into a single
  `ChainloadConfig` struct passed into `chainload_image()` rather than two
  mutable globals.

## Console Verbosity Reduction (2026-09-01)

Console I/O dominates runtime: a full run is 5-10 minutes on screen versus ~19s
redirected to a file. Reduced default log volume by ~62% of lines / ~72% of
characters, measured against a captured 362-line run.

- [x] Default log level pinned to `Info` in `main()` before arg parsing.
- [x] `-v` / `-verbose` raises it to `Trace` to restore everything.
- [x] Demoted to `debug!`: per-round NIC enumeration and link probing
  (`http_api.rs`), TCP4 ServiceBinding selection / configure / connect
  (`tcp4_http.rs`), HTTP header and body dumps (`http.rs`), and the
  `SNP mode: {...}` dump (a single ~2.6 KB line).
- [x] Demoted all `info!` lines whose payload is a `{:02x?}` hex dump in
  `fdo.rs` and `tpm.rs` (42 sites).
- [x] Kept exactly one progress line per HTTP round:
  `TCP4 HTTP POST to <url> (N bytes)`.

### Security note

The suppressed output included the AES session key (`COSE: key`) and the derived
SEK preview, printed to console on every encrypted round. These are now `debug!`.

- [ ] Consider removing the key material dumps entirely rather than leaving them
  behind `-v`. Printing session keys is a bad default even in a debug build.

## Load Mode: buffer is now the default and there is no fallback (2026-09-01)

Removed `LoadMode::Auto`. `chainload_image()` loads from memory
(`LoadImageSource::FromBuffer`) and fails loudly if that does not work.

Rationale — the fallback was never justified:

- No firmware we have tested needs it. OVMF/QEMU worked with buffer loads
  (the original committed behaviour), and the K800 was confirmed with
  `-load-mode buffer`, which has no fallback to hide behind.
- The file path was introduced to chase the "AMI does not relocate FromBuffer"
  theory, which hardware testing disproved.
- It has real costs: requires a writable ESP, writes the payload to disk, leaves
  `\EFI\BOOT\temp_bmo.efi` behind, and makes the logs ambiguous about which
  mechanism actually ran.

`-load-mode file` is retained purely as a diagnostic escape hatch, and now logs
a warning that it is writing the payload to the ESP.

- [ ] If `-load-mode file` goes unused for a while, delete `load_via_temp_file()`
  and the flag outright (~100 lines).

## ServiceInfo/BMO Round Logging Collapsed (2026-09-01)

The BMO transfer loop was the dominant console cost: ~11 INFO lines per
ServiceInfo round, and a 51 KB payload takes ~54 rounds (~590 lines).

Now exactly ONE line per round, emitted at the end of the round with progress:

```
  Round 22: BMO 19266 bytes (37%)
```

Demoted to `debug!`: `ServiceInfo round N` header, DeviceSvcInfo/OwnerSvcInfo
plaintext sizes, `is_done/is_more/svc_info_len`, ServiceInfo array entry dumps,
`Processing BMO message`, and in `bmo.rs` the per-chunk decode/receive lines plus
the image-begin field-by-field dump.

Also demoted `tcp4_http.rs` "TCP4 HTTP POST to ..." — during ServiceInfo it
duplicated the round line, and both the DI and TO1/TO2 layers already announce
each protocol message themselves.

Percentage is only shown when the server sent a `total_size` in image-begin.

## Network Teardown Now OFF by Default (2026-09-01)

`-no-teardown` replaced by `-teardown` (inverted): the teardown is off unless
explicitly requested.

Evidence it was never needed:

- Confirmed working on K800 hardware with the teardown disabled.
- The original crash was deterministic and always landed on 0xA0000 (the VGA
  window). A stray IP4/DHCP timer callback would land somewhere different each
  time; a fixed address indicates deliberate arithmetic, not a race. The
  timer theory the teardown was built on never fit the evidence.

Consequences:

- No disconnect means no reconnect, so the 6 "NIC #n reconnected" lines are gone
  from a normal run. `reconnect_network()` is now a no-op unless `-teardown`.
- When `-teardown` IS used, reconnect still runs and now emits a single summary
  line (`Reconnected 6/6 NIC(s)`) rather than one per NIC. It is not for our
  benefit — we exit straight after a chainload — but to avoid leaving the UEFI
  session with SNP uninstalled.

- [ ] If `-teardown` goes unused, delete `teardown_network()` /
  `reconnect_network()` and the flag (~70 lines).

## Three-Stage Chain Test (2026-09-01)

Stage 1 (RV firmware delivery) confirmed working on K800 with the hello payload.
Next: full chain, where each stage is a genuinely separate binary.

| Stage | Build | Size | Role |
|-------|-------|-----:|------|
| 1 | `--no-default-features --features uefi-http,tcp4-http,rv-firmware,di` | 238.5 KiB | On ESP. Reads DCTPM, downloads + verifies COSE, chainloads Stage 2 |
| 2 | `--no-default-features --features uefi-http,tcp4-http,fdo-installer` | 226 KiB | Delivered via COSE. Runs TO1/TO2 + BMO, chainloads Stage 3 |
| 3 | `test-keys/payload_image.efi` | 50 KiB | Hello-world EFI app |

Stage 1 gained `di` so it can re-provision itself (`-force-di`); a pure
`rv-firmware` stub is 178 KiB but cannot rewrite its own DCTPM.

Stage 1 deliberately excludes `fdo-installer`, and Stage 2 deliberately excludes
`rv-firmware` — otherwise Stage 2 would run the firmware check again and
re-download itself in a loop.

Signed with `fdo-meta-tool platform sign -rev 2` (go-fdo-meta-tool). The Python
`tools/sign_firmware.py` in efi-fdo-bmo needs `cbor2`, which is not installed and
there is no pip on this host.

### Anti-rollback consequence

The TPM counter at NV 0x01D10002 ratchets on every successful verification. It
was at 1 after the hello-payload test; Stage 2 is rev 2, so after this test the
counter becomes 2 and **the rev-1 hello payload can no longer be delivered via
Stage 1**. Re-sign it at a higher rev if it is needed again.

### Known issues

- [ ] `fdo-meta-tool platform verify` fails on its own output for images this
  size: "byte array exceeds max size: 230986". A decoder limit in the tool, not
  a bad payload — structure and FWImageHash verified independently. Worth fixing
  so the tool can validate what it produces.
- [ ] Stage 2 is chainloaded with **no command-line arguments**, so it must get
  the owner URL from the DCTPM rather than `-rv`. Untested: every successful
  TO1/TO2 run so far passed `-rv` explicitly.
- [x] FIXED: the TCP4 receive loops were capped at a fixed round count (500 for
  GET, 50 for POST). That caps a transfer at roughly rounds*fragment_size and
  would silently truncate anything large — a real Linux UKI is hundreds of MB,
  which the old GET cap could not have carried. Both loops now terminate on
  Content-Length or on the peer going quiet, with `MAX_RESPONSE_BYTES`
  (512 MB) as a memory-exhaustion sanity bound rather than an expected limit.


## Anti-Rollback Semantics — clarification (2026-09-01)

Recording this because it was nearly mis-filed as a bug.

Current behaviour is already correct for a chainload-from-RAM design:

- The counter is set to the DELIVERED revision, not blindly incremented:
  `update_firmware_rev_counter(payload.firmware_rev)` ratchets to
  `max(current, delivered)`.
- The gate is `delivered_rev >= max(persisted_counter, RVMinFirmwareRev)`.
  Re-delivering the same rev passes; only a LOWER rev is refused, which is
  exactly the downgrade attack the counter exists to stop.

So "rev 1 can no longer be delivered after rev 2" is the intended security
property, not a regression.

### Not implemented, and deliberately so

Skipping the download when `RVMinFirmwareRev` is not newer than what we already
have would be a valid optimisation for a FLASH-update design: no point fetching
a rev we already hold. It does NOT apply here. We never persist the image — we
chainload it out of RAM every boot — so skipping the download would leave us
with nothing to execute.

- [ ] Revisit if a flash-resident Stage 2 is ever introduced.

## RV Info in DCTPM — verified (2026-09-01)

Question: does DI provision enough into the TPM that a chainloaded Stage 2 (which
gets no command line) can find the owner? **Yes.**

Decoded from the server's msg/11 DISetCredentials response for the 14:49 DI:

```
[2,  c0a8c81e]                                          owner IP 192.168.200.30
[3,  0x1f90]                                            port 8080
[16, "/signed_payload.cose"]                            RVFirmwarePath
[17, "http://192.168.200.30:9080/signed_payload.cose"]  RVFirmwareURL
[18, 0x01]                                              RVMinFirmwareRev
```

`build_dctpm()` stores RVInfo at DCTPM index 5, and `parse_rv_info_at()` handles
tags 2/3 (IP + port) and DNS, so `read_fdo_rv_info()` reconstructs
`http://192.168.200.30:8080`. No `-rv` needed — this is the production path.

Caveat: past logs are ambiguous about whether the URL came from CLI or TPM,
because `-rv` was always passed. The distinguishing log line is
`Using CLI-provided RV/Owner URL` vs `Using RV URL from device credential`.

## -force-di must skip the RV firmware check (2026-09-01)

The firmware URL and min revision live in the DCTPM written at DI time, and the
RV firmware check runs BEFORE the credential check. So `-force-di` against a
device with an existing DCTPM would:

1. Run the firmware check using the OLD credential
2. Download and chainload whatever the PREVIOUS DI pointed at
3. Exit on return — never reaching DI at all

Fixed: `-force-di` now skips the RV firmware check. Re-provisioning happens
first; the new firmware config takes effect on the next boot.

- [ ] Stage 1 is now built as `rv-firmware,di` (the README's "self-provisioning
  firmware stub", recommended OEM config) so it can re-provision itself. A pure
  `rv-firmware` Stage 1 cannot, and would need a separate DI binary deployed.

## Build Size Analysis — all 8 feature combinations

### Current (2026-09-24)

Since the 2026-09-01 baseline, the `fdo-installer` feature gained:
- Delegation support (x5chain X.509 chain validation in `delegate.rs`)
- Signed BMO (COSE_Sign1 tag 18 verification for image-begin + set)
- `fdo.bmo.scope` evaluation (guid, not_before, not_after, generation)
- Signed `fdo.bmo:set` handling with BIOS parameter parsing

Crate restructured into lib + bin (2026-09-24): `src/lib.rs` exports all
modules, `src/main.rs` is a thin UEFI entry point. UEFI deps are
target-conditional. `make test` runs 157 native unit tests on Linux
(no UEFI, no QEMU). All test code is `#[cfg(test)]` — zero impact on
UEFI binary size.

Release builds, `x86_64-unknown-uefi`, all with `uefi-http,tcp4-http`:

| `di` | `fdo-installer` | `rv-firmware` | Size | over base | Δ from Sep-01 |
|:----:|:---------------:|:-------------:|---------:|----------:|-------------:|
| | | | 51 KiB | base | +0 |
| ✓ | | | 167 KiB | +116 KiB | +5 KiB |
| | | ✓ | 167 KiB | +116 KiB | −11 KiB |
| | ✓ | | 330 KiB | +279 KiB | +104 KiB |
| ✓ | | ✓ | 330 KiB | +279 KiB | +91.5 KiB |
| ✓ | ✓ | | 368 KiB | +317 KiB | +104 KiB |
| | ✓ | ✓ | 376 KiB | +325 KiB | +70 KiB |
| ✓ | ✓ | ✓ | 410 KiB | +359 KiB | +70 KiB |

Marginal cost, alone vs added to a build that already has the other two:

| Feature | alone | incremental |
|---------|---------:|-----------:|
| `di` | +116 KiB | +34 KiB |
| `fdo-installer` | +279 KiB | +80 KiB |
| `rv-firmware` | +116 KiB | +42 KiB |

### Where the growth went

The `fdo-installer` feature grew **+104 KiB** (from 226→330 KiB). This is the
cost of the new security features:
- **Delegation** (`delegate.rs`): X.509 chain validation, ASN.1 DER parsing,
  OID matching, signature verification for x5chain — replaces the need for an
  external x509 crate.
- **COSE verification** (`cose.rs`): COSE_Sign1 parsing, protected header map
  iteration, content_type and fdo.bmo.scope evaluation, ECDSA signature
  verification against Owner or delegate keys.
- **Signed BMO handlers** (`bmo.rs`): unwrap_bmo_signed for image-begin and set,
  BIOS parameter CBOR parsing, set-response builder.
- **BMO authorization** (`bmo.rs`): `check_bmo_authorization()` extracted for
  testability, `hmac_sha256()` software HMAC (+2 KiB).

The non-`fdo-installer` features (`di`, `rv-firmware`, base) barely changed
because the new code is gated behind `fdo-installer`.

### Previous (2026-09-01 baseline)

| `di` | `fdo-installer` | `rv-firmware` | Size |
|:----:|:---------------:|:-------------:|---------:|
| | | | 51 KiB |
| ✓ | | | 162 KiB |
| | | ✓ | 178 KiB |
| | ✓ | | 226 KiB |
| ✓ | | ✓ | 238.5 KiB |
| ✓ | ✓ | | 264 KiB |
| | ✓ | ✓ | 306 KiB |
| ✓ | ✓ | ✓ | 340 KiB |

### Observations

- The everything binary grew from 340→409 KiB (+69 KiB, +20%) — the cost of
  full Model 3/4 security (delegation + signed BMO + scope).
- `di` and `rv-firmware` converged to the same size (168 KiB each), likely due
  to shared code paths being refactored.
- The transports alone remain 51 KiB — no change.
- Incrementally, `fdo-installer` costs only +81 KiB when `di` + `rv-firmware`
  are already present (shared COSE/CBOR/crypto code).

### Stripped sizes: still identical (verified, 2026-09-23)

`RUSTFLAGS="-C strip=symbols"` produces byte-identical output:

```
di,fdo-installer,rv-firmware  409 KiB   -> 409 KiB
```

Same reasons as before: UEFI target puts debug info in `.pdb` (not in `.efi`),
and `[profile.release]` already has `lto = true`, `opt-level = "z"`.

- [ ] The only remaining lever is content, not flags: `.rdata` is likely ~80 KiB
  now with the added log strings from scope/delegation. A build-time feature to
  compile out non-error logging would be the next real saving.
