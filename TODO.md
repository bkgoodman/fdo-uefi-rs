<!-- Copyright 2026 Dell Technologies, All Rights Reserved -->
<!-- Author: Brad Goodman <bradley.goodman@dell.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# TODO - FDO UEFI Client

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
- [ ] BIOS parameter setting (fdo.bmo:set) - enroll/change BIOS config (e.g. enable Secure Boot, EFI DB keys)
- [ ] **Secure Boot + BMO** - allow unsigned BMO payloads to execute when Secure Boot is on (owner-signed via FDO = sufficient trust)

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
