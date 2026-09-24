# Agents

## Test Environment

See `AGENTS.local.md` for environment-specific machine aliases, paths, and access
instructions. That file is .gitignored — it holds personal/environment-identifying
details.

Test scripts (on the test machine):
- `init-tpm.sh` — one-time: creates device credentials + voucher via quick-di
- `start4.sh` — repeatable: runs FDO server + QEMU with swtpm, tests TO1/TO2/BMO
- `start5-verify.sh` — fast TO1/TO2 **crypto verification** run (no BMO, ~60s).
  Use this when changing signature/voucher code; `start4.sh` spends 10+ minutes on
  the UKI transfer. Runs TO0 registration so a to1d blob exists to verify.
- `start6-negative.sh <msg_type> [OFFSET=n]` — **negative** tests. Puts
  `fdo-tamper-proxy.py` on :8080 in front of the real server on :8081 and flips one
  byte of the chosen response. Message types: 33 = to1d, 83 = ProveOVHdr,
  85 = OVNextEntry. `OFFSET` picks the byte (default last = inside the signature).
  Always run a control (e.g. `./start6-negative.sh 99`, a type that never occurs) to
  prove failures come from the tampering and not from the proxy.
- `start15-meta-url.sh [unsigned|signed|all]` — **meta-URL delivery** tests.
  Creates a test image + meta-payload, hosts both on a Python HTTP server,
  runs FDO TO2 with `delivery_mode=2`. Tests unsigned meta, signed meta
  (COSE_Sign1 with ES256), and hash verification.

`quick-di-tpm` is **self-contained** — it does DI locally and needs no DI server, so
it runs before the FDO server is started. It has no `-di` flag.

The FDO server does **not** self-register a rendezvous blob. Without a separate
`server server -db <db> -to0 http://host:port -to0-guid <guid>` run, TO1 returns
`[6, 30, "not found"]` and there is no to1d to verify.

## Signature Work: Definition of Done

A protocol message that carries a signature is not "done" until the **negative test
passes** — i.e. until a corrupted signature is shown to *fail* the protocol. Wording a
checklist item as "parses X" or "fetches Y" and marking it complete hides whether
verification happens at all; "onboarding completed" is not evidence that anything was
verified. This is how the TO2 owner-authentication gap (see `TODO.md` CRITICAL section)
went unnoticed through multiple "FULLY TESTED" sign-offs.

## Be Careful

About commands such as `apt` and others which require user-interaction as they may hang agent work.

## Native Unit Tests (188 tests)

```bash
make test          # Runs cargo test on native Linux (no UEFI, no QEMU, ~0.15s)
```

The crate is structured as lib + bin: `src/lib.rs` exports all modules,
`src/main.rs` is the UEFI entry point. UEFI deps (`uefi`, `uefi-raw`) are
target-conditional. `#[cfg(target_os = "uefi")]` gates all UEFI-dependent
code so it compiles out on native Linux.

Tests cover:
- **COSE** (49): Sign1 parse/verify, ES256 +/-, domain AAD (v101 vs v200,
  cross-tag), scope (GUID/combined/fail-closed), BMO signed verify, delegate
  PERM.7 check, malformed inputs
- **Delegate** (19): 1/2/3-cert chains, permission inheritance, self-signed
  rejection, all 5 OID flags
- **FDO** (41): CBOR encoder/decoder, AES-GCM (wrong key/nonce/AAD/tampered),
  KDF, COSE_Encrypt0, encrypted message parsing, SetupDevice parsing, session
  key derivation
- **BMO** (27): Image-begin parse, result/ack/set builders, full Model 1-4
  authorization matrix, delegate-signed x5chain
- **Voucher** (20): OVHeader/PublicKey parse, HMAC (RFC 4231), 0/1/2-entry
  chains, entry swap/reorder, cross-device entry injection, wrong domain AAD,
  chain break at arbitrary index
- **DI** (1): DeviceMfgInfo encoding

See `TODO_TEST.md` for the full test plan and remaining items.

### Adding tests

Put `#[cfg(test)] mod tests { ... }` at the bottom of the module.

Test helpers (all `#[cfg(test)]`):
- `cose.rs`: `gen_test_keypair()`, `gen_test_keypair_b()`,
  `build_test_cose_sign1()`, `build_test_protected_header()`, `domain_aad()`,
  `encode_bstr()`, `encode_tstr()`
- `delegate.rs`: `build_test_cert()`, OID constants (`pub(crate)`)
- `voucher.rs`: `build_test_ov_header()`, `build_test_fdo_public_key()`,
  `build_ov_entry_payload()`, `hmac_sha256()` (pub)
- `bmo.rs`: `check_bmo_authorization()`, `parse_meta_payload()`,
  `parse_cose_key_p256()`, `verify_and_extract_meta()` (all pub),
  test helpers: `build_test_meta_payload()`, `build_test_cose_key()`

## Build & Ship

```bash
# Build UEFI binary (on dev machine)
make release       # or: cargo build --release --features fdo-installer \
                   #       --target x86_64-unknown-uefi -Z build-std=core,alloc

# Create disk image
rm -f build/efi-disk-release.img && make build/efi-disk-release.img
```

Ship the disk image to the test machine — see `AGENTS.local.md` for the
`scp` destination path.

## Documentation

### Spec
Keep a rolling `spec.md` as a somewhat posthumous document that we update as we develop and learn — serves as an after-the-fact spec on the scope of work.

### Tutorialization
Maintain a running tutorialization (in README.md) on how to build and run this project — e.g. in our QEMU environment.

### TODO
Maintain a running `TODO.md` of remaining/outstanding items and technical debt.

## Key Files & UKI Build

See `AGENTS.local.md` for the key file paths on the test machine and
UKI build instructions (machine-specific paths).

## Develop and Build

Develop and build on the dev machine only (see `AGENTS.local.md` for which
host). This is the source-of-truth for all code, tools, and where our working
code and git repos live. Build *here*, and copy any required components to
other machines we actually run and deliver code, servers, etc.


