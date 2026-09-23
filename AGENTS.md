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

## Build & Ship

```bash
# Build (on dev machine)
cargo build --release --features fdo-installer

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


