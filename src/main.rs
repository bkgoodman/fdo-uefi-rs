// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0

#![no_main]
#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;
use log::{debug, info, error, warn};
use uefi::prelude::*;
use uefi::boot;
use uefi::proto::loaded_image::LoadedImage;

mod tpm;
mod http_api;
#[cfg(feature = "uefi-http")]
mod http;
#[cfg(feature = "tcp4-http")]
mod tcp4_http;
#[cfg(feature = "fdo-installer")]
mod fdo;
#[cfg(feature = "fdo-installer")]
mod bmo;
// Shared COSE_Sign1 verification, used by TO1/TO2/voucher and (later) BMO.
#[cfg(any(feature = "fdo-installer", feature = "rv-firmware"))]
mod cose;
// Ownership Voucher verification — establishes the TO2-proven Owner key.
#[cfg(feature = "fdo-installer")]
mod voucher;
// Delegate certificate chain validation — FDO 2.0 delegate support.
#[cfg(feature = "fdo-installer")]
mod delegate;
mod chainload;
#[cfg(feature = "di")]
mod di;
#[cfg(feature = "rv-firmware")]
mod rv_firmware;

/// Global watchdog timeout, in seconds.
///
/// Armed at entry and re-armed after a chainloaded image returns, so a hang
/// anywhere in the run auto-reboots instead of requiring a lab visit.
pub const WATCHDOG_TIMEOUT_SECS: usize = 1800; // 30 minutes (106MB UKI at 65KB MTU ~1670 rounds)

/// Parsed command-line options
struct FdoOptions {
    /// Override DI (manufacturing) server URL
    di_url: Option<String>,
    /// Override RV/Owner server URL (for TO1/TO2)
    rv_url: Option<String>,
    /// Just set watchdog and exit (for testing watchdog reboot)
    watchdog_test: Option<usize>,
    /// Chainload a PE straight off the ESP and exit (control test —
    /// no network, no TPM, no FDO)
    chainload_file: Option<String>,
    /// Run DI even if credentials already exist in the TPM.
    /// Needed when re-provisioning against a different server, since the
    /// existing GUID has no voucher in the new server's database.
    force_di: bool,
    /// Pin the chainload LoadImage source (buffer vs ESP file)
    load_mode: chainload::LoadMode,
    /// Enable the pre-StartImage network teardown (diagnostic; off by default)
    teardown: bool,
    /// Re-enable the per-round transport logging suppressed by default
    verbose: bool,
}

/// Well-known FDO manufacturing server DNS names (per fdo-appnote-device-mfg-info.bs)
/// Devices try these in order when no explicit DI server URL is provided.
const WELL_KNOWN_DI_NAMES: &[&str] = &[
    "_fdo._tcp",        // DNS-SD service discovery
    "fdo-mfg",          // Simple well-known hostname
];

/// Default DI server port
const DEFAULT_DI_PORT: u16 = 8080;

/// Parse command-line arguments from EFI shell load options.
/// Supports:  -di <url>   Override DI server URL
///            -rv <url>   Override RV/Owner server URL
///            -h          Show usage help
fn parse_args() -> FdoOptions {
    let mut opts = FdoOptions {
        di_url: None,
        rv_url: None,
        watchdog_test: None,
        chainload_file: None,
        force_di: false,
        load_mode: chainload::LoadMode::Buffer,
        teardown: false,
        verbose: false,
    };

    let loaded_image = match boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle()) {
        Ok(li) => li,
        Err(_) => return opts,
    };

    let args_str = match loaded_image.load_options_as_cstr16() {
        Ok(s) => {
            // Convert UCS-2 to ASCII string
            let mut buf = Vec::new();
            for c in s.iter() {
                let ch = u16::from(*c) as u8;
                if ch == 0 { break; }
                buf.push(ch);
            }
            match core::str::from_utf8(&buf) {
                Ok(s) => String::from(s),
                Err(_) => return opts,
            }
        }
        Err(_) => return opts,
    };

    if args_str.is_empty() {
        return opts;
    }
    debug!("Command line: {}", args_str);

    // Split on whitespace and parse flags
    // Note: first token is typically the EFI app path itself, skip it
    let tokens: Vec<&str> = args_str.split_ascii_whitespace().collect();
    let mut i = 1; // skip argv[0] (the EFI binary path)
    while i < tokens.len() {
        match tokens[i] {
            "-di" => {
                if i + 1 < tokens.len() {
                    opts.di_url = Some(String::from(tokens[i + 1]));
                    debug!("CLI: DI server URL = {}", tokens[i + 1]);
                    i += 2;
                } else {
                    warn!("CLI: -di requires a URL argument");
                    i += 1;
                }
            }
            "-rv" => {
                if i + 1 < tokens.len() {
                    opts.rv_url = Some(String::from(tokens[i + 1]));
                    debug!("CLI: RV/Owner URL = {}", tokens[i + 1]);
                    i += 2;
                } else {
                    warn!("CLI: -rv requires a URL argument");
                    i += 1;
                }
            }
            "-watchdog" => {
                let secs = if i + 1 < tokens.len() {
                    match tokens[i + 1].parse::<usize>() {
                        Ok(n) => { i += 2; n }
                        Err(_) => { i += 1; 30 }
                    }
                } else {
                    i += 1;
                    30
                };
                debug!("CLI: Watchdog test mode — will arm {}s watchdog and exit", secs);
                opts.watchdog_test = Some(secs);
            }
            "-v" | "-verbose" => {
                opts.verbose = true;
                i += 1;
            }
            "-teardown" => {
                debug!("CLI: Will tear down NICs before StartImage (diagnostic)");
                opts.teardown = true;
                i += 1;
            }
            "-load-mode" => {
                if i + 1 < tokens.len() {
                    opts.load_mode = match tokens[i + 1] {
                        "buffer" => chainload::LoadMode::Buffer,
                        "file" => chainload::LoadMode::File,
                        other => {
                            error!("CLI: unknown -load-mode '{}' (use buffer|file)", other);
                            chainload::LoadMode::Buffer
                        }
                    };
                    debug!("CLI: Chainload load mode = {:?}", opts.load_mode);
                    i += 2;
                } else {
                    error!("CLI: -load-mode requires buffer|file|auto");
                    i += 1;
                }
            }
            "-force-di" => {
                debug!("CLI: Force DI — will re-provision even if TPM credentials exist");
                opts.force_di = true;
                i += 1;
            }
            "-chainload" => {
                if i + 1 < tokens.len() {
                    let path = String::from(tokens[i + 1]);
                    debug!("CLI: Chainload control test — will load {} directly", path);
                    opts.chainload_file = Some(path);
                    i += 2;
                } else {
                    error!("CLI: -chainload requires a file path (e.g. \\EFI\\hello.efi)");
                    i += 1;
                }
            }
            "-h" | "--help" | "-help" | "/?" => {
                info!("");
                info!("Usage: fdo-uefi.efi [options]");
                info!("  -di <url>   DI (manufacturing) server URL");
                info!("              e.g. -di http://192.168.1.100:8080");
                info!("  -rv <url>   RV/Owner server URL (TO1/TO2 override)");
                info!("              e.g. -rv http://fdo-server.local:8080");
                info!("  -watchdog [s] Arm watchdog for [s] seconds (default 30) and exit");
                info!("              Tests firmware watchdog reboot without running FDO");
                info!("  -v          Verbose: per-round transport logging (NIC");
                info!("              enumeration, TCP4 setup, HTTP headers, hex dumps)");
                info!("              Off by default — console output is slow");
                info!("  -teardown   Disconnect NICs before StartImage (diagnostic)");
                info!("              Off by default: not needed on tested firmware");
                info!("  -load-mode <m>  Chainload source: buffer|file (default buffer)");
                info!("              buffer = LoadImage from memory (production)");
                info!("              file   = write to ESP + LoadImage from file");
                info!("                       (diagnostic only; no auto-fallback)");
                info!("  -force-di   Run DI even if TPM already holds credentials");
                info!("              Use when re-provisioning against a new server");
                info!("  -chainload <path>  Chainload a PE straight off the ESP and exit");
                info!("              e.g. -chainload \\EFI\\hello.efi");
                info!("              Control test: no network, no TPM, no FDO");
                info!("  -h          Show this help");
                info!("");
                info!("If no -di URL is given, the client tries well-known DNS names:");
                for name in WELL_KNOWN_DI_NAMES {
                    info!("  http://{}:{}", name, DEFAULT_DI_PORT);
                }
                info!("");
                info!("If no -rv URL is given, the RV URL is read from the FDO");
                info!("device credential stored in the TPM (written during DI).");
                i += 1;
            }
            _ => {
                debug!("CLI: ignoring unknown argument: {}", tokens[i]);
                i += 1;
            }
        }
    }

    opts
}

/// Read a file from the ESP that this application was loaded from.
///
/// Used by the `-chainload` control test so we can feed a known-good PE to
/// `chainload_image()` without involving the network, the TPM, or FDO.
fn load_file_from_esp(path: &str) -> Option<Vec<u8>> {
    use uefi::proto::media::file::{File, FileAttribute, FileMode};
    use uefi::proto::media::fs::SimpleFileSystem;
    use uefi::CString16;

    let device_handle = {
        let li = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle()).ok()?;
        li.device()?
    };

    let mut fs = boot::open_protocol_exclusive::<SimpleFileSystem>(device_handle).ok()?;
    let mut root = fs.open_volume().ok()?;

    let cpath = CString16::try_from(path).ok()?;
    let handle = root.open(&cpath, FileMode::Read, FileAttribute::empty()).ok()?;
    let mut file = handle.into_regular_file()?;

    // Read in chunks and grow. We deliberately avoid FileInfo/get_boxed_info
    // here: it pulls in wcslen, which isn't available in this no_std target.
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = alloc::vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Some(out)
}

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    
    // Writing to the UEFI console is extremely slow — a full run takes 5-10
    // minutes on-screen versus ~19s redirected to a file. Suppress the
    // per-round transport chatter (NIC enumeration, TCP4 setup, HTTP headers,
    // hex dumps) by default and leave one progress line per HTTP round.
    // `-v` puts it all back.
    log::set_max_level(log::LevelFilter::Info);
    
    // Set a global watchdog timer — if anything hangs or crashes into a loop,
    // the firmware will automatically reboot after this timeout.
    // This is a safety net to avoid needing a physical hard-reset.
    match boot::set_watchdog_timer(WATCHDOG_TIMEOUT_SECS, 0x10000, None) {
        Ok(_) => info!("Watchdog: armed for {} seconds (auto-reboot on hang)", WATCHDOG_TIMEOUT_SECS),
        Err(e) => warn!("Watchdog: failed to set timer: {:?} (continuing without)", e.status()),
    }
    
    info!("===========================================");
    info!("  FDO UEFI Client");
    info!("===========================================");
    
    // Parse command-line arguments
    let opts = parse_args();
    
    // Apply the chainload source override to every chainload site (control
    // test, BMO, and RV firmware) so a single flag pins the behaviour.
    chainload::set_load_mode(opts.load_mode);
    chainload::set_teardown(opts.teardown);
    
    if opts.verbose {
        log::set_max_level(log::LevelFilter::Trace);
        debug!("Verbose logging enabled (-v)");
    }
    
    // Watchdog test mode: just arm the watchdog and exit immediately.
    // Usage: fdo-uefi.efi -watchdog 30
    // The machine should auto-reboot after 30 seconds, proving watchdog works.
    // If it doesn't reboot, the firmware's watchdog is broken/unsupported.
    if let Some(secs) = opts.watchdog_test {
        info!("=== WATCHDOG TEST MODE ===");
        info!("Arming watchdog for {} seconds, then exiting.", secs);
        info!("If watchdog works: machine will reboot in ~{} seconds.", secs);
        info!("If watchdog broken: machine will stay at EFI shell.");
        match boot::set_watchdog_timer(secs, 0x10002, None) {
            Ok(_) => info!("Watchdog armed: {} seconds. Exiting now. Good luck!", secs),
            Err(e) => error!("Watchdog FAILED to arm: {:?} — firmware may not support it", e.status()),
        }
        boot::stall(Duration::from_secs(2));
        return Status::SUCCESS;
    }
    
    // Chainload control test: read a PE off the ESP and chainload it directly.
    // Deliberately runs BEFORE any TPM or network initialisation, so the only
    // variables are the loader and the binary. If this works but the BMO or
    // Stage 1 paths crash with the same binary, the loader is exonerated and
    // the fault is in the environment (network stack, boot stage) instead.
    if let Some(ref path) = opts.chainload_file {
        info!("=== CHAINLOAD CONTROL TEST ===");
        info!("Loading {} from ESP (no network, no TPM, no FDO)", path);
        match load_file_from_esp(path) {
            Some(data) => {
                info!("Read {} bytes from {}", data.len(), path);
                match chainload::chainload_image(&data) {
                    Ok(()) => info!("Control test: chainload returned successfully"),
                    Err(e) => error!("Control test: chainload FAILED: {:?}", e.status()),
                }
            }
            None => error!("Control test: could not read {} from ESP", path),
        }
        let _ = boot::set_watchdog_timer(0, 0x10000, None);
        boot::stall(Duration::from_secs(5));
        return Status::SUCCESS;
    }
    
    // Check for TPM presence first
    if !tpm::tpm_is_present() {
        error!("No TPM found! TCG2 protocol not available in this UEFI environment.");
        error!("Please enable TPM in BIOS (e.g. Intel PTT under System Security).");
        info!("");
        info!("FDO UEFI Client exiting.");
        boot::stall(Duration::from_secs(5));
        return Status::DEVICE_ERROR;
    }
    info!("TPM detected (TCG2 protocol available).");
    
    // RV-based firmware delivery check (if feature enabled)
    // In combined binary mode, check for firmware updates first.
    // If a newer image is available, chainload it.
    // If no update (same version or server unreachable), fall through to normal onboarding.
    //
    // Skipped entirely under -force-di. The firmware URL and minimum revision
    // come from the DCTPM written at DI time, so running the check before a
    // re-provision would act on the OLD credential — fetching whatever the
    // previous DI pointed at and chainloading it, which exits before DI ever
    // runs. Re-provisioning has to happen first; the new firmware config takes
    // effect on the next boot.
    #[cfg(feature = "rv-firmware")]
    if opts.force_di {
        info!("Skipping RV firmware check (-force-di: re-provisioning first)");
    } else {
        info!("Checking for RV-based firmware update...");
        match rv_firmware::check_and_deliver() {
            rv_firmware::DeliveryResult::Chainloaded => {
                info!("Firmware image was chainloaded and returned.");
                info!("FDO UEFI Client exiting.");
                boot::stall(Duration::from_secs(2));
                return Status::SUCCESS;
            }
            rv_firmware::DeliveryResult::NoUpdate => {
                info!("No firmware update available, continuing to onboarding...");
            }
            rv_firmware::DeliveryResult::Error => {
                info!("Firmware delivery error, continuing to onboarding...");
            }
        }
    }

    // Check if device credentials exist in TPM
    #[cfg(any(feature = "di", feature = "fdo-installer"))]
    {
        info!("Checking for FDO credentials in TPM...");
        
        // -force-di: ignore any existing credential and re-provision. The GUID
        // already in the TPM only means something to the server that issued it;
        // pointing at a different server requires a fresh DI so that server has
        // a matching voucher.
        let existing = if opts.force_di {
            info!("Force DI requested — ignoring any existing TPM credentials");
            None
        } else {
            tpm::read_fdo_credentials()
        };

        match existing {
            Some(creds) => {
                // Credentials exist - run TO1/TO2 onboarding
                debug!("Device GUID found: {:02x?}", creds.guid);
                debug!("DeviceKeyHandle: 0x{:08x}", creds.device_key_handle);
                debug!("HMACKeyHandle: 0x{:08x}", creds.hmac_key_handle);
                #[cfg(feature = "fdo-installer")]
                run_onboarding(&creds, &opts);
                #[cfg(not(feature = "fdo-installer"))]
                {
                    let _ = creds;
                    info!("FDO Installer not compiled in — nothing to do.");
                }
            }
            None => {
                // No credentials - attempt Device Initialization
                #[cfg(feature = "di")]
                {
                    info!("No credentials found in TPM.");
                    info!("Attempting Device Initialization (DI)...");
                    
                    match di::run_di_protocol(opts.di_url.as_deref()) {
                        Status::SUCCESS => {
                            info!("Device Initialization completed successfully.");
                            info!("Reboot required to proceed with onboarding.");
                        }
                        Status::NOT_FOUND => {
                            info!("No manufacturing server available. Exiting.");
                        }
                        status => {
                            info!("Device Initialization failed: {:?}", status);
                        }
                    }
                }
                #[cfg(not(feature = "di"))]
                {
                    info!("No credentials found in TPM.");
                    info!("DI not compiled in — cannot provision. Exiting.");
                }
            }
        }
    }
    
    info!("");
    info!("FDO UEFI Client exiting.");
    
    // Disarm watchdog on clean exit
    let _ = boot::set_watchdog_timer(0, 0x10000, None);
    info!("Watchdog: disarmed (clean exit)");
    
    boot::stall(Duration::from_secs(2));
    
    Status::SUCCESS
}

#[cfg(feature = "fdo-installer")]
/// Run TO1/TO2 onboarding protocols.
/// Per securing-fdo-in-tpm.bs spec, the device key handle is read from
/// DCTPM.DeviceKeyHandle — never hardcoded.
fn run_onboarding(creds: &tpm::FdoCredentials, opts: &FdoOptions) {
    // RV URL priority: 1) CLI -rv flag, 2) parsed from TPM credential, 3) error
    let owner_url = if let Some(ref url) = opts.rv_url {
        debug!("Using CLI-provided RV/Owner URL");
        url.clone()
    } else {
        match tpm::read_fdo_rv_info() {
            Some(url) => {
                debug!("Using RV URL from device credential");
                url
            }
            None => {
                error!("No RV/Owner URL available!");
                error!("  Provide one with: fdo-uefi.efi -rv http://server:port");
                error!("  Or ensure DI stored valid rendezvous info in TPM.");
                return;
            }
        }
    };
    debug!("Owner/RV URL: {}", owner_url);
    
    // Run TO1 protocol. Keep the to1d ("rendezvous blob") — its signature can
    // only be checked once TO2 has established the Owner key from the voucher,
    // so it is verified inside TO2 rather than here.
    info!("");
    info!("--- TO1 Protocol ---");
    let to1d = match fdo::perform_to1(&owner_url, &creds.guid, creds.device_key_handle) {
        Ok(redirect) => {
            info!("TO1 complete: to1d blob {} bytes (verified in TO2)", redirect.to1d_cose.len());
            Some(redirect.to1d_cose)
        }
        Err(e) => {
            warn!("TO1 failed: {:?}", e);
            None
        }
    };
    
    // Run TO2 protocol (pass device_key_handle from DCTPM per spec)
    info!("");
    info!("--- TO2 Protocol ---");
    fdo::test_to2_protocol(
        &owner_url,
        &creds.guid,
        creds.device_key_handle,
        creds.hmac_key_handle,
        to1d.as_deref(),
    );
}
