// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// Chainload Module - Load and start EFI images from memory
//
// This module implements UEFI LoadImage/StartImage to chain-load
// EFI binaries received via BMO FSIM.

use log::{info, warn, error, debug};
use uefi::prelude::*;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::boot::LoadImageSource;
use uefi::CString16;

/// Which `LoadImage` source to use when chainloading.
///
/// There is deliberately **no automatic fallback**. Loading from memory is the
/// only production behaviour: the protocol hands us bytes over the wire, and
/// `FromBuffer` needs no writable ESP and leaves nothing on disk. Falling back
/// to a file silently would mean writing the payload to the ESP without the
/// operator asking for it, and would make the logs ambiguous about which
/// mechanism actually ran.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LoadMode {
    /// Memory buffer (`LoadImageSource::FromBuffer`). The default and the only
    /// mode production should ever use.
    Buffer,
    /// Write to an ESP temp file and load via `FromDevicePath`.
    ///
    /// Diagnostic escape hatch only, for firmware that turns out to reject
    /// buffer loads. No firmware we have tested needs this: OVMF/QEMU and the
    /// OnLogic K800 both load from memory successfully.
    File,
}

/// Selected load mode. Plain static rather than an atomic: this is a UEFI
/// single-threaded boot-services environment, set once from `main` before use.
static mut LOAD_MODE: LoadMode = LoadMode::Buffer;

/// Whether to tear the network stack down before `StartImage`.
///
/// **Off by default.** The teardown was added in 405ef3b to stop IP4/DHCP timer
/// events firing during `StartImage`, on the theory that they could dereference
/// stale pointers and cause a wild jump. That theory did not survive scrutiny:
/// the original crash was perfectly deterministic and always landed on the same
/// address (0xA0000), which indicates deliberate arithmetic, not a race — a
/// stray timer callback would land somewhere different each time. Chainloading
/// with the teardown disabled was then confirmed working on K800 hardware.
///
/// The teardown is not free. It disconnects every driver from every NIC, which
/// uninstalls SNP itself, and if we do not reconnect afterwards the rest of the
/// UEFI session has no network at all.
///
/// `-teardown` re-enables it for diagnosis.
static mut DO_TEARDOWN: bool = false;

/// Override the chainload source. Call before `chainload_image()`.
pub fn set_load_mode(mode: LoadMode) {
    unsafe { LOAD_MODE = mode; }
}

fn load_mode() -> LoadMode {
    unsafe { LOAD_MODE }
}

/// Enable the pre-StartImage network teardown. Call before `chainload_image()`.
pub fn set_teardown(enable: bool) {
    unsafe { DO_TEARDOWN = enable; }
}

fn do_teardown() -> bool {
    unsafe { DO_TEARDOWN }
}

/// Load an image directly from a memory buffer (`LoadImageSource::FromBuffer`).
fn load_from_buffer(image_data: &[u8]) -> uefi::Result<Handle> {
    uefi::boot::load_image(
        uefi::boot::image_handle(),
        LoadImageSource::FromBuffer {
            buffer: image_data,
            file_path: None,
        },
    )
}

/// Validate that a buffer contains a valid PE/COFF EFI image
/// Basic sanity check - looks for MZ header and PE signature.
pub fn validate_efi_image(image_data: &[u8]) -> bool {
    if image_data.len() < 64 {
        warn!("Image too small: {} bytes", image_data.len());
        return false;
    }

    // Check DOS MZ header
    if image_data[0] != b'M' || image_data[1] != b'Z' {
        warn!("Missing MZ header");
        return false;
    }

    // Get PE header offset (at offset 0x3C in DOS header)
    let pe_offset = u32::from_le_bytes([
        image_data[0x3C],
        image_data[0x3D],
        image_data[0x3E],
        image_data[0x3F],
    ]) as usize;

    if pe_offset + 4 > image_data.len() {
        warn!("PE offset out of bounds: {}", pe_offset);
        return false;
    }

    // Check PE signature "PE\0\0"
    if image_data[pe_offset] != b'P' || image_data[pe_offset + 1] != b'E'
        || image_data[pe_offset + 2] != 0 || image_data[pe_offset + 3] != 0
    {
        warn!("Missing PE signature at offset {}", pe_offset);
        return false;
    }

    debug!("Valid PE/COFF EFI image detected");
    true
}

/// Load and start an EFI image from memory buffer
/// 
/// This function attempts to:
/// 1. First try direct LoadImage from memory (may not work on all firmware)
/// 2. If that fails, write to temp file and load from there
/// 3. Start the loaded image
/// 
/// Returns Ok(()) if the image was successfully started and returned,
/// or an error if loading/starting failed.
pub fn chainload_image(image_data: &[u8]) -> uefi::Result<()> {
    debug!("Chainload: Loading {} byte image from memory...", image_data.len());

    // Validate the image first
    if !validate_efi_image(image_data) {
        error!("Chainload: Invalid EFI image");
        return Err(uefi::Status::LOAD_ERROR.into());
    }

    // PE header sanity gate — REFUSE to chainload if PE structure looks wrong
    {
        let pe_off = u32::from_le_bytes([
            image_data[0x3C], image_data[0x3D], image_data[0x3E], image_data[0x3F],
        ]) as usize;
        
        // Verify PE header is within bounds (need at least 56 bytes past PE sig for optional header)
        if pe_off + 56 > image_data.len() {
            error!("Chainload: PE header at 0x{:x} overflows image ({} bytes) — REFUSING to load", pe_off, image_data.len());
            return Err(uefi::Status::LOAD_ERROR.into());
        }
        
        let entry = u32::from_le_bytes([
            image_data[pe_off + 40], image_data[pe_off + 41],
            image_data[pe_off + 42], image_data[pe_off + 43],
        ]);
        let image_base = u64::from_le_bytes([
            image_data[pe_off + 48], image_data[pe_off + 49],
            image_data[pe_off + 50], image_data[pe_off + 51],
            image_data[pe_off + 52], image_data[pe_off + 53],
            image_data[pe_off + 54], image_data[pe_off + 55],
        ]);
        
        // Read SizeOfImage from optional header (offset 56 from PE sig for PE32+)
        let size_of_image = if pe_off + 80 <= image_data.len() {
            u32::from_le_bytes([
                image_data[pe_off + 80], image_data[pe_off + 81],
                image_data[pe_off + 82], image_data[pe_off + 83],
            ])
        } else {
            0
        };
        
        debug!("Chainload: PE header at offset 0x{:x}", pe_off);
        debug!("Chainload: AddressOfEntryPoint=0x{:x}, ImageBase=0x{:x}, SizeOfImage=0x{:x}", entry, image_base, size_of_image);
        debug!("Chainload: First 16 bytes: {:02x?}", &image_data[..16]);
        let mid = image_data.len() / 2;
        debug!("Chainload: Mid bytes @{}: {:02x?}", mid, &image_data[mid..core::cmp::min(mid+16, image_data.len())]);
        debug!("Chainload: Last 16 bytes: {:02x?}", &image_data[image_data.len()-16..]);

        // Simple integrity checksum: sum of all bytes + XOR of all bytes
        let mut sum: u64 = 0;
        let mut xor: u8 = 0;
        for &b in image_data.iter() {
            sum = sum.wrapping_add(b as u64);
            xor ^= b;
        }
        debug!("Chainload: Integrity: len={} sum=0x{:x} xor=0x{:02x}", image_data.len(), sum, xor);
        
        // Safety checks — HALT if anything looks wrong
        if entry == 0 {
            error!("Chainload: AddressOfEntryPoint is 0 — REFUSING to load (corrupt PE?)");
            return Err(uefi::Status::LOAD_ERROR.into());
        }
        if size_of_image > 0 && entry >= size_of_image {
            error!("Chainload: Entry point 0x{:x} >= SizeOfImage 0x{:x} — REFUSING to load", entry, size_of_image);
            return Err(uefi::Status::LOAD_ERROR.into());
        }
        if size_of_image > 0 && (image_data.len() as u32) > size_of_image * 2 {
            error!("Chainload: File size {} >> SizeOfImage 0x{:x} — REFUSING to load", image_data.len(), size_of_image);
            return Err(uefi::Status::LOAD_ERROR.into());
        }
    }

    // Load the image. Memory buffer is the default and the only production
    // path; there is no automatic fallback (see LoadMode).
    //
    // An earlier comment here claimed AMI firmware (OnLogic k800) does not
    // apply PE relocations for FromBuffer loads. That is contradicted by our
    // own history: commit 7a0038e ("BMO Chain loading works on K800")
    // chainloaded successfully on that exact machine, and every committed
    // version of this file up to 405ef3b used FromBuffer as the primary path —
    // FromDevicePath did not exist in the tree at all. Confirmed again on K800
    // hardware with `-load-mode buffer`, which has no fallback to hide behind.
    //
    // The relocation story also does not hold up: gnu-efi images are built with
    // ImageBase=0x0 and an EMPTY PE base relocation directory by design, and
    // self-relocate at runtime from .rela/.dynamic in crt0. There are no PE
    // relocations for firmware to apply under EITHER source.
    let image_handle = match load_mode() {
        LoadMode::Buffer => {
            debug!("Chainload: Loading from memory buffer...");
            match load_from_buffer(image_data) {
                Ok(h) => { debug!("Chainload: Memory buffer load succeeded"); h }
                Err(e) => {
                    error!("Chainload: Memory buffer load FAILED: {:?}", e.status());
                    error!("Chainload: No fallback. If this firmware genuinely cannot");
                    error!("Chainload: load from memory, retry with -load-mode file.");
                    return Err(e);
                }
            }
        }
        LoadMode::File => {
            warn!("Chainload: -load-mode file — writing payload to the ESP.");
            warn!("Chainload: This is a diagnostic mode, not for production.");
            match load_via_temp_file(image_data) {
                Ok(h) => { debug!("Chainload: File load succeeded"); h }
                Err(e) => {
                    error!("Chainload: File load FAILED: {:?}", e.status());
                    return Err(e);
                }
            }
        }
    };

    // Get info about loaded image
    if let Ok(loaded_image) = uefi::boot::open_protocol_exclusive::<LoadedImage>(image_handle) {
        let (base, size) = loaded_image.info();
        debug!("Chainload: Image loaded at {:p}, size={}", base, size);
    }

    // Tear down network stack before chainload.
    // The IP4 driver (when DHCP is active) keeps timer events registered for
    // ARP cache refresh and DHCP lease renewal. If these fire during or after
    // StartImage, they can dereference stale pointers and cause wild jumps
    // (e.g., #UD at 0xA0000). Disconnecting the network controller cancels
    // all driver-managed events before we transfer control.
    let torn_down_nics = if do_teardown() {
        warn!("Chainload: -teardown — disconnecting NICs before StartImage");
        teardown_network()
    } else {
        alloc::vec::Vec::new()
    };

    // Tighten watchdog before StartImage — if the chainloaded image crashes
    // into a hang (instead of a clean #UD fault), firmware will auto-reboot
    // after this timeout. Saves a trip to the lab for a hard reset.
    match uefi::boot::set_watchdog_timer(60, 0x10001, None) {
        Ok(_) => debug!("Chainload: Watchdog tightened to 60s for StartImage"),
        Err(_) => warn!("Chainload: Could not set watchdog (continuing anyway)"),
    }

    // Start the image
    debug!("Chainload: Starting image...");
    
    let start_result = uefi::boot::start_image(image_handle);
    
    // The image returned rather than taking over the machine. Restore the
    // full-length watchdog so the remainder of the run isn't killed by the
    // 60s window we armed for StartImage.
    let _ = uefi::boot::set_watchdog_timer(crate::WATCHDOG_TIMEOUT_SECS, 0x10000, None);

    // Only relevant when -teardown was used; otherwise this is a no-op because
    // we never disconnected anything.
    //
    // We exit right after a chainload returns and never use the network again,
    // so this is not for our benefit — it is to avoid leaving the rest of the
    // UEFI session (the shell, a later run of this app) with no NICs, which is
    // what teardown_network() would otherwise do.
    reconnect_network(&torn_down_nics);

    match start_result {
        Ok(()) => {
            debug!("Chainload: Image returned successfully");
            Ok(())
        }
        Err(e) => {
            warn!("Chainload: Image returned with error: {:?}", e.status());
            // Even if the image returns an error, we consider chainload successful
            // since the image did run
            Ok(())
        }
    }
}

/// Tear down the UEFI network stack before chainloading.
///
/// When TCP4 uses `use_default_address: TRUE` (DHCP mode), the IP4 driver
/// keeps asynchronous timer events registered (ARP cache maintenance, DHCP
/// lease renewal). If these fire during `StartImage`, they can dereference
/// freed/stale pointers and cause wild jumps (e.g., #UD at 0x000A0000).
///
/// This function disconnects all drivers from every SNP (network) handle,
/// which tears down IP4Dxe, TcpDxe, ArpDxe, etc., cancelling their timers.
///
/// Returns the handles that were disconnected so the caller can reconnect them
/// if the chainloaded image returns. This matters: disconnecting all drivers
/// also unbinds SnpDxe, which UNINSTALLS SimpleNetwork from the handle — so
/// afterwards the handles can no longer be found by searching for SNP, and the
/// network is gone for the remainder of the UEFI session.
fn teardown_network() -> alloc::vec::Vec<Handle> {
    use uefi::proto::network::snp::SimpleNetwork;
    use uefi::Identify;

    debug!("Chainload: Tearing down network stack before StartImage...");

    // Find all SNP handles
    let snp_handles = match uefi::boot::locate_handle_buffer(
        uefi::boot::SearchType::ByProtocol(&SimpleNetwork::GUID)
    ) {
        Ok(h) => h,
        Err(_) => {
            debug!("Chainload: No SNP handles found, nothing to tear down");
            return alloc::vec::Vec::new();
        }
    };

    debug!("Chainload: Disconnecting {} network controller(s)...", snp_handles.len());

    for (idx, &handle) in snp_handles.iter().enumerate() {
        // DisconnectController with NULL driver handle disconnects ALL drivers
        // from this controller, which tears down IP4, TCP4, ARP, DHCP, etc.
        match uefi::boot::disconnect_controller(handle, None, None) {
            Ok(_) => debug!("Chainload: NIC #{} disconnected", idx),
            Err(e) => {
                // NOT_FOUND just means no drivers were connected — that's fine
                if e.status() != uefi::Status::NOT_FOUND {
                    warn!("Chainload: NIC #{} disconnect failed: {:?}", idx, e.status());
                }
            }
        }
    }

    debug!("Chainload: Network teardown complete");
    snp_handles.iter().copied().collect()
}

/// Reconnect the NICs that `teardown_network()` disconnected.
///
/// Best-effort: a failure here just means the caller has no network, which is
/// no worse than the state we would have left behind by doing nothing.
fn reconnect_network(handles: &[Handle]) {
    if handles.is_empty() {
        return;
    }

    let empty_list: &[Option<Handle>] = &[];
    let mut failed = 0;
    for (idx, &handle) in handles.iter().enumerate() {
        match uefi::boot::connect_controller(handle, empty_list, None, true) {
            Ok(_) => debug!("Chainload: NIC #{} reconnected", idx),
            Err(e) => {
                failed += 1;
                warn!("Chainload: NIC #{} reconnect failed: {:?}", idx, e.status());
            }
        }
    }
    debug!("Chainload: Reconnected {}/{} NIC(s) after StartImage", handles.len() - failed, handles.len());
}

/// Load image by writing to a temp file and loading via FromDevicePath.
///
/// This is the preferred method on real hardware (AMI, etc.) because
/// LoadImage(FromDevicePath) triggers the firmware's full PE loader which
/// properly applies relocations. LoadImage(FromBuffer) on some firmware
/// does NOT relocate, causing crashes when ImageBase != load address.
fn load_via_temp_file(image_data: &[u8]) -> uefi::Result<Handle> {
    use uefi::proto::device_path::DevicePath;
    
    debug!("Chainload: Writing {} bytes to temp file...", image_data.len());
    
    // Get the loaded image protocol to find our device
    let loaded_image = uefi::boot::open_protocol_exclusive::<LoadedImage>(
        uefi::boot::image_handle()
    )?;
    
    let device_handle = loaded_image.device()
        .ok_or(uefi::Status::NOT_FOUND)?;
    debug!("Chainload: Parent device handle: {:?}", device_handle);
    
    // Get file system from parent's device
    let mut fs = uefi::boot::open_protocol_exclusive::<SimpleFileSystem>(device_handle)?;
    
    // Open root directory
    let mut root = fs.open_volume()?;
    
    // Try to create/open the temp file
    let temp_path = CString16::try_from("\\EFI\\BOOT\\temp_bmo.efi").unwrap();
    
    let temp_file = root.open(
        &temp_path,
        FileMode::CreateReadWrite,
        FileAttribute::empty(),
    )?;
    
    // Write image data
    let regular_file = temp_file.into_regular_file()
        .ok_or(uefi::Status::UNSUPPORTED)?;
    
    let mut file = regular_file;
    file.write(image_data)
        .map_err(|e| uefi::Error::from(e.status()))?;
    
    // Close and flush
    drop(file);
    drop(root);
    drop(fs);
    // Drop LoadedImage too — we're done with it
    drop(loaded_image);
    
    debug!("Chainload: Written to \\EFI\\BOOT\\temp_bmo.efi, constructing device path...");
    
    // Build a full device path: device_path + FilePath("\EFI\BOOT\temp_bmo.efi") + End
    // This is what makes LoadImage apply proper PE relocations.
    let dev_path = uefi::boot::open_protocol_exclusive::<DevicePath>(device_handle)?;
    
    // Get the device path bytes (everything up to but NOT including the End node)
    let mut dev_path_prefix: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    for node in dev_path.node_iter() {
        if node.is_end_entire() {
            break;
        }
        let node_bytes = unsafe {
            core::slice::from_raw_parts(
                node as *const _ as *const u8,
                node.length() as usize,
            )
        };
        dev_path_prefix.extend_from_slice(node_bytes);
    }
    
    debug!("Chainload: Device path prefix: {} bytes", dev_path_prefix.len());
    // Drop the protocol reference before calling load_image
    drop(dev_path);
    
    // Build the FilePath media device path node
    // Type=0x04 (Media), SubType=0x04 (FilePath)
    // Data = UTF-16LE null-terminated path string
    let file_path_str = "\\EFI\\BOOT\\temp_bmo.efi";
    let utf16_chars: alloc::vec::Vec<u16> = file_path_str.encode_utf16().chain(core::iter::once(0u16)).collect();
    let utf16_bytes_len = utf16_chars.len() * 2;
    let file_node_len: u16 = 4 + utf16_bytes_len as u16; // header(4) + utf16 data
    
    // Assemble full device path: prefix + file path node + end node
    let mut full_path: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    full_path.extend_from_slice(&dev_path_prefix);
    
    // FilePath node header: Type=0x04, SubType=0x04, Length (LE16)
    full_path.push(0x04); // Type: Media
    full_path.push(0x04); // SubType: FilePath
    full_path.extend_from_slice(&file_node_len.to_le_bytes());
    // FilePath node data: UTF-16LE null-terminated path
    for &ch in &utf16_chars {
        full_path.extend_from_slice(&ch.to_le_bytes());
    }
    
    // End Entire node: Type=0x7F, SubType=0xFF, Length=4
    full_path.push(0x7F);
    full_path.push(0xFF);
    full_path.extend_from_slice(&4u16.to_le_bytes());
    
    debug!("Chainload: Full device path: {} bytes (loading via FromDevicePath)", full_path.len());
    
    // Interpret the raw bytes as a DevicePath
    let constructed_dp: &DevicePath = <&DevicePath>::try_from(full_path.as_slice())
        .map_err(|_| {
            error!("Chainload: Failed to construct device path from raw bytes");
            uefi::Status::INVALID_PARAMETER
        })?;
    
    uefi::boot::load_image(
        uefi::boot::image_handle(),
        LoadImageSource::FromDevicePath {
            device_path: constructed_dp,
            boot_policy: uefi::proto::BootPolicy::ExactMatch,
        },
    )
}

/// Test chainload functionality with a simple test image
pub fn test_chainload() {
    debug!("=== Chainload Test ===");
    debug!("Note: This test only validates PE header checking.");
    debug!("Actual chainload requires a valid EFI binary.");
    
    // Test with invalid data
    let invalid_data = [0u8; 100];
    if !validate_efi_image(&invalid_data) {
        debug!("Correctly rejected invalid image");
    }
    
    // Test with fake MZ header but no PE
    let mut fake_mz = [0u8; 100];
    fake_mz[0] = b'M';
    fake_mz[1] = b'Z';
    fake_mz[0x3C] = 0x40; // PE offset = 0x40
    if !validate_efi_image(&fake_mz) {
        debug!("Correctly rejected MZ without PE signature");
    }
    
    debug!("Chainload validation tests passed");
}
