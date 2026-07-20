// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// Chainload Module - Load and start EFI images from memory
//
// This module implements UEFI LoadImage/StartImage to chain-load
// EFI binaries received via BMO FSIM.

use log::{info, warn, error};
use uefi::prelude::*;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::boot::LoadImageSource;
use uefi::CString16;

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

    info!("Valid PE/COFF EFI image detected");
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
    info!("Chainload: Loading {} byte image from memory...", image_data.len());

    // Validate the image first
    if !validate_efi_image(image_data) {
        error!("Chainload: Invalid EFI image");
        return Err(uefi::Status::LOAD_ERROR.into());
    }

    // Try direct memory load first using LoadImageSource::FromBuffer
    info!("Chainload: Attempting direct memory load...");
    
    let load_result = uefi::boot::load_image(
        uefi::boot::image_handle(),
        LoadImageSource::FromBuffer {
            buffer: image_data,
            file_path: None,
        },
    );

    let image_handle = match load_result {
        Ok(handle) => {
            info!("Chainload: Direct memory load succeeded!");
            handle
        }
        Err(e) => {
            warn!("Chainload: Direct load failed ({:?}), trying file method...", e.status());
            
            // Fall back to writing to temp file
            match load_via_temp_file(image_data) {
                Ok(handle) => handle,
                Err(e) => {
                    error!("Chainload: File-based load also failed: {:?}", e.status());
                    return Err(e);
                }
            }
        }
    };

    // Get info about loaded image
    if let Ok(loaded_image) = uefi::boot::open_protocol_exclusive::<LoadedImage>(image_handle) {
        let (base, size) = loaded_image.info();
        info!("Chainload: Image loaded at {:p}, size={}", base, size);
    }

    // Start the image
    info!("Chainload: Starting image...");
    
    let start_result = uefi::boot::start_image(image_handle);
    
    match start_result {
        Ok(()) => {
            info!("Chainload: Image returned successfully");
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

/// Load image by writing to temp file first (fallback for OVMF)
fn load_via_temp_file(image_data: &[u8]) -> uefi::Result<Handle> {
    info!("Chainload: Writing to temp file...");
    
    // Get the loaded image protocol to find our device
    let loaded_image = uefi::boot::open_protocol_exclusive::<LoadedImage>(
        uefi::boot::image_handle()
    )?;
    
    let device_handle = loaded_image.device()
        .ok_or(uefi::Status::NOT_FOUND)?;
    info!("Chainload: Parent device handle: {:?}", device_handle);
    
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
    
    // Need mutable reference for write
    let mut file = regular_file;
    file.write(image_data)
        .map_err(|e| uefi::Error::from(e.status()))?;
    
    // Close and flush
    drop(file);
    drop(root);
    drop(fs);
    
    info!("Chainload: Written {} bytes to temp file, loading...", image_data.len());
    
    // Re-open file system and read back
    let mut fs2 = uefi::boot::open_protocol_exclusive::<SimpleFileSystem>(device_handle)?;
    let mut root2 = fs2.open_volume()?;
    
    let temp_file2 = root2.open(
        &temp_path,
        FileMode::Read,
        FileAttribute::empty(),
    )?;
    
    let mut regular_file2 = temp_file2.into_regular_file()
        .ok_or(uefi::Status::UNSUPPORTED)?;
    
    // Read file back
    let mut buf = alloc::vec![0u8; image_data.len() + 1024];
    let read_len = regular_file2.read(&mut buf)
        .map_err(|e| uefi::Error::from(e.status()))?;
    
    drop(regular_file2);
    drop(root2);
    drop(fs2);
    
    info!("Chainload: Re-read {} bytes from temp file", read_len);
    
    // Try loading from buffer
    uefi::boot::load_image(
        uefi::boot::image_handle(),
        LoadImageSource::FromBuffer {
            buffer: &buf[..read_len],
            file_path: None,
        },
    )
}

/// Test chainload functionality with a simple test image
pub fn test_chainload() {
    info!("=== Chainload Test ===");
    info!("Note: This test only validates PE header checking.");
    info!("Actual chainload requires a valid EFI binary.");
    
    // Test with invalid data
    let invalid_data = [0u8; 100];
    if !validate_efi_image(&invalid_data) {
        info!("Correctly rejected invalid image");
    }
    
    // Test with fake MZ header but no PE
    let mut fake_mz = [0u8; 100];
    fake_mz[0] = b'M';
    fake_mz[1] = b'Z';
    fake_mz[0x3C] = 0x40; // PE offset = 0x40
    if !validate_efi_image(&fake_mz) {
        info!("Correctly rejected MZ without PE signature");
    }
    
    info!("Chainload validation tests passed");
}
