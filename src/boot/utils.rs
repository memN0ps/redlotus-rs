use core::ptr::{copy_nonoverlapping};
use uefi::proto::device_path::{LoadedImageDevicePath, DeviceType, DeviceSubType, build};
use uefi::proto::device_path::build::DevicePathBuilder;
use uefi::table::boot::LoadImageSource;
use uefi::{Handle, cstr16};
use uefi::{
    prelude::BootServices,
};

use alloc::vec::Vec;
extern crate alloc;

/// Load the Windows EFI Boot Manager from file path (\EFI\Microsoft\Boot\bootmgfw.efi) and return a handle to it
pub fn load_windows_boot_manager(boot_services: &BootServices) -> uefi::Result<Handle> {

    let loaded_image_device_path = boot_services.open_protocol_exclusive::<LoadedImageDevicePath>(boot_services.image_handle())?;

    let mut storage = Vec::new();
    let mut builder = DevicePathBuilder::with_vec(&mut storage);

    for node in loaded_image_device_path.node_iter() {
        if node.full_type() == (DeviceType::MEDIA, DeviceSubType::MEDIA_FILE_PATH) {
            break;
        }

        builder = builder.push(&node).unwrap();
    }

    builder = builder
    .push(&build::media::FilePath {
        path_name: cstr16!(r"EFI\Microsoft\Boot\bootmgfw.efi"),
    })
    .unwrap();
    
    let new_image_path = builder.finalize().unwrap();

    let new_image = boot_services.load_image(
        boot_services.image_handle(),
        LoadImageSource::FromFilePath {
            file_path: new_image_path,
            from_boot_manager: false,
        },
    )?;

    return Ok(new_image);
}

const JMP_SIZE: usize = 14;

/// Creates a gateway to store the stolen bytes and the resume execution flow, then calls the detour function
pub fn trampoline_hook64(src: *mut u8, dst: *mut u8, len: usize) -> Result<[u8; JMP_SIZE], ()> {
    // 5 bytes for x86 and 14 bytes for x86_64
    if len < JMP_SIZE {
        return Err(());
    }

    // Location of stolen bytes and jmp back to original function right after hook to resume execution flow
    let mut gateway: [u8; JMP_SIZE] = [0; JMP_SIZE];

    // Gateway: Store the bytes that are to be stolen in the gateway so we can resume execution flow and jump to them later
    unsafe { copy_nonoverlapping(src, gateway.as_mut_ptr(), len) };

    // 14 bytes for x86_64 for the gateway
    let mut jmp_bytes: [u8; 14] = [
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];

    let jmp_bytes_ptr = jmp_bytes.as_mut_ptr();

    // Populate jmp with an address to jump to: jmp <addresss>
    unsafe { copy_nonoverlapping(((&((src as usize) + len)) as *const usize) as *mut u8, jmp_bytes_ptr.offset(6),8) };

    // Gateway: Write a jmp at the end of the gateway (after the restoring stolen bytes), to the address of the instruction after the hook to resume execution flow
    unsafe { copy_nonoverlapping(jmp_bytes_ptr, ((gateway.as_mut_ptr() as usize) + len) as *mut u8, 14) };

    // Perform the actual hook
    detour64(src, dst, len)?;

    //return the gateway

    Ok( gateway )
}

/// Performs a detour or hook, from source to the destination function.
fn detour64(src: *mut u8, dst: *mut u8, len: usize) -> Result<(), ()> {
    // 5 bytes for x86 and 14 bytes for x86_64
    if len < JMP_SIZE {
        return Err(());
    }

    // 14 bytes for x86_64 for the inline hook
    let mut jmp_bytes: [u8; 14] = [
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];

    let jmp_bytes_ptr = jmp_bytes.as_mut_ptr();

    // Populate jmp array with the address of our detour function: jmp <dst>
    unsafe { copy_nonoverlapping((&(dst as usize) as *const usize) as *mut u8, jmp_bytes_ptr.offset(6), 8) };
    
    // Memory must be writable before hook

    // Hook the original function and place a jmp <dst>
    unsafe { copy_nonoverlapping(jmp_bytes_ptr, src, 14); }

    Ok(())
}


pub fn trampoline_unhook(src: *mut u8, original_bytes: *mut u8, len: usize) {
    unsafe { copy_nonoverlapping(original_bytes, src, len) };
}

/// Convert a combo pattern to bytes without wildcards
pub fn get_bytes_as_hex(pattern: &str) -> Result<Vec<Option<u8>>, ()> {
    let mut pattern_bytes = Vec::new();

    for x in pattern.split_whitespace() {
        match x {
            "?" => pattern_bytes.push(None),
            _ => pattern_bytes.push(u8::from_str_radix(x, 16).map(Some).map_err(|_| ())?),
        }
    }

    Ok(pattern_bytes)
}

/// Pattern or Signature scan a region of memory
pub fn pattern_scan(data: &[u8], pattern: &str) -> Result<Option<usize>, ()> {
    let pattern_bytes = get_bytes_as_hex(pattern)?;

    let offset = data.windows(pattern_bytes.len()).position(|window| {
        window
            .iter()
            .zip(&pattern_bytes)
            .all(|(byte, pattern_byte)| pattern_byte.map_or(true, |b| *byte == b))
    });

    Ok(offset)
}
