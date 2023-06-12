use core::ptr::copy_nonoverlapping;
use core::slice::from_raw_parts;
use uefi::prelude::BootServices;
use uefi::proto::device_path::build::DevicePathBuilder;
use uefi::proto::device_path::{build, DeviceSubType, DeviceType, LoadedImageDevicePath};
use uefi::table::boot::LoadImageSource;
use uefi::{cstr16, Handle};

use alloc::vec::Vec;

use super::includes::{_KLDR_DATA_TABLE_ENTRY, _LIST_ENTRY};
extern crate alloc;

const JMP_SIZE: usize = 14;

/// Load the Windows EFI Boot Manager from file path (\EFI\Microsoft\Boot\bootmgfw.efi) and return a handle to it
pub fn load_windows_boot_manager(boot_services: &BootServices) -> uefi::Result<Handle> {
    let loaded_image_device_path = boot_services
        .open_protocol_exclusive::<LoadedImageDevicePath>(boot_services.image_handle())?;

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

pub unsafe fn get_loaded_module_by_hash(
    load_order_list_head: *mut _LIST_ENTRY,
    module_hash: u32,
) -> Option<*mut _KLDR_DATA_TABLE_ENTRY> {
    let mut list_entry = (*load_order_list_head).Flink;

    while list_entry != load_order_list_head {
        let entry = ((list_entry as usize)
            - core::mem::offset_of!(_KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks))
            as *mut _KLDR_DATA_TABLE_ENTRY;

        let dll_buffer_ptr = (*entry).BaseDllName.Buffer;
        let dll_length = (*entry).BaseDllName.Length as usize;
        let dll_name_slice = from_raw_parts(dll_buffer_ptr as *const u8, dll_length);

        if module_hash == dbj2_hash(dll_name_slice) {
            return Some(entry);
        }

        list_entry = (*list_entry).Flink;
    }

    None
}

/// Generate a unique hash
pub fn dbj2_hash(buffer: &[u8]) -> u32 {
    let mut hsh: u32 = 5381;
    let mut iter: usize = 0;
    let mut cur: u8;

    while iter < buffer.len() {
        cur = buffer[iter];
        if cur == 0 {
            iter += 1;
            continue;
        }
        if cur >= ('a' as u8) {
            cur -= 0x20;
        }
        hsh = ((hsh << 5).wrapping_add(hsh)) + cur as u32;
        iter += 1;
    }
    return hsh;
}

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
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let jmp_bytes_ptr = jmp_bytes.as_mut_ptr();

    // Populate jmp with an address to jump to: jmp <addresss>
    unsafe {
        copy_nonoverlapping(
            ((&((src as usize) + len)) as *const usize) as *mut u8,
            jmp_bytes_ptr.offset(6),
            8,
        )
    };

    // Gateway: Write a jmp at the end of the gateway (after the restoring stolen bytes), to the address of the instruction after the hook to resume execution flow
    unsafe {
        copy_nonoverlapping(
            jmp_bytes_ptr,
            ((gateway.as_mut_ptr() as usize) + len) as *mut u8,
            jmp_bytes.len(),
        )
    };

    // Perform the actual hook
    detour64(src, dst, len)?;

    //return the gateway

    Ok(gateway)
}

/// Performs a detour or hook, from source to the destination function.
fn detour64(src: *mut u8, dst: *mut u8, len: usize) -> Result<(), ()> {
    // 5 bytes for x86 and 14 bytes for x86_64
    if len < JMP_SIZE {
        return Err(());
    }

    // 14 bytes for x86_64 for the inline hook
    let mut jmp_bytes: [u8; 14] = [
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let jmp_bytes_ptr = jmp_bytes.as_mut_ptr();

    // Populate jmp array with the address of our detour function: jmp <dst>
    unsafe {
        copy_nonoverlapping(
            (&(dst as usize) as *const usize) as *mut u8,
            jmp_bytes_ptr.offset(6),
            8,
        )
    };

    // Memory must be writable before hook

    // Hook the original function and place a jmp <dst>
    unsafe {
        copy_nonoverlapping(jmp_bytes_ptr, src, 14);
    }

    Ok(())
}

/// Restore the stolen bytes by unhooking
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
