use core::ptr::copy_nonoverlapping;
use core::slice;
use uefi::proto::media::file::{FileInfo};
use uefi::table::boot::{LoadImageSource, MemoryType};
use uefi::{Handle, CStr16};
use uefi::{
    prelude::BootServices,
    proto::media::{
        file::{File, FileAttribute, FileMode},
        fs::SimpleFileSystem,
    },
};

use alloc::vec::Vec;
extern crate alloc;

/// Load the Windows EFI Boot Manager (\EFI\Microsoft\Boot\bootmgfw.efi) and return a handle to it
pub fn load_windows_boot_manager(path: &str, boot_services: &BootServices) -> uefi::Result<Handle> {
    let mut buf = [0u16; 256];
    
    // Convert a &str to a &CStr16, backed by a buffer. (Can also use cstr16!() macro)
    let filename = CStr16::from_str_with_buf(path, &mut buf).unwrap();

    // Returns all the handles implementing a certain protocol.
    // FS0 is the first handle, which is the EFI System Partition (ESP) containing the windows boot manager
    let handle = *boot_services.find_handles::<SimpleFileSystem>()?.first().unwrap();

    // Open a protocol interface for a handle in exclusive mode.
    let mut file_system = boot_services.open_protocol_exclusive::<SimpleFileSystem>(handle)?;

    // Open the root directory on a volume.
    let mut root = file_system.open_volume()?;

    // Try to open a file relative to this file.
    let mut bootmgfw_file = root.open(filename, FileMode::Read, FileAttribute::READ_ONLY)?.into_regular_file().unwrap();

    // Create a buffer to store file information
    let mut file_information_buffer = [0; 128];

    // Queries some information about a file
    let bootmgfw_info = bootmgfw_file.get_info::<FileInfo>(&mut file_information_buffer).unwrap();

    // File size (number of bytes stored in the file)
    let bootmgfw_size = bootmgfw_info.file_size() as usize;
    
    // Allocates from a memory pool. The pointer will be 8-byte aligned
    let memory_pool = boot_services.allocate_pool(MemoryType::LOADER_DATA, bootmgfw_size)?;
    
    // Read the empty memory pool and form a slice with a size of bootmgfw.efi
    let bootmgfw_data = unsafe { core::slice::from_raw_parts_mut(memory_pool, bootmgfw_size) };

    // Read bootmgfw.efi and populate the memory pool
    let _bytes_read = bootmgfw_file.read(bootmgfw_data).expect("Failed to read bootmgfw.efi into memory pool");
   
    // Load an EFI image into memory and return a Handle to the image.
    let bootmgfw_handle = boot_services.load_image(
        boot_services.image_handle(),
        LoadImageSource::FromBuffer {
            file_path: None,
            buffer: bootmgfw_data,
        },
    )?;

    // Frees memory allocated from a pool.
    boot_services.free_pool(memory_pool)?;

    return Ok(bootmgfw_handle);
}

/// Trampoline hook to redirect execution flow
pub fn trampoline_hook(dest: *mut u8, src: *mut u8, original: Option<&mut [u8; 6]>) -> *mut u8 {
    if let Some(original) = original {
        original.copy_from_slice(unsafe { slice::from_raw_parts(src, 6) });
    }

    unsafe {
        let jmp_size = 6;
        let hook_bytes = [0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
        copy_nonoverlapping(hook_bytes.as_ptr(), src, jmp_size);

        let dest_ptr = dest as *mut *mut u8;
        let dst_jmp_offset = src.offset(6) as *mut *mut u8;
        dst_jmp_offset.write(dest_ptr as _);

        src
    }
}

/// Trampoline unhook and restore bytes to original
pub fn trampoline_unhook(src: *mut u8, original: &[u8; 6]) {
    unsafe {
        copy_nonoverlapping(original.as_ptr(), src, 6);
    }
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
