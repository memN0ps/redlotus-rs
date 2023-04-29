use core::ptr::copy_nonoverlapping;
use core::slice::from_raw_parts;
use core::{slice};

use uefi::proto::loaded_image::LoadedImage;
use uefi::{CStr16, Handle};
use uefi::{
    prelude::BootServices,
    proto::media::{
        file::{File, FileAttribute, FileMode, RegularFile},
        fs::SimpleFileSystem,
    },
};

use alloc::vec::Vec;
extern crate alloc;

/// Gets the Windows EFI Boot Manager device as vector of bytes
pub fn get_windows_bootmgr_device(
    path: &str,
    boot_services: &BootServices,
) -> uefi::Result<Vec<u8>> {
    let mut buf = [0u16; 256];

    // Convert a &str to a &CStr16, backed by a buffer. (Can also use cstr16!() macro)
    let filename = CStr16::from_str_with_buf(path, &mut buf).expect("Failed to create CStr16");

    // Returns all the handles implementing a certain protocol.
    // FS0 is the first handle, which is the EFI System Partition (ESP) containing the windows boot manager)
    let handle = *boot_services
        .find_handles::<SimpleFileSystem>()
        .expect("Failed to locate handle buffer")
        .first()
        .expect("First element in handle list empty");

    // Open a protocol interface for a handle in exclusive mode.
    let mut file_system = boot_services
        .open_protocol_exclusive::<SimpleFileSystem>(handle)
        .expect("Failed to open protocol exclusive");

    // Open the root directory on a volume.
    let mut root = file_system.open_volume().expect("Failed to open volume");

    // Try to open a file relative to this file.
    let mut bootmgfw_file = root
        .open(filename, FileMode::Read, FileAttribute::READ_ONLY)
        .expect("Failed to open file")
        .into_regular_file()
        .expect("Failed convert into regular file");

    // Read the whole file into a vector.
    let bootmgfw_data =
        read_all(&mut bootmgfw_file).expect("Failed to read kernel file into memory");

    return Ok(bootmgfw_data);
}

/// Read a RegularFile and return it as a vector of bytes (u8).
pub fn read_all(file: &mut RegularFile) -> uefi::Result<Vec<u8>> {
    let mut buffer = Vec::new();

    loop {
        let mut chunk = [0; 512];
        let read_bytes = file.read(&mut chunk).map_err(|e| e.status())?;

        if read_bytes == 0 {
            break;
        }

        buffer.extend_from_slice(&chunk[0..read_bytes]);
    }

    Ok(buffer)
}

pub fn setup_hooks(bootmgr_handle: Handle, boot_services: &BootServices) {
    log::info!("Opening a handle to uefi bootmgr");
    
    let bootmgr = boot_services.open_protocol_exclusive::<LoadedImage>(bootmgr_handle)
    .expect("Failed to open handle to uefi bootmgr");

    // Returns the base address and the size in bytes of the loaded image.
    let (image_base, image_size) = bootmgr.info();

    log::info!("Reading data from uefi bootmgr");
    // Read the data bootmgr_data as bytes
    let bootmgr_data = unsafe { from_raw_parts(image_base as *mut u8, image_size as usize) };

    log::info!("Pattern scanning");
    // Look for the ImgArchStartBootApplication signature in Windows EFI Boot Manager (bootmgfw.efi) and return an offset
    let offset = pattern_scan(bootmgr_data, "48 8B C4 48 89 58 20 44 89 40 18 48 89 50 10 48 89 48 08 55 56 57 41 54 41 55 41 56 41 57 48 8D 68 A9")
    .expect("Failed to pattern scan").expect("Failed to convert to offset from pattern scan");

    log::info!("Image Base: {:#x} + Function Offset: {:#x} = {:#x}", image_base as usize, offset, (image_base as usize + offset));

    // Trampline hook the ImgArchStartBootApplication function to setup winload.efi hook
    //
    // ImgArchStartBootApplication in bootmgfw.efi or bootmgr.efi:
    // This function is commonly hooked by bootkits to catch the moment when the Windows OS loader (winload.efi) is loaded in the memory but still hasn't been executed
    // – which is the right moment to perform more in-memory patching.
    // https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/
}


#[allow(dead_code)]
fn trampoline_hook(dest: *mut u8, src: *mut u8, original: Option<&mut [u8; 6]>) -> *mut u8 {
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

#[allow(dead_code)]
fn trampoline_unhook(src: *mut u8, original: &[u8; 6]) {
    unsafe {
        copy_nonoverlapping(original.as_ptr(), src, 6);
    }
}

/// Convert a combo pattern to bytes without wildcards
pub fn get_bytes_as_hex(pattern: &str) -> Result<Vec<Option<u8>>, ()> 
{
    let mut pattern_bytes = Vec::new();

    for x in pattern.split_whitespace() 
    {
        match x 
        {
            "?" => pattern_bytes.push(None),
            _ => pattern_bytes.push(u8::from_str_radix(x, 16).map(Some).map_err(|_| ())?),
        }
    }

    Ok(pattern_bytes)
}

/// Pattern or Signature scan a region of memory
pub fn pattern_scan(data: &[u8], pattern: &str) -> Result<Option<usize>, ()> 
{
    let pattern_bytes = get_bytes_as_hex(pattern)?;

    let offset = data
        .windows(pattern_bytes.len())
        .position(|window| {
            window.iter().zip(&pattern_bytes).all(|(byte, pattern_byte)| 
            {
                pattern_byte.map_or(true, |b| *byte == b)
            })
        });

    Ok(offset)
}