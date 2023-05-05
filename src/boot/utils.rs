use core::ptr::copy_nonoverlapping;
use core::slice;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::FileInfo;
use uefi::table::boot::{LoadImageSource, MemoryType};
use uefi::{cstr16, Handle};
use uefi::{
    prelude::BootServices,
    proto::media::{
        file::{File, FileAttribute, FileMode},
        fs::SimpleFileSystem,
    },
};

use alloc::vec::Vec;
extern crate alloc;

/// Load Windows Boot Manager (\EFI\Microsoft\Boot\bootmgfw.efi) by buffer using load_image and return a handle
pub fn load_windows_boot_manager_by_buffer(boot_services: &BootServices) -> uefi::Result<Handle> {
    let cuurent_image_handle = boot_services.image_handle();
    let load_image_protocol =
        boot_services.open_protocol_exclusive::<LoadedImage>(cuurent_image_handle)?;

    let mut simple_file_system_protocol =
        boot_services.open_protocol_exclusive::<SimpleFileSystem>(load_image_protocol.device())?;
    let mut directory = simple_file_system_protocol.open_volume()?;

    let bootmgfw_path = cstr16!(r"\EFI\Microsoft\Boot\bootmgfw.efi");
    let mut bootmgfw_handle =
        directory.open(bootmgfw_path, FileMode::Read, FileAttribute::READ_ONLY)?;

    let mut file_info_bufffer = [0; 128];
    let file_info = bootmgfw_handle
        .get_info::<FileInfo>(&mut file_info_bufffer)
        .unwrap();

    let file_size = file_info.file_size() as usize;
    let memory_pool = boot_services.allocate_pool(MemoryType::LOADER_DATA, file_size)?;
    let bootmgfw_data =
        unsafe { core::slice::from_raw_parts_mut(memory_pool as *mut u8, file_size) };

    let bootmgfw_handle = boot_services.load_image(
        cuurent_image_handle,
        LoadImageSource::FromBuffer {
            file_path: None,
            buffer: bootmgfw_data,
        },
    )?;

    boot_services.free_pool(memory_pool)?;

    Ok(bootmgfw_handle)
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
