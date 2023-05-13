use core::ptr::{copy_nonoverlapping};
use core::slice;
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
