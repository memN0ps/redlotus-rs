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

    log::info!("UEFI Bootkit in Rust");
    log::info!("Finding Windows EFI Boot Manager");

    //
    // 1. Locate Windows EFI Boot Manager (\EFI\Microsoft\Boot\bootmgfw.efi)
    //

    // Gets the Windows EFI Boot Manager device as slice of bytes
    let _bootmgr_slice = boot::get_windows_bootmgr_device("\\EFI\\Microsoft\\Boot\\bootmgfw.efi", &system_table).expect("Failed to get device path");


    //
    // 2. Set BootCurrent to Windows Boot Manager (bootmgr) option
    //

    // todo: set_bootcurrent_to_windows_bootmgr()

    //
    // 3. Load the Windows EFI Boot Manager (bootmgr)
    //

    //todo:
    //let loaded_image_handle = boot_services.load_image(boot_services.image_handle(), source);

    //
    // 4. Set up the hook chain from bootmgr -> windload -> ntoskrnl
    //

    // todo: setup_hooks()

    //
    // 5. Start Windows EFI Boot Manager (bootmgr)
    //

    // todo:
    //boot_services.start_image(loaded_image_handle);

    // Make the system pause for 10 seconds
    log::info!("Stalling the processor for 20 seconds");
    system_table.boot_services().stall(20_000_000);
    Status::SUCCESS
}
