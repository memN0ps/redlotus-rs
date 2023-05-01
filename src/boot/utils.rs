use uefi::CStr16;
use uefi::{
    prelude::BootServices,
    proto::media::{
        file::{File, FileAttribute, FileMode, RegularFile},
        fs::SimpleFileSystem,
    },
};

use alloc::vec::Vec;
extern crate alloc;

/// Gets the Windows EFI Boot Manager device as vector of bytes
pub fn get_windows_bootmgr_device(
    path: &str,
    boot_services: &BootServices,
) -> uefi::Result<Vec<u8>> {
    let mut buf = [0u16; 256];

    // Convert a &str to a &CStr16, backed by a buffer. (Can also use cstr16!() macro)
    let filename = CStr16::from_str_with_buf(path, &mut buf).expect("Failed to create CStr16");

    // Returns all the handles implementing a certain protocol.
    // FS0 is the first handle, which is the EFI System Partition (ESP) containing the windows boot manager)
    let handle = *boot_services
        .find_handles::<SimpleFileSystem>()
        .expect("Failed to locate handle buffer")
        .first()
        .expect("First element in handle list empty");

    // Open a protocol interface for a handle in exclusive mode.
    let mut file_system = boot_services
        .open_protocol_exclusive::<SimpleFileSystem>(handle)
        .expect("Failed to open protocol exclusive");

    // Open the root directory on a volume.
    let mut root = file_system.open_volume().expect("Failed to open volume");

    // Try to open a file relative to this file.
    let mut bootmgfw_file = root
        .open(filename, FileMode::Read, FileAttribute::READ_ONLY)
        .expect("Failed to open file")
        .into_regular_file()
        .expect("Failed convert into regular file");

    // Read the whole file into a vector.
    let bootmgfw_data =
        read_all(&mut bootmgfw_file).expect("Failed to read kernel file into memory");

    return Ok(bootmgfw_data);
}

/// Read a RegularFile and return it as a vector of bytes (u8).
pub fn read_all(file: &mut RegularFile) -> uefi::Result<Vec<u8>> {
    let mut buffer = Vec::new();

    loop {
        let mut chunk = [0; 512];
        let read_bytes = file.read(&mut chunk).map_err(|e| e.status())?;

        if read_bytes == 0 {
            break;
        }

        buffer.extend_from_slice(&chunk[0..read_bytes]);
    }

    Ok(buffer)
}
