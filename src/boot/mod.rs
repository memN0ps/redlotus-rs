use uefi::prelude::BootServices;
use uefi::proto::device_path::text::{AllowShortcuts, DevicePathToText, DisplayOnly};
use uefi::proto::loaded_image::LoadedImage;
//use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::SearchType;
use uefi::{Identify, Result};

/// Gets the current image path
pub fn get_current_image_path(boot_services: &BootServices) -> Result {
    let loaded_image = boot_services
    .open_protocol_exclusive::<LoadedImage>(boot_services.image_handle())?;

    let device_path_to_text_handle = *boot_services
        .locate_handle_buffer(SearchType::ByProtocol(&DevicePathToText::GUID))?
        .first()
        .expect("DevicePathToText is missing");

    let device_path_to_text = boot_services
        .open_protocol_exclusive::<DevicePathToText>(
            device_path_to_text_handle,
        )?;

    let image_device_path =
        loaded_image.file_path().expect("File path is not set");
    let image_device_path_text = device_path_to_text
        .convert_device_path_to_text(
            boot_services,
            image_device_path,
            DisplayOnly(true),
            AllowShortcuts(false),
        )
        .expect("convert_device_path_to_text failed");

    log::info!("Image path: {}", &*image_device_path_text);
    Ok(())
}


/* 
/// Get the Windows boot manager device path
/// https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcd-system-store-settings-for-uefi?view=windows-11
/// https://edk2-docs.gitbook.io/edk-ii-uefi-driver-writer-s-guide/5_uefi_services/51_services_that_uefi_drivers_commonly_use/513_handle_database_and_protocol_services#5.1.3.2-locatehandlebuffer
pub fn get_windows_boot_mgr(boot_services: &BootServices) -> Result {
    let handle_list = *boot_services
        .locate_handle_buffer(SearchType::ByProtocol(&SimpleFileSystem::GUID))
        .expect("Failed return an array of handles");

    for x in handle_list.iter() {
        let loaded_image = boot_services.open_protocol_exclusive::<SimpleFileSystem>(handle_list[x]).unwrap();
        
    }

    Ok(())
}
*/