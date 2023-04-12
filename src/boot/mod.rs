use core::ptr::{self};
use uefi::proto::media::file::{File, FileMode, FileAttribute, FileInfo, FileType::{Regular, Dir}};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::{SystemTable, Boot};
use uefi::table::boot::{AllocateType, MemoryType};
use uefi::{CStr16};

/// Gets the Windows EFI Boot Manager device as slice of bytes
pub fn get_windows_bootmgr_device(name: &str, system_table: &SystemTable<Boot>) -> Option<&'static mut [u8]>
{
    // https://docs.rs/uefi/latest/uefi/table/struct.SystemTable.html#method.boot_services
    //
    // Access boot services
    let boot_services = system_table.boot_services();

    let mut buf = [0u16; 256];
    // https://docs.rs/uefi/latest/uefi/data_types/struct.CStr16.html#method.from_str_with_buf
    //
    // Convert a &str to a &CStr16, backed by a buffer.
    let filename = CStr16::from_str_with_buf(name, &mut buf).expect("Failed to create CStr16");

    // https://docs.rs/uefi/latest/uefi/table/boot/enum.SearchType.html
    // https://docs.rs/uefi/latest/uefi/table/boot/struct.BootServices.html#method.locate_handle_buffer
    //
    // Returns an array of handles that support the requested protocol in a buffer allocated from pool.
    // Return all handles present on the system.
    // let handle_buffer = boot_services.locate_handle_buffer(AllHandles).expect("Failed to locate handle buffer");
   
   // https://docs.rs/uefi/latest/uefi/table/boot/struct.BootServices.html#method.find_handles
   // https://docs.rs/uefi/latest/uefi/proto/media/fs/struct.SimpleFileSystem.html
   // 
   // Returns all the handles implementing a certain protocol.
   let handle_list = boot_services.find_handles::<SimpleFileSystem>().expect("Failed to locate handle buffer");

    // Iterate over all handles
    for handle in handle_list
    {
        // https://docs.rs/uefi/latest/uefi/table/boot/struct.BootServices.html#method.open_protocol_exclusive
        // https://docs.rs/uefi/latest/uefi/proto/trait.Protocol.html
        //
        // Open a protocol interface for a handle in exclusive mode.
        let mut file_system = boot_services.open_protocol_exclusive::<SimpleFileSystem>(handle).expect("Failed to open protocol exclusive");
        
        // https://docs.rs/uefi/latest/uefi/proto/media/fs/struct.SimpleFileSystem.html#method.open_volume
        // https://docs.rs/uefi/latest/uefi/proto/media/file/struct.Directory.html
        //
        // Open the root directory on a volume.
        let mut root = file_system.open_volume().expect("Failed to open volume");

        // https://docs.rs/uefi/latest/uefi/proto/media/file/trait.File.html#method.open
        // https://docs.rs/uefi/latest/uefi/proto/media/file/enum.FileMode.html
        // https://docs.rs/uefi/latest/uefi/proto/media/file/struct.FileAttribute.html
        // 
        // Try to open a file relative to this file.
        let file_handle_result = root.open(filename, FileMode::Read, FileAttribute::READ_ONLY);

        // we continue if we can't open a handle on \\EFI\\Microsoft\\Boot\\bootmgfw.efi
        let file_handle = match file_handle_result {
            Err(_) => continue,
            Ok(handle) => handle,
        };

        let mut file = match file_handle.into_type().unwrap() {
            Regular(f) => f,
            Dir(_) => panic!(),
        };

        // https://docs.rs/uefi/latest/uefi/proto/media/file/trait.File.html#method.get_info
        // 
        //
        // Queries some information about a file
        let mut buffer = [0u8; 1024];
        let file_info = file.get_info::<FileInfo>(&mut buffer).unwrap();
        let file_size = usize::try_from(file_info.file_size()).unwrap();

        // https://docs.rs/uefi/latest/uefi/table/boot/struct.BootServices.html#method.allocate_pages
        // https://docs.rs/uefi/latest/uefi/table/boot/enum.AllocateType.html#variant.AnyPages
        // https://docs.rs/uefi/latest/uefi/table/boot/struct.MemoryType.html#associatedconstant.LOADER_DATA
        //
        // Allocates memory pages from the system
        let file_ptr = boot_services.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, ((file_size - 1) / 4096) + 1)
        .expect("Failed to allocate pages") as *mut u8;

        log::info!("Pointer: {:p}", file_ptr);
        log::info!("Size: {}", file_size);

        // https://doc.rust-lang.org/core/ptr/fn.write_bytes.html
        //
        // write_bytes is similar to C’s memset, but sets count * size_of::<T>() bytes to val.
        unsafe { ptr::write_bytes(file_ptr, 0, file_size) };
        
        // https://doc.rust-lang.org/beta/core/slice/fn.from_raw_parts_mut.html
        //
        // Forms a slice from a pointer and a length. The len argument is the number of elements, not the number of bytes.
        let file_slice = unsafe { core::slice::from_raw_parts_mut(file_ptr, file_size) };
        
        // https://docs.rs/uefi/latest/uefi/proto/media/file/struct.RegularFile.html#method.read
        //
        // Read data from file.
        let _bytes_read = file.read(file_slice).expect("Failed to read file");
        
        return Some(file_slice)
    }

    None
}
