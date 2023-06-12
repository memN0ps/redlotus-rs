use self::headers::{
    IMAGE_BASE_RELOCATION, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DOS_SIGNATURE, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE,
    IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW, PIMAGE_BASE_RELOCATION, PIMAGE_DOS_HEADER,
    PIMAGE_EXPORT_DIRECTORY, PIMAGE_IMPORT_BY_NAME, PIMAGE_IMPORT_DESCRIPTOR, PIMAGE_NT_HEADERS64,
    PIMAGE_SECTION_HEADER, PIMAGE_THUNK_DATA64,
};
use crate::boot::globals::{
    ALLOCATED_BUFFER, DRIVER_PHYSICAL_MEMORY, MAPPER_DATA_HASH, MAPPER_DATA_SIZE,
};
use core::{mem::size_of, ptr::copy_nonoverlapping, slice::from_raw_parts};
mod headers;

/// Manually map Windows kernel driver and get address of entry point
pub unsafe fn manually_map(
    ntoskrnl_base: *mut u8,
    target_module_entry_point: *mut u8,
) -> Option<*mut u8> {
    log::info!("[*] ### Manual Mapper ###");
    let module_base = DRIVER_PHYSICAL_MEMORY as *mut u8;
    let new_module_base = ALLOCATED_BUFFER as *mut u64 as *mut u8;

    log::info!("[+] RedLotus.sys Physical Memory: {:p}", module_base);
    log::info!("[+] RedLotus.sys Virtual Memory: {:p}", new_module_base);

    // Copy DOS/NT headers to newly allocated memory
    copy_headers(module_base, new_module_base).expect("Failed to copy headers");
    log::info!("[+] Copied headers");

    // Copy sections to newly allocated memory
    copy_sections(module_base, new_module_base).expect("Failed to copy sections");
    log::info!("[+] Copied sections");

    /* Since we have copied the headers and sections, we can rebase image and resolve imports using the new_module_base (newly allocated memory) */

    // Process image relocations (rebase image)
    rebase_image(new_module_base).expect("Failed to rebase image");
    log::info!("[+] Rebased image");

    // Resolve imports using ntoskrnl
    resolve_imports(new_module_base, ntoskrnl_base).expect("Failed to resolve imports");
    log::info!("[+] Resolved imports");

    log::info!("[+] Finished manual mapping!");

    // Store the target module entry point in the new module base's export address table (DriverEntry)
    hook_export_address_table(new_module_base, MAPPER_DATA_HASH, target_module_entry_point)
        .expect("Failed to hook export address table");
    log::info!("[+] Hooked export address table (EAT)");

    let nt_headers = get_nt_headers(new_module_base).expect("Failed to get NT headers");
    let manually_mapped_driver_entry = (new_module_base as usize
        + (*nt_headers).OptionalHeader.AddressOfEntryPoint as usize)
        as *mut u8;

    return Some(manually_mapped_driver_entry);
}

/// Save the target driver_entry address inside the manually mapped Windows kernel export, driver_entry
pub unsafe fn hook_export_address_table(
    module_base: *mut u8,
    export_hash: u32,
    target_base: *mut u8,
) -> Option<()> {
    let nt_headers = get_nt_headers(module_base)?;
    let export_directory = (module_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            .VirtualAddress as usize) as PIMAGE_EXPORT_DIRECTORY;

    let names = from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNames as usize) as *const u32,
        (*export_directory).NumberOfNames as _,
    );
    let functions = from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfFunctions as usize) as *const u32,
        (*export_directory).NumberOfFunctions as _,
    );
    let ordinals = from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u16,
        (*export_directory).NumberOfNames as _,
    );

    for i in 0..(*export_directory).NumberOfNames {
        let name_addr = (module_base as usize + names[i as usize] as usize) as *const i8;
        let name_len = get_cstr_len(name_addr as _);
        let name_slice: &[u8] = from_raw_parts(name_addr as _, name_len);

        // Ordinal 0: __CxxFrameHandler3
        // Ordinal 1: _fltused
        // Ordinal 2: driver_entry
        // Ordinal 3: <exported function>
        if export_hash == dbj2_hash(name_slice) {
            let ordinal = ordinals[i as usize] as usize;

            // Copy the original bytes of the target module to the export function
            let mapper_data_addy = (module_base as usize + functions[ordinal] as usize) as *mut u8;
            copy_nonoverlapping(target_base, mapper_data_addy, MAPPER_DATA_SIZE);

            return Some(());
        }
    }

    return None;
}

/// Get a pointer to IMAGE_DOS_HEADER
pub unsafe fn get_dos_header(module_base: *mut u8) -> Option<PIMAGE_DOS_HEADER> {
    let dos_header = module_base as PIMAGE_DOS_HEADER;

    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    return Some(dos_header);
}

/// Get a pointer to IMAGE_NT_HEADERS64 x86_64
pub unsafe fn get_nt_headers(module_base: *mut u8) -> Option<PIMAGE_NT_HEADERS64> {
    let dos_header = get_dos_header(module_base)?;

    let nt_headers =
        (module_base as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS64;

    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE as _ {
        return None;
    }

    return Some(nt_headers);
}

/// Copy headers into the target memory location (remember to stomp/erase DOS and NT headers later, if required)
pub unsafe fn copy_headers(module_base: *mut u8, new_module_base: *mut u8) -> Option<()> {
    let nt_headers = get_nt_headers(module_base)?;

    for i in 0..(*nt_headers).OptionalHeader.SizeOfHeaders {
        new_module_base
            .cast::<u8>()
            .add(i as usize)
            .write(module_base.add(i as usize).read());
    }

    Some(())
}

/// Copy sections into the newly allocated memory
pub unsafe fn copy_sections(module_base: *mut u8, new_module_base: *mut u8) -> Option<()> {
    let nt_headers = get_nt_headers(module_base)?;
    let section_header = (&(*nt_headers).OptionalHeader as *const _ as usize
        + (*nt_headers).FileHeader.SizeOfOptionalHeader as usize)
        as PIMAGE_SECTION_HEADER;

    for i in 0..(*nt_headers).FileHeader.NumberOfSections {
        let section_header_i = &*(section_header.add(i as usize));
        let destination = new_module_base
            .cast::<u8>()
            .add(section_header_i.VirtualAddress as usize);
        let source =
            (module_base as usize + section_header_i.PointerToRawData as usize) as *const u8;
        let size = section_header_i.SizeOfRawData as usize;

        //core::ptr::copy_nonoverlapping(source, destination, size);
        let source_data = core::slice::from_raw_parts(source as *const u8, size);

        for x in 0..size {
            let src_data = source_data[x];
            let dest_data = destination.add(x);
            *dest_data = src_data;
        }
    }

    Some(())
}

/// Get the address of an export by hash
pub unsafe fn get_export_by_hash(module_base: *mut u8, export_hash: u32) -> Option<*mut u8> {
    let nt_headers = get_nt_headers(module_base)?;
    let export_directory = (module_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            .VirtualAddress as usize) as PIMAGE_EXPORT_DIRECTORY;

    let names = from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNames as usize) as *const u32,
        (*export_directory).NumberOfNames as _,
    );
    let functions = from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfFunctions as usize) as *const u32,
        (*export_directory).NumberOfFunctions as _,
    );
    let ordinals = from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u16,
        (*export_directory).NumberOfNames as _,
    );

    for i in 0..(*export_directory).NumberOfNames {
        let name_addr = (module_base as usize + names[i as usize] as usize) as *const i8;
        let name_len = get_cstr_len(name_addr as _);
        let name_slice: &[u8] = from_raw_parts(name_addr as _, name_len);

        if export_hash == dbj2_hash(name_slice) {
            let ordinal = ordinals[i as usize] as usize;
            return Some((module_base as usize + functions[ordinal] as usize) as *mut u8);
        }
    }

    return None;
}

/// Process image relocations (rebase image)
pub unsafe fn rebase_image(module_base: *mut u8) -> Option<bool> {
    let nt_headers = get_nt_headers(module_base)?;

    // Calculate the difference between remote allocated memory region where the image will be loaded and preferred ImageBase (delta)
    let delta = module_base as isize - (*nt_headers).OptionalHeader.ImageBase as isize;

    // Return early if delta is 0
    if delta == 0 {
        return Some(true);
    }

    // Resolve the imports of the newly allocated memory region

    // Get a pointer to the first _IMAGE_BASE_RELOCATION
    let mut base_relocation = (module_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize]
            .VirtualAddress as usize) as PIMAGE_BASE_RELOCATION;

    if base_relocation.is_null() {
        return Some(false);
    }

    // Get the end of _IMAGE_BASE_RELOCATION
    let base_relocation_end = base_relocation as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].Size
            as usize;

    while (*base_relocation).VirtualAddress != 0u32
        && (*base_relocation).VirtualAddress as usize <= base_relocation_end
        && (*base_relocation).SizeOfBlock != 0u32
    {
        // Get the VirtualAddress, SizeOfBlock and entries count of the current _IMAGE_BASE_RELOCATION block
        let address = (module_base as usize + (*base_relocation).VirtualAddress as usize) as isize;

        let item = (base_relocation as usize + size_of::<IMAGE_BASE_RELOCATION>()) as *const u16;
        let count = ((*base_relocation).SizeOfBlock as usize - size_of::<IMAGE_BASE_RELOCATION>())
            / size_of::<u16>() as usize;

        for i in 0..count {
            // Get the Type and Offset from the Block Size field of the _IMAGE_BASE_RELOCATION block
            let type_field = (item.offset(i as isize).read() >> 12) as u32;
            let offset = item.offset(i as isize).read() & 0xFFF;

            //IMAGE_REL_BASED_DIR32 does not exist
            //#define IMAGE_REL_BASED_DIR64   10
            if type_field == IMAGE_REL_BASED_DIR64 || type_field == IMAGE_REL_BASED_HIGHLOW {
                // Add the delta to the value of each address where the relocation needs to be performed
                *((address + offset as isize) as *mut isize) += delta;
            }
        }

        // Get a pointer to the next _IMAGE_BASE_RELOCATION
        base_relocation = (base_relocation as usize + (*base_relocation).SizeOfBlock as usize)
            as PIMAGE_BASE_RELOCATION;
    }

    return Some(true);
}

/// Process image import table (resolve imports)
pub unsafe fn resolve_imports(module_base: *mut u8, ntoskrnl_base: *mut u8) -> Option<bool> {
    let nt_headers = get_nt_headers(module_base)?;

    // Get a pointer to the first _IMAGE_IMPORT_DESCRIPTOR
    let mut import_directory = (module_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
            .VirtualAddress as usize) as PIMAGE_IMPORT_DESCRIPTOR;

    if import_directory.is_null() {
        return Some(false);
    }

    while (*import_directory).Name != 0x0 {
        // Get a pointer to the Original Thunk or First Thunk via OriginalFirstThunk or FirstThunk
        let mut original_thunk = if (module_base as usize
            + (*import_directory).Anonymous.OriginalFirstThunk as usize)
            != 0
        {
            let orig_thunk = (module_base as usize
                + (*import_directory).Anonymous.OriginalFirstThunk as usize)
                as PIMAGE_THUNK_DATA64;
            orig_thunk
        } else {
            let thunk = (module_base as usize + (*import_directory).FirstThunk as usize)
                as PIMAGE_THUNK_DATA64;
            thunk
        };

        if original_thunk.is_null() {
            return Some(false);
        }

        let mut thunk =
            (module_base as usize + (*import_directory).FirstThunk as usize) as PIMAGE_THUNK_DATA64;

        if thunk.is_null() {
            return Some(false);
        }

        while (*original_thunk).u1.Function != 0 {
            // Get a pointer to _IMAGE_IMPORT_BY_NAME
            let thunk_data = (module_base as usize + (*original_thunk).u1.AddressOfData as usize)
                as PIMAGE_IMPORT_BY_NAME;

            // Get a pointer to the function name in the IMAGE_IMPORT_BY_NAME
            let fn_name = (*thunk_data).Name.as_ptr();
            let fn_len: usize = get_cstr_len(fn_name);
            let fn_slice = from_raw_parts(fn_name, fn_len);
            //log::info!("fn_name: {:?}", String::from_utf8_lossy(fn_slice));

            // Retrieve the address of the exported function from the DLL and ovewrite the value of "Function" in IMAGE_THUNK_DATA by calling function pointer GetProcAddress by name
            (*thunk).u1.Function = get_export_by_hash(ntoskrnl_base, dbj2_hash(fn_slice))? as _;

            // Increment and get a pointer to the next Thunk and Original Thunk
            thunk = thunk.add(1);
            original_thunk = original_thunk.add(1);
        }

        // Increment and get a pointer to the next _IMAGE_IMPORT_DESCRIPTOR
        import_directory =
            (import_directory as usize + size_of::<IMAGE_IMPORT_DESCRIPTOR>() as usize) as _;
    }

    return Some(true);
}

pub fn dbj2_hash(buffer: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i: usize = 0;
    let mut char: u8;

    while i < buffer.len() {
        char = buffer[i];

        if char == 0 {
            i += 1;
            continue;
        }

        if char >= ('a' as u8) {
            char -= 0x20;
        }

        hash = ((hash << 5).wrapping_add(hash)) + char as u32;
        i += 1;
    }

    return hash;
}

/// Get the length of a C String
pub unsafe fn get_cstr_len(pointer: *const u8) -> usize {
    let mut tmp: u64 = pointer as u64;

    while *(tmp as *const u8) != 0 {
        tmp += 1;
    }

    (tmp - pointer as u64) as _
}
