use core::ptr::null_mut;

use alloc::vec::Vec;
extern crate alloc;
use bstr::ByteSlice;
use winapi::{
    ctypes::c_void,
    shared::ntdef::NT_SUCCESS,
    um::winnt::{
        RtlZeroMemory, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, PIMAGE_DOS_HEADER,
        PIMAGE_NT_HEADERS64,
    },
};

use crate::{
    includes::SystemInformationClass,
    includes::{
        ExAllocatePool, ExFreePool, NonPagedPool, SystemModuleInformation, ZwQuerySystemInformation,
    },
};

pub fn get_module_base(module_name: &[u8]) -> *mut c_void {
    let mut bytes = 0;

    // Get buffer size
    let _status = unsafe {
        ZwQuerySystemInformation(
            SystemInformationClass::SystemModuleInformation,
            null_mut(),
            0,
            &mut bytes,
        )
    };

    /* Error check will fail and that is intentional to get the buffer size
    if !NT_SUCCESS(status) {
        log::error!("[-] 1st ZwQuerySystemInformation failed {:?}", status);
        return null_mut();
    } */

    let module_info =
        unsafe { ExAllocatePool(NonPagedPool, bytes as usize) as *mut SystemModuleInformation };

    if module_info.is_null() {
        log::error!("[-] ExAllocatePool failed");
        return null_mut();
    }

    unsafe { RtlZeroMemory(module_info as *mut c_void, bytes as usize) };

    let status = unsafe {
        ZwQuerySystemInformation(
            SystemInformationClass::SystemModuleInformation,
            module_info as *mut c_void,
            bytes,
            &mut bytes,
        )
    };

    if !NT_SUCCESS(status) {
        log::info!("[-] 2nd ZwQuerySystemInformation failed {:#x}", status);
        return null_mut();
    }

    let mut p_module: *mut c_void = null_mut();
    //log::info!("[+] Module count: {:?}", unsafe { (*module_info).modules_count as usize});

    for i in unsafe { 0..(*module_info).modules_count as usize } {
        let image_name = unsafe { (*module_info).modules[i].image_name };
        let image_base = unsafe { (*module_info).modules[i].image_base };

        //log::info!("[+] Module name: {:?} and module base: {:?}", image_name.as_bstr(), image_base);

        if let Some(_) = image_name.find(module_name) {
            //log::info!("[+] Module name: {:?} and module base: {:?}", image_name, image_base);
            p_module = image_base;
            break;
        }
    }

    unsafe { ExFreePool(module_info as u64) };

    return p_module;
}

#[allow(dead_code)]
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

#[allow(dead_code)]
/// Get a pointer to IMAGE_DOS_HEADER
pub unsafe fn get_dos_header(module_base: *mut u8) -> Option<PIMAGE_DOS_HEADER> {
    let dos_header = module_base as PIMAGE_DOS_HEADER;

    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    return Some(dos_header);
}

/// Convert a combo pattern to bytes without wildcards
pub fn get_bytes_as_hex(pattern: &str) -> Result<Vec<Option<u8>>, ()> {
    let mut pattern_bytes = Vec::new();

    for x in pattern.split_whitespace() {
        match x {
            "?" => pattern_bytes.push(None),
            _ => pattern_bytes.push(u8::from_str_radix(x, 16).map(Some).map_err(|_| ())?),
        }
    }

    Ok(pattern_bytes)
}

/// Pattern or Signature scan a region of memory
pub fn pattern_scan(data: &[u8], pattern: &str) -> Result<Option<usize>, ()> {
    let pattern_bytes = get_bytes_as_hex(pattern)?;

    let offset = data.windows(pattern_bytes.len()).position(|window| {
        window
            .iter()
            .zip(&pattern_bytes)
            .all(|(byte, pattern_byte)| pattern_byte.map_or(true, |b| *byte == b))
    });

    Ok(offset)
}

/*
pub fn safe_copy(dest: PVOID, src: PVOID, size: SIZE_T) -> Result<i32, i32> {
    let mut return_size: SIZE_T = 0;

    let status = unsafe {
        MmCopyVirtualMemory(
            PsGetCurrentProcess(),
            src,
            PsGetCurrentProcess(),
            dest,
            size,
            KernelMode,
            &mut return_size,
        )
    };

    if NT_SUCCESS(status) && return_size == size {
        Ok(status)
    } else {
        Err(status)
    }
}
*/
