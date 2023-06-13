use core::ptr::{copy_nonoverlapping, null_mut};

use crate::includes::LOCK_OPERATION::IoModifyAccess;
use crate::includes::_MM_PAGE_PRIORITY::HighPagePriority;
use kernel_alloc::nt::MEMORY_CACHING_TYPE::MmNonCached;
use kernel_log::KernelLogger;
use log::LevelFilter;
use winapi::km::wdm::KPROCESSOR_MODE::KernelMode;

use crate::includes::{IoFreeMdl, MmMapLockedPagesSpecifyCache, MmUnlockPages, MmUnmapLockedPages};
use crate::{
    includes::{IoAllocateMdl, MmProbeAndLockPages},
    mapper_data,
};

pub fn restore_bytes(target_module_entry: *mut u8) {
    KernelLogger::init(LevelFilter::Info).expect("Failed to initialize logger");

    log::info!("[+] Driver Entry called");
    log::info!(
        "[+] Target Driver DriverEntry Address: {:p}",
        target_module_entry
    );
    log::info!("[+] Stolen Bytes Address: {:p}", unsafe {
        mapper_data.as_ptr()
    });

    /* Force to 1 CPU */
    //unsafe { KeSetSystemAffinityThread(1) };

    /* Remove write protection */
    // Credits Austin Hudson: https://github.com/realoriginal/bootlicker/blob/master/bootkit/DrvMain.c#L116
    //log::info!("[+] Write protection removed");
    //disable_write_protect();

    // Restore stolen bytes before we do anything else
    unsafe { memcopywp(target_module_entry) };

    log::info!("[+] Stolen bytes restored");

    /* Insert write protection */
    // Credits Austin Hudson: https://github.com/realoriginal/bootlicker/blob/master/bootkit/DrvMain.c#L128
    //log::info!("[+] Write protection restored");
    //enable_write_protect();
}

/// Credits: btbd's umap: https://github.com/btbd/umap/blob/master/mapper/util.c#L117
pub unsafe fn memcopywp(target_module_entry: *mut u8) -> Option<()> {
    let mdl = IoAllocateMdl(
        target_module_entry as _,
        mapper_data.len() as u32,
        0,
        0,
        null_mut(),
    );

    if mdl.is_null() {
        log::info!("[-] Failed to call IoAllocateMdl");
        return None;
    }

    MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);

    let mapped = unsafe {
        MmMapLockedPagesSpecifyCache(
            mdl,
            KernelMode,
            MmNonCached,
            null_mut(),
            0,
            HighPagePriority as _,
        )
    };

    if mapped.is_null() {
        log::info!("[-] Failed to call MmMapLockedPagesSpecifyCache");
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return None;
    }

    copy_nonoverlapping(mapper_data.as_ptr(), mapped as _, mapper_data.len());

    MmUnmapLockedPages(mapped, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);

    Some(())
}
