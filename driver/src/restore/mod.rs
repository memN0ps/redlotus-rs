use core::ptr::{copy_nonoverlapping, null_mut};

use crate::includes::LOCK_OPERATION::IoModifyAccess;
use crate::includes::_MM_PAGE_PRIORITY::HighPagePriority;
use crate::includes::{IoFreeMdl, MmMapLockedPagesSpecifyCache, MmUnlockPages, MmUnmapLockedPages};
use crate::{
    includes::{IoAllocateMdl, MmProbeAndLockPages},
    mapper_data,
};
use kernel_alloc::nt::MEMORY_CACHING_TYPE::MmNonCached;
use winapi::km::wdm::KPROCESSOR_MODE::KernelMode;

pub fn restore_bytes(target_module_entry: *mut u8) {
    log::info!(
        "[+] Target Driver DriverEntry Address: {:p}",
        target_module_entry
    );
    log::info!("[+] Stolen Bytes Address: {:p}", unsafe {
        mapper_data.as_ptr()
    });

    // Restore stolen bytes before we do anything else
    unsafe { memcopywp(target_module_entry) };

    log::info!("[+] Stolen bytes restored");
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
