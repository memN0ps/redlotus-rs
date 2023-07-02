#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use kernel_alloc::nt::MEMORY_CACHING_TYPE;
use winapi::{
    ctypes::c_void,
    km::wdm::{KPROCESSOR_MODE, PEPROCESS, PIRP},
    shared::{
        minwindef::{PULONG, ULONG},
        ntdef::{BOOLEAN, CSHORT, NTSTATUS, PVOID},
    },
};

#[link(name = "ntoskrnl")]
extern "system" {
    /// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kesetsystemaffinitythread
    /// The KeSetSystemAffinityThread routine sets the system affinity of the current thread.
    pub fn KeSetSystemAffinityThread(Affinity: usize);

    /// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioallocatemdl
    /// The IoAllocateMdl routine allocates a memory descriptor list (MDL) large enough to map a buffer,
    /// given the buffer's starting address and length. Optionally, this routine associates the MDL with an IRP.
    pub fn IoAllocateMdl(
        VirtualAddress: PVOID,
        Length: ULONG,
        SecondaryBuffer: BOOLEAN,
        ChargeQuota: BOOLEAN,
        Irp: PIRP,
    ) -> PMDL;

    /// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages
    /// The MmProbeAndLockPages routine probes the specified virtual memory pages, makes them resident,
    /// and locks them in memory (say for a DMA transfer).
    /// This ensures the pages cannot be freed and reallocated while a device driver (or hardware) is still using them.
    pub fn MmProbeAndLockPages(
        MemoryDescriptorList: *mut MDL,
        AccessMode: KPROCESSOR_MODE,
        Operation: LOCK_OPERATION,
    );

    /// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmmaplockedpagesspecifycache?source=recommendations
    /// The MmMapLockedPagesSpecifyCache routine maps the physical pages that are described by an MDL to a virtual address,
    /// and enables the caller to specify the cache attribute that is used to create the mapping.
    pub fn MmMapLockedPagesSpecifyCache(
        MemoryDescriptorList: PMDL,
        AccessMode: KPROCESSOR_MODE,
        CacheType: MEMORY_CACHING_TYPE,
        RequestedAddress: PVOID,
        BugCheckOnFailure: ULONG,
        Priority: ULONG,
    ) -> PVOID;

    /// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmunmaplockedpages
    /// The MmUnmapLockedPages routine releases a mapping that was set up by a preceding call to the
    /// MmMapLockedPages or MmMapLockedPagesSpecifyCache routine.
    pub fn MmUnmapLockedPages(BaseAddress: PVOID, MemoryDescriptorList: PMDL);

    /// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmunlockpages
    /// The MmUnlockPages routine unlocks the physical pages that are described by the specified memory descriptor list (MDL).
    pub fn MmUnlockPages(MemoryDescriptorList: PMDL);

    /// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iofreemdl
    /// The IoFreeMdl routine releases a caller-allocated memory descriptor list (MDL).
    pub fn IoFreeMdl(Mdl: PMDL);

    /// https://learn.microsoft.com/en-us/windows/win32/sysinfo/zwquerysysteminformation
    /// Retrieves the specified system information.
    pub fn ZwQuerySystemInformation(
        system_information_class: SystemInformationClass,
        system_information: PVOID,
        system_information_length: ULONG,
        return_length: PULONG,
    ) -> NTSTATUS;

    /// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exgetpreviousmode
    pub fn ExGetPreviousMode() -> KPROCESSOR_MODE;

    /// Undocumented
    pub fn PsGetCurrentProcess() -> PEPROCESS;

    /// Undocumented
    pub fn MmCopyVirtualMemory(
        from_process: PEPROCESS,
        from_address: *mut c_void,
        to_process: PEPROCESS,
        to_address: *mut c_void,
        size: usize,
        previous_mode: KPROCESSOR_MODE,
        bytes_copied: &mut usize,
    ) -> NTSTATUS;

    /// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepool
    pub fn ExAllocatePool(pool_type: POOL_TYPE, number_of_bytes: usize) -> *mut u64;

    /// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exfreepool
    pub fn ExFreePool(pool: u64);
}

// Credits: https://github.com/microsoft/windows-rs/blob/a817607f4a48c891e4d598b40b8685c59d18743b/crates/libs/sys/src/Windows/Wdk/Foundation/mod.rs#L60
// https://www.vergiliusproject.com/kernels/x64/Windows%2011/22H2%20(2022%20Update)/_POOL_TYPE
pub type POOL_TYPE = i32;
pub const NonPagedPool: POOL_TYPE = 0i32;
pub const NonPagedPoolExecute: POOL_TYPE = 0i32;
pub const PagedPool: POOL_TYPE = 1i32;

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LOCK_OPERATION {
    IoReadAccess = 0,
    IoWriteAccess = 1,
    IoModifyAccess = 2,
}

#[repr(C)]
#[derive(Debug)]
pub struct _MDL {
    pub Next: *mut _MDL,
    pub Size: CSHORT,
    pub MdlFlags: CSHORT,
    pub Process: PEPROCESS,
    pub MappedSystemVa: PVOID,
    pub StartVa: PVOID,
    pub ByteCount: ULONG,
    pub ByteOffset: ULONG,
}

pub type MDL = _MDL;
pub type PMDL = *mut _MDL;

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum _MM_PAGE_PRIORITY {
    LowPagePriority = 0,
    NormalPagePriority = 16,
    HighPagePriority = 32,
}

#[repr(C)]
pub enum SystemInformationClass {
    SystemModuleInformation = 11,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SystemModuleInformation {
    pub modules_count: u32,
    pub modules: [SystemModule; 256],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SystemModule {
    pub section: *mut c_void,
    pub mapped_base: *mut c_void,
    pub image_base: *mut c_void,
    pub size: u32,
    pub flags: u32,
    pub index: u8,
    pub name_length: u8,
    pub load_count: u8,
    pub path_length: u8,
    pub image_name: [u8; 256],
}
