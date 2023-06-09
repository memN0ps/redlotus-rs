#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use kernel_alloc::nt::MEMORY_CACHING_TYPE;
use winapi::{shared::{ntdef::{PVOID, BOOLEAN, CSHORT}, minwindef::ULONG}, km::wdm::{PIRP, KPROCESSOR_MODE, PEPROCESS}};

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
}

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
