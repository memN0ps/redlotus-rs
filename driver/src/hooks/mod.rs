use alloc::vec::Vec;
extern crate alloc;
use includes::ExGetPreviousMode;
use mapper::manually_map;
use winapi::{
    km::wdm::KPROCESSOR_MODE::UserMode,
    shared::{
        ntdef::NTSTATUS,
        ntstatus::{STATUS_ACCESS_VIOLATION, STATUS_NO_MEMORY, STATUS_SUCCESS},
    },
};

use core::slice::from_raw_parts;

use crate::{
    includes::{self, ExAllocatePool, ExFreePool, NonPagedPool},
    mapper::{self, get_nt_headers},
    pe::{get_module_base, pattern_scan},
};

type HalDispatchType = fn(image_data: *mut IMAGE_DATA, out_status: *mut i32) -> NTSTATUS;

static mut HalDispatchOriginal: Option<HalDispatchType> = None;

pub fn setup_hooks() {
    // Get the base address of the Windows kernel (ntoskrnl.exe)
    let ntoskrnl_address = get_module_base(b"ntoskrnl.exe");
    let nt_headers =
        unsafe { get_nt_headers(ntoskrnl_address as _).expect("Failed to get kernel nt headers") };
    let ntoskrnl_size = unsafe { (*nt_headers).OptionalHeader.SizeOfImage };

    log::info!(
        "[+] ntoskrnl.exe address: 0x{:x}",
        ntoskrnl_address as usize
    );
    log::info!("[+] ntoskrnl.exe size: 0x{:x}", ntoskrnl_size);

    // Read Windows kernel (ntoskrnl.exe) from memory and store in a slice
    let kernel_data =
        unsafe { from_raw_parts(ntoskrnl_address as *mut u8, ntoskrnl_size as usize) };
    log::info!("[+] Attempting to scan for xKdEnumerateDebuggingDevices .data ptr");

    /*.data ptr inside NtConvertBetweenAuxiliaryCounterAndPerformanceCounter():
        PAGE:00000001409F7AC4 48 8B 05 75 A2 20 00                          mov     rax, cs:off_140C01D40
        PAGE:00000001409F7ACB E8 80 29 A3 FF                                call    _guard_dispatch_icall

        Math:
        RIP: 0x1409F7AC4
        OFFSET = 0x20A275
        INSTRUCTION_SIZE size = 0x7
        RIP + INSTRUCTION_SIZE + OFFSET = 0x140C01D40
    */

    // Look for the xKdEnumerateDebuggingDevices .data ptr signature in Windows kernel (ntoskrnl.exe) and return an offset
    let rip = pattern_scan(kernel_data, "48 8B 05 ? ? ? ? E8 80 29 A3 FF")
        .expect("Failed to pattern scan")
        .expect("Failed to find xKdEnumerateDebuggingDevices offset") as *mut usize;

    log::info!(
        "[+] xKdEnumerateDebuggingDevices .data ptr signature RIP: {:p}",
        rip
    );

    let absolute_rip_addy = (ntoskrnl_address as usize + rip as usize) as *mut u8;
    log::info!(
        "[+] xKdEnumerateDebuggingDevices .data ptr signature absolute address: 0x{:x}",
        absolute_rip_addy as usize
    );

    // Read the offset from rip + 3
    let absolute_rip_plus3_addy = unsafe { absolute_rip_addy.add(3) };
    log::info!(
        "[+] xKdEnumerateDebuggingDevices .data ptr RIP + 3 {:p}",
        absolute_rip_plus3_addy
    );

    // Read 4 bytes after absolute_rip_addy + 3
    let offset_slice = unsafe { from_raw_parts(absolute_rip_plus3_addy, 4) };
    //log::info!("[+] xKdEnumerateDebuggingDevices .data ptr offset slice: {:#x?}", offset_slice);

    // Create a native endian integer value from its representation as a byte array in little endian.
    let offset = u32::from_le_bytes(
        offset_slice[..4]
            .try_into()
            .expect("slice with incorrect length"),
    );
    //log::info!("[+] xKdEnumerateDebuggingDevices .data ptr OFFSET: {:#x}", offset);

    let instruction_size = 7;

    let final_offset = rip as usize + instruction_size as usize + offset as usize;
    log::info!(
        "[+] xKdEnumerateDebuggingDevices .data ptr final OFFSET: {:#x}",
        final_offset
    );

    // Get the absolute address
    let hal_dispatch_table_address = (ntoskrnl_address as usize + final_offset) as *mut u8;
    log::info!(
        "[+] HalDispatchTable .data ptr absolute address: {:p}",
        hal_dispatch_table_address
    );
    log::info!(
        "[+] HalDispatchHook absolute address: {:#p}",
        HalDispatchHook as *mut () as *mut u64
    );

    // Save it for later
    unsafe {
        HalDispatchOriginal = Some(core::mem::transmute::<_, HalDispatchType>(
            hal_dispatch_table_address,
        ))
    };

    // .data ptr hook
    unsafe {
        hal_dispatch_table_address
            .cast::<*mut u64>()
            .write(HalDispatchHook as *mut () as *mut u64)
    };

    // We should be using interlocked_exchange_pointer instead of the above, but could not get it to work.
    /*
    let hal_dispatch_ptr = core::sync::atomic::AtomicPtr::new(hal_dispatch_table_address as *mut u64);
    let old_value = interlocked_exchange_pointer(&hal_dispatch_ptr, HalDispatchHook as *mut () as *mut u64);
    */
}

#[allow(dead_code)]
fn interlocked_exchange_pointer(
    target: &core::sync::atomic::AtomicPtr<u64>,
    value: *mut u64,
) -> *mut u64 {
    target.swap(value, core::sync::atomic::Ordering::SeqCst)
}

pub fn HalDispatchHook(image_data: *mut IMAGE_DATA, out_status: *mut i32) -> NTSTATUS {
    log::info!("HalDispatchHook called");

    if unsafe { ExGetPreviousMode() } as u8 != UserMode as u8 {
        log::info!("[-] ExGetPreviousMode is not user mode");
        return unsafe { HalDispatchOriginal.unwrap()(image_data as _, out_status) };
    }

    if image_data.is_null() {
        log::info!("[-] Image data is null");
        return unsafe { HalDispatchOriginal.unwrap()(image_data as _, out_status) };
    }

    log::info!("[+] IMAGE_DATA Magic: {:#x}", unsafe {
        (*image_data).magic
    });
    log::info!("[+] IMAGE_DATA Buffer ptr: {:#p}", unsafe {
        (*image_data).buffer.as_ptr()
    });

    if unsafe { (*image_data).magic } != 0xdeadbeef {
        log::info!("[-] Magic value is does not match");
        return unsafe { HalDispatchOriginal.unwrap()(image_data as _, out_status) };
    }

    log::info!("[+] Allocating kernel buffer");

    let unmapped_driver_kernel_buffer =
        unsafe { ExAllocatePool(NonPagedPool, (*image_data).buffer.len()) };

    if unmapped_driver_kernel_buffer.is_null() {
        log::info!("[-] Failed to call ExAllocatePool");
        unsafe { *out_status = STATUS_NO_MEMORY };
        return STATUS_SUCCESS;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(
            (*image_data).buffer.as_mut_ptr(),
            unmapped_driver_kernel_buffer as _,
            (*image_data).buffer.len(),
        )
    };

    log::info!(
        "[+] Unmapped Driver Address: {:p}",
        unmapped_driver_kernel_buffer
    );

    // Manually map the driver and call driver entry and return the status
    let Some(status) = (unsafe { manually_map(unmapped_driver_kernel_buffer as _) }) else {
        log::info!("[-] Failed to manually map kernel driver");
        unsafe { ExFreePool(unmapped_driver_kernel_buffer as _) };
        unsafe { *out_status = STATUS_ACCESS_VIOLATION };
        return STATUS_SUCCESS;
    };

    log::info!("Done!");
    log::info!("[+] Freeing unmapped driver memory");
    unsafe { ExFreePool(unmapped_driver_kernel_buffer as _) };
    unsafe { *out_status = status };

    log::info!("[+] HalDispatchHook ended!");
    return STATUS_SUCCESS;
}

// Change if changed in driver communication
#[repr(C)]
#[derive(Debug, Clone)]
pub struct IMAGE_DATA {
    pub magic: u64,
    pub buffer: Vec<u8>,
}

impl Default for IMAGE_DATA {
    fn default() -> Self {
        IMAGE_DATA {
            magic: 0,
            buffer: Vec::new(),
        }
    }
}
