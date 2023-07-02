#![no_std]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate alloc;
use kernel_log::KernelLogger;
use log::LevelFilter;
use winapi::{
    km::wdm::DRIVER_OBJECT,
    shared::{
        ntdef::{NTSTATUS, UNICODE_STRING},
        ntstatus::STATUS_SUCCESS,
    },
};

#[no_mangle]
pub extern "system" fn __CxxFrameHandler3(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8) -> i32 {
    unimplemented!()
}

#[global_allocator]
static GLOBAL: kernel_alloc::KernelAlloc = kernel_alloc::KernelAlloc;

#[export_name = "_fltused"]
static _FLTUSED: i32 = 0;

#[allow(unused_imports)]
use core::panic::PanicInfo;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "system" fn driver_entry(
    _driver_object: &mut DRIVER_OBJECT,
    _registry_path: &UNICODE_STRING,
) -> NTSTATUS {
    KernelLogger::init(LevelFilter::Info).expect("Failed to initialize logger");
    log::info!("Driver loaded successfully!");
    log::info!("Hello from testing123.sys");

    //_driver_object.DriverUnload = Some(driver_unload);

    return STATUS_SUCCESS;
}

/*
// When manually mapping a driver you don't call driver_unload. You restart the system instead.
pub extern "system" fn driver_unload(_driver: &mut DRIVER_OBJECT) {
    log::info!("Driver unloaded successfully!");
}
*/
