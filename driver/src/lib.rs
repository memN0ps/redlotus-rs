#![no_std]

use kernel_log::KernelLogger;
use log::LevelFilter;
use winapi::{km::wdm::{DRIVER_OBJECT}, shared::{ntdef::{UNICODE_STRING, NTSTATUS}, ntstatus::{STATUS_SUCCESS}}};

#[no_mangle]
pub extern "system" fn __CxxFrameHandler3(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8) -> i32 { unimplemented!() }

#[global_allocator]
static GLOBAL: kernel_alloc::KernelAlloc = kernel_alloc::KernelAlloc;

#[export_name = "_fltused"]
static _FLTUSED: i32 = 0;

#[allow(unused_imports)]
use core::panic::PanicInfo;
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! { loop {} }


#[no_mangle]
pub extern "system" fn driver_entry(_driver: &mut DRIVER_OBJECT, _: &UNICODE_STRING) -> NTSTATUS {
    KernelLogger::init(LevelFilter::Info).expect("Failed to initialize logger");
    log::info!("Driver Entry called");

    //driver.DriverUnload = Some(driver_unload);

    STATUS_SUCCESS
}

// When manually mapping a driver this is not required.
/* 
pub extern "system" fn driver_unload(_driver: &mut DRIVER_OBJECT) {
    log::info!("Driver unloaded successfully!");
}
*/