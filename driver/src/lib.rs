#![no_std]
use winapi::{
    km::wdm::DRIVER_OBJECT,
    shared::ntdef::{NTSTATUS, UNICODE_STRING},
};
mod includes;
mod restore;

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

#[allow(unused_imports)]
use core::panic::PanicInfo;

use crate::restore::magic;
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[allow(non_camel_case_types)]
type DriverEntryType =
    fn(driver_object: &mut DRIVER_OBJECT, registry_path: &UNICODE_STRING) -> NTSTATUS;

#[allow(non_upper_case_globals)]
static mut DriverEntry: Option<DriverEntryType> = None;

#[no_mangle]
pub extern "system" fn driver_entry(
    driver_object: &mut DRIVER_OBJECT,
    registry_path: &UNICODE_STRING,
    target_module_entry: *mut u8,
) -> NTSTATUS {
    // When manually mapping a driver you don't call driver_unload. You restart the system instead.
    /* Restore execution flow and hooked functions */
    magic(target_module_entry);

    /* Your code goes here ( Do the other kernel magic below) */

    /* End of your code (Do the other kernel magic above) */

    log::info!("Calling Unhooked DriverEntry....");
    // Call the original driver entry to restore execution flow (target driver)
    unsafe {
        DriverEntry = Some(core::mem::transmute::<*mut u8, DriverEntryType>(
            target_module_entry,
        ))
    };
    return unsafe { DriverEntry.unwrap()(driver_object, registry_path) };
}
