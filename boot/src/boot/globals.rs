use core::ffi::c_void;
use uefi::data_types::PhysicalAddress;
extern crate alloc;

pub static mut ALLOCATED_BUFFER: *mut c_void = core::ptr::null_mut();
pub static mut DRIVER_PHYSICAL_MEMORY: PhysicalAddress = 0;
pub static mut DRIVER_IMAGE_SIZE: u64 = 0;