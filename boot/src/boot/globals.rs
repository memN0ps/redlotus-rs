use core::ffi::c_void;
use uefi::data_types::PhysicalAddress;
extern crate alloc;

pub const JMP_SIZE: usize = 14;
pub const MAPPER_DATA_SIZE: usize = JMP_SIZE + 7;
pub static mut ALLOCATED_BUFFER: *mut c_void = core::ptr::null_mut();
pub static mut DRIVER_PHYSICAL_MEMORY: PhysicalAddress = 0;
pub static mut DRIVER_IMAGE_SIZE: u64 = 0;