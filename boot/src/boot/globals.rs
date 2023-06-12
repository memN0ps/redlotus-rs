use core::ffi::c_void;
use uefi::data_types::PhysicalAddress;
extern crate alloc;

// Change accordignly
pub const TARGET_DRIVER_HASH: u32 = 0xf78f291d;   // Disk.sys hash: 0xf78f291d
pub const NTOSKRNL_HASH: u32 = 0xa3ad0390;        // ntoskrnl.exe hash: 0xa3ad0390
pub const MAPPER_DATA_HASH: u32 = 0xd007e143;     // mapper_data hash: 0xd007e143

pub const JMP_SIZE: usize = 14;
pub const MAPPER_DATA_SIZE: usize = JMP_SIZE + 7;
pub static mut ALLOCATED_BUFFER: *mut c_void = core::ptr::null_mut();
pub static mut DRIVER_PHYSICAL_MEMORY: PhysicalAddress = 0;
pub static mut DRIVER_IMAGE_SIZE: u64 = 0;