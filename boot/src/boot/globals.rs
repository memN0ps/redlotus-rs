use uefi::data_types::PhysicalAddress;

pub static mut DRIVER_MEMORY: Option<PhysicalAddress> = None;