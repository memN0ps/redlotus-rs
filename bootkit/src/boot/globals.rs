#![allow(non_upper_case_globals)]

use core::ffi::c_void;
use uefi::data_types::PhysicalAddress;
extern crate alloc;

// Change accordignly
pub const TARGET_DRIVER_HASH: u32 = 0xf78f291d; // Disk.sys hash: 0xf78f291d
pub const NTOSKRNL_HASH: u32 = 0xa3ad0390; // ntoskrnl.exe hash: 0xa3ad0390
pub const MAPPER_DATA_HASH: u32 = 0xd007e143; // mapper_data hash: 0xd007e143

// Signatures:
// ImgArchStartBootApplication for Windows 10 and Windows 11
pub const ImgArchStartBootApplicationSignature: &str = "48 8B C4 48 89 58 ? 44 89 40 ? 48 89 50 ? 48 89 48 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 68 A9";

// BlImgAllocateImageBuffer for Windows 10
pub const BlImgAllocateImageBufferSignature_1: &str = "48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC ? 48 8B 31";

// BlImgAllocateImageBuffer for Windows 11
pub const BlImgAllocateImageBufferSignature_2: &str =
    "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC ? 4C 8B 39";

// OslFwpKernelSetupPhase1 for Windows 10
pub const OslFwpKernelSetupPhase1Signature_1: &str =
    "48 89 4C 24 ? 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 E1 48 81 EC ? ? ? ? 48 8B F1";

// OslFwpKernelSetupPhase1 for Windows 11
pub const OslFwpKernelSetupPhase1Signature_2: &str =
    "48 89 4C 24 ? 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 E1 48 81 EC ? ? ? ? 45 33 E4";

pub const JMP_SIZE: usize = 14;
pub const MAPPER_DATA_SIZE: usize = JMP_SIZE + 7;

pub const BL_MEMORY_ATTRIBUTE_RWX: u32 = 0x424000;
pub const BL_MEMORY_TYPE_APPLICATION: u32 = 0xE0000012;

pub static mut ORIGINAL_BYTES: [u8; JMP_SIZE] = [0; JMP_SIZE];
pub static mut ORIGINAL_BYTES_COPY: [u8; JMP_SIZE] = [0; JMP_SIZE];

pub static mut ALLOCATED_BUFFER: *mut c_void = core::ptr::null_mut();
pub static mut DRIVER_PHYSICAL_MEMORY: PhysicalAddress = 0;
pub static mut DRIVER_IMAGE_SIZE: u64 = 0;
