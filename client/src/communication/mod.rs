#![allow(non_snake_case)]
use std::{mem::transmute, ptr::null_mut};

use winapi::{
    shared::ntdef::PVOID,
    um::libloaderapi::{GetModuleHandleA, GetProcAddress},
};

type NtConvertBetweenAuxiliaryCounterAndPerformanceCounterType =
    unsafe extern "system" fn(a1: PVOID, a2: PVOID, a3: PVOID, a4: PVOID);
static mut NtConvertBetweenAuxiliaryCounterAndPerformanceCounter: Option<
    NtConvertBetweenAuxiliaryCounterAndPerformanceCounterType,
> = None;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct IMAGE_DATA {
    pub magic: u64,
    pub buffer: Vec<u8>,
}

impl Default for IMAGE_DATA {
    fn default() -> Self {
        IMAGE_DATA {
            magic: 0,
            buffer: Vec::new(),
        }
    }
}
pub struct Communication;

impl Communication {
    pub fn new() -> Result<Self, String> {
        let ntdll_handle = unsafe { GetModuleHandleA(b"ntdll.dll\0".as_ptr() as _) };

        if ntdll_handle.is_null() {
            return Err("[-] Failed to get ntdll handle".to_owned());
        }

        let proc_address = unsafe {
            GetProcAddress(
                ntdll_handle,
                b"NtConvertBetweenAuxiliaryCounterAndPerformanceCounter\0".as_ptr() as _,
            )
        };

        if proc_address.is_null() {
            return Err("[-] Failed to GetProcAddress".to_owned());
        }

        unsafe {
            NtConvertBetweenAuxiliaryCounterAndPerformanceCounter = Some(transmute::<
                _,
                NtConvertBetweenAuxiliaryCounterAndPerformanceCounterType,
            >(proc_address))
        };

        Ok(Self)
    }

    pub fn send_request(&self, mut image_data: &mut IMAGE_DATA) -> Result<i32, String> {
        let mut status = 0i32;

        let Some(pNtConvertBetweenAuxiliaryCounterAndPerformanceCounter) = (unsafe { NtConvertBetweenAuxiliaryCounterAndPerformanceCounter.take() }) else {
            return Err("[-] Failed to takes the value out of the option NtConvertBetweenAuxiliaryCounterAndPerformanceCounter".to_owned());
        };

        unsafe {
            pNtConvertBetweenAuxiliaryCounterAndPerformanceCounter(
                null_mut(),
                &mut image_data as *mut _ as *mut _,
                &mut status as *mut _ as *mut _,
                null_mut(),
            )
        };

        return Ok(status);
    }
}
