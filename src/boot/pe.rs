use core::slice::from_raw_parts;
use super::includes::{_KLDR_DATA_TABLE_ENTRY, _LOADER_PARAMETER_BLOCK, _LIST_ENTRY};

pub unsafe fn get_loaded_module_by_hash(loaded_block: *mut _LOADER_PARAMETER_BLOCK, module_hash: u32) -> Option<(*mut u8, u32)>
{
    let load_order_list_head = unsafe { &(*loaded_block).LoadOrderListHead as *mut _LIST_ENTRY };
    let mut module_list = load_order_list_head.Flink as *mut _KLDR_DATA_TABLE_ENTRY;

    while !(*module_list).DllBase.is_null() 
    {
        let dll_buffer_ptr = (*module_list).BaseDllName.Buffer;
        let dll_length = (*module_list).BaseDllName.Length as usize;
        let dll_name_slice = from_raw_parts(dll_buffer_ptr as *const u8, dll_length);

        if module_hash == dbj2_hash(dll_name_slice) 
        {
            return Some(((*module_list).DllBase as _, (*module_list).SizeOfImage));
        }

        module_list = (*module_list).InLoadOrderLinks.Flink as *mut _KLDR_DATA_TABLE_ENTRY;
    }

    return None;
}

pub fn dbj2_hash(buffer: &[u8]) -> u32 
{
    let mut hash: u32 = 5381;
    let mut i: usize = 0;
    let mut char: u8;

    while i < buffer.len() 
    {
        char = buffer[i];
        
        if char == 0 
        {
            i += 1;
            continue;
        }
        
        if char >= ('a' as u8) 
        {
            char -= 0x20;
        }

        hash = ((hash << 5).wrapping_add(hash)) + char as u32;
        i += 1;
    }

    return hash;
}