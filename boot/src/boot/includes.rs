#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
//Credit: https://www.vergiliusproject.com/kernels/x64/Windows%2011/22H2%20(2022%20Update)/_LOADER_PARAMETER_BLOCK
// Some of these structs could be incorrect but most are correct.

use core::ffi::c_void;

//0x10 bytes (sizeof)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct _LIST_ENTRY {
    pub Flink: *mut _LIST_ENTRY, //0x0
    pub Blink: *mut _LIST_ENTRY, //0x8
}

//0x48 bytes (sizeof)
#[repr(C)]
pub struct _CONFIGURATION_COMPONENT_DATA {
    pub Parent: *mut _CONFIGURATION_COMPONENT_DATA,  //0x0
    pub Child: *mut _CONFIGURATION_COMPONENT_DATA,   //0x8
    pub Sibling: *mut _CONFIGURATION_COMPONENT_DATA, //0x10
    pub ComponentEntry: _CONFIGURATION_COMPONENT,    //0x18
    pub ConfigurationData: *mut u8,                  //0x40
}

//0x28 bytes (sizeof)
#[repr(C)]
pub struct _CONFIGURATION_COMPONENT {
    Class: _CONFIGURATION_CLASS,                // 0x0
    Type: _CONFIGURATION_TYPE,                  // 0x4
    Flags: _DEVICE_FLAGS,                       // 0x8
    Version: u16,                               // 0xc
    Revision: u16,                              // 0xe
    Key: u32,                                   // 0x10
    AffinityMask: _CONFIGURATION_AFFINITY_MASK, // 0x14
    ConfigurationDataLength: u32,               // 0x18
    IdentifierLength: u32,                      // 0x1c
    Identifier: *const i8,                      // 0x20
}

//0x4 bytes (sizeof)
#[repr(C)]
union _CONFIGURATION_AFFINITY_MASK {
    pub AffinityMask: u32,
    pub Group: u16,
    pub GroupIndex: u16,
}

//0x4 bytes (sizeof)
#[repr(u32)]
pub enum _CONFIGURATION_CLASS {
    SystemClass = 0,
    ProcessorClass = 1,
    CacheClass = 2,
    AdapterClass = 3,
    ControllerClass = 4,
    PeripheralClass = 5,
    MemoryClass = 6,
    MaximumClass = 7,
}

//0x4 bytes (sizeof)
#[repr(u32)]
pub enum _CONFIGURATION_TYPE {
    ArcSystem = 0,
    CentralProcessor = 1,
    FloatingPointProcessor = 2,
    PrimaryIcache = 3,
    PrimaryDcache = 4,
    SecondaryIcache = 5,
    SecondaryDcache = 6,
    SecondaryCache = 7,
    EisaAdapter = 8,
    TcAdapter = 9,
    ScsiAdapter = 10,
    DtiAdapter = 11,
    MultiFunctionAdapter = 12,
    DiskController = 13,
    TapeController = 14,
    CdromController = 15,
    WormController = 16,
    SerialController = 17,
    NetworkController = 18,
    DisplayController = 19,
    ParallelController = 20,
    PointerController = 21,
    KeyboardController = 22,
    AudioController = 23,
    OtherController = 24,
    DiskPeripheral = 25,
    FloppyDiskPeripheral = 26,
    TapePeripheral = 27,
    ModemPeripheral = 28,
    MonitorPeripheral = 29,
    PrinterPeripheral = 30,
    PointerPeripheral = 31,
    KeyboardPeripheral = 32,
    TerminalPeripheral = 33,
    OtherPeripheral = 34,
    LinePeripheral = 35,
    NetworkPeripheral = 36,
    SystemMemory = 37,
    DockingInformation = 38,
    RealModeIrqRoutingTable = 39,
    RealModePCIEnumeration = 40,
    MaximumType = 41,
}

#[repr(C)]
struct _DEVICE_FLAGS {
    pub Flags: u32, // 0x0
}

impl _DEVICE_FLAGS {
    const FAILED: u32 = 0x1;
    const READ_ONLY: u32 = 0x2;
    const REMOVABLE: u32 = 0x4;
    const CONSOLE_IN: u32 = 0x8;
    const CONSOLE_OUT: u32 = 0x10;
    const INPUT: u32 = 0x20;
    const OUTPUT: u32 = 0x40;

    pub fn is_failed(&self) -> bool {
        self.Flags & Self::FAILED != 0
    }

    pub fn is_read_only(&self) -> bool {
        self.Flags & Self::READ_ONLY != 0
    }

    pub fn is_removable(&self) -> bool {
        self.Flags & Self::REMOVABLE != 0
    }

    pub fn is_console_in(&self) -> bool {
        self.Flags & Self::CONSOLE_IN != 0
    }

    pub fn is_console_out(&self) -> bool {
        self.Flags & Self::CONSOLE_OUT != 0
    }

    pub fn is_input(&self) -> bool {
        self.Flags & Self::INPUT != 0
    }

    pub fn is_output(&self) -> bool {
        self.Flags & Self::OUTPUT != 0
    }
}

//0x18 bytes (sizeof)
#[repr(C)]
pub struct _NLS_DATA_BLOCK {
    pub AnsiCodePageData: *mut u8,     // 0x0
    pub OemCodePageData: *mut u8,      // 0x8
    pub UnicodeCaseTableData: *mut u8, // 0x10
}

//0x10 bytes (sizeof)
#[repr(C)]
pub struct _ARC_DISK_INFORMATION {
    pub DiskSignatures: _LIST_ENTRY, // 0x0
}

// 0x14 bytes (sizeof)
#[repr(C)]
pub struct _LOADER_BLOCK {
    pub I386: Option<_I386_LOADER_BLOCK>, // x86 specific loader block
    pub Arm: Option<_ARM_LOADER_BLOCK>,   // ARM specific loader block
}

// 0x10 bytes (sizeof)
#[repr(C)]
pub struct _I386_LOADER_BLOCK {
    pub CommonDataArea: *mut c_void, // Pointer to common data area
    pub MachineType: u32,            // Machine type
    pub VirtualBias: u32,            // Virtual bias
}

// 0x4 bytes (sizeof)
#[repr(C)]
pub struct _ARM_LOADER_BLOCK {
    pub PlaceHolder: u32, // Placeholder
}

// 0x40 bytes (sizeof)
#[repr(C)]
pub struct _FIRMWARE_INFORMATION_LOADER_BLOCK {
    pub FirmwareTypeUefi: u32,                       // UEFI firmware type
    pub EfiRuntimeUseIum: u32,                       // EFI runtime use IUM
    pub EfiRuntimePageProtectionSupported: u32,      // EFI runtime page protection supported
    pub Reserved: u32,                               // Reserved
    pub u: _FIRMWARE_INFORMATION_LOADER_BLOCK_Union, // Union for firmware information
}

#[repr(C)]
pub struct _FIRMWARE_INFORMATION_LOADER_BLOCK_Union {
    pub EfiInformation: _EFI_FIRMWARE_INFORMATION, // EFI firmware information
    pub PcatInformation: _PCAT_FIRMWARE_INFORMATION, // PCAT firmware information
}

// 0x38 bytes (sizeof)
#[repr(C)]
pub struct _EFI_FIRMWARE_INFORMATION {
    pub FirmwareVersion: u32, // Firmware version
    pub VirtualEfiRuntimeServices: *mut _VIRTUAL_EFI_RUNTIME_SERVICES, // Pointer to virtual EFI runtime services
    pub SetVirtualAddressMapStatus: i32, // Status of virtual address map
    pub MissedMappingsCount: u32,        // Count of missed mappings
    pub FirmwareResourceList: _LIST_ENTRY, // Firmware resource list
    pub EfiMemoryMap: *mut u8,           // Pointer to EFI memory map
    pub EfiMemoryMapSize: u32,           // Size of EFI memory map
    pub EfiMemoryMapDescriptorSize: u32, // Size of EFI memory map descriptor
}

//0x70 bytes (sizeof)
#[repr(C)]
pub struct _VIRTUAL_EFI_RUNTIME_SERVICES {
    pub GetTime: u64,                   // 0x0
    pub SetTime: u64,                   // 0x8
    pub GetWakeupTime: u64,             // 0x10
    pub SetWakeupTime: u64,             // 0x18
    pub SetVirtualAddressMap: u64,      // 0x20
    pub ConvertPointer: u64,            // 0x28
    pub GetVariable: u64,               // 0x30
    pub GetNextVariableName: u64,       // 0x38
    pub SetVariable: u64,               // 0x40
    pub GetNextHighMonotonicCount: u64, // 0x48
    pub ResetSystem: u64,               // 0x50
    pub UpdateCapsule: u64,             // 0x58
    pub QueryCapsuleCapabilities: u64,  // 0x60
    pub QueryVariableInfo: u64,         // 0x68
}

//0x4 bytes (sizeof)
#[repr(C)]
pub struct _PCAT_FIRMWARE_INFORMATION {
    pub PlaceHolder: u32, // 0x0
}

//0x10 bytes (sizeof)
#[repr(C)]
pub struct _RTL_RB_TREE {
    pub Root: *mut _RTL_BALANCED_NODE, // 0x0
    pub Encoded: u8,                   // 0x8 (1 bit)
    pub Min: *mut _RTL_BALANCED_NODE,  // 0x8
}

//0x18 bytes (sizeof)
#[repr(C)]
pub struct _RTL_BALANCED_NODE {
    pub Children: [*mut _RTL_BALANCED_NODE; 2], // 0x0
    pub Left: *mut _RTL_BALANCED_NODE,          // 0x0
    pub Right: *mut _RTL_BALANCED_NODE,         // 0x8
    pub Red: u8,                                // 0x10 (1 bit)
    pub Balance: u8,                            // 0x10 (2 bits)
    pub ParentValue: u64,                       // 0x10
}

//TODO (too big and not required for now)
#[repr(C)]
pub struct _LOADER_PARAMETER_EXTENSION;

//0x170 bytes (sizeof)
#[repr(C)]
pub struct _LOADER_PARAMETER_BLOCK {
    pub OsMajorVersion: u32,                                     //0x00
    pub OsMinorVersion: u32,                                     //0x4
    pub Size: u32,                                               //0x8
    pub OsLoaderSecurityVersion: u32,                            //0xc
    pub LoadOrderListHead: _LIST_ENTRY,                          //0x10
    pub MemoryDescriptorListHead: _LIST_ENTRY,                   //0x20
    pub BootDriverListHead: _LIST_ENTRY,                         //0x30
    pub EarlyLaunchListHead: _LIST_ENTRY,                        //0x40
    pub CoreDriverListHead: _LIST_ENTRY,                         //0x50
    pub CoreExtensionsDriverListHead: _LIST_ENTRY,               //0x60
    pub TpmCoreDriverListHead: _LIST_ENTRY,                      //0x70
    pub KernelStack: u64,                                        //0x80
    pub Prcb: u64,                                               //0x88
    pub Process: u64,                                            //0x90
    pub Thread: u64,                                             //0x98
    pub KernelStackSize: u32,                                    //0xa0
    pub RegistryLength: u32,                                     //0xa4
    pub RegistryBase: *mut u8,                                   //0xa8
    pub ConfigurationRoot: *mut _CONFIGURATION_COMPONENT_DATA,   //0xb0
    pub ArcBootDeviceName: *const i8,                            //0xb8
    pub ArcHalDeviceName: *const i8,                             //0xc0
    pub NtBootPathName: *const i8,                               //0xc8
    pub NtHalPathName: *const i8,                                //0xd0
    pub LoadOptions: *const i8,                                  //0xd8
    pub NlsData: *mut _NLS_DATA_BLOCK,                           //0xe0
    pub ArcDiskInformation: *mut _ARC_DISK_INFORMATION,          //0xe8
    pub Extension: *mut _LOADER_PARAMETER_EXTENSION,             //0xf0
    pub u: _LOADER_BLOCK,                                        //0xf8
    pub FirmwareInformation: _FIRMWARE_INFORMATION_LOADER_BLOCK, //0x108
    pub OsBootstatPathName: *const i8,                           //0x148
    pub ArcOSDataDeviceName: *const i8,                          //0x150
    pub ArcWindowsSysPartName: *const i8,                        //0x158
    pub MemoryDescriptorTree: _RTL_RB_TREE,                      //0x160
}

// 0xa0 bytes (sizeof)
#[repr(C)]
pub struct _KLDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: _LIST_ENTRY,                 // 0x0
    pub ExceptionTable: *const c_void,                 // 0x10
    pub ExceptionTableSize: u32,                       // 0x18
    pub GpValue: *const c_void,                        // 0x20
    pub NonPagedDebugInfo: *mut _NON_PAGED_DEBUG_INFO, // 0x28
    pub DllBase: *const c_void,                        // 0x30
    pub EntryPoint: *const c_void,                     // 0x38
    pub SizeOfImage: u32,                              // 0x40
    pub FullDllName: _UNICODE_STRING,                  // 0x48
    pub BaseDllName: _UNICODE_STRING,                  // 0x58
    pub Flags: u32,                                    // 0x68
    pub LoadCount: u16,                                // 0x6c
    pub SignatureLevel: u16,                           // 0x6e
    pub SectionPointer: *const c_void,                 // 0x70
    pub CheckSum: u32,                                 // 0x78
    pub CoverageSectionSize: u32,                      // 0x7c
    pub CoverageSection: *const c_void,                // 0x80
    pub LoadedImports: *const c_void,                  // 0x88
    pub Spare: *const c_void,                          // 0x90
    pub SizeOfImageNotRounded: u32,                    // 0x98
    pub TimeDateStamp: u32,                            // 0x9c
}

// Unicode string structure
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _UNICODE_STRING {
    pub Length: u16,        // Length of the string
    pub MaximumLength: u16, // Maximum length of the string
    pub Buffer: *mut u16,   // Pointer to the string buffer
}

//0x20 bytes (sizeof)
#[repr(C)]
pub struct _NON_PAGED_DEBUG_INFO {
    pub Signature: u16,       // 0x0
    pub Flags: u16,           // 0x2
    pub Size: u32,            // 0x4
    pub Machine: u16,         // 0x8
    pub Characteristics: u16, // 0xa
    pub TimeDateStamp: u32,   // 0xc
    pub CheckSum: u32,        // 0x10
    pub SizeOfImage: u32,     // 0x14
    pub ImageBase: u64,       // 0x18
}
