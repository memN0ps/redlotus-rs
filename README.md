# A UEFI Bootkit in Rust

**Note: This project is incomplete and work is in progress (W.I.P).**

While it's possible to use this for advanced adversary simulation or emulation (red teaming), it's unlikely to be used in most engagements. This tool can also be used for game hacking and is a side project for those interested in fun, learning, malware research, and spreading security awareness. It also demonstrates that Rust can handle both low-level and high-level tasks. One important capability of this tool is its ability to load a kernel driver before the operating system, or even execute shellcode in the kernel to bypass Windows security protections. It's important to recognize the potential of Rust and not underestimate its power. 

Feel free to check out my Windows Kernel Rootkit and Blue Pill Hypervisor in pure Rust: 

* https://github.com/memN0ps/rootkit-rs
* https://github.com/memN0ps/hypervisor-rs

This project is mostly inspired by:

* [BlackLotus UEFI Bootkit](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)

* [ESPecter Bootkit](https://www.welivesecurity.com/2021/10/05/uefi-threats-moving-esp-introducing-especter-bootkit/)

* [Rootkits and Bootkits by Alex Matrosov (matrosov)](https://nostarch.com/rootkits)

* [umap by btbd](https://github.com/btbd/umap/)

* [UEFI-Bootkit by  Aidan Khoury (ajkhoury)](https://github.com/ajkhoury/UEFI-Bootkit/)

* [EfiGuard by Matthijs Lavrijsen (Mattiwatti)](https://github.com/Mattiwatti/EfiGuard)

* [Secret Club's article on Bootkitting Windows Sandbox by mrexodia](https://secret.club/2022/08/29/bootkitting-windows-sandbox.html)

* [bootlicker by Austin Hudson (realoriginal / ilove2pwn_ / secidiot / mumbai) ](https://github.com/realoriginal/bootlicker)


## Features 

TODO

## Description

A kernel driver can be loaded during boot using a bootkit. A bootkit can run code before the operating system and potentially inject malicious code into the kernel or load a malicious kernel driver by infecting the boot process and taking over the system's firmware or bootloader.

The image below shows how Legacy and UEFI boot works.

![Legacy-and-UEFI-Boot](/images/Legacy-and-UEFI-Boot.png)
**Figure 1. Comparison of the Legacy Boot flow (left) and UEFI boot flow (right) on Windows (Vista and newer) systems (Full Credits: [WeLiveSecurity](https://www.welivesecurity.com/2021/10/05/uefi-threats-moving-esp-introducing-especter-bootkit/))**


1. There are a few ways to achieve the same objective as shown below:

a) Hook/detour `Archpx64TransferTo64BitApplicationAsm` in `bootmgfw.efi` (Windows OS loader), which transfers execution to the OS loader (`winload.efi`) or 

b) `ImgArchStartBootApplication` to catch the moment when the Windows OS loader (`winload.efi`) is loaded in the memory but still has not been executed or

c) Hook/Detour `ExitBootServices`, which is UEFI firmware service that signals the end of the boot process and transitions the system from the firmware environment to the operating system environment.
    
    1.2. The following is required if UEFI Secure Boot is enabled:

    - Patch `BmFwVerifySelfIntegrity` to bypass self integrity checks.
    - Execute `bcdedit /set {bootmgr} nointegritychecks on` to skip the integrity checks.
    - Inject `bcdedit /set {bootmgr} nointegritychecks on` option dynamically by modifying the `LoadOptions`.

    1.3. The following is required to allocate an additional memory buffer for the malicious kernel driver, because as a UEFI Application it will be unloaded from memory after returning from its entry point function.
    
    - `BlImgAllocateImageBuffer` or `BlMmAllocateVirtualPages` in the Windows OS loader (`winload.efi`).

2. Hook/detour `OslArchTransferToKernel` in `winload.efi` (Windows OS loader), which transfers execution to the Windows Kernel (`ntoskrnl.exe`) to catch the moment when the OS kernel and some of the system drivers are already loaded in the memory, but still haven’t been executed, which is a perfect moment to perform more in-memory patching.
    
    - Patch `SepInitializeCodeIntegrity`, a parameter to `CiInitialize` in `ntoskrnl.exe` to disable Driver Signature Enforcement (DSE).
    - Patch `KeInitAmd64SpecificState` in `ntoskrnl.exe` to disable PatchGuard.


## Usage

A UEFI Bootkit works under one or more of the following conditions:

a) Secure boot must be off 

b) Install your secure boot keys

c) Bring your vulnerable binary (BYOVB) that is not in the "deny list." to exploit a 1-day to bypass secure boot.

d) Exploit a 0-day to bypass secure boot.

### Usage 1: Infect Windows Boot Manager `bootmgfw.efi` on Disk (Unsupported)

Typically UEFI Bootkits infect the Windows Boot Manager `bootmgfw.efi` located in EFI partition `\EFI\Microsoft\Boot\bootmgfw.efi` or `C:\Windows\Boot\EFI\bootmgfw.efi` as shown below:

- Convert our bootkit to shellcode
- Find `bootmgfw.efi` (Windows Boot Manager)
- Add `.efi` section to `bootmgfw.efi` (Windows Boot Manager)
- Inject/copy bootkit shellcode.
- Change entry point of the `bootmgfw.efi` (Windows Boot Manager) to `.efi` bootkit shellcode
- Reboot

### Usage 2: Execute UEFI Bootkit via UEFI Shell (Supported)

0. Compile the project

```
cargo build --target x86_64-unknown-uefi
```

Download [EDK2 efi shell](https://github.com/tianocore/edk2/releases) or [UEFI-Shell](https://github.com/pbatard/UEFI-Shell/releases) and follow these steps:

1. Extract downloaded efi shell and rename file `Shell.efi` (should be in folder `UefiShell/X64`) to `bootx64.efi`

2. Format some USB drive to FAT32

3. Create following folder structure:

```
USB:.
 │   bootkit.efi
 │
 └───EFI
      └───Boot
              bootx64.efi
```

4. Boot from the USB drive

    * VMware Workstation: `VM -> Settings -> Hardware -> Add -> Hard Disk -> Next -> SCSI or NVMe (Recommended) -> Next -> Use a physical disk (for advanced users) -> Next -> Device: PhysicalDrive1 and Usage: Use entire disk -> Next -> Finish.` 

    * Start VM by clicking `Power On to Firmware`

    * Select Internal Shell (Unsupported option) or EFI Vmware Virtual SCSI Hard Drive (1.0)

5. An UEFI shell should start, change directory to your USB (`FS1` should be the USB since we are booting from it) and list files:

```
FS1:
ls
```

6. You should see file `bootkit.efi`, if you do, load it:

```
bootkit.efi
```

7. Now you should see output from the bootkit.efi application. If it is successful, Windows should boot automatically otherwise, exit and boot into Windows (change to Windows boot media - usually `FS0` - and run `\EFI\Microsoft\Boot\bootmgfw.efi` or `\EFI\Boot\bootx64.efi`)


## Credits / References / Thanks / Motivation

Special thanks to [btbd](https://github.com/btbd), [ajkhoury](https://github.com/ajkhoury), [Mattiwatti](https://github.com/Mattiwatti), [mrexodia](https://github.com/mrexodia), [SamuelTulach](https://github.com/SamuelTulach), [realoriginal](https://github.com/realoriginal), [Cr4sh](https://github.com/Cr4sh), [matrosov](https://github.com/matrosov), [not-matthias](https://github.com/not-matthias) and [welivesecurity](https://www.welivesecurity.com/)

* https://github.com/btbd/umap/

* https://github.com/ajkhoury/UEFI-Bootkit/

* https://github.com/Mattiwatti/EfiGuard

* https://secret.club/2022/08/29/bootkitting-windows-sandbox.html

* https://github.com/SamuelTulach/rainbow

* https://www.unknowncheats.me/forum/anti-cheat-bypass/452202-rainbow-efi-bootkit-hwid-spoofer-smbios-disk-nic.html

* https://github.com/realoriginal/bootlicker

* https://github.com/Cr4sh/s6_pcie_microblaze/tree/master/python/payloads/DmaBackdoorBoot

* Rootkits and Bootkits: https://nostarch.com/rootkits by [Alex Matrosov](https://twitter.com/matrosov)

* https://www.welivesecurity.com/2021/10/05/uefi-threats-moving-esp-introducing-especter-bootkit/

* https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/

* https://github.com/rust-osdev/uefi-rs

* https://github.com/rust-osdev/bootloader

* https://crates.io/crates/uefi

* https://docs.rs/uefi/latest/

* https://rust-osdev.github.io/uefi-rs/HEAD/

* https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcd-system-store-settings-for-uefi?view=windows-11

* https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/

* https://github.com/LongSoft/UEFITool

* https://github.com/tianocore/edk2

* https://github.com/pbatard/UEFI-Shell

* https://securelist.com/cosmicstrand-uefi-firmware-rootkit/106973/

* https://github.com/nix-community/lanzaboote/

* https://wikileaks.org/ciav7p1/cms/page_36896783.html