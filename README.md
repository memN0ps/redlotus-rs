# A UEFI Bootkit in Rust

**Note: This project is incomplete and work is in progress (W.I.P). A lot of things could be incorrect until this is complete.**

While it's possible to use this for advanced adversary simulation or emulation (red teaming), it's unlikely to be used in most engagements. This tool can also be used for game hacking and is a side project for those interested in fun, learning, malware research, and spreading security awareness. It also demonstrates that Rust can handle both low-level and high-level tasks. One important capability of this tool is its ability to load a kernel driver before the operating system, or even execute shellcode in the kernel to bypass Windows security protections. It's important to recognize the potential of Rust and not underestimate its power. 

Feel free to check out my Windows Kernel Rootkit and Blue Pill Hypervisor in pure Rust: 

* https://github.com/memN0ps/rootkit-rs
* https://github.com/memN0ps/hypervisor-rs

## Features

* Manually Map a Windows kernel driver and/or blue-pill (type-2) hypervisor driver (TODO)

## Description

A bootkit can run code before the operating system and potentially inject malicious code into the kernel or load a malicious kernel driver by infecting the boot process and taking over the system's firmware or bootloader, effectively disabling or bypassing security protections.

The image below shows how Legacy and UEFI boot works.

![Legacy-and-UEFI-Boot](/images/Legacy-and-UEFI-Boot.png)
**Figure 1. Comparison of the Legacy Boot flow (left) and UEFI boot flow (right) on Windows (Vista and newer) systems (Full Credits: [WeLiveSecurity](https://www.welivesecurity.com/2021/10/05/uefi-threats-moving-esp-introducing-especter-bootkit/))**


1. AFAIK there are a few ways to achieve the same objective as shown below:

    - Hook/detour `Archpx64TransferTo64BitApplicationAsm` in `bootmgfw.efi` (Windows OS loader), which transfers execution to the OS loader (`winload.efi`) or 

    - `ImgArchStartBootApplication` to catch the moment when the Windows OS loader (`winload.efi`) is loaded in the memory but still has not been executed or

    - Hook/Detour `ExitBootServices`, which is UEFI firmware service that signals the end of the boot process and transitions the system from the firmware environment to the operating system environment.
    
        1.1. The following is required if UEFI Secure Boot is enabled:

        - Patch `BmFwVerifySelfIntegrity` to bypass self integrity checks.
        - Execute `bcdedit /set {bootmgr} nointegritychecks on` to skip the integrity checks.
        - Inject `bcdedit /set {bootmgr} nointegritychecks on` option dynamically by modifying the `LoadOptions`.

        1.2. The following is required to allocate an additional memory buffer for the malicious kernel driver, because as a UEFI Application it will be unloaded from memory after returning from its entry point function.
        
        - `BlImgAllocateImageBuffer` or `BlMmAllocateVirtualPages` in the Windows OS loader (`winload.efi`).

2. Hook/detour `OslArchTransferToKernel` in `winload.efi` (Windows OS loader), which transfers execution to the Windows Kernel (`ntoskrnl.exe`) to catch the moment when the OS kernel and some of the system drivers are already loaded in the memory, but still not been executed, which is a perfect moment to perform more in-memory patching.
    
    - Patch `SepInitializeCodeIntegrity`, a parameter to `CiInitialize` in `ntoskrnl.exe` to disable Driver Signature Enforcement (DSE).
    - Patch `KeInitAmd64SpecificState` in `ntoskrnl.exe` to disable PatchGuard.


## Usage

A UEFI Bootkit works under one or more of the following conditions:

- Secure Boot is disabled on the machine, so no vulnerabilities are required to exploit it. (**Supported by this project**).

- Exploiting a known flaw in the UEFI firmware to disable Secure Boot in the case of an out-of-date firmware version or a product no longer supported, including the Bring Your Own Vulnerable Binary (BYOVB) technique to bring copies of vulnerable binaries to the machines to exploit a vulnerability or vulnerabilities and bypass Secure Boot on up-to-date UEFI systems (1-day/one-day).

- Exploiting an unspecified flaw in the UEFI firmware to disable Secure Boot (0-day/zero-day vulnerability).

### Usage 1: Infect Windows Boot Manager `bootmgfw.efi` on Disk (Unsupported)

Typically UEFI Bootkits infect the Windows Boot Manager `bootmgfw.efi` located in EFI partition `\EFI\Microsoft\Boot\bootmgfw.efi` (`C:\Windows\Boot\EFI\bootmgfw.efi`. Modification of the bootloader includes adding a new section called .efi to the Windows Boot Manager `bootmgfw.efi`, and changing the executable's entry point address so program flow jumps to the beginning of the added section as shown below:

- Convert bootkit to position-independent code (PIC) or shellcode
- Find `bootmgfw.efi` (Windows Boot Manager) located in EFI partition `\EFI\Microsoft\Boot\bootmgfw.efi`
- Add `.efi` section to `bootmgfw.efi` (Windows Boot Manager)
- Inject or copy bootkit shellcode to the `.efi` section in `bootmgfw.efi` (Windows Boot Manager)
- Change entry point of the `bootmgfw.efi` (Windows Boot Manager) to newly added `.efi` section bootkit shellcode
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

    4.1. The following is required for VMware Workstation:

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

7. Now you should see output from the `bootkit.efi` application. If it is successful, Windows should boot automatically.


## Credits / References / Thanks / Motivation

* Rust Community Discord: https://discord.com/invite/rust-lang (#windows-dev channel)

* Austin Hudson: https://github.com/realoriginal/bootlicker

* BTBD: https://github.com/btbd/umap/

* Aidan Khoury: https://github.com/ajkhoury/UEFI-Bootkit/

* Matthijs Lavrijsen: https://github.com/Mattiwatti/EfiGuard

* Samuel Tulach: https://github.com/SamuelTulach/rainbow

* MrExodia: https://secret.club/2022/08/29/bootkitting-windows-sandbox.html

* UnknownCheats: https://www.unknowncheats.me/forum/anti-cheat-bypass/452202-rainbow-efi-bootkit-hwid-spoofer-smbios-disk-nic.html

* Cr4sh: https://github.com/Cr4sh/s6_pcie_microblaze/tree/master/python/payloads/DmaBackdoorBoot

* Alex Matrosov: Rootkits and Bootkits: https://nostarch.com/rootkits by [Alex Matrosov](https://twitter.com/matrosov)

* Welivesecurity: https://www.welivesecurity.com/2021/10/05/uefi-threats-moving-esp-introducing-especter-bootkit/

* Welivesecurity: https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/

* rust-osdev: https://github.com/rust-osdev/uefi-rs

* rust-osdev: https://github.com/rust-osdev/bootloader

* rust-osdev: https://crates.io/crates/uefi

* rust-osdev: https://docs.rs/uefi/latest/

* rust-osdev: https://rust-osdev.github.io/uefi-rs/HEAD/

* https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcd-system-store-settings-for-uefi?view=windows-11

* https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/

* https://github.com/LongSoft/UEFITool

* https://github.com/tianocore/edk2

* https://github.com/pbatard/UEFI-Shell

* https://securelist.com/cosmicstrand-uefi-firmware-rootkit/106973/

* https://wikileaks.org/ciav7p1/cms/page_36896783.html

* https://github.com/nix-community/lanzaboote/

* https://github.com/lyricalsoul/genie/

* https://github.com/pfnsec/uefi-bin-enum/

* https://github.com/coreos/picker

* https://github.com/mikroskeem/apple-set-os/