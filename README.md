# A UEFI Bootkit in Rust

A UEFI Bootkit in Rust. 

**Work in progress (W.I.P)**

## Usage

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