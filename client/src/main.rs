#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use clap::{arg, command, Parser};

use crate::communication::Communication;
use crate::communication::IMAGE_DATA;

mod communication;

/// Manually Map Windows Kernel Driver
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The Windows kernel driver path to be manually mapped
    #[arg(short, long)]
    path: String,
}

fn main() {
    let args = Args::parse();
    let driver_path = args.path;
    let driver_bytes = std::fs::read(driver_path).expect("Failed to read driver path");

    let mut image_data = IMAGE_DATA::default();
    image_data.magic = 0xdeadbeef;
    image_data.buffer = driver_bytes;

    println!("[+] Driver pointer: {:?}", image_data.buffer.as_ptr());
    println!("[+] Magic bytes: {:#x}", image_data.magic);

    match Communication::new() {
        Ok(communication) => match communication.send_request(&mut image_data) {
            Ok(status) => {
                println!("[+] Driver manually mapped successfully! {:#x}", status);
            }
            Err(e) => {
                println!("[-] Failed to send request: {:?}", e);
            }
        },
        Err(e) => {
            println!("[-] Failed to setup communication: {:?}", e);
        }
    }
}
