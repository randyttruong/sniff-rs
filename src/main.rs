extern crate argparse;
extern crate pcap;
extern crate pcap_parser;

use argparse::{ArgumentParser, Store, StoreTrue};
use pcap::{Capture, Device};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use std::io::Write;
use std::process;

fn main() -> std::io::Result<()> {
    let mut requested_device: Device = Device::lookup().unwrap().unwrap();

    // Arguments
    let mut print_devices: bool = false;
    let mut requested_device_s: String = String::from("wlan0");
    let mut output_name = String::from("output");
    let mut verbose: bool = false;

    {
        let mut parser = ArgumentParser::new();
        parser.set_description(
            "this is a packet sniffer. i monitor interactions
between any of your devices.",
        );
        parser.refer(&mut print_devices).add_option(
            &["-p", "--printall"],
            StoreTrue,
            "This will print all of your available devices to sniff.",
        );

        parser.refer(&mut requested_device_s).add_option(
            &["-d", "--devices"],
            Store,
            "Request a device",
        );

        parser.refer(&mut verbose).add_option(
            &["-v", "--verbose"],
            StoreTrue,
            "Be verbose and print out all arguments",
        );

        parser.refer(&mut output_name).add_option(
            &["-o", "--output"],
            Store,
            "Input an output name (default is 'output.txt')",
        );

        parser.parse_args_or_exit();
    }

    // arguments end, now for utilities
    let devices = Device::list();

    match devices {
        Ok(device_list) => {
            if print_devices {
                let stars = "*".repeat(80);
                println!("Here are some devices you can look at: \t");
                println!("{}", stars);

                for curr_device in device_list {
                    if curr_device.name == requested_device_s {
                        println!(
                            "\t=> * Device {:?} : {:?}",
                            curr_device.name, curr_device.desc
                        );
                        continue;
                    };
                    if curr_device.desc.is_none() {
                        println!("\t* Device {:?} : No description.", curr_device.name);
                        continue;
                    }

                    println!(
                        "\t* Device {:?} : {:?}",
                        curr_device.name,
                        curr_device.desc.unwrap()
                    );
                }
            }
        }
        Err(e) => {
            println!("No devices found");
            process::exit(0);
        }
    }

    println!(
        "Your selected devices are: {}, is this correct? (Y/n)",
        requested_device_s
    );

    let mut continue_sniff = false;

    loop {
        let mut line = String::new();
        let _b1 = std::io::stdin().read_line(&mut line).unwrap();
        println!("this is the current string: {}", line);
        if (line.to_lowercase().trim() == "y") {
            continue_sniff = true;
            break;
        } else if (line.to_lowercase().trim() == "n") {
            continue_sniff = false;
            break;
        } else {
            println!("Invalid input. Please try again");
        }
    }

    if (continue_sniff != true) {
        println!("Devices incorrect. Process exiting");
        process::exit(0);
    }

    let mut cap = Capture::from_device(requested_device)
        .unwrap()
        .promisc(true)
        .snaplen(5000)
        .open()
        .unwrap();

    output_name.push_str(".pcap");
    let mut file: pcap::Savefile = match cap.savefile(output_name) {
        Ok(f) => f,
        Err(e) => process::exit(0),
    };

    while let Ok(packet) = cap.next_packet() {
        println!("received packet! {:?}", packet);
        file.write(&packet);
    }

    Ok(())
}
