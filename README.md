# sniff-rs: a small packer sniffer in rust 

this is a work-in-progress packet sniffer that utilizes the `argparse` and `pcap` packages to sniff
packet interactions across various devices. this is a small project that i'm writing based on the[packetSniffer project by k0pernicus](https://github.com/k0pernicus/packetSniffer/tree/master) with plans for `.pcap` file parsing as well as multi-device support. *note: this project is by no means intended for any unethical purposes, so please use this project responsibly.*

## current features 
- packet sniffing over default device 
- printing of all available devices to sniff 
- parsing of request and response messages into an output file 
- ability to change output file name 

## todos 
- finish implementing device selection 
- prettify packets 
