# ZigCap
A packet capture and parsing library for Zig.

## Status
ZigCap is currently **experimental** and under active development. APIs may change frequently.

## Features
Currently supported functionality:
- Build packets
- Parse and modify existing packets
- Build standalone layers (not attached to Packet)
- Sniff and Inject packets with the PcapWrapper (only tested on Windows)

## Supported Protocols
- Ethernet (`src/Eth.zig`)
- IPv4 (`src/IPv4.zig`)
- IPv6 (`src/IPv6.zig`)
- UDP (`src/UDP.zig`)
- ARP (`src/ARP.zig`)
- ICMP (`src/ICMP.zig`)
- DNS (`src/DNS.zig`)
- Generic / Application Layer (`src/GenericLayer.zig`)

Note, these protocols are supported but not fully implemented with their extended features:
- IPv4 base header parsing is completely supported but IPv4 options only have basic support
- TCP base header parsing is completely supported but TCP options only have basic support (options cannot be added or removed yet)
- IPv6 extension headers cannot be parsed, added or removed yet



## Testing
All tests (other than UDP checksum calculation - see issue 3) are currently passing (`tests/`).

## Contributing
Contributions are welcome, but note:
- The project is evolving quickly
- Open issues or PRs may overlap with ongoing work

Feel free to open an issue or submit a pull request regardless.
