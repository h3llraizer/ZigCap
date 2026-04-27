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
- IPv4-header options only have basic support to add options only
- a select few TCP-Header options are parsable (cannot be added or removed from layers yet)
- a select few IPv6-Header extensions are parsable (cannot be added or removed from layers yet)



## Testing
All tests are currently passing (`tests/`).

## Contributing
Contributions are welcome, but note:
- The project is evolving quickly
- Open issues or PRs may overlap with ongoing work

Feel free to open an issue or submit a pull request regardless.
