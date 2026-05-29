# ZigCap
A packet capture and parsing library for Zig.

## Status
ZigCap is currently **experimental** and under active development. All changes are being made on the main branch until the overall design is stable. APIs may change frequently.


## Features
Currently supported functionality:
- Build packets
- Parse and modify existing packets
- Build standalone layers (not attached to Packet)
- Sniff and Inject packets with the PcapWrapper (tested on Windows & Linux)
- Sniff, Block, Modify or Drop Packets with the WinDivertWrapper (Windows)

## Supported Protocols
- Loopback (`src/Loopback.zig`)
- Ethernet (`src/Eth.zig`)
- ARP (`src/ARP.zig`)
- IPv4 (`src/IPv4.zig`)
- IPv6 (`src/IPv6.zig`)
- UDP (`src/UDP.zig`)
- TCP (`src/TCP.zig`)
- ICMP (`src/ICMP.zig`)
- DNS (`src/DNS.zig`)
- DHCP (`src/DHCP.zig`)
- Generic / Application Layer (`src/GenericLayer.zig`)

Note, these protocols are supported but not fully implemented with their extended features:
- IPv6 extensions are not fully parsable and adding or removing them is fragile.

## Testing
All tests are can be found in `tests/`.

## Contributing
Contributions are welcome, but note:
- The project is evolving quickly
- Open issues or PRs may overlap with ongoing work

Feel free to open an issue or submit a pull request regardless.
