# ZigCap
A packet capture and parsing library for Zig.

## Status
ZigCap is currently **experimental** and under active development. APIs may change frequently.

## Features
Currently supported functionality:
- Build packets
- Parse and modify existing packets

## Supported Protocols
- Ethernet (`src/Eth.zig`)
- IPv4 (`src/IPv4.zig`)
- UDP (`src/UDP.zig`)
- ARP (`src/ARP.zig`)
- ICMP (`src/ICMP.zig`)
- DNS (`src/DNS.zig`)
- Generic / Application Layer (`src/GenericLayer.zig`)

## Testing
All tests are currently passing (`tests.zig`).

## Contributing
Contributions are welcome, but note:
- The project is evolving quickly
- Open issues or PRs may overlap with ongoing work

Feel free to open an issue or submit a pull request regardless.
