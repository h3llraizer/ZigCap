# ZigCap
A packet creation, capture and parsing library for Zig.

## Status
ZigCap is currently **experimental** and under active development but is usable. All changes are being made on the main branch until the overall design is stable. APIs may change frequently.


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

## Testing
All tests can be found in `tests/`.

## Examples
All examples can be found in `examples/`

## Contributing
Contributions are welcome.
