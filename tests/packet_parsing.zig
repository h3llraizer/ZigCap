const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const Packet = zigcap.Packet.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const tcp_ip_protocol = zigcap.tcp_ip_protocol;

test "parse udp packet" {
    const simple_udp_packet: [51]u8 = [_]u8{
        // ========== ETHERNET HEADER (14 bytes) ==========
        // Destination MAC Address (6 bytes)
        0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, // Dest MAC: 38:06:e6:92:63:ac

        // Source MAC Address (6 bytes)
        0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, // Src MAC: 14:4f:8a:a4:15:7d

        // EtherType (2 bytes) - 0x0800 = IPv4
        0x8, 0x0, // EtherType: IPv4

        // ========== IP HEADER (20 bytes) ==========
        // Byte 0: Version (4) + IHL (5) = 0x45
        0x45, // Version: 4, IHL: 5 (20 bytes header)

        // Byte 1: DSCP + ECN (0x00 = best effort)
        0x0, // DSCP: 0, ECN: 0

        // Bytes 2-3: Total Length (0x0025 = 37 bytes)
        0x0, 0x25, // Total IP packet length: 37 bytes

        // Bytes 4-5: Identification (0xa4af)
        0xa4, 0xaf, // ID: 0xa4af

        // Bytes 6-7: Flags (3 bits) + Fragment Offset (13 bits)
        0x0, 0x0, // Flags: 0, Fragment Offset: 0

        // Byte 8: Time To Live (0x80 = 128)
        0x80, // TTL: 128

        // Byte 9: Protocol (0x11 = UDP)
        0x11, // Protocol: UDP (17)

        // Bytes 10-11: Header Checksum (0x10e9)
        0x10, 0xe9, // IP header checksum

        // Bytes 12-15: Source IP Address (192.168.1.225)
        0xc0, 0xa8, 0x1, 0xe1, // Src IP: 192.168.1.225

        // Bytes 16-19: Destination IP Address (192.168.1.254)
        0xc0, 0xa8, 0x1, 0xfe, // Dest IP: 192.168.1.254

        // ========== UDP HEADER (8 bytes) ==========
        // Bytes 0-1: Source Port (0xd30d = 54029)
        0xd3, 0xd, // Src Port: 54029

        // Bytes 2-3: Destination Port (0x138d = 5005)
        0x13, 0x8d, // Dest Port: 5005

        // Bytes 4-5: UDP Length (0x0011 = 17 bytes)
        0x0, 0x11, // UDP length (header + payload): 17 bytes

        // Bytes 6-7: UDP Checksum (0xd053)
        0xd0, 0x53, // UDP checksum

        // ========== UDP PAYLOAD (11 bytes) ==========
        // ASCII: "Some data"
        0x73, // 's'
        0x6f, // 'o'
        0x6d, // 'm'
        0x65, // 'e'
        0x20, // ' '
        0x64, // 'd'
        0x61, // 'a'
        0x74, // 't'
        0x61, // 'a'
    };

    print("start parse of simple UDP packet.\n", .{});

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;

    var allocator = debug_allocator.allocator();

    const pkt_data = try allocator.alloc(u8, simple_udp_packet.len);
    @memmove(pkt_data, simple_udp_packet[0..]);

    print("raw: ({}) {x}\n", .{ pkt_data.len, pkt_data });

    var packet = try Packet.from_raw(allocator, pkt_data, link_layer_type.ETHERNET, null);

    try expect(packet.get_layer_count() == 4);

    packet.print_layers_meta();

    print("end of parsing of simple UDP packet.\n", .{});
}

test "parse icmp packet" {
    //   const icmp_request_raw = [74]u8{ 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x3c, 0x71, 0xdc, 0x0, 0x0, 0x80, 0x1, 0xf5, 0xef, 0xc0, 0xa8, 0x1, 0xe1, 0x8e, 0xfa, 0x81, 0x71, 0x8, 0x0, 0x4d, 0x5a, 0x0, 0x1, 0x0, 0x1, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69 };
    //
    //   var backing_buffer: [1024]u8 = undefined;
    //
    //   var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);
    //
    //   const allocator = fba.allocator();
    //
    //   var copied = try allocator.alloc(u8, icmp_request_raw.len);
    //
    //   @memmove(copied, icmp_request_raw[0..]);
    //
    //   var packet = try Packet.create(allocator, allocator);
    //   defer packet.deinit();
    //
    //   packet.from_raw(copied[0..], link_layer_type.ETHERNET) catch |err| {
    //       print("{s}\n", .{@errorName(err)});
    //   };
    //
    //   packet.print_layers_meta();
}
