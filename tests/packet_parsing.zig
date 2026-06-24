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

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    var raw_packet_buffer: std.ArrayList(u8) = .empty;
    //    defer raw_packet_buffer.deinit(allocator); - doesn't need to be called because Packet takes ownership but it is still safe to do so

    try raw_packet_buffer.appendSlice(allocator, &simple_udp_packet);

    const original_raw_packet_buffer_len = raw_packet_buffer.items.len;

    var packet = Packet.create(allocator, allocator);
    try packet.from_raw(allocator, &raw_packet_buffer, link_layer_type.ETHERNET, null);
    defer packet.deinit();

    try expect(packet.get_layer_count() == 4);

    if (packet.last_layer) |last| {
        try expect(last.get_data().len == 9);
        try expect(try packet.delete_layer(last.layer_iface));
        try expect(packet.get_layer_count() == 3);
        try expect(packet.get_raw().len == original_raw_packet_buffer_len - 9);
    }

    const original_raw_packet_buffer = raw_packet_buffer.items;

    try expect(original_raw_packet_buffer.len == 0);

    //packet.get_raw().len;

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
    //   const copied = try allocator.alloc(u8, icmp_request_raw.len);
    //
    //   @memmove(copied, icmp_request_raw[0..]);
    //
    //   var packet = try Packet.from_raw(allocator, copied, link_layer_type.ETHERNET, null);
    //   defer packet.deinit();
    //
    //   packet.print_layers_meta();
}
