const std = @import("std");
const zigcap = @import("zigcap");

const print = std.debug.print;
const expect = std.testing.expect;

const Packet = zigcap.Packet.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const LayerOwner = zigcap.Layer.LayerOwner;
const LayerIface = zigcap.LayerIface;
const ARP = zigcap.ARP;
const IPv4 = zigcap.IPv4;
const Eth = zigcap.Eth;
const DNS = zigcap.DNS;
const IPProtocol = zigcap.ProtocolEnums.IPProtocol;

test "owned_slice" {
    const ipv4_header: [20]u8 align(2) = [_]u8{ 0x45, 0x0, 0x0, 0x54, 0xa3, 0xef, 0x40, 0x0, 0x40, 0x1, 0xbb, 0xff, 0xc0, 0xa8, 0xa, 0x2, 0x8, 0x8, 0x8, 0x8 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const ipv4_slice: []align(2) u8 = try allocator.alignedAlloc(u8, std.mem.Alignment.@"2", ipv4_header.len);

    @memmove(ipv4_slice[0..], &ipv4_header);

    const tmp_buf: LayerOwner = LayerOwner{ .owned_buffer = try .init(ipv4_slice, allocator) };

    //defer tmp_buf.deinit();

    var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, tmp_buf);
    defer ipv4_layer_iface.deinit();

    ipv4_layer_iface.ipv4Layer.get_mutable_header().set_protocol(IPProtocol.TCP);

    var ipv4_layer_iface1: LayerIface = try LayerIface.init(IPv4.IPv4Layer, tmp_buf);
    //defer ipv4_layer_iface1.deinit();

    ipv4_layer_iface1.ipv4Layer.get_mutable_header().set_protocol(IPProtocol.UDP);
}

test "packet ownership" {
    const raw: [93]u8 = [_]u8{ 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x4f, 0xcd, 0x45, 0x0, 0x0, 0x80, 0x11, 0xe8, 0x28, 0xc0, 0xa8, 0x1, 0xe1, 0xc0, 0xa8, 0x1, 0xfe, 0xc5, 0xd1, 0x0, 0x35, 0x0, 0x3b, 0x74, 0x70, 0xb7, 0x79, 0x1, 0x20, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x6, 0x7a, 0x69, 0x67, 0x67, 0x69, 0x74, 0x3, 0x64, 0x65, 0x76, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x29, 0x4, 0xd0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x0, 0xa, 0x0, 0x8, 0xa0, 0xd9, 0x37, 0x2e, 0xaa, 0x24, 0xf8, 0x1d };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var raw_packet_buffer: std.array_list.Aligned(u8, std.mem.Alignment.@"2") = .empty;

    try raw_packet_buffer.appendSlice(allocator, &raw);

    var packet = try Packet.create(allocator, allocator);
    try packet.from_raw(allocator, &raw_packet_buffer, link_layer_type.ETHERNET, null);
    defer packet.deinit();

    try expect(packet.get_layer_count() == 4);

    try expect(packet.has_protocol_layer(.eth));
    try expect(packet.has_protocol_layer(.ipv4));
    try expect(packet.has_protocol_layer(.udp));
    try expect(packet.has_protocol_layer(.dns));

    // if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4_layer| {
    //     print("IPV4 OPTIONS: {x}\n", .{ipv4_layer.get_options()});
    // } else {
    //     std.debug.panic("no IPv4 layer.", .{});
    // }

    const dns_layer = packet.search_layers(.dns) orelse {
        try expect(false); // failed to retrieve dns layer in packet
        return;
    };

    var dns_layer_iface = try LayerIface.init(DNS.DNSLayer, .{ .packet_layer = dns_layer });

    const str = dns_layer_iface.to_string(allocator);
    defer allocator.free(str);
}
