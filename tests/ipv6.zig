const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const Packet = zigcap.Packet.Packet;
const ProtocolEnums = zigcap.ProtocolEnums;
const link_layer_type = ProtocolEnums.link_layer_type;
const IPProtocol = ProtocolEnums.IPProtocol;
const tcp_ip_protocol = zigcap.tcp_ip_protocol;
const LayerOwner = zigcap.Layer.LayerOwner;
const LayerIface = zigcap.LayerIface;

const IPv6 = zigcap.IPv6;

test "parse ipv6 with hop-by-hop ext and ICMPv6 listen report" {
    const ipv6_hbh_icmpv6: [90]u8 = [_]u8{ 0x33, 0x33, 0x0, 0x0, 0x0, 0x16, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x86, 0xdd, 0x60, 0x0, 0x0, 0x0, 0x0, 0x24, 0x0, 0x1, 0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa6, 0x61, 0x8f, 0x26, 0x87, 0xeb, 0xbe, 0x60, 0xff, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x16, 0x3a, 0x0, 0x5, 0x2, 0x0, 0x0, 0x1, 0x0, 0x8f, 0x0, 0xf4, 0x32, 0x0, 0x0, 0x0, 0x1, 0x4, 0x0, 0x0, 0x0, 0xff, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x3 };
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var raw_packet_buffer: std.array_list.Aligned(u8, std.mem.Alignment.@"2") = .empty;

    try raw_packet_buffer.appendSlice(allocator, &ipv6_hbh_icmpv6);

    var packet = try Packet.create(allocator, allocator);
    try packet.from_raw(allocator, &raw_packet_buffer, link_layer_type.ETHERNET, null);
    defer packet.deinit();

    if (packet.get_layer_of_type(IPv6.IPv6Layer)) |ipv6_layer| {
        var extensions = try ipv6_layer.get_extensions(allocator) orelse {
            print("no extension headers.\n", .{});
            return;
        };

        defer extensions.deinit(allocator);

        var cur = extensions.first;
        while (cur) |ext| {
            //   print("{any}\n", .{ext.get_type()});
            cur = ext.get_next_extension();
        }

        //  try expect(ipv6_layer.get_ext_header(IPv6.NextHeader.HopByHop) != null);

        //  if (ipv6_layer.get_ext_header(IPv6.NextHeader.HopByHop)) |hbh| {
        //      const hbh_ext: *IPv6.HobByHop = &hbh.hbh;
        //      try expect(hbh_ext.get_action() == IPv6.OptionType.ROUTER_ALERT);

        //      //          hbh_ext.set_action(IPv6.OptionType.QUICK_START);

        //      //            try expect(hbh_ext.get_action() == IPv6.OptionType.QUICK_START);
        //  }
    }
}

test "parse ipv6 packet" {
    const ipv6_dns_req: [89]u8 = [_]u8{ 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x86, 0xdd, 0x60, 0x5, 0x51, 0x97, 0x0, 0x23, 0x11, 0x40, 0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa6, 0x61, 0x8f, 0x26, 0x87, 0xeb, 0xbe, 0x60, 0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3a, 0x6, 0xe6, 0xff, 0xfe, 0x92, 0x63, 0xac, 0xfc, 0x41, 0x0, 0x35, 0x0, 0x23, 0x94, 0x62, 0xc1, 0x0, 0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4, 0x77, 0x70, 0x61, 0x64, 0x4, 0x68, 0x6f, 0x6d, 0x65, 0x0, 0x0, 0x1, 0x0, 0x1 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var raw_packet_buffer: std.array_list.Aligned(u8, std.mem.Alignment.@"2") = .empty;

    try raw_packet_buffer.appendSlice(allocator, &ipv6_dns_req);

    var packet = try Packet.create(allocator, allocator);
    try packet.from_raw(allocator, &raw_packet_buffer, link_layer_type.ETHERNET, null);
    defer packet.deinit();

    //    packet.print_layers_meta();

    if (packet.get_layer_of_type(IPv6.IPv6Layer)) |ipv6_layer| {
        const hdr = ipv6_layer.get_immutable_header();
        try expect(hdr.get_payload_length() == 35);
    }
}

test "parse ipv6 layer" {
    const ipv6_raw_layer: [48]u8 = [_]u8{ 0x60, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x40, 0x2a, 0x0, 0x23, 0xc8, 0x73, 0xa8, 0xc1, 0x1, 0xf2, 0xce, 0xcb, 0xf2, 0x41, 0x11, 0xc5, 0x54, 0x20, 0x1, 0xd, 0xb8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x3a, 0x0, 0x0, 0x1, 0x3, 0x0, 0x0, 0x0 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const ipv6_bytes = try allocator.alignedAlloc(u8, std.mem.Alignment.@"2", ipv6_raw_layer.len);
    @memmove(ipv6_bytes, ipv6_raw_layer[0..]);

    const buf: LayerOwner = LayerOwner{ .owned_buffer = try .init(ipv6_bytes, allocator) };

    var ipv6_iface = try LayerIface.init(IPv6.IPv6Layer, buf);
    defer ipv6_iface.deinit();

    const hdr = ipv6_iface.ipv6Layer.get_mutable_header();

    const src_str = try hdr.get_src_ip().to_string(allocator);
    defer allocator.free(src_str);

    const dst_ip = try hdr.get_dst_ip().to_string(allocator);
    defer allocator.free(dst_ip);

    var extensions = try ipv6_iface.ipv6Layer.get_extensions(allocator) orelse {
        print("no extension headers.\n", .{});
        return;
    };

    defer extensions.deinit(allocator);

    var cur = extensions.first;
    while (cur) |ext| {
        //print("{any}\n", .{ext.get_type()});
        cur = ext.get_next_extension();
    }
}

test "build ipv6 layer" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const tmp_buf: LayerOwner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
    //    defer _ = tmp_buf.owned_buffer.deinit();

    var ipv6_iface = try LayerIface.init(IPv6.IPv6Layer, tmp_buf);
    defer ipv6_iface.deinit();

    const hdr = ipv6_iface.ipv6Layer.get_mutable_header();

    hdr.set_src_ip(IPv6.IPv6Address.init_from_array(.{ 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x61, 0x8f, 0x26, 0x87, 0xeb, 0xbe, 0x60 }));
}
