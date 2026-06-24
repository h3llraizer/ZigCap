const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const Packet = zigcap.Packet.Packet;
const ProtocolEnums = zigcap.ProtocolEnums;
const link_layer_type = ProtocolEnums.link_layer_type;
const IPProtocol = ProtocolEnums.IPProtocol;
const tcp_ip_protocol = zigcap.tcp_ip_protocol;
const LayerOwner = zigcap.Owner.LayerOwner;
const Layer = zigcap.Layer;

const IPv6 = zigcap.IPv6;
const IPv6Address = IPv6.IPv6Address;

test "parse ipv6 with hop-by-hop ext and ICMPv6 listen report" {
    var ipv6_hbh_icmpv6 = [_]u8{ 0x60, 0x0, 0x0, 0x0, 0x0, 0x24, 0x0, 0x1, 0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa6, 0x61, 0x8f, 0x26, 0x87, 0xeb, 0xbe, 0x60, 0xff, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x16, 0x3a, 0x0, 0x5, 0x2, 0x0, 0x0, 0x1, 0x0 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var ipv6_layer = try IPv6.IPv6Layer.initFromSlice(ipv6_hbh_icmpv6[0..], allocator);
    defer ipv6_layer.deinit();

    const src = try ipv6_layer.get_immutable_header().get_src_ip().to_string(allocator);
    defer allocator.free(src);

    const dst = try ipv6_layer.get_immutable_header().get_dst_ip().to_string(allocator);
    defer allocator.free(dst);

    var extensions = try ipv6_layer.get_extensions(allocator) orelse {
        try expect(false); // failed to get extension headers
        return;
    };

    defer extensions.deinit(allocator);

    try expect(extensions.ext_header_count == 1);

    try expect(ipv6_layer.get_immutable_header().get_next_header() == .HopByHop);

    var cur = extensions.first;
    while (cur) |ext| {
        //print("{any}\n", .{ext.get_type()});
        //print("data: {x}\n", .{ext.hop_by_hop.get_data()});
        //print("offset: {}\n", .{ext.hop_by_hop.get_offset()});
        //print("ipv6 ext buf: {x}\n", .ipv6_layer.get_data()[ext.hop_by_hop.get_offset()..]});
        //print("{any}\n", .{ext.hop_by_hop.get_opt_type()});
        //print("opt len: {}\n", .{ext.hop_by_hop.get_opt_len()});
        //print("opt value: {}\n", .{ext.hop_by_hop.get_opt_value()});

        //print("pad option: {any}\n", .{ext.hop_by_hop.get_pad_option()});

        //print("pad len: {}\n", .{ext.hop_by_hop.get_pad_len()});
        //print("next header: {any}\n", .{ext.next_ext()});
        cur = ext.get_next();
    }

    try ipv6_layer.remove_extension(extensions.first.?);

    //print("ipv6 layer: ({}) {x}\n", .{ipv6_layer.get_data().len,ipv6_layer.get_data() });

    try expect(ipv6_layer.get_immutable_header().get_next_header() == .ICMPv6);
}

test "parse ipv6 packet" {
    const ipv6_dns_req: [89]u8 = [_]u8{ 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x86, 0xdd, 0x60, 0x5, 0x51, 0x97, 0x0, 0x23, 0x11, 0x40, 0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa6, 0x61, 0x8f, 0x26, 0x87, 0xeb, 0xbe, 0x60, 0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3a, 0x6, 0xe6, 0xff, 0xfe, 0x92, 0x63, 0xac, 0xfc, 0x41, 0x0, 0x35, 0x0, 0x23, 0x94, 0x62, 0xc1, 0x0, 0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4, 0x77, 0x70, 0x61, 0x64, 0x4, 0x68, 0x6f, 0x6d, 0x65, 0x0, 0x0, 0x1, 0x0, 0x1 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var raw_packet_buffer: std.ArrayList(u8) = .empty;

    try raw_packet_buffer.appendSlice(allocator, &ipv6_dns_req);

    var packet = Packet.create(allocator, allocator);
    try packet.from_raw(allocator, &raw_packet_buffer, link_layer_type.ETHERNET, null);
    defer packet.deinit();

    //    packet.print_layers_meta();

    if (packet.get_layer_of_type(IPv6.IPv6Layer)) |ipv6_layer| {
        const hdr = ipv6_layer.get_immutable_header();
        try expect(hdr.get_payload_length() == 35);
    }
}

test "parse ipv6 layer" {
    var ipv6_raw_layer = [_]u8{ 0x60, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x40, 0x2a, 0x0, 0x23, 0xc8, 0x73, 0xa8, 0xc1, 0x1, 0xf2, 0xce, 0xcb, 0xf2, 0x41, 0x11, 0xc5, 0x54, 0x20, 0x1, 0xd, 0xb8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x3a, 0x0, 0x0, 0x1, 0x3, 0x0, 0x0, 0x0 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    var ipv6_layer = try IPv6.IPv6Layer.initFromSlice(ipv6_raw_layer[0..], allocator);
    defer ipv6_layer.deinit();

    const hdr = ipv6_layer.get_mutable_header();

    const src_str = try hdr.get_src_ip().to_string(allocator);
    defer allocator.free(src_str);

    const dst_ip = try hdr.get_dst_ip().to_string(allocator);
    defer allocator.free(dst_ip);

    var extensions = try ipv6_layer.get_extensions(allocator) orelse {
        print("no extension headers.\n", .{});
        return;
    };

    defer extensions.deinit(allocator);

    var cur = extensions.first;
    while (cur) |ext| {
        //print("{any}\n", .{ext.get_type()});
        cur = ext.get_next();
    }
}

test "build ipv6 layer" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var ipv6_iface = try Layer.init(IPv6.IPv6Layer, allocator);
    defer ipv6_iface.deinit();

    const hdr = ipv6_iface.ipv6Layer.get_mutable_header();

    hdr.set_src_ip(IPv6.IPv6Address.init_from_array(.{ 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x61, 0x8f, 0x26, 0x87, 0xeb, 0xbe, 0x60 }));
}

test "ipv6 header getters/setters" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var ipv6_iface = try Layer.init(IPv6.IPv6Layer, allocator);
    defer ipv6_iface.deinit();

    const hdr = ipv6_iface.ipv6Layer.get_mutable_header();

    const src_ip = try IPv6Address.init_from_string("2a00:23c8:73ca:d701:c71d:3969:7e99:f486");

    const dst_ip = try IPv6Address.init_from_string("2a00:23c8:73ca:d701:a00:27ff:fe5f:bdc5");

    hdr.set_traffic_class(0);

    const flow_label: u20 = 0x0b4140;

    hdr.set_flow_label(flow_label);

    hdr.set_src_ip(src_ip);
    hdr.set_dst_ip(dst_ip);

    try expect(hdr.get_version() == 6);

    try expect(hdr.get_traffic_class() == 0);
    try expect(hdr.get_flow_label() == flow_label);

    try expect(std.mem.eql(u8, &hdr.get_src_ip().array, &src_ip.array));
    try expect(std.mem.eql(u8, &hdr.get_dst_ip().array, &dst_ip.array));
}
