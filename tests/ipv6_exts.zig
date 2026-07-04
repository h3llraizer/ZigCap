const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const Packet = zigcap.Packet;
const ProtocolEnums = zigcap.ProtocolEnums;
const link_layer_type = ProtocolEnums.link_layer_type;
const IPProtocol = ProtocolEnums.IPProtocol;
const tcp_ip_protocol = zigcap.tcp_ip_protocol;
const LayerOwner = zigcap.Owner.LayerOwner;
const TLVOwner = zigcap.Owner.TLVOwner;
const Layer = zigcap.Layer;

const IPv6 = zigcap.IPv6;
const IPv6Extensions = IPv6.IPv6Extensions;

const UDP = zigcap.UDP;

test "hop-by-hop" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const tlv_owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };

    var hbh: IPv6Extensions.HopByHop = try IPv6Extensions.HopByHop.init(tlv_owner);
    defer hbh.deinit();

    try expect(hbh.get_data().len == 8);

    hbh.set_opt_type(.ROUTER_ALERT);

    hbh.set_opt_value(0);

    hbh.set_pad_option(1);

    try expect(hbh.get_opt_type() == .ROUTER_ALERT);

    try expect(hbh.get_opt_len() == 2);

    try expect(hbh.get_opt_value() == 0);

    try expect(hbh.get_pad_option() == .PADN);

    try expect(hbh.get_pad_len() == 0);

    var ipv6_layer = try IPv6.IPv6Layer.init(allocator);
    defer ipv6_layer.deinit();

    var hbh_ext = IPv6.ExtensionHeader{ .hop_by_hop = hbh };

    try ipv6_layer.add_extension(&hbh_ext);

    var extensions = try ipv6_layer.get_extensions(allocator) orelse {
        try expect(false); // failed to get extension headers
        return;
    };

    defer extensions.deinit(allocator);

    try expect(extensions.ext_header_count == 1);

    var cur = extensions.first;
    while (cur) |ext| {
        //print("type: {any}\n", .{ext.get_type()});
        //print("data: {x}\n", .{ext.hop_by_hop.get_data()});

        cur = ext.get_next();
    }

    try ipv6_layer.remove_extension(extensions.first.?);

    _ = ipv6_layer.get_ip_protocol();

    //print("ipv6 layer: ({}) {x}\n", .{ ipv6_layer.get_data().len, ipv6_layer.get_data() });
}

test "hop-by-hop & destination opts" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const tlv_owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };

    var hbh: IPv6Extensions.HopByHop = try IPv6Extensions.HopByHop.init(tlv_owner);
    defer hbh.deinit();

    try expect(hbh.get_data().len == 8);

    hbh.set_opt_type(.ROUTER_ALERT);

    hbh.set_opt_value(0);

    hbh.set_pad_option(1);

    try expect(hbh.get_opt_type() == .ROUTER_ALERT);

    try expect(hbh.get_opt_len() == 2);

    try expect(hbh.get_opt_value() == 0);

    try expect(hbh.get_pad_option() == .PADN);

    try expect(hbh.get_pad_len() == 0);

    var dest_opts: IPv6Extensions.DestinationOpts = try IPv6Extensions.DestinationOpts.init(tlv_owner);
    defer dest_opts.deinit();

    try expect(dest_opts.get_data().len == 8);

    dest_opts.set_opt_type(.ROUTER_ALERT);

    dest_opts.set_opt_value(0);

    dest_opts.set_pad_option(1);

    try expect(dest_opts.get_opt_type() == .ROUTER_ALERT);

    try expect(dest_opts.get_opt_len() == 2);

    try expect(dest_opts.get_opt_value() == 0);

    try expect(dest_opts.get_pad_option() == .PADN);

    try expect(dest_opts.get_pad_len() == 0);

    var ipv6_layer = try IPv6.IPv6Layer.init(allocator);
    defer ipv6_layer.deinit();

    var hbh_ext = IPv6.ExtensionHeader{ .hop_by_hop = hbh };

    var dest_opts_ext = IPv6.ExtensionHeader{ .dest_opts = dest_opts };

    try ipv6_layer.add_extension(&hbh_ext);

    //print("ipv6 layer: ({}) {x}\n", .{ ipv6_layer.get_data().len, ipv6_layer.get_data() });

    try ipv6_layer.add_extension(&dest_opts_ext);

    var extensions = try ipv6_layer.get_extensions(allocator) orelse {
        try expect(false); // failed to get extension headers
        return;
    };

    defer extensions.deinit(allocator);

    //print("ext count: {}\n", .{extensions.ext_header_count});

    //try expect(extensions.ext_header_count == 2);

    //print("ipv6 layer: ({}) {x}\n", .{ ipv6_layer.get_data().len, ipv6_layer.get_data() });

    var cur = extensions.first;
    while (cur) |ext| {
        //print("type: {any}\n", .{ext.get_type()});
        //print("data: {x}\n", .{ext.hop_by_hop.get_data()});

        cur = ext.get_next();
    }
    //
    //   try ipv6_layer.remove_extension(extensions.first.?);
    //
    //   ////print("ipv6 layer: ({}) {x}\n", .{ ipv6_layer.get_data().len, ipv6_layer.get_data() });

    //print(" ------ END ------ \n", .{});
}

test "hop-by-hop & destination opts in packet" {
    // print(" ------ TESTING MULTIPLE OPTIONS IN PACKET ------ \n", .{});
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var packet = Packet.create(allocator, allocator);
    defer packet.deinit();

    const tlv_owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };

    var hbh: IPv6Extensions.HopByHop = try IPv6Extensions.HopByHop.init(tlv_owner);
    defer hbh.deinit();

    try expect(hbh.get_data().len == 8);

    hbh.set_opt_type(.ROUTER_ALERT);

    hbh.set_opt_value(0);

    hbh.set_pad_option(1);

    try expect(hbh.get_opt_type() == .ROUTER_ALERT);

    try expect(hbh.get_opt_len() == 2);

    try expect(hbh.get_opt_value() == 0);

    try expect(hbh.get_pad_option() == .PADN);

    try expect(hbh.get_pad_len() == 0);

    var dest_opts: IPv6Extensions.DestinationOpts = try IPv6Extensions.DestinationOpts.init(tlv_owner);
    defer dest_opts.deinit();

    try expect(dest_opts.get_data().len == 8);

    dest_opts.set_opt_type(.ROUTER_ALERT);

    dest_opts.set_opt_value(0);

    dest_opts.set_pad_option(1);

    try expect(dest_opts.get_opt_type() == .ROUTER_ALERT);

    try expect(dest_opts.get_opt_len() == 2);

    try expect(dest_opts.get_opt_value() == 0);

    try expect(dest_opts.get_pad_option() == .PADN);

    try expect(dest_opts.get_pad_len() == 0);

    var ipv6_layer_iface = try Layer.init(IPv6.IPv6Layer, allocator);
    defer ipv6_layer_iface.deinit();

    var udp_layer_iface = try Layer.init(UDP.UDPLayer, allocator);
    defer udp_layer_iface.deinit();

    udp_layer_iface.udpLayer.get_mutable_header().set_src_port(1234);
    udp_layer_iface.udpLayer.get_mutable_header().set_dst_port(5005);

    try packet.add_layer(&ipv6_layer_iface);
    try packet.add_layer(&udp_layer_iface);

    var ipv6_layer: IPv6.IPv6Layer = packet.get_layer_of_type(IPv6.IPv6Layer) orelse {
        try expect(false); // failed to get IPv6 layer from packet
        return;
    };

    ipv6_layer.get_mutable_header().set_next_header(IPv6.NextHeader.UDP);

    try expect(@as(IPv6.NextHeader, @enumFromInt(ipv6_layer.get_immutable_header().next_header)) == .UDP);

    try expect(ipv6_layer.get_ip_protocol() == .UDP);

    var hbh_ext = IPv6.ExtensionHeader{ .hop_by_hop = hbh };

    var dest_opts_ext = IPv6.ExtensionHeader{ .dest_opts = dest_opts };

    try ipv6_layer.add_extension(&hbh_ext);

    try ipv6_layer.add_extension(&dest_opts_ext);

    var extensions = try ipv6_layer.get_extensions(allocator) orelse {
        try expect(false); // failed to get extension headers
        return;
    };

    defer extensions.deinit(allocator);

    try expect(extensions.ext_header_count == 2);

    var cur = extensions.first;
    var count: usize = 0;
    while (cur) |ext| {
        if (count == 0) {
            try expect(ext.get_type() == .HopByHop);
            try expect(ext.next_ext() == .DestOpts);
        }
        if (count == 1) {
            try expect(ext.get_type() == .DestOpts);
            try expect(ext.next_ext() == .UDP);
        }

        count += 1;
        cur = ext.get_next();
    }
    var d: [8]u8 = .{0x00} ** 8;

    @memmove(&d, extensions.first.?.get_data());

    //print("first d: {x}\n", .{d});

    try ipv6_layer.remove_extension(extensions.first.?);

    //print("NH: {any}\n", .{@as(IPv6.NextHeader, (@enumFromInt(ipv6_layer.get_immutable_header().next_header)))});

    //print("ipv6 layer: ({}) {x}\n", .{ ipv6_layer.get_data().len, ipv6_layer.get_data() });

    const i = std.mem.indexOf(u8, ipv6_layer.get_data()[IPv6.IPv6HeaderSize + 8 ..], &d);

    if (i) |offset| {
        _ = offset;
        try expect(false);
        //print("found at {}\n", .{offset});
    } else {
        //print("not found.\n", .{});
    }

    try expect(ipv6_layer.get_immutable_header().next_header == @intFromEnum(IPv6.NextHeader.DestOpts));

    //try ipv6_layer.remove_extension(extensions.first.?.get_next().?);

    //   //print(" ------ END ------ \n", .{});

}

test "ipv6 esp" {
    //    print("----------- TESTING IPV6 ESP Extension -----------", .{});
    var ipv6_hdr: [176]u8 = [_]u8{ 0x60, 0xb, 0x41, 0x40, 0x0, 0x88, 0x32, 0x40, 0x2a, 0x0, 0x23, 0xc8, 0x73, 0xca, 0xd7, 0x1, 0xc7, 0x1d, 0x39, 0x69, 0x7e, 0x99, 0xf4, 0x86, 0x2a, 0x0, 0x23, 0xc8, 0x73, 0xca, 0xd7, 0x1, 0xa, 0x0, 0x27, 0xff, 0xfe, 0x5f, 0xbd, 0xc5, 0xc8, 0xb8, 0x9a, 0x4b, 0x0, 0x0, 0x0, 0xe0, 0x98, 0x7c, 0xa5, 0x20, 0xe6, 0x44, 0xfc, 0x22, 0xd0, 0x49, 0x36, 0xc, 0x6, 0x8f, 0xf9, 0x6a, 0xd8, 0x7b, 0xb4, 0x6e, 0x40, 0xaa, 0xe0, 0x1d, 0xf1, 0x33, 0x0, 0xdb, 0xfb, 0xed, 0x9d, 0x7b, 0x7c, 0xd6, 0xa4, 0xbc, 0xd9, 0x69, 0xc9, 0x6b, 0x52, 0x32, 0xc2, 0xf9, 0x92, 0x9f, 0xc1, 0x69, 0xf2, 0x79, 0x52, 0xf, 0xb8, 0xf9, 0x2c, 0x6d, 0xbd, 0xf1, 0x1b, 0x34, 0xb4, 0x37, 0x9a, 0xff, 0x17, 0xdc, 0x80, 0xe1, 0x25, 0x99, 0x87, 0xf7, 0xab, 0x4a, 0x60, 0x59, 0x1, 0xbe, 0x95, 0x5a, 0xf7, 0xc5, 0x24, 0x16, 0x37, 0xe6, 0x4, 0x5, 0x92, 0x40, 0xc6, 0x8d, 0xe7, 0x50, 0x13, 0x6, 0x6d, 0x7c, 0x6, 0x5f, 0x92, 0x3a, 0x82, 0xb7, 0x9c, 0x98, 0x8a, 0x38, 0xf6, 0x3f, 0xa4, 0x6c, 0xaa, 0x25, 0x25, 0x5b, 0xf5, 0x50, 0x85, 0xd9, 0x9c, 0xa3, 0x7e, 0xa2, 0xa, 0xd1, 0xc6, 0xbf };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var ipv6_layer = try IPv6.IPv6Layer.initFromSlice(ipv6_hdr[0..], allocator);
    defer ipv6_layer.deinit();

    var ipv6_layer_iface = Layer{ .ipv6Layer = ipv6_layer };

    const ipv6_header: *const IPv6.IPv6Header = ipv6_layer_iface.ipv6Layer.get_immutable_header();

    try expect(ipv6_header.get_version() == 6);

    try expect(ipv6_header.get_traffic_class() == 0);

    try expect(ipv6_header.get_flow_label() == 0xb4140);

    try expect(ipv6_header.next_header == @intFromEnum(IPv6.NextHeader.ESP));
    try expect(ipv6_header.get_payload_length() == 136);
    try expect(ipv6_header.hop_limit == 64);

    const expected_src_ip = try IPv6.IPv6Address.init_from_string("2a00:23c8:73ca:d701:c71d:3969:7e99:f486");
    const expected_dst_ip = try IPv6.IPv6Address.init_from_string("2a00:23c8:73ca:d701:a00:27ff:fe5f:bdc5");

    try expect(std.mem.eql(u8, &ipv6_header.get_src_ip().array, &expected_src_ip.array));
    try expect(std.mem.eql(u8, &ipv6_header.get_dst_ip().array, &expected_dst_ip.array));

    var extensions = try ipv6_layer_iface.ipv6Layer.get_extensions(allocator) orelse {
        try expect(false); // failed to get extension headers
        return;
    };

    defer extensions.deinit(allocator);

    try expect(extensions.ext_header_count == 1);

    const ext = extensions.first.?;

    try expect(ext.get_type() == .ESP);
    try expect(ext.esp.get_spi() == 0xc8b89a4b);
    try expect(ext.esp.get_seq_num() == 224);
    try expect(ext.esp.get_payload().len == 128);
    try expect(std.mem.eql(u8, ipv6_hdr[48..], ext.esp.get_payload()));

    //  ext.esp.set_spi(123456);

    //  try expect(ext.esp.get_spi() == 123456);

    //  ext.esp.set_seq_num(891234);

    //  try expect(ext.esp.get_seq_num() == 891234);

    try ipv6_layer_iface.ipv6Layer.remove_extension(ext);

    const ipv6_h = ipv6_layer_iface.ipv6Layer.get_immutable_header();

    try expect(ipv6_h.get_version() == 6);

    try expect(ipv6_h.get_traffic_class() == 0);

    try expect(ipv6_h.get_flow_label() == 0xb4140);

    try expect(ipv6_h.next_header == @intFromEnum(IPv6.NextHeader.NoNext));
    try expect(ipv6_h.get_payload_length() == 0);
    try expect(ipv6_h.hop_limit == 64);

    try expect(std.mem.eql(u8, &ipv6_h.get_src_ip().array, &expected_src_ip.array));
    try expect(std.mem.eql(u8, &ipv6_h.get_dst_ip().array, &expected_dst_ip.array));
}
