const std = @import("std");
const zigcap = @import("zigcap");

const print = std.debug.print;
const expect = std.testing.expect;

const Packet = zigcap.Packet.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const LayerOwner = zigcap.Owner.LayerOwner;
const LayerIface = zigcap.LayerIface;
const ARP = zigcap.ARP;
const IPv4 = zigcap.IPv4;
const Eth = zigcap.Eth;
const IPProtocol = zigcap.ProtocolEnums.IPProtocol;

test "build independant ipv4 layer" {
    //  var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    //  defer _ = debug_allocator.detectLeaks();

    //  const allocator = debug_allocator.allocator();

    //  const ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    //  var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);
    //  defer ipv4_layer_iface.deinit();

    //  var ipv4_hdr = ipv4_layer_iface.ipv4Layer.get_mutable_header();

    //  ipv4_hdr.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.122.1"));

    //  ipv4_hdr.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.122.254"));

    //  ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);

    //  ipv4_hdr.set_ttl(64);
}

test "build ipv4 layer with Router Alert option" {
    //   var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    //   defer _ = debug_allocator.detectLeaks();
    //
    //   const allocator = debug_allocator.allocator();
    //
    //   const ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
    //
    //   //defer ipv4_layer_owner.deinit();
    //
    //   var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);
    //   defer ipv4_layer_iface.deinit();
    //
    //   var ipv4_hdr = ipv4_layer_iface.ipv4Layer.get_mutable_header();
    //
    //
    // ipv4_hdr.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.122.1"));

    // ipv4_hdr.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.122.254"));
    //
    //
    //
    //   ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);
    //
    //   ipv4_hdr.set_ttl(1);
    //
    //   var router_alert_op: [2]u8 align(2) = [_]u8{ 0x00, 0x00 };
    //
    //   const op = try IPv4.IPOption.init(IPv4.IPOptionType.RouterAlert, &router_alert_op);
    //
    //   const op_bytes = try op.toBytes(allocator);
    //   defer allocator.free(op_bytes);
    //
    //   try expect(op_bytes[0] == 0x94);
    //   try expect(op_bytes[1] == 0x04);
    //   try expect(op_bytes[2] == 0x00);
    //   try expect(op_bytes[3] == 0x00);
    //
    //   try ipv4_layer_iface.ipv4Layer.add_option(op, allocator);
    //
    //   const ipv4_slice = ipv4_layer_iface.ipv4Layer.get_data();
    //
    //   try expect(ipv4_slice.len == 24);
    //
    //   //   try ipv4_layer_iface.ipv4Layer.remove_all_options();
    //
    //   const str = try ipv4_layer_iface.ipv4Layer.get_immutable_header().to_string(allocator);
    //   defer allocator.free(str);
}

test "build ipv4 layer with Record Route option" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    //defer ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);

    var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);
    defer ipv4_layer_iface.deinit();

    var ipv4_hdr = ipv4_layer_iface.ipv4Layer.get_mutable_header();

    ipv4_hdr.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.122.1"));

    ipv4_hdr.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.122.254"));

    ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);

    ipv4_hdr.set_ttl(64);

    var record_route_op: [12]u8 align(2) = [_]u8{
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    const rr_op = try IPv4.IPOption.init(IPv4.IPOptionType.RecordRoute, &record_route_op);

    try ipv4_layer_iface.ipv4Layer.add_option(rr_op, allocator);

    var router_alert_op: [2]u8 align(2) = [_]u8{ 0x00, 0x00 };

    const ra_op = try IPv4.IPOption.init(IPv4.IPOptionType.RouterAlert, &router_alert_op);

    const ra_op_bytes = try ra_op.toBytes(allocator);
    defer allocator.free(ra_op_bytes);

    try expect(ra_op_bytes[0] == 0x94);
    try expect(ra_op_bytes[1] == 0x04);
    try expect(ra_op_bytes[2] == 0x00);
    try expect(ra_op_bytes[3] == 0x00);

    try ipv4_layer_iface.ipv4Layer.add_option(ra_op, allocator);
}

test "parse icmp request with ipv4 rr set" {
    const raw: [86]u8 = [_]u8{ 0xc, 0x0, 0x6c, 0x8f, 0x0, 0x0, 0x52, 0x54, 0x0, 0xf5, 0x3, 0x1, 0x8, 0x0, 0x49, 0x0, 0x0, 0x48, 0x0, 0x0, 0x0, 0x0, 0x40, 0x1, 0x25, 0xfa, 0xc0, 0xa8, 0x7a, 0x1, 0xa, 0x1, 0x1, 0x2, 0x7, 0xf, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x0, 0xe5, 0xfa, 0x4, 0xd2, 0x16, 0x2e, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x68, 0x69 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var raw_packet_buffer: std.array_list.Aligned(u8, std.mem.Alignment.@"2") = .empty;

    try raw_packet_buffer.appendSlice(allocator, &raw);

    var packet = try Packet.create(allocator, allocator);
    try packet.from_raw(allocator, &raw_packet_buffer, link_layer_type.ETHERNET, null);
    defer packet.deinit();

    try expect(packet.get_layer_count() == 3);

    try expect(packet.has_protocol_layer(.eth));
    try expect(packet.has_protocol_layer(.ipv4));
    try expect(packet.has_protocol_layer(.icmp));

    var ipv4_layer: *IPv4.IPv4Layer = packet.get_layer_of_type(IPv4.IPv4Layer) orelse {
        try expect(false); //failed to get IPv4 layer
        return;
    };

    var opts = try ipv4_layer.get_opts(allocator) orelse {
        try expect(false); // failed to get opts
        return;
    };

    defer opts.deinit(allocator);

    var cur = opts.first;
    while (cur) |opt| {
        print("{any}\n", .{opt});

        const bytes = try opt.toBytes(allocator);
        print("bytes: {x}\n", .{bytes});
        allocator.free(bytes);

        cur = opt.next_opt;
    }

    print("opt count: {}\n", .{opts.opts_count});
}

test "parse icmp reply with ipv4 rr populated" {
    const raw: [86]u8 = [_]u8{ 0x52, 0x54, 0x0, 0xf5, 0x3, 0x1, 0xc, 0x0, 0x6c, 0x8f, 0x0, 0x0, 0x8, 0x0, 0x49, 0x0, 0x0, 0x48, 0x49, 0x6e, 0x0, 0x0, 0x3f, 0x1, 0xc9, 0x6a, 0xa, 0x1, 0x1, 0x2, 0xc0, 0xa8, 0x7a, 0x1, 0x7, 0xf, 0x10, 0xa, 0x1, 0x1, 0x1, 0xa, 0x1, 0x1, 0x2, 0xa, 0x1, 0x1, 0x2, 0x0, 0x0, 0x0, 0xed, 0xfa, 0x4, 0xd2, 0x16, 0x2e, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x68, 0x69 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var raw_packet_buffer: std.array_list.Aligned(u8, std.mem.Alignment.@"2") = .empty;

    try raw_packet_buffer.appendSlice(allocator, &raw);

    var packet = try Packet.create(allocator, allocator);
    try packet.from_raw(allocator, &raw_packet_buffer, link_layer_type.ETHERNET, null);
    defer packet.deinit();

    try expect(packet.get_layer_count() == 3);

    try expect(packet.has_protocol_layer(.eth));
    try expect(packet.has_protocol_layer(.ipv4));
    try expect(packet.has_protocol_layer(.icmp));
}
