const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const Packet = zigcap.Packet.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const LayerOwner = zigcap.Layer.LayerOwner;
const LayerIface = zigcap.LayerIface;
const ARP = zigcap.ARP;
const IPv4 = zigcap.IPv4;
const Eth = zigcap.Eth;
const IPProtocol = zigcap.ProtocolEnums.IPProtocol;

test "build independant ipv4 layer" {
    var ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(std.heap.page_allocator) };

    defer ipv4_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);

    var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);

    var ipv4_hdr = ipv4_layer_iface.ipv4Layer.get_mutable_header();

    ipv4_hdr.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));

    ipv4_hdr.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.2"));

    ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);

    ipv4_hdr.set_ttl(64);
}

test "ipv4 option parse" {
    //   print("========================== START ==========================\n", .{});
    //   print("ipv4 option parse\n", .{});

    var backing_buffer: [1024]u8 = undefined;

    var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);

    const allocator = fba.allocator();

    var ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    defer ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);

    var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);

    var ipv4_hdr = ipv4_layer_iface.ipv4Layer.get_mutable_header();

    ipv4_hdr.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));

    ipv4_hdr.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.2"));

    ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);

    ipv4_hdr.set_ttl(64);

    var record_route_op: [15]u8 align(2) = [_]u8{
        0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    };

    var op = try IPv4.IPOption.init(IPv4.IPOptionType.RecordRoute, &record_route_op);

    op.set_len(15);

    try ipv4_layer_iface.ipv4Layer.add_option(op, allocator);

    ipv4_layer_iface.ipv4Layer.validate_layer();

    //   print("========================== END ==========================\n", .{});
}

test "build ipv4 layer with Router Alert option" {
    //print("========================== START ==========================\n", .{});
    //print("build ipv4 layer with Router Alert option\n", .{});
    var backing_buffer: [1024]u8 = undefined;

    var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);

    const allocator = fba.allocator();

    var ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    defer ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);

    var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);

    var ipv4_hdr = ipv4_layer_iface.ipv4Layer.get_mutable_header();

    ipv4_hdr.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.225"));

    ipv4_hdr.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.254"));

    ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);

    ipv4_hdr.set_ttl(1);

    var router_alert_op: [2]u8 align(2) = [_]u8{ 0x00, 0x00 };

    const op = try IPv4.IPOption.init(IPv4.IPOptionType.RouterAlert, &router_alert_op);

    const op_bytes = try op.toBytes(allocator);

    try expect(op_bytes[0] == 0x94);
    try expect(op_bytes[1] == 0x04);
    try expect(op_bytes[2] == 0x00);
    try expect(op_bytes[3] == 0x00);

    try ipv4_layer_iface.ipv4Layer.add_option(op, allocator);

    var ipv4_slice = ipv4_layer_iface.ipv4Layer.get_data();

    try expect(ipv4_slice.len == 24);

    try ipv4_layer_iface.ipv4Layer.remove_all_options();

    ipv4_slice = ipv4_layer_iface.ipv4Layer.get_data();

    //  print("========================== END ==========================\n", .{});
}

test "build ipv4 layer with Record Route option" {
    //   print("========================== START ==========================\n", .{});
    //   print("build ipv4 layer with Record Route option\n", .{});
    var backing_buffer: [1024]u8 = undefined;

    var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);

    const allocator = fba.allocator();

    var ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    defer ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);

    var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);

    var ipv4_hdr = ipv4_layer_iface.ipv4Layer.get_mutable_header();

    ipv4_hdr.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.225"));

    ipv4_hdr.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.254"));

    ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);

    ipv4_hdr.set_ttl(64);

    var record_route_op: [15]u8 align(2) = [_]u8{
        0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    };

    const op = try IPv4.IPOption.init(IPv4.IPOptionType.RecordRoute, &record_route_op);

    try ipv4_layer_iface.ipv4Layer.add_option(op, allocator);

    var packet = try Packet.create(allocator, allocator);

    try expect(try packet.add_layer(&ipv4_layer_iface));

    //   print("========================== END ==========================\n", .{});
}
