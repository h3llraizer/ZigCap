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
const IPProtocol = zigcap.ProtocolEnums.IPProtocol;

test "build independant ipv4 layer" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);
    defer ipv4_layer_iface.deinit();

    var ipv4_hdr = ipv4_layer_iface.ipv4Layer.get_mutable_header();

    ipv4_hdr.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));

    ipv4_hdr.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.2"));

    ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);

    ipv4_hdr.set_ttl(64);
}

test "build ipv4 layer with Router Alert option" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    defer ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);

    var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);
    defer ipv4_layer_iface.deinit();

    var ipv4_hdr = ipv4_layer_iface.ipv4Layer.get_mutable_header();

    ipv4_hdr.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.225"));

    ipv4_hdr.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.254"));

    ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);

    ipv4_hdr.set_ttl(1);

    var router_alert_op: [2]u8 align(2) = [_]u8{ 0x00, 0x00 };

    const op = try IPv4.IPOption.init(IPv4.IPOptionType.RouterAlert, &router_alert_op);

    const op_bytes = try op.toBytes(allocator);
    defer allocator.free(op_bytes);

    try expect(op_bytes[0] == 0x94);
    try expect(op_bytes[1] == 0x04);
    try expect(op_bytes[2] == 0x00);
    try expect(op_bytes[3] == 0x00);

    try ipv4_layer_iface.ipv4Layer.add_option(op, allocator);

    const ipv4_slice = ipv4_layer_iface.ipv4Layer.get_data();

    try expect(ipv4_slice.len == 24);

    //   try ipv4_layer_iface.ipv4Layer.remove_all_options();

    const str = try ipv4_layer_iface.ipv4Layer.get_immutable_header().to_string(allocator);
    defer allocator.free(str);
}

test "build ipv4 layer with Record Route option" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    defer ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);

    var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);
    defer ipv4_layer_iface.deinit();

    var ipv4_hdr = ipv4_layer_iface.ipv4Layer.get_mutable_header();

    ipv4_hdr.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.225"));

    ipv4_hdr.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.254"));

    ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);

    ipv4_hdr.set_ttl(64);

    var data = ipv4_layer_iface.get_data();

    print("ipv4 data: ({}) {x}\n", .{ data.len, data });

    var record_route_op: [15]u8 align(2) = [_]u8{
        0x04, // ptr byte
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };

    const op = try IPv4.IPOption.init(IPv4.IPOptionType.RecordRoute, &record_route_op);

    const op_bytes = try op.toBytes(allocator);
    defer allocator.free(op_bytes);

    print("ops bytes: ({}) {x}\n", .{ op_bytes.len, op_bytes });

    try ipv4_layer_iface.ipv4Layer.add_option(op, allocator);

    print("ipv4 data: ({}) {x}\n", .{ ipv4_layer_iface.get_data().len, ipv4_layer_iface.get_data() });

    print("removing options.\n", .{});
    try ipv4_layer_iface.ipv4Layer.remove_all_options();
    print("options removed.\n", .{});

    data = ipv4_layer_iface.get_data();
    print("ipv4 data: ({}) {x}\n", .{ ipv4_layer_iface.get_data().len, ipv4_layer_iface.get_data() });

    const str = try ipv4_layer_iface.ipv4Layer.get_immutable_header().to_string(allocator);
    defer allocator.free(str);

    print("{s}\n", .{str});
}
