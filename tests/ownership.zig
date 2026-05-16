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
