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

const Eth = zigcap.Eth;
const IPv6 = zigcap.IPv6;
const TCP = zigcap.TCP;
const ApplicationLayer = zigcap.ApplicationLayer;

test "build ipv6 layer" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var tmp_buf: LayerOwner = LayerOwner{ .owned_buffer = .init(allocator) };
    defer _ = tmp_buf.owned_buffer.deinit();

    const ipv6_iface = try LayerIface.init(IPv6.IPv6Layer, tmp_buf);

    _ = ipv6_iface;
}
