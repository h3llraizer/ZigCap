const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const LayerOwner = zigcap.Layer.LayerOwner;
const LayerIface = zigcap.LayerIface;
const Eth = zigcap.Eth;
const ARP = zigcap.ARP;
const IPv4 = zigcap.IPv4;
const ICMP = zigcap.ICMP;

test "build icmp request" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    var icmp_layer_iface: LayerIface = try LayerIface.init(ICMP.ICMPLayer, owner);

    defer icmp_layer_iface.deinit();
}
