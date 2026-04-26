const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const LayerOwner = zigcap.Layer.LayerOwner;
const LayerIface = zigcap.LayerIface;
const UDP = zigcap.UDP;

test "build udp layer independant" {
    //  print("========================== START ==========================\n", .{});
    //  print("build udp layer independant\n", .{});
    var udp_layer_owner = LayerOwner{ .owned_buffer = .init_empty(std.heap.page_allocator) };

    defer udp_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);

    var udp_layer_iface: LayerIface = try LayerIface.init(UDP.UDPLayer, udp_layer_owner);

    var udp_hdr = udp_layer_iface.udpLayer.get_mutable_header();

    udp_hdr.set_src_port(1024);
    udp_hdr.set_dst_port(53);

    //  print("========================== END ==========================\n", .{});
}

test "parse udp layer" {}
