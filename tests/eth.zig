const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const LayerOwner = zigcap.Layer.LayerOwner;
const LayerIface = zigcap.LayerIface;
const Eth = zigcap.Eth;

test "build independant eth layer" {
    var eth_layer_owner = LayerOwner{ .owned_buffer = .init_empty(std.heap.page_allocator) };

    defer eth_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);

    var eth_layer: Eth.EthLayer = try Eth.EthLayer.init(eth_layer_owner);

    var eth_hdr = eth_layer.get_mutable_header();

    eth_hdr.set_eth_type(Eth.EthType.IP);

    try expect(eth_hdr.get_eth_type() == Eth.EthType.IP);

    eth_hdr.set_dst_mac(try Eth.MacAddress.init_from_string("1A:2A:3A:4A:5A:6A"));

    eth_hdr.set_src_mac(try Eth.MacAddress.init_from_string("1B:2B:3B:4B:5B:6B"));
}
