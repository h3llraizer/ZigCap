const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const LayerOwner = zigcap.Owner.LayerOwner;
const Layer = zigcap.Layer;
const Eth = zigcap.Eth;

test "init ethlayer from slice" {
    var data = [_]u8{ 0xf0, 0x68, 0xe3, 0x5a, 0xac, 0x9e, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x8, 0x0, 0x45, 0x0, 0x0, 0x89, 0x52, 0xfa, 0x0, 0x0, 0x79, 0x6, 0x32, 0xb3, 0xac, 0xd9, 0x4c, 0x5f, 0xc0, 0xa8, 0x1, 0xe1 };

    var dba: std.heap.DebugAllocator(.{}) = .init;
    _ = dba.detectLeaks();

    const allocator = dba.allocator();

    var eth_layer: Eth.EthLayer = try Eth.EthLayer.initFromSlice(data[0..], allocator);
    defer eth_layer.deinit();

    const hdr = eth_layer.get_immutable_header();

    try expect(hdr.get_eth_type() == .IP);

    try expect(std.mem.eql(u8, &hdr.get_dst_mac().addr, &(try Eth.MacAddress.init_from_string("f0:68:e3:5a:ac:9e")).addr));

    try expect(std.mem.eql(u8, &hdr.get_src_mac().addr, &(try Eth.MacAddress.init_from_string("38:06:e6:92:63:ac")).addr));
}

test "build independant eth layer" {
    var dba: std.heap.DebugAllocator(.{}) = .init;
    _ = dba.detectLeaks();

    const allocator = dba.allocator();

    var eth_layer: Eth.EthLayer = try Eth.EthLayer.init(allocator);

    var eth_hdr = eth_layer.get_mutable_header();

    eth_hdr.set_eth_type(Eth.EthType.IP);

    try expect(eth_hdr.get_eth_type() == Eth.EthType.IP);

    eth_hdr.set_dst_mac(try Eth.MacAddress.init_from_string("1A:2A:3A:4A:5A:6A"));

    eth_hdr.set_src_mac(try Eth.MacAddress.init_from_string("1B-2B-3B-4B-5B-6B"));
}
