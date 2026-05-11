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
    const ip = try IPv4.IPv4Address.init_from_string("192.168.1.133");

    const ip_slice: []const u8 = &ip.array;

    _ = ip_slice;

    //    print("ip_slice: {x}\n", .{ip_slice});
}
