const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const LayerOwner = zigcap.Owner.LayerOwner;
const LayerIface = zigcap.LayerIface;
const VLAN = zigcap.VLAN;
const Eth = zigcap.Eth;
const Packet = zigcap.Packet.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;

test "parse vlan_tagged_tcp_syn_ack" {
    const vlan_tagged_tcp_syn_ack: [70]u8 align(2) = [_]u8{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x81, 0x0, 0x0, 0x0, 0x8, 0x0, 0x45, 0x60, 0x0, 0x34, 0x0, 0x0, 0x40, 0x0, 0x7a, 0x6, 0xca, 0x1b, 0x23, 0xbe, 0x50, 0x1, 0xc0, 0xa8, 0x1, 0xe1, 0x1, 0xbb, 0x65, 0x31, 0xc9, 0x82, 0x66, 0xa, 0x5c, 0x95, 0xc4, 0x84, 0x80, 0x12, 0xff, 0xff, 0x81, 0x54, 0x0, 0x0, 0x2, 0x4, 0x5, 0x84, 0x1, 0x1, 0x4, 0x2, 0x1, 0x3, 0x3, 0x8 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    var raw_packet_buffer: std.array_list.Aligned(u8, std.mem.Alignment.@"2") = .empty;

    try raw_packet_buffer.appendSlice(allocator, &vlan_tagged_tcp_syn_ack);

    var packet = try Packet.create(allocator, allocator);
    try packet.from_raw(allocator, &raw_packet_buffer, link_layer_type.ETHERNET, null);
    defer packet.deinit();

    //    packet.print_layers_meta();
}

test "build independant vlan layer" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;

    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const tmp = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    var vlan_iface: LayerIface = try LayerIface.init(VLAN.VlanLayer, tmp);
    defer vlan_iface.deinit();

    var vlan_hdr = vlan_iface.vlanLayer.get_mutable_header();

    vlan_hdr.set_tpi(Eth.EthType.IP);

    try expect(vlan_hdr.get_tpi() == Eth.EthType.IP);
}
