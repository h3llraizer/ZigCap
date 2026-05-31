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
const TLVOwner = zigcap.Layer.TLVOwner;
const LayerIface = zigcap.LayerIface;

const IPv6 = zigcap.IPv6;

test "hop-by-hop" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const tlv_owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };

    var hbh: IPv6.HobByHop = try IPv6.HobByHop.init(tlv_owner);
    defer hbh.deinit();

    try expect(hbh.get_data().len == 8);

    hbh.set_opt_type(.ROUTER_ALERT);

    hbh.set_opt_value(0);

    hbh.set_pad_option(1);

    try expect(hbh.get_opt_type() == .ROUTER_ALERT);

    try expect(hbh.get_opt_len() == 2);

    try expect(hbh.get_opt_value() == 0);

    try expect(hbh.get_pad_option() == .PADN);

    try expect(hbh.get_pad_len() == 0);
}
