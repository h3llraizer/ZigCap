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

    const tmp_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    var ipv6_layer = try IPv6.IPv6Layer.init(tmp_owner);
    defer ipv6_layer.deinit();

    var hbh_ext = IPv6.ExtensionHeader{ .hop_by_hop = hbh };

    try ipv6_layer.add_extension(&hbh_ext);

    var extensions = try ipv6_layer.get_extensions(allocator) orelse {
        try expect(false); // failed to get extension headers
        return;
    };

    defer extensions.deinit(allocator);

    //   print("ipv6 data: {x}\n", .{ipv6_layer_iface.get_data()});

    try expect(extensions.ext_header_count == 1);

    print("ipv6 layer: ({}) {x}\n", .{ ipv6_layer.get_data().len, ipv6_layer.get_data() });

    var cur = extensions.first;
    while (cur) |ext| {
        print("{any}\n", .{ext.get_type()});
        print("data: {x}\n", .{ext.hop_by_hop.get_data()});
        print("offset: {}\n", .{ext.hop_by_hop.get_offset()});
        print("ipv6 ext buf: {x}\n", .{ipv6_layer.get_data()[ext.hop_by_hop.get_offset()..]});
        print("{any}\n", .{ext.hop_by_hop.get_opt_type()});
        print("opt len: {}\n", .{ext.hop_by_hop.get_opt_len()});
        print("opt value: {}\n", .{ext.hop_by_hop.get_opt_value()});

        print("pad option: {any}\n", .{ext.hop_by_hop.get_pad_option()});

        print("pad len: {}\n", .{ext.hop_by_hop.get_pad_len()});
        cur = ext.get_next();
    }
}
