const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const Packet = zigcap.Packet.Packet;
const ProtocolEnums = zigcap.ProtocolEnums;
const link_layer_type = ProtocolEnums.link_layer_type;
const IPProtocol = ProtocolEnums.IPProtocol;
const tcp_ip_protocol = zigcap.tcp_ip_protocol;
const LayerOwner = zigcap.Owner.LayerOwner;
const TLVOwner = zigcap.Owner.TLVOwner;
const LayerIface = zigcap.LayerIface;

const IPv6 = zigcap.IPv6;
const IPv6Extensions = IPv6.IPv6Extensions;

const UDP = zigcap.UDP;

test "build" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var packet = try Packet.create(allocator, allocator);
    defer packet.deinit();

    const tlv_owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };

    var hbh: IPv6Extensions.HopByHop = try IPv6Extensions.HopByHop.init(tlv_owner);
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

    var ipv6_layer_iface = try LayerIface.init(IPv6.IPv6Layer, tmp_owner);
    defer ipv6_layer_iface.deinit();

    var udp_layer_iface = try LayerIface.init(UDP.UDPLayer, tmp_owner);
    defer udp_layer_iface.deinit();

    udp_layer_iface.udpLayer.get_mutable_header().set_src_port(1234);
    udp_layer_iface.udpLayer.get_mutable_header().set_dst_port(5005);

    try packet.add_layer(&ipv6_layer_iface);
    try packet.add_layer(&udp_layer_iface);

    var ipv6_layer: *IPv6.IPv6Layer = packet.get_layer_of_type(IPv6.IPv6Layer) orelse {
        try expect(false); // failed to get IPv6 layer from packet
        return;
    };

    try expect(ipv6_layer.get_immutable_header().get_payload_length() == 0);

    const src_ip = try IPv6.IPv6Address.init_from_string("3a4f:0c91:7b2d:9e10:4f6a:bb83:01d7:6c2e");
    const dst_ip = try IPv6.IPv6Address.init_from_string("f1c0:8a3e:2d19:5b7f:9c44:0e6a:73d2:18bf");

    ipv6_layer.get_mutable_header().set_src_ip(src_ip);
    ipv6_layer.get_mutable_header().set_dst_ip(dst_ip);

    try expect(ipv6_layer.owner.packet_layer.length == IPv6.IPv6HeaderSize);

    var hbh_ext = IPv6.ExtensionHeader{ .hop_by_hop = hbh };

    try ipv6_layer.add_extension(&hbh_ext);

    try expect(ipv6_layer.owner.packet_layer.length == IPv6.IPv6HeaderSize + hbh_ext.get_data().len);

    try expect(ipv6_layer.get_immutable_header().get_payload_length() == 8);

    try ipv6_layer.remove_extension(&hbh_ext);

    try expect(ipv6_layer.owner.packet_layer.length == IPv6.IPv6HeaderSize);

    try expect(ipv6_layer.get_immutable_header().get_payload_length() == 0);
}
