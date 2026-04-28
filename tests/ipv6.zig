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

const IPv6 = zigcap.IPv6;

test "parse ipv6 layer" {
    const ipv6_raw_layer: [48]u8 = [_]u8{ 0x60, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x40, 0x2a, 0x0, 0x23, 0xc8, 0x73, 0xa8, 0xc1, 0x1, 0xf2, 0xce, 0xcb, 0xf2, 0x41, 0x11, 0xc5, 0x54, 0x20, 0x1, 0xd, 0xb8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x3a, 0x0, 0x0, 0x1, 0x3, 0x0, 0x0, 0x0 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const ipv6_bytes = try allocator.alignedAlloc(u8, std.mem.Alignment.@"2", ipv6_raw_layer.len);
    @memmove(ipv6_bytes, ipv6_raw_layer[0..]);

    const buf: LayerOwner = LayerOwner{ .owned_buffer = try .init(ipv6_bytes, allocator) };

    var ipv6_iface = try LayerIface.init(IPv6.IPv6Layer, buf);
    defer ipv6_iface.deinit();

    const hdr = ipv6_iface.ipv6Layer.get_mutable_header();

    const src_str = try hdr.get_src_ip().to_string(allocator);
    defer allocator.free(src_str);

    const dst_ip = try hdr.get_dst_ip().to_string(allocator);
    defer allocator.free(dst_ip);

    try ipv6_iface.ipv6Layer.parse_extensions();
}

test "build ipv6 layer" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const tmp_buf: LayerOwner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
    //    defer _ = tmp_buf.owned_buffer.deinit();

    var ipv6_iface = try LayerIface.init(IPv6.IPv6Layer, tmp_buf);
    defer ipv6_iface.deinit();

    const hdr = ipv6_iface.ipv6Layer.get_mutable_header();

    hdr.set_src_ip(IPv6.IPv6Address.init_from_array(.{ 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x61, 0x8f, 0x26, 0x87, 0xeb, 0xbe, 0x60 }));
}
