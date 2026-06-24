const std = @import("std");
const zigcap = @import("zigcap");
const print = std.debug.print;
const expect = std.testing.expect;

const Packet = zigcap.Packet.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const LayerOwner = zigcap.Owner.LayerOwner;
const Layer = zigcap.Layer;
const ARP = zigcap.ARP;
const IPv4 = zigcap.IPv4;
const Eth = zigcap.Eth;
const UDP = zigcap.UDP;
const DNS = zigcap.DNS;
const ApplicationLayer = zigcap.ApplicationLayer;
const IPProtocol = zigcap.ProtocolEnums.IPProtocol;
const tcp_ip_protocol = zigcap.tcp_ip_protocol;

test "packet buffer" {
    const raw: [93]u8 = [_]u8{ 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x4f, 0xcd, 0x45, 0x0, 0x0, 0x80, 0x11, 0xe8, 0x28, 0xc0, 0xa8, 0x1, 0xe1, 0xc0, 0xa8, 0x1, 0xfe, 0xc5, 0xd1, 0x0, 0x35, 0x0, 0x3b, 0x74, 0x70, 0xb7, 0x79, 0x1, 0x20, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x6, 0x7a, 0x69, 0x67, 0x67, 0x69, 0x74, 0x3, 0x64, 0x65, 0x76, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x29, 0x4, 0xd0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x0, 0xa, 0x0, 0x8, 0xa0, 0xd9, 0x37, 0x2e, 0xaa, 0x24, 0xf8, 0x1d };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var raw_packet_buffer: std.ArrayList(u8) = .empty;

    try raw_packet_buffer.appendSlice(allocator, &raw);
    raw_packet_buffer.deinit(allocator);
}

test "layer owner" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    //defer tmp_buf.deinit();

    var eth_layer_iface: Layer = try Layer.init(Eth.EthLayer, allocator);
    defer eth_layer_iface.deinit();

    var eth_hdr: *Eth.EthHeader = eth_layer_iface.ethLayer.get_mutable_header();

    eth_hdr.set_src_mac(try Eth.MacAddress.init_from_string("14:4f:8a:a4:15:7d"));
    eth_hdr.set_dst_mac(try Eth.MacAddress.init_from_string("38:06:e6:92:63:ac"));
    eth_hdr.set_eth_type(Eth.EthType.IP);

    //   var ipv4_layer_iface: Layer = try Layer.init(IPv4.IPv4Layer, owner);
    //   defer ipv4_layer_iface.deinit();
    //
    //   var ipv4_hdr: *IPv4.IPv4Header = ipv4_layer_iface.ipv4Layer.get_mutable_header();
    //
    //   ipv4_hdr.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.225"));
    //   ipv4_hdr.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.254"));
    //   ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.ICMP);
}
