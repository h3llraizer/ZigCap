const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const Packet = zigcap.Packet;
const ProtocolEnums = zigcap.ProtocolEnums;
const link_layer_type = ProtocolEnums.link_layer_type;
const IPProtocol = ProtocolEnums.IPProtocol;
const tcp_ip_protocol = zigcap.tcp_ip_protocol;

const Eth = zigcap.Eth;
const IPv4 = zigcap.IPv4;
const TCP = zigcap.TCP;
const ApplicationLayer = zigcap.ApplicationLayer;

test "parse tcp syn packet" {
    var tcp_syn_req = [_]u8{ 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x34, 0x8c, 0x1a, 0x40, 0x0, 0x80, 0x6, 0xe9, 0x79, 0xc0, 0xa8, 0x1, 0xe1, 0xc0, 0xa8, 0x1, 0xfe, 0x7f, 0x91, 0x13, 0x8d, 0xe4, 0x4b, 0x4a, 0xa5, 0x0, 0x0, 0x0, 0x0, 0x80, 0x2, 0xff, 0xff, 0x27, 0xd1, 0x0, 0x0, 0x2, 0x4, 0x5, 0xb4, 0x1, 0x3, 0x3, 0x8, 0x1, 0x1, 0x4, 0x2 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var raw_packet_buffer: std.ArrayList(u8) = .empty;
    //    defer raw_packet_buffer.deinit(allocator); - doesn't need to be called because Packet takes ownership but it is still safe to do so

    try raw_packet_buffer.appendSlice(allocator, &tcp_syn_req);

    //const original_raw_packet_buffer_len = raw_packet_buffer.items.len;

    var packet = Packet.create(allocator, allocator);
    try packet.from_raw(allocator, &raw_packet_buffer, link_layer_type.ETHERNET, null);
    defer packet.deinit();

    try expect(packet.get_layer_count() == 3);

    try expect(packet.has_protocol_layer(tcp_ip_protocol.eth));
    try expect(packet.has_protocol_layer(tcp_ip_protocol.ipv4));
    try expect(packet.has_protocol_layer(tcp_ip_protocol.tcp));

    const eth_layer: Eth.EthLayer = packet.get_layer_of_type(Eth.EthLayer) orelse {
        try expect(false); // packet does not have EthLayer
        return;
    };

    const eth_hdr = eth_layer.get_immutable_header();

    try expect(eth_hdr.get_eth_type() == Eth.EthType.IP);

    const expected_dst_eth: [6]u8 = .{ 0x38, 0x06, 0xe6, 0x92, 0x63, 0xac };
    try expect(std.mem.eql(u8, &eth_hdr.get_dst_mac().addr, &expected_dst_eth));

    const expected_src_eth: [6]u8 = .{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d };
    try expect(std.mem.eql(u8, &eth_hdr.get_src_mac().addr, &expected_src_eth));

    const ipv4_layer: IPv4.IPv4Layer = packet.get_layer_of_type(IPv4.IPv4Layer) orelse {
        try expect(false); // packet does not have IPv4 Layer
        return;
    };

    const ipv4_hdr = ipv4_layer.get_immutable_header();
    try expect(ipv4_hdr.get_checksum() == 59769);

    const expected_src_ip: [4]u8 = .{ 0xc0, 0xa8, 0x01, 0xe1 };
    try expect(std.mem.eql(u8, &ipv4_hdr.get_src_ip().array, &expected_src_ip));

    const expected_dst_ip: [4]u8 = .{ 0xc0, 0xa8, 0x01, 0xfe };
    try expect(std.mem.eql(u8, &ipv4_hdr.get_dst_ip().array, &expected_dst_ip));

    try expect(ipv4_hdr.get_ttl() == 128);

    try expect(ipv4_hdr.get_ihl() == 5);

    try expect(ipv4_layer.get_header_len() == 20);

    try expect(ipv4_layer.get_payload().len == 32);

    try expect(ipv4_hdr.get_length() == 52);

    try expect(try ipv4_layer.get_ip_proto() == IPProtocol.TCP);

    var tcp_layer: TCP.TCPLayer = packet.get_layer_of_type(TCP.TCPLayer) orelse {
        try expect(false); // packet does not have TCP layer
        return;
    };

    var tcp_hdr = tcp_layer.get_immutable_header();

    const hdr_length = tcp_hdr.get_hdr_length();

    try expect(hdr_length == 32);

    try expect(tcp_hdr.get_src_port() == 32657);
    try expect(tcp_hdr.get_dst_port() == 5005);
    try expect(tcp_hdr.get_seq_num() == 2773109732);
    try expect(tcp_hdr.get_ack_num() == 0);
    try expect(tcp_hdr.get_window() == 65535);
    try expect(tcp_hdr.get_checksum() == 10193);
    try expect(tcp_hdr.get_urgent_ptr() == 0);

    const tcp_flags = tcp_hdr.get_flags_immutable();

    try expect(tcp_flags.cwr == 0);
    try expect(tcp_flags.ece == 0);
    try expect(tcp_flags.urg == 0);
    try expect(tcp_flags.ack == 0);
    try expect(tcp_flags.psh == 0);
    try expect(tcp_flags.rst == 0);
    try expect(tcp_flags.syn == 1);
    try expect(tcp_flags.fin == 0);

    try expect(tcp_layer.has_option(TCP.TCPOption.WS));
    try expect(tcp_layer.has_option(TCP.TCPOption.MSS));

    tcp_layer.validate_layer(); // doesn't do anything for independant layer

    try expect(tcp_layer.get_immutable_header().get_checksum() == 10193);

    try expect(packet.get_transport_type().? == .tcp);

    try expect(std.meta.activeTag(packet.get_transport_layer().?) == .tcp);
}
