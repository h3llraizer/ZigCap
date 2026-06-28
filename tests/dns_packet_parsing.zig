const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const Packet = zigcap.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const IPProtocol = zigcap.ProtocolEnums.IPProtocol;
const tcp_ip_protocol = zigcap.tcp_ip_protocol;

const Eth = zigcap.Eth;
const IPv4 = zigcap.IPv4;
const UDP = zigcap.UDP;
const DNS = zigcap.DNS;

// The purpose of this test is to parse a DNS packet which is known to have the expected values, in particular checking the DNS parsing via the DNS Layer, and also to confirm the packet it is not mutated.
test "parse dns packet" {
    const ziggit_dev_a_resp: [97]u8 = [_]u8{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x8, 0x0, 0x45, 0x0, 0x0, 0x53, 0xd, 0x2a, 0x40, 0x0, 0x40, 0x11, 0xa8, 0x40, 0xc0, 0xa8, 0x1, 0xfe, 0xc0, 0xa8, 0x1, 0xe1, 0x0, 0x35, 0xee, 0x99, 0x0, 0x3f, 0x26, 0xd1, 0x5a, 0xf2, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x6, 0x7a, 0x69, 0x67, 0x67, 0x69, 0x74, 0x3, 0x64, 0x65, 0x76, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x3, 0x56, 0x0, 0x4, 0xaa, 0xbb, 0xcb, 0x4d, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var raw_packet_buffer: std.ArrayList(u8) = .empty;
    //    defer raw_packet_buffer.deinit(allocator); - doesn't need to be called because Packet takes ownership but it is still safe to do so

    try raw_packet_buffer.appendSlice(allocator, &ziggit_dev_a_resp);

    const original_raw_packet_buffer_len = raw_packet_buffer.items.len;

    var packet = Packet.create(allocator, allocator);
    try packet.from_raw(allocator, &raw_packet_buffer, link_layer_type.ETHERNET, null);
    defer packet.deinit();

    try expect(packet.get_layer_count() == 4);

    try expect(packet.last_layer.?.layer_iface.get_protocol() == tcp_ip_protocol.dns);

    const eth_layer: Eth.EthLayer = packet.get_layer_of_type(Eth.EthLayer) orelse {
        try expect(false); // packet does not have EthLayer
        return;
    };

    const eth_hdr = eth_layer.get_immutable_header();

    try expect(eth_hdr.get_eth_type() == Eth.EthType.IP);

    const expected_src_eth: [6]u8 = .{ 0x38, 0x06, 0xe6, 0x92, 0x63, 0xac };
    try expect(std.mem.eql(u8, &eth_hdr.get_src_mac().addr, &expected_src_eth));

    const expected_dst_eth: [6]u8 = .{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d };
    try expect(std.mem.eql(u8, &eth_hdr.get_dst_mac().addr, &expected_dst_eth));

    var ipv4_layer: IPv4.IPv4Layer = packet.get_layer_of_type(IPv4.IPv4Layer) orelse {
        try expect(false); // packet does not have IPv4 Layer
        return;
    };

    const ipv4_hdr = ipv4_layer.get_immutable_header();
    try expect(ipv4_hdr.get_checksum() == 43072);
    const expected_dst_ip: [4]u8 = .{ 0xc0, 0xa8, 0x01, 0xe1 };
    try expect(std.mem.eql(u8, &ipv4_hdr.get_dst_ip().array, &expected_dst_ip));

    const expected_src_ip: [4]u8 = .{ 0xc0, 0xa8, 0x01, 0xfe };
    try expect(std.mem.eql(u8, &ipv4_hdr.get_src_ip().array, &expected_src_ip));

    try expect(ipv4_hdr.get_ttl() == 64);

    try expect(ipv4_hdr.get_ihl() == 5);

    try expect(ipv4_layer.get_header_len() == 20);

    try expect(ipv4_layer.get_payload().len == 63);

    try expect(ipv4_hdr.get_length() == 83);

    try expect(try ipv4_layer.get_ip_proto() == IPProtocol.UDP);

    var udp_layer: UDP.UDPLayer = packet.get_layer_of_type(UDP.UDPLayer) orelse {
        try expect(false); // packet does not have UDP layer
        return;
    };

    const udp_hdr = udp_layer.get_immutable_header();

    try expect(udp_hdr.get_src_port() == 53);
    try expect(udp_hdr.get_dst_port() == 61081);
    try expect(udp_hdr.get_length() == 63);
    try expect(udp_hdr.get_checksum() == 9937);

    var dns_layer: DNS.DNSLayer = packet.get_layer_of_type(DNS.DNSLayer) orelse {
        try expect(false); // packet does not have DNS layer
        return;
    };

    const hdr = dns_layer.get_immutable_header();
    try expect(hdr.get_ancount() == 1);
    try expect(hdr.get_arcount() == 1);
    try expect(hdr.get_nscount() == 0);
    try expect(hdr.get_qdcount() == 1);
    try expect(hdr.get_id() == 23282);

    var queries = try dns_layer.get_queries(allocator) orelse {
        try expect(false); // failed to get queries
        return;
    };

    defer queries.deinit(allocator);

    //    try dns_layer.get_queries(); // doesn't need to be called when get_answers() is called
    var answers = try dns_layer.get_answers(allocator) orelse {
        try expect(false);
        return;
    };

    defer answers.deinit(allocator);

    var query = queries.first orelse {
        try expect(false);
        return;
    };

    const qname = try query.decode_qname(allocator);
    defer allocator.free(qname);
    try expect(std.mem.eql(u8, qname, "ziggit.dev"));

    try expect(query.qtype == DNS.QueryType.A);
    try expect(query.qclass == DNS.DnsClass.IN);

    var answer = answers.first orelse {
        try expect(false);
        return;
    };

    const name = try answer.get_name(allocator);
    defer allocator.free(name);

    try expect(std.mem.eql(u8, name, "ziggit.dev"));

    try expect(answer.get_class_type() == DNS.DnsClass.IN);
    try expect(answer.get_rr_type() == DNS.QueryType.A);

    try expect(answer.get_ttl() == 854);

    const ip = answer.a.get_ip();

    const ip_str = try ip.to_string(allocator);
    defer allocator.free(ip_str);
    try expect(std.mem.eql(u8, ip_str, "170.187.203.77"));

    try expect(original_raw_packet_buffer_len == 97);

    const original_raw_packet_buffer = raw_packet_buffer.items;

    try expect(original_raw_packet_buffer.len == 0);

    try expect(packet.get_raw().len == 97); // confirms that the packet buffer passed in at the start has not changed in lenghth during parsing

    try expect(ipv4_hdr.get_checksum() == 43072); // confirms ipv4 hdr has not mutated since parsing

    try expect(udp_hdr.get_checksum() == 9937); // confirms the ip addressing, udp header and payload have not mutated since parsing

    udp_layer = packet.get_layer_of_type(UDP.UDPLayer) orelse {
        try expect(false); // no udp layer
        return;
    };
    udp_layer.validate_layer();
    const udp_layer_header = udp_layer.get_immutable_header();

    try expect(udp_layer_header.get_checksum() == 9937);

    //try expect(std.mem.eql(u8, &raw_packet_buffer.items, &ziggit_dev_a_resp));

}
