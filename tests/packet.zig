const std = @import("std");
const zigcap = @import("zigcap");
const print = std.debug.print;
const expect = std.testing.expect;

const Packet = zigcap.Packet;
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

test "packet layer extract" {
    const raw: [93]u8 = [_]u8{ 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x4f, 0xcd, 0x45, 0x0, 0x0, 0x80, 0x11, 0xe8, 0x28, 0xc0, 0xa8, 0x1, 0xe1, 0xc0, 0xa8, 0x1, 0xfe, 0xc5, 0xd1, 0x0, 0x35, 0x0, 0x3b, 0x74, 0x70, 0xb7, 0x79, 0x1, 0x20, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x6, 0x7a, 0x69, 0x67, 0x67, 0x69, 0x74, 0x3, 0x64, 0x65, 0x76, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x29, 0x4, 0xd0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x0, 0xa, 0x0, 0x8, 0xa0, 0xd9, 0x37, 0x2e, 0xaa, 0x24, 0xf8, 0x1d };

    const raw_hash = std.hash.Wyhash.hash(0, &raw); // hash original data

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var raw_packet_buffer: std.ArrayList(u8) = .empty;

    try raw_packet_buffer.appendSlice(allocator, &raw);

    const buffer_hash = std.hash.Wyhash.hash(0, raw_packet_buffer.items);

    try expect(raw_hash == buffer_hash);

    var packet = Packet.create(allocator, allocator);
    try packet.from_raw(allocator, &raw_packet_buffer, link_layer_type.ETHERNET, null);
    defer packet.deinit();

    const packet_buf_hash = std.hash.Wyhash.hash(0, packet.get_raw());

    try expect(raw_hash == packet_buf_hash);

    try expect(packet.get_layer_count() == 4);

    try expect(packet.has_protocol_layer(.eth));
    try expect(packet.has_protocol_layer(.ipv4));
    try expect(packet.has_protocol_layer(.udp));
    try expect(packet.has_protocol_layer(.dns));

    const ipv4_layer: IPv4.IPv4Layer = packet.get_layer_of_type(IPv4.IPv4Layer) orelse {
        try expect(false); // failed to retrieve ipv4 layer in packet
        return;
    };

    try expect(ipv4_layer.owner.packet_layer.offset == 14);
    try expect(ipv4_layer.owner.packet_layer.length == 20);

    const ip_hdr: *const IPv4.IPv4Header = ipv4_layer.get_immutable_header();
    const ip_hdr_bytes: []const u8 = std.mem.asBytes(ip_hdr);

    try expect(std.mem.eql(u8, ip_hdr_bytes, raw[14..34])); // confirm the header (as bytes) we have matches the original

    //    const ipv4_checksum = ipv4_layer.layer_iface.ipv4Layer.get_immutable_header().get_checksum();

    var ipv4_layer_iface = try packet.extract_layer(Layer{ .ipv4Layer = ipv4_layer }, allocator) orelse {
        try expect(false); // failed to extract ipv4 layer from packet
        return;
    };

    defer ipv4_layer_iface.deinit();

    try expect(std.mem.eql(u8, ipv4_layer_iface.get_data(), raw[14..34])); // confirm the extracted ipv4 layer contains the same bytes as the original

    try expect(packet.has_protocol_layer(.ipv4) == false);

    const eth_layer = packet.get_layer_of_type(Eth.EthLayer) orelse {
        try expect(false); // failed to retrieve eth layer in packet
        return;
    };

    _ = try packet.insert_layer(Layer{ .ethLayer = eth_layer }, &ipv4_layer_iface);

    const packet_buf_post_mod = std.hash.Wyhash.hash(0, packet.get_raw());

    // the original packet which we extracted the ipv4 layer from and then re-inserted back into the position it was at previously should yield the same hash at the original buffer
    try expect(raw_hash == packet_buf_post_mod);

    try expect(packet.get_layer_count() == 4);

    // and finally confirm all protocol layers are there
    try expect(packet.has_protocol_layer(.eth));
    try expect(packet.has_protocol_layer(.ipv4));
    try expect(packet.has_protocol_layer(.udp));
    try expect(packet.has_protocol_layer(.dns));
}

test "packet dissection" {
    const raw: [93]u8 = [_]u8{ 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x4f, 0xcd, 0x45, 0x0, 0x0, 0x80, 0x11, 0xe8, 0x28, 0xc0, 0xa8, 0x1, 0xe1, 0xc0, 0xa8, 0x1, 0xfe, 0xc5, 0xd1, 0x0, 0x35, 0x0, 0x3b, 0x74, 0x70, 0xb7, 0x79, 0x1, 0x20, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x6, 0x7a, 0x69, 0x67, 0x67, 0x69, 0x74, 0x3, 0x64, 0x65, 0x76, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x29, 0x4, 0xd0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x0, 0xa, 0x0, 0x8, 0xa0, 0xd9, 0x37, 0x2e, 0xaa, 0x24, 0xf8, 0x1d };

    const raw_hash = std.hash.Wyhash.hash(0, &raw); // hash original data

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var raw_packet_buffer: std.ArrayList(u8) = .empty;

    try raw_packet_buffer.appendSlice(allocator, &raw);

    const buffer_hash = std.hash.Wyhash.hash(0, raw_packet_buffer.items);

    try expect(raw_hash == buffer_hash);

    var packet = Packet.create(allocator, allocator);
    try packet.from_raw(allocator, &raw_packet_buffer, link_layer_type.ETHERNET, null);
    defer packet.deinit();

    const packet_buf_hash = std.hash.Wyhash.hash(0, packet.get_raw());

    try expect(raw_hash == packet_buf_hash);

    try expect(packet.get_layer_count() == 4);

    try expect(packet.has_protocol_layer(.eth));
    try expect(packet.has_protocol_layer(.ipv4));
    try expect(packet.has_protocol_layer(.udp));
    try expect(packet.has_protocol_layer(.dns));

    const ipv4_layer = packet.get_layer_of_type(IPv4.IPv4Layer) orelse {
        try expect(false); // failed to retrieve ipv4 layer in packet
        return;
    };

    try expect(ipv4_layer.owner.packet_layer.offset == 14);
    try expect(ipv4_layer.owner.packet_layer.length == 20);

    const ip_hdr: *const IPv4.IPv4Header = ipv4_layer.get_immutable_header();

    const ip_hdr_bytes: []const u8 = std.mem.asBytes(ip_hdr);

    try expect(std.mem.eql(u8, ip_hdr_bytes, raw[14..34])); // confirm the header (as bytes) we have matches the original

    //    const ipv4_checksum = ipv4_layer.layer_iface.ipv4Layer.get_immutable_header().get_checksum();

    var ipv4_layer_iface = try packet.extract_layer(Layer{ .ipv4Layer = ipv4_layer }, allocator) orelse {
        try expect(false); // failed to extract ipv4 layer from packet
        return;
    };

    defer ipv4_layer_iface.deinit();

    try expect(std.mem.eql(u8, ipv4_layer_iface.get_data(), raw[14..34])); // confirm the extracted ipv4 layer contains the same bytes as the original

    try expect(packet.has_protocol_layer(.ipv4) == false);

    const eth_layer = packet.get_layer_of_type(Eth.EthLayer) orelse {
        try expect(false); // failed to retrieve eth layer in packet
        return;
    };

    _ = try packet.insert_layer(Layer{ .ethLayer = eth_layer }, &ipv4_layer_iface);

    const packet_buf_post_mod = std.hash.Wyhash.hash(0, packet.get_raw());

    // the original packet which we extracted the ipv4 layer from and then re-inserted back into the position it was at previously should yield the same hash at the original buffer
    try expect(raw_hash == packet_buf_post_mod);

    try expect(packet.get_layer_count() == 4);

    // and finally confirm all protocol layers are there
    try expect(packet.has_protocol_layer(.eth));
    try expect(packet.has_protocol_layer(.ipv4));
    try expect(packet.has_protocol_layer(.udp));
    try expect(packet.has_protocol_layer(.dns));
}

test "packet extract layers" {
    const raw: [93]u8 = [_]u8{ 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x4f, 0xcd, 0x45, 0x0, 0x0, 0x80, 0x11, 0xe8, 0x28, 0xc0, 0xa8, 0x1, 0xe1, 0xc0, 0xa8, 0x1, 0xfe, 0xc5, 0xd1, 0x0, 0x35, 0x0, 0x3b, 0x74, 0x70, 0xb7, 0x79, 0x1, 0x20, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x6, 0x7a, 0x69, 0x67, 0x67, 0x69, 0x74, 0x3, 0x64, 0x65, 0x76, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x29, 0x4, 0xd0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x0, 0xa, 0x0, 0x8, 0xa0, 0xd9, 0x37, 0x2e, 0xaa, 0x24, 0xf8, 0x1d };

    const raw_hash = std.hash.Wyhash.hash(0, &raw); // hash original data

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var raw_packet_buffer: std.ArrayList(u8) = .empty;

    try raw_packet_buffer.appendSlice(allocator, &raw);

    const buffer_hash = std.hash.Wyhash.hash(0, raw_packet_buffer.items);

    try expect(raw_hash == buffer_hash);

    var packet = Packet.create(allocator, allocator);
    try packet.from_raw(allocator, &raw_packet_buffer, link_layer_type.ETHERNET, null);
    defer packet.deinit();

    const packet_buf_hash = std.hash.Wyhash.hash(0, packet.get_raw());

    try expect(raw_hash == packet_buf_hash);

    try expect(packet.get_layer_count() == 4);

    try expect(packet.has_protocol_layer(.eth));
    try expect(packet.has_protocol_layer(.ipv4));
    try expect(packet.has_protocol_layer(.udp));
    try expect(packet.has_protocol_layer(.dns));

    const dns_layer = packet.get_layer_of_type(DNS.DNSLayer) orelse {
        try expect(false); // failed to retrieve dns layer in packet
        return;
    };

    var dns_layer_iface: Layer = try packet.extract_layer(Layer{ .dnsLayer = dns_layer }, allocator) orelse {
        try expect(false); // failed to extract layer
        return;
    };

    defer dns_layer_iface.deinit();
}

test "packet delete layers" {
    const raw: [93]u8 = [_]u8{ 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x4f, 0xcd, 0x45, 0x0, 0x0, 0x80, 0x11, 0xe8, 0x28, 0xc0, 0xa8, 0x1, 0xe1, 0xc0, 0xa8, 0x1, 0xfe, 0xc5, 0xd1, 0x0, 0x35, 0x0, 0x3b, 0x74, 0x70, 0xb7, 0x79, 0x1, 0x20, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x6, 0x7a, 0x69, 0x67, 0x67, 0x69, 0x74, 0x3, 0x64, 0x65, 0x76, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x29, 0x4, 0xd0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x0, 0xa, 0x0, 0x8, 0xa0, 0xd9, 0x37, 0x2e, 0xaa, 0x24, 0xf8, 0x1d };

    const raw_hash = std.hash.Wyhash.hash(0, &raw); // hash original data

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var raw_packet_buffer: std.ArrayList(u8) = .empty;

    try raw_packet_buffer.appendSlice(allocator, &raw);

    const buffer_hash = std.hash.Wyhash.hash(0, raw_packet_buffer.items);

    try expect(raw_hash == buffer_hash);

    var packet = Packet.create(allocator, allocator);
    try packet.from_raw(allocator, &raw_packet_buffer, link_layer_type.ETHERNET, null);
    defer packet.deinit();

    const packet_buf_hash = std.hash.Wyhash.hash(0, packet.get_raw());

    try expect(raw_hash == packet_buf_hash);

    try expect(packet.get_layer_count() == 4);

    try expect(packet.has_protocol_layer(.eth));
    try expect(packet.has_protocol_layer(.ipv4));
    try expect(packet.has_protocol_layer(.udp));
    try expect(packet.has_protocol_layer(.dns));

    // if (packet.get_layer_of_type(DNS.DNSLayer)) |dns_layer| {
    //     try dns_layer.get_answers();
    // }

    const dns_layer: DNS.DNSLayer = packet.get_layer_of_type(DNS.DNSLayer) orelse {
        try expect(false); // failed to retrieve dns layer in packet
        return;
    };

    _ = try packet.delete_layer(Layer{ .dnsLayer = dns_layer });
}
