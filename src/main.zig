const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;
const activeTag = std.meta.activeTag;

const PcapWrapper = @import("PcapWrapper.zig");

const Packet = @import("Packet.zig");

const LayerProtocols = @import("ProtocolHelpers.zig").LayerProtocols;
const get_next_layer_type = @import("ProtocolHelpers.zig").get_next_layer_type;

const LinkLayerProtocols = @import("ProtocolHelpers.zig").LinkLayerProtocols;
const NetworkProtocols = @import("ProtocolHelpers.zig").NetworkProtocols;
const TransportProtocols = @import("ProtocolHelpers.zig").TransportProtocols;

const IPv4Proto = @import("ProtocolEnums.zig").IPv4Proto;
const WirePacket = @import("WirePacket.zig").WirePacket;

const Eth = @import("Eth.zig");
const EthLayer = @import("Eth.zig").EthLayer;
const EthType = @import("Eth.zig").EthType;
const EthHeader = @import("Eth.zig").EthHeader;
const MacAddress = @import("Eth.zig").MacAddress;

const IPv4Layer = @import("IPv4.zig").IPv4Layer;
const IPv4Address = @import("IPv4.zig").IPv4Address;
const IPv4Header = @import("IPv4.zig").IPv4Header;

const DNSLayer = @import("DNS.zig").DNSLayer;
const UDPLayer = @import("UDPLayer.zig").UDPLayer;
const UDPHeader = @import("UDPLayer.zig").UDPHeader;
const DNS = @import("DNS.zig");

const GenericLayer = @import("GenericLayer.zig").GenericLayer;

const ARP = @import("ARP.zig");

const IPv6 = @import("IPv6.zig");

const ICMP = @import("ICMP.zig");

const TCP = @import("TCP.zig");

pub fn alignment_check(buffer: []u8, protocol_hdr: anytype) usize {
    const alignment = @alignOf(protocol_hdr);
    const addr = @intFromPtr(buffer.ptr);

    return addr % alignment;
}

pub fn test_ipv4_ext(allocator: Allocator) !void {
    const ipv4_ext_raw = [54]u8{
        // Ethernet Header
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Dest MAC
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Src MAC
        0x08, 0x00, // EtherType (IPv4)

        // IPv4 Header (IHL = 6 → includes 4 bytes options)
        0x46, // Version + IHL
        0x00, // DSCP/ECN
        0x00, 0x2c, // Total Length
        0x12, 0x34, // Identification
        0x40, 0x00, // Flags + Fragment Offset
        0x40, // TTL
        0x11, // Protocol (UDP)
        0xa6, 0xec, // Header checksum (approx)
        0xc0, 0xa8, 0x01, 0x01, // Src IP
        0xc0, 0xa8, 0x01, 0x02, // Dst IP

        // IPv4 Options (4 bytes to align to 24-byte header)
        0x01, // NOP
        0x02, 0x03, 0x04, // Arbitrary option data

        // UDP Header
        0x1f, 0x90, // Src port (8080)
        0x00, 0x35, // Dst port (53)
        0x00, 0x18, // Length
        0x00, 0x00, // Checksum (0 = unused in IPv4)

        // Payload ("HelloUDP")
        0x48, 0x65,
        0x6c, 0x6c,
        0x6f, 0x55,
        0x44, 0x50,
    };

    var packet = try Packet.Packet.create(allocator, LinkLayerProtocols.ETHERNET);
    //defer packet.deinit();

    const pkt_data: []u8 = try allocator.alloc(u8, ipv4_ext_raw.len);
    defer allocator.free(pkt_data);

    std.mem.copyForwards(u8, pkt_data, ipv4_ext_raw[0..]);

    print("Original: ({}) {x}\n", .{ pkt_data.len, pkt_data });

    var wire_packet = WirePacket.init(0, 0, pkt_data, LinkLayerProtocols.ETHERNET);

    try packet.from_wire_packet(&wire_packet);

    var ipv4_layer: IPv4Layer = try packet.get_layer_of_type(IPv4Layer) orelse {
        return;
    };

    print("{s}\n", .{ipv4_layer.to_string(std.heap.page_allocator)});

    print("IPv4 data: {x}\n", .{ipv4_layer.data});

    var udp_layer: UDPLayer = try packet.get_layer_of_type(UDPLayer) orelse {
        return;
    };

    const src_ip = ipv4_layer.get_src_ip();
    const dst_ip = ipv4_layer.get_dst_ip();

    print("Array: {any} U32: {any}\n", .{ src_ip, src_ip.to_u32() });

    udp_layer.calculate_checksum(src_ip.to_u32(), dst_ip.to_u32());

    print("UDP payload: {x}\n", .{udp_layer.get_payload()});

    print("{s}\n", .{udp_layer.to_string(std.heap.page_allocator)});

    //0xFA2D - expected UDP checksum

    //packet.print_layers();
}

pub fn main() !void {
    var backing_buffer: [2048]u8 = undefined;

    var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);
    const allocator = fba.allocator();

    const page_allocator = std.heap.page_allocator;

    _ = &page_allocator;

    var eth_data: [14]u8 = undefined;

    var ip_data: [20]u8 = undefined;

    var packet = try Packet.Packet.create(allocator, LinkLayerProtocols.ETHERNET);

    _ = try packet.add_layer(EthLayer, eth_data[0..]);

    var eth_layer: EthLayer = try packet.get_layer_of_type(EthLayer) orelse {
        return;
    };

    eth_layer.set_dst_mac(try MacAddress.init_from_string("38:06:e6:92:63:ac"));
    eth_layer.set_src_mac(try MacAddress.init_from_string("14:4f:8a:a4:15:7d"));
    try eth_layer.set_eth_type(EthType.IP);

    _ = try packet.add_layer(IPv4Layer, ip_data[0..]);

    var ipv4_layer: IPv4Layer = try packet.get_layer_of_type(IPv4Layer) orelse {
        return;
    };

    ipv4_layer.zero_hdr();

    ipv4_layer.set_src_ip(try IPv4Address.init_from_string("192.168.1.225"));
    ipv4_layer.set_dst_ip(try IPv4Address.init_from_string("192.168.1.254"));

    var udp_data: [8]u8 = undefined;

    _ = try packet.add_layer(UDPLayer, udp_data[0..]);

    var udp_layer: UDPLayer = try packet.get_layer_of_type(UDPLayer) orelse {
        return;
    };

    udp_layer.zero_hdr();

    udp_layer.set_dst_port(5005);
    udp_layer.set_src_port(1024);

    print("src ip: {x}\n", .{ipv4_layer.get_src_ip().array});

    ipv4_layer = try packet.get_layer_of_type(IPv4Layer) orelse {
        return;
    };

    print("ipv4 data len: {}\n", .{ipv4_layer.data.len});

    udp_layer.calculate_checksum(ipv4_layer.get_src_ip().to_u32(), ipv4_layer.get_dst_ip().to_u32());

    ipv4_layer.set_protocol(TransportProtocols.UDP);

    ipv4_layer.calculate_length();

    ipv4_layer.calculate_checksum();

    print("{s}\n", .{udp_layer.to_string(page_allocator)});

    print("{s}\n", .{ipv4_layer.to_string(page_allocator)});

    //    packet.print_layers_meta();

    print("packet data: {x}\n", .{packet.aligned_buffer});

    try send_packet(packet.aligned_buffer);

    fba.reset();
}

pub fn send_packet(buf: []u8) !void {
    var wifi_interface = try open_pcap() orelse {
        return error.FailedToOpen;
    };

    try wifi_interface.send(buf);

    print("No error during send.\n", .{});
}

pub fn open_pcap() !?*PcapWrapper.Interface {
    print("starting...\n", .{});

    const ip: []const u8 = "192.168.1.225";

    const allocator = std.heap.page_allocator;

    var interfaces = PcapWrapper.Interfaces.init() catch |err| {
        print("Failed to init interfaces: {s}.\n", .{@errorName(err)});
        return err;
    };

    const device_list = try interfaces.list_all(allocator);

    if (device_list.items.len > 0) {
        const main_iface = interfaces.find_by_ip(ip);
        if (main_iface) |iface| {
            try iface.open(allocator);

            if (iface.isOpened()) {
                return iface;
            } else {
                return null;
            }
        } else {
            return null;
        }
    } else {
        return null;
    }
}

pub fn test_ipv4(allocator: Allocator) !void {
    print("Testing IPv6.\n", .{});
    var packet = try Packet.Packet.create(allocator, LinkLayerProtocols.ETHERNET);
    defer packet.deinit();

    const pkt_data: []u8 = try allocator.alloc(u8, raw.len);
    defer allocator.free(pkt_data);

    std.mem.copyForwards(u8, pkt_data, raw[0..]);

    print("Original: ({}) {x}\n", .{ pkt_data.len, pkt_data });

    var wire_packet = WirePacket.init(0, 0, pkt_data, LinkLayerProtocols.ETHERNET);

    try packet.from_wire_packet(&wire_packet);

    packet.print_layers();
}

pub fn test_ipv6(allocator: Allocator) !void {
    print("Testing IPv6.\n", .{});
    var packet = try Packet.Packet.create(allocator, LinkLayerProtocols.ETHERNET);
    defer packet.deinit();

    const pkt_data: []u8 = try allocator.alloc(u8, ipv6_dns_request_raw.len);
    defer allocator.free(pkt_data);

    std.mem.copyForwards(u8, pkt_data, ipv6_dns_request_raw[0..ipv6_dns_request_raw.len]);

    print("align: {}\n", .{alignment_check(pkt_data[14..], IPv6.IPv6Header)});

    print("Original: ({}) {x}\n", .{ pkt_data.len, pkt_data });

    var wire_packet = WirePacket.init(0, 0, pkt_data, LinkLayerProtocols.ETHERNET);

    try packet.from_wire_packet(&wire_packet);

    var ipv6_layer: IPv6.IPv6Layer = try packet.get_layer_of_type(IPv6.IPv6Layer) orelse {
        print("could not get IPv6 layer.\n", .{});
        return;
    };

    _ = &ipv6_layer;

    //print("{s}\n", .{ipv6_layer.to_string(std.heap.page_allocator)});

    print("aligned_buffer: ({}) {x}\n\n", .{ packet.aligned_buffer.len, packet.aligned_buffer });

    //packet.print_layers();
}

pub fn test_arp(allocator: Allocator) !void {
    var packet = try Packet.Packet.create(allocator, LinkLayerProtocols.ETHERNET);
    defer packet.deinit();

    const pkt_data: []u8 = try allocator.alloc(u8, arp_request_raw.len);
    defer allocator.free(pkt_data);

    std.mem.copyForwards(u8, pkt_data, arp_request_raw[0..]);

    print("Original: ({}) {x}\n", .{ pkt_data.len, pkt_data });

    var wire_packet = WirePacket.init(0, 0, pkt_data, LinkLayerProtocols.ETHERNET);

    try packet.from_wire_packet(&wire_packet);

    packet.print_layers_meta();
}

pub fn test_icmp(allocator: Allocator) !void {
    var packet = try Packet.Packet.create(allocator, LinkLayerProtocols.ETHERNET);
    //    defer packet.deinit();

    const pkt_data: []u8 = try allocator.alloc(u8, icmp_request_raw.len);
    defer allocator.free(pkt_data);

    std.mem.copyForwards(u8, pkt_data, icmp_request_raw[0..]);

    print("Original: ({}) {x}\n", .{ pkt_data.len, pkt_data });

    var wire_packet = WirePacket.init(0, 0, pkt_data, LinkLayerProtocols.ETHERNET);

    try packet.from_wire_packet(&wire_packet);

    var icmp_layer = try packet.get_layer_of_type(ICMP.ICMPLayer) orelse {
        return;
    };

    print("{s}\n", .{try icmp_layer.to_string(std.heap.page_allocator)});
    //packet.print_layers();
}

pub fn test_tcp(allocator: Allocator) !void {
    var packet = try Packet.Packet.create(allocator, LinkLayerProtocols.ETHERNET);
    //    defer packet.deinit();

    const pkt_data: []u8 = try allocator.alloc(u8, tcp_syn_raw.len);
    defer allocator.free(pkt_data);

    std.mem.copyForwards(u8, pkt_data, tcp_syn_raw[0..]);

    print("Original: ({}) {x}\n", .{ pkt_data.len, pkt_data });

    var wire_packet = WirePacket.init(0, 0, pkt_data, LinkLayerProtocols.ETHERNET);

    try packet.from_wire_packet(&wire_packet);

    packet.print_layers_meta();
}

pub fn test_http(allocator: Allocator) !void {
    var packet = try Packet.Packet.create(allocator, LinkLayerProtocols.ETHERNET);
    defer packet.deinit();

    const pkt_data: []u8 = try allocator.alloc(u8, http_raw.len);
    //defer allocator.free(packet.aligned_buffer);

    std.mem.copyForwards(u8, pkt_data, http_raw[0..]);

    print("Original: ({}) {x}\n", .{ pkt_data.len, pkt_data });

    var wire_packet = WirePacket.init(0, 0, pkt_data, LinkLayerProtocols.ETHERNET);

    try packet.from_wire_packet(&wire_packet);

    var tcp_layer: TCP.TCPLayer = try packet.extract_layer(TCP.TCPLayer, allocator) orelse {
        return;
    };

    print("{s}\n", .{tcp_layer.to_string(std.heap.page_allocator)});

    packet.print_layers_meta();

    print("aligned buffer: {x} ({})\n", .{ packet.aligned_buffer[0..], packet.aligned_buffer[0..].len });
}

pub fn test_udp(allocator: Allocator) !void {
    var packet = try Packet.Packet.create(allocator, LinkLayerProtocols.ETHERNET);
    //    defer packet.deinit();

    const pkt_data: []u8 = try allocator.alloc(u8, udp_raw.len);
    defer allocator.free(pkt_data);

    std.mem.copyForwards(u8, pkt_data, udp_raw[0..]);

    print("Original: ({}) {x}\n", .{ pkt_data.len, pkt_data });

    var wire_packet = WirePacket.init(0, 0, pkt_data, LinkLayerProtocols.ETHERNET);

    try packet.from_wire_packet(&wire_packet);

    packet.print_layers();
}

const udp_raw = [47]u8{ 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x21, 0xb5, 0xba, 0x0, 0x0, 0x80, 0x11, 0xff, 0xe1, 0xc0, 0xa8, 0x1, 0xe1, 0xc0, 0xa8, 0x1, 0xfe, 0xe8, 0xd9, 0x13, 0x8d, 0x0, 0xd, 0x3a, 0x6b, 0x68, 0x65, 0x6c, 0x6c, 0x6f };

const http_raw = [148]u8{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x20, 0x35, 0x43, 0x5e, 0xdd, 0x17, 0x8, 0x0, 0x45, 0x0, 0x0, 0x86, 0x17, 0x3, 0x40, 0x0, 0x40, 0x6, 0x9e, 0x8f, 0xc0, 0xa8, 0x1, 0xae, 0xc0, 0xa8, 0x1, 0xe1, 0xdd, 0xd6, 0xf7, 0x7d, 0x4f, 0x90, 0xa1, 0x3b, 0x23, 0x25, 0x46, 0x9b, 0x50, 0x18, 0x7, 0x64, 0xc1, 0x1a, 0x0, 0x0, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0xd, 0xa, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x78, 0x6d, 0x6c, 0xd, 0xa, 0x41, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x55, 0x52, 0x4c, 0x3a, 0x20, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x31, 0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x31, 0x2e, 0x31, 0x37, 0x34, 0x3a, 0x35, 0x36, 0x37, 0x38, 0x39, 0x2f, 0x61, 0x70, 0x70, 0x73, 0x2f, 0xd, 0xa, 0xd, 0xa };

const tcp_syn_raw = [66]u8{ 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x34, 0x25, 0x20, 0x40, 0x0, 0x80, 0x6, 0x50, 0x74, 0xc0, 0xa8, 0x1, 0xe1, 0xc0, 0xa8, 0x1, 0xfe, 0xa7, 0xe, 0x15, 0xb3, 0xdb, 0xb7, 0xfb, 0x41, 0x0, 0x0, 0x0, 0x0, 0x80, 0x2, 0xff, 0xff, 0x56, 0x25, 0x0, 0x0, 0x2, 0x4, 0x5, 0xb4, 0x1, 0x3, 0x3, 0x8, 0x1, 0x1, 0x4, 0x2 };

const icmp_request_raw = [74]u8{ 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x3c, 0x71, 0xdc, 0x0, 0x0, 0x80, 0x1, 0xf5, 0xef, 0xc0, 0xa8, 0x1, 0xe1, 0x8e, 0xfa, 0x81, 0x71, 0x8, 0x0, 0x4d, 0x5a, 0x0, 0x1, 0x0, 0x1, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69 };

const ipv6_dns_request_raw = [89]u8{ 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x86, 0xdd, 0x60, 0x8, 0x5a, 0x43, 0x0, 0x23, 0x11, 0x40, 0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa6, 0x61, 0x8f, 0x26, 0x87, 0xeb, 0xbe, 0x60, 0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3a, 0x6, 0xe6, 0xff, 0xfe, 0x92, 0x63, 0xac, 0xdb, 0xe4, 0x0, 0x35, 0x0, 0x23, 0x26, 0x20, 0x4f, 0xa0, 0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4, 0x77, 0x70, 0x61, 0x64, 0x4, 0x68, 0x6f, 0x6d, 0x65, 0x0, 0x0, 0x1, 0x0, 0x1 };

const arp_request_raw = [60]u8{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x8, 0x6, 0x0, 0x1, 0x8, 0x0, 0x6, 0x4, 0x0, 0x1, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0xc0, 0xa8, 0x1, 0xfe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc0, 0xa8, 0x1, 0xe1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

const raw_udp: [42]u8 = .{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x8, 0x0, 0x45, 0x0, 0x0, 0x49, 0x5d, 0xf7, 0x40, 0x0, 0x40, 0x11, 0x57, 0x7d, 0xc0, 0xa8, 0x1, 0xfe, 0xc0, 0xa8, 0x1, 0xe1, 0x0, 0x35, 0xfd, 0xdf, 0x0, 0x35, 0x9d, 0xff };

const raw: [87]u8 = .{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x8, 0x0, 0x45, 0x0, 0x0, 0x49, 0x5d, 0xf7, 0x40, 0x0, 0x40, 0x11, 0x57, 0x7d, 0xc0, 0xa8, 0x1, 0xfe, 0xc0, 0xa8, 0x1, 0xe1, 0x0, 0x35, 0xfd, 0xdf, 0x0, 0x35, 0x9d, 0xff, 0x3a, 0xd0, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x7, 0x7a, 0x69, 0x67, 0x6c, 0x61, 0x6e, 0x67, 0x3, 0x6f, 0x72, 0x67, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1, 0x2c, 0x0, 0x4, 0x41, 0x6d, 0x69, 0xb2 };
