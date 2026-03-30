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

pub fn alignment_check(buffer: []u8, protocol_hdr: anytype) usize {
    const alignment = @alignOf(protocol_hdr);
    const addr = @intFromPtr(buffer.ptr);

    return addr % alignment;
}

pub fn test_ipv4_ext(allocator: Allocator) !void {
    print("Testing IPv6.\n", .{});
    var packet = try Packet.Packet.create(allocator, LinkLayerProtocols.ETHERNET);
    defer packet.deinit();

    const pkt_data: []u8 = try allocator.alloc(u8, ipv4_ext_raw.len);
    defer allocator.free(pkt_data);

    std.mem.copyForwards(u8, pkt_data, ipv4_ext_raw[0..]);

    print("Original: ({}) {x}\n", .{ pkt_data.len, pkt_data });

    var wire_packet = WirePacket.init(0, 0, pkt_data, LinkLayerProtocols.ETHERNET);

    try packet.from_wire_packet(&wire_packet);

    //packet.print_layers();
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

    packet.print_layers();
}

pub fn test_udp(allocator: Allocator) !void {
    var packet = try Packet.Packet.create(allocator, LinkLayerProtocols.ETHERNET);
    //    defer packet.deinit();

    const pkt_data: []u8 = try allocator.alloc(u8, raw_udp.len);
    defer allocator.free(pkt_data);

    std.mem.copyForwards(u8, pkt_data, raw_udp[0..]);

    print("Original: ({}) {x}\n", .{ pkt_data.len, pkt_data });

    var wire_packet = WirePacket.init(0, 0, pkt_data, LinkLayerProtocols.ETHERNET);

    try packet.from_wire_packet(&wire_packet);

    packet.print_layers_meta();
}

pub fn test_arp(allocator: Allocator) !void {
    var packet = try Packet.Packet.create(allocator, LinkLayerProtocols.ETHERNET);
    //    defer packet.deinit();

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

pub fn main() !void {
    var pkt_data_backing_buffer: [2048]u8 = undefined;

    var pkt_data_fba = std.heap.FixedBufferAllocator.init(&pkt_data_backing_buffer);
    const pkt_data_allocator = pkt_data_fba.allocator();

    const page_allocator = std.heap.page_allocator;

    _ = &page_allocator;

    //try test_udp(pkt_data_allocator);

    //try test_ipv4(pkt_data_allocator);
    //try test_ipv6(pkt_data_allocator);
    //try test_arp(pkt_data_allocator);
    try test_icmp(pkt_data_allocator);
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

const icmp_request_raw = [74]u8{ 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x3c, 0x71, 0xdc, 0x0, 0x0, 0x80, 0x1, 0xf5, 0xef, 0xc0, 0xa8, 0x1, 0xe1, 0x8e, 0xfa, 0x81, 0x71, 0x8, 0x0, 0x4d, 0x5a, 0x0, 0x1, 0x0, 0x1, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69 };

const ipv6_dns_request_raw = [89]u8{ 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x86, 0xdd, 0x60, 0x8, 0x5a, 0x43, 0x0, 0x23, 0x11, 0x40, 0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa6, 0x61, 0x8f, 0x26, 0x87, 0xeb, 0xbe, 0x60, 0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3a, 0x6, 0xe6, 0xff, 0xfe, 0x92, 0x63, 0xac, 0xdb, 0xe4, 0x0, 0x35, 0x0, 0x23, 0x26, 0x20, 0x4f, 0xa0, 0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4, 0x77, 0x70, 0x61, 0x64, 0x4, 0x68, 0x6f, 0x6d, 0x65, 0x0, 0x0, 0x1, 0x0, 0x1 };

const arp_request_raw = [60]u8{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x8, 0x6, 0x0, 0x1, 0x8, 0x0, 0x6, 0x4, 0x0, 0x1, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0xc0, 0xa8, 0x1, 0xfe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc0, 0xa8, 0x1, 0xe1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

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

const raw_udp: [42]u8 = .{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x8, 0x0, 0x45, 0x0, 0x0, 0x49, 0x5d, 0xf7, 0x40, 0x0, 0x40, 0x11, 0x57, 0x7d, 0xc0, 0xa8, 0x1, 0xfe, 0xc0, 0xa8, 0x1, 0xe1, 0x0, 0x35, 0xfd, 0xdf, 0x0, 0x35, 0x9d, 0xff };

const raw: [87]u8 = .{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x8, 0x0, 0x45, 0x0, 0x0, 0x49, 0x5d, 0xf7, 0x40, 0x0, 0x40, 0x11, 0x57, 0x7d, 0xc0, 0xa8, 0x1, 0xfe, 0xc0, 0xa8, 0x1, 0xe1, 0x0, 0x35, 0xfd, 0xdf, 0x0, 0x35, 0x9d, 0xff, 0x3a, 0xd0, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x7, 0x7a, 0x69, 0x67, 0x6c, 0x61, 0x6e, 0x67, 0x3, 0x6f, 0x72, 0x67, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1, 0x2c, 0x0, 0x4, 0x41, 0x6d, 0x69, 0xb2 };
