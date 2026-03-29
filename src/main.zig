const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;
const activeTag = std.meta.activeTag;

const PcapWrapper = @import("PcapWrapper.zig");

const Packet = @import("Packet.zig");

const LayerProtocols = @import("ProtocolHelpers.zig").LayerProtocols;

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

pub fn alignment_check(buffer: []u8, protocol_hdr: anytype) usize {
    const alignment = @alignOf(protocol_hdr);
    const addr = @intFromPtr(buffer.ptr);

    return addr % alignment;
}

pub fn main() !void {
    var pkt_data_backing_buffer: [2048]u8 = undefined;

    var pkt_data_fba = std.heap.FixedBufferAllocator.init(&pkt_data_backing_buffer);
    const pkt_data_allocator = pkt_data_fba.allocator();

    const page_allocator = std.heap.page_allocator;

    _ = &page_allocator;

    var packet = try Packet.Packet.create(pkt_data_allocator, LinkLayerProtocols.ETHERNET);
    defer packet.deinit();

    const pkt_data: []u8 = try pkt_data_allocator.alloc(u8, arp_request_raw.len);

    std.mem.copyForwards(u8, pkt_data, arp_request_raw[0..arp_request_raw.len]);

    print("Original: ({}) {x}\n", .{ pkt_data.len, pkt_data });

    var wire_packet = WirePacket.init(0, 0, pkt_data, LinkLayerProtocols.ETHERNET);

    try packet.from_wire_packet(&wire_packet);

    var arp_layer: ARP.ArpLayer = try packet.get_layer_of_type(ARP.ArpLayer) orelse {
        print("failed to get arp layer.\n", .{});
        return;
    };

    print("{s}\n", .{arp_layer.to_string(page_allocator)});

    print("Arp data: {x} ({})\n", .{ arp_layer.data, arp_layer.data.len });

    print("aligned_buffer: ({}) {x}\n\n", .{ packet.aligned_buffer.len, packet.aligned_buffer });

    //packet.print_layers();
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

const raw: [87]u8 = .{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x8, 0x0, 0x45, 0x0, 0x0, 0x49, 0x5d, 0xf7, 0x40, 0x0, 0x40, 0x11, 0x57, 0x7d, 0xc0, 0xa8, 0x1, 0xfe, 0xc0, 0xa8, 0x1, 0xe1, 0x0, 0x35, 0xfd, 0xdf, 0x0, 0x35, 0x9d, 0xff, 0x3a, 0xd0, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x7, 0x7a, 0x69, 0x67, 0x6c, 0x61, 0x6e, 0x67, 0x3, 0x6f, 0x72, 0x67, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1, 0x2c, 0x0, 0x4, 0x41, 0x6d, 0x69, 0xb2 };
