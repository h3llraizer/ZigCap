const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const PcapWrapper = @import("PcapWrapper.zig");

const Packet = @import("Packet.zig").Packet;
const LayerProtocols = @import("Layer.zig").LayerProtocols;
const Layer = @import("Layer.zig").Layer;
const TPtr = @import("Layer.zig").TPtr;
const LinkLayerProtocols = @import("Layer.zig").LinkLayerProtocols;
const IPv4Proto = @import("ProtocolEnums.zig").IPv4Proto;
const RawPacket = @import("RawPacket.zig").RawPacket;

const EthLayer = @import("Eth.zig").EthLayer;
const EthType = @import("Eth.zig").EthType;
const EthHeader = @import("Eth.zig").EthHeader;
const MacAddress = @import("Eth.zig").MacAddress;

const IPv4Layer = @import("IPv4.zig").IPv4Layer;
const IPv4Address = @import("IPv4.zig").IPv4Address;
const IPv4Header = @import("IPv4.zig").IPv4Header;

const UDPLayer = @import("UDP.zig").UDPLayer;
const DNSLayer = @import("DNS.zig").DNSLayer;
const UDP = @import("UDPLayer.zig");
const DNS = @import("DNS.zig");

const from_protocol_layer = @import("Layer.zig").from_protocol_layer;

pub fn calculate_next_offset(current_offset: usize, comptime HdrType: type) usize {
    const alignment = @alignOf(HdrType);
    const next_offset = (current_offset + alignment - 1) / alignment * alignment;
    print("Current offset: {}, alignment: {}, next offset: {}\n", .{ current_offset, alignment, next_offset });
    return next_offset;
}

pub fn calculate_padding(current_offset: usize, comptime HdrType: type) usize {
    const padding = (@alignOf(HdrType) - (current_offset % @alignOf(HdrType))) % @alignOf(HdrType);
    return padding;
}

fn removeRangeInPlace(buf: []u8, offset: usize, len: usize) []const u8 {
    std.debug.assert(offset + len <= buf.len);

    const tail_start = offset + len;
    const tail_len = buf.len - tail_start;

    // Shift tail left
    @memmove(
        buf[offset .. offset + tail_len],
        buf[tail_start .. tail_start + tail_len],
    );

    // Return shortened slice
    return buf[0 .. buf.len - len];
}

fn create_packet(allocator: Allocator) ![]const u8 {
    const eth_size: usize = @sizeOf(EthHeader);
    const ipv4_size: usize = @sizeOf(IPv4Header);
    const udp_size: usize = @sizeOf(UDP.UDPHeader);
    const payload_data = "Hello, UDP!";
    const udp_total_len = udp_size + payload_data.len;

    var packet_buffer = try allocator.alloc(u8, eth_size);
    @memset(packet_buffer, 0);

    var eth_layer = try EthLayer.preallocated_buffer(packet_buffer[0..eth_size]);
    eth_layer.set_src_mac(try MacAddress.init_from_string("14:4f:8a:a4:15:7d"));
    eth_layer.set_dst_mac(try MacAddress.init_from_string("38:06:e6:92:63:ac"));
    try eth_layer.set_eth_type(EthType.IP);

    // IPv4 layer
    const old_size = packet_buffer.len;
    var current_offset: usize = eth_size;
    const next_offset = calculate_next_offset(current_offset, IPv4Header);
    const new_size = next_offset + ipv4_size;

    packet_buffer = try allocator.realloc(packet_buffer, new_size);
    @memset(packet_buffer[old_size..], 0);

    var ipv4_layer = try IPv4Layer.preallocated_buffer(packet_buffer[next_offset..][0..ipv4_size]);
    var ip_hdr = ipv4_layer.get_header();

    ip_hdr.version_ihl = 0x45;
    ip_hdr.ttl = 64;
    ip_hdr.protocol = @intFromEnum(IPv4Proto.UDP);
    ip_hdr.checksum = 0;

    ipv4_layer.set_src_ip(try IPv4Address.init_from_string("192.168.1.225"));
    ipv4_layer.set_dst_ip(try IPv4Address.init_from_string("192.168.1.254"));

    // UDP layer
    const old_size2 = packet_buffer.len;
    current_offset = next_offset + ipv4_size;
    const udp_next_offset = calculate_next_offset(current_offset, UDP.UDPHeader);
    const udp_start = udp_next_offset; // Where UDP header starts in padded buffer
    const new_size2 = udp_start + udp_total_len;

    packet_buffer = try allocator.realloc(packet_buffer, new_size2);
    @memset(packet_buffer[old_size2..], 0);

    var udp_layer = try UDP.UDPLayer.preallocated_buffer(packet_buffer[udp_start..][0..udp_total_len]);

    udp_layer.set_src_port(1234);
    udp_layer.set_dst_port(30045);
    try udp_layer.set_payload(payload_data, allocator);

    // Update IPv4 total length
    ip_hdr.total_length = @byteSwap(@as(u16, @intCast(ipv4_size + udp_total_len)));

    // Calculate checksums
    ip_hdr.calculate_checksum();
    udp_layer.calculate_checksum(ip_hdr.src_ip, ip_hdr.dst_ip);

    print("Built packet with padding: {} bytes\n", .{packet_buffer.len});
    print("Packet bytes (with padding): ", .{});
    for (packet_buffer) |byte| {
        print("{x:0>2}", .{byte});
    }
    print("\n", .{});

    print("packet buf len: {}\n", .{packet_buffer.len});

    //    const padding = (alignment - (offset % alignment)) % alignment;

    const padding = calculate_padding(@sizeOf(EthHeader), IPv4Header);

    print("padding: {}\n", .{padding});

    // Move the tail down over the removed section
    const trimmed = removeRangeInPlace(packet_buffer, 14, padding);

    print("trimmed len: {}\n", .{trimmed.len});

    return trimmed;
}

pub fn main() !void {
    var backing_buffer: [55]u8 = undefined;

    var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);
    const allocator = fba.allocator();
    const packet_to_send = try create_packet(allocator);
    defer allocator.free(packet_to_send);

    print("{x}\n", .{fba.buffer});

    print("end index: {}\n", .{fba.end_index});

    print("{x}\n", .{packet_to_send});

    var wifi_interface = try pcap_test() orelse {
        return error.FailedToOpen;
    };

    try wifi_interface.send(packet_to_send);

    print("No error during send.\n", .{});
}

pub fn pcap_test() !?*PcapWrapper.Interface {
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
            print("Found:\n{s}\n", .{iface.toString(allocator)});

            try iface.open(allocator);

            if (iface.isOpened()) {
                print("Device is open.\n", .{});
                return iface;
            } else {
                print("Device not open.\n", .{});
                return null;
            }
        } else {
            return null;
        }
    } else {
        return null;
    }
}

const raw: [87]u8 = .{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x8, 0x0, 0x45, 0x0, 0x0, 0x49, 0x5d, 0xf7, 0x40, 0x0, 0x40, 0x11, 0x57, 0x7d, 0xc0, 0xa8, 0x1, 0xfe, 0xc0, 0xa8, 0x1, 0xe1, 0x0, 0x35, 0xfd, 0xdf, 0x0, 0x35, 0x9d, 0xff, 0x3a, 0xd0, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x7, 0x7a, 0x69, 0x67, 0x6c, 0x61, 0x6e, 0x67, 0x3, 0x6f, 0x72, 0x67, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1, 0x2c, 0x0, 0x4, 0x41, 0x6d, 0x69, 0xb2 };
