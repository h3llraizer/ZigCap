const std = @import("std");
const print = std.debug.print;
const PacketStructs = @import("PacketStructs.zig");
const PcapWrapper = @import("PcapWrapper.zig");
const Packet = PacketStructs.Packet;
const EthLayer = PacketStructs.EthLayer;

pub fn parseIPv4Header(packet: []const u8) !void {
    if (packet.len < 20) {
        return error.InvalidPacket;
    }

    const version_ihl = packet[0];
    const version = version_ihl >> 4;
    const ihl = version_ihl & 0x0F; // header length in 32-bit words
    const header_length = ihl * 4;

    if (packet.len < header_length) {
        return error.InvalidPacket;
    }

    const total_length = std.mem.readInt(u16, packet[2..4], .big);
    const protocol = packet[9]; // 1 = ICMP, 6 = TCP, 17 = UDP
    const src_ip = packet[12..16];
    const dst_ip = packet[16..20];

    std.debug.print("IPv4 Header:\n", .{});
    std.debug.print("Version: {d}, Header Length: {d} bytes\n", .{ version, header_length });
    std.debug.print("Total Length: {d}\n", .{total_length});
    std.debug.print("Protocol: {d}\n", .{protocol});
    std.debug.print("Source IP: {d}.{d}.{d}.{d}\n", .{ src_ip[0], src_ip[1], src_ip[2], src_ip[3] });
    std.debug.print("Destination IP: {d}.{d}.{d}.{d}\n", .{ dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3] });
}

pub fn parseUDPHeader(packet: []const u8) !void {
    if (packet.len < 8) {
        return error.InvalidPacket;
    }

    const src_port = std.mem.readInt(u16, packet[0..2], .big);
    const dst_port = std.mem.readInt(u16, packet[2..4], .big);
    const length = std.mem.readInt(u16, packet[4..6], .big);
    const checksum = std.mem.readInt(u16, packet[6..8], .big);

    std.debug.print("UDP Header:\n", .{});
    std.debug.print("Source Port: {d}, Destination Port: {d}\n", .{ src_port, dst_port });
    std.debug.print("Length: {d}, Checksum: {x}\n", .{ length, checksum });
}

pub fn parseDnsHeader(payload: []const u8) !void {
    if (payload.len < 12) {
        return error.InvalidPacket;
    }

    // DNS fields are big-endian (network byte order)
    const transaction_id = std.mem.readInt(u16, payload[0..2], .big);
    const flags = std.mem.readInt(u16, payload[2..4], .big);
    const qdcount = std.mem.readInt(u16, payload[4..6], .big);
    const ancount = std.mem.readInt(u16, payload[6..8], .big);
    const nscount = std.mem.readInt(u16, payload[8..10], .big);
    const arcount = std.mem.readInt(u16, payload[10..12], .big);

    std.debug.print("DNS Header:\n", .{});
    std.debug.print("Transaction ID: {d}\n", .{transaction_id});
    std.debug.print("Flags: {x}\n", .{flags});
    std.debug.print("Questions: {d}, Answers: {d}, Authority: {d}, Additional: {d}\n", .{ qdcount, ancount, nscount, arcount });
}

const PacketType = enum {
    Eth,
    IPv4,
    UDP,
    DNS,

    /// Returns true if this raw packet contains a UDP layer (IPv4 + Protocol 17)
    pub fn isUDP(raw_packet: *PacketStructs.RawPacket) bool {
        const ETH_HEADER_LEN = 14;

        // Check packet is long enough for Ethernet + IPv4 minimum header
        if (raw_packet.raw_len < ETH_HEADER_LEN + 20) return false;

        // Check Ethernet type = IPv4
        const eth_type = std.mem.readInt(u16, raw_packet.raw_data[12..14], .big);
        if (eth_type != 0x0800) return false;

        // IPv4 protocol field (byte 9 in IPv4 header)
        const protocol = raw_packet.raw_data[ETH_HEADER_LEN + 9];
        return protocol == 17;
    }

    /// Returns true if this packet is DNS (UDP port 53)
    pub fn isDNS(raw_packet: *PacketStructs.RawPacket) bool {
        if (!PacketType.isUDP(raw_packet)) return false;

        const ip_start = 14;
        const version_ihl = raw_packet.raw_data[ip_start];
        const ihl = version_ihl & 0x0F;
        const ip_header_len = ihl * 4;

        const udp_start = ip_start + ip_header_len;
        if (raw_packet.raw_len < udp_start + 8) return false;

        const src_port = std.mem.readInt(u16, raw_packet.raw_data[udp_start .. udp_start + 2], .Big);
        const dst_port = std.mem.readInt(u16, raw_packet.raw_data[udp_start + 2 .. udp_start + 4], .Big);

        return src_port == 53 or dst_port == 53;
    }
};

pub fn packet_callback(raw_packet: *PacketStructs.RawPacket, allocator: *std.mem.Allocator) void {
    defer raw_packet.deinit(allocator);

    var packet = PacketStructs.Packet.init(raw_packet);

    packet.parse_layers(allocator) catch |err| {
        print("Error parsing layers {s}\n", .{@errorName(err)});
    };

    packet.print_layers();
}

pub fn main() !void {
    print("starting...\n", .{});

    const ip: []const u8 = "192.168.1.225";

    var allocator = std.heap.page_allocator;

    var interfaces = PcapWrapper.Interfaces.init() catch |err| {
        print("Failed to init interfaces: {s}.\n", .{@errorName(err)});
        return err;
    };

    const device_list = try interfaces.list_all(&allocator);

    if (device_list.items.len > 0) {
        const main_iface = interfaces.find_by_ip(ip);
        if (main_iface) |iface| {
            print("Found:\n{s}\n", .{iface.toString(&allocator)});

            try iface.*.open(&allocator);

            if (iface.*.isOpened()) {
                print("Device is open.\n", .{});
            } else {
                print("Device not open.\n", .{});
            }

            var buffer: [131072]u8 = undefined;
            var fba: std.heap.FixedBufferAllocator = .init(&buffer);
            var alloc = fba.allocator();
            try iface.*.capture(packet_callback, &alloc);
        }
    }
}
