const std = @import("std");
const print = std.debug.print;
const PacketStructs = @import("PacketStructs.zig");
const PcapWrapper = @import("PcapWrapper.zig");
const ProtocolType = @import("ProtocolEnums.zig").ProtocolType;
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

pub fn getUDPSrcPort(packet: []const u8) !u16 {
    if (packet.len < 8) {
        return error.InvalidPacket;
    }

    const src_port = std.mem.readInt(u16, packet[0..2], .big);

    return src_port;
}

pub fn getUDPDstPort(packet: []const u8) !u16 {
    if (packet.len < 8) {
        return error.InvalidPacket;
    }

    const dst_port = std.mem.readInt(u16, packet[2..4], .big);

    return dst_port;
}

pub fn getDnsFlags(flags: u16) PacketStructs.DNSFlags {
    const dns_flags: PacketStructs.DNSFlags = .{
        .QR = (flags >> 15) & 0x1,
        .OPCODE = (flags >> 11) & 0xF,
        .AA = (flags >> 10) & 0x1,
        .TC = (flags >> 9) & 0x1,
        .RD = (flags >> 8) & 0x1,
        .RA = (flags >> 7) & 0x1,
        .Z = (flags >> 4) & 0x7, // reserved
        .RCODE = flags & 0xF,
    };

    return dns_flags;
}

pub fn parseDnsHeader(payload: []const u8) !void {
    if (payload.len < 12) {
        return error.InvalidPacket;
    }

    // DNS fields are big-endian (network byte order)
    const transaction_id = std.mem.readInt(u16, payload[0..2], .big);
    const flags = getDnsFlags(std.mem.readInt(u16, payload[2..4], .big));
    const qdcount = std.mem.readInt(u16, payload[4..6], .big);
    const ancount = std.mem.readInt(u16, payload[6..8], .big);
    const nscount = std.mem.readInt(u16, payload[8..10], .big);
    const arcount = std.mem.readInt(u16, payload[10..12], .big);

    std.debug.print("DNS Header:\n", .{});
    std.debug.print("Transaction ID: {d}\n", .{transaction_id});
    //std.debug.print("Flags: {x}\n", .{flags});
    std.debug.print("QR Type: {s}\n", .{if (flags.QR == 0) "query" else "response"});
    std.debug.print("Questions: {d}, Answers: {d}, Authority: {d}, Additional: {d}\n", .{ qdcount, ancount, nscount, arcount });
}

pub fn parseEthHeader(payload: []const u8) !void {
    if (payload.len < 12) {
        return error.InvalidLength;
    }

    const dst = payload[0..6];
    const src = payload[6..12];

    std.debug.print("Dst: ", .{});
    var i: usize = 0;
    for (dst) |b| {
        if (i != 0) std.debug.print(":", .{});
        std.debug.print("{x}", .{b});
        i += 1;
    }

    i = 0;
    std.debug.print(" Src: ", .{});
    for (src) |b| {
        if (i != 0) std.debug.print(":", .{});
        std.debug.print("{x}", .{b});
        i += 1;
    }
    std.debug.print("\n", .{});
}

pub fn packet_callback(raw_packet: *PacketStructs.RawPacket, allocator: *std.mem.Allocator) void {
    defer raw_packet.deinit(allocator);

    var packet = PacketStructs.Packet.init(raw_packet);

    packet.parse_layers(allocator) catch |err| {
        print("Error parsing layers {s}\n", .{@errorName(err)});
    };
    //
    //    const eth_layer = packet.get_layer(ProtocolType.Ethernet);
    //
    //    if (eth_layer) |eth| {
    //        parseEthHeader(eth.raw) catch |err| {
    //            print("Error printing Eth layer: {s}\n", .{@errorName(err)});
    //        };
    //    }
    //
    //    const ip_layer = packet.get_layer(ProtocolType.IPv4);
    //
    //    if (ip_layer) |ip| {
    //        parseIPv4Header(ip.raw) catch |err| {
    //            print("Error printing IP layer: {s}\n", .{@errorName(err)});
    //            return;
    //        };
    //    }

    const udp_layer = packet.get_layer(ProtocolType.UDP);

    if (udp_layer) |udp| {
        //        parseUDPHeader(udp.raw) catch |err| {
        //            print("Error printing UDP layer: {s}\n", .{@errorName(err)});
        //            return;
        //        };

        const src_port = getUDPSrcPort(udp.raw) catch |err| {
            print("Error getting src port: {s}\n", .{@errorName(err)});
            return;
        };
        const dst_port = getUDPDstPort(udp.raw) catch |err| {
            print("Error getting dst port: {s}\n", .{@errorName(err)});
            return;
        };

        if (src_port == 53 or dst_port == 53) {
            print("got dns packet.\n", .{});
            const generic_payload = packet.get_layer(ProtocolType.GenericPayload);

            if (generic_payload) |generic_layer| {
                const transformed_layer = packet.transform_layer(generic_layer, PacketStructs.DNSHeader) catch |err| {
                    print("Error transforming layer: {s}\n", .{@errorName(err)});
                    return;
                };

                if (transformed_layer) |layer| {
                    print("{any}\n", .{layer.len});
                    parseDnsHeader(layer.raw) catch |err| {
                        print("Error parsing DNS header: {s}\n", .{@errorName(err)});
                        return;
                    };
                } else {
                    print("transform_layer returned null.\n", .{});
                }
            } else {
                print("Packet has no generic layer to transform.\n", .{});
                return;
            }
        }
    }
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
