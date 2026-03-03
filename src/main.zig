const std = @import("std");
const print = std.debug.print;
const PacketStructs = @import("PacketStructs.zig");
const PcapWrapper = @import("PcapWrapper.zig");
const ProtocolType = @import("ProtocolEnums.zig").ProtocolType;
const Packet = PacketStructs.Packet;
const EthLayer = PacketStructs.EthLayer;
const DNS = @import("DNS");
const UDP = @import("UDP");

pub fn packet_callback(raw_packet: *PacketStructs.RawPacket, allocator: *std.mem.Allocator) void {
    defer raw_packet.deinit(allocator);

    var packet = PacketStructs.Packet.init(raw_packet);

    packet.parse_layers(allocator) catch |err| {
        print("Error parsing layers {s}\n", .{@errorName(err)});
    };

    const udp_layer = packet.get_layer(ProtocolType.UDP);

    if (udp_layer) |udp| {
        const src_port = UDP.getSrcPort(udp.raw) catch |err| {
            print("Error getting src port: {s}\n", .{@errorName(err)});
            return;
        };
        const dst_port = UDP.getDstPort(udp.raw) catch |err| {
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
                    DNS.parseHeader(layer.raw) catch |err| {
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
