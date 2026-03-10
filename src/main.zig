const std = @import("std");
const print = std.debug.print;

const Packet = @import("Packet.zig").Packet;
const LayerProtocols = @import("Layer.zig").LayerProtocols;
const LinkLayerProtocols = @import("Layer.zig").LinkLayerProtocols;
const RawPacket = @import("RawPacket.zig").RawPacket;

const EthLayer = @import("Eth.zig").EthLayer;
const EthType = @import("Eth.zig").EthType;
const MacAddress = @import("Eth.zig").MacAddress;

const IPv4Layer = @import("IPv4.zig").IPv4Layer;
const IPv4Address = @import("IPv4.zig").IPv4Address;

const UDPLayer = @import("UDP.zig").UDPLayer;
const DNSLayer = @import("DNS.zig").DNSLayer;
const DNS = @import("DNS.zig");

const raw: [87]u8 = .{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x8, 0x0, 0x45, 0x0, 0x0, 0x49, 0x5d, 0xf7, 0x40, 0x0, 0x40, 0x11, 0x57, 0x7d, 0xc0, 0xa8, 0x1, 0xfe, 0xc0, 0xa8, 0x1, 0xe1, 0x0, 0x35, 0xfd, 0xdf, 0x0, 0x35, 0x9d, 0xff, 0x3a, 0xd0, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x7, 0x7a, 0x69, 0x67, 0x6c, 0x61, 0x6e, 0x67, 0x3, 0x6f, 0x72, 0x67, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1, 0x2c, 0x0, 0x4, 0x41, 0x6d, 0x69, 0xb2 };

pub fn main() !void {
    var raw_pkt_buf: [1024]u8 = undefined;

    var fba = std.heap.FixedBufferAllocator.init(&raw_pkt_buf);
    const allocator = fba.allocator();

    const packet = try Packet.init(allocator);
    defer packet.deinit(allocator);

    const eth_layer = try EthLayer.create(allocator);

    eth_layer.set_src_mac(try MacAddress.init_from_string("14:4f:8a:a4:15:7d"));
    eth_layer.set_dst_mac(try MacAddress.init_from_string("38:06:e6:92:63:ac"));
    try eth_layer.set_eth_type(EthType.IP);

    try packet.add_layer(eth_layer, allocator);

    //    eth_layer.to_string();

    const ipv4_layer = try IPv4Layer.create(allocator);

    ipv4_layer.set_src_ip(try IPv4Address.init_from_string("192.168.1.225"));
    ipv4_layer.set_dst_ip(try IPv4Address.init_from_string("192.168.1.254"));

    try packet.add_layer(ipv4_layer, allocator);

    const udp_layer = try UDPLayer.create(allocator);

    udp_layer.set_src_port(1234);
    udp_layer.set_dst_port(53);

    try packet.add_layer(udp_layer, allocator);

    const dns_layer = try DNSLayer.create(allocator, 40);

    try dns_layer.add_query("ziglang.org", DNS.QueryType.A, DNS.DnsClass.IN, allocator);

    if (dns_layer.get_first_query()) |query| {
        print("Query Added: {s}\n", .{try DNS.decodeQname(allocator, query.qname)});
    }

    try packet.add_layer(dns_layer, allocator);

    ipv4_layer.calculate_checksum();

    print("ipv4 checksum: {x}\n", .{ipv4_layer.get_checksum()});

    udp_layer.calculate_checksum();
}

// TODO: to finalise a packet before sending - start from last layer and take its hdr+payload then cast it back to u8 for the prev layers payload until first layer reached

//pub fn pcap_test() !void {
//    print("starting...\n", .{});
//
//    const ip: []const u8 = "192.168.1.225";
//
//    var allocator = std.heap.page_allocator;
//
//    var interfaces = PcapWrapper.Interfaces.init() catch |err| {
//        print("Failed to init interfaces: {s}.\n", .{@errorName(err)});
//        return err;
//    };
//
//    const device_list = try interfaces.list_all(&allocator);
//
//    if (device_list.items.len > 0) {
//        const main_iface = interfaces.find_by_ip(ip);
//        if (main_iface) |iface| {
//            print("Found:\n{s}\n", .{iface.toString(&allocator)});
//
//            try iface.*.open(&allocator);
//
//            if (iface.*.isOpened()) {
//                print("Device is open.\n", .{});
//            } else {
//                print("Device not open.\n", .{});
//            }
//
//            var buffer: [131072]u8 = undefined;
//            var fba: std.heap.FixedBufferAllocator = .init(&buffer);
//            var alloc = fba.allocator();
//            try iface.*.capture(pcap_packet_callback, &alloc);
//        }
//    }
//}
//
//pub fn pcap_packet_callback(raw_packet: *PacketStructs.RawPacket, allocator: *std.mem.Allocator) void {
//    defer raw_packet.deinit(allocator);
//
//    var packet = PacketStructs.Packet.init(raw_packet);
//
//    packet.parse_layers(allocator) catch |err| {
//        print("Error parsing layers {s}\n", .{@errorName(err)});
//    };
//
//    const udp_layer = packet.get_layer(ProtocolType.UDP);
//
//    if (udp_layer) |udp| {
//        const src_port = UDP.getSrcPort(udp.raw) catch |err| {
//            print("Error getting src port: {s}\n", .{@errorName(err)});
//            return;
//        };
//        const dst_port = UDP.getDstPort(udp.raw) catch |err| {
//            print("Error getting dst port: {s}\n", .{@errorName(err)});
//            return;
//        };
//
//        if (src_port == 53 or dst_port == 53) {
//            print("got dns packet.\n", .{});
//            const generic_payload = packet.get_layer(ProtocolType.GenericPayload);
//
//            if (generic_payload) |generic_layer| {
//                const transformed_layer = packet.transform_layer(generic_layer, PacketStructs.DNSHeader) catch |err| {
//                    print("Error transforming layer: {s}\n", .{@errorName(err)});
//                    return;
//                };
//
//                if (transformed_layer) |layer| {
//                    print("{any}\n", .{layer.len});
//                    DNS.parseHeader(layer.raw) catch |err| {
//                        print("Error parsing DNS header: {s}\n", .{@errorName(err)});
//                        return;
//                    };
//                } else {
//                    print("transform_layer returned null.\n", .{});
//                }
//            } else {
//                print("Packet has no generic layer to transform.\n", .{});
//                return;
//            }
//        }
//    }
//}
