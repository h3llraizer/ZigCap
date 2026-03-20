const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

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

fn add_layers(packet: *Packet, allocator: Allocator) !void {
    print("add_layers: \n", .{});
    const eth_layer = try EthLayer.create(allocator);

    eth_layer.set_src_mac(try MacAddress.init_from_string("14:4f:8a:a4:15:7d"));
    eth_layer.set_dst_mac(try MacAddress.init_from_string("38:06:e6:92:63:ac"));
    try eth_layer.set_eth_type(EthType.IP);

    try packet.add_layer(eth_layer, allocator);

    const ipv4_layer = try IPv4Layer.create(allocator);

    ipv4_layer.set_src_ip(try IPv4Address.init_from_string("192.168.1.225"));
    ipv4_layer.set_dst_ip(try IPv4Address.init_from_string("192.168.1.254"));

    try packet.add_layer(ipv4_layer, allocator);

    var udp_layer = try UDPLayer.create(allocator);

    udp_layer.set_src_port(1234);
    udp_layer.set_dst_port(53);

    print("From original UDP Layer: {s}\n", .{udp_layer.to_string(allocator)});

    try packet.add_layer(&udp_layer, allocator);

    print("From packet last layer (UDP layer just added) {s}\n", .{packet.get_last_layer().?.to_string(allocator)});

    var dns_layer = try DNSLayer.create(allocator, 40);

    try dns_layer.add_query("ziglang.org", DNS.QueryType.A, DNS.DnsClass.IN, allocator);

    try packet.add_layer(dns_layer, allocator);

    //try udp_layer.set_payload(dns_layer.get_payload(), allocator);

    std.debug.print("From packet 3 layer depth: {s}\n", .{packet.get_first_layer().?.get_next_layer().?.get_next_layer().?.to_string(allocator)});

    const udp_data = udp_layer.get_data();

    print("Data len: {}\n", .{udp_data.len});
}

pub fn calculate_next_offset(buffer: []const u8, hdr: anytype) usize {
    const offset = (buffer.len + @alignOf(hdr) - 1) / @alignOf(hdr) * @alignOf(hdr);

    print("offset: {}\n", .{offset});

    return offset;
}

pub fn testp(allocator: Allocator) !void {

    // Calculate offset for IPv4 header that ensures alignment
    // Align eth_size up to the next multiple of align_ipv4

    var packet_buffer = try allocator.alloc(u8, @sizeOf(EthHeader));
    @memset(packet_buffer, 0);

    var eth_layer = try EthLayer.preallocated_buffer(packet_buffer[0..@sizeOf(EthHeader)]);

    // Set Ethernet layer
    eth_layer.set_src_mac(try MacAddress.init_from_string("14:4f:8a:a4:15:7d"));
    eth_layer.set_dst_mac(try MacAddress.init_from_string("38:06:e6:92:63:ac"));
    try eth_layer.set_eth_type(EthType.IP);

    var next_offset = calculate_next_offset(packet_buffer, IPv4Header);

    packet_buffer = try allocator.realloc(packet_buffer, (next_offset + @sizeOf(IPv4Header)));
    // remember to zero the memory

    // Create IPv4 layer at the aligned offset
    var ipv4_layer = try IPv4Layer.preallocated_buffer(packet_buffer[next_offset..][0..@sizeOf(IPv4Header)]);

    var ip_hdr = ipv4_layer.get_header();

    // Set IPv4 header fields
    ip_hdr.version_ihl = 0x45;
    ip_hdr.dscp_ecn = 0;
    ip_hdr.total_length = @byteSwap(@as(u16, @sizeOf(IPv4Header)));
    ip_hdr.identification = 0;
    ip_hdr.flags_fragment = 0;
    ip_hdr.ttl = 64;
    ip_hdr.protocol = @intFromEnum(IPv4Proto.UDP);
    ip_hdr.checksum = 0;

    // Set IP addresses
    ipv4_layer.set_src_ip(try IPv4Address.init_from_string("192.168.1.225"));
    ipv4_layer.set_dst_ip(try IPv4Address.init_from_string("192.168.1.254"));

    // Calculate checksum
    ip_hdr.calculate_checksum();

    next_offset = calculate_next_offset(packet_buffer, UDP.UDPHeader);

    packet_buffer = try allocator.realloc(packet_buffer, (next_offset + @sizeOf(UDP.UDPHeader)));
    // remember to zero the memory

    var udp_layer = try UDP.UDPLayer.preallocated_buffer(packet_buffer[next_offset..][0..@sizeOf(UDP.UDPHeader)]);

    udp_layer.set_src_port(1234);
    udp_layer.set_dst_port(53);
    //try udp_layer.set_payload("1", allocator); // adding payload causes

    udp_layer.calculate_checksum(ip_hdr.src_ip, ip_hdr.dst_ip);

    print("payload: {s}\n", .{udp_layer.get_payload()});

    print("len: {}\n", .{packet_buffer.len});

    // Print the packet
    print("Packet bytes (contiguous): ", .{});
    for (packet_buffer[0..packet_buffer.len]) |byte| {
        print("{x:0>2}", .{byte});
    }

    print("\n", .{});
}

pub fn main() !void {
    // Ensure backing buffer is properly aligned
    //    var backing_buffer: [65536]u8 align(@alignOf(EthHeader)) = undefined;

    print("Size of IPv4Header: {}\n", .{@sizeOf(IPv4Header)});

    var backing_buffer: [65536]u8 = undefined;

    var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);
    const allocator = fba.allocator();

    try testp(allocator);

    // should be 0 because the packet deinit is defered in testp
    print("end index: {}\n", .{fba.end_index});

    // Now print the contiguous packet
    print("Packet bytes (contiguous): ", .{});
    for (backing_buffer[0..fba.end_index]) |byte| {
        print("{x:0>2}", .{byte});
    }
    print("\n", .{});
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
//

const raw: [87]u8 = .{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x8, 0x0, 0x45, 0x0, 0x0, 0x49, 0x5d, 0xf7, 0x40, 0x0, 0x40, 0x11, 0x57, 0x7d, 0xc0, 0xa8, 0x1, 0xfe, 0xc0, 0xa8, 0x1, 0xe1, 0x0, 0x35, 0xfd, 0xdf, 0x0, 0x35, 0x9d, 0xff, 0x3a, 0xd0, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x7, 0x7a, 0x69, 0x67, 0x6c, 0x61, 0x6e, 0x67, 0x3, 0x6f, 0x72, 0x67, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1, 0x2c, 0x0, 0x4, 0x41, 0x6d, 0x69, 0xb2 };
