const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;
const activeTag = std.meta.activeTag;

const PcapWrapper = @import("PcapWrapper.zig");

const Packet = @import("Packet.zig");

const LayerProtocols = @import("Layer.zig").LayerProtocols;
const Layer = @import("Layer.zig").Layer;

const TPtr = @import("Layer.zig").TPtr;
const LinkLayerProtocols = @import("Layer.zig").LinkLayerProtocols;
const IPv4Proto = @import("ProtocolEnums.zig").IPv4Proto;
const WirePacket = @import("WirePacket.zig").WirePacket;

const EthLayer = @import("Eth.zig").EthLayer;
const EthType = @import("Eth.zig").EthType;
const EthHeader = @import("Eth.zig").EthHeader;
const MacAddress = @import("Eth.zig").MacAddress;

const IPv4Layer = @import("IPv4.zig").IPv4Layer;
const IPv4Address = @import("IPv4.zig").IPv4Address;
const IPv4Header = @import("IPv4.zig").IPv4Header;

//const UDPLayer = @import("UDP.zig").UDPLayer;
const DNSLayer = @import("DNS.zig").DNSLayer;
const UDPLayer = @import("UDPLayer.zig").UDPLayer;
const DNS = @import("DNS.zig");

const GenericLayer = @import("GenericLayer.zig").GenericLayer;

const from_protocol_layer = @import("Layer.zig").from_protocol_layer;

/// Returns the slice which the next layer can be allocated in
fn add_layer_slice_in_buffer(self: *Packet, comptime HdrType: type) ![]u8 {
    const current_offset = self.buffer.len;
    const next_offset = Packet.calculate_next_offset(current_offset, HdrType);
    const resized_buffer = try add_padding(self.buffer, HdrType, self.buffer_allocator);
    const hdr_size: usize = @sizeOf(HdrType);
    return resized_buffer[next_offset..][0..hdr_size];
}

/// Returns buffer with the padding added
fn add_padding(self: *Packet, comptime HdrType: type) ![]u8 {
    const old_size = self.buffer.len;
    const current_offset = self.buffer.len;
    const hdr_size: usize = @sizeOf(HdrType);
    const next_offset = Packet.calculate_next_offset(current_offset, HdrType);
    const new_size = next_offset + hdr_size;
    const resized_buffer = try self.buffer_allocator.realloc(self.buffer, new_size);
    @memset(resized_buffer[old_size..], 0);
    return resized_buffer;
}

pub fn add_layer_to_buf(allocator: Allocator, buffer: *[]u8, layer_type: LayerProtocols) ![]u8 {
    const hdr_size = Packet.get_layer_size(layer_type);
    const alignment_size = Packet.get_layer_alignment(layer_type);
    const current_offset = buffer.len;
    const next_offset = Packet.get_header_aligned_size(current_offset, alignment_size); // should be called get alignment size

    print("next offset: {} hdr_size: {}\n", .{ next_offset, hdr_size });

    var new_buffer = try allocator.realloc(buffer.*, next_offset + hdr_size);
    buffer.* = new_buffer;
    @memset(new_buffer[current_offset..], 0); // zero the pad bytes
    return new_buffer[next_offset..]; // returns the slice which the layer can be init'd from
}

fn create_packet_test(packet: *Packet.Packet, allocator: Allocator) !void {
    var packet_buffer = try allocator.alloc(u8, 0);
    const eth_buffer = try add_layer_to_buf(allocator, &packet_buffer, LayerProtocols{ .LinkLayer = .ETHERNET });
    var eth_layer = try EthLayer.preallocated_buffer(eth_buffer);
    eth_layer.set_src_mac(try MacAddress.init_from_string("14:4f:8a:a4:15:7d"));
    eth_layer.set_dst_mac(try MacAddress.init_from_string("38:06:e6:92:63:ac"));
    try eth_layer.set_eth_type(EthType.IP);

    print("eth: {x}\n", .{eth_buffer});

    try packet.add_layer(&eth_layer);

    const ipv4_buffer = try add_layer_to_buf(allocator, &packet_buffer, LayerProtocols{ .Network = .IPv4 });

    print("ipv4 len: {}\n", .{ipv4_buffer.len});

    var ipv4_layer = try IPv4Layer.preallocated_buffer(ipv4_buffer);

    var ip_hdr = ipv4_layer.get_header();
    ip_hdr.version_ihl = 0x45;
    ip_hdr.ttl = 64;
    ip_hdr.protocol = @intFromEnum(IPv4Proto.UDP);
    ip_hdr.checksum = 0;

    ipv4_layer.set_src_ip(try IPv4Address.init_from_string("192.168.1.225"));
    ipv4_layer.set_dst_ip(try IPv4Address.init_from_string("192.168.1.254"));

    try packet.add_layer(&ipv4_layer);

    print("{x}\n", .{packet_buffer});
    print("packet len: {}\n", .{packet_buffer.len});
}

fn add_eth(packet: *Packet.Packet) !void {
    var eth_layer: EthLayer = try packet.create_new_layer(EthLayer);

    eth_layer.set_src_mac(try MacAddress.init_from_string("14:4f:8a:a4:15:7d"));
    eth_layer.set_dst_mac(try MacAddress.init_from_string("38:06:e6:92:63:ac"));
    try eth_layer.set_eth_type(EthType.IP);

    print("eth: {x}\n", .{eth_layer.data});
}

fn add_ip(packet: *Packet.Packet) !void {
    var ipv4_layer: IPv4Layer = try packet.create_new_layer(IPv4Layer);
    var ip_hdr = ipv4_layer.get_header();
    ip_hdr.version_ihl = 0x45;
    ip_hdr.ttl = 64;
    ip_hdr.protocol = @intFromEnum(IPv4Proto.UDP);
    ip_hdr.checksum = 0;

    ipv4_layer.set_src_ip(try IPv4Address.init_from_string("192.168.1.225"));
    ipv4_layer.set_dst_ip(try IPv4Address.init_from_string("192.168.1.254"));
}

fn add_udp(packet: *Packet.Packet) !void {
    var udp_layer: UDPLayer = try packet.create_new_layer(UDPLayer);

    udp_layer.set_src_port(1234);
    udp_layer.set_dst_port(30045);
    try udp_layer.set_payload("hello", packet.allocator);

    var ipv4_layer: IPv4Layer = try packet.get_layer(IPv4Layer) orelse {
        return error.NoIPLayer;
    };

    var ip_hdr = ipv4_layer.get_header();

    // Update IPv4 total length
    ip_hdr.total_length = @byteSwap(@as(u16, @intCast(@sizeOf(IPv4Header) + udp_layer.data.len)));

    // Calculate checksums
    ip_hdr.calculate_checksum();
    print("{x}\n", .{ip_hdr.checksum});
    udp_layer.calculate_checksum(ip_hdr.src_ip, ip_hdr.dst_ip);
    print("{x}\n", .{udp_layer.get_header().checksum});

    print("UDP Data: {x}\n", .{udp_layer.data});
}

pub fn main() !void {
    var pkt_data_backing_buffer: [2048]u8 = undefined;

    var pkt_data_fba = std.heap.FixedBufferAllocator.init(&pkt_data_backing_buffer);
    const pkt_data_allocator = pkt_data_fba.allocator();

    const page_allocator = std.heap.page_allocator;

    _ = &page_allocator;

    var packet = try Packet.Packet.create(pkt_data_allocator);
    defer packet.deinit();

    try add_eth(&packet);
    try add_ip(&packet);

    print("mem: {}\n", .{pkt_data_fba.end_index});

    var layer = try packet.get_layer(EthLayer) orelse {
        print("no first layer.\n", .{});
        return;
    };

    print("{any}\n", .{layer.get_protocol()});

    if (try packet.has_layer(IPv4Layer)) {
        print("packet has IPv4 Layer.\n", .{});
    } else {
        print("no IPv4 layer.\n", .{});
    }

    try add_udp(&packet);

    print("{x}\n", .{packet.aligned_buffer});

    print("wire size: {}\n", .{packet.get_wire_size()});

    const wire_buf = packet.get_wire_format();

    print("{x}\n", .{wire_buf});

    var wifi_interface = try open_pcap() orelse {
        return error.FailedToOpen;
    };

    try wifi_interface.send(wire_buf);

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
            //print("Found:\n{s}\n", .{iface.toString(allocator)});

            try iface.open(allocator);

            if (iface.isOpened()) {
                //print("Device is open.\n", .{});
                return iface;
            } else {
                //print("Device not open.\n", .{});
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
