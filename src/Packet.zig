const std = @import("std");
const print = std.debug.print;
const activeTag = std.meta.activeTag;

const RawPacket = @import("RawPacket.zig").RawPacket;
const Layer = @import("Layer.zig").Layer;
const LayerProtocols = @import("Layer.zig").LayerProtocols;
const LinkLayerProtocols = @import("Layer.zig").LinkLayerProtocols;
const NetworkProtocols = @import("Layer.zig").NetworkProtocols;
const TPtr = @import("Layer.zig").TPtr;

const EthLayer = @import("Eth.zig").EthLayer;
const EthHeaderSize = @import("Eth.zig").EthHeaderSize;
const EthType = @import("Eth.zig").EthType;

const IPv4Layer = @import("IPv4.zig").IPv4Layer;
const IPv4Header = @import("IPv4.zig").IPv4Header;
const IPv4 = @import("IPv4.zig");

const IPv6Layer = @import("IPv6.zig").IPv6Layer;
const IPv6HeaderSize = @import("IPv6.zig").HeaderSize;

pub const Packet = struct {
    raw_packet: ?*RawPacket,
    first_layer: ?*Layer,
    last_layer: ?*Layer,

    /// Creates empty Packet struct with with empty RawPacket. First and Last layer are null.
    pub fn init(allocator: std.mem.Allocator) !*Packet {
        var p = try allocator.create(Packet);
        p.first_layer = null;
        p.last_layer = null;
        p.raw_packet = try allocator.create(RawPacket);
        return p;
    }

    pub fn init_from_raw(raw_packet: *RawPacket, allocator: std.mem.Allocator) !*Packet {
        var p = try allocator.create(Packet);
        p.first_layer = null;
        p.last_layer = null;
        p.raw_packet = raw_packet;
        return p;
    }

    pub fn parse_link_layer(self: *Packet, allocator: std.mem.Allocator) !void {
        if (self.raw_packet == null) {
            return error.RawPacketNotAllocated;
        }

        const raw: []u8 = self.raw_packet.?.raw_data;

        switch (self.raw_packet.?.link_type) {
            LinkLayerProtocols.ETHERNET => {
                const eth_layer = try EthLayer.init(raw[0..14], allocator);
                try self.add_layer(eth_layer, allocator);
            },
            else => return error.UnknownLinkType,
        }
    }

    pub fn parse_layers(self: *Packet, allocator: std.mem.Allocator) !void {
        if (self.first_layer == null) {
            return error.LinkLayerIsNull;
        }

        const raw: []u8 = self.raw_packet.?.raw_data;

        const first_layer: *Layer = self.first_layer.?;

        switch (activeTag(first_layer.get_protocol())) {
            LayerProtocols{ .LinkLayer = .ETHERNET } => {
                const eth_layer: *EthLayer =
                    self.get_layer_of_type(LayerProtocols{ .LinkLayer = .ETHERNET }, EthLayer) orelse return error.EthLayerNull;
                const eth_type: EthType = try eth_layer.get_eth_type();
                switch (eth_type) {
                    EthType.IP => {
                        if (raw.len < EthHeaderSize) return error.PacketTooSmall;

                        const ip_version = raw[EthHeaderSize] >> 4;

                        if (ip_version == @intFromEnum(NetworkProtocols.IPv4)) {
                            const hdr_len = (raw[EthHeaderSize] & 0x0F) * 4;

                            if (hdr_len < IPv4.MinHeaderLength or hdr_len > IPv4.MaxHeaderLength) return error.IPv4HdrLenInvalid;

                            const IPv4HeaderSlice = EthHeaderSize + IPv4.MinHeaderLength;

                            const ipv4_layer = try IPv4Layer.init(raw[EthHeaderSize..IPv4HeaderSlice], allocator);
                            try self.add_layer(ipv4_layer, allocator);

                            return;
                        }
                        if (ip_version == @intFromEnum(NetworkProtocols.IPv6)) {
                            const ipv6_layer = try IPv6Layer.init(raw[14..54], allocator);
                            try self.add_layer(ipv6_layer, allocator);

                            return;
                        } else {
                            print("Unknown network protocol.\n", .{});
                            return;
                        }
                    },
                    else => print("unknown ethtype.\n", .{}),
                }
            },
            else => return error.UnknownLinkType,
        }
    }

    /// Adds a layer to the tail of the layers.
    pub fn add_layer(self: *Packet, layer: anytype, allocator: std.mem.Allocator) !void {
        print("Adding layer of type: {s}\n", .{@typeName(@TypeOf(layer))});
        //        var curr_layer = self.first_layer;
        self.first_layer = try allocator.create(Layer); // create interface layer
        self.first_layer.?.* = Layer.implBy(layer); // deref the interface layer and assign to the implementation layer

    }

    pub fn get_layer_type(self: *Packet, layer: anytype) ?*layer {
        print("Getting layer of type: {s}\n", .{@typeName(@TypeOf(layer))});

        if (self.first_layer) |l| { // iterate here
            print("{s}\n", .{@typeName(@TypeOf(TPtr(*layer, l.layer_type)))});
            const lay = TPtr(*layer, l.layer_type);
            return lay;
        }

        return null;
    }

    pub fn get_layer_of_type(self: *Packet, protocol_layer: LayerProtocols, layer: anytype) ?*layer {
        if (self.first_layer) |l| {
            if (std.meta.activeTag(l.get_protocol()) == std.meta.activeTag(protocol_layer)) {
                print("ProtocolLayer type {s}\n", .{@tagName(std.meta.activeTag(l.get_protocol()))});

                return TPtr(*layer, l.layer_type);
            }
        }

        return null;
    }

    pub fn has_layer(self: *Packet, protocol_layer: LayerProtocols) bool {
        if (self.first_layer) |layer| {
            if (std.meta.activeTag(layer.get_protocol()) == std.meta.activeTag(protocol_layer)) {
                return true;
            }
        }

        return false;
    }

    pub fn deinit(self: *Packet, allocator: std.mem.Allocator) void {
        //TODO: Iterate through layers and deinit them
        allocator.destroy(self);
    }
};

//test "DNS_Packet" {
//    const raw: [87]u8 = .{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x8, 0x0, 0x45, 0x0, 0x0, 0x49, 0x5d, 0xf7, 0x40, 0x0, 0x40, 0x11, 0x57, 0x7d, 0xc0, 0xa8, 0x1, 0xfe, 0xc0, 0xa8, 0x1, 0xe1, 0x0, 0x35, 0xfd, 0xdf, 0x0, 0x35, 0x9d, 0xff, 0x3a, 0xd0, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x7, 0x7a, 0x69, 0x67, 0x6c, 0x61, 0x6e, 0x67, 0x3, 0x6f, 0x72, 0x67, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1, 0x2c, 0x0, 0x4, 0x41, 0x6d, 0x69, 0xb2 };
//
//    var raw_pkt_buf: [@sizeOf(raw)]u8 = undefined;
//
//    var fba = std.heap.FixedBufferAllocator(&raw_pkt_buf);
//    var allocator = fba.allocator();
//
//    var buf: []u8 = try allocator.alloc(u8, raw_pkt_buf.len);
//
//    std.mem.copyForwards(u8, buf, &raw);
//
//    const udp_layer = try UDPLayer.init(buf[0..8], allocator);
//
//    var packet = try Packet.init(allocator);
//
//    try packet.add_layer(udp_layer, allocator);
//
//    const udp_l = packet.get_layer_type(UDPLayer);
//
//    //    udp_layer.set_src_port(53);
//
//    print("Src port: {d}\n", .{udp_l.?.get_src_port()});
//    print("Dst port: {d}\n", .{udp_l.?.get_dst_port()});
//    print("Checksum: {d}\n", .{udp_l.?.get_checksum()});
//    print("Length: {d}\n", .{udp_l.?.get_length()});
//
//    const ulayer: ?*UDPLayer = packet.get_layer_of_type(LayerProtocols{ .Transport = .UDP }, UDPLayer);
//    if (ulayer) |l| {
//        _ = l;
//        print("Packet has UDP Layer.\n", .{});
//        return;
//    }
//}
