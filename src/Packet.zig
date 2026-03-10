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

    /// Creates empty Packet struct with with empty RawPacket. First and Last layer are set to null.
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
        try p.parse_link_layer(allocator);
        p.parse_all_layers(allocator);
        return p;
    }

    fn parse_link_layer(self: *Packet, allocator: std.mem.Allocator) !void {
        if (self.raw_packet == null) {
            return error.RawPacketNotAllocated;
        }

        const raw: []u8 = self.raw_packet.?.raw_data;

        switch (self.raw_packet.?.link_type) {
            LinkLayerProtocols.ETHERNET => {
                const eth_layer = try EthLayer.init(raw[0..], allocator);
                try self.add_layer(eth_layer, allocator);
            },
            else => return error.UnknownLinkType,
        }
    }

    fn parse_all_layers(self: *Packet, allocator: std.mem.Allocator) void {
        var cur = self.first_layer;

        while (cur) |layer| {
            const next = layer.parse_next_layer(allocator) orelse break;

            layer.next_layer = next;
            cur = next;
        }

        self.last_layer = cur;
    }

    /// Adds a layer to the tail of the layers.
    pub fn add_layer(self: *Packet, layer: anytype, allocator: std.mem.Allocator) !void {
        var cur = self.first_layer;
        const new_layer: ?*Layer = try allocator.create(Layer); // create interface layer
        new_layer.?.* = Layer.implBy(layer); // deref the interface layer and assign to the implementation layer

        while (cur) |l| {
            if (l.next_layer == null) {
                print("found null layer.\n", .{});
                l.next_layer = new_layer;
                self.last_layer = new_layer;
                break;
            }
            cur = l.next_layer;
        }
    }

    pub fn get_layer_of_type(self: *Packet, protocol_layer: LayerProtocols, layer: anytype) ?*layer {
        var cur = self.first_layer;

        while (cur) |l| {
            if (std.meta.activeTag(l.get_protocol()) == std.meta.activeTag(protocol_layer)) {
                return TPtr(*layer, l.layer_type);
            }

            cur = l.next_layer;
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
