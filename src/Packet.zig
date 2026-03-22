const std = @import("std");
const print = std.debug.print;
const activeTag = std.meta.activeTag;
const Allocator = std.mem.Allocator;

const RawPacket = @import("RawPacket.zig").RawPacket;
const Layer = @import("Layer.zig").Layer;
const LayerProtocols = @import("Layer.zig").LayerProtocols;

const LinkLayerProtocols = @import("Layer.zig").LinkLayerProtocols;
const NetworkProtocols = @import("Layer.zig").NetworkProtocols;
const TPtr = @import("Layer.zig").TPtr;

const Eth = @import("Eth.zig");
const IPv4 = @import("IPv4.zig");
const IPv6Layer = @import("IPv6.zig");
const UDP = @import("UDPLayer.zig");

pub const Packet = struct {
    raw_packet: ?*RawPacket,
    first_layer: ?*Layer,
    last_layer: ?*Layer,
    allocator: Allocator,

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

    /// Creaates an empty Packet, the interface is only used for creating the interface Layer structs.
    /// Using a seperate allocator from your packet buffer is recommended to avoid alignment and casting bugs
    pub fn create(allocator: Allocator) Packet {
        return Packet{ .raw_packet = null, .first_layer = null, .last_layer = null, .allocator = allocator };
    }

    fn parse_link_layer(self: *Packet, allocator: std.mem.Allocator) !void {
        if (self.raw_packet == null) {
            return error.RawPacketNotAllocated;
        }

        const raw: []u8 = self.raw_packet.?.raw_data;

        switch (self.raw_packet.?.link_type) {
            LinkLayerProtocols.ETHERNET => {
                const eth_layer = try Eth.EthLayer.init(raw[0..], allocator);
                try self.add_layer(eth_layer, allocator);
            },
            else => return error.UnknownLinkType,
        }
    }

    fn parse_all_layers(self: *Packet, allocator: std.mem.Allocator) void {
        var cur = self.first_layer;

        while (cur) |layer| {
            const next = layer.parse_next_layer(allocator) orelse break;

            layer.set_next_layer(next);
            cur = next;
        }

        self.last_layer = cur;
    }

    /// Adds a layer to the tail of the layers.
    pub fn add_layer(self: *Packet, layer: anytype) !void {
        const new_layer = try self.allocator.create(Layer);
        new_layer.* = Layer.implBy(layer);

        if (self.first_layer == null) {
            self.first_layer = new_layer;
            print("added first layer.\n", .{});
            return;
        }

        var cur = self.first_layer;

        while (cur) |current_layer| {
            if (current_layer.next_layer == null) {
                current_layer.set_next_layer(new_layer);
                if (current_layer.next_layer) |next_layer| {
                    next_layer.set_prev_layer(current_layer);
                    self.last_layer = current_layer.next_layer;
                }
                break;
            }
            cur = current_layer.next_layer;
        }
    }

    /// This method returns the layer desired if it's present in the packet already casted to the implementation
    pub fn get_layer_of_type(self: *Packet, protocol_layer: LayerProtocols, layer: anytype) ?*layer {
        var cur = self.first_layer;

        while (cur) |l| {
            if (activeTag(l.get_protocol()) == activeTag(protocol_layer)) {
                return TPtr(*layer, l.layer_type);
            }

            cur = l.next_layer;
        }

        return null;
    }

    /// This method returns the Layer desired if it's present. It returns *Layer, if you want the implementation, cast it
    pub fn get_layer(self: *Packet, protocol_layer: LayerProtocols) ?*Layer {
        var cur = self.first_layer;

        while (cur) |l| {
            if (activeTag(l.get_protocol()) == activeTag(protocol_layer)) {
                return l;
            }

            cur = l.next_layer;
        }

        return null;
    }

    pub fn has_layer(self: *Packet, protocol_layer: LayerProtocols) bool {
        var cur = self.first_layer;
        while (cur) |layer| {
            if (std.meta.activeTag(layer.get_protocol()) == std.meta.activeTag(protocol_layer)) {
                return true;
            }
            if (layer.next_layer) |next| {
                cur = next;
            } else {
                break;
            }
        }

        return false;
    }

    pub fn get_first_layer(self: *Packet) ?*Layer {
        return self.first_layer;
    }

    pub fn get_last_layer(self: *Packet) ?*Layer {
        return self.last_layer;
    }

    pub fn print_protocol_stack(self: *Packet) void {
        var cur = self.first_layer;
        while (cur) |layer| {
            print("{s} ", .{@tagName(std.meta.activeTag(layer.get_protocol()))});
            cur = layer.next_layer;
        }
    }

    pub fn print_layer_alignments(self: *Packet) void { // use this to determine "actual size"
        var cur = self.first_layer;
        while (cur) |layer| {
            print("{s} ", .{@tagName(activeTag(layer.get_protocol()))});
            const alignment = get_layer_alignment(layer.get_protocol());
            print("{}\n", .{alignment});
            cur = layer.next_layer;
        }
    }

    pub fn get_layer_from_buffer(self: *Packet, protocol_layer: LayerProtocols, buffer: []u8) ?[]u8 {
        print("Finding layer in buffer:\n", .{});

        var cur = self.first_layer;

        const protocol_layer_hdr_size = get_layer_size(protocol_layer);
        print("protocol hdr size: {}\n", .{protocol_layer_hdr_size});

        print("buf size: {}\n", .{buffer.len});

        var current_offset: usize = 0;

        while (cur) |l| {
            print("current offset: {}\n", .{current_offset});
            const layer_protocol = l.get_protocol();
            const cur_hdr_size = get_layer_size(layer_protocol);

            print("cur hdr size: {}\n", .{cur_hdr_size});

            const active_tag = activeTag(layer_protocol);

            if (active_tag == activeTag(protocol_layer)) {
                print("found layer.\n", .{});

                //                return buffer[current_offset..][0..protocol_layer_hdr_size];
                return buffer[current_offset..][0..];
            }

            // skip padding by calculating the aligned header size
            if (l.get_next_layer()) |next| {
                current_offset += get_header_aligned_size(cur_hdr_size, get_layer_alignment(next.get_protocol()));
            }

            cur = l.next_layer;
        }

        return null;
    }

    pub fn deinit(self: *Packet, allocator: std.mem.Allocator) void {
        //TODO: Iterate through layers and deinit them
        allocator.destroy(self);
    }
};

pub fn get_header_aligned_size(header_size: usize, alignment_size: usize) usize {
    const aligned_header_size = (header_size + alignment_size - 1) / alignment_size * alignment_size;
    print("Current offset: {}, alignment: {}, next offset: {}\n", .{ header_size, alignment_size, aligned_header_size });
    return aligned_header_size;
}

pub fn calc_padding(current_offset: usize, alignment_size: usize) usize {
    const padding = (alignment_size - (current_offset % alignment_size)) % alignment_size;
    return padding;
}

pub fn calculate_next_offset(current_offset: usize, comptime HdrType: type) usize {
    const alignment = @alignOf(HdrType);
    const next_offset = (current_offset + alignment - 1) / alignment * alignment;
    print("Current offset: {}, alignment of {s}: {}, next offset: {}\n", .{ current_offset, @typeName(HdrType), alignment, next_offset });
    return next_offset;
}

pub fn calculate_padding(current_offset: usize, comptime HdrType: type) usize {
    const alignment = @alignOf(HdrType);
    const padding = (alignment - (current_offset % alignment)) % alignment;
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

pub fn get_layer_size(protocol: LayerProtocols) usize {
    return switch (protocol) {
        .LinkLayer => |link_proto| switch (link_proto) {
            .ETHERNET => return @sizeOf(Eth.EthHeader),
            else => return 0,
        },

        .Network => |net_proto| switch (net_proto) {
            .IPv4 => return @sizeOf(IPv4.IPv4Header),
            else => return 0,
        },

        .Transport => |trans_proto| switch (trans_proto) {
            .UDP => return @sizeOf(UDP.UDPHeader),
            else => return 0,
        },

        else => return 0,
    };
}

pub fn get_layer_alignment(protocol: LayerProtocols) usize {
    return switch (protocol) {
        .LinkLayer => |link_proto| switch (link_proto) {
            .ETHERNET => return @alignOf(Eth.EthHeader),
            else => return 0,
        },

        .Network => |net_proto| switch (net_proto) {
            .IPv4 => return @alignOf(IPv4.IPv4Header),
            else => return 0,
        },

        .Transport => |trans_proto| switch (trans_proto) {
            .UDP => return @alignOf(UDP.UDPHeader),
            else => return 0,
        },

        else => return 0,
    };
}

pub fn get_alignment(comptime HdrType: type) usize {
    return @alignOf(HdrType);
}
