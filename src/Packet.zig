const std = @import("std");
const print = std.debug.print;
const activeTag = std.meta.activeTag;
const Allocator = std.mem.Allocator;

const WirePacket = @import("WirePacket.zig").WirePacket;
const Layer = @import("Layer.zig").Layer;
const LayerProtocols = @import("Layer.zig").LayerProtocols;

const LayerError = @import("Layer.zig").LayerError;

const LinkLayerProtocols = @import("Layer.zig").LinkLayerProtocols;
const NetworkProtocols = @import("Layer.zig").NetworkProtocols;
const TPtr = @import("Layer.zig").TPtr;

const Eth = @import("Eth.zig");
const IPv4 = @import("IPv4.zig");
const IPv6Layer = @import("IPv6.zig");
const UDP = @import("UDPLayer.zig");

const GenericLayer = @import("GenericLayer.zig").GenericLayer;

const EthLayer = Eth.EthLayer;

fn get_layer_type_enum(value: type) !LayerProtocols {
    switch (value) {
        EthLayer => return LayerProtocols{ .LinkLayer = .ETHERNET },
        IPv4.IPv4Layer => return LayerProtocols{ .Network = .IPv4 },
        UDP.UDPLayer => return LayerProtocols{ .Transport = .UDP },
        else => return error.LayerInvalid,
    }
}

pub fn get_layer_init(choice: type) !*const fn ([]u8) LayerError!choice {
    switch (choice) {
        EthLayer => return EthLayer.init,
        IPv4.IPv4Layer => return IPv4.IPv4Layer.init,
        UDP.UDPLayer => return UDP.UDPLayer.init,
        else => return error.LayerInvalid,
    }
}

pub fn get_init(choice: LayerProtocols) !*Layer {
    switch (choice) {
        LayerProtocols{ .LinkLayer = .ETHERNET },
        => return EthLayer.preallocated_buffer,
        LayerProtocols{ .Network = .IPv4 },
        => return IPv4.IPv4Layer.preallocated_buffer,
        LayerProtocols{ .Transport = .UDP },
        => return UDP.UDPLayer.preallocated_buffer,
        else => return error.LayerInvalid,
    }
}

/// returns a slice in an existing buffer for layer to be created from
pub fn get_padded_buffer(layer_type: type, current_offset: usize, buffer: *[]u8, allocator: Allocator) ![]u8 {
    print("Getting padded buffer for {s}: \n", .{@typeName(layer_type)});
    const protocol_enum = try get_layer_type_enum(layer_type);

    print("\tcurrent offset: {}\n", .{current_offset});
    const hdr_size: usize = get_layer_size(protocol_enum); // get the size of the layers hdr type
    print("\thdr size: {}\n", .{hdr_size});
    const alignment_size: usize = get_layer_alignment(protocol_enum); // get the alignment size of the layers hdr type
    print("\talignment size: {}\n", .{alignment_size});
    const next_offset = get_next_relative_offset(current_offset, alignment_size);
    print("\tnext_offset: {}\n", .{next_offset});

    const pad_size = buffer.*[current_offset..next_offset].len;

    print("\tpad size: {}\n", .{pad_size});

    _ = try insert_padding(buffer, current_offset, pad_size, allocator);

    print("\tslice {x}\n", .{buffer.*[0..]});

    return buffer.*[next_offset..];
}

pub const Packet = struct {
    first_layer: ?*Layer,
    last_layer: ?*Layer,
    allocator: Allocator,
    aligned_buffer: []u8,

    /// Creates an empty Packet - alloc's zero bytes to aligned buffer initially
    pub fn create(allocator: Allocator) !Packet {
        return Packet{
            .first_layer = null,
            .last_layer = null,
            .allocator = allocator,
            .aligned_buffer = try allocator.alloc(u8, 0),
        };
    }

    /// Creates a Packet from an existing wire packet. The buffer needs to be mutable so padding can be inserted
    /// if required and the alllocator used to allocate the buffer needs to be passed for potentail realloc.
    pub fn from_wire_packet(self: *Packet, wire_packet: *WirePacket) !void {
        self.aligned_buffer = wire_packet.raw_data;

        var starting_offset: usize = 0;

        switch (wire_packet.link_type) {
            LinkLayerProtocols.ETHERNET => {
                if (self.aligned_buffer.len < @sizeOf(Eth.EthHeader)) return error.BufferTooSmallForEth;
                const eth_layer = try self.allocator.create(EthLayer);
                eth_layer.* = try EthLayer.init(self.aligned_buffer);
                starting_offset = 0;
                try self.add_layer(eth_layer);

                //                const next_type = eth_layer.get_next_layer_type();
                //                print("{any}\n", .{next_type});
            },
            else => return error.UnknownLinkType,
        }
        try self.accumulate_layers(self.get_first_layer(), starting_offset);
    }

    /// Creates new layer in the Packet. Specify the layer (e.g. EthLayer, IPv4Layer etc), and the layer will be returned with it's memory allocated in the aligned_buffer. You must free the layer returned when done with it. The underlying bytes representing the layer are preserved in the aligned buffer
    pub fn create_new_layer(self: *Packet, layer_type: type) !*layer_type {
        const protocol_enum = try get_layer_type_enum(layer_type);

        const hdr_size: usize = get_layer_size(protocol_enum); // get the size of the layers hdr type
        const alignment_size: usize = get_layer_alignment(protocol_enum); // get the alignment size of the layers hdr type

        const current_offset = self.aligned_buffer.len;
        const next_offset = get_next_relative_offset(current_offset, alignment_size);

        var new_buffer = try self.allocator.realloc(self.aligned_buffer, next_offset + hdr_size);
        self.aligned_buffer = new_buffer;
        @memset(new_buffer[current_offset..], 0); // zero the pad bytes

        const impl_init = try get_layer_init(layer_type);

        const impl_layer: *layer_type = try self.allocator.create(layer_type);

        impl_layer.* = try impl_init(new_buffer[next_offset..]);

        try self.add_layer(impl_layer);

        return impl_layer;
    }

    pub fn get_all_layers(self: *Packet) void {
        var cur = self.get_first_layer();
        while (cur) |layer| {
            print("Next layer type: {any}\n", .{layer.get_next_layer_type() orelse return});
            cur = layer.get_next_layer();
        }
    }

    /// returns a slice in an existing buffer for layer to be created from
    fn return_padded_buffer(self: *Packet, layer_type: LayerProtocols, current_offset: usize) ![]u8 {
        print("current offset: {}\n", .{current_offset});
        const hdr_size: usize = get_layer_size(layer_type); // get the size of the layers hdr type
        print("hdr size: {}\n", .{hdr_size});
        const alignment_size: usize = get_layer_alignment(layer_type); // get the alignment size of the layers hdr type
        print("alignment size: {}\n", .{alignment_size});
        const next_offset = get_next_relative_offset(current_offset, alignment_size);
        print("next_offset: {}\n", .{next_offset});

        const pad_size = self.aligned_buffer[current_offset..next_offset].len;

        print("pad size: {}\n", .{pad_size});

        var slice = try insert_padding(&self.aligned_buffer, current_offset, pad_size, self.allocator);

        print("slice {x}\n", .{self.aligned_buffer[0..]});

        return slice[next_offset..];
    }

    fn accumulate_layers(self: *Packet, layer: ?*Layer, current_offset: usize) !void {
        if (layer) |cur| {
            print("cur layer data: {x}\n", .{cur.get_data()});

            const next_protocol_layer = cur.get_next_layer_type();
            // store the sliced buf for the layer init here
            // store the layer init here

            switch (cur.get_next_layer_type()) {
                .Network => |net| switch (net) {
                    .IPv4 => {
                        print("IPv4\n", .{});
                        var ipv4_buf = try self.return_padded_buffer(next_protocol_layer, 14);
                        const ipv4_layer = try self.allocator.create(IPv4.IPv4Layer);
                        ipv4_layer.* = try IPv4.IPv4Layer.init(ipv4_buf[0..]);
                        try self.add_layer(ipv4_layer);
                    },
                    .IPv6 => {
                        print("IPv6\n", .{});
                    },
                    .Generic => {
                        print("Generic network protocol\n", .{});
                    },
                },
                else => {}, // Ignore other layers
            }

            // call init here
            // call layer.set_next_layer() here

            try self.accumulate_layers(cur.get_next_layer(), current_offset);
        }

        // Remember to add the tail layer at the end

        return;
    }

    fn parse_all_layers(self: *Packet) void {
        print("parsing layers:\n", .{});
        var cur = self.get_first_layer();

        while (cur) |layer| {
            print("cur offset: {x}\n", .{layer.get_data()});
            print("current: {any}\n", .{layer.get_protocol()});
            const next_protocol = layer.get_next_layer_type();

            print("{any}\n", .{next_protocol});

            const next = layer.parse_next_layer(self.allocator) orelse break;

            print("data from next layer: {x}\n", .{next.get_data()});

            layer.set_next_layer(next);
            cur = next;
        }

        self.last_layer = cur;
    }

    // Adds a layer to the tail of the layers.
    fn add_layer(self: *Packet, layer: anytype) !void {
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

    /// returns the Layer desired if it is present
    pub fn get_layer(self: *Packet, layer_type: type) !?*layer_type {
        const protocol_enum = try get_layer_type_enum(layer_type);

        const impl_init = try get_layer_init(layer_type);

        var cur = self.first_layer;

        while (cur) |l| {
            if (activeTag(l.get_protocol()) == activeTag(protocol_enum)) {
                const layer: *layer_type = try self.allocator.create(layer_type);
                const layer_slice: []u8 = self.get_layer_from_buffer(protocol_enum) orelse {
                    return null;
                };

                layer.* = try impl_init(layer_slice);
                return layer;
            }

            cur = l.next_layer;
        }

        return null;
    }

    pub fn get_layer_data(self: *Packet, layer_type: type) !?[]u8 {
        const layer_enum = try get_layer_type_enum(layer_type);

        print("{any}\n", .{layer_enum});

        var cur = self.first_layer;

        while (cur) |l| {
            if (activeTag(l.get_protocol()) == activeTag(layer_enum)) {
                return l.get_data();
            }

            cur = l.next_layer;
        }

        return null;
    }

    /// returns true if the layer is present
    pub fn has_layer(self: *Packet, layer_type: type) !bool {
        const layer_enum = try get_layer_type_enum(layer_type);

        var cur = self.first_layer;

        while (cur) |l| {
            if (activeTag(l.get_protocol()) == activeTag(layer_enum)) {
                return true;
            }

            cur = l.next_layer;
        }

        return false;
    }

    pub fn get_first_layer(self: *Packet) ?*Layer {
        return self.first_layer;
    }

    pub fn get_last_layer(self: *Packet) ?*Layer {
        return self.last_layer;
    }

    /// does not work currently
    pub fn to_string(self: *Packet, allocator: Allocator) !void {
        var cur = self.first_layer;

        while (cur) |l| {
            print("{s}\n", .{l.to_string(allocator)});

            cur = l.next_layer;
        }
    }

    pub fn print_protocol_stack(self: *Packet) void {
        var cur = self.first_layer;
        while (cur) |layer| {
            print("{s}\n", .{@tagName(std.meta.activeTag(layer.get_protocol()))});
            cur = layer.next_layer;
        }
    }

    /// This method will return the actual size of packet buffer as it would be on the wire, not including the padding bytes
    pub fn get_wire_size(self: *Packet) usize { // use this to determine "actual size"
        var cur = self.first_layer;

        var wire_size: usize = self.aligned_buffer.len;

        while (cur) |l| {
            const layer_protocol = l.get_protocol();
            const cur_hdr_size = get_layer_size(layer_protocol);

            if (l.get_next_layer()) |next| {
                const padding = calc_padding(cur_hdr_size, get_layer_alignment(next.get_protocol()));
                wire_size -= padding;
            }

            cur = l.next_layer;
        }

        return wire_size;
    }

    /// This takes takes the packet buffer and iterates through the layers, removing the padding bytes and returning the mutable contiguous packet buffer
    pub fn get_wire_format(self: *Packet) []u8 {
        var cur = self.first_layer;

        var wire_buf = self.aligned_buffer;

        while (cur) |l| {
            const layer_protocol = l.get_protocol();
            const cur_hdr_size = get_layer_size(layer_protocol);

            if (l.get_next_layer()) |next| {
                const padding = calc_padding(cur_hdr_size, get_layer_alignment(next.get_protocol()));
                wire_buf = removeRangeInPlace(wire_buf, cur_hdr_size, padding);
            }

            cur = l.next_layer;
        }

        return wire_buf;
    }

    pub fn get_layer_from_buffer(self: *Packet, protocol_layer: LayerProtocols) ?[]u8 {
        var cur = self.first_layer;

        var current_offset: usize = 0;

        while (cur) |l| {
            const layer_protocol = l.get_protocol();
            const cur_hdr_size = get_layer_size(layer_protocol);

            const active_tag = activeTag(layer_protocol);

            if (active_tag == activeTag(protocol_layer)) {
                print("found layer.\n", .{});

                return self.aligned_buffer[current_offset..][0..get_layer_size(protocol_layer)];
                //return buffer[current_offset..][0..];
            }

            // skip padding by calculating the aligned header size
            if (l.get_next_layer()) |next| {
                current_offset += get_next_relative_offset(cur_hdr_size, get_layer_alignment(next.get_protocol()));
            }

            cur = l.next_layer;
        }

        return null;
    }

    /// destroys interface layers from last to first
    pub fn deinit(self: *Packet) void {
        var cur = self.last_layer;
        while (cur) |l| {
            const prev = l.get_prev_layer();
            self.allocator.destroy(l);
            cur = prev;
        }
        self.first_layer = null;
        self.last_layer = null;
    }
};

pub fn get_next_relative_offset(header_size: usize, alignment_size: usize) usize {
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

fn insert_padding(buf: *[]u8, offset: usize, len: usize, allocator: std.mem.Allocator) ![]u8 {
    std.debug.assert(offset <= buf.len);

    const original_len = buf.len;
    const new_len = original_len + len;

    // Reallocate to make room for padding
    var padded_slice = try allocator.realloc(buf.*, new_len);

    // Move the trailing bytes (from offset to end) to the right
    // to make space for the padding
    @memmove(
        padded_slice[offset + len .. new_len],
        padded_slice[offset..original_len],
    );

    // Fill the padding area with 'X'
    @memset(padded_slice[offset .. offset + len], 0);

    // Update the original slice pointer
    buf.* = padded_slice;

    // Return the entire padded slice
    return padded_slice[0..];
}

fn removeRangeInPlace(buf: []u8, offset: usize, len: usize) []u8 {
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

pub fn get_header(protocol: LayerProtocols) type {
    return switch (protocol) {
        .LinkLayer => |link_proto| switch (link_proto) {
            .ETHERNET => return Eth.EthHeader,
            else => return 0,
        },

        .Network => |net_proto| switch (net_proto) {
            .IPv4 => return IPv4.IPv4Header,
            else => return 0,
        },

        .Transport => |trans_proto| switch (trans_proto) {
            .UDP => return UDP.UDPHeader,
            else => return 0,
        },

        else => return 0,
    };
}
