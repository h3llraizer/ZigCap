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
const TCP = @import("TCP.zig");

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
pub fn alignment_check(buffer: []u8, alignment: usize) usize {
    const addr = @intFromPtr(buffer.ptr);

    return addr % alignment;
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
    pub fn from_wire_packet(self: *Packet, wire_packet: *WirePacket) !void { // may ditch the wire packet and just use slices
        self.aligned_buffer = wire_packet.raw_data;

        try self.accum_layers(0, LayerProtocols{ .LinkLayer = wire_packet.link_type });
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

    /// returns a slice in an existing buffer for layer to be created from
    fn return_padded_buffer(self: *Packet, layer_type: LayerProtocols, current_offset: usize) ![]u8 {
        const alignment_size: usize = get_layer_alignment(layer_type); // get the alignment size of the layers hdr type
        const next_offset = get_next_relative_offset(current_offset, alignment_size);
        const pad_size = self.aligned_buffer[current_offset..next_offset].len;
        print("pad size: {}\n", .{pad_size});
        if (pad_size == 0) {
            return self.aligned_buffer[current_offset..];
        }
        var slice = try insert_padding(&self.aligned_buffer, current_offset, pad_size, self.allocator);

        return slice[next_offset..];
    }

    fn accum_layers(self: *Packet, current_offset: usize, protocol_layer: LayerProtocols) !void {
        print("aligned buf: {x} len: {}\n", .{ self.aligned_buffer, self.aligned_buffer.len });

        print("current offset: {}\n", .{current_offset});

        var next_layer_type: LayerProtocols = undefined;

        switch (protocol_layer) {
            .LinkLayer => |protocol| switch (protocol) {
                .ETHERNET => {
                    print("Link Layer: ETHERNET (Ethernet)\n", .{});
                    next_layer_type = try Eth.get_next_layer_type(self.aligned_buffer[current_offset..]);
                }, // if linktype is RAW uses Eth.get_next_layer_type to get the IP version
                else => {
                    next_layer_type = LayerProtocols{ .Network = .Generic };
                    return;
                },
            },
            .Network => |protocol| switch (protocol) {
                .ICMP => {
                    print("Transport Layer: ICMP\n", .{});
                    return;
                },
                .IPv4 => {
                    print("Network Layer: IPv4\n", .{});
                    next_layer_type = try IPv4.get_next_layer_type(self.aligned_buffer[current_offset..]);
                },
                .IPv6 => {
                    print("Network Layer: IPv6\n", .{});
                    next_layer_type = try IPv6Layer.get_next_layer_type(self.aligned_buffer[current_offset..]);
                },
                .Generic => {
                    next_layer_type = LayerProtocols{ .Transport = .Generic };
                    print("Network Layer: Generic/Unknown\n", .{});
                    return;
                },
            },
            .Transport => |protocol| switch (protocol) {
                .TCP => {
                    print("Transport Layer: TCP\n", .{});
                    next_layer_type = try TCP.get_next_layer_type(self.aligned_buffer[current_offset..]);
                },
                .UDP => {
                    print("Transport Layer: UDP\n", .{});
                    next_layer_type = try UDP.get_next_layer_type(self.aligned_buffer[current_offset..]);
                },
                .Generic => {
                    print("Transport Layer: Generic/Unknown\n", .{});
                    next_layer_type = LayerProtocols{ .Transport = .Generic };
                    return;
                },
            },
            .Application => |protocol| switch (protocol) {
                .DNS => {
                    print("Application Layer: Generic/Unknown\n", .{});
                    next_layer_type = LayerProtocols{ .Application = .Generic };
                    return;
                },
                .HTTP => {
                    print("Application Layer: Generic/Unknown\n", .{});
                    next_layer_type = LayerProtocols{ .Application = .Generic };
                    return;
                },
                .Generic => {
                    print("Application Layer: Generic/Unknown\n", .{});
                    next_layer_type = LayerProtocols{ .Application = .Generic };
                    return;
                },
            },
        }

        const alignment_size: usize = get_layer_alignment(next_layer_type); // get the alignment size of the layers hdr type
        const current_size = get_layer_size(protocol_layer);
        const current_end = current_offset + current_size;

        const next_offset = get_next_relative_offset(current_end, alignment_size);

        const padding = next_offset - current_end;

        try insert_padding_in_place(&self.aligned_buffer, current_end, padding, self.allocator);

        print("recalling with next offset: {}\n", .{next_offset});

        try self.accum_layers(next_offset, next_layer_type);
    }

    // Layer data[] are getting invalidated on realloc
    fn accumulate_layers(self: *Packet, layer: ?*Layer, current_offset: usize) !void {
        if (layer) |cur| {
            //print("cur layer data: {x}\n", .{cur.get_data()});
            //print("{s}\n", .{cur.to_string(std.heap.page_allocator)});

            print("aligned buffer ptr={*} len={}\n", .{ self.aligned_buffer.ptr, self.aligned_buffer.len });
            print("cur data: {x}\n", .{cur.get_data()});
            const next_protocol_layer = cur.get_next_layer_type();
            // store the sliced buf for the layer init here
            //var layer_buf: []u8 = undefined;
            // store the layer init here

            print("current offset: {}\n", .{current_offset});
            var next_offset = current_offset;

            switch (cur.get_next_layer_type()) {
                .Network => |net| switch (net) {
                    .IPv4 => {
                        print("Adding IPv4 layer:\n", .{});
                        var ipv4_buf = try self.return_padded_buffer(next_protocol_layer, current_offset); // should add a check to determine if realloc is even required
                        print("padded buf len: {}\n", .{ipv4_buf.len});
                        const ipv4_layer = try self.allocator.create(IPv4.IPv4Layer);
                        ipv4_layer.* = try IPv4.IPv4Layer.init(ipv4_buf[0..]);
                        try self.add_layer(ipv4_layer);
                        next_offset = calculate_next_offset(next_offset, IPv4.IPv4Header);
                    },
                    .IPv6 => {
                        print("IPv6\n", .{});
                    },
                    .Generic => {
                        print("Generic network protocol\n", .{});
                    },
                },
                .Transport => |tx| switch (tx) {
                    .UDP => {
                        print("Adding UDP layer:\n", .{});
                        var udp_buf = try self.return_padded_buffer(next_protocol_layer, current_offset);
                        print("padded buf len: {}\n", .{udp_buf.len});
                        const udp_layer = try self.allocator.create(UDP.UDPLayer);
                        udp_layer.* = try UDP.UDPLayer.init(udp_buf[0..]);
                        try self.add_layer(udp_layer);
                        next_offset = calculate_next_offset(next_offset, UDP.UDPHeader);
                    },
                    else => {},
                },
                else => {}, // Ignore other layers
            }

            next_offset += get_layer_size(next_protocol_layer);
            print("next offset: {}\n", .{next_offset});
            if (next_offset > current_offset) {
                if (cur.get_prev_layer()) |prev| {
                    print("prev data: {x}\n", .{prev.get_data()});
                    print("cur layer: {any}\n", .{cur.get_protocol()});
                    print("{*}\n", .{cur.get_data().ptr}); // = self.aligned_buffer;
                    print("prev layer: {any}\n", .{prev.get_protocol()});
                    print("{*}\n", .{prev.get_data().ptr}); // = self.aligned_buffer;
                } else {
                    print("cur layer is first layer: {any}\n", .{cur.get_protocol()});
                    print("{*}\n", .{cur.get_data().ptr}); // = self.aligned_buffer;

                }
            }
            print("cur_layer_if: {any}, self={*}, self.data.ptr={*}, self.data.len={}\n", .{ cur.get_protocol(), cur, cur.get_data().ptr, cur.get_data().len });
            try self.accumulate_layers(cur.get_next_layer(), next_offset);
        }

        // Remember to add the tail layer at the end

        return;
    }

    // Adds a layer to the tail of the layers.
    fn add_layer(self: *Packet, layer: anytype) !void {
        print("adding layer:\n", .{});
        print("add_layer: impl_layer={*}\n", .{layer});
        const new_layer = try self.allocator.create(Layer);
        print("add_layer: interface={*}\n", .{new_layer});

        new_layer.* = Layer.implBy(layer);
        print("add_layer: new_layer_type_ptr={*}, new_layer.data.ptr={*}, new_layer.data.len={}\n", .{ new_layer, new_layer.get_data().ptr, new_layer.get_data().len });

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
        // _ = allocator;

        while (cur) |l| {
            print("{s}\n", .{l.to_string(allocator)});
            print("{any}\n", .{l.get_protocol()});
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
    //    print("hdr size: {} align_size: {}", .{ header_size, alignment_size });
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

fn insert_padding_in_place(buf: *[]u8, offset: usize, len: usize, allocator: std.mem.Allocator) !void {
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

    // Fill the padding area with 'X' (changed from 0 to 'X' to match comment)
    @memset(padded_slice[offset .. offset + len], 0);

    // Update the original slice pointer
    buf.* = padded_slice;
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
            else => {
                return 2;
            },
        },

        else => return 2,
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
