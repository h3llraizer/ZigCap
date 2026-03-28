const std = @import("std");
const print = std.debug.print;
const activeTag = std.meta.activeTag;
const Allocator = std.mem.Allocator;

const WirePacket = @import("WirePacket.zig").WirePacket;
const LayerProtocols = @import("ProtocolHelpers.zig").LayerProtocols;

const LinkLayerProtocols = @import("ProtocolHelpers.zig").LinkLayerProtocols;
const NetworkProtocols = @import("ProtocolHelpers.zig").NetworkProtocols;

const Eth = @import("Eth.zig");
const IPv4 = @import("IPv4.zig");
const IPv6Layer = @import("IPv6.zig");
const UDP = @import("UDPLayer.zig");
const TCP = @import("TCP.zig");

const GenericLayer = @import("GenericLayer.zig").GenericLayer;

const EthLayer = Eth.EthLayer;

const get_layer_size = @import("ProtocolHelpers.zig").get_layer_size;
const get_layer_type_enum = @import("ProtocolHelpers.zig").get_layer_type_enum;
const get_layer_alignment = @import("ProtocolHelpers.zig").get_layer_alignment;
const get_layer_init = @import("ProtocolHelpers.zig").get_layer_init;
const get_layer_to_string = @import("ProtocolHelpers.zig").get_layer_to_string;
const comparePayloads = @import("ProtocolHelpers.zig").comparePayloads;

pub fn alignment_check(buffer: []u8, alignment: usize) usize {
    const addr = @intFromPtr(buffer.ptr);

    return addr % alignment;
}

pub const Layer = struct {
    protocol: LayerProtocols,
    offset: usize,
    length: usize,
    next_layer: ?*Layer,

    pub fn init(protocol: LayerProtocols, offset: usize, length: usize) Layer {
        print("layer init called: {any} offset={} length={}\n", .{ protocol, offset, length });
        return Layer{ .protocol = protocol, .offset = offset, .length = length, .next_layer = null };
    }
};

pub const Packet = struct {
    allocator: Allocator,
    aligned_buffer: []u8, // this buffer is aligned - NOT wire format. don't send it over the network
    link_layer: LinkLayerProtocols,
    first_layer: ?*Layer,

    /// Creates an empty Packet - alloc's zero bytes to aligned buffer initially
    pub fn create(allocator: Allocator, link_layer: LinkLayerProtocols) !Packet {
        return Packet{
            .allocator = allocator,
            .aligned_buffer = try allocator.alloc(u8, 0),
            .link_layer = link_layer,
            .first_layer = null,
        };
    }

    /// Creates a Packet from an existing wire packet. The buffer needs to be mutable so padding can be inserted
    /// if required and the alllocator used to allocate the buffer needs to be passed for potentail realloc.
    pub fn from_wire_packet(self: *Packet, wire_packet: *WirePacket) !void { // may ditch the wire packet and just use slices
        self.aligned_buffer = wire_packet.raw_data;
        self.first_layer = try self.allocator.create(Layer);
        self.first_layer.?.* = Layer.init(LayerProtocols{ .LinkLayer = wire_packet.link_type }, 0, Eth.EthHeaderSize);
        try self.accum_layers(self.first_layer.?);
    }

    /// Creates new layer in the Packet. Specify the layer (e.g. EthLayer, IPv4Layer etc), and the layer will be returned with it's memory allocated in the aligned_buffer. You must free the layer returned when done with it. The underlying bytes representing the layer are preserved in the aligned buffer
    //   pub fn create_new_layer(self: *Packet, layer_type: type) !*layer_type {
    //       const protocol_enum = try get_layer_type_enum(layer_type);
    //
    //       const hdr_size: usize = get_layer_size(protocol_enum); // get the size of the layers hdr type
    //       const alignment_size: usize = get_layer_alignment(protocol_enum); // get the alignment size of the layers hdr type
    //
    //       const current_offset = self.aligned_buffer.len;
    //       const next_offset = get_next_relative_offset(current_offset, alignment_size);
    //
    //       var new_buffer = try self.allocator.realloc(self.aligned_buffer, next_offset + hdr_size);
    //       self.aligned_buffer = new_buffer;
    //       @memset(new_buffer[current_offset..], 0); // zero the pad bytes
    //
    //       const impl_init = try get_layer_init(layer_type);
    //
    //       const impl_layer: *layer_type = try self.allocator.create(layer_type);
    //
    //       impl_layer.* = try impl_init(new_buffer[next_offset..]);
    //
    //       try self.add_layer(impl_layer);
    //
    //       return impl_layer;
    //   }

    pub fn get_layer_of_type(self: *Packet, layer_type: anytype) !?layer_type {
        const layer_type_enum = try get_layer_type_enum(layer_type);

        const layer_init = try get_layer_init(layer_type);

        const buf = try self.find_layer(layer_type_enum);

        if (buf) |b| {
            return try layer_init(b);
        }

        return null;
    }

    fn find_layer(self: *Packet, protocol_layer: LayerProtocols) !?[]u8 {
        const layer: ?*Layer = try self.search_layers(protocol_layer);
        if (layer) |l| {
            return self.aligned_buffer[l.offset .. l.offset + l.length];
        }
        return null;
    }

    /// this doesn't work completely yet. It doesn't match on payload
    fn search_layers(self: *Packet, target: LayerProtocols) !?*Layer {
        var cur = self.first_layer;
        while (cur) |layer| {
            if (comparePayloads(layer.protocol, target)) {
                print("{s}\n", .{@tagName(activeTag(layer.protocol))});
                return layer;
            }
            print("{any}, {}, {}\n", .{ layer.protocol, layer.offset, layer.length });
            cur = layer.next_layer;
        }

        return null;
    }

    pub fn detach_layer(self: *Packet, layer_type: anytype, allocator: Allocator) !?layer_type {
        const layer_type_enum = try get_layer_type_enum(layer_type);

        const layer_init = try get_layer_init(layer_type);

        var init_buf: []u8 = undefined;

        const buf = try self.find_layer(layer_type_enum);

        if (buf) |b| {
            // Compute the offset of the layer in the buffer
            const start = b.ptr - self.aligned_buffer.ptr;
            const size = get_layer_size(layer_type_enum);
            const end = start + (calculate_padding(start, layer_type)); // calculate padding from start

            init_buf = try allocator.alloc(u8, size);

            // Move bytes into the init buffer
            @memmove(init_buf[0..size], // destination
            self.aligned_buffer[end..(end + size)] // source
            );

            const remaining_start = end + size; // where the rest of the bytes after the removed layer ends

            const remaining_bytes_len = self.aligned_buffer[remaining_start..].len;
            @memmove(
                self.aligned_buffer[start .. start + remaining_bytes_len],
                self.aligned_buffer[remaining_start..],
            );

            const new_len = start + remaining_bytes_len;
            self.aligned_buffer = self.aligned_buffer[0..new_len];

            return try layer_init(init_buf);
        }

        return null;
    }

    /// Warning: removing a layer in between two layers will result in invalidating layer chain
    /// Consider swapping the layer
    pub fn remove_layer_of_type(self: *Packet, layer_type: anytype) !bool {
        const layer_type_enum = try get_layer_type_enum(layer_type);

        const buf = try self.find_layer(layer_type_enum);
        if (buf) |b| {
            // Compute the offset of the layer in the buffer
            const start = b.ptr - self.aligned_buffer.ptr;
            const size = get_layer_size(layer_type_enum);
            const end = start + (calculate_padding(start, layer_type)); // calculate padding from start

            const remaining_start = end + size; // where the rest of the bytes after the removed layer ends

            const remaining_bytes_len = self.aligned_buffer[remaining_start..].len;
            @memmove(
                self.aligned_buffer[start .. start + remaining_bytes_len],
                self.aligned_buffer[remaining_start..],
            );

            const new_len = start + remaining_bytes_len;
            self.aligned_buffer = self.aligned_buffer[0..new_len];

            return true;
        }

        print("layer not found.\n", .{});
        return false;
    }

    pub fn to_string(self: *Packet) !void {
        var cur = self.first_layer;
        while (cur) |layer| {
            const to_string_method = try get_layer_to_string(layer.protocol);
            _ = to_string_method;
            cur = layer.next_layer;
        }
    }

    pub fn print_layers(self: *Packet) void {
        var cur = self.first_layer;
        while (cur) |layer| {
            print("{any}, {}, {}\n", .{ layer.protocol, layer.offset, layer.length });
            cur = layer.next_layer;
        }
    }

    fn accum_layers(self: *Packet, layer: *Layer) !void {
        var next_layer_type: LayerProtocols = undefined;

        switch (layer.protocol) {
            .LinkLayer => |protocol| switch (protocol) {
                .ETHERNET => {
                    next_layer_type = try Eth.get_next_layer_type(self.aligned_buffer[layer.offset..]);
                },
                else => {
                    next_layer_type = LayerProtocols{ .Network = .Generic };
                    return;
                },
            },
            .Network => |protocol| switch (protocol) {
                .ICMP => {
                    return;
                },
                .IPv4 => {
                    next_layer_type = try IPv4.get_next_layer_type(self.aligned_buffer[layer.offset..]);
                },
                .IPv6 => {
                    next_layer_type = try IPv6Layer.get_next_layer_type(self.aligned_buffer[layer.offset..]);
                },
                .Generic => {
                    next_layer_type = LayerProtocols{ .Transport = .Generic };
                    return;
                },
            },
            .Transport => |protocol| switch (protocol) {
                .TCP => {
                    next_layer_type = try TCP.get_next_layer_type(self.aligned_buffer[layer.offset..]);
                },
                .UDP => {
                    next_layer_type = try UDP.get_next_layer_type(self.aligned_buffer[layer.offset..]);
                },
                .Generic => {
                    next_layer_type = LayerProtocols{ .Transport = .Generic };
                    return;
                },
            },
            .Application => |protocol| switch (protocol) {
                .DNS => {
                    next_layer_type = LayerProtocols{ .Application = .Generic };
                    return;
                },
                .HTTP => {
                    next_layer_type = LayerProtocols{ .Application = .Generic };
                    return;
                },
                .Generic => {
                    next_layer_type = LayerProtocols{ .Application = .Generic };
                    return;
                },
            },
        }

        const alignment_size: usize = get_layer_alignment(next_layer_type); // get the alignment size of the layers hdr type
        const current_size = get_layer_size(layer.protocol);
        const current_end = layer.offset + current_size;

        const next_offset = get_next_relative_offset(current_end, alignment_size);

        const padding = next_offset - current_end;

        try insert_padding_in_place(&self.aligned_buffer, current_end, padding, self.allocator);

        const next_layer = try self.allocator.create(Layer);

        next_layer.* = Layer.init(next_layer_type, next_offset, get_layer_size(next_layer_type));

        layer.next_layer = next_layer;

        try self.accum_layers(next_layer);
    }

    // Adds a layer to the tail of the layers.
    //  fn add_layer(self: *Packet, layer: anytype) !void {
    //      print("adding layer:\n", .{});
    //      print("add_layer: impl_layer={*}\n", .{layer});
    //      const new_layer = try self.allocator.create(Layer);
    //      print("add_layer: interface={*}\n", .{new_layer});

    //      new_layer.* = Layer.implBy(layer);
    //      print("add_layer: new_layer_type_ptr={*}, new_layer.data.ptr={*}, new_layer.data.len={}\n", .{ new_layer, new_layer.get_data().ptr, new_layer.get_data().len });

    //      if (self.first_layer == null) {
    //          self.first_layer = new_layer;
    //          print("added first layer.\n", .{});
    //          return;
    //      }

    //      var cur = self.first_layer;

    //      while (cur) |current_layer| {
    //          if (current_layer.next_layer == null) {
    //              current_layer.set_next_layer(new_layer);
    //              if (current_layer.next_layer) |next_layer| {
    //                  next_layer.set_prev_layer(current_layer);
    //                  self.last_layer = current_layer.next_layer;
    //              }
    //              break;
    //          }
    //          cur = current_layer.next_layer;
    //      }
    //  }

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

    /// destroys interface layers from last to first
    pub fn deinit(self: *Packet) void {
        _ = self;
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
