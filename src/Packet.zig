const std = @import("std");
const print = std.debug.print;
const activeTag = std.meta.activeTag;
const Allocator = std.mem.Allocator;

const WirePacket = @import("WirePacket.zig").WirePacket;
const ProtocolHelpers = @import("ProtocolHelpers.zig");

const LayerProtocols = ProtocolHelpers.LayerProtocols;
const LayerError = @import("ProtocolHelpers.zig").LayerError;

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
    next_layer: ?*Layer = null,
    prev_layer: ?*Layer = null,

    pub fn init(protocol: LayerProtocols, offset: usize, length: usize) Layer {
        //print("layer init called: {any} offset={} length={}\n", .{ protocol, offset, length });
        return Layer{ .protocol = protocol, .offset = offset, .length = length, .next_layer = null, .prev_layer = null };
    }

    pub fn to_string(self: *Layer) void {
        print("{any}, offset={}, length={}\n", .{ self.protocol, self.offset, self.length });
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

    /// Creates a Packet from an existing wire packet. Padding might be inserted and the alllocator used to allocate the buffer needs to be passed for potentail realloc.
    pub fn from_wire_packet(self: *Packet, wire_packet: *WirePacket) !void { // may ditch the wire packet and just use slices
        self.aligned_buffer = wire_packet.raw_data;
        self.first_layer = try self.allocator.create(Layer);
        self.first_layer.?.* = Layer.init(LayerProtocols{ .LinkLayer = wire_packet.link_type }, 0, Eth.EthHeaderSize);
        try self.accum_layers(self.first_layer.?);
    }

    fn get_last_layer(self: *Packet) !?*Layer {
        var cur = self.first_layer;

        while (cur) |layer| {
            if (layer.next_layer == null) {
                return layer;
            }

            cur = layer.next_layer;
        }

        return null;
    }

    pub fn add_layer(self: *Packet, layer_type: anytype, layer_data: []u8) !bool {
        const layer_type_enum = get_layer_type_enum(layer_type) catch |err| {
            print("error deleting layer: {s}\n", .{@errorName(err)});
            return false;
        };

        const layer_init = try get_layer_init(layer_type);

        _ = try layer_init(layer_data); // confirms the data provided is valid

        //TODO: Ideally add more validation - the layer data might contain preceeding layers data  - renaming to merge layer chain might be preferred

        const last_layer = try self.get_last_layer();

        const layer = try self.allocator.create(Layer);
        layer.* = Layer.init(layer_type_enum, 0, layer_data.len);

        if (last_layer) |last| {
            last.next_layer = layer;
            layer.offset = (last.offset + last.length);
        } else {
            self.first_layer.? = layer;
        }

        const current_buf_len = self.aligned_buffer.len;

        const new_buf = try self.allocator.realloc(self.aligned_buffer, current_buf_len + layer_data.len);

        const dest = new_buf[current_buf_len..];

        @memmove(dest, layer_data);

        self.aligned_buffer = new_buf[0..];

        _ = try layer_init(dest[0..20]); // confirms the data provided is valid
        //print("{s}\n", .{n.to_string(std.heap.page_allocator)});

        return true;
    }

    pub fn delete_layer(self: *Packet, layer_type: anytype) !bool {
        const layer_type_enum = get_layer_type_enum(layer_type) catch |err| {
            print("error deleting layer: {s}\n", .{@errorName(err)});
            return false;
        };

        const layer = try self.search_layers(layer_type_enum) orelse {
            return false;
        };

        var delete_start: usize = 0;
        if (layer.prev_layer) |prev| {
            print("prev layer len: {}\n", .{prev.length});
            delete_start = prev.length;
            prev.next_layer = layer.next_layer;
        }

        const padding = layer.offset % delete_start;

        print("padding: {}\n", .{padding});

        const delete_buf = self.aligned_buffer[(layer.offset - padding) .. layer.offset + layer.length];
        print("deletion buffer: {x} ({})\n", .{ delete_buf, delete_buf.len });

        const remaining_buf = self.aligned_buffer[delete_start + delete_buf.len ..];
        print("remaining buf: {x} ({})\n", .{ remaining_buf, remaining_buf.len });

        const dest = self.aligned_buffer[delete_start .. delete_start + remaining_buf.len];

        print("dest: {x} ({})\n", .{ dest, dest.len });

        @memmove(dest, remaining_buf);

        const new_len = delete_start + remaining_buf.len;
        self.aligned_buffer = self.aligned_buffer[0..new_len];

        var cur = layer.next_layer;
        while (cur) |next| {
            print("next: {any}: offset={} length={}\n", .{ next.protocol, next.offset, next.length });
            next.offset -= delete_buf.len;
            print("updated offset: {}\n", .{next.offset});
            cur = next.next_layer;
        }

        self.allocator.destroy(layer);

        return true;
    }

    pub fn extract_layer(self: *Packet, layer_type: anytype, allocator: Allocator) !?layer_type {
        const layer_type_enum = get_layer_type_enum(layer_type) catch |err| {
            print("error deleting layer: {s}\n", .{@errorName(err)});
            return null;
        };

        const layer = try self.search_layers(layer_type_enum) orelse {
            return null;
        };

        const layer_init = try get_layer_init(layer_type);

        var init_buf: []u8 = undefined;

        var delete_start: usize = 0;
        if (layer.prev_layer) |prev| {
            print("prev layer len: {}\n", .{prev.length});
            delete_start = prev.length;
            prev.next_layer = layer.next_layer;
        }

        const padding = layer.offset % delete_start;

        print("padding: {}\n", .{padding});

        const delete_buf = self.aligned_buffer[(layer.offset - padding) .. layer.offset + layer.length];
        print("deletion buffer: {x} ({})\n", .{ delete_buf, delete_buf.len });

        const remaining_buf = self.aligned_buffer[delete_start + delete_buf.len ..];
        print("remaining buf: {x} ({})\n", .{ remaining_buf, remaining_buf.len });

        const dest = self.aligned_buffer[delete_start .. delete_start + remaining_buf.len];

        print("dest: {x} ({})\n", .{ dest, dest.len });

        init_buf = try allocator.alloc(u8, delete_buf.len - padding);

        print("init buf len: {}\n", .{init_buf.len});

        print("dest buf len: {}\n", .{dest[padding..].len});

        @memmove(init_buf, delete_buf[padding..]);

        @memmove(dest, remaining_buf);

        const new_len = delete_start + remaining_buf.len;
        self.aligned_buffer = self.aligned_buffer[0..new_len];

        var cur = layer.next_layer;
        while (cur) |next| {
            print("next: {any}: offset={} length={}\n", .{ next.protocol, next.offset, next.length });
            next.offset -= delete_buf.len;
            print("updated offset: {}\n", .{next.offset});
            cur = next.next_layer;
        }

        self.allocator.destroy(layer);

        return try layer_init(init_buf);
    }

    fn search_layers(self: *Packet, target: LayerProtocols) !?*Layer {
        var cur = self.first_layer;
        while (cur) |layer| {
            if (comparePayloads(layer.protocol, target)) {
                print("{s}\n", .{@tagName(activeTag(layer.protocol))});
                return layer;
            }
            cur = layer.next_layer;
        }

        return null;
    }

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
            const slice = self.aligned_buffer[layer.offset..(layer.offset + layer.length)];
            print("{any}, {}, {}: {x} ({})\n", .{ layer.protocol, layer.offset, layer.length, slice, slice.len });
            cur = layer.next_layer;
        }
    }

    pub fn print_layers_meta(self: *Packet) void {
        var cur = self.first_layer;
        while (cur) |layer| {
            print("{any}, {}, {}, buf-pos={}\n", .{ layer.protocol, layer.offset, layer.length, layer.offset + layer.length });
            cur = layer.next_layer;
        }
    }

    fn accum_layers(self: *Packet, layer: *Layer) !void {
        var next_layer: Layer = undefined;

        const current_slice = self.aligned_buffer[layer.offset..];

        print("current slice: {x}\n", .{current_slice});

        const get_next = ProtocolHelpers.get_next_layer_type(layer.protocol) orelse {
            print("no init method.\n", .{});
            return;
        };

        next_layer = get_next(current_slice[0..]) catch |err| {
            print("{s}\n", .{@errorName(err)});
            return;
        };

        if (next_layer.length == 0) {
            return;
        }

        next_layer.offset += layer.offset;

        layer.to_string();

        next_layer.to_string();

        const alignment = get_layer_alignment(next_layer.protocol); // next layers alignment requirement
        const padding = alignment_check(current_slice[layer.length..], alignment);

        //        print("padding: {}\n", .{padding});

        if (padding > 0) {
            try insert_padding_in_place(&self.aligned_buffer, layer.length, padding, self.allocator);
            next_layer.offset += padding;
        }

        //        print("next_layer offset: {}\n", .{next_layer.offset});

        const next_layer_ = try self.allocator.create(Layer);

        next_layer_.* = next_layer;

        layer.next_layer = next_layer_;

        try self.accum_layers(next_layer_);
    }

    /// returns true if the packet buffer can be sent over the network. Useful if you just want to send an already wire capable buffer without calling get_wire_format
    pub fn wire_ready(self: *Packet) bool {
        _ = self;
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

    /// destroys interface layers from first to last. It DOES NOT free the buffer - you need to free the buffer
    pub fn deinit(self: *Packet) void {
        var cur = self.first_layer;

        while (cur) |layer| {
            const next = layer.next_layer;
            print("destroying: {any}\n", .{layer.protocol});
            self.allocator.destroy(layer);
            cur = next;
        }
    }
};

pub fn get_next_relative_offset(header_size: usize, alignment_size: usize) usize {
    //    print("hdr size: {} align_size: {}", .{ header_size, alignment_size });
    const aligned_header_size = (header_size + alignment_size - 1) / alignment_size * alignment_size;
    //    print("Current offset: {}, alignment: {}, next offset: {}\n", .{ header_size, alignment_size, aligned_header_size });
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
