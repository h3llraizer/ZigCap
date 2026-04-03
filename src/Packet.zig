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

const LayerImpl = @import("ProtocolHelpers.zig").LayerImpl;

const Eth = @import("Eth.zig");
const IPv4 = @import("IPv4.zig");
const IPv6Layer = @import("IPv6.zig");
const UDP = @import("UDPLayer.zig");
const TCP = @import("TCP.zig");

const GenericLayer = @import("GenericLayer.zig").GenericLayer;

const EthLayer = Eth.EthLayer;

const LayerOwner = @import("Layer.zig").LayerOwner;

const get_layer_size = @import("ProtocolHelpers.zig").get_layer_size;
const get_layer_type_enum = @import("ProtocolHelpers.zig").get_layer_type_enum;
const get_layer_alignment = @import("ProtocolHelpers.zig").get_layer_alignment;
const get_layer_init = @import("ProtocolHelpers.zig").get_layer_init;
const get_layer_to_string = @import("ProtocolHelpers.zig").get_layer_to_string;
const comparePayloads = @import("ProtocolHelpers.zig").comparePayloads;

const compare_impl = @import("ProtocolHelpers.zig").compare_impl;

pub const Layer = struct {
    layer_impl: LayerImpl,
    offset: usize, // hdr start
    length: usize,
    packet: *Packet,
    next_layer: ?*Layer = null,
    prev_layer: ?*Layer = null,

    pub fn init(layer_impl: LayerImpl, offset: usize, length: usize, packet: *Packet) Layer {
        return Layer{ .layer_impl = layer_impl, .offset = offset, .length = length, .packet = packet, .next_layer = null, .prev_layer = null };
    }

    pub fn to_string(self: *Layer, allocator: Allocator) void {
        print("layer struct to string: \n", .{});
        print("{s}\n", .{self.layer_impl.to_string(allocator)});
    }
};

/// if data is owned by Packet it has to be mutable. if it is owned by WirePacket, it can be mutable or immutable
pub const Packet = struct {
    allocator: Allocator,
    aligned_buffer: []u8, // this buffer is aligned - NOT wire format. don't send it over the network
    first_layer: ?*Layer,
    free_buffer: bool = false,

    /// Creates an empty Packet - alloc's zero bytes to aligned buffer initially
    pub fn create(allocator: Allocator) !Packet {
        return Packet{
            .allocator = allocator,
            .aligned_buffer = try allocator.alloc(u8, 0),
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

    pub fn add_layer(self: *Packet, layer_impl: *LayerImpl) !bool {
        const data = layer_impl.get_data();

        const layer: *Layer = try self.allocator.create(Layer); // create the layer (part of the linked list)
        layer.* = Layer.init(layer_impl.*, 0, data.len, self); // deref and set the values

        try layer.layer_impl.reinit(LayerOwner{ .packet_layer = layer });

        const last_layer: ?*Layer = try self.get_last_layer();

        if (last_layer) |last| {
            last.next_layer = layer;
            layer.prev_layer = last;
            layer.offset = (last.offset + last.length);
        } else {
            self.first_layer = layer;
        }

        const current_buf_len: usize = self.aligned_buffer.len;

        const new_buf: []u8 = try self.allocator.realloc(self.aligned_buffer, current_buf_len + data.len);

        const dest = new_buf[current_buf_len..];

        @memmove(dest, data);

        self.aligned_buffer = new_buf[0..];

        return true;
    }

    /// used by layers to find their data
    pub fn find_layer_ptr(self: *Packet, layer_ptr: *anyopaque) ?[]u8 {
        var cur = self.first_layer;

        while (cur) |layer| {
            if (layer.layer_impl.ptr() == layer_ptr) {
                return self.aligned_buffer[layer.offset..];
            }

            cur = layer.next_layer;
        }
        return null;
    }

    pub fn to_string(self: *Packet, allocator: Allocator) !void {
        var cur = self.first_layer;
        while (cur) |layer| {
            print("{s}\n", .{layer.layer_impl.to_string(allocator)});
            cur = layer.next_layer;
        }
    }

    pub fn print_ptrs(self: *Packet) void {
        var cur = self.first_layer;
        while (cur) |layer| {
            print("impl: {*}\n", .{layer.layer_impl.ptr()});
            cur = layer.next_layer;
        }
    }

    pub fn get_layer_of_type(self: *Packet, layer_type: anytype) ?*layer_type {
        const layer_type_enum = get_layer_type_enum(layer_type) catch {
            return null;
        };

        const layer: ?*Layer = self.search_layers(layer_type_enum) catch {
            return null;
        };

        if (layer) |b| {
            return @as(*layer_type, @ptrCast(@alignCast(b.layer_impl.ptr())));
        }

        return null;
    }

    fn search_layers(self: *Packet, target: LayerProtocols) !?*Layer {
        var cur = self.first_layer;
        while (cur) |layer| {
            if (comparePayloads(try layer.layer_impl.get_protocol(), target)) {
                return layer;
            }
            cur = layer.next_layer;
        }

        return null;
    }

    fn create_layer(self: *Packet, layer_impl: *LayerImpl) !*Layer {
        const data = layer_impl.get_data();

        const layer: *Layer = try self.allocator.create(Layer); // create the layer (part of the linked list)
        layer.* = Layer.init(layer_impl.*, 0, data.len, self); // deref and set the values

        //try layer.layer_impl.reinit(LayerOwner{ .packet_layer = layer });

        return layer;
    }

    pub fn insert_layer(self: *Packet, prev_layer: ?*anyopaque, layer_to_insert: *LayerImpl) !bool {
        if (prev_layer) |prev| {
            var cur = self.first_layer;

            while (cur) |layer| {
                if (layer.layer_impl.ptr() == prev) {
                    print("found prev layer: {any}, offset: {} length: {}\n", .{ layer.layer_impl.get_protocol(), layer.offset, layer.length });

                    const new_layer: *Layer = try self.create_layer(layer_to_insert);

                    print("{x}\n", .{new_layer.layer_impl.get_data()});

                    new_layer.prev_layer = layer;
                    new_layer.next_layer = layer.next_layer;

                    // Calculate the correct offset for the new layer
                    new_layer.offset = layer.offset + layer.length;

                    // Update the previous layer's next pointer
                    layer.next_layer = new_layer;

                    // Update the next layer's prev pointer if it exists
                    if (new_layer.next_layer) |next| {
                        next.prev_layer = new_layer;
                        // Update subsequent layers' offsets using a simple loop
                        var current: ?*Layer = next;
                        while (current) |n| {
                            n.offset += new_layer.length; // Add new layer's header size
                            current = n.next_layer;
                        }
                    }

                    // Update the packet buffer
                    const current_buf_len: usize = self.aligned_buffer.len;
                    const insert_offset = new_layer.offset;

                    // Reallocate buffer to make room for new layer
                    const new_buf: []u8 = try self.allocator.realloc(self.aligned_buffer, current_buf_len + new_layer.length);
                    self.aligned_buffer = new_buf;

                    // Shift data after insertion point to the right
                    const data_to_shift = new_buf[insert_offset..current_buf_len];
                    const shifted_start = insert_offset + new_layer.length;
                    @memmove(new_buf[shifted_start..], data_to_shift);

                    // Copy the new layer's data into the space
                    const dest = new_buf[insert_offset..][0..new_layer.length];
                    @memcpy(dest, new_layer.layer_impl.get_data());

                    try new_layer.layer_impl.reinit(LayerOwner{ .packet_layer = new_layer });

                    return true;
                }
                cur = layer.next_layer;
            }
        } else {
            return self.add_layer(layer_to_insert);
        }
        return false;
    }

    fn remove_layer(self: *Packet, layer_type: anytype) !?*Layer {
        const layer_type_enum = get_layer_type_enum(layer_type) catch |err| {
            print("error deleting layer: {s}\n", .{@errorName(err)});
            return null;
        };

        const layer = try self.search_layers(layer_type_enum) orelse {
            return null;
        };

        var delete_start: usize = 0;
        if (layer.prev_layer) |prev| {
            print("prev layer len: {}\n", .{prev.length});
            delete_start = prev.length;
            prev.next_layer = layer.next_layer;
        }

        var padding: usize = 0;
        if (delete_start > 0) {
            padding = layer.offset % delete_start;
        }

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
            print("next: offset={} length={}\n", .{ next.offset, next.length });
            next.offset -= delete_buf.len;
            print("updated offset: {}\n", .{next.offset});
            cur = next.next_layer;
        }

        return layer;
    }

    pub fn delete_layer(self: *Packet, layer_type: anytype) !bool {
        const layer = try self.remove_layer(layer_type) orelse {
            return false;
        };

        self.allocator.destroy(layer);

        return true;
    }

    pub fn extract_layer(self: *Packet, layer_type: anytype, owner: *LayerOwner) !?LayerImpl {
        const layer: *Layer = try self.move_layer(layer_type, owner) orelse {
            return null;
        };

        try layer.layer_impl.reinit(owner.*);

        const return_layer = layer.layer_impl;

        self.allocator.destroy(layer);

        return return_layer;
    }

    //
    fn move_layer(self: *Packet, layer_type: anytype, owner: *LayerOwner) !?*Layer {
        const layer_type_enum = get_layer_type_enum(layer_type) catch |err| {
            print("error deleting layer: {s}\n", .{@errorName(err)});
            return null;
        };

        const layer = try self.search_layers(layer_type_enum) orelse {
            return null;
        };

        //const init_buf: []u8 = try owner.allocator_owned.allocator.alloc(u8, layer.length);

        var delete_start: usize = 0;
        if (layer.prev_layer) |prev| {
            print("prev layer len: {}\n", .{prev.length});
            delete_start = prev.length;
            prev.next_layer = layer.next_layer;
        } else {
            print("no prev layer.\n", .{});
        }

        var padding: usize = 0;

        if (delete_start > 0) {
            padding = layer.offset % delete_start;
        }

        const delete_buf = self.aligned_buffer[(layer.offset - padding) .. layer.offset + layer.length];

        const remaining_buf = self.aligned_buffer[delete_start + delete_buf.len ..];

        const dest = self.aligned_buffer[delete_start .. delete_start + remaining_buf.len];

        try owner.allocator_owned.copy_from(delete_buf[padding..]);

        @memmove(dest, remaining_buf);

        const new_len = delete_start + remaining_buf.len;
        self.aligned_buffer = self.aligned_buffer[0..new_len];

        var cur = layer.next_layer;
        while (cur) |next| {
            next.offset -= delete_buf.len;
            cur = next.next_layer;
        }

        return layer;
    }

    //
    //   fn extend_layer(self: *Packet, layer: *Layer, len: usize) !void {
    //       var cur = self.first_layer;
    //       while (cur) |l| {
    //           if (l == layer) {
    //               l.length += len;
    //               var next = l.next_layer;
    //               while (next) |n| {
    //                   n.offset += len;
    //                   n.length += len;
    //                   next = n.next_layer;
    //               }
    //           }
    //           cur = l.next_layer;
    //       }
    //   }
    //
    //   fn shorten_layer(self: *Packet, layer: *Layer, len: usize) !void {
    //       var cur = self.first_layer;
    //       while (cur) |l| {
    //           if (l == layer) {
    //               l.length -= len;
    //               var next = l.next_layer;
    //               while (next) |n| {
    //                   n.offset -= len;
    //                   n.length -= len;
    //                   next = n.next_layer;
    //               }
    //           }
    //           cur = l.next_layer;
    //       }
    //   }
    //
    //   pub fn find_layer(self: *Packet, protocol_layer: LayerProtocols) ?[]u8 {
    //       const layer: ?*Layer = self.search_layers(protocol_layer) catch {
    //           return null;
    //       };
    //       if (layer) |l| {
    //           return self.aligned_buffer[l.offset..];
    //       }
    //       return null;
    //   }
    //
    //   pub fn to_string(self: *Packet) !void {
    //       var cur = self.first_layer;
    //       while (cur) |layer| {
    //           const to_string_method = try get_layer_to_string(layer.protocol);
    //           _ = to_string_method;
    //           cur = layer.next_layer;
    //       }
    //   }
    //
    //   pub fn print_layers(self: *Packet) void {
    //       var cur = self.first_layer;
    //       while (cur) |layer| {
    //           //const slice = self.aligned_buffer[layer.offset..(layer.offset + layer.length)];
    //           const slice = self.aligned_buffer[layer.offset..];
    //
    //           print("{any}, {}, {}: {x} ({})\n", .{ layer.protocol, layer.offset, layer.length, slice, slice.len });
    //           cur = layer.next_layer;
    //       }
    //   }
    //
    pub fn print_layers_meta(self: *Packet) void {
        var cur = self.first_layer;
        while (cur) |layer| {
            print("{any}, {}, {}, buf-pos={}\n", .{ layer.layer_impl.get_protocol(), layer.offset, layer.length, layer.offset + layer.length });
            cur = layer.next_layer;
        }
    }

    //   fn accum_layers(self: *Packet, layer: *Layer) !void {
    //       var next_layer: Layer = undefined;
    //
    //       const current_slice = self.aligned_buffer[layer.offset..];
    //
    //       print("current slice: {x}\n", .{current_slice});
    //
    //       const get_next = ProtocolHelpers.get_next_layer_type(layer.protocol) orelse {
    //           print("no init method.\n", .{});
    //           return;
    //       };
    //
    //       next_layer = get_next(current_slice[0..]) catch |err| {
    //           print("{s}\n", .{@errorName(err)});
    //           return;
    //       };
    //
    //       if (next_layer.length == 0) {
    //           return;
    //       }
    //
    //       next_layer.offset += layer.offset;
    //
    //       layer.to_string();
    //
    //       next_layer.to_string();
    //
    //       const next_layer_ = try self.allocator.create(Layer);
    //
    //       next_layer_.* = next_layer;
    //
    //       layer.next_layer = next_layer_;
    //
    //       next_layer_.prev_layer = layer;
    //
    //       try self.accum_layers(next_layer_);
    //   }
    //
    //   /// destroys protocol layers linkedlist. The buffer is not freed.
    //   pub fn deinit(self: *Packet) void {
    //       var cur = self.first_layer;
    //
    //       while (cur) |layer| {
    //           const next = layer.next_layer;
    //           print("destroying: {any}\n", .{layer.protocol});
    //           self.allocator.destroy(layer);
    //           cur = next;
    //       }
    //   }
};
