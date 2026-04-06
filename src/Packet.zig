const std = @import("std");
const print = std.debug.print;
const activeTag = std.meta.activeTag;
const Allocator = std.mem.Allocator;
const panic = std.debug.panic;

const ProtocolHelpers = @import("ProtocolHelpers.zig");
const LayerProtocols = ProtocolHelpers.LayerProtocols;
const LayerError = @import("ProtocolHelpers.zig").LayerError;
const LinkLayerProtocols = @import("ProtocolHelpers.zig").LinkLayerProtocols;
const NetworkProtocols = @import("ProtocolHelpers.zig").NetworkProtocols;
const LayerImpl = @import("ProtocolHelpers.zig").LayerImpl;
const Eth = @import("Eth.zig");
const EthLayer = Eth.EthLayer;
const LayerOwner = @import("Layer.zig").LayerOwner;
const get_layer_type_enum = @import("ProtocolHelpers.zig").get_layer_type_enum;
const comparePayloads = @import("ProtocolHelpers.zig").comparePayloads;
const compare_impl = @import("ProtocolHelpers.zig").compare_impl;

const RawData = @import("RawData.zig").RawData;

pub const Layer = struct {
    layer_impl: LayerImpl,
    offset: usize, // hdr start
    length: usize,
    packet: *Packet,
    next_layer: ?*Layer = null,
    prev_layer: ?*Layer = null,

    pub fn init(layer_impl: LayerImpl, offset: usize, length: usize, packet: *Packet) Layer {
        return Layer{ .layer_impl = layer_impl, .offset = offset, .length = length, .packet = packet };
    }

    pub fn get_data(self: *Layer) RawData {
        return self.packet.raw_data.get_slice_from_offset(self.offset);
    }

    pub fn to_string(self: *Layer, allocator: Allocator) void {
        print("{s}\n", .{self.layer_impl.to_string(allocator)});
    }
};

/// if data is owned by Packet it has to be mutable. if it is owned by WirePacket, it can be mutable or immutable
pub const Packet = struct {
    allocator: Allocator,
    raw_data: RawData, // this buffer is aligned - NOT wire format. don't send it over the network
    first_layer: ?*Layer,

    /// Creates an empty Packet - alloc's zero bytes to aligned buffer initially
    pub fn create(allocator: Allocator) !Packet {
        return Packet{
            .allocator = allocator,
            .raw_data = RawData{ .mutable = try allocator.alloc(u8, 0) },
            .first_layer = null,
        };
    }

    /// Packet must be created with .create first. raw_data will be overwritten with the RawData provided
    pub fn from_raw(self: *Packet, raw_data: RawData, link_layer_type: LinkLayerProtocols) !void {
        self.raw_data = raw_data;

        _ = link_layer_type;

        const first_layer = try self.allocator.create(Layer); // create layer struct

        const link_layer = try LayerImpl.init(EthLayer, LayerOwner{ .packet_layer = first_layer });

        first_layer.* = Layer.init(link_layer, 0, Eth.EthHeaderSize, self); // harcoded for the moment for testing
        first_layer.layer_impl = try LayerImpl.init(EthLayer, LayerOwner{ .packet_layer = first_layer });

        self.first_layer = first_layer;

        self.accumulate_layers() catch |err| {
            print("couldn't parse all layers: {s}\n", .{@errorName(err)});
            return;
        };
    }

    fn accumulate_layers(self: *Packet) !void {
        var cur = self.first_layer;
        while (cur) |current_layer| {
            const current_layer_payload = current_layer.layer_impl.get_payload() orelse { // if the current layer only has a header
                current_layer.length = current_layer.layer_impl.get_data().get_immutable().len; // set its length to the length of the header
                return;
            };

            const next_layer: *Layer = try self.allocator.create(Layer);

            next_layer.offset = current_layer.length;

            const impl_layer = blk: {
                const result = current_layer.layer_impl.get_next_layer(next_layer) catch |err| {
                    print("error getting next layer: {}\n", .{err});
                    current_layer.length = current_layer_payload.len;
                    self.allocator.destroy(next_layer);
                    return;
                };

                if (result) |layer| {
                    break :blk layer;
                } else {
                    print("no next layer.\n", .{});
                    current_layer.length = current_layer_payload.len;
                    self.allocator.destroy(next_layer);
                    return;
                }
            };

            print("{any}\n", .{impl_layer});

            const next_layer_data_len = current_layer_payload.len;

            // Initialize the layer with its actual data length
            next_layer.* = Layer.init(impl_layer, next_layer_data_len, 0, self);

            // Set up the linked list pointers
            next_layer.prev_layer = current_layer;
            current_layer.next_layer = next_layer;

            // Set the offset (based on current layer's offset + length)
            next_layer.offset = current_layer.length;

            const next_layer_payload = next_layer.layer_impl.get_payload() orelse {
                return;
            };

            const next_layer_data = next_layer.layer_impl.get_data().get_immutable();

            const next_layer_hdr_len = next_layer_data.len - next_layer_payload.len;

            next_layer.length += next_layer_hdr_len;
            next_layer.offset += current_layer.offset;

            cur = next_layer;
        }
    }

    fn get_last_layer(self: *Packet) ?*Layer {
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
        print("adding: {any}\n", .{layer_impl});

        const data = layer_impl.get_data();

        print("data: {x}\n", .{data});

        const layer: *Layer = try self.allocator.create(Layer); // create the layer (part of the linked list)
        layer.* = Layer.init(layer_impl.*, 0, data.len, self); // deref and set the values

        try layer.layer_impl.reinit(LayerOwner{ .packet_layer = layer });

        const last_layer: ?*Layer = self.get_last_layer();

        if (last_layer) |last| {
            last.next_layer = layer;
            layer.prev_layer = last;
            layer.offset = (last.offset + last.length);
        } else {
            self.first_layer = layer;
        }

        const current_buf_len: usize = self.raw_data.len;

        const new_buf: []u8 = try self.allocator.realloc(self.raw_data, current_buf_len + data.len);

        const dest = new_buf[current_buf_len..];

        @memmove(dest, data);

        self.raw_data = new_buf[0..];

        print("added: {any}\n", .{layer});

        return true;
    }

    /// used by layers to find their data
    pub fn find_layer_ptr(self: *Packet, layer_ptr: *anyopaque) ?[]u8 {
        var cur = self.first_layer;

        while (cur) |layer| {
            if (layer.layer_impl.ptr() == layer_ptr) {
                return self.raw_data[layer.offset..];
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

    pub fn search_layers(self: *Packet, target: LayerProtocols) !?*Layer {
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
                    const current_buf_len: usize = self.raw_data.len;
                    const insert_offset = new_layer.offset;

                    // Reallocate buffer to make room for new layer
                    const new_buf: []u8 = try self.allocator.realloc(self.raw_data, current_buf_len + new_layer.length);
                    self.raw_data = new_buf;

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
            delete_start = prev.length + prev.offset;
            prev.next_layer = layer.next_layer;
        }

        const raw_data = self.raw_data.get_mutable();

        const delete_buf = raw_data[layer.offset .. layer.offset + layer.length];
        print("deletion buffer: {x} ({})\n", .{ delete_buf, delete_buf.len });

        const remaining_buf = raw_data[delete_start + delete_buf.len ..];
        print("remaining buf: {x} ({})\n", .{ remaining_buf, remaining_buf.len });

        const dest = raw_data[delete_start .. delete_start + remaining_buf.len];

        print("dest: {x} ({})\n", .{ dest, dest.len });

        @memmove(dest, remaining_buf);

        const new_len = delete_start + remaining_buf.len;
        self.raw_data = RawData{ .mutable = raw_data[0..new_len] };

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

        if (layer.prev_layer == null) {
            self.first_layer = layer.next_layer;
        }

        self.allocator.destroy(layer);

        return true;
    }

    pub fn extract_layer(self: *Packet, layer_type: anytype, owner: *LayerOwner) !?LayerImpl {
        const layer: *Layer = try self.move_layer(layer_type, owner) orelse {
            return null;
        };

        try layer.layer_impl.reinit(owner.*); // transfers ownership of the packets data

        const return_layer = layer.layer_impl; // copy the layer_impl before Layer is destroyed

        if (layer.prev_layer == null) { // if this was the first layer
            self.first_layer = layer.next_layer; // set the first layer to the layers next layer (can be null)
        }

        self.allocator.destroy(layer); // destroy the layer

        return return_layer; // return the copied implementation layer
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

        var delete_start: usize = 0;
        if (layer.prev_layer) |prev| {
            delete_start = prev.length + prev.offset;
            prev.next_layer = layer.next_layer;
        } else {
            print("no prev layer.\n", .{});
        }

        const raw_data = self.raw_data.get_mutable();

        const delete_buf = raw_data[layer.offset .. layer.offset + layer.length];

        const remaining_buf = raw_data[delete_start + delete_buf.len ..];

        const dest = raw_data[delete_start .. delete_start + remaining_buf.len];

        try owner.allocator_owned.copy_from(delete_buf[0..]);

        @memmove(dest, remaining_buf);

        const new_len = delete_start + remaining_buf.len;
        self.raw_data = RawData{ .mutable = raw_data[0..new_len] };

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
    //
    //   pub fn print_layers(self: *Packet) void {
    //       var cur = self.first_layer;
    //       while (cur) |layer| {
    //           //const slice = self.raw_data[layer.offset..(layer.offset + layer.length)];
    //           const slice = self.raw_data[layer.offset..];
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
