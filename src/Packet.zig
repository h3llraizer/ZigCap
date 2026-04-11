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
    raw_data: RawData,
    layer_impl: LayerImpl,
    packet: *Packet,
    next_layer: ?*Layer = null,
    prev_layer: ?*Layer = null,

    pub fn init(raw_data: RawData, layer_impl: LayerImpl, packet: *Packet) Layer {
        return Layer{ .raw_data = raw_data, .layer_impl = layer_impl, .packet = packet };
    }

    pub fn get_data(self: *Layer) RawData {
        return self.raw_data;
    }

    /// get the Layers payload as a const slice. It's const because it adheres to the API design in that modifications should be made through the layers concrete layer type
    pub fn get_payload(self: *Layer) []const u8 {
        if (self.next_layer) |next| {
            const next_layer_offset: usize = self.packet.raw_data.subsliceOffset(next.get_data().get_immutable()) orelse {
                return self.raw_data.get_immutable();
            };
            return self.packet.raw_data.get_slice_from_offset(next_layer_offset).get_immutable();
        }

        return self.raw_data.get_immutable();
    }

    pub fn to_string(self: *Layer, allocator: Allocator) void {
        print("{s}\n", .{self.layer_impl.to_string(allocator)});
    }
};

pub const Packet = struct {
    allocator: Allocator,
    raw_data: RawData,
    first_layer: ?*Layer,
    last_layer: ?*Layer,
    // *Packet // encapsulation? e.g. VPN packets etc

    /// Creates an empty Packet - alloc's zero bytes to aligned buffer initially
    pub fn create(allocator: Allocator) !Packet {
        return Packet{
            .allocator = allocator,
            .raw_data = RawData{ .mutable = try allocator.alloc(u8, 0) },
            .first_layer = null,
            .last_layer = null,
        };
    }

    /// Packet must be created with .create first. raw_data will be overwritten with the RawData provided
    pub fn from_raw(self: *Packet, raw_data: RawData, link_layer_type: LinkLayerProtocols) !void {
        self.raw_data = raw_data;

        const first_layer = try self.allocator.create(Layer); // create layer struct

        const link_layer = try ProtocolHelpers.create_first_layer(self.raw_data.get_immutable(), link_layer_type, first_layer) orelse {
            return error.LinkLayerCreationFailed;
        };

        first_layer.* = Layer.init(self.raw_data, link_layer, self);

        self.first_layer = first_layer;

        if (self.first_layer) |f_layer| { // if the self.first_layer = first_layer line failed silently for some reason, this is not recoverable. The packet is not in a state to process further
            f_layer.raw_data = self.raw_data.get_slice_from_offset(0);
        } else {
            panic("first layer didn't get assigned to the Packet.", .{});
        }

        try self.accumulate_layers();
    }

    fn accumulate_layers(self: *Packet) !void {
        var cur = self.first_layer;

        while (cur) |current_layer| {
            const next_layer: *Layer = try self.allocator.create(Layer);

            const impl_layer = blk: {
                const result = current_layer.layer_impl.get_next_layer(next_layer) catch |err| {
                    print("error getting next layer: {}\n", .{err});
                    self.allocator.destroy(next_layer);
                    self.last_layer = current_layer;
                    return;
                };

                if (result) |layer| {
                    break :blk layer;
                } else {
                    self.allocator.destroy(next_layer);
                    self.last_layer = current_layer;
                    return;
                }
            };

            const current_layer_payload = current_layer.layer_impl.get_payload() orelse {
                self.allocator.destroy(next_layer);
                return;
            };

            const current_layer_len = current_layer.get_data().get_len() - current_layer_payload.len;

            next_layer.* = Layer.init(current_layer.get_data().get_slice_from_offset(current_layer_len), impl_layer, self);

            // Set up the linked list pointers
            next_layer.prev_layer = current_layer;
            current_layer.next_layer = next_layer;

            cur = next_layer;
        }

        self.last_layer = cur;
    }

    pub fn get_last_layer(self: *Packet) ?*Layer {
        return self.last_layer;
    }

    pub fn add_layer(self: *Packet, layer_impl: *LayerImpl) !bool {
        print("adding: {any}\n", .{layer_impl});

        const data = layer_impl.get_data();

        print("data: {x}\n", .{data.get_immutable()});

        const layer: *Layer = try self.allocator.create(Layer); // create the layer
        layer.* = Layer.init(data, layer_impl.*, self); // copy

        try layer.layer_impl.reinit(LayerOwner{ .packet_layer = layer });

        const last_layer: ?*Layer = self.get_last_layer();

        if (last_layer) |last| {
            last.next_layer = layer;
            layer.prev_layer = last;
        } else {
            self.first_layer = layer;
            self.last_layer = layer;
        }

        const current_buf_len: usize = self.raw_data.get_len();

        const new_buf: []u8 = try self.allocator.realloc(self.raw_data.get_mutable(), current_buf_len + data.get_len());

        const dest = new_buf[current_buf_len..];

        @memmove(dest, data.get_mutable());

        self.raw_data = RawData{ .mutable = new_buf[0..] };

        return true;
    }

    pub fn to_string(self: *Packet, allocator: Allocator) !void {
        var cur = self.first_layer;
        while (cur) |layer| {
            const str: []const u8 = layer.layer_impl.to_string(allocator);
            //defer allocator.free(str);

            print("{s}\n", .{str});

            // TODO: add the defer free of the returned slice - why is it causing double free?
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
        layer.* = Layer.init(data, layer_impl.*, self); // deref and set the values

        return layer;
    }

    pub fn insert_layer(self: *Packet, prev_layer: ?*Layer, layer_to_insert: *LayerImpl) !bool {
        if (prev_layer) |prev| {
            var cur = self.first_layer;

            while (cur) |layer| {
                if (layer == prev) {
                    print("found prev layer: {any}\n", .{layer.layer_impl.get_protocol()});

                    const new_layer: *Layer = try self.create_layer(layer_to_insert);

                    print("{x}\n", .{new_layer.layer_impl.get_data().get_immutable()});

                    new_layer.prev_layer = layer;
                    new_layer.next_layer = layer.next_layer;

                    // Get the correct offset for the new layer
                    const position = try self.find_by_layer(layer);

                    //const start = position[0];
                    const end = position[1];

                    // Update the packet buffer
                    const current_buf_len: usize = self.raw_data.get_len();
                    const insert_offset = end;

                    // Reallocate buffer to make room for new layer
                    const new_buf: []u8 = try self.allocator.realloc(self.raw_data.get_mutable(), current_buf_len + new_layer.get_data().get_len());
                    self.raw_data = RawData{ .mutable = new_buf };

                    // Shift data after insertion point to the right
                    const data_to_shift = new_buf[insert_offset..current_buf_len];
                    const shifted_start = insert_offset + new_layer.get_data().get_len();
                    @memmove(new_buf[shifted_start..], data_to_shift);

                    // Copy the new layer's data into the space
                    const dest = new_buf[insert_offset..][0..end];
                    @memcpy(dest, new_layer.layer_impl.get_data().get_mutable());

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

    /// returns the start and end position of a layer in the Packet's RawData
    fn find_by_type(self: *Packet, layer_type: anytype) ![2]usize {
        const layer_type_enum: LayerProtocols = get_layer_type_enum(layer_type) catch |err| {
            print("error deleting layer: {s}\n", .{@errorName(err)});
            return error.err;
        };

        const layer: *Layer = try self.search_layers(layer_type_enum) orelse {
            print("layer not found.\n", .{});
            return error.LayerNotFound;
        };

        const layer_start = self.raw_data.subsliceOffset(layer.get_data().get_immutable()) orelse {
            return error.OffsetNotFound;
        };

        // Get the actual end of the layer (start + layer length)
        const layer_end = layer_start + layer.get_data().get_len();

        return .{ layer_start, layer_end };
    }

    fn find_by_layer(self: *Packet, layer: *Layer) ![2]usize {
        const layer_start = self.raw_data.subsliceOffset(layer.get_data().get_immutable()) orelse {
            return error.OffsetNotFound;
        };

        // Get the actual end of the layer (start + layer length)
        const layer_end = layer_start + layer.get_data().get_len();

        return .{ layer_start, layer_end };
    }

    pub fn extract_layer(self: *Packet, layer: *Layer, owner: *LayerOwner) !?LayerImpl {
        try self.move_layer(layer, owner);

        try layer.layer_impl.reinit(owner.*); // transfers ownership of the packets data to the new owner

        const return_layer = layer.layer_impl; // copy the layer_impl before Layer is destroyed

        if (layer.prev_layer == null) {
            self.first_layer = layer.next_layer;
        }

        if (layer.prev_layer) |prev| {
            prev.next_layer = layer.next_layer;
        }

        if (layer.next_layer) |next| {
            next.prev_layer = layer.prev_layer;
        }

        if (self.first_layer) |first_layer| {
            self.raw_data = first_layer.raw_data; // update Packet RawData ptr again because previous mutations changed ptr
        } else { // the last layer was deleted, there is no more RawData to use
            self.raw_data = RawData{ .mutable = undefined };
            print("last layer has been deleted.\n", .{});
        }

        self.allocator.destroy(layer); // destroy the layer

        return return_layer; // return the copied implementation layer
    }

    fn move_layer(self: *Packet, layer: *Layer, owner: *LayerOwner) !void {
        const data = layer.get_data();
        const payload = layer.get_payload();

        const start_in_packet = self.raw_data.subsliceOffset(data.get_immutable()) orelse {
            return error.LayerDataNotFound;
        };
        var end_in_packet = self.raw_data.get_len();
        if (self.raw_data.subsliceOffset(payload)) |payload_start| {
            end_in_packet = payload_start;
        }

        print("start in packet:{} end in packet: {}\n", .{ start_in_packet, end_in_packet });

        const removal_data = self.raw_data.get_slice(start_in_packet, end_in_packet);

        print("removal data: {x}\n", .{removal_data.get_immutable()});

        try self.copy_data(layer, removal_data, owner);
    }

    fn find_layer(self: *Packet, layer: *Layer) bool {
        var cur = self.first_layer;
        while (cur) |l| {
            if (l == layer) {
                return true;
            }

            cur = l.next_layer;
        }

        return false;
    }

    pub fn delete_layer(self: *Packet, layer: *Layer) !bool {
        try self.remove_data(layer, layer.raw_data);

        if (layer.prev_layer == null) {
            self.first_layer = layer.next_layer;
        }

        if (layer.prev_layer) |prev| {
            prev.next_layer = layer.next_layer;
        }

        if (layer.next_layer) |next| {
            next.prev_layer = layer.prev_layer;
        } else {
            self.last_layer = layer.prev_layer;
        }

        self.allocator.destroy(layer);

        if (self.first_layer) |first_layer| {
            _ = first_layer;
            //self.raw_data = first_layer.raw_data; // update Packet RawData ptr again because previous mutations changed the ptr
        } else { // the last layer was deleted, there is no more RawData
            self.raw_data = RawData{ .mutable = undefined };
            print("no more layers.\n", .{});
        }

        return true;
    }

    /// removes a slice of data from the Layer. Mostly used by Application Layers to modify their payload in the packet, but can be used directly if required but be aware that attempting to remove data in a layers header will result in an exception. Don't use this function to "delete" a layer (use delete_layer instead)
    pub fn remove_data(self: *Packet, layer: *Layer, raw_data: RawData) !void {
        if (!self.find_layer(layer)) {
            return error.LayerNotFound;
        }

        if (!self.raw_data.is_mutable()) {
            return error.PacketRawDataNotMutable;
        }

        if (!layer.get_data().isSubslice(raw_data.get_immutable())) {
            return error.SliceDoesNotBelongToLayer;
        }

        const delete_start_in_layer: usize = layer.get_data().subsliceOffset(raw_data.get_immutable()) orelse {
            return error.OffsetNotFound;
        };

        const delete_end_in_layer: usize = raw_data.get_immutable().len - layer.get_payload().len;

        //const delete_end_in_layer: usize = raw_data.get_immutable().len;

        print("delete start offset in layer: {}\n", .{delete_start_in_layer});

        print("delete end in layer: {}\n", .{delete_end_in_layer});

        const slice_for_removal = raw_data.get_slice(delete_start_in_layer, delete_end_in_layer).get_immutable();

        print("slice removal: {x}\n", .{slice_for_removal});

        const position_in_packet = try self.find_by_layer(layer);

        print("position: {any}\n", .{position_in_packet});

        const start_in_packet: usize = position_in_packet[0];

        const delete_start_in_packet = start_in_packet + delete_start_in_layer;

        print("delete start in packet: {}\n", .{delete_start_in_packet});

        const delete_end_in_packet = delete_start_in_packet + delete_end_in_layer;

        print("delete end in packet: {}\n", .{delete_end_in_packet});

        const packet_data = self.raw_data.get_mutable();

        print("original: ({}) {x}\n", .{ packet_data.len, packet_data });

        const delete_buf = packet_data[delete_start_in_packet..delete_end_in_packet];
        print("deletion buffer: {x} ({})\n", .{ delete_buf, delete_buf.len });

        const remaining_buf = packet_data[delete_start_in_packet + delete_buf.len ..];
        print("remaining buf: {x} ({})\n", .{ remaining_buf, remaining_buf.len });

        const dest = packet_data[delete_start_in_packet .. delete_start_in_packet + remaining_buf.len];
        print("dest: {x} ({})\n", .{ dest, dest.len });

        @memmove(dest, remaining_buf);

        const new_len = delete_start_in_packet + remaining_buf.len;
        print("new len: {}\n", .{new_len});

        var cur = layer.prev_layer;
        while (cur) |prev| {
            print("{any}\n", .{try prev.layer_impl.get_protocol()});
            const pos = try self.find_by_layer(prev);
            prev.raw_data = RawData{ .mutable = packet_data[pos[0]..new_len] };
            cur = prev.prev_layer;
        }

        cur = layer.next_layer;
        while (cur) |next| {
            print("{any}\n", .{try next.layer_impl.get_protocol()});
            const pos = try self.find_by_layer(next);
            next.raw_data = RawData{ .mutable = packet_data[(pos[0] - slice_for_removal.len)..new_len] };
            cur = next.next_layer;
        }

        const new_buf = RawData{ .mutable = packet_data[0..new_len] };

        self.raw_data = new_buf;

        print("new len: {}\n", .{new_len});

        print("new buf: {x}\n", .{new_buf.get_immutable()});
    }

    pub fn copy_data(self: *Packet, layer: *Layer, raw_data: RawData, new_owner: *LayerOwner) !void {
        if (!self.find_layer(layer)) {
            return error.LayerNotFound;
        }

        if (!self.raw_data.is_mutable()) {
            return error.PacketRawDataNotMutable;
        }

        if (!layer.get_data().isSubslice(raw_data.get_immutable())) {
            return error.SliceDoesNotBelongToLayer;
        }

        const delete_start_in_layer: usize = layer.get_data().subsliceOffset(raw_data.get_immutable()) orelse {
            return error.OffsetNotFound;
        };

        const delete_end_in_layer: usize = raw_data.get_immutable().len;

        print("delete start offset in layer: {}\n", .{delete_start_in_layer});

        print("delete end in layer: {}\n", .{delete_end_in_layer});

        const slice_for_removal = raw_data.get_slice(delete_start_in_layer, delete_end_in_layer).get_immutable();

        print("slice removal: {x}\n", .{slice_for_removal});

        const position_in_packet = try self.find_by_layer(layer);

        print("position: {any}\n", .{position_in_packet});

        const start_in_packet: usize = position_in_packet[0];

        const delete_start_in_packet = start_in_packet + delete_start_in_layer;

        print("delete start in packet: {}\n", .{delete_start_in_packet});

        const delete_end_in_packet = delete_start_in_packet + delete_end_in_layer;

        print("delete end in packet: {}\n", .{delete_end_in_packet});

        const packet_data = self.raw_data.get_mutable();

        print("original: ({}) {x}\n", .{ packet_data.len, packet_data });

        const delete_buf = packet_data[delete_start_in_packet..delete_end_in_packet];
        print("deletion buffer: {x} ({})\n", .{ delete_buf, delete_buf.len });

        const remaining_buf = packet_data[delete_start_in_packet + delete_buf.len ..];
        print("remaining buf: {x} ({})\n", .{ remaining_buf, remaining_buf.len });

        const dest = packet_data[delete_start_in_packet .. delete_start_in_packet + remaining_buf.len];
        print("dest: {x} ({})\n", .{ dest, dest.len });

        try new_owner.allocator_owned.copy_from(delete_buf);

        @memmove(dest, remaining_buf);

        const new_len = delete_start_in_packet + remaining_buf.len;

        var cur = layer.prev_layer;
        while (cur) |prev| {
            const pos = try self.find_by_layer(prev);
            prev.raw_data = RawData{ .mutable = packet_data[pos[0]..new_len] };
            cur = prev.prev_layer;
        }

        const new_buf = RawData{ .mutable = packet_data[0..new_len] };

        self.raw_data = new_buf;

        print("new len: {}\n", .{new_len});

        print("new buf: {x}\n", .{new_buf.get_immutable()});
    }

    /// inserts a slice of data into the Layer. Mostly used by Application Layers to modify their payload in the packet, but can be used directly if required
    pub fn insert_data(self: *Packet, layer: *Layer, raw_data: RawData) !void {
        if (!self.find_layer(layer)) {
            return error.LayerNotFound;
        }

        if (!self.raw_data.is_mutable()) {
            return error.PacketRawDataNotMutable;
        }

        const raw_data_len = raw_data.get_len();

        print("raw data append len: {}\n", .{raw_data_len});

        const current_packet_len: usize = self.raw_data.get_immutable().len;

        print("current buf len: {}\n", .{current_packet_len});

        const new_buf: RawData = RawData{ .mutable = try self.allocator.realloc(self.raw_data.get_mutable(), current_packet_len + raw_data_len) };

        const dest = new_buf.get_slice_from_offset(current_packet_len);

        @memmove(dest.get_mutable(), raw_data.get_immutable());

        var cur = self.first_layer;
        while (cur) |next| {
            const pos = try self.find_by_layer(next);
            print("{any} {any}\n", .{ next.layer_impl.get_protocol(), pos });
            const layer_start = pos[0];
            const layer_end = (pos[1] + raw_data_len);
            next.raw_data = RawData{ .mutable = new_buf.get_slice(layer_start, (layer_end)).get_mutable() };
            cur = next.next_layer;
        }

        self.raw_data = new_buf;
    }

    pub fn print_layers_metad(self: *Packet) !void {
        var cur = self.first_layer;
        while (cur) |layer| {
            const data = layer.get_data().get_immutable();

            print("{any} ({}) {x}\n", .{ layer.layer_impl.get_protocol(), data.len, data });

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
