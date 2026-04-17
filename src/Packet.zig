const std = @import("std");
const print = std.debug.print;
const activeTag = std.meta.activeTag;
const Allocator = std.mem.Allocator;
const panic = std.debug.panic;

const ProtocolEnums = @import("ProtocolEnums.zig");
const IPVersions = ProtocolEnums.IPVersions;
const tcp_ip_protocols = @import("tcp_ip_protocols.zig");
const tcp_ip_protocol = tcp_ip_protocols.tcp_ip_protocol;
const get_layer_type_enum = tcp_ip_protocols.get_layer_type_enum;
const LayerError = ProtocolEnums.LayerError;
const link_layer_type = ProtocolEnums.link_layer_type;
const LayerIface = @import("LayerIface.zig").LayerIface;
const Eth = @import("Eth.zig");
const EthLayer = Eth.EthLayer;
const LoopBack = @import("Loopback.zig");
const IPv4 = @import("IPv4.zig");
const IPv6 = @import("IPv6.zig");
const GenericLayer = @import("GenericLayer.zig");
const LayerOwner = @import("Layer.zig").LayerOwner;

const Buffer = @import("Buffer.zig").Buffer;

/// Do NOT change the offset and lengths manually - there is no need to. They are public by default but let the Packet manage these members
pub const Layer = struct {
    offset: usize,
    length: usize,
    layer_iface: LayerIface,
    packet: *Packet,
    next_layer: ?*Layer = null,
    prev_layer: ?*Layer = null,

    pub fn init(offset: usize, length: usize, layer_iface: LayerIface, packet: *Packet) Layer {
        return Layer{ .offset = offset, .length = length, .layer_iface = layer_iface, .packet = packet };
    }

    pub fn get_data(self: *Layer) []u8 {
        return self.packet.buffer.buffer.items[self.offset..];
        //return self.packet.buffer.get_mutable_slice(self.offset, self.packet.buffer.get_len());
    }

    /// get the Layers payload as a const slice. It's const because it adheres to the API design in that modifications should be made through the layers concrete layer type
    pub fn get_payload(self: *Layer) []const u8 {
        const payload_start = self.offset + self.length;
        if (self.packet.buffer.buffer.items.len > payload_start) {
            return self.packet.buffer.buffer.items[payload_start..];
        } else {
            return "";
        }
    }

    pub fn to_string(self: *Layer, allocator: Allocator) void {
        print("{s}\n", .{self.layer_iface.to_string(allocator)});
    }
};

pub const Packet = struct {
    layer_allocator: Allocator,
    buffer: Buffer,
    first_layer: ?*Layer,
    last_layer: ?*Layer,
    // *Packet // encapsulation? e.g. VPN packets etc

    /// Creates an empty Packet - alloc's zero bytes to aligned buffer initially
    pub fn create(buffer_allocator: Allocator, layer_allocator: Allocator) !Packet {
        return Packet{
            .layer_allocator = layer_allocator,
            .buffer = Buffer.init_empty(buffer_allocator),
            .first_layer = null,
            .last_layer = null,
        };
    }

    /// Packet must be created with .create first. raw_data will be overwritten with the RawData provided
    pub fn from_raw(self: *Packet, data: []align(2) u8, link_type: link_layer_type) !void {
        self.buffer.buffer.items = data;

        const first_layer = try self.layer_allocator.create(Layer); // create layer struct

        const link_layer = try create_first_layer(self.buffer.buffer.items, link_type, first_layer) orelse {
            return error.LinkLayerCreationFailed;
        };

        first_layer.* = Layer.init(0, self.buffer.buffer.items.len, link_layer, self);

        self.first_layer = first_layer;

        try self.accumulate_layers();
    }

    fn create_ip_layer(raw: []const u8, layer: *Layer) !?LayerIface {
        if (raw.len < IPv4.MinHeaderLength) {
            return error.HeaderTooSmall;
        }

        const ihl_byte = raw[0];
        const ip_version = ihl_byte >> 4;
        if (ip_version == @intFromEnum(IPVersions.IPv4)) {
            const hdr_len = (ihl_byte & 0x0F) * 4;
            if (hdr_len < IPv4.MinHeaderLength or hdr_len > IPv4.MaxHeaderLength) {
                return try LayerIface.init(GenericLayer.ApplicationLayer, LayerOwner{ .packet_layer = layer });
            }

            return try LayerIface.init(IPv4.IPv4Layer, LayerOwner{ .packet_layer = layer });
        }

        if (ip_version == @intFromEnum(IPVersions.IPv6)) {
            if (raw.len < IPv6.IPv6HeaderSize) {
                return error.HeaderTooSmall;
            }
            return try LayerIface.init(IPv6.IPv6Layer, LayerOwner{ .packet_layer = layer });
        } else {
            print("Unknown link type.\n", .{});
            return null;
        }
    }

    fn create_first_layer(raw: []const u8, link_type: link_layer_type, layer: *Layer) !?LayerIface {
        switch (link_type) {
            .ETHERNET => {
                return try LayerIface.init(Eth.EthLayer, LayerOwner{ .packet_layer = layer });
            },
            .RAW => {
                return try create_ip_layer(raw, layer);
            },
            .LOOP, .NULL => {
                return try LayerIface.init(LoopBack.LoopBackLayer, LayerOwner{ .packet_layer = layer });
            },
            else => {
                return error.LinkLayerUnknown;
            },
        }
    }

    fn accumulate_layers(self: *Packet) !void {
        var cur = self.first_layer;

        while (cur) |current_layer| {
            const next_layer: *Layer = try self.layer_allocator.create(Layer);

            print("current layer: {any}\n", .{current_layer.layer_iface.get_protocol()});

            const impl_layer = blk: {
                const result = current_layer.layer_iface.get_next_layer(next_layer) catch |err| {
                    print("error getting next layer: {}\n", .{err});
                    self.layer_allocator.destroy(next_layer);
                    self.last_layer = current_layer;
                    return;
                };

                if (result) |layer| {
                    break :blk layer;
                } else {
                    self.layer_allocator.destroy(next_layer);
                    self.last_layer = current_layer;
                    return;
                }
            };

            const current_layer_len = current_layer.length;

            const next_layer_len = current_layer.get_payload().len;

            next_layer.* = Layer.init(current_layer_len, next_layer_len, impl_layer, self);

            current_layer.length = current_layer_len - next_layer_len;

            next_layer.offset = current_layer.length + current_layer.offset;

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

    pub fn add_layer(self: *Packet, layer_iface: *LayerIface) !bool {
        const data = layer_iface.get_data();

        const layer: *Layer = try self.layer_allocator.create(Layer); // create the layer
        // init the layer by setting the initial offset to 0, data len to len of the layer data, deref th layerIface to copy it, specify the Packet to self (this Packet)
        layer.* = Layer.init(0, data.len, layer_iface.*, self);

        // set the owner to packet layer that was just created
        try layer.layer_iface.reinit(LayerOwner{ .packet_layer = layer });

        const last_layer: ?*Layer = self.last_layer; // get the last layer (might be null)

        if (last_layer) |last| { // if the last layer is not null
            last.next_layer = layer; // set the last layer next layer to the layer created (layer being added)
            layer.prev_layer = last; // set the layer created (layer being added)'s prev layer to the last layer
            self.last_layer = layer; // the last layer is now the layer that's being added
            layer.offset = last.offset + last.length; // set layer added offset to the last offset + last length
        } else { // there was no last layer
            self.first_layer = layer; // set first layer to this layer being added
            self.last_layer = layer; // set last layer to this layer being added
        }

        // now extend the packet's buffer to make space for copyng the layer being added's buffer into the packet
        const layer_buffer = try self.buffer.extend(layer.offset, layer.length);

        // copy the data into the slice
        @memmove(layer_buffer, data);

        return true; // tbh it probably shouldn't even need to return a true, just void with error union
    }

    pub fn to_string(self: *Packet, allocator: Allocator) !void {
        var cur = self.first_layer;
        while (cur) |layer| {
            const str: []const u8 = layer.layer_iface.to_string(allocator);

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
            return @as(*layer_type, @ptrCast(@alignCast(b.layer_iface.ptr())));
        }

        return null;
    }

    pub fn search_layers(self: *Packet, target: tcp_ip_protocol) !?*Layer {
        var cur = self.first_layer;
        while (cur) |layer| {
            if (try layer.layer_iface.get_protocol() == target) {
                return layer;
            }
            cur = layer.next_layer;
        }

        return null;
    }

    fn create_layer(self: *Packet, layer_iface: *LayerIface) !*Layer {
        const data = layer_iface.get_data();

        const layer: *Layer = try self.allocator.create(Layer);
        layer.* = Layer.init(data, layer_iface.*, self); // deref and set the values

        return layer;
    }

    pub fn extend_layer(self: *Packet, layer: *Layer, length: usize) ![]u8 {
        const extend_offset = layer.offset + layer.length;
        const buf = try self.buffer.extend(extend_offset, length);

        layer.length += length; // increase the length of the layer by length that it was extended by

        // now the proceeding layers offsets and lengths need to be increased by the length that this layer was extended by
        var cur = layer.next_layer; // get the layers next layer
        while (cur) |next| {
            next.offset += length; // increase it's offset by the length
            cur = next.next_layer; // set cur to its next layer
        }

        return buf; // return the extend slice
    }

    pub fn shorten_layer(self: *Packet, layer: *Layer, offset: usize, length: usize) !void {
        const shorten_offset = layer.offset + offset;

        print("shorten offset: {} length: {}\n", .{ shorten_offset, length });

        self.print_layers_meta();

        try self.buffer.shorten(shorten_offset, length);

        layer.length -= length;

        var cur = layer.next_layer;
        while (cur) |next| {
            print("current layer {any} {} {} \n", .{ next.layer_iface.get_protocol(), next.offset, next.length });
            next.offset -= length;
            print("layer adjusted {any} {} {} \n", .{ next.layer_iface.get_protocol(), next.offset, next.length });
            //next.length -= length;
            cur = next.next_layer;
        }
    }

    pub fn get_layer_count(self: *Packet) usize {
        var count: usize = 0;

        var cur = self.first_layer;
        while (cur) |layer| {
            count += 1;
            cur = layer.next_layer;
        }

        return count;
    }

    /// Insert a layer after the prev_layer
    /// Use search_layers to find the specific layer you want to insert after
    pub fn insert_layer(self: *Packet, prev_layer: *Layer, layer_to_insert: *LayerIface) !bool {
        var cur = self.first_layer;
        while (cur) |layer| {
            if (layer == prev_layer) {
                const data = layer_to_insert.get_data();

                const new_layer: *Layer = try self.layer_allocator.create(Layer);
                new_layer.* = Layer.init(layer.offset + layer.length, data.len, layer_to_insert.*, self);

                try new_layer.layer_iface.reinit(LayerOwner{ .packet_layer = new_layer });

                var next_layer = layer.next_layer;
                layer.next_layer = new_layer;
                new_layer.prev_layer = layer;

                if (next_layer) |next| {
                    new_layer.next_layer = next;
                    next.prev_layer = new_layer;
                }

                // Update offsets for subsequent layers
                while (next_layer) |next| {
                    next.offset += data.len;
                    next_layer = next.next_layer;
                }

                const layer_buffer = try self.buffer.extend(layer.offset + layer.length, data.len);
                @memmove(layer_buffer, data);

                return true;
            }
            cur = layer.next_layer;
        }
        return false;
    }

    pub fn print_layers(self: *Packet) void {
        var cur = self.first_layer;
        while (cur) |layer| {
            print("{any} {x}\n", .{ layer.layer_iface.get_protocol(), layer.get_data().get_immutable() });
            cur = layer.next_layer;
        }
    }

    pub fn extract_layer(self: *Packet, layer: *Layer, owner: *LayerOwner) !?LayerIface {
        try self.buffer.cutRange(&owner.owned_buffer, layer.offset, layer.length);

        try layer.layer_iface.reinit(owner.*); // transfers ownership of the packets data to the new owner

        const return_layer = layer.layer_iface; // copy the layer_iface before Layer is destroyed

        var cur = layer.next_layer;
        while (cur) |next_layer| {
            next_layer.offset -= layer.length;
            cur = next_layer.next_layer;
        }

        if (layer.prev_layer == null) {
            self.first_layer = layer.next_layer;
        }

        if (layer.prev_layer) |prev| {
            prev.next_layer = layer.next_layer;
        }

        if (layer.next_layer) |next| {
            next.prev_layer = layer.prev_layer;
        }

        self.layer_allocator.destroy(layer); // destroy the layer

        return return_layer; // return the copied implementation layer
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
        try self.buffer.shorten(layer.offset, layer.length);

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

        var cur = layer.next_layer;
        while (cur) |next_layer| {
            next_layer.offset -= layer.length;
            cur = next_layer.next_layer;
        }

        self.layer_allocator.destroy(layer);

        return true;
    }

    pub fn print_layers_meta(self: *Packet) void {
        var count: usize = 0;
        var cur = self.first_layer;
        while (cur) |layer| {
            count += 1;
            const layer_slice = self.buffer.get_immutable_slice(layer.offset, layer.length);
            print("{}. {any} offset={} length={} end: {} data:{x} ({})\n", .{
                count,
                layer.layer_iface.get_protocol(),
                layer.offset,
                layer.length,
                layer.offset + layer.length,
                layer_slice,
                layer_slice.len,
            });
            cur = layer.next_layer;
        }
    }

    /// destroys protocol layers linkedlist. The buffer is not freed.
    pub fn deinit(self: *Packet) void {
        var cur = self.first_layer;

        while (cur) |layer| {
            const next = layer.next_layer;
            //print("destroying: {any}\n", .{layer.layer_iface.get_protocol()});
            self.layer_allocator.destroy(layer);
            cur = next;
        }

        // free buffer?
    }
};
