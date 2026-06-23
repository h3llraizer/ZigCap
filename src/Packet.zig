const std = @import("std");
const ProtocolEnums = @import("ProtocolEnums.zig");
const tcp_ip_protocols = @import("tcp_ip_protocols.zig");
const LayerIface = @import("LayerIface.zig").LayerIface;
const Eth = @import("Eth.zig");
const Loopback = @import("Loopback.zig");
const IPv4 = @import("IPv4.zig");
const IPv6 = @import("IPv6.zig");
const GenericLayer = @import("GenericLayer.zig");
const LayerOwner = @import("Owner.zig").LayerOwner;
const Buffer = @import("Buffer.zig").Buffer;

const print = std.debug.print;
const activeTag = std.meta.activeTag;
const Allocator = std.mem.Allocator;
const panic = std.debug.panic;
const IPVersions = ProtocolEnums.IPVersions;
const EthLayer = Eth.EthLayer;
const LayerError = ProtocolEnums.LayerError;
const link_layer_type = ProtocolEnums.link_layer_type;
const tcp_ip_protocol = tcp_ip_protocols.tcp_ip_protocol;
const get_layer_type_enum = tcp_ip_protocols.get_layer_type_enum;

/// Do NOT change the offset and lengths manually - there is no need to. They are public by default but let the Packet manage these members
pub const Layer = struct {
    offset: usize, // absolute offset in the owning packet
    length: usize,
    layer_iface: LayerIface,
    packet: *Packet,
    next_layer: ?*Layer = null,
    prev_layer: ?*Layer = null,

    pub fn init(offset: usize, length: usize, layer_iface: LayerIface, packet: *Packet) Layer {
        return Layer{ .offset = offset, .length = length, .layer_iface = layer_iface, .packet = packet };
    }

    /// Returns data from first byte of header to last byte of packet
    pub fn get_data(self: *Layer) []u8 {
        return self.packet.buffer.buffer.items[self.offset..];
    }

    pub fn print_meta(self: *Layer) void {
        print("{any}: offset: {} length: {}\n", .{
            self.layer_iface.get_protocol(),
            self.offset,
            self.length,
        });
    }

    /// to_string returns immut slice. caller free memory using the allocator provided
    pub fn to_string(self: *Layer, allocator: Allocator) []const u8 {
        const str = self.layer_iface.to_string(allocator);
        return str;
    }
};

pub const InitError = error{
    PacketBufferNotEmpty,
    LinkLayerCreationFailed,
    LinkLayerNotHandled,
};

pub const ParseError = error{
    HeaderTooSmall,
};

pub const Packet = struct {
    layer_allocator: Allocator,
    buffer: Buffer,
    first_layer: ?*Layer,
    last_layer: ?*Layer,

    /// Creates an empty Packet by creating it's internal buffer using the first (buffer allocator) passed
    /// the second allocator is used to create the layer structs (you can pass the same allocator if you want)
    pub fn create(buffer_allocator: Allocator, layer_allocator: Allocator) Packet {
        return Packet{
            .layer_allocator = layer_allocator,
            .buffer = Buffer.init_empty(buffer_allocator),
            .first_layer = null,
            .last_layer = null,
        };
    }

    /// Parses a packet from an existing slice (data).
    /// Each layer is parsed until optional tcp_ip_protocol specified or until last layer in packet.
    /// Takes ownership of the buffer provided.
    pub fn from_raw(
        self: *Packet,
        allocator: Allocator,
        buffer: *std.ArrayList(u8),
        link_type: link_layer_type,
        parse_until: ?tcp_ip_protocol,
    ) (InitError || LayerError || Allocator.Error)!void {
        if (self.buffer.buffer.items.len > 0) {
            return InitError.PacketBufferNotEmpty;
        }
        // Take ownership of the ArrayList's memory
        self.buffer = try Buffer.init(try buffer.toOwnedSlice(allocator), allocator);

        const first_layer = try self.layer_allocator.create(Layer);
        const link_layer = try create_first_layer(self.buffer.buffer.items, link_type, first_layer) orelse {
            return InitError.LinkLayerCreationFailed;
        };

        first_layer.* = Layer.init(0, self.buffer.buffer.items.len, link_layer, self);
        self.first_layer = first_layer;

        try self.accumulate_layers(parse_until);
    }

    pub fn from_slice(
        self: *Packet,
        allocator: Allocator,
        buffer: []u8,
        link_type: link_layer_type,
        parse_until: ?tcp_ip_protocol,
    ) (InitError || LayerError || Allocator.Error)!void {
        if (self.buffer.buffer.items.len > 0) {
            return InitError.PacketBufferNotEmpty;
        }
        self.buffer = Buffer.init_empty(allocator);

        self.buffer.buffer.items = buffer;

        const first_layer = try self.layer_allocator.create(Layer);
        const link_layer = try create_first_layer(self.buffer.buffer.items, link_type, first_layer) orelse {
            return InitError.LinkLayerCreationFailed;
        };

        first_layer.* = Layer.init(0, self.buffer.buffer.items.len, link_layer, self);
        self.first_layer = first_layer;

        try self.accumulate_layers(parse_until);
    }

    pub fn get_raw(self: *Packet) []const u8 {
        return self.buffer.buffer.items;
    }

    fn create_ip_layer(raw: []const u8, layer: *Layer) LayerError!?LayerIface {
        if (raw.len < IPv4.MinHeaderLength) {
            return LayerError.LayerInvalid;
        }

        const ihl_byte = raw[0];
        const ip_version = ihl_byte >> 4;
        if (ip_version == @intFromEnum(IPVersions.IPv4)) {
            const hdr_len = (ihl_byte & 0x0F) * 4;
            if (hdr_len < IPv4.MinHeaderLength or hdr_len > IPv4.MaxHeaderLength) {
                return LayerIface{ .genericAppLayer = .{ .owner = .{ .packet_layer = layer } } };
            }

            layer.length = IPv4.MinHeaderLength;
            return LayerIface{ .ipv4Layer = .{ .owner = .{ .packet_layer = layer } } };
        }

        if (ip_version == @intFromEnum(IPVersions.IPv6)) {
            if (raw.len < IPv6.IPv6HeaderSize) {
                return LayerError.LayerInvalid;
            }
            layer.length = IPv6.IPv6HeaderSize;
            return LayerIface{ .ipv6Layer = .{ .owner = .{ .packet_layer = layer } } };
        } else {
            print("Unknown link type.\n", .{});
            return null;
        }
    }

    fn create_first_layer(raw: []const u8, link_type: link_layer_type, layer: *Layer) (InitError || LayerError)!?LayerIface {
        switch (link_type) {
            .ETHERNET => {
                layer.length = Eth.EthHeaderSize;
                return LayerIface{ .ethLayer = .{ .owner = .{ .packet_layer = layer } } };
            },
            .RAW => {
                return try create_ip_layer(raw, layer);
            },
            .LOOP, .NULL => {
                return LayerIface{ .loopbackLayer = .{ .owner = .{ .packet_layer = layer } } };
            },
            else => {
                return InitError.LinkLayerNotHandled;
            },
        }
    }

    fn accumulate_layers(self: *Packet, parse_until: ?tcp_ip_protocol) (LayerError || Allocator.Error)!void {
        var cur = self.first_layer;

        while (cur) |current_layer| {
            const next_layer: *Layer = try self.layer_allocator.create(Layer);

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

            const current_layer_payload = current_layer.layer_iface.get_payload();

            current_layer.length -= current_layer_payload.len;

            const next_layer_offset = current_layer.offset + current_layer.length;

            next_layer.* = Layer.init(next_layer_offset, current_layer_payload.len, impl_layer, self);

            // Set up the linked list pointers
            next_layer.prev_layer = current_layer;
            current_layer.next_layer = next_layer;

            if (parse_until) |protocol| {
                if (next_layer.layer_iface.get_protocol() == protocol) {
                    next_layer.prev_layer = current_layer;
                    current_layer.next_layer = next_layer;
                    break;
                }
            }

            cur = next_layer;
        }

        self.last_layer = cur;
    }

    pub fn get_last_layer(self: *Packet) ?*Layer {
        return self.last_layer;
    }

    pub fn add_layer(self: *Packet, layer_iface: *LayerIface) (LayerError || Allocator.Error)!void {
        const data = layer_iface.get_data();

        // create the layer
        const layer: *Layer = try self.layer_allocator.create(Layer);

        // init the layer by:
        //  setting the initial offset to 0,
        //  data len to len of the layer data,
        //  deref th layerIface to copy it,
        //  specify the Packet to self (this Packet)
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
    }

    /// Returns ptr to the concrete type
    /// changes made are made directly in the packet - zero-copy
    pub fn get_layer_of_type(self: *Packet, layer_type: anytype) ?*layer_type {
        const layer_type_enum = get_layer_type_enum(layer_type) catch {
            return null;
        };

        // TODO: investigate using active_tag of the Layer's LayerIface instead of get_layer_type_enum
        // e.g std.meta.activeTag(layer.layeriface) == layertype

        const layer: ?*Layer = self.search_layers(layer_type_enum);

        if (layer) |b| {
            return @as(*layer_type, @ptrCast(@alignCast(b.layer_iface.ptr())));
        }

        return null;
    }

    /// example: has_protocol_layer(.eth) in a packet which has EthLayer->IPv4Layer->UDPLayer->DNSLayer returns true
    pub fn has_protocol_layer(self: *Packet, layer_proto: tcp_ip_protocol) bool {
        if (self.search_layers(layer_proto) != null) {
            return true;
        }

        return false;
    }

    // TODO: make this private and allow callers to insert/delete/extract layers using get_layer_of_type with depth arg
    /// Returns Layer. Packet uses this Layer struct to seperate layers and coordinate mutations
    pub fn search_layers(self: *Packet, target: tcp_ip_protocol) ?*Layer { // this should return a const ptr
        var cur = self.first_layer;
        while (cur) |layer| {
            if (layer.layer_iface.get_protocol() == target) {
                return layer;
            }
            cur = layer.next_layer;
        }

        return null;
    }

    /// calls each layers validate_layer method in backwards traversal
    pub fn validate_packet(self: *Packet) void {
        var cur = self.last_layer;
        while (cur) |layer| {
            layer.layer_iface.validate_layer();
            cur = layer.prev_layer;
        }
    }

    pub fn extend_layer(self: *Packet, layer: *Layer, offset: usize, length: usize) Allocator.Error![]u8 {
        // TODO: call proceeding layers calculate_length
        // TODO: ensure layer cannot be shorten beyond its Minimum or fixed header header length

        const extend_offset = layer.offset + offset; // absolute position in packet

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

    pub fn shorten_layer(self: *Packet, layer: *Layer, offset: usize, length: usize) Allocator.Error!void {
        // TODO: call proceeding layers calculate_length
        // TODO: ensure layer cannot be shorten beyond its Minimum or fixed header header length
        const shorten_offset = layer.offset + offset;

        try self.buffer.shorten(shorten_offset, length);

        layer.length -= length;

        var cur = layer.next_layer;
        while (cur) |next| {
            next.offset -= length;
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
    pub fn insert_layer(self: *Packet, prev_layer: *Layer, layer_to_insert: *LayerIface) (LayerError || Allocator.Error)!bool {
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

    pub fn extract_layer(self: *Packet, layer: *Layer, owner: *LayerOwner) (LayerError || Allocator.Error)!?LayerIface {
        try self.buffer.cutRange(&owner.owned_buffer, layer.offset, layer.length);

        layer.layer_iface.deinit();

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

    pub fn delete_layer(self: *Packet, layer: *Layer) Allocator.Error!bool {
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

        layer.layer_iface.deinit();

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

    /// calls each layers to_string method and appends to an ArrayList, returning an ownedSlice of that ArrayList
    pub fn to_string(self: *Packet, allocator: Allocator) Allocator.Error![]const u8 {
        var buffer: std.ArrayList(u8) = .empty;
        var cur = self.first_layer;
        while (cur) |layer| {
            const returned_str = layer.layer_iface.to_string(allocator);
            defer allocator.free(returned_str);
            try buffer.appendSlice(allocator, returned_str);

            cur = layer.next_layer;
        }

        return buffer.toOwnedSlice(allocator);
    }

    /// deinits by destroying layer structs and deiniting (freeing) the packets Buffer
    pub fn deinit(self: *Packet) void {
        var cur = self.first_layer;

        while (cur) |layer| {
            //layer.layer_iface.deinit();
            const next = layer.next_layer;
            self.layer_allocator.destroy(layer);
            cur = next;
        }

        self.buffer.deinit();
    }
};
