const std = @import("std");
const Packet = @import("Packet.zig");
const Buffer = @import("Buffer.zig").Buffer;
const LayerIface = @import("LayerIface.zig").LayerIface;

const print = std.debug.print;
const Allocator = std.mem.Allocator;

/// The Layer data is either owned by Packet or Buffer ("owned_buffer")
/// When owned by packet_layer, the data is retrieved and modified via the Layers e.g. get_data() calls Layer.get_data() which uses its own offset to return the packets buffer from its offset. See Packet.Layer.
/// when "owned_buffer" owns the layers data (Buffer is a wrapper around std.ArrayList(u8)), it just uses the pub methods from Buffer to coordinate data retrival and modification, the same way Packet does for the Layers which it owns.
/// when you init a layer with a LayerOwner{.owned_buffer = ...}, it stores a copy of the union, which means you can use the same layer owner for multiple instances of created layers. You don't need to call deinit directly on this LayerOwner but rememeber to call deinit on the layer you've created (which has the logic to perform the free properly) to avoid a leak.
pub const LayerOwner = union(enum) {
    packet_layer: *Packet.Layer,
    owned_buffer: Buffer,

    pub fn get_data(self: *const LayerOwner) []u8 {
        return switch (self.*) {
            .packet_layer => |layer| layer.get_data(),
            .owned_buffer => |buffer| buffer.buffer.items,
        };
    }

    /// to be removed
    fn get_allocator(self: *LayerOwner) Allocator {
        switch (self.*) {
            .packet_layer => |layer| {
                return layer.packet.layer_allocator;
            },
            .owned_buffer => |*buffer| {
                return buffer.allocator;
            },
        }
    }

    // TODO: Rename to extend_layer
    pub fn extend_payload(self: *LayerOwner, offset: usize, extend_len: usize) ![]u8 {
        var buf: []u8 = undefined;
        switch (self.*) {
            .packet_layer => |layer| {
                buf = try layer.packet.extend_layer(layer, offset, extend_len); // TODO: extend at offset instead
            },
            .owned_buffer => |*buffer| {
                buf = try buffer.extend(offset, extend_len);
            },
        }

        @memset(buf, 0);

        return buf;
    }

    // TODO: Rename to shorten_layer
    pub fn shorten_payload(self: *LayerOwner, offset: usize, shorten_len: usize) !void {
        switch (self.*) {
            .packet_layer => |layer| {
                try layer.packet.shorten_layer(layer, offset, shorten_len);
            },
            .owned_buffer => |*buffer| {
                try buffer.shorten(offset, shorten_len);
            },
        }
    }

    pub fn is_packet_owned(self: *LayerOwner) bool {
        switch (self.*) {
            .packet_layer => {
                return true;
            },
            .owned_buffer => {
                return false;
            },
        }
    }

    pub fn deinit(self: *LayerOwner) void {
        switch (self.*) {
            .packet_layer => {
                return; // Layer in packet - don't free
            },
            .owned_buffer => |*buffer| {
                return buffer.deinit(); // standalone layer - it is mutable by default
            },
        }
    }
};

pub const TLVOwner = union(enum) {
    layer: *LayerOwner,
    owned_buffer: Buffer,

    pub fn get_data(self: *TLVOwner) []u8 {
        return switch (self.*) {
            .layer => |layer| layer.get_data(),
            .owned_buffer => |buffer| buffer.buffer.items,
        };
    }

    pub fn extend_buffer(self: *TLVOwner, offset: usize, extend_len: usize) ![]u8 {
        var buf: []u8 = undefined;
        switch (self.*) {
            .layer => |layer| {
                buf = try layer.extend_payload(offset, extend_len); // TODO: extend at offset instead
            },
            .owned_buffer => |*buffer| {
                buf = try buffer.extend(offset, extend_len);
            },
        }

        @memset(buf, 0);

        return buf;
    }

    pub fn shorten_buffer(self: *TLVOwner, offset: usize, shorten_len: usize) !void {
        switch (self.*) {
            .layer => |layer| {
                try layer.shorten_payload(offset, shorten_len);
            },
            .owned_buffer => |*buffer| {
                try buffer.shorten(offset, shorten_len);
            },
        }
    }

    pub fn is_layer_owned(self: *TLVOwner) bool {
        switch (self.*) {
            .layer => {
                return true;
            },
            .owned_buffer => {
                return false;
            },
        }
    }

    pub fn deinit(self: *TLVOwner) void {
        switch (self.*) {
            .layer => {
                return; // TLV in Layer - don't free
            },
            .owned_buffer => |*buffer| {
                return buffer.deinit(); // standalone layer - it is mutable by default
            },
        }
    }
};
