const print = @import("std").debug.print;
const Packet = @import("Packet.zig");
const Allocator = @import("std").mem.Allocator;
const Buffer = @import("Buffer.zig").Buffer;

/// The Layer is either owned by Packet or Buffer ("owned_buffer")
/// When owned by packet_layer, the data is retrieved and modified via the Layers e.g. get_data() calls Layer.get_data() which uses its own offset to return the packets buffer from its offset. See Packet.Layer.
/// when "owned_buffer" owns the layers data (Buffer is a wrapper around std.ArrayList(u8)), it just uses the pub methods from Buffer to coordinate data retrival and modification, the same way Packet does for the Layers which it owns.
/// when you init a layer with a LayerOwner{.owned_buffer = ...}, it stores a copy of the union, which means you can use the same layer owner for multiple instances of created layers. You don't need to call deinit directly on this LayerOwner but rememeber to call deinit on the layer you've created (which has the logic to perform the free properly) to avoid a leak.
pub const LayerOwner = union(enum) {
    packet_layer: *Packet.Layer,
    owned_buffer: Buffer,

    //TODO: add common method

    pub fn get_data(self: *const LayerOwner) []u8 {
        return switch (self.*) {
            .packet_layer => |layer| layer.get_data(),
            .owned_buffer => |buffer| buffer.buffer.items,
        };
    }

    /// gets the allocator which the owner provides - this is used for creating structs to aid managing the data the protocol has beyound it's standard/base header
    /// e.g. DNS has variable length data in the form of queries and answers (RRData), the owners allocator will be used to create the Query and ResponseRecord structs to parse and potentially mutate
    pub fn get_allocator(self: *LayerOwner) Allocator {
        switch (self.*) {
            .packet_layer => |layer| {
                return layer.packet.layer_allocator;
            },
            .owned_buffer => |*buffer| {
                return buffer.allocator;
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
