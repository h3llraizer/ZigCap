const print = @import("std").debug.print;
const Packet = @import("Packet.zig");
const Allocator = @import("std").mem.Allocator;
const Buffer = @import("Buffer.zig").Buffer;

/// The Layer is either owned by Packet or Buffer ("owned_buffer")
/// When owned by packet_layer, the data is retrieved and modified via the Layers e.g. get_data() calls Layer.get_data() which uses its own offset to return the packets buffer from its offset. See Packet.Layer.
/// when "owned_buffer" owns the layers data (Buffer is a wrapper around std.ArrayList(u8)), it just uses the pub methods from Buffer to coordinate data retrival and modification, the same way Packet does for the Layers which it owns.
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
};
