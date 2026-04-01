const Packet = @import("Packet.zig");
const Allocator = @import("std").mem.Allocator;

pub const AllocatorOwned = struct {
    allocator: Allocator,
    data: []u8,

    pub fn deinit(self: *AllocatorOwned) void {
        self.allocator.free(self.data);
    }
};

/// choose who owns this layers data
pub const LayerOwner = union(enum) {
    packet_layer: *Packet.Layer,
    allocator_owned: AllocatorOwned,
};
