const std = @import("std");
const Packet = @import("Packet.zig").Packet;
const LayerOwner = @import("Layer.zig").LayerOwner;
const LayerError = @import("ProtocolHelpers.zig").LayerError;

const Allocator = std.mem.Allocator;

pub const ApplicationLayer = struct {
    owner: LayerOwner,
    data: []u8,

    pub fn init(owner: LayerOwner) LayerError!ApplicationLayer {
        switch (owner) {
            .packet_layer => return ApplicationLayer{ .owner = owner, .data = undefined },
            .allocator => {
                const self = ApplicationLayer{ .owner = owner, .data = try owner.allocator.alloc(u8, 0) };
                return self;
            },
        }
    }

    /// Get slice of data (header + payload)
    pub fn get_data(self: *ApplicationLayer) []u8 {
        return self.data;
    }

    pub fn to_string(self: *ApplicationLayer, allocator: Allocator) []const u8 {
        _ = allocator;
        return self.data;
    }

    pub fn deinit(self: *ApplicationLayer, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};
