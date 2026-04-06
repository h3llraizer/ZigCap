const std = @import("std");
const Packet = @import("Packet.zig").Packet;
const Layer = @import("Packet.zig").Layer;
const LayerOwner = @import("Layer.zig").LayerOwner;
const LayerError = @import("ProtocolHelpers.zig").LayerError;
const LayerImpl = @import("ProtocolHelpers.zig").LayerImpl;

const print = std.debug.print;

const Allocator = std.mem.Allocator;

pub const ApplicationLayer = struct {
    owner: LayerOwner,

    pub fn init(owner: LayerOwner) LayerError!ApplicationLayer {
        switch (owner) {
            .packet_layer => {
                return ApplicationLayer{
                    .owner = owner,
                };
            },
            .allocator_owned => {
                const self = ApplicationLayer{ .owner = owner };
                // Allocate directly into the struct's data field
                //self.owner.allocator_owned.data = try self.owner.allocator_owned.allocator.alloc(u8, MinHeaderLength);

                //var header = ApplicationHeader.init_default();
                //@memcpy(self.owner.allocator_owned.data[0..MinHeaderLength], std.mem.asBytes(&header));

                return self;
            },
        }
    }

    pub fn get_next_layer_type(self: *const ApplicationLayer, layer: *Layer) !?LayerImpl {
        _ = self;
        _ = layer;
        return null;
    }

    /// Get slice of data (header + payload)
    pub fn get_data(self: *const ApplicationLayer) []u8 {
        switch (self.owner) {
            .packet_layer => {
                //print("getting self ({*}) data from packet\n", .{self});
                const app_data = self.owner.packet_layer.get_data();
                return app_data;
            },
            else => {
                //print("getting self ({*}) data from allocator\n", .{self});
                return self.owner.allocator_owned.data;
            },
        }
    }

    pub fn get_payload(self: *ApplicationLayer) ?[]const u8 {
        return self.get_data();
    }

    pub fn to_string(self: *const ApplicationLayer, allocator: Allocator) []const u8 {
        _ = allocator;
        return self.get_data();
    }

    pub fn deinit(self: *ApplicationLayer, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};
