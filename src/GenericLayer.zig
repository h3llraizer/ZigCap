const std = @import("std");
const Packet = @import("Packet.zig").Packet;
const Layer = @import("Packet.zig").Layer;
const LayerOwner = @import("Layer.zig").LayerOwner;
const LayerError = @import("ProtocolHelpers.zig").LayerError;
const LayerImpl = @import("ProtocolHelpers.zig").LayerImpl;
const LayerProtocols = @import("ProtocolHelpers.zig").LayerProtocols;

const print = std.debug.print;

const Allocator = std.mem.Allocator;

const RawData = @import("RawData.zig").RawData;

pub const ApplicationLayer = struct {
    owner: LayerOwner,
    const Protocol = LayerProtocols{ .Application = .Generic };

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
            .immutable_layer => return {
                return ApplicationLayer{ .owner = owner };
            },
        }
    }

    pub fn get_next_layer_type(self: *const ApplicationLayer, layer: *Layer) !?LayerImpl {
        _ = self;
        _ = layer;
        return null;
    }

    /// Get slice of data (header + payload)
    pub fn get_data(self: *const ApplicationLayer) RawData {
        switch (self.owner) {
            .packet_layer => {
                return self.owner.packet_layer.get_data();
            },
            .allocator_owned => {
                //print("getting self ({*}) data from allocator\n", .{self});
                return RawData{ .mutable = self.owner.allocator_owned.data };
            },
            .immutable_layer => {
                return RawData{ .immutable = self.owner.immutable_layer.raw_data };
            },
        }
    }

    pub fn get_payload(self: *ApplicationLayer) ?[]const u8 {
        return self.get_data().get_immutable();
    }

    pub fn to_string(self: *const ApplicationLayer, allocator: Allocator) []const u8 {
        _ = allocator;
        return self.get_data().get_immutable();
    }

    pub fn get_protocol(self: *ApplicationLayer) LayerProtocols {
        _ = self;
        return ApplicationLayer.Protocol;
    }

    pub fn deinit(self: *ApplicationLayer, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};
