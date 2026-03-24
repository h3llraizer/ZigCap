const std = @import("std");
const Packet = @import("Packet.zig").Packet;
const LayerProtocols = @import("Layer.zig").LayerProtocols;
const Layer = @import("Layer.zig").Layer;

const Allocator = std.mem.Allocator;

pub const GenericLayer = struct {
    data: []u8, // UDP header + payload
    const Protocol = LayerProtocols{ .Generic = .Generic };

    pub fn init(data: []u8, protocol: LayerProtocols) GenericLayer {
        return GenericLayer{ .data = data, .protocol = protocol };
    }

    /// Get slice of data (header + payload)
    pub fn get_data(self: *GenericLayer) []u8 {
        return self.data;
    }

    /// Get the payload (data after UDP header)
    pub fn get_payload(self: *GenericLayer) []u8 {
        return self.data;
    }

    pub fn to_string(self: *GenericLayer, allocator: Allocator) []const u8 {
        _ = allocator;
        return self.data;
    }

    pub fn parse_next_layer(self: *GenericLayer, buffer_allocator: Allocator, layer_allocator: Allocator) ?*Layer {
        const packet_layer: *Layer = layer_allocator.create(Layer) catch return null;
        _ = buffer_allocator;
        _ = &self;
        _ = packet_layer;

        return null;
    }

    pub fn set_protocol(self: *GenericLayer, protocol: LayerProtocols) void {
        self.protocol = protocol;
    }

    pub fn get_protocol(self: *GenericLayer) LayerProtocols {
        return self.protocol;
    }

    pub fn deinit(self: *GenericLayer, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};
