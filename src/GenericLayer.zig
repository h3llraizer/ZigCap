const std = @import("std");
const Packet = @import("Packet.zig").Packet;
const Layer = @import("Packet.zig").Layer;
const LayerOwner = @import("Owner.zig").LayerOwner;
const LayerError = @import("ProtocolEnums.zig").LayerError;
const LayerIface = @import("LayerIface.zig").LayerIface;
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;

const print = std.debug.print;

const Allocator = std.mem.Allocator;

pub const ApplicationLayer = struct {
    owner: LayerOwner,
    const Protocol = tcp_ip_protocol.generic;

    pub fn init(owner: LayerOwner) LayerError!ApplicationLayer {
        switch (owner) {
            .packet_layer => {
                return ApplicationLayer{
                    .owner = owner,
                };
            },
            .owned_buffer => {
                const self = ApplicationLayer{ .owner = owner };

                return self;
            },
        }
    }

    pub fn get_next_layer_type(self: *const ApplicationLayer, layer: *Layer) LayerError!?LayerIface {
        _ = self;
        _ = layer;
        return null;
    }

    /// Get slice of data (header + payload)
    pub fn get_data(self: *const ApplicationLayer) []u8 {
        return self.owner.get_data();
    }

    pub fn get_payload(self: *ApplicationLayer) []const u8 {
        const payload: []const u8 = self.get_data();
        return payload;
    }

    pub fn set_payload(self: *ApplicationLayer, data: []const u8) Allocator.Error!void {
        switch (self.owner) {
            .packet_layer => |layer| {
                const buf = try layer.packet.extend_layer(layer, 0, data.len);
                @memmove(buf, data);
            },
            .owned_buffer => |*buffer| { // Capture as pointer
                try buffer.buffer.appendSlice(buffer.allocator, data);
            },
        }
    }

    pub fn delete_payload_data(self: *ApplicationLayer) Allocator.Error!void {

        //        const raw_len = raw_data.get_immutable().len;

        switch (self.owner) {
            .packet_layer => |layer| {
                try layer.packet.shorten_layer(layer, 0, self.get_data().len);
                //                try layer.packet.remove_data(layer, raw_data);
            },
            .owned_buffer => |*buffer| {
                try buffer.shorten(0, self.get_data().len);
            },
        }
    }

    pub fn validate_layer(self: *ApplicationLayer) void {
        _ = self;
    }

    pub fn to_string(self: *const ApplicationLayer, allocator: Allocator) []const u8 {
        const data = self.get_data();
        return std.fmt.allocPrint(allocator, "Application Layer: {s}\n", .{
            data,
        }) catch return "";
    }

    pub fn get_protocol(self: *ApplicationLayer) tcp_ip_protocol {
        _ = self;
        return ApplicationLayer.Protocol;
    }

    pub fn deinit(self: *ApplicationLayer) void {
        self.owner.deinit();
    }
};
