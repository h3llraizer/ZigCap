const std = @import("std");
const Packet = @import("Packet.zig").Packet;
const PacketLayer = @import("PacketLayer.zig").Layer;
const LayerOwner = @import("Owner.zig").LayerOwner;
const LayerError = @import("ProtocolEnums.zig").LayerError;
const Layer = @import("LayerIface.zig").Layer;
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;

const initLayerFromSlice = @import("LayerIface.zig").initFromSlice;

const print = std.debug.print;
const Allocator = std.mem.Allocator;

pub const ApplicationLayer = struct {
    owner: LayerOwner,
    const Protocol = tcp_ip_protocol.generic;

    pub fn init(allocator: Allocator) LayerError!ApplicationLayer {
        const owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

        const self = ApplicationLayer{ .owner = owner };

        return self;
    }

    pub fn initFromSlice(slice: []u8, allocator: Allocator) LayerError!ApplicationLayer {
        const hdr_len = slice.len;

        return try initLayerFromSlice(slice, ApplicationLayer, hdr_len, slice.len, hdr_len, allocator);
    }

    pub fn get_next_layer_type(self: *const ApplicationLayer, layer: *PacketLayer) LayerError!?Layer {
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

    pub fn set_payload(self: *ApplicationLayer, data: []const u8) (LayerError || Allocator.Error)!void {
        const buf = try self.owner.extend_layer(0, data.len);
        @memmove(buf, data);
    }

    pub fn delete_payload_data(self: *ApplicationLayer) Allocator.Error!void {
        try self.owner.shorten_layer(self.get_data().len, self.get_data().len);
    }

    pub fn validate_layer(self: *ApplicationLayer) void {
        _ = self;
    }

    fn return_raw(bytes: []const u8, allocator: Allocator) ![]const u8 {
        const new_lines = bytes.len / 16;

        var buf = try allocator.alloc(u8, bytes.len + new_lines);

        var idx: usize = 0;

        for (bytes, 0..) |byte, i| {
            buf[idx] =
                if (byte >= 32 and byte <= 126)
                    byte
                else
                    '.';
            idx += 1;

            if ((i + 1) % 16 == 0) {
                buf[idx] = '\n';
                idx += 1;
            }
        }

        return buf[0..idx];
    }

    pub fn to_string(self: *const ApplicationLayer, allocator: Allocator) []const u8 {
        const data = self.get_data();

        const str = return_raw(data, allocator) catch {
            return "Error executing to_string\n";
        };

        return str;
    }

    pub fn get_protocol(self:ApplicationLayer) tcp_ip_protocol {
        _ = self;
        return ApplicationLayer.Protocol;
    }

    pub fn deinit(self: *ApplicationLayer) void {
        self.owner.deinit();
    }
};
