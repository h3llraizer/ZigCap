const std = @import("std");
const LayerIface = @import("LayerIface.zig").Layer;
const Packet = @import("Packet.zig").Packet;

const print = std.debug.print;
const Allocator = std.mem.Allocator;

/// Do NOT change the offset and lengths manually - there is no need to. They are public by default but let the Packet manage these members
/// TODO: Rename or make out of scope
pub const Layer = struct {
    offset: usize, // absolute offset in the owning packet
    length: usize,
    layer_iface: LayerIface,
    packet: *Packet,
    next_layer: ?*Layer = null,
    prev_layer: ?*Layer = null,

    pub fn init(offset: usize, length: usize, layer_iface: LayerIface, packet: *Packet) Layer {
        return Layer{
            .offset = offset,
            .length = length,
            .layer_iface = layer_iface,
            .packet = packet,
        };
    }

    /// Returns data from first byte of header to last byte of packet
    pub fn get_data(self: *Layer) []u8 {
        return self.packet.buffer.buffer.items[self.offset..];
    }

    pub fn print_meta(self: *Layer) void {
        print("{any}: offset: {} length: {}\n", .{
            self.layer_iface.get_protocol(),
            self.offset,
            self.length,
        });
    }

    /// to_string returns immut slice. caller free memory using the allocator provided
    pub fn to_string(self: *Layer, allocator: Allocator) []const u8 {
        const str = self.layer_iface.to_string(allocator);
        return str;
    }
};
