const std = @import("std");
const Packet = @import("Packet.zig").Packet;

pub const GenericLayer = struct {
    payload: []u8,
    packet: *Packet,

    pub fn init(raw: []u8, allocator: std.mem.Allocator) ?*GenericLayer {
        const self = allocator.create(GenericLayer) orelse return null;
        self.payload = raw;
        return self;
    }
};
