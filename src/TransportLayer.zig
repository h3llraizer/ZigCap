const std = @import("std");
const TCP = @import("TCP.zig");
const UDP = @import("UDP.zig");

pub const TransportLayer = union(enum) {
    tcp: TCP.TCPLayer,
    udp: UDP.UDPLayer,

    pub fn get_src_port(self: *const TransportLayer) u16 {
        return switch (self.*) {
            inline else => |*layer| layer.get_immutable_header().get_src_port(),
        };
    }

    pub fn get_dst_port(self: *const TransportLayer) u16 {
        return switch (self.*) {
            inline else => |*layer| layer.get_immutable_header().get_dst_port(),
        };
    }
};
