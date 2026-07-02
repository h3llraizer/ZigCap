const std = @import("std");

const Allocator = @import("std").mem.Allocator;

const IPv4Address = @import("IPv4.zig").IPv4Address;
const IPv6Address = @import("IPv6.zig").IPv6Address;

pub const IPAddress = union(enum) {
    ipv4: IPv4Address,
    ipv6: IPv6Address,

    pub fn eql(self: IPAddress, other: IPAddress) bool {
        return switch (self) {
            .ipv4 => |a| switch (other) {
                .ipv4 => |b| a.to_u32() == b.to_u32(),
                .ipv6 => false,
            },
            .ipv6 => |a| switch (other) {
                .ipv6 => |b| std.mem.eql(u8, &a.array, &b.array),
                .ipv4 => false,
            },
        };
    }

    pub fn to_string(self: IPAddress, allocator: Allocator) Allocator.Error![]u8 {
        return switch (self) {
            inline else => |ip| try ip.to_string(allocator),
        };
    }
};
