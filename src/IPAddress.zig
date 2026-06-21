const Allocator = @import("std").mem.Allocator;

const IPv4Address = @import("IPv4.zig").IPv4Address;
const IPv6Address = @import("IPv6.zig").IPv6Address;

pub const IPAddress = union(enum) {
    ipv4: IPv4Address,
    ipv6: IPv6Address,

    pub fn to_string(self: IPAddress, allocator: Allocator) Allocator.Error![]u8 {
        return switch (self) {
            inline else => |ip| try ip.to_string(allocator),
        };
    }
};
