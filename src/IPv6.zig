const std = @import("std");
const print = std.debug.print;

const LayerProtocols = @import("Layer.zig").LayerProtocols;

pub const HeaderSize = 40;

pub const IPv6Header = packed struct {
    version_traffic_flow: u32, // 4-bit version, 8-bit traffic class, 20-bit flow label
    payload_length: u16, // Length of payload in bytes (excluding header)
    next_header: u8, // Identifies next header type (TCP=6, UDP=17, etc.)
    hop_limit: u8, // Decremented at each hop

    // Source address (128 bits) as individual bytes
    src_addr_0: u8,
    src_addr_1: u8,
    src_addr_2: u8,
    src_addr_3: u8,
    src_addr_4: u8,
    src_addr_5: u8,
    src_addr_6: u8,
    src_addr_7: u8,
    src_addr_8: u8,
    src_addr_9: u8,
    src_addr_10: u8,
    src_addr_11: u8,
    src_addr_12: u8,
    src_addr_13: u8,
    src_addr_14: u8,
    src_addr_15: u8,

    // Destination address (128 bits) as individual bytes
    dst_addr_0: u8,
    dst_addr_1: u8,
    dst_addr_2: u8,
    dst_addr_3: u8,
    dst_addr_4: u8,
    dst_addr_5: u8,
    dst_addr_6: u8,
    dst_addr_7: u8,
    dst_addr_8: u8,
    dst_addr_9: u8,
    dst_addr_10: u8,
    dst_addr_11: u8,
    dst_addr_12: u8,
    dst_addr_13: u8,
    dst_addr_14: u8,
    dst_addr_15: u8,
};

pub const IPv6Layer = struct {
    hdr: *align(1) IPv6Header,
    const Protocol = LayerProtocols{ .Network = .IPv6 };

    pub fn init(raw: *[HeaderSize]u8, allocator: std.mem.Allocator) !*IPv6Layer {
        const i = try allocator.create(IPv6Layer);
        i.hdr = @ptrCast(raw);
        return i;
    }

    pub fn to_string(self: *IPv6Layer) void {
        inline for (@typeInfo(IPv6Header).@"struct".fields) |f| {
            print("{s} : {any} : ", .{
                f.name,
                f.type,
            });
            if (f.type == u16) {
                print("{d}\n", .{std.mem.bigToNative(f.type, @field(self.hdr, f.name))});
            } else {
                print("{d}\n", .{@field(self.hdr, f.name)});
            }
        }
    }

    pub fn get_protocol(self: *IPv6Layer) LayerProtocols {
        _ = self;
        return IPv6Layer.Protocol;
    }

    pub fn deinit(self: *IPv6Layer, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};
