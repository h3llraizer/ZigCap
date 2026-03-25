const std = @import("std");
const print = std.debug.print;
const LinkLayerProtocols = @import("Layer.zig").LinkLayerProtocols;

/// A Packet which is captured from the wire or is to be transmitted on the wire
pub const WirePacket = struct {
    timestamp_s: i64,
    timestamp_ms: i64,
    raw_data: []u8,
    link_type: LinkLayerProtocols,

    pub fn init(ts_usec: i64, ts_sec: i64, raw: []u8, link_type: LinkLayerProtocols) WirePacket {
        const self: WirePacket = WirePacket{
            .timestamp_ms = ts_usec,

            .timestamp_s = ts_sec,

            .raw_data = raw,

            .link_type = link_type,
        };

        return self;
    }

    pub fn slice(self: *WirePacket, offset: usize, len: usize) ![]const u8 {
        if (offset > self.raw_len or offset > len or len > self.raw_len) {
            return error.InvalidBounds;
        }

        return self.raw_data[offset..len];
    }

    pub fn to_string(self: WirePacket) void {
        print("Timestamp_s: {any} Timestamp_ms: {any} Raw_data (ptr): {any} raw_len: {any}\n", .{ self.timestamp_s, self.timestamp_ms, self.raw_data.ptr, self.raw_len });
    }

    pub fn print_bytes(self: WirePacket, len: u32) void {
        const bytes: []const u8 = @ptrCast(self.raw_data[0..len]);
        for (bytes) |b| {
            std.debug.print("{x} ", .{b});
        }
        std.debug.print("\n", .{});
    }

    pub fn print_raw(self: *WirePacket) void {
        print("{x}\n", .{self.raw_data});
        print("len {d}\n", .{self.raw_data.len});
    }

    pub fn deinit(self: *WirePacket, allocator: std.mem.Allocator) void {
        allocator.free(self.raw_data);
        allocator.destroy(self);
    }
};
