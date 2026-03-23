const std = @import("std");
const print = std.debug.print;
const LinkLayerProtocols = @import("Layer.zig").LinkLayerProtocols;

/// A Packet which is captured from the wire or is to be transmitted on the wire
pub const WirePacket = struct {
    timestamp_s: i64,
    timestamp_ms: i64,
    raw_data: []u8,
    raw_len: u32,
    link_type: LinkLayerProtocols,
    additional: ?*anyopaque, // Optional additional member to store any data of the developers choosing

    pub fn init(ts_usec: i64, ts_sec: i64, raw: []const u8, len: c_uint, link_type: LinkLayerProtocols, allocator: std.mem.Allocator) !*WirePacket {
        var p: *WirePacket = try allocator.create(WirePacket);

        p.timestamp_ms = ts_usec;

        p.timestamp_s = ts_sec;

        p.raw_len = @intCast(len);

        p.raw_data = try allocator.alloc(u8, p.raw_len);

        p.link_type = link_type;

        @memmove(p.raw_data, raw[0..p.raw_len]);

        return p;
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
