const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;
const Packet = @import("Packet.zig");
const panic = std.debug.panic;

pub const RawData = union(enum) {
    mutable: []u8,
    immutable: []const u8,

    pub fn is_mutable(self: RawData) bool {
        switch (self) {
            .mutable => return true,
            .immutable => return false,
        }
    }

    pub fn get_mutable(self: RawData) []u8 {
        if (self.is_mutable()) {
            return self.mutable;
        } else {
            panic("RawData is not mutable.", .{});
        }
    }

    pub fn get_len(self: RawData) usize {
        return self.get_immutable().len;
    }

    pub fn isSubslice(self: RawData, sub: []const u8) bool {
        const main = self.get_immutable();
        const main_start = @intFromPtr(main.ptr);
        const main_end = main_start + main.len;
        const sub_start = @intFromPtr(sub.ptr);
        const sub_end = sub_start + sub.len;

        return sub_start >= main_start and sub_end <= main_end;
    }

    pub fn subsliceOffset(self: RawData, sub: []const u8) ?usize {
        const main = self.get_immutable();
        const main_start = @intFromPtr(main.ptr);
        const main_end = main_start + main.len;
        const sub_start = @intFromPtr(sub.ptr);
        const sub_end = sub_start + sub.len;

        // Check if sub is within main's memory range
        if (sub_start >= main_start and sub_end <= main_end) {
            // Calculate offset in bytes
            const offset_bytes = sub_start - main_start;
            // Verify it's a valid element offset (no partial elements)
            // For u8, offset_bytes is the element offset since each element is 1 byte
            return @intCast(offset_bytes);
        }

        return null;
    }

    pub fn get_immutable(self: RawData) []const u8 {
        switch (self) {
            .mutable => {
                //                print("getting immutable data.\n", .{});
                const sub: []const u8 = self.mutable;
                return sub;
            },
            .immutable => return self.immutable,
        }
    }

    pub fn get_slice(self: RawData, offset: usize, length: usize) RawData {
        return switch (self) {
            inline else => |slice, tag| {
                // bounds check once
                if (offset > slice.len) {
                    panic("out of bounds. offset {} exceeds data length {}\n", .{ offset, slice.len });
                }
                if (length > slice.len) {
                    panic("out of bounds. length {} exceeds data length {}\n", .{ length, slice.len });
                }

                //               print("getting slice.\n", .{});

                //                const sub = slice[offset .. offset + length];
                const sub = slice[offset..length];
                return switch (tag) {
                    .mutable => RawData{ .mutable = sub },
                    .immutable => RawData{ .immutable = sub },
                };
            },
        };
    }

    pub fn get_slice_from_offset(self: RawData, offset: usize) RawData {
        return switch (self) {
            inline else => |slice, tag| {
                // bounds check once
                if (offset > slice.len) {
                    panic("out of bounds. offset {} exceeds data length {}\n", .{ offset, slice.len });
                }

                const sub = slice[offset..];

                return switch (tag) {
                    .mutable => RawData{ .mutable = sub },
                    .immutable => RawData{ .immutable = sub },
                };
            },
        };
    }
};
