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
                if (offset + length > slice.len) {
                    panic("out of bounds. offset {} + length {} exceeds data length {}\n", .{ offset, length, slice.len });
                }

                //               print("getting slice.\n", .{});

                const sub = slice[offset .. offset + length];

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

pub const Mutable = struct {
    raw_data: []u8,
    allocator: ?Allocator,

    pub fn init(allocator: Allocator, initial_len: usize) !Mutable {
        return Mutable{ .raw_data = try allocator.alloc(u8, initial_len), .allocator = allocator };
    }

    pub fn get_slice(self: *Mutable, offset: usize, len: usize) ![]u8 {
        return self.raw_data[offset..len];
    }

    pub fn deinit(self: *Mutable) void {
        if (self.allocator) |allocator| {
            allocator.free(self.raw_data);
        }
    }

    pub fn copy_from(self: *Mutable, data: []u8) !void {
        if (self.data.len < data.len) {
            const new_buf = try self.allocator.realloc(self.data, data.len);
            self.data = new_buf;
        }

        @memmove(self.data, data);

        //      print("data in allocator: {x}\n", .{self.data});
    }
};

pub const Immutable = struct {
    raw_data: []const u8,

    pub fn from_mutable(mutable: Mutable) Immutable {
        return Immutable{ .raw_data = mutable.raw_data };
    }

    pub fn get_slice(self: *const Immutable, offset: usize, len: usize) ![]const u8 {
        return self.raw_data[offset..len];
    }
};

pub const LayerOwned = struct { // layers use this when they are not in a Packet
    raw_data: RawData,

    pub fn init(allocator: Allocator, initial_len: usize) LayerOwned {
        const self = LayerOwned{ .raw_data = .{ .mutable = .init(allocator, initial_len) } };
        return self;
    }

    pub fn deinit(self: *LayerOwned) void {
        self.allocator.free(self.data);
    }
};

pub const PacketOwned = struct {
    packet_layer: *Packet.Layer,
};

pub const LayerData = union(enum) { // concrete layers store this
    packet_layer: *Packet.Layer, // layer gets data from packet_layer.get_data() - RawData is returned, layer checks mutability
    layer_owned: LayerOwned, // lets gets data from layer_owned.data
};

pub const PacketData = union(enum) { // Packet stores this
    data: RawData,
};
