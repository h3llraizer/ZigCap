const print = @import("std").debug.print;
const Packet = @import("Packet.zig");
const Allocator = @import("std").mem.Allocator;

/// soon to be renamed to SelfOwned
pub const AllocatorOwned = struct {
    allocator: Allocator,
    data: []u8,

    pub fn copy_from(self: *AllocatorOwned, data: []u8) !void {
        if (self.data.len < data.len) {
            const new_buf = try self.allocator.realloc(self.data, data.len);
            self.data = new_buf;
        }

        @memmove(self.data, data);

        print("data in allocator: {x}\n", .{self.data});
    }

    pub fn deinit(self: *AllocatorOwned) void {
        self.allocator.free(self.data);
    }
};

/// choose who owns this layers data
pub const LayerOwner = union(enum) {
    packet_layer: *Packet.Layer,
    allocator_owned: AllocatorOwned,
    immutable_layer: ImmutableLayer,
};

pub const MutableLayer = struct {
    raw_data: []u8,
    allocator: Allocator,
};

pub const ImmutableLayer = struct {
    raw_data: []const u8,
};

pub const LayerVariant = union(enum) {
    mutable: MutableLayer,
    immutable: ImmutableLayer,
    packet_layer: *Packet.Layer,
};
