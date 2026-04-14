const std = @import("std");
const Allocator = std.mem.Allocator;

/// Wrapper around std.ArrayList(u8) with public methods to faciliate easier work on Packet and Layer data
pub const Buffer = struct {
    buffer: std.array_list.Aligned(u8, std.mem.Alignment.@"2"),
    allocator: Allocator,

    /// creates an empty buffer.
    pub fn init_empty(allocator: Allocator) Buffer {
        return Buffer{ .buffer = .empty, .allocator = allocator };
    }

    /// creates a buffer by taking and existing slice and takes ownership of that slice
    pub fn init(raw: []u8, allocator: Allocator) !Buffer {
        const self = Buffer{ .buffer = .fromOwnedSlice(raw), .allocator = allocator };

        return self;
    }

    /// takes slice offset and length in THIS buffer and appends it to the dst buffer
    pub fn cutRange(self: *Buffer, dst: *Buffer, start: usize, len: usize) !void {
        const end = start + len;
        std.debug.assert(end <= self.buffer.items.len);

        const slice = self.buffer.items[start..end];

        // 1. Append to destination
        try dst.buffer.appendSlice(dst.allocator, slice);

        try self.shorten(start, len);
    }

    /// takes slice from another Buffer and inserts into index of offset
    pub fn cutFrom(self: *Buffer, src: *Buffer, start: usize, len: usize, offset: usize) !void {
        const end = start + len;
        std.debug.assert(end <= src.buffer.items.len);

        const slice: []u8 = try src.buffer.toOwnedSlice(src.allocator);

        try self.buffer.insertSlice(self.allocator, offset, slice);

        self.buffer.shrinkAndFree(self.allocator, self.buffer.items.len);
    }

    /// extends the buffer from the offset by length
    pub fn extend(self: *Buffer, offset: usize, length: usize) ![]u8 {
        const slice = try self.buffer.addManyAt(self.allocator, offset, length);
        self.buffer.shrinkAndFree(self.allocator, self.buffer.items.len);
        return slice;
    }

    /// shortens the buffer at the offset by length
    pub fn shorten(self: *Buffer, offset: usize, length: usize) !void {
        const end = offset + length;
        std.debug.assert(end <= self.buffer.items.len);

        const dest = self.buffer.items[offset..];
        const src = self.buffer.items[end..];

        @memmove(dest[0..src.len], src); // shift down

        const new_len = self.buffer.items.len - length;

        self.buffer.shrinkAndFree(self.allocator, new_len); // shrink to avoid any leftover memory
        //self.buffer.items.len -= length;
    }

    /// returns non owning slice from the current buffer using offset and length
    pub fn get_immutable_slice(self: *Buffer, offset: usize, length: usize) []const u8 {
        return self.buffer.items[offset .. offset + length];
    }

    /// returns slices
    pub fn get_mutable_slice(self: *Buffer, offset: usize, length: usize) []u8 {
        return self.buffer.items[offset .. offset + length];
    }
};
