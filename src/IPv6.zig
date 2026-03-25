const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const LayerProtocols = @import("Layer.zig").LayerProtocols;
const Layer = @import("Layer.zig").Layer;
const LayerError = @import("Layer.zig").LayerError;

const TransportProtocol = @import("Layer.zig").TransportProtocols;

const TCPLayer = @import("TCP.zig").TCPLayer;
const UDPLayer = @import("UDP.zig").UDPLayer;

pub const HeaderSize = 40;

pub const IPv6Header = packed struct {
    version_traffic_flow: u32, // 4-bit version, 8-bit traffic class, 20-bit flow label
    data_length: u16, // Length of data in bytes (excluding header)
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
    data: []u8,
    const Protocol = LayerProtocols{ .Network = .IPv6 };

    pub fn init(buffer: []u8) LayerError!IPv6Layer {
        if (buffer.len < HeaderSize) return LayerError.BufferTooSmall;

        // Verify alignment (optional)
        const alignment = @alignOf(IPv6Header);
        const addr = @intFromPtr(buffer.ptr);
        if (addr % alignment != 0) {
            return Layer.LayerError.MisalignedBuffer;
        }

        return IPv6Layer{ .data = buffer };
    }

    pub fn to_string(self: *IPv6Layer, allocator: Allocator) []const u8 {
        _ = self;
        _ = allocator;
        return "";
    }

    /// get slice of data (hdr+payload)
    pub fn get_data(self: *IPv6Layer) []u8 {
        return self.data;
    }

    /// return mutable slice of the payload
    pub fn get_payload(self: *IPv6Layer) []u8 {
        return self.data[20..];
    }

    pub fn get_next_layer_type(self: *IPv6Layer) LayerProtocols {
        const transport_type: TransportProtocol = self.get_transport_type() catch return LayerProtocols{ .Transport = .Generic };

        switch (transport_type) {
            TransportProtocol.TCP => {
                return LayerProtocols{ .Transport = .TCP };
            },
            TransportProtocol.UDP => {
                return LayerProtocols{ .Transport = .UDP };
            },
            else => {
                print("Unhandled Transport layer.\n", .{});
                return LayerProtocols{ .Transport = .Generic };
            },
        }

        return LayerProtocols{ .Transport = .Generic };
    }

    pub fn get_transport_type(self: *IPv6Layer) !TransportProtocol {
        const hdr = self.get_header();
        return try std.meta.intToEnum(TransportProtocol, hdr.next_header);
    }

    pub fn get_protocol(self: *IPv6Layer) LayerProtocols {
        _ = self;
        return IPv6Layer.Protocol;
    }

    pub fn get_header(self: *IPv6Layer) *IPv6Header {
        return @ptrCast(@alignCast(self.data[0..40]));
    }

    pub fn deinit(self: *IPv6Layer, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};

pub const IPv6Address = struct {
    array: [16]u8,

    pub const Error = error{
        InvalidFormat,
        TooManyGroups,
        TooFewGroups,
        GroupOverflow,
        NonHexDigit,
    };

    pub fn init_from_array(raw: [16]u8) IPv6Address {
        return .{ .array = raw };
    }

    pub fn init_from_string(str: []const u8) !IPv6Address {
        var groups: [8]u16 = undefined;

        var group_index: usize = 0;
        var cur_value: u32 = 0;
        var have_digit = false;

        var i: usize = 0;
        while (i < str.len) : (i += 1) {
            const c = str[i];

            if (c == ':') {
                if (!have_digit) return Error.InvalidFormat;
                if (group_index >= 8) return Error.TooManyGroups;

                groups[group_index] = @intCast(cur_value);
                group_index += 1;

                cur_value = 0;
                have_digit = false;
                continue;
            }

            const digit = switch (c) {
                '0'...'9' => c - '0',
                'a'...'f' => 10 + (c - 'a'),
                'A'...'F' => 10 + (c - 'A'),
                else => return Error.NonHexDigit,
            };

            have_digit = true;
            cur_value = (cur_value << 4) | digit;

            if (cur_value > 0xFFFF)
                return Error.GroupOverflow;
        }

        if (!have_digit) return Error.InvalidFormat;
        if (group_index != 7) return Error.TooFewGroups;

        groups[group_index] = @intCast(cur_value);

        // Convert 8 groups (u16) → 16 bytes (big endian)
        var result: [16]u8 = undefined;
        for (groups, 0..) |g, idx| {
            result[idx * 2 + 0] = @intCast((g >> 8) & 0xFF);
            result[idx * 2 + 1] = @intCast(g & 0xFF);
        }

        return .{ .array = result };
    }

    pub fn to_string(self: IPv6Address, allocator: std.mem.Allocator) ![]u8 {
        var groups: [8]u16 = undefined;

        // Convert bytes → 8 u16 groups
        for (0..8) |i| {
            const hi: u16 = self.array[i * 2];
            const lo: u16 = self.array[i * 2 + 1];
            groups[i] = (hi << 8) | lo;
        }

        return std.fmt.allocPrint(
            allocator,
            "{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}",
            .{
                groups[0],
                groups[1],
                groups[2],
                groups[3],
                groups[4],
                groups[5],
                groups[6],
                groups[7],
            },
        );
    }
};
