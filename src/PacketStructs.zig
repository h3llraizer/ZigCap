const std = @import("std");
const print = std.debug.print;
const allocPrint = std.fmt.allocPrint;

pub const RawPacket = struct {
    timestamp_s: u32,
    timestamp_ms: u32,
    raw_data: []u8,
    raw_len: u32,

    pub fn init(ts_usec: c_long, ts_sec: c_long, raw: []const u8, len: c_uint, allocator: *std.mem.Allocator) !*RawPacket {
        var p: *RawPacket = try allocator.create(RawPacket);

        p.timestamp_ms = @intCast(ts_usec);

        p.timestamp_s = @intCast(ts_sec);

        p.raw_len = @intCast(len);

        p.raw_data = try allocator.alloc(u8, p.raw_len);

        @memmove(p.raw_data, raw[0..p.raw_len]);

        return p;
    }

    pub fn to_string(self: RawPacket) void {
        print("Timestamp_s: {any} Timestamp_ms: {any} Raw_data (ptr): {any} raw_len: {any}\n", .{ self.timestamp_s, self.timestamp_ms, self.raw_data.ptr, self.raw_len });
    }

    pub fn print_bytes(self: RawPacket, len: u32) void {
        const bytes: []const u8 = @ptrCast(self.raw_data[0..len]);
        for (bytes) |b| {
            std.debug.print("{x} ", .{b});
        }
        std.debug.print("\n", .{});
    }

    pub fn deinit(self: *RawPacket, allocator: *std.mem.Allocator) void {
        allocator.free(self.raw_data);
        allocator.destroy(self);
    }
};

pub const EthHeader = struct {
    dst: [6]u8,
    src: [6]u8,
    //    ethertype: u16, // network byte order (big-endian)
};

pub const EthLayer = struct {
    eth_header: *EthHeader,

    pub fn init(eth_header: *EthHeader) EthLayer {
        const eth = EthLayer{ .eth_header = eth_header };

        return eth;
    }

    pub fn to_string(self: *EthLayer, allocator: *std.mem.Allocator) void {
        const dst = self.eth_header.dst;

        const dest = allocPrint(allocator.*, "{x}:{x}:{x}:{x}:{x}:{x}", .{ dst[0], dst[1], dst[2], dst[3], dst[4], dst[5] }) catch |err| {
            print("{s}\n", .{@errorName(err)});
            return;
        };

        const src = self.eth_header.src;

        const source = allocPrint(allocator.*, "{x}:{x}:{x}:{x}:{x}:{x}", .{ src[0], src[1], src[2], src[3], src[4], src[5] }) catch |err| {
            print("{s}\n", .{@errorName(err)});
            return;
        };

        print("Src: {s} Dst: {s}\n", .{ source, dest });
    }
};

pub const Packet = struct {
    raw_packet: *RawPacket,

    pub fn init(rawPacket: *RawPacket) Packet {
        const p = Packet{ .raw_packet = rawPacket };

        return p;
    }

    pub fn get_eth_layer(self: Packet) ?EthLayer {
        if (self.raw_packet.raw_len < 12) return null;

        const eth_hdr: *EthHeader = @ptrCast(self.raw_packet.raw_data);

        return EthLayer{ .eth_header = eth_hdr };
    }

    pub fn deinit(self: *Packet, allocator: *std.mem.Allocator) void {
        allocator.destroy(self);
    }
};
