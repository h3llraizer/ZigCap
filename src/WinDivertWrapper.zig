const std = @import("std");
const PacketStructs = @import("PacketStructs.zig");
const RawPacket = PacketStructs.RawPacket;
const print = std.debug.print;
const LinkLayerType = @import("ProtocolEnums.zig").LinkLayerType;

const c = @cImport({
    @cInclude("WinDivert.h");
});

pub const WINDIVERT_ADDRESS = extern struct {
    Timestamp: i64,
    flags: u32,
    Reserved2: u32,
    data: [64]u8,
};

pub const PWINDIVERT_ADDRESS = ?*WINDIVERT_ADDRESS;

pub const CaptureLayer = enum(c_uint) {
    WINDIVERT_LAYER_NETWORK = 0,
    WINDIVERT_LAYER_NETWORK_FORWARD = 1,
    WINDIVERT_LAYER_FLOW = 2,
    WINDIVERT_LAYER_SOCKET = 3,
    WINDIVERT_LAYER_REFLECT = 4,
};

pub const CaptureMode = enum(u64) {
    WINDIVERT_FLAG_SNIFF = 1,
    WINDIVERT_FLAG_DROP = 2,
    WINDIVERT_FLAG_RECV_ONLY = 4,
    WINDIVERT_FLAG_SEND_ONLY = 8,
};

pub const WinDivert = struct {
    handle: ?*anyopaque,

    pub fn init(filter: []const u8, layer: CaptureLayer, priority: i16, flags: u64) !WinDivert {
        var self = WinDivert{ .handle = null };
        self.handle = c.WinDivertOpen(
            filter.ptr,
            @intFromEnum(layer), // intFromEnum ?
            priority,
            flags,
        );

        if (self.handle == c.INVALID_HANDLE_VALUE) {
            return error.FailedToOpenWinDivert;
        }

        return self;
    }

    pub fn capture(self: WinDivert, allocator: std.mem.Allocator, callback: fn (*RawPacket, std.mem.Allocator) void) !void {
        const pkt_buf = try allocator.alloc(u8, 1024);

        const windivert_addr: *WINDIVERT_ADDRESS = try allocator.create(WINDIVERT_ADDRESS);

        var recvLen: c_uint = 0;

        if (c.WinDivertRecv(self.handle, pkt_buf.ptr, @intCast(pkt_buf.len), &recvLen, @ptrCast(windivert_addr)) == 0) {
            return error.WinDivertRecvFailed;
        }

        print("captured packet len: {d}\n", .{recvLen});

        const buf = try allocator.realloc(pkt_buf, @intCast(recvLen));

        var raw_pkt = try allocator.create(RawPacket);

        raw_pkt = try RawPacket.init(std.time.microTimestamp(), std.time.timestamp(), buf, recvLen, LinkLayerType.RAW, allocator);

        raw_pkt.additional = windivert_addr;

        callback(raw_pkt, allocator);
    }

    pub fn deinit(self: WinDivert) void {
        _ = c.WinDivertClose(self.handle);
    }
};
