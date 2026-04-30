const std = @import("std");
const link_layer_type = @import("ProtocolEnums.zig").link_layer_type;
const print = std.debug.print;

const Allocator = std.mem.Allocator;

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

pub const WDPacket = struct {
    raw: []align(2) u8,
    wd_addr: *WINDIVERT_ADDRESS,
};

pub const WinDivert = struct {
    handle: ?*anyopaque, // windows handle are just opaque ptrs (in c/c++ they're void*)

    pub fn init(filter: []const u8, layer: CaptureLayer, priority: i16, flags: u64) !WinDivert {
        var self = WinDivert{ .handle = null };
        self.handle = c.WinDivertOpen(
            filter.ptr,
            @intFromEnum(layer),
            priority,
            flags,
        );

        if (self.handle == c.INVALID_HANDLE_VALUE) {
            return error.FailedToOpenWinDivert;
        }

        return self;
    }

    pub fn capture_one_raw(self: WinDivert, max_pkt_size: usize, allocator: Allocator) !?WDPacket {
        const pkt_buf: []align(2) u8 = try allocator.alignedAlloc(u8, std.mem.Alignment.@"2", max_pkt_size);

        const windivert_addr: *WINDIVERT_ADDRESS = try allocator.create(WINDIVERT_ADDRESS);

        var recvLen: c_uint = 0;

        if (c.WinDivertRecv(self.handle, pkt_buf.ptr, @intCast(pkt_buf.len), &recvLen, @ptrCast(windivert_addr)) == 0) {
            print("WinDivertRecvFailed.\n", .{});
            return null;
        }

        const trimmed = try allocator.realloc(pkt_buf, recvLen);

        const wdpacket = WDPacket{ .raw = trimmed, .wd_addr = windivert_addr };

        return wdpacket;
    }

    pub fn inject_one(self: WinDivert, packet: WDPacket) void {
        var send_len: c_uint = 0;
        const res = c.WinDivertSend(self.handle, packet.raw.ptr, @intCast(packet.raw.len), &send_len, @ptrCast(packet.wd_addr));

        _ = res;
    }

    pub fn deinit(self: WinDivert) void {
        _ = c.WinDivertClose(self.handle);
    }
};
