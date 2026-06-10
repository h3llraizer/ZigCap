const std = @import("std");
const c = @cImport({
    @cInclude("WinDivert.h");
});

const link_layer_type = @import("ProtocolEnums.zig").link_layer_type;
const print = std.debug.print;
const Allocator = std.mem.Allocator;

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

///  SniffRecvOnly   -  Sniffing with receive-only restriction
///  SniffNoDrvrInst -  Sniffing without driver installation
///  RecvNoDrvrInst  -  Receive-only without driver installation
///  SendNoDrvrInst  -  Send-only without driver installation
///  SniffWithIPFrag -  Sniffing with IP fragment capture
///  RecvWithIPFrag  -  Receive-only with IP fragment capture
///  CaptureAndBlock -  Capture packets and block until reinjected
const CaptureModeCombo = enum(u64) {
    SniffRecvOnly = (@intFromEnum(CaptureMode.WINDIVERT_FLAG_SNIFF) | @intFromEnum(CaptureMode.WINDIVERT_FLAG_RECV_ONLY)), //       Sniffing with receive-only restriction
    //   SniffNoDrvrInst = (@intFromEnum(CaptureMode.WINDIVERT_FLAG_SNIFF) | @intFromEnum(CaptureMode.WINDIVERT_FLAG_NO_INSTALL)), //    Sniffing without driver installation
    //   RecvNoDrvrInst = (@intFromEnum(CaptureMode.WINDIVERT_FLAG_RECV_ONLY) | @intFromEnum(CaptureMode.WINDIVERT_FLAG_NO_INSTALL)), // Receive-only without driver installation
    //   SendNoDrvrInst = (@intFromEnum(CaptureMode.WINDIVERT_FLAG_SEND_ONLY) | @intFromEnum(CaptureMode.WINDIVERT_FLAG_NO_INSTALL)), // Send-only without driver installation
    //SniffWithIPFrag = (@intFromEnum(CaptureMode.WINDIVERT_FLAG_SNIFF) | @intFromEnum(CaptureMode.WINDIVERT_FLAG_FRAGMENTS)), //  -  Sniffing with IP fragment capture
    //RecvWithIPFrag = (@intFromEnum(CaptureMode.WINDIVERT_FLAG_RECV_ONLY) | @intFromEnum(CaptureMode.WINDIVERT_FLAG_FRAGMENTS)), //  Receive-only with IP fragment capture

};

pub const WDPacket = struct {
    raw: []u8,
    wd_addr: *WINDIVERT_ADDRESS,
};

pub const WinDivertError = error{
    FailedToOpenWinDivert,
};

pub const WinDivert = struct {
    handle: ?*anyopaque, // windows handle are just opaque ptrs (in c/c++ they're void*)

    pub fn init(filter: []const u8, layer: CaptureLayer, priority: i16, flags: u64) WinDivertError!WinDivert {
        var self = WinDivert{ .handle = null };
        self.handle = c.WinDivertOpen(
            filter.ptr,
            @intFromEnum(layer),
            priority,
            flags,
        );

        if (self.handle == c.INVALID_HANDLE_VALUE) {
            return WinDivertError.FailedToOpenWinDivert;
        }

        return self;
    }

    pub fn capture_one_raw(self: WinDivert, max_pkt_size: usize, allocator: Allocator) Allocator.Error!?WDPacket {
        const pkt_buf: []u8 = try allocator.alloc(u8, max_pkt_size);

        const windivert_addr: *WINDIVERT_ADDRESS = try allocator.create(WINDIVERT_ADDRESS);

        var recvLen: c_uint = 0;

        if (c.WinDivertRecv(self.handle, pkt_buf.ptr, @intCast(pkt_buf.len), &recvLen, @ptrCast(windivert_addr)) == 0) {
            print("WinDivertRecvFailed.\n", .{});
            return null;
        }

        const trimmed = try allocator.realloc(pkt_buf, recvLen); // trim the allocation to the actual size recieved

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
