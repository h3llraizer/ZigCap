const std = @import("std");
const c = @cImport({
    @cInclude("windivert.h");
});

const link_layer_type = @import("ProtocolEnums.zig").link_layer_type;
const print = std.debug.print;
const Allocator = std.mem.Allocator;

pub const UINT8 = u8;
pub const UINT16 = u16;
pub const UINT32 = u32;
pub const UINT64 = u64;
pub const INT16 = i16;
pub const INT64 = i64;

// Replace with your actual enum definition.
pub const WINDIVERT_LAYER = enum(u32) {
    network,
    flow,
    socket,
    reflect,
};

pub const WINDIVERT_DATA_NETWORK = extern struct {
    IfIdx: UINT32,
    SubIfIdx: UINT32,
};

pub const WINDIVERT_DATA_FLOW = extern struct {
    Endpoint: UINT64,
    ParentEndpoint: UINT64,
    ProcessId: UINT32,
    LocalAddr: [4]UINT32,
    RemoteAddr: [4]UINT32,
    LocalPort: UINT16,
    RemotePort: UINT16,
    Protocol: UINT8,
};

pub const WINDIVERT_DATA_SOCKET = extern struct {
    Endpoint: UINT64,
    ParentEndpoint: UINT64,
    ProcessId: UINT32,
    LocalAddr: [4]UINT32,
    RemoteAddr: [4]UINT32,
    LocalPort: UINT16,
    RemotePort: UINT16,
    Protocol: UINT8,
};

pub const WINDIVERT_DATA_REFLECT = extern struct {
    Timestamp: INT64,
    ProcessId: UINT32,
    Layer: WINDIVERT_LAYER,
    Flags: UINT64,
    Priority: INT16,
};

pub const WINDIVERT_ADDRESS = extern struct {
    Timestamp: i64,
    bits: u64, // Store all bitfields in a single u64

    data: extern union {
        Network: WINDIVERT_DATA_NETWORK,
        Flow: WINDIVERT_DATA_FLOW,
        Socket: WINDIVERT_DATA_SOCKET,
        Reflect: WINDIVERT_DATA_REFLECT,
    },

    // Helper methods for accessing bits
    pub fn getLayer(self: *const WINDIVERT_ADDRESS) u8 {
        return @as(u8, @truncate(self.bits));
    }

    pub inline fn getEvent(self: *const WINDIVERT_ADDRESS) u8 {
        return @as(u8, @truncate(self.bits >> 8));
    }

    pub inline fn isSniffed(self: *const WINDIVERT_ADDRESS) bool {
        return (self.bits >> 16) & 1 == 1;
    }

    pub inline fn isOutbound(self: *const WINDIVERT_ADDRESS) bool {
        return (self.bits >> 17) & 1 == 1;
    }

    pub inline fn isLoopback(self: *const WINDIVERT_ADDRESS) bool {
        return (self.bits >> 18) & 1 == 1;
    }

    pub inline fn isImpostor(self: *const WINDIVERT_ADDRESS) bool {
        return (self.bits >> 19) & 1 == 1;
    }

    pub inline fn isIPv6(self: *const WINDIVERT_ADDRESS) bool {
        return (self.bits >> 20) & 1 == 1;
    }

    pub inline fn hasIPChecksum(self: *const WINDIVERT_ADDRESS) bool {
        return (self.bits >> 21) & 1 == 1;
    }

    pub inline fn hasTCPChecksum(self: *const WINDIVERT_ADDRESS) bool {
        return (self.bits >> 22) & 1 == 1;
    }

    pub inline fn hasUDPChecksum(self: *const WINDIVERT_ADDRESS) bool {
        return (self.bits >> 23) & 1 == 1;
    }

    // Setter methods (mutable version)
    pub inline fn setLayer(self: *WINDIVERT_ADDRESS, value: u8) void {
        self.bits = (self.bits & ~@as(u64, 0xFF)) | value;
    }

    pub inline fn setEvent(self: *WINDIVERT_ADDRESS, value: u8) void {
        const shifted = @as(u64, value) << 8;
        self.bits = (self.bits & ~(@as(u64, 0xFF) << 8)) | shifted;
    }

    pub inline fn setSniffed(self: *WINDIVERT_ADDRESS, value: bool) void {
        const bit: u64 = @as(u64, @intFromBool(value)) << 16;
        self.bits = (self.bits & ~(@as(u64, 1) << 16)) | bit;
    }

    pub inline fn setOutbound(self: *WINDIVERT_ADDRESS, value: bool) void {
        const bit: u64 = @as(u64, @intFromBool(value)) << 17;
        self.bits = (self.bits & ~(@as(u64, 1) << 17)) | bit;
    }

    pub inline fn setLoopback(self: *WINDIVERT_ADDRESS, value: bool) void {
        const bit: u64 = @as(u64, @intFromBool(value)) << 18;
        self.bits = (self.bits & ~(@as(u64, 1) << 18)) | bit;
    }

    pub inline fn setImpostor(self: *WINDIVERT_ADDRESS, value: bool) void {
        const bit: u64 = @as(u64, @intFromBool(value)) << 19;
        self.bits = (self.bits & ~(@as(u64, 1) << 19)) | bit;
    }

    pub inline fn setIPv6(self: *WINDIVERT_ADDRESS, value: bool) void {
        const bit: u64 = @as(u64, @intFromBool(value)) << 20;
        self.bits = (self.bits & ~(@as(u64, 1) << 20)) | bit;
    }

    pub inline fn setIPChecksum(self: *WINDIVERT_ADDRESS, value: bool) void {
        const bit: u64 = @as(u64, @intFromBool(value)) << 21;
        self.bits = (self.bits & ~(@as(u64, 1) << 21)) | bit;
    }

    pub inline fn setTCPChecksum(self: *WINDIVERT_ADDRESS, value: bool) void {
        const bit: u64 = @as(u64, @intFromBool(value)) << 22;
        self.bits = (self.bits & ~(@as(u64, 1) << 22)) | bit;
    }

    pub inline fn setUDPChecksum(self: *WINDIVERT_ADDRESS, value: bool) void {
        const bit: u64 = @as(u64, @intFromBool(value)) << 23;
        self.bits = (self.bits & ~(@as(u64, 1) << 23)) | bit;
    }
};

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

pub const Event = enum(u8) {
    BIND = c.WINDIVERT_EVENT_SOCKET_BIND,
    CONNECT = c.WINDIVERT_EVENT_SOCKET_CONNECT,
    CLOSE = c.WINDIVERT_EVENT_SOCKET_CLOSE,
};

pub const WDPacket = struct {
    raw: []u8,
    wd_addr: *WINDIVERT_ADDRESS,
};

pub const WinDivertError = error{
    FailedToOpenWinDivert,
};

pub const WINDIVERT_HANDLE = ?*anyopaque;

pub fn open(filter: []const u8, layer: CaptureLayer, priority: i16, flags: u64) WinDivertError!WINDIVERT_HANDLE {
    const handle = c.WinDivertOpen(filter.ptr, @intFromEnum(layer), priority, flags);
    if (handle == c.INVALID_HANDLE_VALUE) {
        return WinDivertError.FailedToOpenWinDivert;
    }

    return handle;
}

pub fn close(handle: WINDIVERT_HANDLE) void {
    _ = c.WinDivertClose(handle);
}

pub fn recv(
    handle: WINDIVERT_HANDLE,
    packet_len: usize,
    recv_len: *u32,
    wdpacket: *WINDIVERT_ADDRESS,
) c_int {
    var len: u32 = 0;
    const res = c.WinDivertRecv(handle, null, @intCast(packet_len), &len, @ptrCast(wdpacket));
    recv_len.* = len;

    return res;
}

pub const WinDivert = struct {
    handle: WINDIVERT_HANDLE, // windows handle are just opaque ptrs (in c/c++ they're void*)

    pub fn init(filter: []const u8, layer: CaptureLayer, priority: i16, flags: u64) WinDivertError!WinDivert {
        return WinDivert{ .handle = try open(filter, layer, priority, flags) };
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
