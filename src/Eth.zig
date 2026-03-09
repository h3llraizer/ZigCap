const std = @import("std");
const print = std.debug.print;

const LayerProtocols = @import("Layer.zig").LayerProtocols;

pub const EthType = enum(u16) {
    IP = 0x0800,
    ARP = 0x0806,
    ETHBRIDGE = 0x6558,
    REVARP = 0x8035,
    AT = 0x809B,
    AARP = 0x80F3,
    VLAN = 0x8100,
    IPX = 0x8137,
    IPV6 = 0x86DD,
    LOOPBACK = 0x9000,
    PPPOED = 0x8863,
    PPPOES = 0x8864,
    MPLS = 0x8847,
    PPP = 0x880B,
    ROCEV1 = 0x8915,
    IEEE_802_1AD = 0x88A8,
    WAKE_ON_LAN = 0x0842,
};

pub const EthHeaderSize = 14;

pub const EthHeader = packed struct {
    dst0: u8,
    dst1: u8,
    dst2: u8,
    dst3: u8,
    dst4: u8,
    dst5: u8,

    src0: u8,
    src1: u8,
    src2: u8,
    src3: u8,
    src4: u8,
    src5: u8,

    eth_type: u16, //// BigEndian
};

pub const EthLayer = struct {
    hdr: *align(1) EthHeader,
    const Protocol = LayerProtocols{ .LinkLayer = .ETHERNET };

    pub fn init(raw: *[EthHeaderSize]u8, allocator: std.mem.Allocator) !*EthLayer {
        const e = try allocator.create(EthLayer);
        e.hdr = @ptrCast(raw);
        return e;
    }

    pub fn to_string(self: *EthLayer) void {
        inline for (@typeInfo(EthHeader).@"struct".fields) |f| {
            print("{s} : {any} : ", .{
                f.name,
                f.type,
            });
            if (f.type == u16) {
                print("{x}\n", .{std.mem.bigToNative(f.type, @field(self.hdr, f.name))});
            } else {
                print("{x}\n", .{@field(self.hdr, f.name)});
            }
        }
    }

    pub fn get_eth_type(self: *EthLayer) !EthType {
        return try std.meta.intToEnum(EthType, std.mem.bigToNative(u16, self.hdr.eth_type));
    }

    pub fn get_protocol(self: *EthLayer) LayerProtocols {
        _ = self;
        return EthLayer.Protocol;
    }

    pub fn deinit(self: *EthLayer, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};

pub fn parseEthHeader(payload: []const u8) !void {
    if (payload.len < 12) {
        return error.InvalidLength;
    }

    const dst = payload[0..6];
    const src = payload[6..12];

    std.debug.print("Dst: ", .{});
    var i: usize = 0;
    for (dst) |b| {
        if (i != 0) std.debug.print(":", .{});
        std.debug.print("{x}", .{b});
        i += 1;
    }

    i = 0;
    std.debug.print(" Src: ", .{});
    for (src) |b| {
        if (i != 0) std.debug.print(":", .{});
        std.debug.print("{x}", .{b});
        i += 1;
    }
    std.debug.print("\n", .{});
}

pub const MacAddressing = struct { dst: [6]u8, src: [6]u8 };

pub const MacAddress = struct { addr: [6]u8 };

pub fn create_macs(eth_hdr: *EthHeader) MacAddressing {
    var src_mac: MacAddress = {};
    src_mac.addr[0] = eth_hdr.src0;
    src_mac.addr[1] = eth_hdr.src1;
    src_mac.addr[2] = eth_hdr.src2;
    src_mac.addr[3] = eth_hdr.src3;
    src_mac.addr[4] = eth_hdr.src4;
    src_mac.addr[5] = eth_hdr.src5;

    var dst_mac: MacAddress = {};
    dst_mac.addr[0] = eth_hdr.dst0;
    dst_mac.addr[1] = eth_hdr.dst1;
    dst_mac.addr[2] = eth_hdr.dst2;
    dst_mac.addr[3] = eth_hdr.dst3;
    dst_mac.addr[4] = eth_hdr.dst4;
    dst_mac.addr[5] = eth_hdr.dst5;

    return MacAddressing{ .dst = dst_mac, .src = src_mac };
}
