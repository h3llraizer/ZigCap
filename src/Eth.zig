const std = @import("std");

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
