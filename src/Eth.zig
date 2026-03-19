const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const Packet = @import("Packet.zig").Packet;

const Layer = @import("Layer.zig").Layer;
const LayerProtocols = @import("Layer.zig").LayerProtocols;
const NetworkProtocols = @import("Layer.zig").NetworkProtocols;

const IPv4Layer = @import("IPv4.zig").IPv4Layer;
const IPv4Header = @import("IPv4.zig").IPv4Header;
const IPv4 = @import("IPv4.zig");

const IPv6Layer = @import("IPv6.zig").IPv6Layer;
const IPv6HeaderSize = @import("IPv6.zig").HeaderSize;

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
    dst0: u8 = 0,
    dst1: u8 = 0,
    dst2: u8 = 0,
    dst3: u8 = 0,
    dst4: u8 = 0,
    dst5: u8 = 0,

    src0: u8 = 0,
    src1: u8 = 0,
    src2: u8 = 0,
    src3: u8 = 0,
    src4: u8 = 0,
    src5: u8 = 0,

    eth_type: u16 = 0, //// BigEndian
};

pub const EthLayer = struct {
    data: []u8, // does not include the ethhdr
    const Protocol = LayerProtocols{ .LinkLayer = .ETHERNET };

    pub fn init(raw: []u8, allocator: std.mem.Allocator) !*EthLayer {
        if (raw.len < EthHeaderSize) {
            return error.RawPayloadTooSmall;
        }

        const e = try allocator.create(EthLayer);

        e.data = raw;
        return e;
    }

    pub fn create(allocator: std.mem.Allocator) !*EthLayer {
        const self = try allocator.create(EthLayer);
        self.data = try allocator.alloc(u8, 14);
        return self;
    }

    pub fn to_string(self: *EthLayer, allocator: Allocator) []const u8 {
        const src_mac = self.get_src_mac().to_string(allocator) catch |err| blk: {
            std.debug.print("src_mac to_string failed: {s}\n", .{@errorName(err)});
            break :blk "";
        };
        defer if (src_mac.len != 0) allocator.free(src_mac);

        const dst_mac = self.get_dst_mac().to_string(allocator) catch |err| blk: {
            std.debug.print("dst_mac to_string failed: {s}\n", .{@errorName(err)});
            break :blk "";
        };
        defer if (dst_mac.len != 0) allocator.free(dst_mac);

        const eth_enum = self.get_eth_type() catch |err| blk: {
            std.debug.print("get_eth_type failed: {s}\n", .{@errorName(err)});
            break :blk EthType.IP;
        };

        const eth_type_str = @tagName(eth_enum);

        const result = std.fmt.allocPrint(
            allocator,
            "EthType: {s}, src_mac: {s}, dst_mac: {s}",
            .{ eth_type_str, src_mac, dst_mac },
        ) catch |err| {
            std.debug.print("allocPrint failed: {s}\n", .{@errorName(err)});
            return "";
        };

        return result;
    }

    pub fn parse_next_layer(self: *EthLayer, allocator: std.mem.Allocator) ?*Layer {
        const eth_type: EthType = self.get_eth_type() catch return null;

        const packet_layer: *Layer = allocator.create(Layer) catch return null;

        switch (eth_type) {
            EthType.IP => {
                const ihl = self.data[0];

                const ip_version = ihl >> 4; // bit shift right 4 yields the IP version

                const hdr_len = (ihl & 0x0F) * 4;

                if (ip_version == @intFromEnum(NetworkProtocols.IPv4)) {
                    if (hdr_len < IPv4.MinHeaderLength or hdr_len > IPv4.MaxHeaderLength) return null;

                    const ipv4_layer = IPv4Layer.init(self.data[0..], allocator) catch return null;
                    packet_layer.* = Layer.implBy(ipv4_layer);
                    print("Setting Eths next layer.\n", .{});
                    //self.set_next_layer(packet_layer);
                    return packet_layer;
                }

                if (ip_version == @intFromEnum(NetworkProtocols.IPv6)) {
                    const ipv6_layer = IPv6Layer.init(self.data[0..], allocator) catch return null;
                    packet_layer.* = Layer.implBy(ipv6_layer);
                } else {
                    print("Unknown network protocol.\n", .{});
                    return null;
                }
            },
            else => {
                print("UknownEthType", .{});
                return null;
            },
        }

        //print("returning packet layer.\n", .{});
        return packet_layer;
    }

    pub fn get_src_mac(self: *EthLayer) MacAddress {
        const hdr = self.get_header();
        const mac = MacAddress.init_from_array(.{ hdr.src0, hdr.src1, hdr.src2, hdr.src3, hdr.src4, hdr.src5 });
        return mac;
    }

    pub fn get_dst_mac(self: *EthLayer) MacAddress {
        const hdr = self.get_header();
        const mac = MacAddress.init_from_array(.{ hdr.dst0, hdr.dst1, hdr.dst2, hdr.dst3, hdr.dst4, hdr.dst5 });
        return mac;
    }

    pub fn set_src_mac(self: *EthLayer, src_mac: MacAddress) void {
        var hdr = self.get_header();

        hdr.src0 = src_mac.addr[0];
        hdr.src1 = src_mac.addr[1];
        hdr.src2 = src_mac.addr[2];
        hdr.src3 = src_mac.addr[3];
        hdr.src4 = src_mac.addr[4];
        hdr.src5 = src_mac.addr[5];
    }

    pub fn set_dst_mac(self: *EthLayer, dst_mac: MacAddress) void {
        var hdr = self.get_header();
        hdr.dst0 = dst_mac.addr[0];
        hdr.dst1 = dst_mac.addr[1];
        hdr.dst2 = dst_mac.addr[2];
        hdr.dst3 = dst_mac.addr[3];
        hdr.dst4 = dst_mac.addr[4];
        hdr.dst5 = dst_mac.addr[5];
    }

    pub fn get_eth_type(self: *EthLayer) !EthType {
        const hdr = self.get_header();
        return try std.meta.intToEnum(EthType, std.mem.bigToNative(u16, hdr.eth_type));
    }

    pub fn set_eth_type(self: *EthLayer, eth_type: EthType) !void {
        var hdr = self.get_header();
        hdr.eth_type = std.mem.nativeToBig(u16, @intFromEnum(eth_type));
    }

    pub fn get_header(self: *EthLayer) *EthHeader {
        return @ptrCast(@alignCast(self.data[0..14]));
    }

    pub fn get_protocol(self: *EthLayer) LayerProtocols {
        _ = self;
        return EthLayer.Protocol;
    }

    pub fn deinit(self: *EthLayer, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};

pub const MacAddress = struct {
    addr: [6]u8,

    pub const Error = error{
        InvalidFormat,
        TooManyOctets,
        TooFewOctets,
        NonHexDigit,
        Overflow,
    };

    /// Create from raw [6]u8 array
    pub fn init_from_array(raw: [6]u8) MacAddress {
        return .{ .addr = raw };
    }

    /// Create from string like "AA:BB:CC:DD:EE:FF" (case-insensitive)
    pub fn init_from_string(str: []const u8) !MacAddress {
        var octets: [6]u8 = undefined;
        var oct_index: usize = 0;
        var cur_value: u8 = 0;
        var digit_count: u8 = 0;

        for (str) |c| {
            if (c == ':' or c == '-') {
                if (digit_count != 2) return Error.InvalidFormat;
                octets[oct_index] = cur_value;
                oct_index += 1;
                if (oct_index > 6) return Error.TooManyOctets;

                cur_value = 0;
                digit_count = 0;
                continue;
            }

            const digit = parseHexDigit(c) orelse return Error.NonHexDigit;
            cur_value = (cur_value << 4) | digit;
            digit_count += 1;
        }

        if (digit_count != 2) return Error.InvalidFormat;
        if (oct_index != 5) return Error.TooFewOctets;

        octets[oct_index] = cur_value;

        return .{ .addr = octets };
    }

    /// Return string like "AA:BB:CC:DD:EE:FF"
    pub fn to_string(self: MacAddress, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(
            allocator,
            "{X}:{X}:{X}:{X}:{X}:{X}",
            .{
                @as(u32, self.addr[0]),
                @as(u32, self.addr[1]),
                @as(u32, self.addr[2]),
                @as(u32, self.addr[3]),
                @as(u32, self.addr[4]),
                @as(u32, self.addr[5]),
            },
        );
    }

    /// Helper to parse a single hex digit
    fn parseHexDigit(c: u8) ?u8 {
        if (c >= '0' and c <= '9') return c - '0';
        if (c >= 'a' and c <= 'f') return c - 'a' + 10;
        if (c >= 'A' and c <= 'F') return c - 'A' + 10;
        return null;
    }
};
