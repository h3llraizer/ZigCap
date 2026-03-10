const std = @import("std");
const print = std.debug.print;

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
    payload: []u8, // does not include the ethhdr
    packet: *Packet,
    const Protocol = LayerProtocols{ .LinkLayer = .ETHERNET };

    pub fn init(raw: []u8, allocator: std.mem.Allocator) !*EthLayer {
        if (raw.len < EthHeaderSize) {
            return error.RawPayloadTooSmall;
        }

        const e = try allocator.create(EthLayer);

        e.hdr = @ptrCast(raw[0..EthHeaderSize]); // ptr cast the first eth hdr length bytes as the ethhdr
        e.payload = raw[EthHeaderSize..]; // store payload as whatever is after the header
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

    pub fn parse_next_layer(self: *EthLayer, allocator: std.mem.Allocator) ?*Layer {
        //        print("Payload len: {d}\n", .{self.payload.len});
        const eth_type: EthType = self.get_eth_type() catch return null;

        const packet_layer: *Layer = allocator.create(Layer) catch return null;

        switch (eth_type) {
            EthType.IP => {
                const ihl = self.payload[0];

                const ip_version = ihl >> 4;

                const hdr_len = (ihl & 0x0F) * 4;

                if (ip_version == @intFromEnum(NetworkProtocols.IPv4)) {
                    if (hdr_len < IPv4.MinHeaderLength or hdr_len > IPv4.MaxHeaderLength) return null;

                    const ipv4_layer = IPv4Layer.init(self.payload[0..], allocator) catch return null;
                    packet_layer.* = Layer.implBy(ipv4_layer);
                    return packet_layer;
                }

                if (ip_version == @intFromEnum(NetworkProtocols.IPv6)) {
                    const ipv6_layer = IPv6Layer.init(self.payload[0..], allocator) catch return null;
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
        const mac = MacAddress.init_from_array(.{ self.hdr.src0, self.hdr.src1, self.hdr.src2, self.hdr.src3, self.hdr.src4, self.hdr.src5 });
        return mac;
    }

    pub fn get_dst_mac(self: *EthLayer) MacAddress {
        const mac = MacAddress.init_from_array(.{ self.hdr.dst0, self.hdr.dst1, self.hdr.dst2, self.hdr.dst3, self.hdr.dst4, self.hdr.dst5 });
        return mac;
    }

    pub fn set_src_mac(self: *EthLayer, src_mac: MacAddress) void {
        self.hdr.src0 = src_mac.addr[0];
        self.hdr.src1 = src_mac.addr[1];
        self.hdr.src2 = src_mac.addr[2];
        self.hdr.src3 = src_mac.addr[3];
        self.hdr.src4 = src_mac.addr[4];
        self.hdr.src5 = src_mac.addr[5];
    }

    pub fn set_dst_mac(self: *EthLayer, dst_mac: MacAddress) void {
        self.hdr.dst0 = dst_mac.addr[0];
        self.hdr.dst1 = dst_mac.addr[1];
        self.hdr.dst2 = dst_mac.addr[2];
        self.hdr.dst3 = dst_mac.addr[3];
        self.hdr.dst4 = dst_mac.addr[4];
        self.hdr.dst5 = dst_mac.addr[5];
    }

    pub fn get_eth_type(self: *EthLayer) !EthType {
        return try std.meta.intToEnum(EthType, std.mem.bigToNative(u16, self.hdr.eth_type));
    }

    pub fn set_eth_type(self: *EthLayer, eth_type: EthType) !void {
        self.hdr.eth_type = std.mem.nativeToBig(u16, @intFromEnum(eth_type));
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
