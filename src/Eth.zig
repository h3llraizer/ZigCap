const std = @import("std");
const Packet = @import("Packet.zig");
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;
const ProtocolEnums = @import("ProtocolEnums.zig");
const LayerIface = @import("LayerIface.zig").LayerIface;
const init_layer = @import("LayerIface.zig").init_layer;
const IPv4 = @import("IPv4.zig");
const IPv6 = @import("IPv6.zig");
const ARP = @import("ARP.zig");
const Owner = @import("Owner.zig");
const GenericLayer = @import("GenericLayer.zig");
const VLAN = @import("VLAN.zig");

const print = std.debug.print;
const Allocator = std.mem.Allocator;
const panic = std.debug.panic;
const IPv4Header = IPv4.IPv4Header;
const LayerError = ProtocolEnums.LayerError;
const IPVersion = ProtocolEnums.IPVersions;
const LayerOwner = Owner.LayerOwner;
const IPv6HeaderSize = IPv6HeaderSize;

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
    Unknown = 0,
    _,

    pub fn is_known(eth_type: u16) bool {
        for (std.enums.values(EthType)) |eth_t| {
            if (@intFromEnum(eth_t) == @byteSwap(eth_type)) {
                return true;
            }
        }

        return false;
    }
};

pub const EthHeaderSize = 14;

const default_hdr = EthHeader{
    .dst = [_]u8{0} ** 6,
    .src = [_]u8{0} ** 6,
    .eth_type = [_]u8{2} ** 2,
};

// Use extern struct for exact 14-byte layout (standard Ethernet header)
pub const EthHeader = extern struct {
    dst: [6]u8, // Destination MAC address
    src: [6]u8, // Source MAC address
    eth_type: [2]u8, // Ethernet type (network byte order)

    comptime {
        if (@sizeOf(EthHeader) != 14) {
            @compileError("EthHeader must be 14 bytes, got " ++ @typeName(@sizeOf(EthHeader)));
        }
    }

    pub fn init_default() EthHeader {
        return .{
            .dst = [_]u8{0} ** 6,
            .src = [_]u8{0} ** 6,
            .eth_type = [_]u8{0} ** 2,
        };
    }

    pub fn set_dst_mac(self: *EthHeader, mac: MacAddress) void {
        self.dst = mac.addr;
    }

    pub fn get_dst_mac(self: *const EthHeader) MacAddress {
        return MacAddress.init_from_array(self.dst);
    }

    pub fn set_src_mac(self: *EthHeader, mac: MacAddress) void {
        self.src = mac.addr;
    }

    pub fn get_src_mac(self: *const EthHeader) MacAddress {
        return MacAddress.init_from_array(self.src);
    }

    pub fn set_eth_type(self: *EthHeader, eth_type: EthType) void {
        std.mem.writeInt(u16, &self.eth_type, @intFromEnum(eth_type), .big); // Network byte order
    }

    pub fn get_eth_type(self: *const EthHeader) EthType {
        return @enumFromInt(std.mem.readInt(u16, &self.eth_type, .big));
    }
};

pub const EthLayer = struct {
    owner: LayerOwner,
    const Protocol = tcp_ip_protocol.eth;

    pub fn init(owner: LayerOwner) LayerError!EthLayer {
        return try init_layer(EthLayer, owner, EthHeader, default_hdr);
    }

    pub fn zero_hdr() []u8 {
        var header = EthHeader.init_default();
        var data: []u8 = undefined;
        @memcpy(data[0..@sizeOf(EthHeader)], std.mem.asBytes(&header));
        return data;
    }

    pub fn get_mutable_header(self: *const EthLayer) *EthHeader {
        const data = self.get_data();
        return @ptrCast(data.ptr);
    }

    pub fn get_immutable_header(self: *const EthLayer) *const EthHeader {
        const data: []const u8 = self.get_data();

        if (data.len < EthHeaderSize) {
            panic("Eth Raw Data len ({}) less than EthHeaderSize", .{data.len});
        }

        return @ptrCast(data.ptr);
    }

    pub fn to_string(self: *const EthLayer, allocator: Allocator) []const u8 {
        const hdr = self.get_immutable_header();

        // Allocate MAC strings
        const src_mac = hdr.get_src_mac().to_string(allocator) catch |err| {
            print("src_mac to_string failed: {s}\n", .{@errorName(err)});
            return "";
        };
        defer allocator.free(src_mac);

        const dst_mac = hdr.get_dst_mac().to_string(allocator) catch |err| {
            print("dst_mac to_string failed: {s}\n", .{@errorName(err)});
            allocator.free(src_mac);
            return "";
        };
        defer allocator.free(dst_mac);

        // Get EtherType in host byte order (network byte order from packet)
        const eth_type_raw = std.mem.readInt(u16, &hdr.eth_type, .big);

        // Try to match against known EtherTypes (without byte-swapping since enum values are in host order)
        var known_type: ?EthType = null;
        for (std.enums.values(EthType)) |eth_t| {
            if (@intFromEnum(eth_t) == eth_type_raw and eth_t != .Unknown) {
                known_type = eth_t;
                break;
            }
        }

        // Format as enum name if known, otherwise as hex
        const eth_type_str = if (known_type) |kt|
            @tagName(kt)
        else
            std.fmt.allocPrint(allocator, "0x{X}", .{eth_type_raw}) catch |err| {
                print("eth_type allocPrint failed: {s}\n", .{@errorName(err)});
                return "";
            };

        // Clean up if we allocated a hex string
        if (known_type == null) {
            defer allocator.free(@constCast(eth_type_str));
        }

        // Create final result
        const result = std.fmt.allocPrint(
            allocator,
            "EthLayer: EthType: {s}, src: {s}, dst: {s}\n",
            .{ eth_type_str, src_mac, dst_mac },
        ) catch |err| {
            print("result allocPrint failed: {s}\n", .{@errorName(err)});
            if (known_type == null) {
                allocator.free(@constCast(eth_type_str));
            }
            return "";
        };

        return result;
    }

    /// get slice of data (hdr+payload)
    pub fn get_data(self: *const EthLayer) []u8 {
        return self.owner.get_data();
    }

    /// return mutable slice of the payload
    pub fn get_payload(self: *EthLayer) []const u8 {
        const data = self.get_data();

        if (data.len > EthHeaderSize) {
            return data[EthHeaderSize..]; // return remaining bytes after the header
        } else {
            return "";
        }
    }

    pub fn validate_layer(self: *EthLayer) void {
        if (self.owner.is_packet_owned()) {
            if (self.owner.packet_layer.next_layer) |next_layer| {
                const protocol = next_layer.layer_iface.get_protocol();

                const hdr = self.get_mutable_header();

                switch (protocol) {
                    .ipv4 => hdr.set_eth_type(.IP),
                    .ipv6 => hdr.set_eth_type(.IPV6),
                    .arp => hdr.set_eth_type(.ARP),
                    .vlan => hdr.set_eth_type(.VLAN),
                    .loopback => hdr.set_eth_type(.LOOPBACK),
                    else => {},
                }
            }
        }
    }

    /// return the next layer protocol type
    pub fn get_next_layer_type(self: *EthLayer, layer: *Packet.Layer) LayerError!?LayerIface {
        const hdr = self.get_immutable_header();
        const eth_type = hdr.get_eth_type();

        const data = self.get_payload();

        if (data.len == 0) {
            return null;
        }

        switch (eth_type) {
            EthType.IP => {
                const ihl_byte = data[0];
                const ip_version = ihl_byte >> 4;
                const hdr_len = (ihl_byte & 0x0F) * 4;

                if (ip_version == @intFromEnum(IPVersion.IPv4)) {
                    if (hdr_len < IPv4.MinHeaderLength or hdr_len > IPv4.MaxHeaderLength) {
                        return try LayerIface.init(GenericLayer.ApplicationLayer, LayerOwner{ .packet_layer = layer });
                    }

                    return try LayerIface.init(IPv4.IPv4Layer, LayerOwner{ .packet_layer = layer });
                }

                if (ip_version == @intFromEnum(IPVersion.IPv6)) {
                    return null;
                } else {
                    return null;
                }
            },
            EthType.IPV6 => {
                return try LayerIface.init(IPv6.IPv6Layer, LayerOwner{ .packet_layer = layer });
            },
            EthType.ARP => {
                return try LayerIface.init(ARP.ARPLayer, LayerOwner{ .packet_layer = layer });
            },
            EthType.VLAN => {
                return try LayerIface.init(VLAN.VLANLayer, LayerOwner{ .packet_layer = layer });
            },
            else => {
                return null;
            },
        }
    }

    pub fn get_protocol(self: *EthLayer) tcp_ip_protocol {
        _ = self;
        return EthLayer.Protocol;
    }

    pub fn deinit(self: *EthLayer) void {
        self.owner.deinit();
    }
};

pub const MacAddress = struct {
    addr: [6]u8,

    pub const InitError = error{
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

    /// Create from u48 value (MAC address as 48-bit integer)
    pub fn init_from_u48(value: u48) MacAddress {
        return .{
            .addr = .{
                @as(u8, @truncate(value >> 40)),
                @as(u8, @truncate(value >> 32)),
                @as(u8, @truncate(value >> 24)),
                @as(u8, @truncate(value >> 16)),
                @as(u8, @truncate(value >> 8)),
                @as(u8, @truncate(value)),
            },
        };
    }

    /// Convert to u48 (MAC address as 48-bit integer)
    pub fn to_u48(self: MacAddress) u48 {
        return (@as(u48, self.addr[0]) << 40) |
            (@as(u48, self.addr[1]) << 32) |
            (@as(u48, self.addr[2]) << 24) |
            (@as(u48, self.addr[3]) << 16) |
            (@as(u48, self.addr[4]) << 8) |
            (@as(u48, self.addr[5]));
    }

    /// Create from string like "AA:BB:CC:DD:EE:FF" or "AA-BB-CC-DD-EE-FF"  (case-insensitive)
    pub fn init_from_string(str: []const u8) InitError!MacAddress {
        var octets: [6]u8 = undefined;
        var oct_index: usize = 0;
        var cur_value: u8 = 0;
        var digit_count: u8 = 0;

        for (str) |c| {
            if (c == ':' or c == '-') {
                if (digit_count != 2) return InitError.InvalidFormat;
                octets[oct_index] = cur_value;
                oct_index += 1;
                if (oct_index > 6) return InitError.TooManyOctets;

                cur_value = 0;
                digit_count = 0;
                continue;
            }

            const digit = parseHexDigit(c) orelse return InitError.NonHexDigit;
            cur_value = (cur_value << 4) | digit;
            digit_count += 1;
        }

        if (digit_count != 2) return InitError.InvalidFormat;
        if (oct_index != 5) return InitError.TooFewOctets;

        octets[oct_index] = cur_value;

        return .{ .addr = octets };
    }

    /// Return string like "AA:BB:CC:DD:EE:FF"
    pub fn to_string(self: MacAddress, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(
            allocator,
            "{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}",
            .{
                self.addr[0],
                self.addr[1],
                self.addr[2],
                self.addr[3],
                self.addr[4],
                self.addr[5],
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

// Compile-time validation
comptime {
    if (@sizeOf(EthHeader) != 14) {
        @compileError("EthHeader size must be 14 bytes");
    }
}
