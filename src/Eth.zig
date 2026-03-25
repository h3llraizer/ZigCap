const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const Packet = @import("Packet.zig");

const Layer = @import("Layer.zig").Layer;
const LayerProtocols = @import("Layer.zig").LayerProtocols;

const LayerError = @import("Layer.zig").LayerError;

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

// Use extern struct for exact 14-byte layout (standard Ethernet header)
pub const EthHeader = extern struct {
    dst: [6]u8, // Destination MAC address
    src: [6]u8, // Source MAC address
    eth_type: u16, // Ethernet type (network byte order)

    comptime {
        if (@sizeOf(EthHeader) != 14) {
            @compileError("EthHeader must be 14 bytes, got " ++ @typeName(@sizeOf(EthHeader)));
        }
    }

    pub fn init_default() EthHeader {
        return .{
            .dst = [_]u8{0} ** 6,
            .src = [_]u8{0} ** 6,
            .eth_type = 0,
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
        self.eth_type = @byteSwap(@intFromEnum(eth_type)); // Network byte order
    }

    pub fn get_eth_type(self: *const EthHeader) EthType {
        return @enumFromInt(@byteSwap(self.eth_type));
    }
};

pub const EthLayer = struct {
    data: []u8, // ethhdr + payload
    const Protocol = LayerProtocols{ .LinkLayer = .ETHERNET };

    pub fn preallocated_buffer(buffer: []u8) LayerError!EthLayer {
        if (buffer.len < @sizeOf(EthHeader)) return LayerError.BufferTooSmall;

        // Verify alignment
        const alignment = @alignOf(EthHeader);
        const addr = @intFromPtr(buffer.ptr);
        if (addr % alignment != 0) {
            return LayerError.MisalignedBuffer;
        }

        return EthLayer{ .data = buffer };
    }

    pub fn print_data(self: *EthLayer) !void {
        print("{x}\n", .{self.data});
    }

    pub fn get_header(self: *EthLayer) *EthHeader {
        // Use alignCast to ensure proper alignment
        const aligned_ptr: [*]align(@alignOf(EthHeader)) u8 = @alignCast(self.data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn to_string(self: *EthLayer, allocator: Allocator) []const u8 {
        print("EthLayer to string called:\n", .{});
        const hdr = self.get_header();

        print("hdr to bytes: {x}\n", .{std.mem.asBytes(hdr)});
        print("data: {x}\n", .{self.data});
        print("data ptr: {*}\n", .{self.data.ptr});

        const src_mac = hdr.get_src_mac().to_string(allocator) catch |err| blk: {
            std.debug.print("src_mac to_string failed: {s}\n", .{@errorName(err)});
            break :blk "";
        };
        defer if (src_mac.len != 0) allocator.free(src_mac);

        const dst_mac = hdr.get_dst_mac().to_string(allocator) catch |err| blk: {
            std.debug.print("dst_mac to_string failed: {s}\n", .{@errorName(err)});
            break :blk "";
        };
        defer if (dst_mac.len != 0) allocator.free(dst_mac);

        const eth_type = hdr.get_eth_type();
        const eth_type_str = @tagName(eth_type);

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

    /// get slice of data (hdr+payload)
    pub fn get_data(self: *EthLayer) []u8 {
        //print("get_data: self={*}, self.data.ptr={*}, self.data.len={}\n", .{ self, self.data.ptr, self.data.len });
        return self.data;
    }

    /// return mutable slice of the payload
    pub fn get_payload(self: *EthLayer) []u8 {
        return self.data[EthHeaderSize..];
    }

    ///
    pub fn parse_next_layer(self: *EthLayer, buffer: []u8, allocator: Allocator) ?*Layer {
        self.* = EthLayer.preallocated_buffer(buffer[0..]) catch |err| {
            print("{s}\n", .{@errorName(err)});
            return null;
        };

        const hdr = self.get_header();
        const eth_type = hdr.get_eth_type();

        print("eth payload: {x}\n", .{self.get_payload()});

        const packet_layer: *Layer = allocator.create(Layer) catch return null;

        switch (eth_type) {
            EthType.IP => {
                if (self.data.len <= EthHeaderSize) return null;

                const ihl_byte = self.data[EthHeaderSize];
                const ip_version = ihl_byte >> 4;
                const hdr_len = (ihl_byte & 0x0F) * 4;

                if (ip_version == @intFromEnum(NetworkProtocols.IPv4)) {
                    if (hdr_len < IPv4.MinHeaderLength or hdr_len > IPv4.MaxHeaderLength) return null;

                    const ipv4_layer = allocator.create(IPv4Layer) catch |err| { // does this really need to be created?
                        print("Error creating IPv4 layer struct: {s}\n", .{@errorName(err)});
                        return null;
                    };

                    // Now you can work with the IP header at the correct offset
                    ipv4_layer.* = IPv4Layer.preallocated_buffer(buffer[0..]) catch |err| {
                        print("Error creating IPv4 Layer: {s}\n", .{@errorName(err)});
                        print("buffer: {x} ({})\n", .{ buffer, buffer.len });
                        return null;
                    };

                    packet_layer.* = Layer.implBy(ipv4_layer);
                    return packet_layer;
                }

                if (ip_version == @intFromEnum(NetworkProtocols.IPv6)) {
                    print("ipv6 layer not implemented yet.\n", .{});
                    return null;
                }

                print("Unknown IP version: {}\n", .{ip_version});
                return null;
            },
            EthType.IPV6 => {
                const ipv6_layer = IPv6Layer.init(self.data[EthHeaderSize..], allocator) catch return null;
                packet_layer.* = Layer.implBy(ipv6_layer);
                return packet_layer;
            },
            else => {
                print("Unhandled EthType: {s}\n", .{@tagName(eth_type)});
                return null;
            },
        }
    }

    /// this method assumes it's parsing from a contiguous/wire buffer. It will realloc and add padding for alignment
    pub fn get_next_layer_type(self: *EthLayer) LayerProtocols {
        const hdr = self.get_header();
        const eth_type = hdr.get_eth_type();

        switch (eth_type) {
            EthType.IP => {
                if (self.data.len <= EthHeaderSize) return LayerProtocols{ .Network = .Generic };

                const ihl_byte = self.data[EthHeaderSize];
                const ip_version = ihl_byte >> 4;
                const hdr_len = (ihl_byte & 0x0F) * 4;

                if (ip_version == @intFromEnum(NetworkProtocols.IPv4)) {
                    if (hdr_len < IPv4.MinHeaderLength or hdr_len > IPv4.MaxHeaderLength) return LayerProtocols{ .Network = .Generic };

                    return LayerProtocols{ .Network = .IPv4 };
                }

                if (ip_version == @intFromEnum(NetworkProtocols.IPv6)) {
                    return LayerProtocols{ .Network = .IPv6 };
                } else {
                    return LayerProtocols{ .Network = .Generic };
                }
            },
            EthType.IPV6 => {
                return LayerProtocols{ .Network = .IPv6 };
            },
            else => {
                return LayerProtocols{ .Network = .Generic };
            },
        }
    }

    pub fn get_src_mac(self: *EthLayer) MacAddress {
        const hdr = self.get_header();
        return hdr.get_src_mac();
    }

    pub fn get_dst_mac(self: *EthLayer) MacAddress {
        const hdr = self.get_header();
        return hdr.get_dst_mac();
    }

    pub fn set_src_mac(self: *EthLayer, src_mac: MacAddress) void {
        var hdr = self.get_header();
        hdr.set_src_mac(src_mac);
    }

    pub fn set_dst_mac(self: *EthLayer, dst_mac: MacAddress) void {
        var hdr = self.get_header();
        hdr.set_dst_mac(dst_mac);
    }

    pub fn get_eth_type(self: *EthLayer) !EthType {
        const hdr = self.get_header();
        return hdr.get_eth_type();
    }

    pub fn set_eth_type(self: *EthLayer, eth_type: EthType) !void {
        var hdr = self.get_header();
        hdr.set_eth_type(eth_type);
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
