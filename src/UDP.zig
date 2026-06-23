const std = @import("std");
const DNS = @import("DNS.zig");
const IPv4 = @import("IPv4.zig");
const DHCP = @import("DHCP.zig");
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;
const ProtocolEnums = @import("ProtocolEnums.zig");

const Packet = @import("Packet.zig");
const LayerOwner = @import("Owner.zig").LayerOwner;
const ApplicationLayer = @import("GenericLayer.zig").ApplicationLayer;
const LayerIface = @import("LayerIface.zig").LayerIface;
const init_layer = @import("LayerIface.zig").init_layer;
const initLayerFromSlice = @import("LayerIface.zig").initFromSlice;

const print = std.debug.print;
const Allocator = std.mem.Allocator;
const nativeToBig = std.mem.nativeToBig;
const activeTag = std.meta.activeTag;
const panic = std.debug.panic;
const LayerError = ProtocolEnums.LayerError;

pub const UDPHeaderSize = 8;

const default_hdr = UDPHeader.init_default();

// UDP Header structure (extern struct for exact layout)
pub const UDPHeader = extern struct {
    src_port: [2]u8 = .{0x00} ** 2, // Source port (network byte order)
    dst_port: [2]u8 = .{0x00} ** 2, // Destination port (network byte order)
    length: [2]u8 = .{ 0x00, 0x08 }, // UDP length (header + payload) in network byte order
    checksum: [2]u8 = .{0x00} ** 2, // UDP checksum (optional, 0 means not used in IPv4)

    comptime {
        if (@sizeOf(UDPHeader) != UDPHeaderSize) {
            @compileError("UDPHeader must be 8 bytes, got " ++ @typeName(@sizeOf(UDPHeader)));
        }
    }

    pub fn init_default() UDPHeader {
        var hdr: UDPHeader = .{
            .src_port = .{0x00} ** 2, // Source port (network byte order)
            .dst_port = .{0x00} ** 2, // Destination port (network byte order)
            .length = .{ 0x00, 0x00 }, // UDP length (header + payload) in network byte order
            .checksum = .{0x00} ** 2, // UDP checksum (optional, 0 means not used in IPv4)
        };

        hdr.set_length(8);

        return hdr;
    }

    /// sets as big endian
    pub fn set_src_port(self: *UDPHeader, port: u16) void {
        std.mem.writeInt(u16, &self.src_port, port, .big); // Network byte order
    }

    /// returns little endian
    pub fn get_src_port(self: *const UDPHeader) u16 {
        return std.mem.readInt(u16, &self.src_port, .big);
    }

    /// sets as big endian
    pub fn set_dst_port(self: *UDPHeader, port: u16) void {
        std.mem.writeInt(u16, &self.dst_port, port, .big);
    }

    /// returns little endian
    pub fn get_dst_port(self: *const UDPHeader) u16 {
        return std.mem.readInt(u16, &self.dst_port, .big);
    }

    pub fn set_length(self: *UDPHeader, len: u16) void {
        std.mem.writeInt(u16, &self.length, len, .big);
    }

    pub fn get_length(self: *const UDPHeader) u16 {
        return std.mem.readInt(u16, &self.length, .big);
    }

    pub fn get_checksum(self: *const UDPHeader) u16 {
        return std.mem.readInt(u16, &self.checksum, .big);
    }

    /// Calculate UDP checksum (requires pseudo-header and payload)
    /// For IPv4, the pseudo-header includes: source IP, dest IP, protocol, UDP length
    pub fn calculate_checksum(self: *UDPHeader, src_ip: [4]u8, dst_ip: [4]u8, payload: []const u8) void {
        self.checksum = .{ 0x00, 0x00 };

        var sum: u32 = 0;

        const src_w1 = (@as(u16, src_ip[0]) << 8) | src_ip[1];
        const src_w2 = (@as(u16, src_ip[2]) << 8) | src_ip[3];

        sum += src_w1;
        sum += src_w2;

        const dst_w1 = (@as(u16, dst_ip[0]) << 8) | dst_ip[1];
        const dst_w2 = (@as(u16, dst_ip[2]) << 8) | dst_ip[3];

        sum += dst_w1;
        sum += dst_w2;

        sum += 0x0011;

        sum += self.get_length();

        const h_src = self.get_src_port();
        const h_dst = self.get_dst_port();
        const h_len = self.get_length();
        const h_chk = self.get_checksum();

        sum += h_src;
        sum += h_dst;
        sum += h_len;
        sum += h_chk;

        var i: usize = 0;
        while (i + 1 < payload.len) {
            const word = (@as(u16, payload[i]) << 8) | payload[i + 1];
            sum += word;
            i += 2;
        }

        if (i < payload.len) {
            const last = @as(u16, payload[i]) << 8;
            sum += last;
        }

        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        const checksum = ~@as(u16, @intCast(sum));

        std.mem.writeInt(u16, &self.checksum, if (checksum == 0) 0xFFFF else checksum, .big);
    }

    /// Validate UDP checksum
    fn validate_checksum(self: *const UDPHeader, src_ip: u32, dst_ip: u32, payload: []const u8) bool {
        var sum: u32 = 0;

        // Add pseudo-header (IPv4)

        const src = @byteSwap(src_ip);
        const dst = @byteSwap(dst_ip);

        sum += (src >> 16) & 0xFFFF;
        sum += src & 0xFFFF;
        sum += (dst >> 16) & 0xFFFF;
        sum += dst & 0xFFFF;
        sum += 0x0011; // Protocol = 17
        sum += self.length;

        const words = @as([*]const u16, @ptrCast(self));
        for (0..UDPHeaderSize / 2) |i| {
            sum += words[i];
        }

        var i: usize = 0;
        while (i + 1 < payload.len) {
            const word = (@as(u16, payload[i]) << 8) | payload[i + 1];
            sum += word;
            i += 2;
        }

        if (i < payload.len) {
            sum += @as(u16, payload[i]) << 8;
        }

        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return @as(u16, @intCast(sum)) == 0xFFFF;
    }
};

pub const UDPLayer = struct {
    owner: LayerOwner,

    const Protocol = tcp_ip_protocol.udp;

    pub fn init(allocator: Allocator) LayerError!UDPLayer {
        return try init_layer(UDPLayer, allocator, UDPHeader, default_hdr);
    }

    pub fn initFromSlice(slice: []u8, allocator: Allocator) LayerError!UDPLayer {
        if (slice.len < UDPHeaderSize) return LayerError.BufferTooSmall;

        const hdr_len = UDPHeaderSize;

        return try initLayerFromSlice(slice, UDPLayer, hdr_len, UDPHeaderSize, UDPHeaderSize, allocator);
    }

    pub fn zero_hdr() []u8 {
        var header = UDPHeader.init_default();
        var data: []u8 = undefined;
        @memcpy(data[0..@sizeOf(UDPHeader)], std.mem.asBytes(&header));
        return data;
    }

    pub fn get_mutable_header(self: *const UDPLayer) *UDPHeader {
        const data = self.get_data();

        if (data.len < UDPHeaderSize) {
            panic("UDP data len ({}) less than UDPHeaderSize", .{data.len});
        }

        return @ptrCast(data.ptr);
    }

    pub fn get_immutable_header(self: *const UDPLayer) *const UDPHeader {
        const data: []const u8 = self.get_data();

        if (data.len < UDPHeaderSize) {
            panic("UDP data len ({}) less than UDPHeaderSize", .{data.len});
        }

        return @ptrCast(data.ptr);
    }

    /// Get slice of data (header + payload)
    pub fn get_data(self: *const UDPLayer) []u8 {
        return self.owner.get_data();
    }

    /// Get the payload (data after UDP header)
    pub fn get_payload(self: *UDPLayer) []const u8 {
        const data = self.get_data();

        if (data.len > UDPHeaderSize) {
            return data[UDPHeaderSize..]; // return remaining bytes after the header
        } else {
            return "";
        }
    }

    pub fn get_length(self: *UDPLayer) u16 {
        const hdr = self.get_immutable_header();
        return hdr.get_length();
    }

    pub fn calculate_length(self: *UDPLayer) void {
        const data = self.get_data();
        var hdr = self.get_mutable_header();
        const length = @as(u16, @intCast(data.len));
        hdr.set_length(length);
    }

    pub fn validate_layer(self: *UDPLayer) void {
        //        const hdr = self.get_mutable_header();
        self.calculate_length();

        switch (self.owner) {
            .packet_layer => |layer| {
                if (layer.prev_layer) |prev_layer| {
                    if (prev_layer.layer_iface.get_protocol() == tcp_ip_protocol.ipv4) {
                        var ipv4_iface: *LayerIface = &prev_layer.layer_iface;
                        var ipv4_layer: *IPv4.IPv4Layer = &ipv4_iface.ipv4Layer;
                        const ipv4_hdr: *const IPv4.IPv4Header = ipv4_layer.get_immutable_header();

                        self.get_mutable_header().calculate_checksum(ipv4_hdr.get_src_ip().array, ipv4_hdr.get_dst_ip().array, self.get_data()[UDPHeaderSize..]);
                    } else if (prev_layer.layer_iface.get_protocol() == tcp_ip_protocol.ipv6) {
                        return;
                        //prev_protocol = net_protocol.IPv6;
                    }
                } else {
                    print("no prev layer.\n", .{});
                }
            },
            else => return,
        }
    }

    pub const UDPError = error{
        IPv6NotImplemented,
        NoPrevLayer,
        NotAttachedToPacket,
        Unhandled,
    };

    pub fn validate_checksum(self: *const UDPLayer) UDPError!bool {
        const hdr = self.get_immutable_header();

        switch (self.owner) {
            .packet_layer => |layer| {
                if (layer.prev_layer) |prev_layer| {
                    if (prev_layer.layer_iface.get_protocol() == tcp_ip_protocol.ipv4) {
                        var ipv4_iface: *LayerIface = &prev_layer.layer_iface;
                        var ipv4_layer: *IPv4.IPv4Layer = &ipv4_iface.ipv4Layer;
                        const ipv4_hdr: *const IPv4.IPv4Header = ipv4_layer.get_immutable_header();

                        return hdr.validate_checksum(ipv4_hdr.get_src_ip().to_u32(), ipv4_hdr.get_dst_ip().to_u32(), self.get_data()[UDPHeaderSize..]);
                    } else if (prev_layer.layer_iface.get_protocol() == tcp_ip_protocol.ipv6) {
                        return error.IPv6NotImplemented;
                        //prev_protocol = net_protocol.IPv6;
                    }
                } else {
                    return error.NoPrevLayer;
                }
            },
            else => return error.NotAttachedToPacket,
        }

        return error.Unhandled;
    }

    /// caller needs to free
    pub fn to_string(self: *UDPLayer, allocator: Allocator) []const u8 {
        const hdr = self.get_immutable_header();

        const src_port = hdr.get_src_port();
        const dst_port = hdr.get_dst_port();

        return std.fmt.allocPrint(allocator, "UDP Layer: src_port: {} dst_port: {}\n", .{ src_port, dst_port }) catch return "";
    }

    pub fn get_next_layer_type(self: *UDPLayer, layer: *Packet.Layer) LayerError!?LayerIface {
        const hdr = self.get_immutable_header();
        // check src and dst ports
        // check header length of expected protocol

        if ((hdr.get_dst_port() == 53 or hdr.get_src_port() == 53) and self.get_payload().len >= DNS.DNSHeaderSize) {
            return LayerIface{ .dnsLayer = .{ .owner = .{ .packet_layer = layer } } };
        }

        if ((hdr.get_dst_port() == 67 or hdr.get_src_port() == 68) and self.get_payload().len >= DHCP.DHCPHeaderSize) {
            return LayerIface{ .dhcpLayer = .{ .owner = .{ .packet_layer = layer } } };
        }

        return LayerIface{ .genericAppLayer = .{ .owner = .{ .packet_layer = layer } } };
    }

    pub fn get_protocol(self: *UDPLayer) tcp_ip_protocol {
        _ = self;
        return UDPLayer.Protocol;
    }

    pub fn deinit(self: *UDPLayer) void {
        self.owner.deinit();
    }
};

// Compile-time validation
comptime {
    if (@sizeOf(UDPHeader) != 8) {
        @compileError("UDPHeader size must be 8 bytes");
    }
}
