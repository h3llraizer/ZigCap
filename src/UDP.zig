const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const DNS = @import("DNS.zig");

const IPv4 = @import("IPv4.zig");

const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;
const ProtocolEnums = @import("ProtocolEnums.zig");
const LayerError = ProtocolEnums.LayerError;

const Packet = @import("Packet.zig");
const LayerOwner = @import("Layer.zig").LayerOwner;
const ApplicationLayer = @import("GenericLayer.zig").ApplicationLayer;

const LayerIface = @import("LayerIface.zig").LayerIface;

const nativeToBig = std.mem.nativeToBig;
const activeTag = std.meta.activeTag;
const panic = std.debug.panic;

pub const UDPHeaderSize = 8;

// UDP Header structure (extern struct for exact layout)
pub const UDPHeader = extern struct {
    src_port: u16 = 0, // Source port (network byte order)
    dst_port: u16 = 0, // Destination port (network byte order)
    length: u16 = 0, // UDP length (header + payload) in network byte order
    checksum: u16 = 0, // UDP checksum (optional, 0 means not used in IPv4)

    comptime {
        if (@sizeOf(UDPHeader) != UDPHeaderSize) {
            @compileError("UDPHeader must be 8 bytes, got " ++ @typeName(@sizeOf(UDPHeader)));
        }
    }

    pub fn init_default() UDPHeader {
        return .{
            .src_port = 0,
            .dst_port = 0,
            .length = std.mem.nativeToBig(u16, 8),
            .checksum = 0,
        };
    }

    pub fn set_src_port(self: *UDPHeader, port: u16) void {
        self.src_port = @byteSwap(port); // Network byte order
    }

    pub fn get_src_port(self: *const UDPHeader) u16 {
        return @byteSwap(self.src_port);
    }

    pub fn set_dst_port(self: *UDPHeader, port: u16) void {
        self.dst_port = @byteSwap(port);
    }

    /// returns little endian
    pub fn get_dst_port(self: *const UDPHeader) u16 {
        return @byteSwap(self.dst_port);
    }

    pub fn set_length(self: *UDPHeader, len: u16) void {
        self.length = @byteSwap(len);
    }

    pub fn get_length(self: *const UDPHeader) u16 {
        return @byteSwap(self.length);
    }

    pub fn get_checksum(self: *const UDPHeader) u16 {
        return @byteSwap(self.checksum);
    }

    /// Calculate UDP checksum (requires pseudo-header and payload)
    /// For IPv4, the pseudo-header includes: source IP, dest IP, protocol, UDP length
    pub fn calculate_checksum(self: *UDPHeader, src_ip: u32, dst_ip: u32, payload: []const u8) void {
        self.checksum = 0;

        var sum: u32 = 0;

        const src = std.mem.nativeToBig(u32, src_ip);
        const src_bytes = std.mem.asBytes(&src);

        const src_w1 = (@as(u16, src_bytes[0]) << 8) | src_bytes[1];
        const src_w2 = (@as(u16, src_bytes[2]) << 8) | src_bytes[3];

        sum += src_w1;
        sum += src_w2;

        const dst = std.mem.nativeToBig(u32, dst_ip);
        const dst_bytes = std.mem.asBytes(&dst);

        const dst_w1 = (@as(u16, dst_bytes[0]) << 8) | dst_bytes[1];
        const dst_w2 = (@as(u16, dst_bytes[2]) << 8) | dst_bytes[3];

        sum += dst_w1;
        sum += dst_w2;

        sum += 0x0011;

        sum += @byteSwap(self.length);

        const udp_bytes = @as([*]const u8, @ptrCast(self));

        const h_src = (@as(u16, udp_bytes[0]) << 8) | udp_bytes[1];
        const h_dst = (@as(u16, udp_bytes[2]) << 8) | udp_bytes[3];
        const h_len = (@as(u16, udp_bytes[4]) << 8) | udp_bytes[5];
        const h_chk = (@as(u16, udp_bytes[6]) << 8) | udp_bytes[7];

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

        self.checksum = ~@as(u16, @intCast(sum));

        if (self.checksum == 0) {
            self.checksum = 0xFFFF;
        }
    }

    /// Validate UDP checksum
    pub fn validate_checksum(self: *const UDPHeader, src_ip: u32, dst_ip: u32, payload: []const u8) bool {
        var sum: u32 = 0;

        // Add pseudo-header (IPv4)
        sum += (src_ip >> 16) & 0xFFFF;
        sum += src_ip & 0xFFFF;
        sum += (dst_ip >> 16) & 0xFFFF;
        sum += dst_ip & 0xFFFF;
        sum += 0x0011; // Protocol = 17
        sum += self.get_length();

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

    pub fn init(owner: LayerOwner) LayerError!UDPLayer {
        switch (owner) {
            .packet_layer => {
                return UDPLayer{
                    .owner = owner,
                };
            },
            .owned_buffer => {
                var self = UDPLayer{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < UDPHeaderSize) {
                    const udp_data = try self.owner.owned_buffer.extend(buffer_len, UDPHeaderSize);
                    @memset(udp_data, 0);
                    var header = UDPHeader.init_default();
                    @memcpy(udp_data[0..UDPHeaderSize], std.mem.asBytes(&header));
                }

                return self;
            },
        }
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

        const aligned_ptr: [*]align(@alignOf(UDPHeader)) u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn get_immutable_header(self: *const UDPLayer) *const UDPHeader {
        const data: []const u8 = self.get_data();

        if (data.len < UDPHeaderSize) {
            panic("UDP data len ({}) less than UDPHeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(UDPHeader)) const u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
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

    pub fn calculate_checksum(self: *UDPLayer) void {
        const hdr = self.get_mutable_header();
        self.calculate_length();

        switch (self.owner) {
            .packet_layer => |layer| {
                if (layer.prev_layer) |prev_layer| {
                    if (prev_layer.layer_iface.get_protocol() == tcp_ip_protocol.ipv4) {
                        var ipv4_iface: *LayerIface = &prev_layer.layer_iface;
                        var ipv4_layer: *IPv4.IPv4Layer = &ipv4_iface.ipv4Layer;
                        const ipv4_hdr: *const IPv4.IPv4Header = ipv4_layer.get_immutable_header();

                        hdr.calculate_checksum(ipv4_hdr.get_src_ip().to_u32(), ipv4_hdr.get_dst_ip().to_u32(), self.get_data()[UDPHeaderSize..]);
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

    /// caller needs to free
    pub fn to_string(self: *UDPLayer, allocator: Allocator) []const u8 {
        const hdr = self.get_immutable_header();

        const src_port = hdr.get_src_port();
        const dst_port = hdr.get_dst_port();
        const length = hdr.get_length();
        const checksum = nativeToBig(u16, hdr.checksum);

        return std.fmt.allocPrint(allocator, "UDP: src_port: {} dst_port: {} length: {} checksum: 0x{x:0>4}", .{
            src_port,
            dst_port,
            length,
            checksum,
        }) catch return "";
    }

    pub fn get_next_layer_type(self: *UDPLayer, layer: *Packet.Layer) !?LayerIface {
        const hdr = self.get_immutable_header();
        // check src and dst ports
        // check header length of expected protocol

        if ((hdr.get_dst_port() == 53 or hdr.get_src_port() == 53) and self.get_payload().len >= DNS.DNSHeaderSize) {
            return try LayerIface.init(DNS.DNSLayer, LayerOwner{ .packet_layer = layer });
        }

        return try LayerIface.init(ApplicationLayer, LayerOwner{ .packet_layer = layer });
    }

    pub fn get_protocol(self: *UDPLayer) tcp_ip_protocol {
        _ = self;
        return UDPLayer.Protocol;
    }

    pub fn deinit(self: *UDPLayer) void {
        switch (self.owner) {
            .packet_layer => {
                return; // Layer in packet - don't free
            },
            .owned_buffer => |*buffer| {
                return buffer.deinit(); // standalone layer - it is mutable by default
            },
        }
    }
};

// Compile-time validation
comptime {
    if (@sizeOf(UDPHeader) != 8) {
        @compileError("UDPHeader size must be 8 bytes");
    }
}
