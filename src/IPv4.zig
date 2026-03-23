const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const LayerProtocols = @import("Layer.zig").LayerProtocols;
const TransportProtocol = @import("Layer.zig").TransportProtocols;

const Layer = @import("Layer.zig").Layer;

const LayerError = @import("Layer.zig").LayerError;

const Packet = @import("Packet.zig");

const UDP = @import("UDPLayer.zig");
const TCPLayer = @import("TCP.zig").TCPLayer;

pub const MaxHeaderLength = 60;
pub const MinHeaderLength = 20;

// Use extern struct for exact 20-byte layout (standard IPv4 header)
pub const IPv4Header = extern struct {
    version_ihl: u8 = 0x45, // Default to version 4, IHL 5
    dscp_ecn: u8 = 0,
    total_length: u16 = 0,
    identification: u16 = 0,
    flags_fragment: u16 = 0,
    ttl: u8 = 64, // Default TTL
    protocol: u8 = 0,
    checksum: u16 = 0,
    src_ip: u32 = 0,
    dst_ip: u32 = 0,

    comptime {
        if (@sizeOf(IPv4Header) != 20) {
            @compileError("IPv4Header must be 20 bytes, got " ++ @typeName(@sizeOf(IPv4Header)));
        }
    }

    pub fn init_default() IPv4Header {
        return .{
            .version_ihl = 0x45,
            .dscp_ecn = 0,
            .total_length = 0,
            .identification = 0,
            .flags_fragment = 0,
            .ttl = 64,
            .protocol = 0,
            .checksum = 0,
            .src_ip = 0,
            .dst_ip = 0,
        };
    }

    pub fn calculate_checksum(self: *IPv4Header) void {
        // Save the original checksum field
        const old_checksum = self.checksum;
        self.checksum = 0;

        var sum: u32 = 0;
        const words = @as([*]const u16, @ptrCast(self));

        // Sum all 16-bit words
        for (0..@sizeOf(IPv4Header) / 2) |i| {
            sum += words[i];
        }

        // Fold the sum to 16 bits
        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // Take one's complement and store
        self.checksum = ~@as(u16, @intCast(sum));

        // If the checksum calculation resulted in 0, the RFC says to use 0xFFFF
        if (self.checksum == 0) {
            self.checksum = 0xFFFF;
        }

        _ = old_checksum;
    }
};

pub const IPv4Layer = struct {
    data: []u8,
    const Protocol = LayerProtocols{ .Network = .IPv4 };

    pub fn init(raw: []u8, allocator: std.mem.Allocator) !*IPv4Layer {
        if (raw.len < 20) {
            return error.RawPayloadTooSmall;
        }

        const self = try allocator.create(IPv4Layer);
        self.data = raw;
        return self;
    }

    pub fn allocator_owned_buffer(allocator: Allocator) !IPv4Layer {
        var self = IPv4Layer{ .data = undefined };
        self.data = try allocator.alloc(u8, @sizeOf(IPv4Header));
        return self;
    }

    pub fn preallocated_buffer(buffer: []u8) LayerError!IPv4Layer {
        print("buffer len: {}\n", .{buffer.len});
        if (buffer.len < @sizeOf(IPv4Header)) return error.BufferTooSmall;

        // Verify alignment
        const alignment = @alignOf(IPv4Header);
        const addr = @intFromPtr(buffer.ptr);
        print("addr {any}\n", .{addr});
        print("mod {any}\n", .{addr % alignment});

        if (addr % alignment != 0) {
            return error.MisalignedBuffer;
        }

        return IPv4Layer{ .data = buffer };
    }

    pub fn create(allocator: std.mem.Allocator) !*IPv4Layer {
        const self = try allocator.create(IPv4Layer);
        self.data = try allocator.alloc(u8, @sizeOf(IPv4Header));
        return self;
    }

    // In your IPv4Layer, update set_src_ip and set_dst_ip:
    pub fn set_src_ip(self: *IPv4Layer, src_ip: IPv4Address) void {
        var hdr = self.get_header();
        // Convert to network byte order (big-endian)
        hdr.src_ip = @byteSwap(src_ip.to_u32());
    }

    pub fn set_dst_ip(self: *IPv4Layer, dst_ip: IPv4Address) void {
        var hdr = self.get_header();
        // Convert to network byte order (big-endian)
        hdr.dst_ip = @byteSwap(dst_ip.to_u32());
    }

    // Also update get_src_ip and get_dst_ip:
    pub fn get_src_ip(self: *IPv4Layer) IPv4Address {
        const hdr = self.get_header();
        // Convert from network byte order to host order
        return IPv4Address.init_from_u32(@byteSwap(hdr.src_ip));
    }

    pub fn get_dst_ip(self: *IPv4Layer) IPv4Address {
        const hdr = self.get_header();
        // Convert from network byte order to host order
        return IPv4Address.init_from_u32(@byteSwap(hdr.dst_ip));
    }

    /// get slice of data (hdr+payload)
    pub fn get_data(self: *IPv4Layer) []u8 {
        return self.data;
    }

    /// return mutable slice of the payload
    pub fn get_payload(self: *IPv4Layer) []u8 {
        const header_len = (self.get_header().version_ihl & 0x0F) * 4;
        return self.data[header_len..];
    }

    pub fn parse_next_layer(self: *IPv4Layer, buffer_allocator: Allocator, layer_allocator: Allocator) ?*Layer {
        const transport_type: TransportProtocol = self.get_transport_type() catch return null;

        const packet_layer: *Layer = layer_allocator.create(Layer) catch return null;

        switch (transport_type) {
            TransportProtocol.TCP => {
                //                const tcp_layer = TCPLayer.init(self.get_payload(), allocator) catch return null;
                //                packet_layer.* = Layer.implBy(tcp_layer);
                return null;
            },
            TransportProtocol.UDP => {
                // Calculate the new total size needed
                const current_offset: usize = @sizeOf(IPv4Header); // where the UDP header starts
                const udp_size: usize = @sizeOf(UDP.UDPHeader);
                const new_total_size = current_offset + udp_size;

                // Reallocate the entire buffer
                self.data = buffer_allocator.realloc(self.data, new_total_size) catch |err| {
                    print("Error reallocing for UDP Layer: {s}\n", .{@errorName(err)});
                    return null;
                };

                // Now you can work with the UDP header at the correct offset
                var udp_layer = IPv4Layer.preallocated_buffer(self.data[current_offset..][0..udp_size]) catch |err| {
                    print("Error creating IPv4 Layer: {s}\n", .{@errorName(err)});
                    return null;
                };
                packet_layer.* = Layer.implBy(&udp_layer);
            },
            else => {
                print("Unhandled Transport layer.\n", .{});
                return null;
            },
        }

        return packet_layer;
    }

    pub fn get_checksum(self: *IPv4Layer) u16 {
        const hdr = self.get_header();
        return std.mem.bigToNative(u16, hdr.checksum);
    }

    pub fn calculate_checksum(self: *IPv4Layer) void {
        var hdr = self.get_header();
        hdr.calculate_checksum();
    }

    pub fn get_header(self: *IPv4Layer) *IPv4Header {
        // Use alignCast to ensure proper alignment
        const aligned_ptr: [*]align(@alignOf(IPv4Header)) u8 = @alignCast(self.data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn to_string(self: *IPv4Layer, allocator: Allocator) []const u8 {
        const hdr = self.get_header();

        const src_ip_str = self.get_src_ip().to_string(allocator) catch return "";
        defer allocator.free(src_ip_str);

        const dst_ip_str = self.get_dst_ip().to_string(allocator) catch return "";
        defer allocator.free(dst_ip_str);

        const version = (hdr.version_ihl >> 4);
        const ihl = (hdr.version_ihl & 0x0F);
        const dscp_ecn: u8 = hdr.dscp_ecn;

        const identification: u16 = std.mem.bigToNative(u16, hdr.identification);
        const flags_fragment: u16 = std.mem.bigToNative(u16, hdr.flags_fragment);
        const total_length: u16 = std.mem.bigToNative(u16, hdr.total_length);
        const checksum: u16 = std.mem.bigToNative(u16, hdr.checksum);

        const ttl: u8 = hdr.ttl;
        const protocol: u8 = hdr.protocol;

        return std.fmt.allocPrint(
            allocator,
            \\IPv4 Layer:
            \\  version: {}
            \\  ihl: {}
            \\  src_ip: {s}
            \\  dst_ip: {s}
            \\  dscp_ecn: {}
            \\  total_length: {}
            \\  identification: {}
            \\  flags_fragment: {}
            \\  ttl: {}
            \\  protocol: {}
            \\  checksum: {}
        ,
            .{
                version,
                ihl,
                src_ip_str,
                dst_ip_str,
                dscp_ecn,
                total_length,
                identification,
                flags_fragment,
                ttl,
                protocol,
                checksum,
            },
        ) catch return "";
    }

    pub fn get_transport_type(self: *IPv4Layer) !TransportProtocol {
        const hdr = self.get_header();
        return try std.meta.intToEnum(TransportProtocol, hdr.protocol);
    }

    pub fn get_protocol(self: *IPv4Layer) LayerProtocols {
        _ = self;
        return IPv4Layer.Protocol;
    }

    pub fn deinit(self: *IPv4Layer, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
        allocator.destroy(self);
    }
};

pub const IPv4Address = struct {
    array: [4]u8,

    pub const Error = error{
        InvalidFormat,
        TooManyOctets,
        TooFewOctets,
        OctetOverflow,
        NonDigit,
    };

    pub fn init_from_array(raw: [4]u8) IPv4Address {
        return .{ .array = raw };
    }

    pub fn init_from_u32(value: u32) IPv4Address {
        return .{
            .array = .{
                @as(u8, @truncate(value >> 24)),
                @as(u8, @truncate(value >> 16)),
                @as(u8, @truncate(value >> 8)),
                @as(u8, @truncate(value)),
            },
        };
    }

    pub fn to_u32(self: IPv4Address) u32 {
        return (@as(u32, self.array[0]) << 24) |
            (@as(u32, self.array[1]) << 16) |
            (@as(u32, self.array[2]) << 8) |
            (@as(u32, self.array[3]));
    }

    pub fn init_from_string(str: []const u8) !IPv4Address {
        var octets: [4]u8 = undefined;

        var oct_index: usize = 0;
        var cur_value: u16 = 0;
        var have_digit = false;

        for (str) |c| {
            if (c == '.') {
                if (!have_digit) return Error.InvalidFormat;
                if (oct_index >= 4) return Error.TooManyOctets;

                octets[oct_index] = @intCast(cur_value);
                oct_index += 1;

                cur_value = 0;
                have_digit = false;
                continue;
            }

            if (c < '0' or c > '9')
                return Error.NonDigit;

            have_digit = true;
            cur_value = cur_value * 10 + (c - '0');

            if (cur_value > 255)
                return Error.OctetOverflow;
        }

        if (!have_digit) return Error.InvalidFormat;
        if (oct_index != 3) return Error.TooFewOctets;

        octets[oct_index] = @intCast(cur_value);

        return .{ .array = octets };
    }

    pub fn to_string(self: IPv4Address, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(
            allocator,
            "{d}.{d}.{d}.{d}",
            .{
                self.array[0],
                self.array[1],
                self.array[2],
                self.array[3],
            },
        );
    }
};

pub fn parseIPv4Header(packet: []const u8) !void {
    if (packet.len < 20) {
        return error.InvalidPacket;
    }

    const version_ihl = packet[0];
    const version = version_ihl >> 4;
    const ihl = version_ihl & 0x0F; // header length in 32-bit words
    const header_length = ihl * 4;

    if (packet.len < header_length) {
        return error.InvalidPacket;
    }

    const total_length = std.mem.readInt(u16, packet[2..4], .big);
    const protocol = packet[9]; // 1 = ICMP, 6 = TCP, 17 = UDP
    const src_ip = packet[12..16];
    const dst_ip = packet[16..20];

    std.debug.print("IPv4 Header:\n", .{});
    std.debug.print("Version: {d}, Header Length: {d} bytes\n", .{ version, header_length });
    std.debug.print("Total Length: {d}\n", .{total_length});
    std.debug.print("Protocol: {d}\n", .{protocol});
    std.debug.print("Source IP: {d}.{d}.{d}.{d}\n", .{ src_ip[0], src_ip[1], src_ip[2], src_ip[3] });
    std.debug.print("Destination IP: {d}.{d}.{d}.{d}\n", .{ dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3] });
}
