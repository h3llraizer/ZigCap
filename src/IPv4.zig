const std = @import("std");
const print = std.debug.print;

const LayerProtocols = @import("Layer.zig").LayerProtocols;
const TransportProtocol = @import("Layer.zig").TransportProtocols;

const Layer = @import("Layer.zig").Layer;

const UDPLayer = @import("UDP.zig").UDPLayer;
const TCPLayer = @import("TCP.zig").TCPLayer;

pub const MaxHeaderLength = 60;
pub const MinHeaderLength = 20;

pub const IPv4Header = packed struct {
    version_ihl: u8,
    dscp_ecn: u8,
    total_length: u16,
    identification: u16,
    flags_fragment: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,

    src_ip0: u8,
    src_ip1: u8,
    src_ip2: u8,
    src_ip3: u8,

    dst_ip0: u8,
    dst_ip1: u8,
    dst_ip2: u8,
    dst_ip3: u8,
};

pub const IPv4Layer = struct {
    hdr: *align(1) IPv4Header,
    payload: []u8,
    const Protocol = LayerProtocols{ .Network = .IPv4 };

    pub fn init(raw: []u8, allocator: std.mem.Allocator) !*IPv4Layer {
        if (raw.len < 20) {
            return error.RawPayloadTooSmall;
        }

        const self = try allocator.create(IPv4Layer);

        self.hdr = @ptrCast(raw[0..20]);
        self.payload = raw[20..];
        return self;
    }

    pub fn to_string(self: *IPv4Layer) void {
        inline for (@typeInfo(IPv4Header).@"struct".fields) |f| {
            print("{s} : {any} : ", .{
                f.name,
                f.type,
            });
            if (f.type == u16) {
                print("{d}\n", .{std.mem.bigToNative(f.type, @field(self.hdr, f.name))});
            } else {
                print("{d}\n", .{@field(self.hdr, f.name)});
            }
        }
    }

    pub fn get_src_ip(self: *IPv4Layer) IPv4Address {
        const ip = IPv4Address.init_from_array(.{ self.hdr.src_ip0, self.hdr.src_ip1, self.hdr.src_ip2, self.hdr.src_ip3 });
        return ip;
    }

    pub fn get_dst_ip(self: *IPv4Layer) IPv4Address {
        const ip = IPv4Address.init_from_array(.{ self.hdr.dst_ip0, self.hdr.dst_ip1, self.hdr.dst_ip2, self.hdr.dst_ip3 });
        return ip;
    }

    pub fn set_src_ip(self: *IPv4Layer, src_ip: IPv4Address) void {
        self.hdr.src_ip0 = src_ip.array[0];
        self.hdr.src_ip1 = src_ip.array[1];
        self.hdr.src_ip2 = src_ip.array[2];
        self.hdr.src_ip3 = src_ip.array[3];
    }

    pub fn set_dst_ip(self: *IPv4Layer, dst_ip: IPv4Address) void {
        self.hdr.dst_ip0 = dst_ip.array[0];
        self.hdr.dst_ip1 = dst_ip.array[1];
        self.hdr.dst_ip2 = dst_ip.array[2];
        self.hdr.dst_ip3 = dst_ip.array[3];
    }

    pub fn parse_next_layer(self: *IPv4Layer, allocator: std.mem.Allocator) ?*Layer {
        const transport_type: TransportProtocol = self.get_transport_type() catch return null;

        const packet_layer: *Layer = allocator.create(Layer) catch return null;

        switch (transport_type) {
            TransportProtocol.TCP => {
                const tcp_layer = TCPLayer.init(self.payload[0..], allocator) catch return null;
                packet_layer.* = Layer.implBy(tcp_layer);
            },
            TransportProtocol.UDP => {
                const udp_layer = UDPLayer.init(self.payload[0..], allocator) catch return null;
                packet_layer.* = Layer.implBy(udp_layer);
            },
            else => {
                print("Unhandled Transport layer.\n", .{});
                return null;
            },
        }

        return packet_layer;
    }

    //TODO: Add checksum getter and setter

    pub fn get_transport_type(self: *IPv4Layer) !TransportProtocol {
        return try std.meta.intToEnum(TransportProtocol, self.hdr.protocol);
    }

    pub fn get_protocol(self: *IPv4Layer) LayerProtocols {
        _ = self;
        return IPv4Layer.Protocol;
    }

    pub fn deinit(self: *IPv4Layer, allocator: std.mem.Allocator) void {
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
