const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const LayerProtocols = @import("Layer.zig").LayerProtocols;
const TransportProtocol = @import("Layer.zig").TransportProtocols;

const Layer = @import("Layer.zig").Layer;

const UDPLayer = @import("UDP.zig").UDPLayer;
const TCPLayer = @import("TCP.zig").TCPLayer;

pub const MaxHeaderLength = 60;
pub const MinHeaderLength = 20;

pub const IPv4Header = packed struct {
    version_ihl: u8 = 0,
    dscp_ecn: u8 = 0,
    total_length: u16 = 0,
    identification: u16 = 0,
    flags_fragment: u16 = 0,
    ttl: u8 = 0,
    protocol: u8 = 0,
    checksum: u16 = 0,

    src_ip0: u8 = 0,
    src_ip1: u8 = 0,
    src_ip2: u8 = 0,
    src_ip3: u8 = 0,

    dst_ip0: u8 = 0,
    dst_ip1: u8 = 0,
    dst_ip2: u8 = 0,
    dst_ip3: u8 = 0,
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

    pub fn create(allocator: std.mem.Allocator) !*IPv4Layer {
        const self = try allocator.create(IPv4Layer);
        self.data = try allocator.alloc(u8, 20);
        return self;
    }

    pub fn get_src_ip(self: *IPv4Layer) IPv4Address {
        const hdr = self.get_header();
        const ip = IPv4Address.init_from_array(.{ hdr.src_ip0, hdr.src_ip1, hdr.src_ip2, hdr.src_ip3 });
        return ip;
    }

    pub fn get_dst_ip(self: *IPv4Layer) IPv4Address {
        const hdr = self.get_header();

        const ip = IPv4Address.init_from_array(.{ hdr.dst_ip0, hdr.dst_ip1, hdr.dst_ip2, hdr.dst_ip3 });
        return ip;
    }

    pub fn set_src_ip(self: *IPv4Layer, src_ip: IPv4Address) void {
        var hdr = self.get_header();

        hdr.src_ip0 = src_ip.array[0];
        hdr.src_ip1 = src_ip.array[1];
        hdr.src_ip2 = src_ip.array[2];
        hdr.src_ip3 = src_ip.array[3];
    }

    pub fn set_dst_ip(self: *IPv4Layer, dst_ip: IPv4Address) void {
        var hdr = self.get_header();
        hdr.dst_ip0 = dst_ip.array[0];
        hdr.dst_ip1 = dst_ip.array[1];
        hdr.dst_ip2 = dst_ip.array[2];
        hdr.dst_ip3 = dst_ip.array[3];
    }

    pub fn parse_next_layer(self: *IPv4Layer, allocator: std.mem.Allocator) ?*Layer {
        const transport_type: TransportProtocol = self.get_transport_type() catch return null;

        const packet_layer: *Layer = allocator.create(Layer) catch return null;

        switch (transport_type) {
            TransportProtocol.TCP => {
                const tcp_layer = TCPLayer.init(self.data[0..], allocator) catch return null;
                packet_layer.* = Layer.implBy(tcp_layer);
            },
            TransportProtocol.UDP => {
                const udp_layer = UDPLayer.init(self.data[0..], allocator) catch return null;
                packet_layer.* = Layer.implBy(udp_layer);
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

    //TODO: Add checksum getter and setter
    pub fn calculate_checksum(self: *IPv4Layer) void {
        const hdr = self.get_header();
        const bytes = std.mem.asBytes(hdr);

        var sum: u32 = 0;

        var i: usize = 0;
        while (i < bytes.len) : (i += 2) {
            const word: u16 = (@as(u16, bytes[i]) << 8) | bytes[i + 1];
            sum += word;
        }

        while (sum >> 16 != 0) {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        self.hdr.checksum = ~@as(u16, @intCast(sum));
    }

    //    pub fn get_header(self: *IPv4Layer) *IPv4Header {
    //        print("layer len: {d}\n", .{self.data.len});
    //        return @ptrCast(@alignCast(self.data[0..20]));
    //    }

    pub fn get_header(self: *IPv4Layer) *align(1) IPv4Header {
        return std.mem.bytesAsValue(IPv4Header, self.data[0..20]);
    }

    pub fn to_string(self: *IPv4Layer, allocator: Allocator) []const u8 {
        const hdr = self.get_header();

        const src_ip_str = self.get_src_ip().to_string(allocator) catch return "";
        defer allocator.free(src_ip_str);

        const dst_ip_str = self.get_dst_ip().to_string(allocator) catch return "";
        defer allocator.free(dst_ip_str);

        const version_ihl: u8 = hdr.version_ihl;
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
            \\  src_ip: {s}
            \\  dst_ip: {s}
            \\  version_ihl: {}
            \\  dscp_ecn: {}
            \\  total_length: {}
            \\  identification: {}
            \\  flags_fragment: {}
            \\  ttl: {}
            \\  protocol: {}
            \\  checksum: {}
        ,
            .{
                src_ip_str,
                dst_ip_str,
                version_ihl,
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
