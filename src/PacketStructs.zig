const std = @import("std");
const print = std.debug.print;
const allocPrint = std.fmt.allocPrint;
const ProtocolEnums = @import("ProtocolEnums.zig");
const ProtocolType = ProtocolEnums.ProtocolType;
const EtherType = ProtocolEnums.EtherType;
const IPv4Protocol = ProtocolEnums.IPv4Protocol;
const Eth = @import("Eth.zig");
const IPv4 = @import("IPv4.zig");
const TCP = @import("TCP.zig");
const UDP = @import("UDP.zig");

pub const RawPacket = struct {
    timestamp_s: u32,
    timestamp_ms: u32,
    raw_data: []u8,
    raw_len: u32,
    link_type: c_int,

    pub fn init(ts_usec: c_long, ts_sec: c_long, raw: []const u8, len: c_uint, link_type: c_int, allocator: *std.mem.Allocator) !*RawPacket {
        var p: *RawPacket = try allocator.create(RawPacket);

        p.timestamp_ms = @intCast(ts_usec);

        p.timestamp_s = @intCast(ts_sec);

        p.raw_len = @intCast(len);

        p.raw_data = try allocator.alloc(u8, p.raw_len);

        p.link_type = link_type;

        @memmove(p.raw_data, raw[0..p.raw_len]);

        return p;
    }

    pub fn slice(self: *RawPacket, offset: usize, len: usize) ![]const u8 {
        if (offset > self.raw_len or offset > len or len > self.raw_len) {
            return error.InvalidBounds;
        }

        return self.raw_data[offset..len];
    }

    pub fn to_string(self: RawPacket) void {
        print("Timestamp_s: {any} Timestamp_ms: {any} Raw_data (ptr): {any} raw_len: {any}\n", .{ self.timestamp_s, self.timestamp_ms, self.raw_data.ptr, self.raw_len });
    }

    pub fn print_bytes(self: RawPacket, len: u32) void {
        const bytes: []const u8 = @ptrCast(self.raw_data[0..len]);
        for (bytes) |b| {
            std.debug.print("{x} ", .{b});
        }
        std.debug.print("\n", .{});
    }

    pub fn deinit(self: *RawPacket, allocator: *std.mem.Allocator) void {
        allocator.free(self.raw_data);
        allocator.destroy(self);
    }
};

const ProtocolHeader = union(enum) {
    eth: Eth.EthHeader,
    ipv4: IPv4.IPv4Header,
    tcp: TCP.TCPHeader,
    udp: UDP.UDPHeader,
};

pub const Layer = struct {
    raw: []const u8,
    len: usize,
    protocol: ProtocolEnums.ProtocolType,
    protocol_header: ?*align(1) const anyopaque,
    prev: ?*Layer,
    next: ?*Layer,
};

pub const Packet = struct {
    raw_packet: *RawPacket,
    offset: usize,
    first_layer: ?*Layer,
    last_layer: ?*Layer,

    pub fn init(raw_packet: *RawPacket) Packet {
        return .{
            .raw_packet = raw_packet,
            .offset = 0,
            .first_layer = null,
            .last_layer = null,
        };
    }

    pub fn parse_layers(self: *Packet, allocator: *std.mem.Allocator) !void {
        var current_layer: ?*Layer = null;

        // --- Ethernet ---
        if (self.raw_packet.raw_data.len < 14) return error.InvalidPacket;
        const eth_ptr: *align(1) const Eth.EthHeader = @ptrCast(self.raw_packet.raw_data.ptr);

        const eth_layer = try allocator.create(Layer);
        eth_layer.raw = self.raw_packet.raw_data[0..14];
        eth_layer.len = 14;
        eth_layer.protocol = ProtocolType.Ethernet;
        eth_layer.protocol_header = eth_ptr;
        eth_layer.prev = null;
        eth_layer.next = null;

        self.first_layer = eth_layer;
        self.last_layer = eth_layer;
        current_layer = eth_layer;
        self.offset += 14;

        // --- IPv4 (if EtherType is IP) --
        if (std.mem.bigToNative(u16, eth_ptr.*.eth_type) == @intFromEnum(EtherType.IP)) {
            if (self.raw_packet.raw_data.len < self.offset + 20) return error.InvalidPacket;
            const ipv4_ptr: *align(1) const IPv4.IPv4Header = @ptrCast(&self.raw_packet.raw_data[self.offset]);
            const ihl = (ipv4_ptr.*.version_ihl & 0x0F) * 4;

            const ip_layer = try allocator.create(Layer);
            ip_layer.raw = self.raw_packet.raw_data[self.offset .. self.offset + ihl];
            ip_layer.len = ihl;
            ip_layer.protocol = ProtocolType.IPv4;
            ip_layer.protocol_header = ipv4_ptr;
            ip_layer.prev = current_layer;
            ip_layer.next = null;

            current_layer.?.next = ip_layer;
            current_layer = ip_layer;
            self.last_layer = ip_layer;
            self.offset += ihl;

            const ip_proto = std.enums.fromInt(IPv4Protocol, ipv4_ptr.protocol).?;

            //print("{d}\n", .{ip_proto});

            // --- TCP / UDP ---
            switch (ip_proto) {
                IPv4Protocol.TCP => {
                    if (self.raw_packet.raw_data.len < self.offset + 20) return error.InvalidPacket;
                    const tcp_layer = try allocator.create(Layer);
                    tcp_layer.raw = self.raw_packet.raw_data[self.offset .. self.offset + 20]; // min TCP header
                    tcp_layer.len = 20;
                    tcp_layer.protocol = ProtocolType.TCP;
                    tcp_layer.protocol_header = tcp_layer;
                    tcp_layer.prev = current_layer;
                    tcp_layer.next = null;

                    current_layer.?.next = tcp_layer;
                    current_layer = tcp_layer;
                    self.last_layer = tcp_layer;
                    self.offset += 20;
                },
                IPv4Protocol.UDP => {
                    if (self.raw_packet.raw_data.len < self.offset + 8) return error.InvalidPacket;
                    const udp_layer = try allocator.create(Layer);
                    udp_layer.raw = self.raw_packet.raw_data[self.offset .. self.offset + 8];
                    udp_layer.len = 8;
                    udp_layer.protocol = ProtocolType.UDP;
                    udp_layer.protocol_header = udp_layer;
                    udp_layer.prev = current_layer;
                    udp_layer.next = null;

                    current_layer.?.next = udp_layer;
                    current_layer = udp_layer;
                    self.last_layer = udp_layer;
                    self.offset += 8;
                },
                else => {},
            }
        }

        // --- Payload ---
        if (self.offset < self.raw_packet.raw_data.len) {
            const payload_layer = try allocator.create(Layer);
            payload_layer.raw = self.raw_packet.raw_data[self.offset..];
            payload_layer.len = self.raw_packet.raw_data.len - self.offset;
            payload_layer.protocol = ProtocolType.GenericPayload;
            payload_layer.prev = current_layer;
            payload_layer.next = null;

            current_layer.?.next = payload_layer;
            self.last_layer = payload_layer;
        }
    }

    pub fn print_layers(self: *Packet) void {
        var layer = self.first_layer;
        while (layer) |l| {
            std.debug.print("Layer: {s}, Len: {d}\n", .{ @tagName(l.protocol), l.len });
            layer = l.next;
        }
    }

    //// returns a layer of known protocol type e.g. IPv4, which is in the layers linked list
    pub fn get_layer(self: *Packet, ptype: ProtocolType) ?*Layer {
        var layer: ?*Layer = self.first_layer;

        while (layer != null) {
            if (layer.?.protocol == ptype) {
                return layer;
            }

            layer = layer.?.next;
        }

        return null;
    }

    pub fn transform_layer(self: *Packet, target_layer: *Layer, ptype: type) !?*Layer {
        var layer: ?*Layer = self.first_layer;

        while (layer != null) {
            if (layer.? == target_layer) {
                // add another check for minimum payload length and return error if required
                if (layer.?.protocol != ProtocolType.GenericPayload) {
                    return error.LayerAlreadyHasValidProtocolType;
                } else {
                    const layer_ptr: *align(1) const ptype = @ptrCast(&target_layer.raw[0]);
                    target_layer.protocol_header = layer_ptr;
                    return target_layer;
                }
            }

            layer = layer.?.next;
        }

        return null;
    }
};
