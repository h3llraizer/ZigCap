const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const LayerProtocols = @import("Layer.zig").LayerProtocols;
const NetworkProtocols = @import("Layer.zig").NetworkProtocols;
const Layer = @import("Layer.zig").Layer;
const TPtr = @import("Layer.zig").TPtr;

const IPv4Layer = @import("IPv4.zig").IPv4Layer;
const IPv6Layer = @import("IPv6.zig").IPv6Layer;
const DNSLayer = @import("DNS.zig").DNSLayer;

pub const UDPHeader = packed struct {
    src_port: u16 = 0,
    dst_port: u16 = 0,
    length: u16 = 0,
    checksum: u16 = 0,
};

pub const UDPHeaderSize = 8;

/// UDPLayer wraps mutable pointer to UDPHeader and functions to work on the header.
/// If header values are changed manually or via setter then ensure calculate_length and calculate_checksum are called to avoid invalidating the layer after all desired changes are made.
pub const UDPLayer = struct {
    data: []u8,
    const Protocol = LayerProtocols{ .Transport = .UDP };

    //// Creates layer from ptr to 8 byte length buffer - ensure that the buffer outlives the UDPLayer or UB occurs
    pub fn init(raw: []u8, allocator: std.mem.Allocator) !*UDPLayer {
        if (raw.len < UDPHeaderSize) return error.RawTooSmallForUDP;

        const self = try allocator.create(UDPLayer);
        self.data = raw[UDPHeaderSize..];
        return self;
    }

    /// Create empty UDP layer. UDPHeader values are Zero initialised
    pub fn create(allocator: std.mem.Allocator) !*UDPLayer {
        const self = try allocator.create(UDPLayer);
        self.data = try allocator.alloc(u8, 8);

        return self;
    }

    /// Get Source Port of the UDPHeader - converts u16 value from Big to Native and returns
    pub fn get_src_port(self: *UDPLayer) u16 {
        const hdr = self.get_header();
        return std.mem.bigToNative(u16, hdr.src_port);
    }

    //// Get Destination Port of the UDPHeader - converts u16 value from Big to Native and returns
    pub fn get_dst_port(self: *UDPLayer) u16 {
        const hdr = self.get_header();
        return std.mem.bigToNative(u16, hdr.dst_port);
    }

    //// Get Checksum of the UDPHeader - converts u16 value from Big to Native and returns
    pub fn get_checksum(self: *UDPLayer) u16 {
        const hdr = self.get_header();
        return std.mem.bigToNative(u16, hdr.checksum);
    }

    //// Get Length of the UDPHeader - converts u16 value from Big to Native and returns
    pub fn get_length(self: *UDPLayer) u16 {
        const hdr = self.get_header();
        return std.mem.bigToNative(u16, hdr.length);
    }

    //// Get Source Port of the UDPHeader - converts u16 value from Big to Native and returns
    pub fn set_src_port(self: *UDPLayer, port: u16) void {
        self.get_header().src_port = std.mem.nativeToBig(u16, port);
        //        hdr.src_port = std.mem.nativeToBig(u16, port);
    }

    //// Get Destination Port of the UDPHeader - converts u16 value from Big to Native and returns
    pub fn set_dst_port(self: *UDPLayer, port: u16) void {
        var hdr = self.get_header();
        hdr.dst_port = std.mem.nativeToBig(u16, port);
    }

    /// get slice of data (hdr+payload)
    pub fn get_data(self: *UDPLayer) []u8 {
        return self.data;
    }

    /// set hdr+payload from single buffer - memory is copied
    pub fn set_data(self: *UDPLayer, data: []u8, allocator: Allocator) !void {
        self.data = try allocator.alloc(u8, data.len);
        @memcpy(self.data, data);
    }

    /// return mutable slice of the payload
    pub fn get_payload(self: *UDPLayer) []u8 {
        return self.data + 8;
    }

    /// preserve the current header and set the payload - two copies occur: current header and payload passed
    pub fn set_payload(self: *UDPLayer, payload: []u8, allocator: Allocator) !void {
        print("new size: {d}\n", .{UDPHeaderSize + payload.len});
        const old_data = self.data;
        var new_data = try allocator.realloc(old_data, UDPHeaderSize + payload.len);

        @memmove(new_data[0..UDPHeaderSize], old_data[0..UDPHeaderSize]);
        @memmove(new_data[UDPHeaderSize..], payload);

        self.data = new_data;
    }

    pub fn get_header(self: *UDPLayer) *align(1) UDPHeader {
        return std.mem.bytesAsValue(UDPHeader, self.data[0..8]);
    }

    //// Calculate the checksum of the UDPHeader
    pub fn calculate_checksum(self: *UDPLayer, ip_layer: *Layer, allocator: Allocator) !void {
        const proto_union: LayerProtocols = ip_layer.get_protocol();

        // 1. check that it's a network layer
        switch (std.meta.activeTag(proto_union)) {
            .Network => {
                // 2. extract the network protocol enum
                const net_proto: NetworkProtocols = proto_union.Network;

                switch (net_proto) {
                    .IPv4 => {
                        const ipv4_layer = TPtr(*IPv4Layer, ip_layer.layer_type); // cast the layer back to the implementation
                        const src_ip = ipv4_layer.get_src_ip().array;
                        const dst_ip = ipv4_layer.get_dst_ip().array;

                        const protocol = ipv4_layer.get_header().protocol;

                        self.calculate_length();

                        var length_bytes: [2]u8 = undefined;
                        std.mem.writeInt(u16, &length_bytes, self.get_header().length, .big);

                        const total_len =
                            src_ip.len +
                            dst_ip.len +
                            1 + // protocol
                            length_bytes.len;

                        var dword = try allocator.alloc(u8, total_len);

                        // offsets
                        var offset: usize = 0;

                        // src_ip
                        @memcpy(dword[offset .. offset + src_ip.len], &src_ip);
                        offset += src_ip.len;

                        // dst_ip
                        @memcpy(dword[offset .. offset + dst_ip.len], &dst_ip);
                        offset += dst_ip.len;

                        // protocol
                        dword[offset] = protocol;
                        offset += 1;

                        // length
                        @memcpy(dword[offset .. offset + length_bytes.len], &length_bytes);
                        offset += length_bytes.len;

                        // ---- COMPUTE CHECKSUM ----
                        const sum = onesComplementSum(dword);
                        const checksum = ~@as(u16, @intCast(sum & 0xFFFF));

                        // RFC: if checksum == 0, transmit as 0xFFFF
                        if (checksum == 0) {
                            self.get_header().checksum = 0xFFFF;
                        } else {
                            self.get_header().checksum = checksum;
                        }

                        print("IPV4/UDP Checksum: {x}\n", .{self.get_checksum()});
                    },
                    .IPv6 => {
                        print("IPv6 layer.\n", .{});
                    },
                }
            },
            else => print("Previous layer is not a network layer.\n", .{}),
        }
    }

    //// Calculate the length of the UDPHeader
    pub fn calculate_length(self: *UDPLayer) void {
        const data_len = self.data.len;

        print("data len: {}\n", .{data_len});

        // Optional safety check
        std.debug.assert(data_len <= 65527);

        self.get_header().length = @intCast(data_len + 8);
    }

    pub fn to_string(self: *UDPLayer, allocator: Allocator) []const u8 {
        const hdr = self.get_header();

        const src_port = std.mem.bigToNative(u16, hdr.src_port);
        const dst_port = std.mem.bigToNative(u16, hdr.dst_port);
        const length = std.mem.bigToNative(u16, hdr.length);
        const checksum = std.mem.bigToNative(u16, hdr.checksum);

        return std.fmt.allocPrint(
            allocator,
            "src_port: {d}, dst_port: {d}, length: {d}, checksum: {d}",
            .{ src_port, dst_port, length, checksum },
        ) catch |err| {
            std.debug.print("allocPrint failed: {s}\n", .{@errorName(err)});
            return "";
        };
    }

    pub fn parse_next_layer(self: *UDPLayer, allocator: std.mem.Allocator) ?*Layer {
        const packet_layer: *Layer = allocator.create(Layer) catch return null;

        if (self.get_dst_port() == 53 or self.get_src_port() == 53) {
            const dns_layer = DNSLayer.init(self.data[0..], allocator) catch return null;
            packet_layer.* = Layer.implBy(dns_layer);
            return packet_layer;
        }

        return null;
    }

    pub fn get_protocol(self: *UDPLayer) LayerProtocols {
        _ = self;
        return UDPLayer.Protocol;
    }

    pub fn deinit(self: *UDPLayer, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};

fn onesComplementSum(data: []const u8) u32 {
    var sum: u32 = 0;

    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        const word = (@as(u16, data[i]) << 8) | @as(u16, data[i + 1]);
        sum += word;
    }

    // If odd length, pad last byte
    if (i < data.len) {
        const word = (@as(u16, data[i]) << 8);
        sum += word;
    }

    // Fold carries
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return sum;
}

pub fn udpChecksum(
    src_ip: [4]u8,
    dst_ip: [4]u8,
    src_port: u16,
    dst_port: u16,
    payload: []const u8,
) u16 {
    var buf = std.ArrayList(u8).init(std.heap.page_allocator);
    defer buf.deinit();

    // ---- PSEUDO HEADER ----
    buf.appendSlice(&src_ip) catch unreachable;
    buf.appendSlice(&dst_ip) catch unreachable;

    buf.append(0) catch unreachable; // zero byte
    buf.append(17) catch unreachable; // protocol (UDP = 17)

    const udp_len: u16 = @as(u16, 8 + payload.len);
    buf.append(@intCast((udp_len >> 8) & 0xFF)) catch unreachable;
    buf.append(@intCast(udp_len & 0xFF)) catch unreachable;

    // ---- UDP HEADER ----
    // source port
    buf.append(@intCast((src_port >> 8) & 0xFF)) catch unreachable;
    buf.append(@intCast(src_port & 0xFF)) catch unreachable;

    // destination port
    buf.append(@intCast((dst_port >> 8) & 0xFF)) catch unreachable;
    buf.append(@intCast(dst_port & 0xFF)) catch unreachable;

    // length
    buf.append(@intCast((udp_len >> 8) & 0xFF)) catch unreachable;
    buf.append(@intCast(udp_len & 0xFF)) catch unreachable;

    // checksum field = 0 for calculation
    buf.append(0) catch unreachable;
    buf.append(0) catch unreachable;

    // ---- PAYLOAD ----
    buf.appendSlice(payload) catch unreachable;

    // ---- COMPUTE CHECKSUM ----
    const sum = onesComplementSum(buf.items);
    const checksum = ~@as(u16, @intCast(sum & 0xFFFF));

    // RFC: if checksum == 0, transmit as 0xFFFF
    return if (checksum == 0) 0xFFFF else checksum;
}
