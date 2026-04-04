const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const DNS = @import("DNS.zig");

const IPv4 = @import("IPv4.zig");

const LayerProtocols = @import("ProtocolHelpers.zig").LayerProtocols;
const LayerError = @import("ProtocolHelpers.zig").LayerError;
const NetworkProtocols = @import("ProtocolHelpers.zig").NetworkProtocols;

const Packet = @import("Packet.zig");
const LayerOwner = @import("Layer.zig").LayerOwner;
const ApplicationLayer = @import("GenericLayer.zig").ApplicationLayer;

const LayerImpl = @import("ProtocolHelpers.zig").LayerImpl;

const comparePayloads = @import("ProtocolHelpers.zig").comparePayloads;

const nativeToBig = std.mem.nativeToBig;
const activeTag = std.meta.activeTag;

pub const UDPHeaderSize = 8;

pub fn get_next_layer_type(buffer: []u8) !Packet.Layer { // could return optional instead to handle empty payloads instead
    if (buffer.len < @sizeOf(UDPHeader)) return LayerError.BufferTooSmall;

    const alignment = @alignOf(UDPHeader);
    const addr = @intFromPtr(buffer.ptr);
    if (addr % alignment != 0) {
        return LayerError.MisalignedBuffer;
    }

    const aligned_ptr: [*]align(@alignOf(UDPHeader)) u8 = @alignCast(buffer.ptr);
    const hdr: *const UDPHeader = @ptrCast(aligned_ptr);

    var layer = Packet.Layer{ .protocol = undefined, .offset = 0, .length = 0, .next_layer = null };

    const total_udp_length = hdr.get_length();

    print("total length udp: {}\n", .{total_udp_length});

    // Validate UDP length
    if (total_udp_length < UDPHeaderSize) {
        return LayerError.BufferTooSmall;
    }

    // Check if we have enough data
    if (buffer.len < total_udp_length) {
        return LayerError.EmptyPayload;
    }

    // set offset to where payload starts (right after UDP header)
    layer.offset = UDPHeaderSize;

    // set length to UDP payload length (total length - header size)
    layer.length = total_udp_length - UDPHeaderSize;

    layer.protocol = LayerProtocols{ .Application = .Generic };

    return layer;
}

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

    pub fn set_length(self: *UDPHeader, len: u16) !void {
        if (len < UDPHeaderSize) return error.UDPLenTooSmall;

        self.length = @byteSwap(len);
    }

    pub fn get_length(self: *const UDPHeader) u16 {
        return @byteSwap(self.length);
    }

    /// Calculate UDP checksum (requires pseudo-header and payload)
    /// For IPv4, the pseudo-header includes: source IP, dest IP, protocol, UDP length
    pub fn calculate_checksum(self: *UDPHeader, src_ip: u32, dst_ip: u32, payload: []const u8) void {
        self.checksum = 0;

        var sum: u32 = 0;

        std.debug.print("\n=== UDP CHECKSUM DEBUG ===\n", .{});

        print("src ip {x}\n", .{src_ip});

        // ---- Source IP ----
        const src = std.mem.nativeToBig(u32, src_ip);
        const src_bytes = std.mem.asBytes(&src);

        const src_w1 = (@as(u16, src_bytes[0]) << 8) | src_bytes[1];
        const src_w2 = (@as(u16, src_bytes[2]) << 8) | src_bytes[3];

        std.debug.print("SRC IP raw: 0x{x}\n", .{src_ip});
        std.debug.print("SRC bytes: {x} {x} {x} {x}\n", .{
            src_bytes[0], src_bytes[1], src_bytes[2], src_bytes[3],
        });
        std.debug.print("SRC words: 0x{x}, 0x{x}\n", .{ src_w1, src_w2 });

        sum += src_w1;
        sum += src_w2;

        // ---- Destination IP ----
        const dst = std.mem.nativeToBig(u32, dst_ip);
        const dst_bytes = std.mem.asBytes(&dst);

        const dst_w1 = (@as(u16, dst_bytes[0]) << 8) | dst_bytes[1];
        const dst_w2 = (@as(u16, dst_bytes[2]) << 8) | dst_bytes[3];

        std.debug.print("DST IP raw: 0x{x}\n", .{dst_ip});
        std.debug.print("DST bytes: {x} {x} {x} {x}\n", .{
            dst_bytes[0], dst_bytes[1], dst_bytes[2], dst_bytes[3],
        });
        std.debug.print("DST words: 0x{x}, 0x{x}\n", .{ dst_w1, dst_w2 });

        sum += dst_w1;
        sum += dst_w2;

        // ---- Protocol ----
        std.debug.print("Protocol: 0x0011\n", .{});
        sum += 0x0011;

        // ---- UDP length (raw field) ----
        std.debug.print("UDP length field (raw): 0x{x}\n", .{self.length});
        sum += @byteSwap(self.length);

        // ---- UDP header ----
        const udp_bytes = @as([*]const u8, @ptrCast(self));

        std.debug.print("UDP header bytes: ", .{});
        for (0..8) |j| {
            std.debug.print("{x} ", .{udp_bytes[j]});
        }
        std.debug.print("\n", .{});

        const h_src = (@as(u16, udp_bytes[0]) << 8) | udp_bytes[1];
        const h_dst = (@as(u16, udp_bytes[2]) << 8) | udp_bytes[3];
        const h_len = (@as(u16, udp_bytes[4]) << 8) | udp_bytes[5];
        const h_chk = (@as(u16, udp_bytes[6]) << 8) | udp_bytes[7];

        std.debug.print("HDR src_port: 0x{x}\n", .{h_src});
        std.debug.print("HDR dst_port: 0x{x}\n", .{h_dst});
        std.debug.print("HDR length:   0x{x}\n", .{h_len});
        std.debug.print("HDR checksum: 0x{x}\n", .{h_chk});

        sum += h_src;
        sum += h_dst;
        sum += h_len;
        sum += h_chk;

        // ---- Payload ----
        var i: usize = 0;
        while (i + 1 < payload.len) {
            const word = (@as(u16, payload[i]) << 8) | payload[i + 1];
            std.debug.print("Payload word @{}: 0x{x}\n", .{ i, word });
            sum += word;
            i += 2;
        }

        if (i < payload.len) {
            const last = @as(u16, payload[i]) << 8;
            std.debug.print("Payload last byte @{}: 0x{x}\n", .{ i, last });
            sum += last;
        }

        std.debug.print("Sum before fold: 0x{x}\n", .{sum});

        // ---- Fold ----
        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
            std.debug.print("Folding... sum = 0x{x}\n", .{sum});
        }

        std.debug.print("Sum after fold: 0x{x}\n", .{sum});

        // ---- Final checksum ----
        self.checksum = ~@as(u16, @intCast(sum));

        std.debug.print("Final checksum (before zero fix): 0x{x}\n", .{self.checksum});

        if (self.checksum == 0) {
            self.checksum = 0xFFFF;
        }

        std.debug.print("Stored checksum: 0x{x}\n", .{self.checksum});
        std.debug.print("=== END DEBUG ===\n\n", .{});
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

        // Add UDP header
        const words = @as([*]const u16, @ptrCast(self));
        for (0..UDPHeaderSize / 2) |i| {
            sum += words[i];
        }

        // Add payload
        var i: usize = 0;
        while (i + 1 < payload.len) {
            const word = (@as(u16, payload[i]) << 8) | payload[i + 1];
            sum += word;
            i += 2;
        }

        if (i < payload.len) {
            sum += @as(u16, payload[i]) << 8;
        }

        // Fold to 16 bits
        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return @as(u16, @intCast(sum)) == 0xFFFF;
    }
};

pub const UDPLayer = struct {
    owner: LayerOwner,

    const Protocol = LayerProtocols{ .Transport = .UDP };

    pub fn init(owner: LayerOwner) LayerError!UDPLayer {
        switch (owner) {
            .packet_layer => {
                return UDPLayer{
                    .owner = owner,
                };
            },
            .allocator_owned => {
                var self = UDPLayer{ .owner = owner };
                // Allocate directly into the struct's data field
                //
                // will cause data wipe
                self.owner.allocator_owned.data = try self.owner.allocator_owned.allocator.alloc(u8, UDPHeaderSize);

                var header = UDPHeader.init_default();
                @memcpy(self.owner.allocator_owned.data[0..UDPHeaderSize], std.mem.asBytes(&header));

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

    pub fn get_header(self: *UDPLayer) *UDPHeader {
        const data = self.get_data();
        const aligned_ptr: [*]align(@alignOf(UDPHeader)) u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    /// Get slice of data (header + payload)
    pub fn set_data(self: *UDPLayer, data: []u8) LayerError!void {
        if (data.len < @sizeOf(UDPHeader)) return LayerError.BufferTooSmall;

        _ = self;

        print("set data called.\n", .{});

        // Verify alignment (optional)
        const alignment = @alignOf(UDPHeader);
        const addr = @intFromPtr(data.ptr);
        if (addr % alignment != 0) {
            return LayerError.MisalignedBuffer;
        }

        //self.data = data;
    }

    /// Get slice of data (header + payload)
    pub fn get_data(self: *const UDPLayer) []u8 {
        switch (self.owner) {
            .packet_layer => {
                //print("getting self ({*}) data from packet\n", .{self});
                const udp_data = self.owner.packet_layer.packet.find_layer_ptr(@ptrCast(@constCast(self))) orelse {
                    std.debug.panic("udp layer ptr ({*}) not found in packet\n", .{self});
                };
                return udp_data;
            },
            else => {
                //print("getting self ({*}) data from allocator\n", .{self});
                return self.owner.allocator_owned.data;
            },
        }
    }

    /// Get the payload (data after UDP header)
    pub fn get_payload(self: *UDPLayer) ?[]u8 {
        //const hdr = self.get_header();
        //const total_len = hdr.get_length();
        //const payload_start = UDPHeaderSize;

        const data = self.get_data();

        //if (total_len < UDPHeaderSize) return data[UDPHeaderSize..];

        if (data.len > UDPHeaderSize) {
            return data[UDPHeaderSize..]; // return remaining bytes after the header
        } else {
            return null;
        }

        // Ensure we don't exceed the buffer
        //        const payload_end = @min(total_len, @as(u16, @intCast(data.len)));
        //        return data[payload_start..payload_end];
    }

    pub fn owns(self: *UDPLayer) void {
        switch (self.owner) {
            .packet_layer => { //call packet extended layer
                print("packet.\n", .{});
            },
            .allocator => {
                print("allocator.\n", .{});
            },
        }
    }

    // pub fn set_payload(self: *UDPLayer, payload: []const u8) !void {
    //     const total_len = UDPHeaderSize + payload.len;

    //     switch (self.owner) {
    //         .packet_layer => { //call packet extended layer

    //             if (self.owner.packet_layer.packet) |owning_packet| {
    //                 if (self.owner.packet_layer.length < payload.len) {
    //                     try owning_packet.extend_layer(self.owner.packet_layer, payload.len % self.get_payload().len);
    //                 } else if (self.owner.packet_layer.length > payload.len) {
    //                     try owning_packet.shorten_layer(self.owner.packet_layer, self.get_payload().len % payload.len);
    //                 }

    //                 _ = try owning_packet.add_layer(ApplicationLayer, payload);
    //             }

    //             return;
    //         },
    //         .allocator => {
    //             print("calling allocator.\n", .{});
    //             if (self.data.len < total_len) {
    //                 self.data = try self.owner.allocator.realloc(self.data, (total_len));
    //             }

    //             // Copy payload
    //             @memcpy(self.data[UDPHeaderSize..][0..payload.len], payload);
    //         },
    //     }

    //     // Update header length
    //     var hdr = self.get_header();
    //     try hdr.set_length(@intCast(total_len));
    // }

    pub fn get_src_port(self: *UDPLayer) u16 {
        const hdr = self.get_header();
        return hdr.get_src_port();
    }

    pub fn get_dst_port(self: *UDPLayer) u16 {
        const hdr = self.get_header();
        return hdr.get_dst_port();
    }

    pub fn set_src_port(self: *UDPLayer, port: u16) void {
        var hdr = self.get_header();
        hdr.set_src_port(port);
    }

    pub fn set_dst_port(self: *UDPLayer, port: u16) void {
        var hdr = self.get_header();
        hdr.set_dst_port(port);
    }

    pub fn get_length(self: *UDPLayer) u16 {
        const hdr = self.get_header();
        return hdr.get_length();
    }

    pub fn set_length(self: *UDPLayer, len: u16) !void {
        var hdr = self.get_header();
        try hdr.set_length(len);
    }

    pub fn get_checksum(self: *UDPLayer) u16 {
        const hdr = self.get_header();
        return hdr.checksum;
    }

    pub fn get_prev_layer(self: *UDPLayer) void {
        switch (self.owner) {
            .packet_layer => {
                const prev_layer = self.owner.packet_layer.prev_layer;
                if (prev_layer) |prev| {
                    prev.to_string();
                } else {
                    print("no prev layer.\n", .{});
                }
            },

            else => {
                return;
            },
        }
    }

    pub fn calculate_checksum(self: *UDPLayer) void {
        const hdr = self.get_header();

        switch (self.owner) {
            .packet_layer => {
                if (self.owner.packet_layer.prev_layer) |prev_layer| {
                    if (comparePayloads(prev_layer.protocol, LayerProtocols{ .Network = .IPv4 })) {
                        var ipv4_layer: IPv4.IPv4Layer = self.owner.packet_layer.packet.get_layer_of_type(IPv4.IPv4Layer) orelse {
                            print("failed to get IPv4 layer.\n", .{});
                            return;
                        };

                        hdr.calculate_checksum(ipv4_layer.get_src_ip().to_u32(), ipv4_layer.get_dst_ip().to_u32(), self.get_data()[UDPHeaderSize..]);
                    } else if (comparePayloads(prev_layer.protocol, LayerProtocols{ .Network = .IPv6 })) {
                        return;
                        //prev_protocol = NetworkProtocols.IPv6;
                    }
                } else {
                    print("no prev layer.\n", .{});
                }
            },
            else => return,
        }

        //const hdr = self.get_header();
        //hdr.calculate_checksum(src_ip, dst_ip, payload);
    }

    pub fn to_string(self: *UDPLayer, allocator: Allocator) []const u8 {
        const hdr = self.get_header();

        const src_port = hdr.get_src_port();
        const dst_port = hdr.get_dst_port();
        const length = hdr.get_length();
        const checksum = hdr.checksum;

        return std.fmt.allocPrint(allocator,
            \\UDP Layer:
            \\  src_port: {}
            \\  dst_port: {}
            \\  length: {}
            \\  checksum: 0x{x:0>4}
            \\
        , .{
            src_port,
            dst_port,
            length,
            checksum,
        }) catch return "";
    }

    pub fn get_next_layer_type(self: *UDPLayer, layer: *Packet.Layer) !?LayerImpl {
        //        const data = self.get_data();
        _ = self;
        return try LayerImpl.init(ApplicationLayer, LayerOwner{ .packet_layer = layer });
    }

    pub fn get_protocol(self: *UDPLayer) LayerProtocols {
        _ = self;
        return UDPLayer.Protocol;
    }

    pub fn deinit(self: *UDPLayer) void {
        switch (self.owner) {
            .allocator_owned => self.owner.allocator_owned.deinit(),
            else => return,
        }
    }
};

// Compile-time validation
comptime {
    if (@sizeOf(UDPHeader) != 8) {
        @compileError("UDPHeader size must be 8 bytes");
    }
}
