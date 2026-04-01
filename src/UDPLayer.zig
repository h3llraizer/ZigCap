const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const DNS = @import("DNS.zig");
const LayerProtocols = @import("ProtocolHelpers.zig").LayerProtocols;
const LayerError = @import("ProtocolHelpers.zig").LayerError;
const Packet = @import("Packet.zig");

const nativeToBig = std.mem.nativeToBig;

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
    data: []u8, // UDP header + payload
    const Protocol = LayerProtocols{ .Transport = .UDP };

    pub fn init(buffer: []u8) LayerError!UDPLayer {
        if (buffer.len < @sizeOf(UDPHeader)) return LayerError.BufferTooSmall;

        // Verify alignment (optional)
        const alignment = @alignOf(UDPHeader);
        const addr = @intFromPtr(buffer.ptr);
        if (addr % alignment != 0) {
            return LayerError.MisalignedBuffer;
        }

        return UDPLayer{ .data = buffer };
    }

    pub fn zero_hdr(self: *UDPLayer) void {
        var header = UDPHeader.init_default();
        @memcpy(self.data[0..@sizeOf(UDPHeader)], std.mem.asBytes(&header));
    }

    pub fn get_header(self: *UDPLayer) *UDPHeader {
        // Use alignCast to ensure proper alignment
        const aligned_ptr: [*]align(@alignOf(UDPHeader)) u8 = @alignCast(self.data.ptr);
        return @ptrCast(aligned_ptr);
    }

    /// Get slice of data (header + payload)
    pub fn get_data(self: *UDPLayer) []u8 {
        return self.data;
    }

    /// Get the payload (data after UDP header)
    pub fn get_payload(self: *UDPLayer) []u8 {
        const hdr = self.get_header();
        const total_len = hdr.get_length();
        const payload_start = UDPHeaderSize;

        if (total_len < UDPHeaderSize) return self.data[UDPHeaderSize..];

        // Ensure we don't exceed the buffer
        const payload_end = @min(total_len, @as(u16, @intCast(self.data.len)));
        return self.data[payload_start..payload_end];
    }

    /// Set the payload. must be called after setting header length)
    pub fn set_payload(self: *UDPLayer, payload: []const u8, allocator: Allocator) !void {
        const total_len = UDPHeaderSize + payload.len;
        print("UDP new total len: {}\n", .{total_len});
        if (self.data.len < total_len) {
            self.data = try allocator.realloc(self.data, (total_len));
        }

        // Copy payload
        @memcpy(self.data[UDPHeaderSize..][0..payload.len], payload);

        //        print("UDP Data added: {x}\n", .{self.data});

        // Update header length
        var hdr = self.get_header();
        hdr.set_length(@intCast(total_len));
    }

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

    pub fn calculate_checksum(self: *UDPLayer, src_ip: u32, dst_ip: u32) void {
        const hdr = self.get_header();
        const payload = self.get_payload();
        hdr.calculate_checksum(src_ip, dst_ip, payload);
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

    pub fn get_next_layer_type(self: *UDPLayer) LayerProtocols {
        _ = self;
        return LayerProtocols{ .Application = .Generic };
    }

    pub fn get_protocol(self: *UDPLayer) LayerProtocols {
        _ = self;
        return UDPLayer.Protocol;
    }

    pub fn deinit(self: *UDPLayer, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};

// Compile-time validation
comptime {
    if (@sizeOf(UDPHeader) != 8) {
        @compileError("UDPHeader size must be 8 bytes");
    }
}
