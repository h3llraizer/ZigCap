const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const DNS = @import("DNS.zig");
const LayerProtocols = @import("ProtocolHelpers.zig").LayerProtocols;
const LayerError = @import("ProtocolHelpers.zig").LayerError;
const Packet = @import("Packet.zig");

pub const UDPHeaderSize = 8;

pub fn get_next_layer_type(buffer: []u8) !Packet.Layer {
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
            .length = UDPHeaderSize,
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
        self.checksum = 0; // Reset checksum before calculation

        var sum: u32 = 0;

        // Add pseudo-header (IPv4)
        // Source IP (16 bits at a time)
        sum += (src_ip >> 16) & 0xFFFF;
        sum += src_ip & 0xFFFF;

        // Destination IP
        sum += (dst_ip >> 16) & 0xFFFF;
        sum += dst_ip & 0xFFFF;

        // Protocol (UDP = 17) and zero padding
        sum += 0x0011; // Protocol = 17, zero pad

        // UDP length
        sum += self.get_length();

        // Add UDP header (including checksum field which is currently 0)
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

        // If payload length is odd, pad with 0
        if (i < payload.len) {
            sum += @as(u16, payload[i]) << 8;
        }

        // Fold 32-bit sum to 16 bits
        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // Take one's complement
        self.checksum = ~@as(u16, @intCast(sum));

        // UDP checksum of 0 is special (means not used), but we set it anyway
        // RFC 768 allows checksum of 0 to indicate no checksum
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

    pub fn create(allocator: std.mem.Allocator) !*UDPLayer {
        const self = try allocator.create(UDPLayer);
        self.data = try allocator.alloc(u8, UDPHeaderSize);
        return self;
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

    pub fn set_length(self: *UDPLayer, len: u16) void {
        var hdr = self.get_header();
        hdr.set_length(len);
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
