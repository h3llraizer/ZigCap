const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const TransportProtocols = @import("ProtocolHelpers.zig").TransportProtocols;

pub const ICMPHeaderSize = 8; // Base ICMP header (without payload)

// ICMP Type definitions
pub const ICMPType = enum(u8) {
    EchoReply = 0,
    DestinationUnreachable = 3,
    SourceQuench = 4,
    Redirect = 5,
    EchoRequest = 8,
    TimeExceeded = 11,
    ParameterProblem = 12,
    TimestampRequest = 13,
    TimestampReply = 14,
    InformationRequest = 15,
    InformationReply = 16,

    pub fn to_string(self: ICMPType) []const u8 {
        return switch (self) {
            .EchoReply => "Echo Reply",
            .DestinationUnreachable => "Destination Unreachable",
            .SourceQuench => "Source Quench",
            .Redirect => "Redirect",
            .EchoRequest => "Echo Request",
            .TimeExceeded => "Time Exceeded",
            .ParameterProblem => "Parameter Problem",
            .TimestampRequest => "Timestamp Request",
            .TimestampReply => "Timestamp Reply",
            .InformationRequest => "Information Request",
            .InformationReply => "Information Reply",
        };
    }
};

// ICMP Code definitions for specific types
pub const ICMPCode = enum(u8) {
    // For DestinationUnreachable
    NetUnreachable = 0,
    HostUnreachable = 1,
    ProtocolUnreachable = 2,
    PortUnreachable = 3,
    FragmentationNeeded = 4,
    SourceRouteFailed = 5,

    // For TimeExceeded
    TTLExceeded = 0,
    FragmentReassemblyTimeExceeded = 1,

    // Default
    None = 0,

    pub fn to_string(self: ICMPCode) []const u8 {
        return switch (self) {
            .NetUnreachable => "Network Unreachable",
            .HostUnreachable => "Host Unreachable",
            .ProtocolUnreachable => "Protocol Unreachable",
            .PortUnreachable => "Port Unreachable",
            .FragmentationNeeded => "Fragmentation Needed",
            .SourceRouteFailed => "Source Route Failed",
            .TTLExceeded => "TTL Exceeded",
            .FragmentReassemblyTimeExceeded => "Fragment Reassembly Time Exceeded",
            .None => "None",
        };
    }
};

// ICMP Header structure (extern struct for exact layout)
pub const ICMPHeader = extern struct {
    type: u8 = 0, // ICMP message type
    code: u8 = 0, // ICMP message code
    checksum: u16 = 0, // ICMP checksum (network byte order)
    rest_of_header: u32 = 0, // Rest of header (varies by type)

    comptime {
        if (@sizeOf(ICMPHeader) != ICMPHeaderSize) {
            @compileError("ICMPHeader must be 8 bytes, got " ++ @typeName(@sizeOf(ICMPHeader)));
        }
    }

    pub fn init_default() ICMPHeader {
        return .{
            .type = 0,
            .code = 0,
            .checksum = 0,
            .rest_of_header = 0,
        };
    }

    pub fn set_type(self: *ICMPHeader, icmp_type: ICMPType) void {
        self.type = @intFromEnum(icmp_type);
    }

    pub fn get_type(self: *const ICMPHeader) ICMPType {
        return @enumFromInt(self.type);
    }

    pub fn set_code(self: *ICMPHeader, code: ICMPCode) void {
        self.code = @intFromEnum(code);
    }

    pub fn get_code(self: *const ICMPHeader) ICMPCode {
        return @enumFromInt(self.code);
    }

    pub fn set_identifier(self: *ICMPHeader, id: u16) void {
        // Identifier is stored in the rest_of_header field for Echo messages
        const current = @byteSwap(self.rest_of_header);
        self.rest_of_header = @byteSwap((current & 0xFFFF0000) | @as(u32, id));
    }

    pub fn get_identifier(self: *const ICMPHeader) u16 {
        // For Echo Request/Reply, rest_of_header contains identifier and sequence number
        return @truncate(@byteSwap(self.rest_of_header) & 0xFFFF);
    }

    pub fn set_sequence(self: *ICMPHeader, seq: u16) void {
        // Sequence number is stored in the rest_of_header field for Echo messages
        const current = @byteSwap(self.rest_of_header);
        self.rest_of_header = @byteSwap((current & 0xFFFF) | (@as(u32, seq) << 16));
    }

    pub fn get_sequence(self: *const ICMPHeader) u16 {
        return @truncate(@byteSwap(self.rest_of_header) >> 16);
    }

    pub fn set_gateway(self: *ICMPHeader, gateway: u32) void {
        // For Redirect messages, rest_of_header contains gateway address
        self.rest_of_header = gateway;
    }

    pub fn get_gateway(self: *const ICMPHeader) u32 {
        return self.rest_of_header;
    }

    pub fn set_mtu(self: *ICMPHeader, mtu: u16) void {
        // For Fragmentation Needed messages, rest_of_header contains MTU
        const current = @byteSwap(self.rest_of_header);
        self.rest_of_header = @byteSwap((current & 0xFFFF0000) | @as(u32, mtu));
    }

    pub fn get_mtu(self: *const ICMPHeader) u16 {
        return @truncate(@byteSwap(self.rest_of_header) & 0xFFFF);
    }

    /// Calculate ICMP checksum (covers header + payload)
    pub fn calculate_checksum(self: *ICMPHeader, payload: []const u8) void {
        self.checksum = 0; // Reset checksum before calculation

        var sum: u32 = 0;

        // Add ICMP header (as 16-bit words)
        const header_words = @as([*]const u16, @ptrCast(self));
        for (0..ICMPHeaderSize / 2) |i| {
            sum += header_words[i];
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

        // ICMP checksum of 0 is valid
        if (self.checksum == 0) {
            self.checksum = 0xFFFF;
        }
    }

    /// Validate ICMP checksum
    pub fn validate_checksum(self: *const ICMPHeader, payload: []const u8) bool {
        var sum: u32 = 0;

        const header_words = @as([*]const u16, @ptrCast(self));
        for (0..ICMPHeaderSize / 2) |i| {
            sum += header_words[i];
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

pub const ICMPLayer = struct {
    data: []u8, // ICMP header + payload
    const Protocol = TransportProtocols.ICMP;

    pub fn preallocated_buffer(buffer: []u8) !ICMPLayer {
        if (buffer.len < @sizeOf(ICMPHeader)) return error.BufferTooSmall;

        // Verify alignment
        const alignment = @alignOf(ICMPHeader);
        const addr = @intFromPtr(buffer.ptr);
        if (addr % alignment != 0) {
            return error.MisalignedBuffer;
        }

        return ICMPLayer{ .data = buffer };
    }

    pub fn create(allocator: std.mem.Allocator) !*ICMPLayer {
        const self = try allocator.create(ICMPLayer);
        self.data = try allocator.alloc(u8, ICMPHeaderSize);
        return self;
    }

    pub fn get_header(self: *ICMPLayer) *ICMPHeader {
        const aligned_ptr: [*]align(@alignOf(ICMPHeader)) u8 = @alignCast(self.data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn get_data(self: *ICMPLayer) []u8 {
        return self.data;
    }

    pub fn get_payload(self: *ICMPLayer) []u8 {
        return self.data[ICMPHeaderSize..];
    }

    pub fn get_type(self: *ICMPLayer) ICMPType {
        const hdr = self.get_header();
        return hdr.get_type();
    }

    pub fn set_type(self: *ICMPLayer, icmp_type: ICMPType) void {
        var hdr = self.get_header();
        hdr.set_type(icmp_type);
    }

    pub fn get_code(self: *ICMPLayer) ICMPCode {
        const hdr = self.get_header();
        return hdr.get_code();
    }

    pub fn set_code(self: *ICMPLayer, code: ICMPCode) void {
        var hdr = self.get_header();
        hdr.set_code(code);
    }

    pub fn get_identifier(self: *ICMPLayer) u16 {
        const hdr = self.get_header();
        return hdr.get_identifier();
    }

    pub fn set_identifier(self: *ICMPLayer, id: u16) void {
        var hdr = self.get_header();
        hdr.set_identifier(id);
    }

    pub fn get_sequence(self: *ICMPLayer) u16 {
        const hdr = self.get_header();
        return hdr.get_sequence();
    }

    pub fn set_sequence(self: *ICMPLayer, seq: u16) void {
        var hdr = self.get_header();
        hdr.set_sequence(seq);
    }

    pub fn get_checksum(self: *ICMPLayer) u16 {
        const hdr = self.get_header();
        return hdr.checksum;
    }

    pub fn calculate_checksum(self: *ICMPLayer) void {
        const hdr = self.get_header();
        const payload = self.get_payload();
        hdr.calculate_checksum(payload);
    }

    pub fn to_string(self: *ICMPLayer, allocator: Allocator) []const u8 {
        const hdr = self.get_header();

        const icmp_type = hdr.get_type();
        const code = hdr.get_code();
        const checksum = hdr.checksum;
        const identifier = hdr.get_identifier();
        const sequence = hdr.get_sequence();

        return std.fmt.allocPrint(allocator,
            \\ICMP Layer:
            \\  Type: {s} ({})
            \\  Code: {s} ({})
            \\  Checksum: 0x{x:0>4}
            \\  Identifier: {}
            \\  Sequence: {}
            \\
        , .{
            icmp_type.to_string(),
            @intFromEnum(icmp_type),
            code.to_string(),
            @intFromEnum(code),
            checksum,
            identifier,
            sequence,
        }) catch return "";
    }

    pub fn get_protocol(self: *ICMPLayer) TransportProtocols {
        _ = self;
        return ICMPLayer.Protocol;
    }

    pub fn deinit(self: *ICMPLayer, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};

// Compile-time validation
comptime {
    if (@sizeOf(ICMPHeader) != 8) {
        @compileError("ICMPHeader size must be 8 bytes");
    }
}
