const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const ProtocolHelpers = @import("ProtocolHelpers.zig");

const LayerError = ProtocolHelpers.LayerError;

pub const ICMPHeaderSize = 8; // Base ICMP header (without payload)

pub const ICMPType = enum(u8) {
    EchoReply = 0,
    DestinationUnreachable = 3,
    SourceQuench = 4,
    Redirect = 5,
    EchoRequest = 8,
    RouterAdvertisement = 9,
    RouterSolicitation = 10,
    TimeExceeded = 11,
    ParameterProblem = 12,
    TimestampRequest = 13,
    TimestampReply = 14,
    InformationRequest = 15,
    InformationReply = 16,
    AddressMaskRequest = 17,
    AddressMaskReply = 18,

    pub fn to_string(self: ICMPType) []const u8 {
        return switch (self) {
            .EchoReply => "Echo Reply",
            .DestinationUnreachable => "Destination Unreachable",
            .SourceQuench => "Source Quench",
            .Redirect => "Redirect",
            .EchoRequest => "Echo Request",
            .RouterAdvertisement => "Router Advertisement",
            .RouterSolicitation => "Router Solicitation",
            .TimeExceeded => "Time Exceeded",
            .ParameterProblem => "Parameter Problem",
            .TimestampRequest => "Timestamp Request",
            .TimestampReply => "Timestamp Reply",
            .InformationRequest => "Information Request",
            .InformationReply => "Information Reply",
            .AddressMaskRequest => "Address Mask Request",
            .AddressMaskReply => "Address Mask Reply",
        };
    }
};

pub const ICMPDestinationUnreachableCode = enum(u8) {
    NetUnreachable = 0,
    HostUnreachable = 1,
    ProtocolUnreachable = 2,
    PortUnreachable = 3,
    FragmentationNeeded = 4,
    SourceRouteFailed = 5,
    DestinationNetworkUnknown = 6,
    DestinationHostUnknown = 7,
    SourceHostIsolated = 8,
    NetworkAdministrativelyProhibited = 9,
    HostAdministrativelyProhibited = 10,
    NetworkUnreachableForTOS = 11,
    HostUnreachableForTOS = 12,
    CommunicationAdministrativelyProhibited = 13,
    HostPrecedenceViolation = 14,
    PrecedenceCutoffInEffect = 15,

    pub fn to_string(self: ICMPDestinationUnreachableCode) []const u8 {
        return switch (self) {
            .NetUnreachable => "Network Unreachable",
            .HostUnreachable => "Host Unreachable",
            .ProtocolUnreachable => "Protocol Unreachable",
            .PortUnreachable => "Port Unreachable",
            .FragmentationNeeded => "Fragmentation Needed",
            .SourceRouteFailed => "Source Route Failed",
            .DestinationNetworkUnknown => "Destination Network Unknown",
            .DestinationHostUnknown => "Destination Host Unknown",
            .SourceHostIsolated => "Source Host Isolated",
            .NetworkAdministrativelyProhibited => "Network Administratively Prohibited",
            .HostAdministrativelyProhibited => "Host Administratively Prohibited",
            .NetworkUnreachableForTOS => "Network Unreachable For TOS",
            .HostUnreachableForTOS => "Host Unreachable For TOS",
            .CommunicationAdministrativelyProhibited => "Communication Administratively Prohibited",
            .HostPrecedenceViolation => "Host Precedence Violation",
            .PrecedenceCutoffInEffect => "Precedence Cutoff In Effect",
        };
    }
};

pub const ICMPRedirectCode = enum(u8) {
    RedirectForNetwork = 0,
    RedirectForHost = 1,
    RedirectForTOSAndNetwork = 2,
    RedirectForTOSAndHost = 3,

    pub fn to_string(self: ICMPRedirectCode) []const u8 {
        return switch (self) {
            .RedirectForNetwork => "Redirect For Network",
            .RedirectForHost => "Redirect For Host",
            .RedirectForTOSAndNetwork => "Redirect For TOS And Network",
            .RedirectForTOSAndHost => "Redirect For TOS And Host",
        };
    }
};

pub const ICMPTimeExceededCode = enum(u8) {
    TTLExceeded = 0,
    FragmentReassemblyTimeExceeded = 1,

    pub fn to_string(self: ICMPTimeExceededCode) []const u8 {
        return switch (self) {
            .TTLExceeded => "TTL Exceeded",
            .FragmentReassemblyTimeExceeded => "Fragment Reassembly Time Exceeded",
        };
    }
};

pub const ICMPParameterProblemCode = enum(u8) {
    PointerIndicatesError = 0,
    MissingOption = 1,
    BadLength = 2,

    pub fn to_string(self: ICMPParameterProblemCode) []const u8 {
        return switch (self) {
            .PointerIndicatesError => "Pointer Indicates Error",
            .MissingOption => "Missing Option",
            .BadLength => "Bad Length",
        };
    }
};

pub const ICMPNoCode = enum(u8) {
    None = 0,

    pub fn to_string(self: ICMPNoCode) []const u8 {
        _ = self;
        return "None";
    }
};

pub const ICMPHeader = extern union {
    // Common header fields for raw access
    type: u8,
    code: u8,
    checksum: u16,

    // For Echo Request/Reply (and Timestamp, Information, Address Mask)
    echo: extern struct {
        type: u8,
        code: u8,
        checksum: u16,
        identifier: u16,
        sequence: u16,
    },

    // For Destination Unreachable and Time Exceeded (unused field is 0)
    unused: extern struct {
        type: u8,
        code: u8,
        checksum: u16,
        unused: u32,
    },

    // For Redirect
    redirect: extern struct {
        type: u8,
        code: u8,
        checksum: u16,
        gateway: u32,
    },

    // For Parameter Problem
    param_problem: extern struct {
        type: u8,
        code: u8,
        checksum: u16,
        pointer: u8,
        unused: [3]u8,
    },

    // For Router Advertisement
    router_advert: extern struct {
        type: u8,
        code: u8,
        checksum: u16,
        num_addresses: u8,
        addr_entry_size: u8,
        lifetime: u16,
    },

    // For Router Solicitation
    router_solicit: extern struct {
        type: u8,
        code: u8,
        checksum: u16,
        reserved: u32,
    },

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
        };
    }

    pub fn set_type(self: *ICMPHeader, icmp_type: ICMPType) void {
        self.type = @intFromEnum(icmp_type);
    }

    pub fn get_type(self: *const ICMPHeader) ICMPType {
        return @enumFromInt(self.type);
    }

    // Type-safe code setters/getters
    pub fn set_dest_unreachable_code(self: *ICMPHeader, code: ICMPDestinationUnreachableCode) void {
        self.code = @intFromEnum(code);
    }

    pub fn get_dest_unreachable_code(self: *const ICMPHeader) ICMPDestinationUnreachableCode {
        return @enumFromInt(self.code);
    }

    pub fn set_redirect_code(self: *ICMPHeader, code: ICMPRedirectCode) void {
        self.code = @intFromEnum(code);
    }

    pub fn get_redirect_code(self: *const ICMPHeader) ICMPRedirectCode {
        return @enumFromInt(self.code);
    }

    pub fn set_time_exceeded_code(self: *ICMPHeader, code: ICMPTimeExceededCode) void {
        self.code = @intFromEnum(code);
    }

    pub fn get_time_exceeded_code(self: *const ICMPHeader) ICMPTimeExceededCode {
        return @enumFromInt(self.code);
    }

    pub fn set_param_problem_code(self: *ICMPHeader, code: ICMPParameterProblemCode) void {
        self.code = @intFromEnum(code);
    }

    pub fn get_param_problem_code(self: *const ICMPHeader) ICMPParameterProblemCode {
        return @enumFromInt(self.code);
    }

    // Echo methods
    pub fn set_identifier(self: *ICMPHeader, id: u16) void {
        self.echo.identifier = @byteSwap(id);
    }

    pub fn get_identifier(self: *const ICMPHeader) u16 {
        return @byteSwap(self.echo.identifier);
    }

    pub fn set_sequence(self: *ICMPHeader, seq: u16) void {
        self.echo.sequence = @byteSwap(seq);
    }

    pub fn get_sequence(self: *const ICMPHeader) u16 {
        return @byteSwap(self.echo.sequence);
    }

    // Redirect methods
    pub fn set_gateway(self: *ICMPHeader, gateway: u32) void {
        self.redirect.gateway = gateway;
    }

    pub fn get_gateway(self: *const ICMPHeader) u32 {
        return self.redirect.gateway;
    }

    // Parameter Problem methods
    pub fn set_pointer(self: *ICMPHeader, pointer: u8) void {
        self.param_problem.pointer = pointer;
    }

    pub fn get_pointer(self: *const ICMPHeader) u8 {
        return self.param_problem.pointer;
    }

    // Calculate ICMP checksum (covers header + payload)
    pub fn calculate_checksum(self: *ICMPHeader, payload: []const u8) void {
        const old_checksum = self.checksum;
        self.checksum = 0;

        var sum: u32 = 0;

        // Add ICMP header (as 16-bit words)
        const header_ptr: [*]const u8 = @ptrCast(self);
        var i: usize = 0;
        while (i < ICMPHeaderSize) {
            if (i + 1 < ICMPHeaderSize) {
                const word = (@as(u16, header_ptr[i]) << 8) | header_ptr[i + 1];
                sum += word;
            } else {
                sum += @as(u16, header_ptr[i]) << 8;
            }
            i += 2;
        }

        // Add payload
        i = 0;
        while (i < payload.len) {
            if (i + 1 < payload.len) {
                const word = (@as(u16, payload[i]) << 8) | payload[i + 1];
                sum += word;
            } else {
                sum += @as(u16, payload[i]) << 8;
            }
            i += 2;
        }

        // Fold 32-bit sum to 16 bits
        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // Take one's complement
        self.checksum = ~@as(u16, @intCast(sum));

        _ = old_checksum;
    }

    /// Validate ICMP checksum
    pub fn validate_checksum(self: *const ICMPHeader, payload: []const u8) bool {
        var sum: u32 = 0;

        const header_ptr: [*]const u8 = @ptrCast(self);
        var i: usize = 0;
        while (i < ICMPHeaderSize) {
            if (i + 1 < ICMPHeaderSize) {
                const word = (@as(u16, header_ptr[i]) << 8) | header_ptr[i + 1];
                sum += word;
            } else {
                sum += @as(u16, header_ptr[i]) << 8;
            }
            i += 2;
        }

        i = 0;
        while (i < payload.len) {
            if (i + 1 < payload.len) {
                const word = (@as(u16, payload[i]) << 8) | payload[i + 1];
                sum += word;
            } else {
                sum += @as(u16, payload[i]) << 8;
            }
            i += 2;
        }

        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return @as(u16, @intCast(sum)) == 0xFFFF;
    }
};

pub const ICMPLayer = struct {
    data: []u8, // ICMP header + payload

    pub fn init(buffer: []u8) LayerError!ICMPLayer {
        if (buffer.len < @sizeOf(ICMPHeader)) return LayerError.BufferTooSmall;

        // Verify alignment
        const alignment = @alignOf(ICMPHeader);
        const addr = @intFromPtr(buffer.ptr);
        if (addr % alignment != 0) {
            return LayerError.MisalignedBuffer;
        }

        return ICMPLayer{ .data = buffer };
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

    // Type-safe code getters/setters based on ICMP type
    pub fn get_dest_unreachable_code(self: *ICMPLayer) !ICMPDestinationUnreachableCode {
        const hdr = self.get_header();
        if (hdr.get_type() != .DestinationUnreachable) {
            return LayerError.InvalidOperation;
        }
        return hdr.get_dest_unreachable_code();
    }

    pub fn set_dest_unreachable_code(self: *ICMPLayer, code: ICMPDestinationUnreachableCode) !void {
        var hdr = self.get_header();
        if (hdr.get_type() != .DestinationUnreachable) {
            return LayerError.InvalidOperation;
        }
        hdr.set_dest_unreachable_code(code);
    }

    pub fn get_redirect_code(self: *ICMPLayer) !ICMPRedirectCode {
        const hdr = self.get_header();
        if (hdr.get_type() != .Redirect) {
            return LayerError.InvalidOperation;
        }
        return hdr.get_redirect_code();
    }

    pub fn set_redirect_code(self: *ICMPLayer, code: ICMPRedirectCode) !void {
        var hdr = self.get_header();
        if (hdr.get_type() != .Redirect) {
            return LayerError.InvalidOperation;
        }
        hdr.set_redirect_code(code);
    }

    pub fn get_time_exceeded_code(self: *ICMPLayer) !ICMPTimeExceededCode {
        const hdr = self.get_header();
        if (hdr.get_type() != .TimeExceeded) {
            return LayerError.InvalidOperation;
        }
        return hdr.get_time_exceeded_code();
    }

    pub fn set_time_exceeded_code(self: *ICMPLayer, code: ICMPTimeExceededCode) !void {
        var hdr = self.get_header();
        if (hdr.get_type() != .TimeExceeded) {
            return LayerError.InvalidOperation;
        }
        hdr.set_time_exceeded_code(code);
    }

    pub fn get_param_problem_code(self: *ICMPLayer) !ICMPParameterProblemCode {
        const hdr = self.get_header();
        if (hdr.get_type() != .ParameterProblem) {
            return LayerError.InvalidOperation;
        }
        return hdr.get_param_problem_code();
    }

    pub fn set_param_problem_code(self: *ICMPLayer, code: ICMPParameterProblemCode) !void {
        var hdr = self.get_header();
        if (hdr.get_type() != .ParameterProblem) {
            return LayerError.InvalidOperation;
        }
        hdr.set_param_problem_code(code);
    }

    // Generic code getter (returns raw u8, use with caution)
    pub fn get_code_raw(self: *ICMPLayer) u8 {
        const hdr = self.get_header();
        return hdr.code;
    }

    pub fn set_code_raw(self: *ICMPLayer, code: u8) void {
        var hdr = self.get_header();
        hdr.code = code;
    }

    // For Echo, Timestamp, Information, and Address Mask messages
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

    // For Redirect messages
    pub fn get_gateway(self: *ICMPLayer) !u32 {
        const hdr = self.get_header();
        if (hdr.get_type() != .Redirect) {
            return LayerError.InvalidOperation;
        }
        return hdr.get_gateway();
    }

    pub fn set_gateway(self: *ICMPLayer, gateway: u32) !void {
        var hdr = self.get_header();
        if (hdr.get_type() != .Redirect) {
            return LayerError.InvalidOperation;
        }
        hdr.set_gateway(gateway);
    }

    // For Parameter Problem messages
    pub fn get_pointer(self: *ICMPLayer) !u8 {
        const hdr = self.get_header();
        if (hdr.get_type() != .ParameterProblem) {
            return LayerError.InvalidOperation;
        }
        return hdr.get_pointer();
    }

    pub fn set_pointer(self: *ICMPLayer, pointer: u8) !void {
        var hdr = self.get_header();
        if (hdr.get_type() != .ParameterProblem) {
            return LayerError.InvalidOperation;
        }
        hdr.set_pointer(pointer);
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

    pub fn validate_checksum(self: *ICMPLayer) bool {
        const hdr = self.get_header();
        const payload = self.get_payload();
        return hdr.validate_checksum(payload);
    }

    pub fn to_string(self: *ICMPLayer, allocator: std.mem.Allocator) ![]const u8 {
        const hdr = self.get_header();
        const icmp_type = hdr.get_type();

        var code_string: []const u8 = undefined;
        var code_value: u8 = undefined;

        switch (icmp_type) {
            .DestinationUnreachable => {
                const code = try self.get_dest_unreachable_code();
                code_string = code.to_string();
                code_value = @intFromEnum(code);
            },
            .Redirect => {
                const code = try self.get_redirect_code();
                code_string = code.to_string();
                code_value = @intFromEnum(code);
            },
            .TimeExceeded => {
                const code = try self.get_time_exceeded_code();
                code_string = code.to_string();
                code_value = @intFromEnum(code);
            },
            .ParameterProblem => {
                const code = try self.get_param_problem_code();
                code_string = code.to_string();
                code_value = @intFromEnum(code);
            },
            else => {
                code_string = "None";
                code_value = hdr.code;
            },
        }

        const checksum = hdr.checksum;

        var buf = std.ArrayList(u8).empty;
        defer buf.deinit(allocator);

        const writer = buf.writer(allocator);

        // Base info
        try writer.print(
            \\ICMP Layer:
            \\  Type: {s} ({})
            \\  Code: {s} ({})
            \\  Checksum: 0x{x:0>4}
            \\
        , .{
            icmp_type.to_string(),
            @intFromEnum(icmp_type),
            code_string,
            code_value,
            checksum,
        });

        // Type-specific fields
        switch (icmp_type) {
            .EchoRequest, .EchoReply, .TimestampRequest, .TimestampReply, .InformationRequest, .InformationReply, .AddressMaskRequest, .AddressMaskReply => {
                try writer.print(
                    "  Identifier: {}\n  Sequence: {}\n",
                    .{ self.get_identifier(), self.get_sequence() },
                );
            },
            .Redirect => {
                const gateway = self.get_gateway() catch 0;
                try writer.print("  Gateway: {}\n", .{gateway});
            },
            .ParameterProblem => {
                const pointer = self.get_pointer() catch 0;
                try writer.print("  Pointer: {}\n", .{pointer});
            },
            else => {},
        }

        // Payload
        const payload = self.get_payload();
        if (payload.len > 0) {
            try writer.print("  Payload Length: {} bytes\n", .{payload.len});
        }

        return buf.toOwnedSlice(allocator);
    }

    pub fn deinit(self: *ICMPLayer, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};

comptime {
    if (@sizeOf(ICMPHeader) != 8) {
        @compileError("ICMPHeader size must be 8 bytes");
    }
}
