const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;
const panic = std.debug.panic;

const ProtocolEnums = @import("ProtocolEnums.zig");
const LayerIface = @import("LayerIface.zig").LayerIface;
const LayerError = ProtocolEnums.LayerError;
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;

const LayerOwner = @import("Layer.zig").LayerOwner;

const Layer = @import("Packet.zig").Layer;

const RawData = @import("RawData.zig").RawData;

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
        unused: [4]u8,
    },

    // For Redirect
    redirect: extern struct {
        type: u8,
        code: u8,
        checksum: u16,
        gateway: [4]u8,
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
        reserved: [4]u8,
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
        self.redirect.gateway = std.mem.toBytes(gateway);
    }

    pub fn get_gateway(self: *const ICMPHeader) u32 {
        return std.mem.bytesToValue(u32, &self.redirect.gateway);
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
    owner: LayerOwner,
    const Protocol = tcp_ip_protocol.icmp;

    pub fn init(owner: LayerOwner) LayerError!ICMPLayer {
        switch (owner) {
            .packet_layer => {
                return ICMPLayer{
                    .owner = owner,
                };
            },
            .allocator_owned => {
                var self = ICMPLayer{ .owner = owner };
                // Allocate directly into the struct's data field
                if (owner.allocator_owned.data.len < ICMPHeaderSize) {
                    self.owner.allocator_owned.data = try self.owner.allocator_owned.allocator.alloc(u8, ICMPHeaderSize);
                }

                //var header = ICMPHeader.init_default();
                //@memcpy(self.owner.allocator_owned.data[0..@sizeOf(ICMPHeader)], std.mem.asBytes(&header));

                return self;
            },
            .immutable_layer => return {
                return ICMPLayer{ .owner = owner };
            },
        }
    }

    fn get_mutable_header(self: *const ICMPLayer) *ICMPHeader {
        const data = self.get_data().mutable;
        const aligned_ptr: [*]align(@alignOf(ICMPHeader)) u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    fn get_immutable_header(self: *const ICMPLayer) *const ICMPHeader {
        var data: []const u8 = undefined;

        if (self.get_data().is_mutable()) { // if the data is actually mutable - we just need immutable in this case anyway
            data = self.get_data().get_mutable();
        } else {
            data = self.get_data().get_immutable();
        }

        if (data.len < ICMPHeaderSize) {
            panic("ICMP Raw Data len ({}) less than ICMPHeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(ICMPHeader)) const u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn get_data(self: *const ICMPLayer) RawData {
        switch (self.owner) {
            .packet_layer => {
                print("getting data from packet.\n", .{});

                return self.owner.packet_layer.get_data(); // Layer in packet - it might be mutable or immutable
            },
            .allocator_owned => {
                return RawData{ .mutable = self.owner.allocator_owned.data }; // standalone layer - it is mutable by default
            },
            .immutable_layer => {
                return RawData{ .immutable = self.owner.immutable_layer.raw_data };
            },
        }
    }

    pub fn get_payload(self: *ICMPLayer) ?[]const u8 { // callers may want to mutate the payload - need to implement this
        const data = self.get_data().get_immutable();
        return data[ICMPHeaderSize..];
    }

    pub fn get_type(self: *ICMPLayer) ICMPType {
        const hdr = self.get_immutable_header();
        return hdr.get_type();
    }

    pub fn set_type(self: *ICMPLayer, icmp_type: ICMPType) void {
        var hdr = self.get_mutable_header();
        hdr.set_type(icmp_type);
    }

    // Type-safe code getters/setters based on ICMP type
    pub fn get_dest_unreachable_code(self: *ICMPLayer) !ICMPDestinationUnreachableCode {
        const hdr = self.get_immutable_header();
        if (hdr.get_type() != .DestinationUnreachable) {
            return LayerError.InvalidOperation;
        }
        return hdr.get_dest_unreachable_code();
    }

    pub fn set_dest_unreachable_code(self: *ICMPLayer, code: ICMPDestinationUnreachableCode) !void {
        var hdr = self.get_mutable_header();
        if (hdr.get_type() != .DestinationUnreachable) {
            return LayerError.InvalidOperation;
        }
        hdr.set_dest_unreachable_code(code);
    }

    pub fn get_redirect_code(self: *ICMPLayer) !ICMPRedirectCode {
        const hdr = self.get_immutable_header();
        if (hdr.get_type() != .Redirect) {
            return LayerError.InvalidOperation;
        }
        return hdr.get_redirect_code();
    }

    pub fn set_redirect_code(self: *ICMPLayer, code: ICMPRedirectCode) !void {
        var hdr = self.get_mutable_header();
        if (hdr.get_type() != .Redirect) {
            return LayerError.InvalidOperation;
        }
        hdr.set_redirect_code(code);
    }

    pub fn get_time_exceeded_code(self: *ICMPLayer) !ICMPTimeExceededCode {
        const hdr = self.get_immutable_header();
        if (hdr.get_type() != .TimeExceeded) {
            return LayerError.InvalidOperation;
        }
        return hdr.get_time_exceeded_code();
    }

    pub fn set_time_exceeded_code(self: *ICMPLayer, code: ICMPTimeExceededCode) !void {
        var hdr = self.get_mutable_header();
        if (hdr.get_type() != .TimeExceeded) {
            return LayerError.InvalidOperation;
        }
        hdr.set_time_exceeded_code(code);
    }

    pub fn get_param_problem_code(self: *ICMPLayer) !ICMPParameterProblemCode {
        const hdr = self.get_immutable_header();
        if (hdr.get_type() != .ParameterProblem) {
            return LayerError.InvalidOperation;
        }
        return hdr.get_param_problem_code();
    }

    pub fn set_param_problem_code(self: *ICMPLayer, code: ICMPParameterProblemCode) !void {
        var hdr = self.get_mutable_header();
        if (hdr.get_type() != .ParameterProblem) {
            return LayerError.InvalidOperation;
        }
        hdr.set_param_problem_code(code);
    }

    // Generic code getter (returns raw u8, use with caution)
    pub fn get_code_raw(self: *ICMPLayer) u8 {
        const hdr = self.get_immutable_header();
        return hdr.code;
    }

    pub fn set_code_raw(self: *ICMPLayer, code: u8) void {
        var hdr = self.get_mutable_header();
        hdr.code = code;
    }

    // For Echo, Timestamp, Information, and Address Mask messages
    pub fn get_identifier(self: *ICMPLayer) u16 {
        const hdr = self.get_immutable_header();
        return hdr.get_identifier();
    }

    pub fn set_identifier(self: *ICMPLayer, id: u16) void {
        var hdr = self.get_mutable_header();
        hdr.set_identifier(id);
    }

    pub fn get_sequence(self: *ICMPLayer) u16 {
        const hdr = self.get_immutable_header();
        return hdr.get_sequence();
    }

    pub fn set_sequence(self: *ICMPLayer, seq: u16) void {
        var hdr = self.get_mutable_header();
        hdr.set_sequence(seq);
    }

    // For Redirect messages
    pub fn get_gateway(self: *ICMPLayer) !u32 {
        const hdr = self.get_immutable_header();
        if (hdr.get_type() != .Redirect) {
            return LayerError.InvalidOperation;
        }
        return hdr.get_gateway();
    }

    pub fn set_gateway(self: *ICMPLayer, gateway: u32) !void {
        var hdr = self.get_mutable_header();
        if (hdr.get_type() != .Redirect) {
            return LayerError.InvalidOperation;
        }
        hdr.set_gateway(gateway);
    }

    // For Parameter Problem messages
    pub fn get_pointer(self: *ICMPLayer) !u8 {
        const hdr = self.get_immutable_header();
        if (hdr.get_type() != .ParameterProblem) {
            return LayerError.InvalidOperation;
        }
        return hdr.get_pointer();
    }

    pub fn set_pointer(self: *ICMPLayer, pointer: u8) !void {
        var hdr = self.get_mutable_header();
        if (hdr.get_type() != .ParameterProblem) {
            return LayerError.InvalidOperation;
        }
        hdr.set_pointer(pointer);
    }

    pub fn get_checksum(self: *ICMPLayer) u16 {
        const hdr = self.get_immutable_header();
        return hdr.checksum;
    }

    pub fn calculate_checksum(self: *ICMPLayer) void {
        const hdr = self.get_mutable_header();
        const payload = self.get_payload();
        hdr.calculate_checksum(payload);
    }

    pub fn validate_checksum(self: *ICMPLayer) bool {
        const hdr = self.get_immutable_header();
        const payload = self.get_payload();
        return hdr.validate_checksum(payload);
    }

    pub fn to_string(self: *ICMPLayer, allocator: std.mem.Allocator) []const u8 {
        const hdr = self.get_immutable_header();
        const icmp_type = hdr.get_type();

        var code_string: []const u8 = undefined;
        var code_value: u8 = undefined;

        switch (icmp_type) {
            .DestinationUnreachable => {
                if (self.get_dest_unreachable_code()) |code| {
                    code_string = code.to_string();
                    code_value = @intFromEnum(code);
                } else |_| {
                    code_string = "Error";
                    code_value = hdr.code;
                }
            },
            .Redirect => {
                if (self.get_redirect_code()) |code| {
                    code_string = code.to_string();
                    code_value = @intFromEnum(code);
                } else |_| {
                    code_string = "Error";
                    code_value = hdr.code;
                }
            },
            .TimeExceeded => {
                if (self.get_time_exceeded_code()) |code| {
                    code_string = code.to_string();
                    code_value = @intFromEnum(code);
                } else |_| {
                    code_string = "Error";
                    code_value = hdr.code;
                }
            },
            .ParameterProblem => {
                if (self.get_param_problem_code()) |code| {
                    code_string = code.to_string();
                    code_value = @intFromEnum(code);
                } else |_| {
                    code_string = "Error";
                    code_value = hdr.code;
                }
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

        // Base info (using catch to handle any print errors)
        _ = writer.print(
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
        }) catch {};

        // Type-specific fields
        switch (icmp_type) {
            .EchoRequest, .EchoReply, .TimestampRequest, .TimestampReply, .InformationRequest, .InformationReply, .AddressMaskRequest, .AddressMaskReply => {
                const identifier = self.get_identifier();
                const sequence = self.get_sequence();
                _ = writer.print("  Identifier: {}\n  Sequence: {}\n", .{ identifier, sequence }) catch {};
            },
            .Redirect => {
                const gateway = self.get_gateway() catch 0;
                _ = writer.print("  Gateway: {}\n", .{gateway}) catch {};
            },
            .ParameterProblem => {
                const pointer = self.get_pointer() catch 0;
                _ = writer.print("  Pointer: {}\n", .{pointer}) catch {};
            },
            else => {},
        }

        // Payload
        const payload = self.get_payload();
        if (payload) |p| {
            _ = writer.print("  Payload Length: {} bytes\n", .{p.len}) catch {};
        }

        return buf.toOwnedSlice(allocator) catch return &[_]u8{};
    }

    pub fn get_protocol(self: *ICMPLayer) tcp_ip_protocol {
        _ = self;
        return ICMPLayer.Protocol;
    }

    pub fn get_next_layer_type(self: *ICMPLayer, layer: *Layer) !?LayerIface {
        _ = self;
        _ = layer;
        return null;
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
