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

const IPv4 = @import("IPv4.zig");

pub const ICMPHeaderSize = 8;

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

pub const ICMPEcho = struct {
    identifier: u16,
    sequence: u16,

    pub fn set_identifier(self: *ICMPEcho, id: u16) void {
        self.identifier = @byteSwap(id);
    }

    pub fn get_identifier(self: *const ICMPEcho) u16 {
        return @byteSwap(self.identifier);
    }

    pub fn set_sequence(self: *ICMPEcho, seq: u16) void {
        self.sequence = @byteSwap(seq);
    }

    pub fn get_sequence(self: *const ICMPEcho) u16 {
        return @byteSwap(self.sequence);
    }
};

pub const ICMPDestUnr = struct {
    unused: [4]u8,
};

pub const ICMPRedirect = struct {
    gateway: [4]u8,

    pub fn set_gateway(self: *ICMPHeader, gateway: IPv4.IPv4Address) void { // TODO: use Ipv4 address struct instead
        self.redirect.gateway = gateway.array;
    }

    pub fn get_gateway(self: *const ICMPHeader) IPv4.IPv4Address { // TODO: use Ipv4 address struct instead
        return IPv4.IPv4Address.init_from_array(self.redirect.gateway);
    }
};

pub const ICMPParamProb = struct {
    pointer: u8,
    unused: [3]u8,

    pub fn set_pointer(self: *ICMPHeader, pointer: u8) void {
        self.param_problem.pointer = pointer;
    }

    pub fn get_pointer(self: *const ICMPHeader) u8 {
        return self.param_problem.pointer;
    }
};

pub const ICMPRouterAd = struct {
    num_addresses: u8,
    addr_entry_size: u8,
    lifetime: u16,

    pub fn get_num_addresses(self: *ICMPRouterAd) u8 {
        return self.num_addresses;
    }

    pub fn set_num_addresses(self: *ICMPRouterAd, num_addresses: u8) void {
        self.num_addresses = num_addresses;
    }

    pub fn get_addr_entry_size(self: *ICMPRouterAd) u8 {
        return self.get_addr_entry_size;
    }

    pub fn set_addr_entry_size(self: *ICMPRouterAd, entry_size: u8) void {
        self.set_addr_entry_size = entry_size;
    }

    pub fn get_lifetime(self: *ICMPRouterAd) u16 {
        return @byteSwap(self.lifetime);
    }

    pub fn set_lifetime(self: *ICMPRouterAd, lifetime: u16) void {
        self.lifetime = @byteSwap(lifetime);
    }
};

pub const ICMPRouterSol = struct {
    reserved: [4]u8,
};

pub const ICMP_type = union(enum) {
    icmpEcho: *ICMPEcho,
    icmpDestUnreachable: *ICMPDestUnr,
    icmpRedirect: *ICMPRedirect,
    icmpParamProbl: *ICMPParamProb,
    icmpRouterAd: *ICMPRouterAd,
    icmpRouterSoli: *ICMPRouterSol,
};

/// Acts as the base header for ICMP
pub const ICMPHeader = struct {
    type: u8,
    code: u8,
    checksum: u16,

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
            .owned_buffer => {
                var self = ICMPLayer{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < ICMPHeaderSize) {
                    const icmp_data = try self.owner.owned_buffer.extend(buffer_len, ICMPHeaderSize);

                    @memset(icmp_data, 0);

                    var header = ICMPHeader.init_default(); // creates the ICMP Base Header default

                    @memcpy(icmp_data[0..4], std.mem.asBytes(&header));
                }

                return self;
            },
        }
    }

    pub fn get_icmp_type_hdr(self: *ICMPLayer) ?ICMP_type {
        const base_hdr = self.get_immutable_header();

        const data = self.get_data();

        switch (base_hdr.get_type()) {
            .EchoReply => {
                const echo_hdr_start = data[4..];
                const aligned_ptr: [*]align(@alignOf(ICMPEcho)) u8 = @alignCast(echo_hdr_start.ptr);
                const icmp_echo_hdr: *ICMPEcho = @ptrCast(aligned_ptr);
                return ICMP_type{ .icmpEcho = icmp_echo_hdr };
            },

            else => return null,
        }
    }

    pub fn get_mutable_header(self: *const ICMPLayer) *ICMPHeader {
        const data = self.get_data();

        if (data.len < ICMPHeaderSize) {
            panic("ICMP data len ({}) less than ICMPHeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(ICMPHeader)) u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn get_immutable_header(self: *const ICMPLayer) *const ICMPHeader {
        const data: []const u8 = self.get_data();

        if (data.len < ICMPHeaderSize) {
            panic("ICMP data len ({}) less than ICMPHeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(ICMPHeader)) const u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    /// returns mutable slice of data (hdr+payload).
    /// this will likely be made private in future to avoid accidental mutations
    pub fn get_data(self: *const ICMPLayer) []u8 {
        switch (self.owner) {
            .packet_layer => |layer| {
                return layer.get_data(); // Layer in packet - it might be mutable or immutable
            },
            .owned_buffer => |*buffer| {
                return buffer.buffer.items; // standalone layer - it is mutable by default
            },
        }
    }

    /// return immutable slice of the payload
    pub fn get_payload(self: *ICMPLayer) []const u8 {
        const data = self.get_data();
        if (data.len > ICMPHeaderSize) {
            return data[ICMPHeaderSize..];
        }
        return "";
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

    pub fn get_checksum(self: *ICMPLayer) u16 {
        const hdr = self.get_immutable_header();
        return hdr.checksum;
    }

    pub fn calculate_checksum(self: *ICMPLayer) void {
        const hdr = self.get_mutable_header();
        if (self.get_payload()) |payload| {
            hdr.calculate_checksum(payload);
        }
    }

    pub fn validate_checksum(self: *ICMPLayer) bool {
        const hdr = self.get_immutable_header();
        if (self.get_payload()) |payload| {
            return hdr.validate_checksum(payload);
        }
    }

    pub fn to_string(self: *ICMPLayer, allocator: std.mem.Allocator) []const u8 {
        const hdr = self.get_immutable_header();

        return std.fmt.allocPrint(allocator, "{s}", .{@tagName(hdr.get_type())}) catch {
            return "";
        };

        //       const icmp_type = hdr.get_type();
        //
        //       var code_string: []const u8 = undefined;
        //       var code_value: u8 = undefined;
        //
        //       switch (icmp_type) {
        //           .DestinationUnreachable => {
        //               if (self.get_dest_unreachable_code()) |code| {
        //                   code_string = code.to_string();
        //                   code_value = @intFromEnum(code);
        //               } else |_| {
        //                   code_string = "Error";
        //                   code_value = hdr.code;
        //               }
        //           },
        //           .Redirect => {
        //               if (self.get_redirect_code()) |code| {
        //                   code_string = code.to_string();
        //                   code_value = @intFromEnum(code);
        //               } else |_| {
        //                   code_string = "Error";
        //                   code_value = hdr.code;
        //               }
        //           },
        //           .TimeExceeded => {
        //               if (self.get_time_exceeded_code()) |code| {
        //                   code_string = code.to_string();
        //                   code_value = @intFromEnum(code);
        //               } else |_| {
        //                   code_string = "Error";
        //                   code_value = hdr.code;
        //               }
        //           },
        //           .ParameterProblem => {
        //               if (self.get_param_problem_code()) |code| {
        //                   code_string = code.to_string();
        //                   code_value = @intFromEnum(code);
        //               } else |_| {
        //                   code_string = "Error";
        //                   code_value = hdr.code;
        //               }
        //           },
        //           else => {
        //               code_string = "None";
        //               code_value = hdr.code;
        //           },
        //       }
        //
        //       const checksum = hdr.checksum;
        //
        //       var buf = std.ArrayList(u8).empty;
        //       defer buf.deinit(allocator);
        //
        //       const writer = buf.writer(allocator);
        //
        //       // Base info (using catch to handle any print errors)
        //       _ = writer.print(
        //           \\ICMP Layer:
        //           \\  Type: {s} ({})
        //           \\  Code: {s} ({})
        //           \\  Checksum: 0x{x:0>4}
        //           \\
        //       , .{
        //           icmp_type.to_string(),
        //           @intFromEnum(icmp_type),
        //           code_string,
        //           code_value,
        //           checksum,
        //       }) catch {};
        //
        //       // Type-specific fields
        //       switch (icmp_type) {
        //           .EchoRequest, .EchoReply, .TimestampRequest, .TimestampReply, .InformationRequest, .InformationReply, .AddressMaskRequest, .AddressMaskReply => {
        //               const identifier = self.get_identifier();
        //               const sequence = self.get_sequence();
        //               _ = writer.print("  Identifier: {}\n  Sequence: {}\n", .{ identifier, sequence }) catch {};
        //           },
        //           .Redirect => {
        //               const gateway = self.get_gateway() catch 0;
        //               _ = writer.print("  Gateway: {}\n", .{gateway}) catch {};
        //           },
        //           .ParameterProblem => {
        //               const pointer = self.get_pointer() catch 0;
        //               _ = writer.print("  Pointer: {}\n", .{pointer}) catch {};
        //           },
        //           else => {},
        //       }
        //
        //       // Payload
        //       const payload = self.get_payload();
        //       if (payload) |p| {
        //           _ = writer.print("  Payload Length: {} bytes\n", .{p.len}) catch {};
        //       }
        //
        //       return buf.toOwnedSlice(allocator) catch return &[_]u8{};
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

    pub fn deinit(self: *ICMPLayer) void {
        switch (self.owner) {
            .packet_layer => {
                return; // Layer in packet - don't free
            },
            .owned_buffer => |*buffer| {
                return buffer.deinit(); // standalone layer - it is mutable by default
            },
        }
    }
};

//   comptime {
//       if (@sizeOf(ICMPHeader) != 8) {
//           @compileError("ICMPHeader size must be 8 bytes");
//       }
//   }
