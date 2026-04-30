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

const IPv4 = @import("IPv4.zig");

pub const ICMPHeaderSize = 8;

pub const ICMPType = enum(u8) {
    EchoReply = 0,
    DestinationUnreachable = 3,
    SourceQuench = 4, // not used often - need to get working example first
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
};

pub const DestinationUnreachableCode = enum(u8) {
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
};

pub const RedirectCode = enum(u8) {
    RedirectForNetwork = 0,
    RedirectForHost = 1,
    RedirectForTOSAndNetwork = 2,
    RedirectForTOSAndHost = 3,
};

pub const TimeExceededCode = enum(u8) {
    TTLExceeded = 0,
    FragmentReassemblyTimeExceeded = 1,
};

pub const ParameterProblemCode = enum(u8) {
    PointerIndicatesError = 0,
    MissingOption = 1,
    BadLength = 2,
};

pub const NoCode = enum(u8) {
    None = 0,
};

pub const ICMPCode = union(enum) {
    no: NoCode,
    param_problem: ParameterProblemCode,
    time_exceeded: TimeExceededCode,
    redirect: RedirectCode,
    dest_unreachable: DestinationUnreachableCode,
};

/// ICMP Echo (Request/Response)
pub const ICMPEcho = extern struct {
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

/// ICMP Destination Unreachable
/// used in TTL timeouts
pub const ICMPDestUnr = extern struct {
    unused: [4]u8,
};

/// ICMP Redirect
pub const ICMPRedirect = extern struct {
    gateway: [4]u8,

    pub fn set_gateway(self: *ICMPRedirect, gateway: IPv4.IPv4Address) void {
        self.redirect.gateway = gateway.array;
    }

    pub fn get_gateway(self: *const ICMPRedirect) IPv4.IPv4Address {
        return IPv4.IPv4Address.init_from_array(self.redirect.gateway);
    }
};

/// ICMP Parameter Problem
pub const ICMPParamProb = extern struct {
    pointer: u8,
    unused: [3]u8,

    pub fn set_pointer(self: *ICMPHeader, pointer: u8) void {
        self.param_problem.pointer = pointer;
    }

    pub fn get_pointer(self: *const ICMPHeader) u8 {
        return self.param_problem.pointer;
    }
};

/// ICMP Router Advertisement
pub const ICMPRouterAd = extern struct {
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

/// ICMP Router Solicitation
pub const ICMPRouterSol = extern struct {
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
pub const ICMPHeader = extern struct {
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

    pub fn set_code(self: *ICMPHeader, code: u8) void {
        self.code = code;
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
        self.checksum = @byteSwap(~@as(u16, @intCast(sum)));

        _ = old_checksum;
    }

    /// Validate ICMP checksum - doesn't work. don't use it
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
                    const diff = ICMPHeaderSize - buffer_len;
                    const icmp_data = try self.owner.owned_buffer.extend(buffer_len, diff);

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
            .EchoReply, .EchoRequest => {
                const echo_hdr_start = data[4..];
                const aligned_ptr: [*]align(@alignOf(ICMPEcho)) u8 = @alignCast(echo_hdr_start.ptr);
                const icmp_echo_hdr: *ICMPEcho = @ptrCast(aligned_ptr);
                return ICMP_type{ .icmpEcho = icmp_echo_hdr };
            },
            .DestinationUnreachable, .TimeExceeded => {
                const te_hdr_start = data[4..];
                const aligned_ptr: [*]align(@alignOf(ICMPDestUnr)) u8 = @alignCast(te_hdr_start.ptr);
                const icmp_te_hdr: *ICMPDestUnr = @ptrCast(aligned_ptr);
                return ICMP_type{ .icmpDestUnreachable = icmp_te_hdr };
            },
            .Redirect => {
                const rd_hdr_start = data[4..];
                const aligned_ptr: [*]align(@alignOf(ICMPRedirect)) u8 = @alignCast(rd_hdr_start.ptr);
                const icmp_rd_hdr: *ICMPRedirect = @ptrCast(aligned_ptr);
                return ICMP_type{ .icmpRedirect = icmp_rd_hdr };
            },

            .ParameterProblem => {
                const hdr: *ICMPParamProb = @ptrCast(@alignCast(data[4..].ptr));
                return ICMP_type{ .icmpParamProbl = hdr };
            },
            .RouterAdvertisement => {
                const hdr: *ICMPRouterAd = @ptrCast(@alignCast(data[4..].ptr));
                return ICMP_type{ .icmpRouterAd = hdr };
            },
            .RouterSolicitation => {
                const hdr: *ICMPRouterSol = @ptrCast(@alignCast(data[4..].ptr));
                return ICMP_type{ .icmpRouterSoli = hdr };
            },

            else => return null, // Timestamp, Information, AddressMask types need structs
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
        return self.owner.get_data();
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

    //fn account_options(self: *ICMPLayer) !void {
    //
    //}

    pub fn validate_layer(self: *ICMPLayer) void {
        const hdr = self.get_mutable_header();
        hdr.calculate_checksum(self.get_payload());
    }

    /// doesn't work - don't use it
    pub fn validate_checksum(self: *ICMPLayer) bool {
        const hdr = self.get_immutable_header();
        if (self.get_payload()) |payload| {
            return hdr.validate_checksum(payload);
        }
    }

    pub fn to_string(self: *ICMPLayer, allocator: std.mem.Allocator) []const u8 {
        const hdr = self.get_immutable_header();

        return std.fmt.allocPrint(allocator, "{any}", .{hdr.get_type()}) catch {
            return "";
        };
    }

    pub fn get_protocol(self: *ICMPLayer) tcp_ip_protocol {
        _ = self;
        return ICMPLayer.Protocol;
    }

    pub fn get_next_layer_type(self: *ICMPLayer, layer: *Layer) !?LayerIface {
        _ = self;
        _ = layer;
        // these types can include original packet copy
        // dest Unreachable
        // time exceeded
        // param Problem
        // source quench
        //
        return null;
    }

    pub fn deinit(self: *ICMPLayer) void {
        self.owner.deinit();
    }
};

//   comptime {
//       if (@sizeOf(ICMPHeader) != 8) {
//           @compileError("ICMPHeader size must be 8 bytes");
//       }
//
