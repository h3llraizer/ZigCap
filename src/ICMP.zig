const std = @import("std");
const ProtocolEnums = @import("ProtocolEnums.zig");
const LayerIface = @import("LayerIface.zig").LayerIface;
const init_layer = @import("LayerIface.zig").init_layer;
const LayerOwner = @import("Owner.zig").LayerOwner;
const Layer = @import("Packet.zig").Layer;
const IPv4 = @import("IPv4.zig");
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;

const ICMP_Types = @import("ICMP_Types.zig");

pub const ICMPType = ICMP_Types.ICMPType;
pub const ICMP_type = ICMP_Types.ICMP_type;

pub const ICMPEcho = ICMP_Types.Echo;
pub const ICMPTimestamp = ICMP_Types.Timestamp;
pub const ICMPDestUnr = ICMP_Types.DestinationUncreachable;
pub const ICMPAddrMask = ICMP_Types.AddressMask;
pub const ICMPRedirect = ICMP_Types.Redirect;
pub const ICMPSourceQuench = ICMP_Types.SourceQuench;
pub const ICMPParamProb = ICMP_Types.ParameterProblem;
pub const ICMPRouterAd = ICMP_Types.RouterAdvertisement;
pub const ICMPRouterSol = ICMP_Types.RouterSolicitation;
pub const ICMPInfo = ICMP_Types.Info;

const print = std.debug.print;
const Allocator = std.mem.Allocator;
const panic = std.debug.panic;
const LayerError = ProtocolEnums.LayerError;

pub const ICMPHeaderSize = 8; // TODO: Rename - this is minimum size because any ICMP type extends from 4 to 8 minimum
const BaseHeaderSize = 4; // absolute base header

const default_hdr = ICMPHeader{
    .type = 0,
    .code = 0,
    .checksum = 0,
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

    /// you can use this but be aware you may malform the packet due to variable length ICMP Headers which go beyond the standard 8 bytes - use ICMPLayer.set_type() instead to be safe
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
    fn validate_checksum(self: *const ICMPHeader, payload: []const u8) bool {
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

                    @memmove(icmp_data[0..BaseHeaderSize], std.mem.asBytes(&header));
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
                const echo_hdr_start = data[BaseHeaderSize..];
                const aligned_ptr: [*]align(@alignOf(ICMPEcho)) u8 = @alignCast(echo_hdr_start.ptr);
                const icmp_echo_hdr: *ICMPEcho = @ptrCast(aligned_ptr);
                return ICMP_type{ .echo = icmp_echo_hdr };
            },
            .DestinationUnreachable, .TimeExceeded => {
                const te_hdr_start = data[BaseHeaderSize..];
                const aligned_ptr: [*]align(@alignOf(ICMPDestUnr)) u8 = @alignCast(te_hdr_start.ptr);
                const icmp_te_hdr: *ICMPDestUnr = @ptrCast(aligned_ptr);
                return ICMP_type{ .dest_unreachable = icmp_te_hdr };
            },
            .Redirect => {
                const rd_hdr_start = data[BaseHeaderSize..];
                const aligned_ptr: [*]align(@alignOf(ICMPRedirect)) u8 = @alignCast(rd_hdr_start.ptr);
                const icmp_rd_hdr: *ICMPRedirect = @ptrCast(aligned_ptr);
                return ICMP_type{ .redirect = icmp_rd_hdr };
            },
            .ParameterProblem => {
                const hdr: *ICMPParamProb = @ptrCast(@alignCast(data[BaseHeaderSize..].ptr));
                return ICMP_type{ .parameter_problem = hdr };
            },
            .RouterAdvertisement => {
                const hdr: *ICMPRouterAd = @ptrCast(@alignCast(data[BaseHeaderSize..].ptr));
                return ICMP_type{ .router_advertisement = hdr };
            },
            .RouterSolicitation => {
                const hdr: *ICMPRouterSol = @ptrCast(@alignCast(data[BaseHeaderSize..].ptr));
                return ICMP_type{ .route_solicitation = hdr };
            },
            .TimestampRequest, .TimestampReply => {
                const hdr: *ICMPTimestamp = @ptrCast(@alignCast(data[BaseHeaderSize..].ptr));
                return ICMP_type{ .timestamp = hdr };
            },
            .InformationReply, .InformationRequest => {
                const hdr: *ICMPInfo = @ptrCast(@alignCast(data[BaseHeaderSize..].ptr));
                return ICMP_type{ .info = hdr };
            },
            .AddressMaskReply, .AddressMaskRequest => {
                const hdr: *ICMPAddrMask = @ptrCast(@alignCast(data[BaseHeaderSize..].ptr));
                return ICMP_type{ .address_mask = hdr };
            },
            .SourceQuench => {
                const hdr: *ICMPSourceQuench = @ptrCast(@alignCast(data[BaseHeaderSize..].ptr));
                return ICMP_type{ .source_quench = hdr };
            },
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
    pub fn get_data(self: *const ICMPLayer) []u8 {
        return self.owner.get_data();
    }

    /// return immutable slice of the payload
    pub fn get_payload(self: *ICMPLayer) []const u8 {
        const data = self.get_data();

        const header_type_size = self.get_header_type_size();

        const full_header_size = BaseHeaderSize + header_type_size;

        if (data.len > full_header_size) {
            return data[full_header_size..];
        }
        return "";
    }

    fn get_header_type_size(self: *ICMPLayer) usize {
        const hdr = self.get_immutable_header();
        const icmp_type = hdr.get_type();
        switch (icmp_type) {
            .TimestampRequest, .TimestampReply => {
                return @sizeOf(ICMPTimestamp);
            },
            .AddressMaskRequest, .AddressMaskReply => {
                return @sizeOf(ICMPAddrMask);
            },
            .SourceQuench => {
                return @sizeOf(ICMPSourceQuench);
            },
            else => {
                return BaseHeaderSize;
            },
        }
    }

    /// Sets the payload of the ICMPLayer.
    /// Can be any ICMP type but commonly ICMP Echo Request/Reply is the type which has a payload
    pub fn set_payload(self: *ICMPLayer, payload: []const u8) Allocator.Error!void {
        const current_payload_len = self.get_payload().len;

        const header_type_size = self.get_header_type_size();

        const full_header_size = BaseHeaderSize + header_type_size;

        var buf: []u8 = self.get_data()[full_header_size..];

        if (payload.len > current_payload_len) {
            const extend_len: usize = payload.len - current_payload_len;

            buf = try self.owner.extend_layer(full_header_size, extend_len);
        }

        if (current_payload_len > payload.len) {
            const shorten_len = current_payload_len - payload.len;

            const offset = full_header_size + payload.len;

            try self.owner.shorten_layer(offset, shorten_len);
            buf = self.get_data()[full_header_size..];
        }

        @memmove(buf, payload);
    }

    pub fn remove_payload(self: *ICMPLayer) Allocator.Error!void {
        const payload_len = self.get_payload().len;
        if (payload_len > 0) {
            try self.owner.shorten_layer(self.get_data().len - payload_len, payload_len);
        }
    }

    pub fn get_type(self: *ICMPLayer) ICMPType {
        const hdr = self.get_immutable_header();
        return hdr.get_type();
    }

    pub fn set_type(self: *ICMPLayer, icmp_type: ICMPType) Allocator.Error!void {
        var hdr = self.get_mutable_header();
        hdr.set_type(icmp_type);

        const current_len = self.get_data().len;

        switch (icmp_type) {
            .TimestampRequest, .TimestampReply => {
                const diff = (BaseHeaderSize + @sizeOf(ICMPTimestamp)) - current_len;

                _ = try self.owner.extend_layer(current_len, diff);
            },
            .AddressMaskRequest, .AddressMaskReply => {
                const diff = (BaseHeaderSize + @sizeOf(ICMPAddrMask)) - current_len;

                _ = try self.owner.extend_layer(current_len, diff);
            },
            .SourceQuench => {
                const diff = (BaseHeaderSize + @sizeOf(ICMPSourceQuench)) - current_len;

                _ = try self.owner.extend_layer(current_len, diff);
            },
            else => {
                return; // no extend required
            },
        }
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
            return "Error";
        };
    }

    pub fn get_protocol(self: *ICMPLayer) tcp_ip_protocol {
        _ = self;
        return tcp_ip_protocol.icmp;
    }

    pub fn get_next_layer_type(self: *ICMPLayer, layer: *Layer) LayerError!?LayerIface {
        _ = self;
        _ = layer;
        // these types can include original IPv4 Header and full TCP Header or psuedo TCP Header:
        // dest Unreachable
        // time exceeded
        // param Problem
        // source quench
        return null;
    }

    pub fn deinit(self: *ICMPLayer) void {
        self.owner.deinit();
    }
};
