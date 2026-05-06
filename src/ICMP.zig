const std = @import("std");
const ProtocolEnums = @import("ProtocolEnums.zig");
const LayerIface = @import("LayerIface.zig").LayerIface;
const LayerOwner = @import("Layer.zig").LayerOwner;
const Layer = @import("Packet.zig").Layer;
const IPv4 = @import("IPv4.zig");
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;

const print = std.debug.print;
const Allocator = std.mem.Allocator;
const panic = std.debug.panic;
const LayerError = ProtocolEnums.LayerError;

pub const ICMPHeaderSize = 8; // TODO: Rename - this is minimum size because any ICMP type extends from 4 to 8 minimum
const BaseHeaderSize = 4; // absolute base header

pub const ICMPType = enum(u8) {
    EchoReply = 0,
    DestinationUnreachable = 3,
    SourceQuench = 4, // not used often - need to get working example first
    Redirect = 5,
    EchoRequest = 8,
    RouterAdvertisement = 9, // IPv6
    RouterSolicitation = 10, // IPv6
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
    /// Redirect datagrams for the Network
    RedirectForNetwork = 0,
    /// Redirect datagrams for the Host
    RedirectForHost = 1,
    /// Redirect datagrams for the Type of Service and Network
    RedirectForTOSAndNetwork = 2,
    /// Redirect datagrams for the Type of Service and Host
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

    pub fn set_seq_num(self: *ICMPEcho, seq: u16) void {
        self.sequence = @byteSwap(seq);
    }

    pub fn get_seq_num(self: *const ICMPEcho) u16 {
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

/// ICMP Timestamp Request/Reply message header.
pub const ICMPTimestamp = extern struct {
    /// Used to match requests with replies (like a port number)
    identifier: u16,
    /// Incremented per request to match replies
    sequence_number: u16,
    /// Time (ms since midnight UTC) when sender last touched the message before sending
    originate_timestamp: [4]u8,
    /// Time (ms since midnight UTC) when receiver first received the request
    receive_timestamp: [4]u8,
    /// Time (ms since midnight UTC) when receiver last touched the reply before sending
    transmit_timestamp: [4]u8,

    pub fn get_identifier(self: *ICMPTimestamp) u16 {
        return @byteSwap(self.identifier);
    }

    pub fn set_identifier(self: *ICMPTimestamp, id: u16) void {
        self.identifier = @byteSwap(id);
    }

    pub fn get_seq_num(self: *ICMPTimestamp) u16 {
        return @byteSwap(self.sequence_number);
    }

    pub fn set_seq_num(self: *ICMPTimestamp, seq_num: u16) void {
        self.sequence_number = @byteSwap(seq_num);
    }

    pub fn get_original_timestamp(self: *ICMPTimestamp) u32 {
        const val = std.mem.bytesToValue(u32, &self.originate_timestamp);
        return @byteSwap(val);
    }

    pub fn set_original_timestamp(self: *ICMPTimestamp, timestamp: u32) void {
        const bytes = std.mem.toBytes(@byteSwap(timestamp));
        self.originate_timestamp = bytes;
    }

    pub fn get_receive_timestamp(self: *ICMPTimestamp) u32 {
        const val = std.mem.bytesToValue(u32, &self.receive_timestamp);
        return @byteSwap(val);
    }

    pub fn set_receive_timestamp(self: *ICMPTimestamp, timestamp: u32) void {
        const bytes = std.mem.toBytes(@byteSwap(timestamp));
        self.receive_timestamp = bytes;
    }

    pub fn get_transmit_timestamp(self: *ICMPTimestamp) u32 {
        const val = std.mem.bytesToValue(u32, &self.transmit_timestamp);
        return @byteSwap(val);
    }

    pub fn set_transmit_timestamp(self: *ICMPTimestamp, timestamp: u32) void {
        const bytes = std.mem.toBytes(@byteSwap(timestamp));
        self.transmit_timestamp = bytes;
    }
};

/// ICMP Info (Request/Response)
pub const ICMPInfo = extern struct {
    identifier: u16,
    sequence: u16,

    pub fn set_identifier(self: *ICMPInfo, id: u16) void {
        self.identifier = @byteSwap(id);
    }

    pub fn get_identifier(self: *const ICMPInfo) u16 {
        return @byteSwap(self.identifier);
    }

    pub fn set_seq_num(self: *ICMPInfo, seq: u16) void {
        self.sequence = @byteSwap(seq);
    }

    pub fn get_seq_num(self: *const ICMPInfo) u16 {
        return @byteSwap(self.sequence);
    }
};

/// ICMP AddrMask (Request/Response)
pub const ICMPAddrMask = extern struct {
    identifier: u16,
    sequence: u16,
    address_mask: [4]u8,

    pub fn set_identifier(self: *ICMPAddrMask, id: u16) void {
        self.identifier = @byteSwap(id);
    }

    pub fn get_identifier(self: *const ICMPAddrMask) u16 {
        return @byteSwap(self.identifier);
    }

    pub fn set_seq_num(self: *ICMPAddrMask, seq: u16) void {
        self.sequence = @byteSwap(seq);
    }

    pub fn get_seq_num(self: *const ICMPAddrMask) u16 {
        return @byteSwap(self.sequence);
    }

    pub fn get_address_mask(self: *const ICMPAddrMask) IPv4.IPv4Address {
        return IPv4.IPv4Address.init_from_array(self.address_mask);
    }

    pub fn set_address_mask(self: *const ICMPAddrMask, mask: IPv4.IPv4Address) void {
        self.address_mask = mask.array;
    }
};

pub const ICMPSourceQuench = extern struct {
    unused: [4]u8,
    original_datagram_data_start: [8]u8,

    //   pub fn get_original_dgram_data(self: *ICMPSourceQuench) [8]u8 {
    //       return self.original_datagram_data_start;
    //   }
    //
    //   // might need endian conversion
    //   pub fn set_original_dgram_data(self: *ICMPSourceQuench, dgram_data: [8]u8) void {
    //       self.original_datagram_data_start = dgram_data;
    //   }
};

pub const ICMP_type = union(enum) {
    icmpEcho: *ICMPEcho,
    icmpDestUnreachable: *ICMPDestUnr,
    icmpRedirect: *ICMPRedirect,
    icmpParamProbl: *ICMPParamProb,
    icmpRouterAd: *ICMPRouterAd,
    icmpRouterSoli: *ICMPRouterSol,
    icmpTimestamp: *ICMPTimestamp,
    icmpInfo: *ICMPInfo,
    icmpAddrMask: *ICMPAddrMask,
    icmpSrcQuench: *ICMPSourceQuench,
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
            .TimestampRequest, .TimestampReply => {
                const hdr: *ICMPTimestamp = @ptrCast(@alignCast(data[4..].ptr));
                return ICMP_type{ .icmpTimestamp = hdr };
            },
            .InformationReply, .InformationRequest => {
                const hdr: *ICMPInfo = @ptrCast(@alignCast(data[4..].ptr));
                return ICMP_type{ .icmpInfo = hdr };
            },
            .AddressMaskReply, .AddressMaskRequest => {
                const hdr: *ICMPAddrMask = @ptrCast(@alignCast(data[4..].ptr));
                return ICMP_type{ .icmpAddrMask = hdr };
            },
            .SourceQuench => {
                const hdr: *ICMPSourceQuench = @ptrCast(@alignCast(data[4..].ptr));
                return ICMP_type{ .icmpSrcQuench = hdr };
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
    /// this will likely be made private in future to avoid accidental mutations
    pub fn get_data(self: *const ICMPLayer) []u8 {
        return self.owner.get_data();
    }

    /// return immutable slice of the payload // TODO: get the icmp type and add base header size
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
                return 4;
            },
        }
    }

    /// Sets the payload of the ICMPLayer.
    /// Can be any ICMP type but commonly ICMP Echo Request/Reply is the type which has a payload
    pub fn set_payload(self: *ICMPLayer, payload: []const u8) !void {
        const current_payload_len = self.get_payload().len;

        const header_type_size = self.get_header_type_size();

        const full_header_size = BaseHeaderSize + header_type_size;

        var buf: []u8 = self.get_data()[full_header_size..];

        if (payload.len > current_payload_len) {
            const extend_len: usize = payload.len - current_payload_len;

            buf = try self.owner.extend_payload(full_header_size, extend_len);
        }

        if (current_payload_len > payload.len) {
            const shorten_len = current_payload_len - payload.len;

            const offset = full_header_size + payload.len;

            try self.owner.shorten_payload(offset, shorten_len);
            buf = self.get_data()[full_header_size..];
        }

        @memmove(buf, payload);
    }

    /// Don't use this.
    pub fn remove_payload(self: *ICMPLayer) !void {
        const payload_len = self.get_payload().len;
        if (payload_len > 0) {
            try self.owner.shorten_payload(self.get_data().len - payload_len, payload_len);
        }
    }

    pub fn get_type(self: *ICMPLayer) ICMPType {
        const hdr = self.get_immutable_header();
        return hdr.get_type();
    }

    pub fn set_type(self: *ICMPLayer, icmp_type: ICMPType) !void {
        var hdr = self.get_mutable_header();
        hdr.set_type(icmp_type);

        switch (icmp_type) {
            .TimestampRequest, .TimestampReply => {
                _ = try self.owner.extend_payload(ICMPHeaderSize, @sizeOf(ICMPTimestamp));
            },
            .AddressMaskRequest, .AddressMaskReply => {
                _ = try self.owner.extend_payload(ICMPHeaderSize, @sizeOf(ICMPAddrMask));
            },
            .SourceQuench => {
                _ = try self.owner.extend_payload(ICMPHeaderSize, @sizeOf(ICMPSourceQuench));
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
