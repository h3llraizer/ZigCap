const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;
const panic = std.debug.panic;

const IPProtocol = @import("ProtocolHelpers.zig").IPProtocol;

const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;

const LayerError = @import("ProtocolHelpers.zig").LayerError;

const Packet = @import("Packet.zig");

const UDP = @import("UDP.zig");
const TCP = @import("TCP.zig");
const ICMP = @import("ICMP.zig");

const LayerOwner = @import("Layer.zig").LayerOwner;

const LayerIface = @import("LayerIface.zig").LayerIface;

const ApplicationLayer = @import("GenericLayer.zig").ApplicationLayer;

const RawData = @import("RawData.zig").RawData;

pub const MaxHeaderLength = 60; //IPv4MinHeader Length
pub const MinHeaderLength = 20;

// Use extern struct for exact 20-byte layout (standard IPv4 header)
pub const IPv4Header = extern struct {
    version_ihl: u8 = 0x45, // Default to version 4, IHL 5
    dscp_ecn: u8 = 0,
    total_length: u16 = 0,
    identification: u16 = 0,
    flags_fragment: u16 = 0,
    ttl: u8 = 64, // Default TTL
    protocol: u8 = 0,
    checksum: u16 = 0,
    src_ip: [4]u8,
    dst_ip: [4]u8,

    comptime {
        if (@sizeOf(IPv4Header) != 20) {
            @compileError("IPv4Header must be 20 bytes, got " ++ @typeName(@sizeOf(IPv4Header)));
        }
    }

    pub fn init_default() IPv4Header {
        return .{
            .version_ihl = 0x45,
            .dscp_ecn = 0,
            .total_length = 0,
            .identification = 0,
            .flags_fragment = 0,
            .ttl = 64,
            .protocol = 0,
            .checksum = 0,
            .src_ip = [_]u8{0} ** 4,
            .dst_ip = [_]u8{0} ** 4,
        };
    }

    pub fn get_ihl(self: *const IPv4Header) u8 {
        //            const ip_version = self.version_ihl >> 4;
        const hdr_len = (self.version_ihl & 0x0F) * 4;

        return hdr_len;
    }

    pub fn calculate_checksum(self: *IPv4Header) void {
        // Save the original checksum field
        const old_checksum = self.checksum;
        self.checksum = 0;

        var sum: u32 = 0;
        const words = @as([*]const u16, @ptrCast(self));

        // Sum all 16-bit words
        for (0..@sizeOf(IPv4Header) / 2) |i| {
            sum += words[i];
        }

        // Fold the sum to 16 bits
        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // Take one's complement and store
        self.checksum = ~@as(u16, @intCast(sum));

        // If the checksum calculation resulted in 0, the RFC says to use 0xFFFF
        if (self.checksum == 0) {
            self.checksum = 0xFFFF;
        }

        _ = old_checksum;
    }
};

// IPv4 Option Types
pub const IPOptionType = enum(u8) {
    EndOfOptions = 0,
    NoOperation = 1,
    Security = 2,
    LooseSourceRoute = 3,
    Timestamp = 4,
    ExtendedSecurity = 5,
    CommercialSecurity = 6,
    RecordRoute = 7,
    StreamID = 8,
    StrictSourceRoute = 9,
    ExperimentalMeasurement = 10,
    MTUProbe = 11,
    MTUReply = 12,
    FlowControl = 13,
    AccessControl = 14,
    ExtendedInternet = 15,
    RouterAlert = 20,
    SelectiveRedirect = 21,
    DynamicPacketState = 23,
    ExperimentalFlowControl = 25,
    QuickStart = 26,
    RFC3692 = 30,
    End,
};

pub const IPOption = struct {
    type: IPOptionType,
    length: u8,
    data: []u8,

    pub fn init(opt_type: IPOptionType, data: []u8) !IPOption {
        const len = 2 + data.len; // type + length + data
        if (len > 40) return error.OptionTooLong;
        return IPOption{
            .type = opt_type,
            .length = @as(u8, @intCast(len)),
            .data = data,
        };
    }

    pub fn initNoData(opt_type: IPOptionType) IPOption {
        return IPOption{
            .type = opt_type,
            .length = 1, // type only (NoOperation or EndOfOptions)
            .data = &[_]u8{},
        };
    }

    pub fn toBytes(self: IPOption) []u8 {
        var bytes = std.ArrayList(u8).init(std.heap.page_allocator);
        defer bytes.deinit();

        bytes.append(@intFromEnum(self.type)) catch unreachable;

        if (self.length > 1) {
            bytes.append(self.length) catch unreachable;
            bytes.appendSlice(self.data) catch unreachable;
        }

        return bytes.toOwnedSlice() catch &[_]u8{};
    }
};

pub const IPv4Layer = struct {
    owner: LayerOwner,
    const Protocol = tcp_ip_protocol.ipv4;

    pub fn init(owner: LayerOwner) LayerError!IPv4Layer {
        switch (owner) {
            .packet_layer => {
                return IPv4Layer{
                    .owner = owner,
                };
            },
            .owned_buffer => {
                var self = IPv4Layer{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < MinHeaderLength) {
                    const ipv4_data = try self.owner.owned_buffer.extend(buffer_len, MinHeaderLength);

                    @memset(ipv4_data, 0);

                    var header = IPv4Header.init_default();

                    @memcpy(ipv4_data[0..MinHeaderLength], std.mem.asBytes(&header));
                }

                return self;
            },
        }
    }

    pub fn zero_hdr() []u8 {
        var header = IPv4Header.init_default();
        var data: []u8 = undefined;
        @memcpy(data[0..MinHeaderLength], std.mem.asBytes(&header));
        return data;
    }

    pub fn set_src_ip(self: *IPv4Layer, src_ip: IPv4Address) void {
        var hdr = self.get_mutable_header();
        hdr.src_ip = src_ip.array;
    }

    pub fn set_dst_ip(self: *IPv4Layer, dst_ip: IPv4Address) void {
        var hdr = self.get_mutable_header();
        hdr.dst_ip = dst_ip.array;
    }

    pub fn get_src_ip(self: *IPv4Layer) IPv4Address {
        const hdr = self.get_immutable_header();
        return IPv4Address.init_from_array(hdr.src_ip);
    }

    pub fn get_dst_ip(self: *IPv4Layer) IPv4Address {
        const hdr = self.get_immutable_header();
        return IPv4Address.init_from_array(hdr.dst_ip);
    }

    /// get slice of data (hdr+payload)
    pub fn get_data(self: *const IPv4Layer) []u8 {
        switch (self.owner) {
            .packet_layer => |layer| {
                return layer.get_data(); // Layer in packet - it might be mutable or immutable
            },
            .owned_buffer => {
                return self.owner.owned_buffer.buffer.items; // standalone layer - it is mutable by default
            },
        }
    }

    pub fn get_next_layer_type(self: *const IPv4Layer, layer: *Packet.Layer) !?LayerIface {
        const data = self.get_data();

        if (data.len < @sizeOf(IPv4Header)) return error.BufferTooSmall;

        //       const alignment = @alignOf(IPv4Header);
        //       const addr = @intFromPtr(data.ptr);
        //
        //       if (addr % alignment != 0) {
        //           return error.MisalignedBuffer;
        //       }
        //       const aligned_ptr: [*]align(@alignOf(IPv4Header)) u8 = @alignCast(data.ptr);
        const hdr = self.get_immutable_header();

        const ip_protocol = std.meta.intToEnum(IPProtocol, hdr.protocol) catch {
            return try LayerIface.init(ApplicationLayer, LayerOwner{ .packet_layer = layer });
        };

        switch (ip_protocol) {
            IPProtocol.ICMP => {
                return try LayerIface.init(ICMP.ICMPLayer, LayerOwner{ .packet_layer = layer });
            },

            IPProtocol.TCP => {
                return try LayerIface.init(TCP.TCPLayer, LayerOwner{ .packet_layer = layer });
            },
            IPProtocol.UDP => {
                return try LayerIface.init(UDP.UDPLayer, LayerOwner{ .packet_layer = layer });
            },
        }
    }

    /// return mutable slice of the payload
    pub fn get_payload(self: *IPv4Layer) ?[]const u8 {
        const header_len = (self.get_immutable_header().version_ihl & 0x0F) * 4;

        const data = self.get_data();

        if (data.len > header_len) {
            return data[header_len..];
        } else {
            return null;
        }
    }

    pub fn get_options(self: *IPv4Layer) []const u8 {
        const hdr = self.get_immutable_header();
        const ihl = hdr.get_ihl();
        return self.get_data()[MinHeaderLength..ihl];
    }

    /// not yet fully implemented. will fail overtly or UB will occur
    pub fn add_option(self: *IPv4Layer, option: IPOption, allocator: Allocator) !void { // extend layer needs to be called if allocated in Packet
        const hdr = self.get_mutable_header();
        const current_ihl = hdr.get_ihl();
        const current_options_len = (current_ihl - 5) * 4;

        const new_option_bytes = option.toBytes();
        defer if (new_option_bytes.len > 0) allocator.free(new_option_bytes);

        const new_options_len = current_options_len + new_option_bytes.len;
        const new_ihl = 5 + (new_options_len + 3) / 4; // Round up to 4-byte boundary
        const new_header_len = new_ihl * 4;

        if (new_header_len > MaxHeaderLength) {
            return error.OptionsTooLong;
        }

        const data = self.get_data();

        // Reallocate buffer if needed
        if (data.len < new_header_len) {
            const new_data = try allocator.realloc(data, new_header_len); // need to call extend instead
            data = new_data;
        }

        // Copy new options
        @memcpy(data[MinHeaderLength + current_options_len ..][0..new_option_bytes.len], new_option_bytes);

        // Zero padding if needed
        if (new_options_len % 4 != 0) {
            const padding = 4 - (new_options_len % 4);
            @memset(data[MinHeaderLength + new_options_len ..][0..padding], 0);
        }

        // Update IHL in header
        hdr.set_ihl(@intCast(new_ihl)); // not yet implemented. will fail.

        // Update total length (must be updated by caller)
    }

    pub fn remove_options(self: *IPv4Layer) void {
        const hdr = self.get_mutable_header();
        hdr.set_ihl(5); // Reset to minimum
        // Options are now ignored (they remain in buffer but won't be used)
    }

    pub fn get_checksum(self: *IPv4Layer) u16 {
        const hdr = self.get_immutable_header();
        return std.mem.bigToNative(u16, hdr.checksum);
    }

    pub fn calculate_checksum(self: *IPv4Layer) void {
        var hdr = self.get_mutable_header();
        self.calculate_length();
        hdr.calculate_checksum();
    }

    pub fn calculate_length(self: *IPv4Layer) void {
        var hdr = self.get_mutable_header();
        const data = self.get_data();
        hdr.total_length = std.mem.nativeToBig(u16, @as(u16, @intCast(data.get_len())));
    }

    pub fn get_length(self: *IPv4Layer) u16 {
        const hdr = self.get_immutable_header();
        const total_length = hdr.total_length;
        return std.mem.nativeToBig(u16, @as(u16, @intCast(total_length))); // No byte swap
    }

    pub fn get_ttl(self: *IPv4Layer) u8 {
        const hdr = self.get_mutable_header();
        return hdr.ttl;
    }

    pub fn set_ttl(self: *IPv4Layer, ttl: u8) void {
        const hdr = self.get_mutable_header();
        hdr.ttl = ttl;
    }

    fn get_mutable_header(self: *const IPv4Layer) *IPv4Header {
        const data = self.get_data();
        const aligned_ptr: [*]align(@alignOf(IPv4Header)) u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    fn get_immutable_header(self: *const IPv4Layer) *const IPv4Header {
        const data: []const u8 = self.get_data();

        //        print("ipv4 data: {x}\n", .{data});

        if (data.len < MinHeaderLength) {
            panic("IPv4 data len ({}) less than IPv4HeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(IPv4Header)) const u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    /// caller must free the memory
    pub fn to_string(self: *IPv4Layer, allocator: Allocator) []const u8 {
        const hdr = self.get_immutable_header();

        const src_ip_str = self.get_src_ip().to_string(allocator) catch return "";
        defer allocator.free(src_ip_str);

        const dst_ip_str = self.get_dst_ip().to_string(allocator) catch return "";
        defer allocator.free(dst_ip_str);

        const version = (hdr.version_ihl >> 4);
        const ihl = (hdr.version_ihl & 0x0F);
        const dscp_ecn: u8 = hdr.dscp_ecn;

        const identification: u16 = std.mem.bigToNative(u16, hdr.identification);
        const flags_fragment: u16 = std.mem.bigToNative(u16, hdr.flags_fragment);
        const total_length: u16 = std.mem.bigToNative(u16, hdr.total_length);
        const checksum: u16 = std.mem.bigToNative(u16, hdr.checksum);

        const ttl: u8 = hdr.ttl;
        const protocol: u8 = hdr.protocol;

        return std.fmt.allocPrint(
            allocator,
            "IP : ver: {} ihl: {} src: {s} dst: {s} dscp_ecn: {} total_length: {} id: {} flags_frag: {} ttl: {} protocol: {} checksum: 0x{x:0>4}",
            .{
                version,
                ihl,
                src_ip_str,
                dst_ip_str,
                dscp_ecn,
                total_length,
                identification,
                flags_fragment,
                ttl,
                protocol,
                checksum,
            },
        ) catch return "";
    }

    pub fn get_transport_type(self: *IPv4Layer) !IPProtocol {
        const hdr = self.get_immutable_header();
        return try std.meta.intToEnum(IPProtocol, hdr.protocol);
    }

    pub fn set_transport_type(self: *IPv4Layer, protocol: IPProtocol) void {
        var hdr = self.get_mutable_header();
        hdr.protocol = @intFromEnum(protocol);
    }

    pub fn get_protocol(self: *IPv4Layer) tcp_ip_protocol {
        _ = self;
        return IPv4Layer.Protocol;
    }

    pub fn deinit(self: *IPv4Layer, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
        allocator.destroy(self);
    }
};

pub const IPv4Address = struct {
    array: [4]u8,

    pub const Error = error{
        InvalidFormat,
        TooManyOctets,
        TooFewOctets,
        OctetOverflow,
        NonDigit,
    };

    pub fn init_from_array(raw: [4]u8) IPv4Address {
        return .{ .array = raw };
    }

    pub fn init_from_u32(value: u32) IPv4Address {
        return .{
            .array = .{
                @as(u8, @truncate(value >> 24)),
                @as(u8, @truncate(value >> 16)),
                @as(u8, @truncate(value >> 8)),
                @as(u8, @truncate(value)),
            },
        };
    }

    pub fn to_u32(self: IPv4Address) u32 {
        return (@as(u32, self.array[0]) << 24) |
            (@as(u32, self.array[1]) << 16) |
            (@as(u32, self.array[2]) << 8) |
            (@as(u32, self.array[3]));
    }

    pub fn init_from_string(str: []const u8) !IPv4Address {
        var octets: [4]u8 = undefined;

        var oct_index: usize = 0;
        var cur_value: u16 = 0;
        var have_digit = false;

        for (str) |c| {
            if (c == '.') {
                if (!have_digit) return Error.InvalidFormat;
                if (oct_index >= 4) return Error.TooManyOctets;

                octets[oct_index] = @intCast(cur_value);
                oct_index += 1;

                cur_value = 0;
                have_digit = false;
                continue;
            }

            if (c < '0' or c > '9')
                return Error.NonDigit;

            have_digit = true;
            cur_value = cur_value * 10 + (c - '0');

            if (cur_value > 255)
                return Error.OctetOverflow;
        }

        if (!have_digit) return Error.InvalidFormat;
        if (oct_index != 3) return Error.TooFewOctets;

        octets[oct_index] = @intCast(cur_value);

        return .{ .array = octets };
    }

    pub fn to_string(self: IPv4Address, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(
            allocator,
            "{d}.{d}.{d}.{d}",
            .{
                self.array[0],
                self.array[1],
                self.array[2],
                self.array[3],
            },
        );
    }
};
