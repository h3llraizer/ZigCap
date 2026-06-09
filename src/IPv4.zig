const std = @import("std");
const ProtocolEnums = @import("ProtocolEnums.zig");
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;
const Packet = @import("Packet.zig");
const UDP = @import("UDP.zig");
const TCP = @import("TCP.zig");
const ICMP = @import("ICMP.zig");
const LayerOwner = @import("Owner.zig").LayerOwner;
const TLVOwner = @import("Owner.zig").TLVOwner;
const LayerIface = @import("LayerIface.zig").LayerIface;
const init_layer = @import("LayerIface.zig").init_layer;

const ApplicationLayer = @import("GenericLayer.zig").ApplicationLayer;
pub const IPv4_Options = @import("IPv4_Options.zig");
pub const IPv4Options = IPv4_Options.IPv4Options;
pub const IPv4Option = IPv4_Options.IPv4Option;
pub const IPOptionType = IPv4_Options.IPOptionType;

const print = std.debug.print;
const Allocator = std.mem.Allocator;
const panic = std.debug.panic;

const LayerError = ProtocolEnums.LayerError;
const IPProtocol = ProtocolEnums.IPProtocol;

pub const MaxHeaderLength = 60; //IPv4MinHeader Length
pub const MinHeaderLength = 20; //IPv4 Max Header Length
pub const HeaderAlignment = 4;

pub const default_hdr = IPv4Header{
    .version_ihl = 0x45,
    .dscp_ecn = 0,
    .total_length = std.mem.nativeToBig(u16, MinHeaderLength),
    .identification = 0,
    .flags_fragment = 0,
    .ttl = 64,
    .protocol = 0,
    .checksum = 0,
    .src_ip = [_]u8{0} ** 4,
    .dst_ip = [_]u8{0} ** 4,
};

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
        return default_hdr;
    }

    /// returns the Internet-Header-Length from the version_ihl.
    /// To get the header length, multiply the returned value by 4. e.g. hdr.get_ihl() * 4
    pub fn get_ihl(self: *const IPv4Header) u8 {
        const hdr_len = (self.version_ihl & 0x0F);

        return hdr_len;
    }

    pub fn set_ihl(self: *IPv4Header, len: u8) void {
        // len should be the header length in bytes (20-60)
        const ihl_value = len / 4; // Convert to 32-bit word count
        // Preserve the high 4 bits (version), replace low 4 bits with IHLself
        self.version_ihl = (self.version_ihl & 0xF0) | (ihl_value & 0x0F);
    }

    pub fn get_dst_ip(self: *const IPv4Header) IPv4Address {
        return IPv4Address.init_from_array(self.dst_ip);
    }

    pub fn set_dst_ip(self: *IPv4Header, dst_ip: IPv4Address) void {
        self.dst_ip = dst_ip.array;
    }

    pub fn get_src_ip(self: *const IPv4Header) IPv4Address {
        return IPv4Address.init_from_array(self.src_ip);
    }

    pub fn set_src_ip(self: *IPv4Header, src_ip: IPv4Address) void {
        self.src_ip = src_ip.array;
    }

    /// gets length from the IPv4 header - not gaurenteed to be accurate (malformed packet / incomplete layers etc)
    /// if unsure, call the IPv4Layer's calculate_length method which will set the correct length in the header
    pub fn get_length(self: *const IPv4Header) u16 {
        const total_length = self.total_length;
        return std.mem.nativeToBig(u16, @as(u16, @intCast(total_length)));
    }

    pub fn set_length(self: *IPv4Header, length: u16) void {
        self.total_length = @byteSwap(length);
    }

    pub fn get_ttl(self: *const IPv4Header) u8 {
        return self.ttl;
    }

    pub fn set_ttl(self: *IPv4Header, ttl: u8) void {
        self.ttl = ttl;
    }

    /// returns the checksum of the IPv4 header in native endian.
    pub fn get_checksum(self: *const IPv4Header) u16 {
        return std.mem.bigToNative(u16, self.checksum);
    }

    /// the ipv4 header should be provided as a const slice and must ensure aligned to 2 bytes
    pub fn calculate_checksum(self: *IPv4Header, full_header: []const u8) void {
        // Save the original checksum field
        const old_checksum = self.checksum;
        self.checksum = 0;

        var sum: u32 = 0;
        const words = @as([*]const u16, @ptrCast(@alignCast(full_header.ptr)));

        const word_count = full_header.len / 2;

        for (0..word_count) |i| {
            sum += std.mem.bigToNative(u16, words[i]);
        }

        // Fold the sum to 16 bits
        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // Take one's complement and store
        self.checksum = @byteSwap(~@as(u16, @intCast(sum)));

        // If the checksum calculation resulted in 0, the RFC says to use 0xFFFF
        if (self.checksum == 0) {
            self.checksum = 0xFFFF;
        }

        _ = old_checksum;
    }

    pub fn get_identification(self: *const IPv4Header) u16 {
        return @byteSwap(self.identification);
    }

    pub fn set_identification(self: *IPv4Header, id: u16) void {
        self.identification = @byteSwap(id);
    }

    pub fn get_flags_fragment(self: *const IPv4Header) u16 {
        return @byteSwap(self.flags_fragment);
    }

    pub fn set_flags_fragment(self: *IPv4Header, flags_frag: u16) void {
        self.flags_fragment = @byteSwap(flags_frag);
    }

    pub fn get_protocol(self: *const IPv4Header) u8 {
        return self.protocol;
    }

    pub fn set_protocol(self: *IPv4Header, proto: IPProtocol) void {
        self.protocol = @intFromEnum(proto);
    }

    pub fn to_string(self: *const IPv4Header, allocator: Allocator) ![]const u8 {
        const vihl = self.get_ihl();
        const dcsp = self.dscp_ecn;
        const total_len = self.get_length();
        const id = self.get_identification();
        const flags = self.get_flags_fragment();
        const ttl = self.ttl;
        const protocol: IPProtocol = @enumFromInt(self.protocol);
        const checksum = self.get_checksum();

        const src_ip_str = self.get_src_ip().to_string(allocator) catch return "";
        defer allocator.free(src_ip_str);

        const dst_ip_str = self.get_dst_ip().to_string(allocator) catch return "";
        defer allocator.free(dst_ip_str);

        return std.fmt.allocPrint(allocator, "IPv4 Header : vihl: {} dcsp: {} total_len: {} id: {} flags: {} ttl: {} protocol: {any} checksum: {} src: {s} dst: {s}\n", .{
            vihl,
            dcsp,
            total_len,
            id,
            flags,
            ttl,
            protocol,
            checksum,
            src_ip_str,
            dst_ip_str,
        }) catch {
            return "";
        };
    }
};

/// IPv4 options can be added one at a time and removed all at once.
pub const IPv4Layer = struct {
    owner: LayerOwner,

    pub fn init(owner: LayerOwner) LayerError!IPv4Layer {
        return try init_layer(IPv4Layer, owner, IPv4Header, default_hdr);
    }

    /// use this when you want to zero the header to default values.
    /// see IPv4Header.init_default() to check what the default values will be
    pub fn zero_hdr(self: *IPv4Layer) Allocator.Error!void {
        var header = IPv4Header.init_default();
        try self.remove_all_options();
        const data = self.get_data();
        const hdr_len = self.get_header_len();
        const hdr_data = data[0..hdr_len];
        @memcpy(hdr_data[0..MinHeaderLength], std.mem.asBytes(&header));
    }

    /// returns mutable slice of data (hdr+payload).
    /// this will likely be made private in future to avoid accidental mutations
    pub fn get_data(self: *const IPv4Layer) []u8 {
        return self.owner.get_data();
    }

    /// return immutable slice of the payload
    pub fn get_payload(self: *IPv4Layer) []const u8 {
        const data = self.get_data();

        const hdr_len = self.get_header_len();

        if (data.len > hdr_len) {
            return data[hdr_len..];
        } else {
            return "";
        }
    }

    fn get_opt_buf(self: *IPv4Layer) []u8 {
        const header_len = self.get_immutable_header().get_ihl() * 4;
        return self.get_data()[MinHeaderLength..header_len];
    }

    // might remove this
    pub fn get_first_op(self: *IPv4Layer) ?IPv4Option {
        const ops_buf = self.get_opt_buf();
        const options_list = std.enums.values(IPOptionType)[1..];
        for (options_list) |option| {
            if (@intFromEnum(option) == ops_buf[0]) {
                return IPv4Option.init(
                    option,
                    TLVOwner{ .layer = &self.owner },
                    null,
                    null,
                );
            }
        }

        return null;
    }

    /// Returns LinkedList of IPv4 Options.
    /// Data is retrieved and made directly to the owning layer.
    /// Caller must deinit the LinkedList - does not destroy options data
    pub fn get_options(self: *IPv4Layer, allocator: Allocator) Allocator.Error!?IPv4Options {
        const ops_buf = self.get_opt_buf();

        if (ops_buf.len == 0) {
            return null;
        }

        const options_list = std.enums.values(IPOptionType)[1..];

        var options: IPv4Options = .{};

        var cur: ?*IPv4Option = null;

        var offset: usize = 0;

        var matched = false;

        while (offset < ops_buf.len) { // was ops_buf.len - 1
            matched = false;
            for (options_list) |option| {
                if (@intFromEnum(option) == ops_buf[offset]) {
                    const length: usize = @intCast(ops_buf[offset + 1]);
                    const opt = try allocator.create(IPv4Option);

                    opt.* = IPv4Option.init(
                        option,
                        TLVOwner{ .layer = &self.owner },
                        null,
                        null,
                    );

                    if (options.first == null) {
                        options.first = opt;
                    }

                    if (cur) |cur_opt| {
                        cur_opt.set_next_opt(opt);
                        opt.set_prev_opt(cur_opt);
                    }

                    cur = opt;

                    matched = true;
                    offset += length;
                    break;
                }
            }

            if (!matched) {
                offset += 1;
            }
        }

        options.last = cur;

        return options;
    }

    fn check_padding(self: *IPv4Layer) usize {
        const ops_buf = self.get_opt_buf();

        if (ops_buf.len == 0) {
            return 0;
        }

        var offset: usize = 0;

        while (offset < ops_buf.len) {
            const option_type = ops_buf[offset];

            // End of Option List
            if (option_type == 0) {
                break;
            }

            // No Operation
            if (option_type == 1) {
                offset += 1;
                continue;
            }

            // Need at least type + length
            if (offset + 1 >= ops_buf.len) {
                return 0;
            }

            const option_len = ops_buf[offset + 1];

            if (option_len < 2) {
                return 0;
            }

            offset += option_len;
        }

        return ops_buf.len - offset;
    }

    pub fn add_option(self: *IPv4Layer, option: *IPv4Option) Allocator.Error!void {
        const new_option_bytes = option.get_data();

        const new_option_bytes_len: usize = new_option_bytes.len;

        const current_header_len: u8 = self.get_immutable_header().get_ihl() * 4;

        const padding_len: usize = self.check_padding(); // get number of pad bytes that are currently added

        var new_header_len: usize = (current_header_len - padding_len) + @as(usize, @intCast(new_option_bytes_len));

        var pad_required = if (new_header_len % HeaderAlignment == 0) 0 else HeaderAlignment - (new_header_len % HeaderAlignment);

        const new_ihl: u8 = @intCast(new_header_len + pad_required);

        if (pad_required == padding_len) {
            pad_required = 0;
        }

        new_header_len += pad_required;

        const offset: usize = @intCast(current_header_len - padding_len);

        const extend_len: usize = new_option_bytes_len + pad_required;

        const ops_buf = try self.owner.extend_layer(
            offset,
            extend_len,
        );

        @memmove(ops_buf[0..new_option_bytes_len], new_option_bytes);

        self.get_mutable_header().set_ihl(@intCast(new_ihl));
        self.get_mutable_header().set_length(@intCast(self.get_data().len));
    }

    pub fn remove_option(self: *IPv4Layer, option: *IPv4Option, allocator: Allocator) Allocator.Error!void {
        const opt_buf = self.get_opt_buf();

        const opt_data = option.get_data();
        const opt_len = option.get_length();

        const hdr_len = self.get_immutable_header().get_ihl() * 4;

        const total_length = self.get_immutable_header().get_length();

        _ = total_length;

        const cur_pad_len = self.check_padding();

        const offset = std.mem.indexOf(u8, opt_buf, opt_data) orelse {
            return;
        };

        try self.owner.shorten_layer(MinHeaderLength + offset, opt_len);

        var new_header_len = hdr_len - opt_len;

        const pad_required = if ((new_header_len - cur_pad_len) % HeaderAlignment == 0) 0 else HeaderAlignment - ((new_header_len - cur_pad_len) % HeaderAlignment);

        if (pad_required > 0) {
            _ = try self.owner.extend_layer( // this can be discarded because its 0'd (NOP'd) by default
                new_header_len - 1, // - 1 added here because without it is causing proceeding layer in packet to be mutated
                pad_required,
            );

            new_header_len += pad_required;
        } else {
            try self.owner.shorten_layer(
                new_header_len - 1, // - 1 added here because without it is causing proceeding layer in packet to be mutated
                cur_pad_len,
            );

            new_header_len -= cur_pad_len;
        }

        self.get_mutable_header().set_ihl(@intCast(new_header_len));
        self.get_mutable_header().set_length(@intCast(self.get_data().len));

        const next = option.get_next();
        const prev = option.get_prev();

        if (next) |next_opt| {
            if (prev) |prev_opt| {
                prev_opt.set_next_opt(next_opt);
                next_opt.set_prev_opt(prev_opt);
            }
        }

        allocator.destroy(option);
    }

    pub fn remove_all_options(self: *IPv4Layer) Allocator.Error!void {
        const header_len: usize = @intCast(self.get_header_len());

        const ops_len = header_len - MinHeaderLength;

        try self.owner.shorten_layer(MinHeaderLength, ops_len);

        const new_hdr = self.get_mutable_header(); // get header again because ptr to to previously initialised one got mutated
        new_hdr.set_ihl(@intCast(MinHeaderLength));
        new_hdr.set_length(@intCast(self.get_data().len));
    }

    /// calculates checksum by setting ihl (version bit) to header len
    /// calculates total length (ipv4.total_length)
    /// calls the checksum calculation function in the IPv4 header (see IPv4Header.calculate_checksum())
    pub fn validate_layer(self: *IPv4Layer) void {
        const hdr_len = self.get_header_len();

        self.calculate_length();

        const new_hdr = self.get_mutable_header();

        new_hdr.calculate_checksum(self.get_data()[0..hdr_len]);

        if (self.owner.is_packet_owned()) {
            if (self.owner.packet_layer.next_layer) |next_layer| {
                const protocol = next_layer.layer_iface.get_protocol();
                const hdr = self.get_mutable_header();
                switch (protocol) {
                    .icmp => hdr.set_protocol(.ICMP),
                    .tcp => hdr.set_protocol(.TCP),
                    .udp => hdr.set_protocol(.UDP),
                    .igmp_v1, .igmp_v2, .igmp_v3 => hdr.set_protocol(.IGMP),
                    else => {},
                }
            }
        }
    }

    /// takes total data (hdr+payload) length and sets the IPv4 header's total length field to that result
    pub fn calculate_length(self: *IPv4Layer) void {
        var hdr = self.get_mutable_header();
        const data = self.get_data();
        const total_length = @as(u16, @intCast(data.len));
        hdr.set_length(total_length);
    }

    /// for Packet owned IPv4Layer: gets length of total data (hdr+payload) and subtracts the payload
    /// for self owned layer: takes total length of data (payload not included because it doesnt't have one)
    pub fn get_header_len(self: *IPv4Layer) usize {
        const hdr = self.get_immutable_header();

        //return hdr.get_length();
        const hdr_length: usize = @intCast(hdr.get_ihl() * 4);
        const data = self.get_data();

        std.debug.assert(data.len >= hdr_length);

        return hdr_length;
    }

    pub fn get_mutable_header(self: *const IPv4Layer) *IPv4Header {
        const data = self.get_data();

        if (data.len < MinHeaderLength) {
            panic("IPv4 data len ({}) less than IPv4HeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(IPv4Header)) u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn get_immutable_header(self: *const IPv4Layer) *const IPv4Header {
        const data: []const u8 = self.get_data();

        if (data.len < MinHeaderLength) {
            panic("IPv4 data len ({}) less than IPv4HeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(IPv4Header)) const u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn get_next_layer_type(self: *const IPv4Layer, layer: *Packet.Layer) LayerError!?LayerIface {
        const data = self.get_data();

        if (data.len < @sizeOf(IPv4Header)) return error.BufferTooSmall;

        const hdr = self.get_immutable_header();

        const ip_protocol = std.enums.fromInt(IPProtocol, hdr.protocol) orelse {
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
            // TODO: handle IGMP - peak the buffer to find the version
            else => {
                return try LayerIface.init(ApplicationLayer, LayerOwner{ .packet_layer = layer });
            },
        }
    }

    /// caller must free the memory
    pub fn to_string(self: *IPv4Layer, allocator: Allocator) []const u8 {
        const hdr = self.get_immutable_header();

        const src_ip_str = hdr.get_src_ip().to_string(allocator) catch return "";
        defer allocator.free(src_ip_str);

        const dst_ip_str = hdr.get_dst_ip().to_string(allocator) catch return "";
        defer allocator.free(dst_ip_str);

        return std.fmt.allocPrint(
            allocator,
            "IPv4 Layer : src: {s} dst: {s}\n",
            .{ src_ip_str, dst_ip_str },
        ) catch {
            return "";
        };
    }

    /// get the IP protocol. E.g. TCP, UDP, ICMP
    pub fn get_ip_proto(self: *IPv4Layer) std.meta.IntToEnumError!IPProtocol {
        const hdr = self.get_immutable_header();
        return try std.meta.intToEnum(IPProtocol, hdr.protocol);
    }

    // set the IP protocol. E.g. TCP, UDP, ICMP
    pub fn set_ip_proto(self: *IPv4Layer, protocol: IPProtocol) void {
        var hdr = self.get_mutable_header();
        hdr.protocol = @intFromEnum(protocol);
    }

    pub fn get_protocol(self: *IPv4Layer) tcp_ip_protocol {
        _ = self;
        return tcp_ip_protocol.ipv4;
    }

    pub fn deinit(self: *IPv4Layer) void {
        self.owner.deinit();
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

    pub fn init_from_string(str: []const u8) IPv4Address.Error!IPv4Address {
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

    pub fn to_string(self: IPv4Address, allocator: Allocator) Allocator.Error![]u8 {
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
