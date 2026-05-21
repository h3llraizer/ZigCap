const std = @import("std");
const ProtocolEnums = @import("ProtocolEnums.zig");
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;
const Packet = @import("Packet.zig");
const UDP = @import("UDP.zig");
const TCP = @import("TCP.zig");
const ICMP = @import("ICMP.zig");
const LayerOwner = @import("Layer.zig").LayerOwner;
const TLVOwner = @import("Layer.zig").TLVOwner;
const LayerIface = @import("LayerIface.zig").LayerIface;
const ApplicationLayer = @import("GenericLayer.zig").ApplicationLayer;

const print = std.debug.print;
const Allocator = std.mem.Allocator;
const panic = std.debug.panic;

const LayerError = ProtocolEnums.LayerError;
const IPProtocol = ProtocolEnums.IPProtocol;

pub const IPv4Options = @import("IPv4_Options.zig");
pub const IPv4Option = IPv4Options.IPv4Option;

pub const MaxHeaderLength = 60; //IPv4MinHeader Length
pub const MinHeaderLength = 20;
const HeaderAlignment = 4;

const default_hdr = IPv4Header{
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
    /// if insure, call the IPv4Layer's calculate_length method which will set the correct length in the header
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

    /// use this when you want to zero the header to default values.
    /// see IPv4Header.init_default() to check what the default values will be
    pub fn zero_hdr(self: *IPv4Layer) !void {
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

    /// calls get_payload and returns the length.
    /// owned_buffer IPv4 layer will always return 0
    pub fn get_payload_len(self: *IPv4Layer) usize {
        return self.get_payload().len;
    }

    fn get_options(self: *IPv4Layer) []u8 {
        const header_len = self.get_immutable_header().get_ihl() * 4;
        return self.get_data()[MinHeaderLength..header_len];
    }

    pub fn get_first_op(self: *IPv4Layer) ?IPv4Option {
        const ops_buf = self.get_options();
        const options_list = std.enums.values(IPOptionType)[1..];
        for (options_list) |option| {
            if (@intFromEnum(option) == ops_buf[0]) {
                const length: usize = @intCast(ops_buf[1]);
                return IPv4Option.init(
                    option,
                    TLVOwner{ .layer = LayerIface{ .ipv4Layer = self.* } },
                    length,
                    null,
                    null,
                );
            }
        }

        return null;
    }

    pub fn get_ip_opts(self: *IPv4Layer, allocator: Allocator) !?*IPv4Option {
        const ops_buf = self.get_options();

        if (ops_buf.len == 0) {
            return null;
        }

        const options_list = std.enums.values(IPOptionType)[1..];

        var cur: ?*IPv4Option = null;

        var offset: usize = 0;

        while (offset < ops_buf.len - 1) {
            for (options_list) |option| {
                if (@intFromEnum(option) == ops_buf[0]) {
                    const length: usize = @intCast(ops_buf[1]);
                    const opt = try allocator.create(IPv4Option);

                    opt.* = IPv4Option.init(
                        option,
                        TLVOwner{ .layer = LayerIface{ .ipv4Layer = self.* } },
                        length,
                        null,
                        null,
                    );

                    if (cur) |cur_opt| {
                        cur_opt.set_next_opt(opt);
                        opt.set_prev_opt(cur_opt);
                        cur = opt;
                    } else {
                        cur = opt;
                    }

                    offset += length;
                    continue;
                }
            }

            offset += 1;
        }

        return cur;
    }

    fn check_pad(self: *IPv4Layer) ?usize {
        const ops_buf = self.get_options();

        if (ops_buf.len == 0) {
            return null;
        }

        const options_list = std.enums.values(IPOptionType);

        var offset: usize = 0;
        var op_type_found: bool = false;
        var length_byte_found: bool = false;
        var last_length: usize = 0;

        while (offset < ops_buf.len - 1) {
            if (op_type_found == false) {
                for (options_list) |option| { // TODO: make this comptime
                    if (@intFromEnum(option) == ops_buf[offset]) {
                        op_type_found = true;
                        offset += 1;

                        if (IPOptionType.requires_ptr_byte(option)) {
                            if (offset + 1 <= ops_buf.len) {
                                offset += 1;
                            }
                        }

                        const op_len: usize = @intCast(ops_buf[offset]);

                        if (op_len <= ops_buf.len) {
                            length_byte_found = true;
                            last_length = offset;

                            offset += op_len;
                        }
                    }
                }
            }

            if (op_type_found == true and length_byte_found == true) {
                op_type_found = false;
                length_byte_found = false;
                continue;
            }

            offset += 1; // op-byte wasn't found. Increment offset by 1
        }

        if (last_length != 0) {
            const pad_bytes = ops_buf.len - last_length;
            return pad_bytes;
        }

        return null;
    }

    pub fn add_option(self: *IPv4Layer, option: *IPv4Option) !void {
        const new_option_bytes = option.get_data();

        print("new_option_bytes: {x}\n", .{new_option_bytes});

        const new_option_bytes_len: usize = new_option_bytes.len;

        print("new_option_bytes_len: {}\n", .{new_option_bytes_len});

        const current_ihl: u8 = self.get_immutable_header().get_ihl();

        const current_header_len: u8 = current_ihl * 4;

        var pad_bytes: usize = 0;

        if (self.check_pad()) |pad| {
            pad_bytes = pad;
        }

        var new_header_len: usize = current_header_len + @as(usize, @intCast(new_option_bytes_len));

        print("new_header_len: {}\n", .{new_header_len});

        const pad_required = if (new_header_len % HeaderAlignment == 0) 0 else HeaderAlignment - (new_header_len % HeaderAlignment);

        print("pad_required: {}\n", .{pad_required});

        new_header_len += pad_required;

        const ops_buf = try self.owner.extend_payload(
            @intCast(current_header_len),
            new_option_bytes_len + pad_required,
        );

        @memmove(ops_buf[0..new_option_bytes_len], new_option_bytes);

        self.get_mutable_header().set_ihl(@intCast(new_header_len));
        self.get_mutable_header().set_length(@intCast(self.get_data().len));
    }

    pub fn remove_all_options(self: *IPv4Layer) !void {
        const header_len: usize = @intCast(self.get_header_len());

        const ops_len = header_len - MinHeaderLength;

        try self.owner.shorten_payload(MinHeaderLength, ops_len);

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

    pub fn get_next_layer_type(self: *const IPv4Layer, layer: *Packet.Layer) !?LayerIface {
        const data = self.get_data();

        if (data.len < @sizeOf(IPv4Header)) return error.BufferTooSmall;

        const hdr = self.get_immutable_header();

        const ip_protocol = std.enums.fromInt(IPProtocol, hdr.protocol) orelse {
            print("unknown protocol: {x}\n", .{hdr.protocol});
            print("src: {any} dst: {any}\n", .{ hdr.get_src_ip(), hdr.get_dst_ip() });
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
    pub fn get_ip_proto(self: *IPv4Layer) !IPProtocol {
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

// TODO: implement helpers for all of these and unit test them
// Security (130) - length 11 bytes (type + len + 9 data)
// Example data: all zeros (unclassified)
//&[_]u8{130, 11, 0,0,0,0,0,0,0,0,0}

// LooseSourceRoute (131) - example: route through 192.0.2.1 and 192.0.2.2
// length = 3 + (n * 4) where n=2 → 11 bytes
//&[_]u8{131, 11, 4, 192,0,2,1, 192,0,2,2}
// (3rd byte = pointer to next addr, starts at 4)

// Timestamp (68) - length 4+ bytes, example: overflow=0, flags=1 (timestamp only)
//&[_]u8{68, 4, 0, 1}

// ExtendedSecurity (133) - length 6 (example minimal data)
//&[_]u8{133, 6, 0,0,0,0}

// CommercialSecurity (134) - length 6 (example minimal data)
//&[_]u8{134, 6, 0,0,0,0}

// RecordRoute (7) - example: pointer=4, space for 1 IP (4 bytes)
//&[_]u8{7, 8, 4, 0,0,0,0}

// StreamID (136) - length 4 (type + len + 2-byte stream ID)
//&[_]u8{136, 4, 0x12, 0x34}

// StrictSourceRoute (137) - same format as LSRR, example: 192.0.2.1
//&[_]u8{137, 8, 4, 192,0,2,1}

// ExperimentalMeasurement (10) - length 4 (example data 0x01 0x02)
//&[_]u8{10, 4, 0x01, 0x02}

// MTUProbe (11) - length 4 (example 2-byte probe value)
//&[_]u8{11, 4, 0x00, 0x40}

// MTUReply (12) - length 4 (example 2-byte MTU value 1500)
//&[_]u8{12, 4, 0x05, 0xDC}

// ExperimentalFlowControl (205) - length 4 (example data)
//&[_]u8{205, 4, 0xAA, 0xBB}

// ExperimentalAccessControl (142) - length 6 (example)
//&[_]u8{142, 6, 0x01,0x02,0x03,0x04}

// ExtendedInternet (145) - length 4 (example)
//&[_]u8{145, 4, 0x00, 0x01}

// RouterAlert (148) - length 4 (value usually 0x0000)
//&[_]u8{148, 4, 0x00, 0x00}

// SelectiveDirectedBroadcast (149) - length 8 (example: mask + 1 IP)
//&[_]u8{149, 8, 0xFF,0xFF,0xFF,0x00, 192,0,2,255}

// DynamicPacketState (151) - length 4 (example)
//&[_]u8{151, 4, 0x00, 0x10}

// UpstreamMulticast (152) - length 4 (example)
//&[_]u8{152, 4, 0x00, 0x01}

// QuickStart (25) - length 8 (example: rate=0x0100, ttl diff=1)
//&[_]u8{25, 8, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00}

// RFC3692Exp1 (30) - length 4 (experimental data)
//&[_]u8{30, 4, 0xCA, 0xFE}

// RFC3692Exp2 (94) - length 4
//&[_]u8{94, 4, 0xDE, 0xAD}

// RFC3692Exp3 (158) - length 6
//&[_]u8{158, 6, 0xBE, 0xEF, 0x12, 0x34}

// RFC3692Exp4 (222) - length 8
//&[_]u8{222, 8, 0x00,0x11,0x22,0x33,0x44,0x55}

// IPv4 Option Types
pub const IPOptionType = enum(u8) {
    EndOfOptions = 0,
    NoOperation = 1,
    Security = 130,
    LooseSourceRoute = 131,
    Timestamp = 68,
    ExtendedSecurity = 133,
    CommercialSecurity = 134,
    RecordRoute = 7,
    StreamID = 136,
    StrictSourceRoute = 137,
    ExperimentalMeasurement = 10,
    MTUProbe = 11,
    MTUReply = 12,
    ExperimentalFlowControl = 205,
    ExperimentalAccessControl = 142,
    ExtendedInternet = 145,
    RouterAlert = 148,
    SelectiveDirectedBroadcast = 149,
    DynamicPacketState = 151,
    UpstreamMulticast = 152,
    QuickStart = 25,
    RFC3692Exp1 = 30,
    RFC3692Exp2 = 94,
    RFC3692Exp3 = 158,
    RFC3692Exp4 = 222,
    _,

    pub fn requires_ptr_byte(opt: IPOptionType) bool {
        switch (opt) {
            .RecordRoute, .LooseSourceRoute, .StrictSourceRoute, .Timestamp => {
                return true;
            },
            else => return false,
        }
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

    pub fn to_string(self: IPv4Address, allocator: Allocator) ![]u8 {
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
