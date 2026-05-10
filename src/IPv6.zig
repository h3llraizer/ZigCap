const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;
const panic = std.debug.panic;

const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;
const LayerError = @import("ProtocolEnums.zig").LayerError;
const LayerIface = @import("LayerIface.zig").LayerIface;

const IPProtocol = @import("ProtocolEnums.zig").IPProtocol;

const ICMP = @import("ICMP.zig");
const TCP = @import("TCP.zig");
const UDP = @import("UDP.zig");
const GenericLayer = @import("GenericLayer.zig");
const Packet = @import("Packet.zig");

const Layer = @import("Layer.zig");
const IPv6Ext = @import("IPv6_Ext.zig");

const LayerOwner = Layer.LayerOwner;
const ApplicationLayer = GenericLayer.ApplicationLayer;

pub const NextHeader = IPv6Ext.NextHeader;
pub const ExtensionHeader = IPv6Ext.ExtensionHeader;
pub const HobByHop = IPv6Ext.HopByHop;
pub const OptionType = IPv6Ext.OptionType;

pub const IPv6HeaderSize = 40;

// IPv6 Hop-by-Hop Options Header
const HopByHopHeader = extern struct {
    next_header: u8 = 0,
    hdr_ext_len: u8 = 0, // Length in 8-octet units, not including first 8 octets

    comptime {
        if (@sizeOf(HopByHopHeader) != 2) {
            @compileError("HopByHopHeader must be 2 bytes");
        }
    }
};

// IPv6 Routing Header Types
pub const RoutingType = enum(u8) {
    Type0 = 0,
    Type2 = 2, // Mobile IPv6
    Type3 = 3, // RPL Source Route Header
    Type4 = 4, // Segment Routing Header

    pub fn to_string(self: RoutingType) []const u8 {
        return switch (self) {
            .Type0 => "Type 0 (deprecated)",
            .Type2 => "Type 2 (Mobile IPv6)",
            .Type3 => "Type 3 (RPL)",
            .Type4 => "Type 4 (Segment Routing)",
        };
    }
};

// IPv6 Routing Header
const RoutingHeader = extern struct {
    next_header: u8 = 0,
    hdr_ext_len: u8 = 0, // Length in 8-octet units, not including first 8 octets
    routing_type: u8 = 0,
    segments_left: u8 = 0,
    // Type-specific data follows...

    comptime {
        if (@sizeOf(RoutingHeader) != 4) {
            @compileError("RoutingHeader must be 4 bytes");
        }
    }
};

const IPV6_FRAG_OFFSET_MASK: u16 = 0xfff8; // top 13 bits
const IPV6_FRAG_RES_MASK: u16 = 0x0006; // next 2 bits
const IPV6_FRAG_M_MASK: u16 = 0x0001; // last bit

// IPv6 Fragment Header
const FragmentHeader = extern struct {
    next_header: u8 = 0,
    reserved: u8 = 0,
    fragment_off_flags: u16 = 0,
    identification: u32 = 0,

    comptime {
        if (@sizeOf(FragmentHeader) != 8) {
            @compileError("FragmentHeader must be 8 bytes");
        }
    }

    pub fn getFragmentOffset(self: *const FragmentHeader) u13 {
        const v = @byteSwap(self.fragment_off_flags);
        return @intCast((v & IPV6_FRAG_OFFSET_MASK) >> 3);
    }

    pub fn setFragmentOffset(self: *FragmentHeader, offset: u13) void {
        var v = @byteSwap(self.fragment_off_flags);

        // clear old offset
        v &= ~IPV6_FRAG_OFFSET_MASK;

        // set new offset (shifted into position)
        v |= (@as(u16, offset) << 3) & IPV6_FRAG_OFFSET_MASK;

        self.fragment_off_flags = @byteSwap(v);
    }

    pub fn getMoreFragments(self: *const FragmentHeader) bool {
        const v = @byteSwap(self.fragment_off_flags);
        return (v & IPV6_FRAG_M_MASK) != 0;
    }

    pub fn setMoreFragments(self: *FragmentHeader, more: bool) void {
        var v = @byteSwap(self.fragment_off_flags);

        // clear flag
        v &= ~IPV6_FRAG_M_MASK;

        // set if needed
        if (more) {
            v |= IPV6_FRAG_M_MASK;
        }

        self.fragment_off_flags = @byteSwap(v);
    }
};

// IPv6 Destination Options Header (similar to Hop-by-Hop)
const DestOptsHeader = extern struct {
    next_header: u8 = 0,
    hdr_ext_len: u8 = 0,
    // Options follow...

    comptime {
        if (@sizeOf(DestOptsHeader) != 2) {
            @compileError("DestOptsHeader must be 2 bytes");
        }
    }
};

// IPv6 Option (for Hop-by-Hop and Destination Options)
const IPv6Option = struct {
    type: u8,
    length: u8, // Length of option data in octets
    data: []u8,

    pub const Pad1 = 0;
    pub const PadN = 1;
    pub const JumboPayload = 194;
    pub const RouterAlert = 5;
    pub const QuickStart = 26;
    pub const CALIPSO = 12;
    pub const HomeAddress = 201;

    pub fn initPad1() IPv6Option {
        return IPv6Option{
            .type = Pad1,
            .length = 0,
            .data = &[_]u8{},
        };
    }

    pub fn initPadN(len: u8) IPv6Option {
        var data = std.ArrayList(u8).init(std.heap.page_allocator);
        defer data.deinit();
        for (0..len) |_| {
            data.append(0) catch unreachable;
        }
        return IPv6Option{
            .type = PadN,
            .length = len,
            .data = data.items,
        };
    }

    pub fn initJumboPayload(len: u32) IPv6Option {
        var data = std.ArrayList(u8).init(std.heap.page_allocator);
        defer data.deinit();
        data.appendSlice(&@as([4]u8, @bitCast(@byteSwap(len)))) catch unreachable;
        return IPv6Option{
            .type = JumboPayload,
            .length = 4,
            .data = data.items,
        };
    }

    pub fn toBytes(self: IPv6Option) []u8 {
        var bytes = std.ArrayList(u8).init(std.heap.page_allocator);
        defer bytes.deinit();

        bytes.append(self.type) catch unreachable;

        if (self.type != Pad1) {
            bytes.append(self.length) catch unreachable;
            bytes.appendSlice(self.data) catch unreachable;
        }

        return bytes.toOwnedSlice() catch &[_]u8{};
    }
};

// IPv6 Header
pub const IPv6Header = extern struct {
    version_traffic_flow: [4]u8, // Version 6, Traffic Class 0, Flow Label 0
    payload_length: u16 = 0, // Payload length (excluding IPv6 header)
    next_header: u8 = 0, // Next header type
    hop_limit: u8 = 64, // Hop limit (similar to TTL)
    src_ip: [16]u8 = .{0} ** 16, // Source IPv6 address
    dst_ip: [16]u8 = .{0} ** 16, // Destination IPv6 address

    comptime {
        if (@sizeOf(IPv6Header) != IPv6HeaderSize) {
            @compileError("IPv6Header must be 40 bytes, got " ++ @typeName(@sizeOf(IPv6Header)));
        }
    }

    pub fn get_version(self: *const IPv6Header) u4 {
        return @truncate(self.version_traffic_flow[0] >> 4);
    }

    pub fn get_traffic_class(self: *const IPv6Header) u8 {
        return self.version_traffic_flow[1];
    }

    pub fn set_traffic_class(self: *IPv6Header, tc: u8) void {
        //        self.version_traffic_flow = (self.version_traffic_flow & 0xF00FFFFF) | (@as(u32, tc) << 20);
        self.version_traffic_flow[1] = tc;
    }

    pub fn get_flow_label(self: *const IPv6Header) u20 {
        return std.mem.readInt(u16, self.version_traffic_flow[2..4], .big);
    }

    pub fn set_flow_label(self: *IPv6Header, label: u20) void {
        self.version_traffic_flow = (self.version_traffic_flow & 0xFFF00000) | (label & 0xFFFFF);
    }

    /// returns the payload length set in the header (can be inaccurate due to malformed packet / incomplete layers etc)
    /// first extension to payload length
    pub fn get_payload_length(self: *const IPv6Header) u16 {
        return @byteSwap(self.payload_length);
    }

    pub fn set_payload_length(self: *IPv6Header, len: u16) void {
        self.payload_length = @byteSwap(len);
    }

    pub fn get_next_header(self: *const IPv6Header) NextHeader {
        return @enumFromInt(self.next_header);
    }

    pub fn set_next_header(self: *IPv6Header, nh: NextHeader) void {
        self.next_header = @intFromEnum(nh);
    }

    pub fn get_src_ip(self: *const IPv6Header) IPv6Address {
        return IPv6Address.init_from_array(self.src_ip);
    }

    pub fn set_src_ip(self: *IPv6Header, ip: IPv6Address) void {
        self.src_ip = ip.array;
    }

    pub fn get_dst_ip(self: *const IPv6Header) IPv6Address {
        return IPv6Address.init_from_array(self.dst_ip);
    }

    pub fn set_dst_ip(self: *IPv6Header, ip: IPv6Address) void {
        self.dst_ip = ip.array;
    }

    pub fn init_default() IPv6Header {
        return IPv6Header{
            .version_traffic_flow = .{ 0x60, 0x0, 0x0, 0x0 },
            .payload_length = 0,
            .next_header = 0,
            .hop_limit = 64,
            .src_ip = .{0} ** 16,
            .dst_ip = .{0} ** 16,
        };
    }
};

const IPv6LayerMeta = struct {
    ext_count: usize, // total extension headers
    ext_total_len: usize, // the total length of the extended headers from first header to last (not including IPProtocol layer)
    ip_proto: IPProtocol, // the IP protocol this layer uses
};

pub const IPv6Layer = struct {
    owner: LayerOwner,
    ext_header: ?*ExtensionHeader = null,

    pub fn init(owner: LayerOwner) LayerError!IPv6Layer {
        switch (owner) {
            .packet_layer => {
                return IPv6Layer{
                    .owner = owner,
                };
            },
            .owned_buffer => {
                var self = IPv6Layer{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < IPv6HeaderSize) {
                    const ipv4_data = try self.owner.owned_buffer.extend(buffer_len, IPv6HeaderSize);

                    @memset(ipv4_data, 0);

                    var header = IPv6Header.init_default();

                    @memcpy(ipv4_data[0..IPv6HeaderSize], std.mem.asBytes(&header));
                }

                return self;
            },
        }
    }

    pub fn to_string(self: *IPv6Layer, allocator: Allocator) []const u8 {
        const hdr = self.get_immutable_header();

        const src_ip = IPv6Address.init_from_array(hdr.src_ip);
        const dst_ip = IPv6Address.init_from_array(hdr.dst_ip);

        const src_ip_str = src_ip.to_string(allocator) catch return "";
        defer allocator.free(src_ip_str);

        const dst_ip_str = dst_ip.to_string(allocator) catch return "";
        defer allocator.free(dst_ip_str);

        return std.fmt.allocPrint(allocator, "IPv6 Layer: src_ip: {s} dst_ip: {s}\n", .{
            src_ip_str,
            dst_ip_str,
        }) catch return "";
    }

    pub fn get_mutable_header(self: *IPv6Layer) *IPv6Header {
        const data = self.get_data();
        const aligned_ptr: [*]align(@alignOf(IPv6Header)) u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn get_immutable_header(self: *const IPv6Layer) *const IPv6Header {
        const data: []const u8 = self.get_data();

        if (data.len < IPv6HeaderSize) {
            panic("IPv6 Raw Data len ({}) less than IPv6HeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(IPv6Header)) const u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    /// get slice of data (hdr+payload)
    pub fn get_data(self: *const IPv6Layer) []u8 {
        return self.owner.get_data();
    }

    /// return mutable slice of the payload
    pub fn get_payload(self: *const IPv6Layer) []const u8 {
        const data = self.get_data();
        const total_len = IPv6HeaderSize + self.get_layer_len();
        if (data.len > total_len) {
            return data[total_len..];
        } else {
            return "";
        }
    }

    fn get_meta(self: *const IPv6Layer) IPv6LayerMeta {
        var offset: usize = IPv6HeaderSize;
        var current_next: u8 = self.get_immutable_header().next_header;
        const data = self.get_data();

        var ext_total_len: usize = 0;
        var ext_count: usize = 0;

        while (current_next != @intFromEnum(NextHeader.NoNext) and
            current_next != @intFromEnum(NextHeader.TCP) and
            current_next != @intFromEnum(NextHeader.UDP) and
            current_next != @intFromEnum(NextHeader.ICMP) and
            current_next != @intFromEnum(NextHeader.ICMPv6))
        {
            if (offset >= data.len) break;

            const next_header_type: NextHeader = @enumFromInt(current_next);

            switch (next_header_type) {
                .HopByHop => {
                    const hbh = @as(*HopByHopHeader, @ptrCast(data[offset..].ptr));
                    const ext_len = (hbh.hdr_ext_len + 1) * 8;

                    current_next = hbh.next_header;
                    offset += ext_len;
                    ext_total_len += ext_len;
                    ext_count += 1;
                },
                .Routing => {
                    const routing = @as(*RoutingHeader, @ptrCast(data[offset..].ptr));
                    const ext_len = (routing.hdr_ext_len + 1) * 8;

                    current_next = routing.next_header;
                    offset += ext_len;
                    ext_total_len += ext_len;
                    ext_count += 1;
                },
                .Fragment => {
                    const frag: *FragmentHeader = @ptrCast(@alignCast(data[offset..].ptr));

                    current_next = frag.next_header;
                    offset += @sizeOf(FragmentHeader);
                    ext_count += 1;
                    ext_total_len += @sizeOf(FragmentHeader);
                },
                .DestOpts => {
                    const dest = @as(*DestOptsHeader, @ptrCast(data[offset..].ptr));
                    const ext_len = (dest.hdr_ext_len + 1) * 8;

                    current_next = dest.next_header;
                    offset += ext_len;
                    ext_count += 1;
                    ext_total_len += ext_len;
                },
                .AH, .ESP => {
                    // Authentication Header or Encapsulating Security Payload
                    // These have variable length, simplified for now
                    const len = @as(u8, data[offset + 1]);
                    const ext_len = (len + 2) * 4;

                    current_next = data[offset];
                    offset += ext_len;
                    ext_count += 1;
                    ext_total_len += ext_len;
                },
                else => {
                    // Unknown extension header, stop parsing
                    print("unknown ext.\n", .{});
                    break;
                },
            }
        }

        // convert the final current_next to IPProtocol
        const ip_proto: u8 = switch (current_next) {
            @intFromEnum(NextHeader.TCP) => @intFromEnum(IPProtocol.TCP),
            @intFromEnum(NextHeader.UDP) => @intFromEnum(IPProtocol.UDP),
            @intFromEnum(NextHeader.ICMP) => @intFromEnum(IPProtocol.ICMP),
            @intFromEnum(NextHeader.ICMPv6) => @intFromEnum(IPProtocol.ICMPv6),
            else => @intFromEnum(IPProtocol.Unknown), // unknown protocol, next layer will be resolved as Application Layer
        };

        const meta = IPv6LayerMeta{ .ext_count = ext_count, .ip_proto = @enumFromInt(ip_proto), .ext_total_len = ext_total_len };

        return meta;
    }

    /// gets the full len of this layer including IPv6 base header + any extensions (not the proceeding payload)
    fn get_layer_len(self: *const IPv6Layer) usize {
        return self.get_meta().ext_total_len;
    }

    pub fn parse_extensions(self: *IPv6Layer) !void {
        var offset: usize = IPv6HeaderSize;
        var current_next: u8 = self.get_immutable_header().next_header;

        const data = self.get_data();

        if (data.len <= IPv6HeaderSize) {
            return;
        }

        if (self.ext_header != null) {
            self.destroy_ext_headers();
        }

        while (current_next != @intFromEnum(NextHeader.NoNext) and
            current_next != @intFromEnum(NextHeader.TCP) and
            current_next != @intFromEnum(NextHeader.UDP) and
            current_next != @intFromEnum(NextHeader.ICMP) and
            current_next != @intFromEnum(NextHeader.ICMPv6))
        {
            if (offset >= data.len) break;

            const next_header_type: NextHeader = @enumFromInt(current_next);

            switch (next_header_type) {
                .HopByHop => {
                    const hbh = @as(*HopByHopHeader, @ptrCast(data[offset..].ptr));
                    const ext_len = (hbh.hdr_ext_len + 1) * 8;

                    try self.add_next_ext_header(ExtensionHeader.init(next_header_type, offset, ext_len, self));

                    current_next = hbh.next_header;
                    offset += ext_len;
                },
                .Routing => {
                    const routing = @as(*RoutingHeader, @ptrCast(data[offset..].ptr));
                    const ext_len = (routing.hdr_ext_len + 1) * 8;

                    try self.add_next_ext_header(ExtensionHeader.init(next_header_type, offset, ext_len, self));

                    current_next = routing.next_header;
                    offset += ext_len;
                },
                .Fragment => {
                    const frag: *FragmentHeader = @ptrCast(@alignCast(data[offset..].ptr));

                    try self.add_next_ext_header(ExtensionHeader.init(next_header_type, offset, @sizeOf(ExtensionHeader), self));

                    current_next = frag.next_header;
                    offset += @sizeOf(FragmentHeader);
                },
                .DestOpts => {
                    const dest = @as(*DestOptsHeader, @ptrCast(data[offset..].ptr));
                    const ext_len = (dest.hdr_ext_len + 1) * 8;

                    try self.add_next_ext_header(ExtensionHeader.init(next_header_type, offset, ext_len, self));

                    current_next = dest.next_header;
                    offset += ext_len;
                },
                .AH, .ESP => {
                    // Authentication Header or Encapsulating Security Payload
                    // These have variable length, simplified for now
                    const len = @as(u8, data[offset + 1]);
                    const ext_len = (len + 2) * 4;

                    try self.add_next_ext_header(ExtensionHeader.init(next_header_type, offset, ext_len, self));

                    current_next = data[offset];
                    offset += ext_len;
                },
                else => {
                    // Unknown extension header, stop parsing
                    print("unknown ext encountered. breaking.\n", .{});
                    break;
                },
            }
        }
    }

    pub fn get_last_ext_header(self: *IPv6Layer) ?*ExtensionHeader {
        var cur = self.ext_header;

        while (cur) |ext| {
            if (ext.next_ext) |next| {
                cur = next;
            } else {
                return cur;
            }
        }

        return cur;
    }

    /// internal use to add an extension header when parsing
    fn add_next_ext_header(self: *IPv6Layer, ext_hdr: ExtensionHeader) !void {
        const allocator = self.owner.get_allocator();

        const ext_ = try allocator.create(ExtensionHeader);
        ext_.* = ext_hdr;

        if (self.ext_header == null) {
            self.ext_header = ext_;
            return;
        }

        var cur = self.ext_header;
        while (cur) |next| {
            if (next.get_next_extension() == null) {
                next.set_next_extension(ext_);
                return;
            }
            cur = next.get_next_extension();
        }
    }

    /// get a specific IPv6 extension header
    pub fn get_ext_header(self: *IPv6Layer, header_type: NextHeader) ?*ExtensionHeader {
        var cur = self.ext_header;
        while (cur) |ext| {
            if (ext.get_type() == header_type) {
                return ext;
            }

            cur = ext.get_next_extension();
        }

        return null;
    }

    //   pub fn add_extension_header(self: *IPv6Layer, next_header: NextHeader, data: []const u8, allocator: Allocator) !void {
    //
    //   }

    pub fn validate_layer(self: *IPv6Layer) void {
        _ = self;
        return;
    }

    pub fn get_ip_proto_type(self: *IPv6Layer) !IPProtocol {
        const hdr = self.get_immutable_header();
        return try std.meta.intToEnum(IPProtocol, hdr.next_header);
    }

    pub fn get_next_layer_type(self: *const IPv6Layer, layer: *Packet.Layer) !?LayerIface {
        const data = self.get_data();

        if (data.len < @sizeOf(IPv6Header)) return error.BufferTooSmall;

        const meta = self.get_meta();

        const ip_proto = meta.ip_proto;

        switch (ip_proto) {
            .ICMP => {
                return try LayerIface.init(ICMP.ICMPLayer, LayerOwner{ .packet_layer = layer });
            },
            .TCP => {
                return try LayerIface.init(TCP.TCPLayer, LayerOwner{ .packet_layer = layer });
            },
            .UDP => {
                return try LayerIface.init(UDP.UDPLayer, LayerOwner{ .packet_layer = layer });
            },
            else => return try LayerIface.init(ApplicationLayer, LayerOwner{ .packet_layer = layer }),
        }
    }

    pub fn get_protocol(self: *IPv6Layer) tcp_ip_protocol {
        _ = self;
        return tcp_ip_protocol.ipv6;
    }

    /// doesn't actually destroy the headers data, just the linkedlist nodes
    fn destroy_ext_headers(self: *IPv6Layer) void {
        var allocator = self.owner.get_allocator();

        var cur = self.ext_header;

        while (cur) |ext| {
            const next = ext.get_next_extension();
            allocator.destroy(ext);
            cur = next;
        }

        self.ext_header = null;
    }

    pub fn deinit(self: *IPv6Layer) void {
        self.destroy_ext_headers();
        self.owner.deinit();
    }
};

pub const IPv6Address = struct {
    array: [16]u8,

    pub const Error = error{
        InvalidFormat,
        TooManyGroups,
        TooFewGroups,
        GroupOverflow,
        NonHexDigit,
    };

    pub fn init_from_array(raw: [16]u8) IPv6Address {
        return .{ .array = raw };
    }

    pub fn init_from_string(str: []const u8) !IPv6Address {
        var groups: [8]u16 = undefined;

        var group_index: usize = 0;
        var cur_value: u32 = 0;
        var have_digit = false;

        var i: usize = 0;
        while (i < str.len) : (i += 1) {
            const c = str[i];

            if (c == ':') {
                if (!have_digit) return Error.InvalidFormat;
                if (group_index >= 8) return Error.TooManyGroups;

                groups[group_index] = @intCast(cur_value);
                group_index += 1;

                cur_value = 0;
                have_digit = false;
                continue;
            }

            const digit = switch (c) {
                '0'...'9' => c - '0',
                'a'...'f' => 10 + (c - 'a'),
                'A'...'F' => 10 + (c - 'A'),
                else => return Error.NonHexDigit,
            };

            have_digit = true;
            cur_value = (cur_value << 4) | digit;

            if (cur_value > 0xFFFF)
                return Error.GroupOverflow;
        }

        if (!have_digit) return Error.InvalidFormat;
        if (group_index != 7) return Error.TooFewGroups;

        groups[group_index] = @intCast(cur_value);

        // Convert 8 groups (u16) → 16 bytes (big endian)
        var result: [16]u8 = undefined;
        for (groups, 0..) |g, idx| {
            result[idx * 2 + 0] = @intCast((g >> 8) & 0xFF);
            result[idx * 2 + 1] = @intCast(g & 0xFF);
        }

        return .{ .array = result };
    }

    pub fn to_string(self: IPv6Address, allocator: std.mem.Allocator) ![]u8 {
        var groups: [8]u16 = undefined;

        // Convert bytes → 8 u16 groups
        for (0..8) |i| {
            const hi: u16 = self.array[i * 2];
            const lo: u16 = self.array[i * 2 + 1];
            groups[i] = (hi << 8) | lo;
        }

        return std.fmt.allocPrint(
            allocator,
            "{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}",
            .{
                groups[0],
                groups[1],
                groups[2],
                groups[3],
                groups[4],
                groups[5],
                groups[6],
                groups[7],
            },
        );
    }
};
