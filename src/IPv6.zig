const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;
const panic = std.debug.panic;

const LayerProtocols = @import("ProtocolHelpers.zig").LayerProtocols;
const LayerError = @import("ProtocolHelpers.zig").LayerError;
const LayerImpl = @import("ProtocolHelpers.zig").LayerImpl;

const TransportProtocol = @import("ProtocolHelpers.zig").TransportProtocols;
const ICMP = @import("ICMP.zig");
const TCP = @import("TCP.zig");
const UDP = @import("UDP.zig");
const Packet = @import("Packet.zig");

const Layer = @import("Layer.zig");
const LayerOwner = Layer.LayerOwner;

const RawData = @import("RawData.zig").RawData;

pub const IPv6HeaderSize = 40;

// IPv6 Next Header Types
pub const NextHeader = enum(u8) {
    HopByHop = 0,
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17,
    IPv6 = 41,
    Routing = 43,
    Fragment = 44,
    ESP = 50,
    AH = 51,
    ICMPv6 = 58,
    NoNext = 59,
    DestOpts = 60,
    Mobility = 135,
    HostIdentity = 139,
    Shim6 = 140,
    Reserved = 253,
    Experimental1 = 254,
    Experimental2 = 255,

    pub fn to_string(self: NextHeader) []const u8 {
        return switch (self) {
            .HopByHop => "Hop-by-Hop Options",
            .ICMP => "ICMP",
            .IGMP => "IGMP",
            .TCP => "TCP",
            .UDP => "UDP",
            .IPv6 => "IPv6",
            .Routing => "Routing",
            .Fragment => "Fragment",
            .ESP => "ESP",
            .AH => "AH",
            .ICMPv6 => "ICMPv6",
            .NoNext => "No Next Header",
            .DestOpts => "Destination Options",
            .Mobility => "Mobility",
            .HostIdentity => "Host Identity",
            .Shim6 => "SHIM6",
            .Reserved => "Reserved",
            .Experimental1 => "Experimental 1",
            .Experimental2 => "Experimental 2",
        };
    }
};

// IPv6 Extension Header Types
pub const ExtensionHeader = struct {
    next_header: NextHeader,
    length: u8, // Length in 8-octet units, not including first 8 octets
    data: []u8,
};

// IPv6 Hop-by-Hop Options Header
pub const HopByHopHeader = extern struct {
    next_header: u8 = 0,
    hdr_ext_len: u8 = 0, // Length in 8-octet units, not including first 8 octets
    // Options follow...

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
pub const RoutingHeader = extern struct {
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

// IPv6 Fragment Header
pub const FragmentHeader = extern struct {
    next_header: u8 = 0,
    reserved: u8 = 0,
    fragment_offset: u13 = 0,
    reserved2: u2 = 0,
    m_flag: u1 = 0, // More fragments flag
    identification: [4]u8 = 0,

    comptime {
        if (@sizeOf(FragmentHeader) != 8) {
            @compileError("FragmentHeader must be 8 bytes");
        }
    }

    pub fn set_fragment_offset(self: *FragmentHeader, offset: u13) void {
        self.fragment_offset = offset;
    }

    pub fn get_fragment_offset(self: *const FragmentHeader) u13 {
        return self.fragment_offset;
    }

    pub fn set_more_fragments(self: *FragmentHeader, more: bool) void {
        self.m_flag = @intFromBool(more);
    }

    pub fn get_more_fragments(self: *const FragmentHeader) bool {
        return self.m_flag == 1;
    }
};

// IPv6 Destination Options Header (similar to Hop-by-Hop)
pub const DestOptsHeader = extern struct {
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
pub const IPv6Option = struct {
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

    pub fn set_version(self: *IPv6Header, version: u4) void {
        self.version_traffic_flow = (self.version_traffic_flow & 0x0FFFFFFF) | (@as(u32, version) << 28);
    }

    pub fn get_traffic_class(self: *const IPv6Header) u8 {
        return self.version_traffic_flow[1];
    }

    pub fn set_traffic_class(self: *IPv6Header, tc: u8) void {
        self.version_traffic_flow = (self.version_traffic_flow & 0xF00FFFFF) | (@as(u32, tc) << 20);
    }

    pub fn get_flow_label(self: *const IPv6Header) u20 {
        return std.mem.readInt(u16, self.version_traffic_flow[2..4], .big);
    }

    pub fn set_flow_label(self: *IPv6Header, label: u20) void {
        self.version_traffic_flow = (self.version_traffic_flow & 0xFFF00000) | (label & 0xFFFFF);
    }

    pub fn get_payload_length(self: *const IPv6Header) u16 {
        return std.mem.bigToNative(u16, self.payload_length);
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

    pub fn init_default() IPv6Header {
        var hdr = IPv6Header{
            .version_traffic_flow = 0x60000000,
            .payload_length = 0,
            .next_header = 0,
            .hop_limit = 64,
            .src_ip = .{0} ** 16,
            .dst_ip = .{0} ** 16,
        };
        hdr.set_version(6);
        return hdr;
    }
};

pub const IPv6Layer = struct {
    owner: LayerOwner,
    const Protocol = LayerProtocols{ .Network = .IPv6 };

    pub fn init(owner: LayerOwner) LayerError!IPv6Layer {
        switch (owner) {
            .packet_layer => {
                return IPv6Layer{
                    .owner = owner,
                };
            },
            .allocator_owned => {
                var self = IPv6Layer{ .owner = owner };
                // Allocate directly into the struct's data field
                if (owner.allocator_owned.data.len < IPv6HeaderSize) {
                    self.owner.allocator_owned.data = try self.owner.allocator_owned.allocator.alloc(u8, IPv6HeaderSize);
                }

                //var header = IPv6Header.init_default();
                //@memcpy(self.owner.allocator_owned.data[0..@sizeOf(IPv6Header)], std.mem.asBytes(&header));

                return self;
            },
            .immutable_layer => return {
                return IPv6Layer{ .owner = owner };
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

        return std.fmt.allocPrint(allocator,
            \\IPv6 Layer:
            \\  version: {}
            \\  traffic_class: {}
            \\  flow_label: {}
            \\  payload_length: {}
            \\  next_header: {s}
            \\  hop_limit: {}
            \\  src_ip: {s}
            \\  dst_ip: {s}
            \\
        , .{
            hdr.get_version(),
            hdr.get_traffic_class(),
            hdr.get_flow_label(),
            hdr.get_payload_length(),
            @tagName(hdr.get_next_header()),
            hdr.hop_limit,
            src_ip_str,
            dst_ip_str,
        }) catch return "";

        //var ext_str = std.ArrayList(u8).empty;
        //defer ext_str.deinit();

        //for (self.extensions.items, 0..) |ext, i| {
        //    ext_str.appendSlice(std.fmt.allocPrint(allocator, "\n    {}: {s}", .{ i, @tagName(ext.next_header) }) catch "") catch {};
        //}

        //return std.fmt.allocPrint(allocator,
        //    \\IPv6 Layer:
        //    \\  version: {}
        //    \\  traffic_class: {}
        //    \\  flow_label: {}
        //    \\  payload_length: {}
        //    \\  next_header: {s}
        //    \\  hop_limit: {}
        //    \\  src_ip: {s}
        //    \\  dst_ip: {s}
        //    \\  extensions: {s}
        //    \\
        //, .{
        //    hdr.get_version(),
        //    hdr.get_traffic_class(),
        //    hdr.get_flow_label(),
        //    hdr.get_payload_length(),
        //    @tagName(hdr.get_next_header()),
        //    hdr.hop_limit,
        //    src_ip_str,
        //    dst_ip_str,
        //    ext_str.items,
        //}) catch return "";
    }

    fn get_mutable_header(self: *const IPv6Layer) *IPv6Header {
        const data = self.get_data().mutable;
        const aligned_ptr: [*]align(@alignOf(IPv6Header)) u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    fn get_immutable_header(self: *const IPv6Layer) *const IPv6Header {
        var data: []const u8 = undefined;

        if (self.get_data().is_mutable()) { // if the data is actually mutable - we just need immutable in this case anyway
            data = self.get_data().get_mutable();
        } else {
            data = self.get_data().get_immutable();
        }

        if (data.len < IPv6HeaderSize) {
            panic("IPv6 Raw Data len ({}) less than IPv6HeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(IPv6Header)) const u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    /// get slice of data (hdr+payload)
    pub fn get_data(self: *const IPv6Layer) RawData {
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

    /// return mutable slice of the payload
    pub fn get_payload(self: *const IPv6Layer) ?[]const u8 { // needs to return RawData
        const data = self.get_data().get_immutable();
        if (data.len > IPv6HeaderSize) {
            return data[IPv6HeaderSize..];
        } else {
            return null;
        }
    }

    fn parse_extensions(self: *IPv6Layer) !void {
        var offset: usize = IPv6HeaderSize;
        var current_next: u8 = self.get_immutable_header().next_header;

        const data = self.get_data().get_immutable();

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

                    try self.extensions.append(ExtensionHeader{
                        .next_header = @enumFromInt(hbh.next_header),
                        .length = ext_len,
                        .data = data[offset .. offset + ext_len],
                    });

                    current_next = hbh.next_header;
                    offset += ext_len;
                },
                .Routing => {
                    const routing = @as(*RoutingHeader, @ptrCast(data[offset..].ptr));
                    const ext_len = (routing.hdr_ext_len + 1) * 8;

                    try self.extensions.append(ExtensionHeader{
                        .next_header = @enumFromInt(routing.next_header),
                        .length = ext_len,
                        .data = data[offset .. offset + ext_len],
                    });

                    current_next = routing.next_header;
                    offset += ext_len;
                },
                .Fragment => {
                    const frag = @as(*FragmentHeader, @ptrCast(data[offset..].ptr));

                    try self.extensions.append(ExtensionHeader{
                        .next_header = @enumFromInt(frag.next_header),
                        .length = @sizeOf(FragmentHeader),
                        .data = data[offset .. offset + @sizeOf(FragmentHeader)],
                    });

                    current_next = frag.next_header;
                    offset += @sizeOf(FragmentHeader);
                },
                .DestOpts => {
                    const dest = @as(*DestOptsHeader, @ptrCast(data[offset..].ptr));
                    const ext_len = (dest.hdr_ext_len + 1) * 8;

                    try self.extensions.append(ExtensionHeader{
                        .next_header = @enumFromInt(dest.next_header),
                        .length = ext_len,
                        .data = data[offset .. offset + ext_len],
                    });

                    current_next = dest.next_header;
                    offset += ext_len;
                },
                .AH, .ESP => {
                    // Authentication Header or Encapsulating Security Payload
                    // These have variable length, simplified for now
                    const len = @as(u8, data[offset + 1]);
                    const ext_len = (len + 2) * 4;

                    try self.extensions.append(ExtensionHeader{
                        .next_header = @enumFromInt(data[offset]),
                        .length = ext_len,
                        .data = data[offset .. offset + ext_len],
                    });

                    current_next = data[offset];
                    offset += ext_len;
                },
                else => {
                    // Unknown extension header, stop parsing
                    break;
                },
            }
        }
    }

    pub fn add_extension_header(self: *IPv6Layer, next_header: NextHeader, data: []const u8, allocator: Allocator) !void {
        const old_len = self.data.len;
        const new_len = old_len + data.len;

        self.data = try allocator.realloc(self.data, new_len);
        @memcpy(self.data[old_len..][0..data.len], data);

        // Update the previous header's next_header field
        if (self.extensions.items.len == 0) {
            var hdr = self.get_mutable_header();
            hdr.set_next_header(next_header);
        } else {
            const last_ext = &self.extensions.items[self.extensions.items.len - 1];
            var last_ext_header = @as(*HopByHopHeader, @ptrCast(last_ext.data.ptr));
            last_ext_header.next_header = @intFromEnum(next_header);
        }

        try self.extensions.append(ExtensionHeader{
            .next_header = next_header,
            .length = @intCast(data.len),
            .data = self.data[old_len..new_len],
        });
    }

    pub fn get_transport_type(self: *IPv6Layer) !TransportProtocol {
        const hdr = self.get_immutable_header();
        return try std.meta.intToEnum(TransportProtocol, hdr.next_header);
    }

    pub fn get_next_layer_type(self: *const IPv6Layer, layer: *Packet.Layer) !?LayerImpl {
        const data = self.get_data().get_immutable();

        if (data.len < @sizeOf(IPv6Header)) return error.BufferTooSmall;

        //       const alignment = @alignOf(IPv4Header);
        //       const addr = @intFromPtr(data.ptr);
        //
        //       if (addr % alignment != 0) {
        //           return error.MisalignedBuffer;
        //       }
        //       const aligned_ptr: [*]align(@alignOf(IPv4Header)) u8 = @alignCast(data.ptr);
        const hdr = self.get_immutable_header();

        switch (hdr.get_next_header()) {
            .ICMP => {
                return try LayerImpl.init(ICMP.ICMPLayer, LayerOwner{ .packet_layer = layer });
            },

            .TCP => {
                return try LayerImpl.init(TCP.TCPLayer, LayerOwner{ .packet_layer = layer });
            },
            .UDP => {
                return try LayerImpl.init(UDP.UDPLayer, LayerOwner{ .packet_layer = layer });
            },
            else => return null,
        }
    }

    pub fn get_protocol(self: *IPv6Layer) LayerProtocols {
        _ = self;
        return IPv6Layer.Protocol;
    }

    pub fn deinit(self: *IPv6Layer, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
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
