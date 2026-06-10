const std = @import("std");
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;
const LayerError = @import("ProtocolEnums.zig").LayerError;
const LayerIface = @import("LayerIface.zig").LayerIface;
const init_layer = @import("LayerIface.zig").init_layer;
const IPProtocol = @import("ProtocolEnums.zig").IPProtocol;
const ICMP = @import("ICMP.zig");
const TCP = @import("TCP.zig");
const UDP = @import("UDP.zig");
const GenericLayer = @import("GenericLayer.zig");
const Packet = @import("Packet.zig");
const Owner = @import("Owner.zig");
const IPv6Ext = @import("IPv6_Ext.zig");

const print = std.debug.print;
const Allocator = std.mem.Allocator;
const panic = std.debug.panic;

const LayerOwner = Owner.LayerOwner;
const TLVOwner = Owner.TLVOwner;
const ApplicationLayer = GenericLayer.ApplicationLayer;

pub const NextHeader = IPv6Ext.NextHeader;
pub const ExtensionHeader = IPv6Ext.ExtensionHeader;
pub const ExtensionHeaders = IPv6Ext.ExtensionHeaders;

pub const IPv6Extensions = IPv6Ext;

pub const IPv6HeaderSize = 40;

const default_hdr = IPv6Header{
    .version_traffic_flow = .{ 0x60, 0x0, 0x0, 0x0 },
    .payload_length = .{0} ** 2,
    .next_header = @intFromEnum(NextHeader.NoNext),
    .hop_limit = 64,
    .src_ip = .{0} ** 16,
    .dst_ip = .{0} ** 16,
};

// IPv6 Header
pub const IPv6Header = extern struct {
    version_traffic_flow: [4]u8, // Version 6, Traffic Class 0, Flow Label 0
    payload_length: [2]u8 = .{0} ** 2, // Payload length (excluding IPv6 header)
    next_header: u8 = 0x3B, // Next header type
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
        const l4 = self.version_traffic_flow[0] & 0x0F;
        const up4 = self.version_traffic_flow[1] >> 4;

        return (up4 << 4) | l4;
    }

    pub fn set_traffic_class(self: *IPv6Header, tc: u8) void {
        var word = std.mem.readInt(u32, self.version_traffic_flow[0..4], .big);

        word &= ~@as(u32, 0x0FF0_0000); // clear traffic class
        word |= (@as(u32, tc & 0xFF) << 20); // set traffic class

        std.mem.writeInt(u32, self.version_traffic_flow[0..4], word, .big);
    }

    pub fn get_flow_label(self: *const IPv6Header) u20 {
        const word = std.mem.readInt(u32, self.version_traffic_flow[0..4], .big);
        return @truncate(word);
    }

    pub fn set_flow_label(self: *IPv6Header, label: u20) void {
        var word = std.mem.readInt(u32, self.version_traffic_flow[0..4], .big);

        word = (word & 0xFFF00000) | @as(u32, label);

        std.mem.writeInt(u32, self.version_traffic_flow[0..4], word, .big);
    }

    /// returns the payload length set in the header (can be inaccurate due to malformed packet / incomplete layers etc)
    /// first extension to payload length
    pub fn get_payload_length(self: *const IPv6Header) u16 {
        return std.mem.readInt(u16, &self.payload_length, .big);
    }

    pub fn set_payload_length(self: *IPv6Header, len: u16) void {
        std.mem.writeInt(u16, &self.payload_length, len, .big);
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
            .payload_length = .{ 0x00, 0x00 },
            .next_header = @intFromEnum(NextHeader.NoNext),
            .hop_limit = 64,
            .src_ip = .{0} ** 16,
            .dst_ip = .{0} ** 16,
        };
    }
};

const IPv6LayerMeta = struct {
    ext_count: usize, // total extension headers
    ext_total_len: usize, // the total length of the extended headers from first header to last (not including IPProtocol layer)
    last_ext: ?NextHeader,
    ip_proto: IPProtocol, // the IP protocol this layer uses

};

pub const IPv6Layer = struct {
    owner: LayerOwner,

    pub fn init(owner: LayerOwner) LayerError!IPv6Layer {
        return try init_layer(IPv6Layer, owner, IPv6Header, default_hdr);
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
        const total_len = IPv6HeaderSize + self.get_meta().ext_total_len;
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

        var end: usize = data.len;

        if (self.owner.is_packet_owned()) {
            end = self.owner.packet_layer.length;
        }

        var ext_total_len: usize = 0;
        var ext_count: usize = 0;

        var last_ext: ?NextHeader = null;

        while (current_next != @intFromEnum(NextHeader.NoNext) and
            current_next != @intFromEnum(NextHeader.TCP) and
            current_next != @intFromEnum(NextHeader.UDP) and
            current_next != @intFromEnum(NextHeader.ICMP) and
            current_next != @intFromEnum(NextHeader.ICMPv6))
        {
            if (offset >= end) break;

            const next_header_type: NextHeader = @enumFromInt(current_next);

            switch (next_header_type) {
                .HopByHop, .DestOpts, .Routing => {
                    const next_header = data[offset];
                    const hdr_ext_len = data[offset + 1];
                    const ext_len = (hdr_ext_len + 1) * 8;

                    current_next = next_header;
                    offset += ext_len;
                    ext_total_len += ext_len;
                    ext_count += 1;

                    last_ext = next_header_type;
                },
                .Fragment => {
                    current_next = data[offset];
                    offset += 8;
                    ext_count += 1;
                    ext_total_len += 8;

                    last_ext = next_header_type;
                },
                .AH => {
                    const payload_len = data[offset + 1];
                    const ext_len = (payload_len + 2) * 4;

                    current_next = data[offset];
                    offset += ext_len;
                    ext_count += 1;
                    ext_total_len += ext_len;
                    last_ext = next_header_type;
                },
                .ESP => {
                    current_next = @intFromEnum(NextHeader.NoNext);
                    offset = data.len;
                    ext_count += 1;
                    ext_total_len += data.len - offset;
                    last_ext = next_header_type;
                },
                .Mobility, .HostIdentity, .Shim6 => {
                    current_next = data[offset];
                    offset += 8;
                    ext_count += 1;
                    ext_total_len += 8;
                    last_ext = next_header_type;
                },
                else => {
                    print("unknown ext.\n", .{});
                    break;
                },
            }
        }

        const ip_proto: u8 = switch (current_next) {
            @intFromEnum(NextHeader.TCP) => @intFromEnum(IPProtocol.TCP),
            @intFromEnum(NextHeader.UDP) => @intFromEnum(IPProtocol.UDP),
            @intFromEnum(NextHeader.ICMP) => @intFromEnum(IPProtocol.ICMP),
            @intFromEnum(NextHeader.ICMPv6) => @intFromEnum(IPProtocol.ICMPv6),
            else => @intFromEnum(IPProtocol.Unknown),
        };

        const meta = IPv6LayerMeta{
            .ext_count = ext_count,
            .ext_total_len = ext_total_len,
            .last_ext = last_ext,
            .ip_proto = @enumFromInt(ip_proto),
        };

        return meta;
    }

    pub fn get_extensions(self: *IPv6Layer, allocator: Allocator) Allocator.Error!?ExtensionHeaders {
        var offset: usize = IPv6HeaderSize;
        var current_next: u8 = self.get_immutable_header().next_header;

        const data = self.get_data();

        var end: usize = data.len;

        if (data.len <= IPv6HeaderSize) {
            return null;
        }

        if (self.owner.is_packet_owned()) {
            end = self.owner.packet_layer.length;
        }

        var extensions: ExtensionHeaders = (.{});

        var cur: ?*ExtensionHeader = null;

        while (current_next != @intFromEnum(NextHeader.NoNext) and
            current_next != @intFromEnum(NextHeader.TCP) and
            current_next != @intFromEnum(NextHeader.UDP) and
            current_next != @intFromEnum(NextHeader.ICMP) and
            current_next != @intFromEnum(NextHeader.ICMPv6))
        {
            if (offset >= end) break;

            const next_header_type: NextHeader = @enumFromInt(current_next);

            const ext = try allocator.create(ExtensionHeader);

            switch (next_header_type) {
                .HopByHop => {
                    const next_header = data[offset];
                    const hdr_ext_len = data[offset + 1];
                    const ext_len = (@as(u16, hdr_ext_len) + 1) * 8;

                    ext.* = ExtensionHeader.init(
                        next_header_type,
                        null,
                        null,
                        TLVOwner{ .layer = &self.owner },
                    );

                    current_next = next_header;
                    offset += ext_len;
                },
                .DestOpts => {
                    const next_header = data[offset];
                    const hdr_ext_len = data[offset + 1];
                    const ext_len = (@as(u16, hdr_ext_len) + 1) * 8;

                    ext.* = ExtensionHeader.init(
                        next_header_type,
                        null,
                        null,
                        TLVOwner{ .layer = &self.owner },
                    );

                    current_next = next_header;
                    offset += ext_len;
                },
                .Routing => {
                    const next_header = data[offset];
                    const hdr_ext_len = data[offset + 1];
                    const ext_len = (@as(u16, hdr_ext_len) + 1) * 8;

                    ext.* = ExtensionHeader.init(
                        next_header_type,
                        null,
                        null,
                        TLVOwner{ .layer = &self.owner },
                    );

                    current_next = next_header;
                    offset += ext_len;
                },
                .Fragment => {
                    ext.* = ExtensionHeader.init(
                        next_header_type,
                        null,
                        null,
                        TLVOwner{ .layer = &self.owner },
                    );

                    current_next = data[offset];
                    offset += 8;
                },
                .AH => {
                    const payload_len = data[offset + 1]; // in 32-bit words minus 2
                    const ext_len = (payload_len + 2) * 4;

                    ext.* = ExtensionHeader.init(
                        next_header_type,
                        null,
                        null,
                        TLVOwner{ .layer = &self.owner },
                    );

                    current_next = data[offset];
                    offset += ext_len;
                },
                .ESP => {
                    ext.* = ExtensionHeader.init(
                        next_header_type,
                        null,
                        null,
                        TLVOwner{ .layer = &self.owner },
                    );

                    // ESP typically ends at the packet end, so break
                    current_next = @intFromEnum(NextHeader.NoNext);
                    offset = data.len; // Consume the rest
                },
                .Mobility => {
                    ext.* = ExtensionHeader.init(
                        next_header_type,
                        null,
                        null,
                        TLVOwner{ .layer = &self.owner },
                    );

                    current_next = data[offset];

                    offset += 8;
                },
                .HostIdentity => {
                    ext.* = ExtensionHeader.init(
                        next_header_type,
                        null,
                        null,
                        TLVOwner{ .layer = &self.owner },
                    );

                    current_next = data[offset];
                    offset += 8;
                },
                .Shim6 => {
                    ext.* = ExtensionHeader.init(
                        next_header_type,
                        null,
                        null,
                        TLVOwner{ .layer = &self.owner },
                    );

                    current_next = data[offset];
                    offset += 8; // Assuming minimal header size
                },
                else => {
                    print("Unknown extension header type: {} (0x{x}). Breaking.\n", .{
                        next_header_type,
                        @intFromEnum(next_header_type),
                    });
                    break;
                },
            }

            if (cur) |e| {
                e.set_next(ext);
                ext.set_prev(e);
            }

            cur = ext;

            if (extensions.first == null) {
                extensions.first = cur;
            }

            extensions.ext_header_count += 1;
        }

        if (extensions.ext_header_count > 0) {
            extensions.last = cur;
            return extensions;
        }

        return null;
    }

    pub const ModError = error{
        CannotSetTransport,
        CannotSetNoNext,
    };

    /// This methods error union will be either a Modification Error (invalid extension being added)
    /// or an allocator error - OOM etc
    pub fn add_extension(self: *IPv6Layer, ext: *ExtensionHeader) Allocator.Error!void {
        const data = self.get_data();

        const len: usize = if (self.owner.is_packet_owned()) self.owner.packet_layer.length else data.len;

        var offset: usize = len - 1;
        while (offset > IPv6HeaderSize) {
            if (data[offset] == @intFromEnum(NextHeader.NoNext)) {
                break;
            }

            offset -= 1;
        }

        const next_header = data[offset];

        const ext_len = ext.get_data().len;

        const ext_buf = try self.owner.extend_layer(len, ext_len);

        @memmove(ext_buf, ext.get_data());

        const non_exts: [5]u8 = .{
            @intFromEnum(NextHeader.NoNext),
            @intFromEnum(NextHeader.TCP),
            @intFromEnum(NextHeader.UDP),
            @intFromEnum(NextHeader.ICMP),
            @intFromEnum(NextHeader.ICMPv6),
        };

        for (non_exts) |non_ext| {
            if (self.get_immutable_header().next_header == non_ext) {
                self.get_mutable_header().next_header = @intFromEnum(ext.get_type());
                ext_buf[0] = non_ext;

                const payload_len = self.get_immutable_header().get_payload_length();

                self.get_mutable_header().set_payload_length(payload_len + @as(u16, @intCast(ext_len)));

                return;
            }
        }

        self.get_data()[offset] = @intFromEnum(ext.get_type());

        ext_buf[0] = next_header;

        const payload_len = self.get_immutable_header().get_payload_length();

        self.get_mutable_header().set_payload_length(payload_len + @as(u16, @intCast(ext_len)));
    }

    pub fn remove_extension(self: *IPv6Layer, ext: *ExtensionHeader) Allocator.Error!void {
        const data = self.get_data();

        const len: usize = if (self.owner.is_packet_owned()) self.owner.packet_layer.length else data.len;

        const ext_type: u8 = @intFromEnum(ext.get_type());

        var offset: usize = IPv6HeaderSize;

        if (self.get_immutable_header().next_header != ext_type) {
            while (offset < len) {
                if (data[offset] == ext_type) {
                    break;
                }

                offset += 1;
            }
        }

        const ext_len = ext.get_data().len;

        const next_header: u8 = if (ext_type == @intFromEnum(NextHeader.ESP)) @intFromEnum(NextHeader.NoNext) else ext.get_data()[0];

        if (offset == IPv6HeaderSize) {
            try self.owner.shorten_layer(offset, ext_len);
            self.get_mutable_header().next_header = next_header;

            const payload_len = self.get_immutable_header().get_payload_length();

            self.get_mutable_header().set_payload_length(payload_len - @as(u16, @intCast(ext_len)));
            return;
        }

        var off: usize = offset;

        while (off > IPv6HeaderSize) {
            if (off == ext_type) {
                break;
            }
            off -= 1;
        }

        try self.owner.shorten_layer(offset + ext_len, ext_len);

        self.get_data()[off - ext_len] = next_header;

        const payload_len = self.get_immutable_header().get_payload_length();

        self.get_mutable_header().set_payload_length(payload_len - @as(u16, @intCast(ext_len)));
    }

    /// order IPv6 extensions in the RFC8200 recommended order.
    /// Ref: https://www.ietf.org/rfc/inline-errata/rfc8200.html 4.1
    //   pub fn order_exts(self: *IPv6Layer) void {
    //       _ = self;
    //   }

    pub fn validate_layer(self: *IPv6Layer) void {
        if (self.owner.is_packet_owned()) {
            if (self.owner.packet_layer.next_layer) |next_layer| {
                const protocol = next_layer.layer_iface.get_protocol();
                _ = protocol;
            }
        }
    }

    pub fn get_ip_protocol(self: *const IPv6Layer) IPProtocol {
        const nh: NextHeader = @enumFromInt(self.get_immutable_header().next_header);

        if (nh != NextHeader.NoNext) {
            switch (nh) {
                .ICMP => return IPProtocol.ICMP,
                .IGMP => return IPProtocol.IGMP,
                .TCP => return IPProtocol.TCP,
                .UDP => return IPProtocol.UDP,
                .ICMPv6 => return IPProtocol.ICMPv6,
                .ESP => return IPProtocol.ESP,
                .AH => return IPProtocol.AH,

                else => {},
            }
        }

        const data: []const u8 = self.get_data();

        const len: usize = if (self.owner.is_packet_owned()) self.owner.packet_layer.length else data.len;

        if (len > IPv6HeaderSize) {
            var offset: usize = IPv6HeaderSize;

            while (offset < len) {
                const next_hdr = data[offset];

                switch (next_hdr) {
                    @intFromEnum(NextHeader.ICMP) => return IPProtocol.ICMP,
                    @intFromEnum(NextHeader.IGMP) => return IPProtocol.IGMP,
                    @intFromEnum(NextHeader.TCP) => return IPProtocol.TCP,
                    @intFromEnum(NextHeader.UDP) => return IPProtocol.UDP,
                    @intFromEnum(NextHeader.ICMPv6) => return IPProtocol.ICMPv6,
                    @intFromEnum(NextHeader.ESP) => return IPProtocol.ESP,
                    @intFromEnum(NextHeader.AH) => return IPProtocol.AH,

                    else => {},
                }

                if (offset + 8 <= len) {
                    offset += 8;
                } else {
                    break;
                }
            }
        }

        return IPProtocol.Unknown;
    }

    pub fn get_next_layer_type(self: *const IPv6Layer, layer: *Packet.Layer) LayerError!?LayerIface {
        const data = self.get_data();

        if (data.len < IPv6HeaderSize) return LayerError.BufferTooSmall;

        const ip_proto = self.get_ip_protocol();

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

    pub fn get_protocol(self: *IPv6Layer) tcp_ip_protocol {
        _ = self;
        return tcp_ip_protocol.ipv6;
    }

    pub fn deinit(self: *IPv6Layer) void {
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
