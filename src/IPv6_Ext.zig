const std = @import("std");
const IPv6 = @import("IPv6.zig");
const TLVOwner = @import("Layer.zig").TLVOwner;

const Allocator = std.mem.Allocator;
const panic = std.debug.panic;

// IPv6 Next Header Types
pub const NextHeader = enum(u8) {
    /// Contains optional information that must be examined by every node along the packet’s path.
    /// Examples: Router Alert option, jumbo payload option.
    /// Used for network services like multicast routing or diagnostic tools.
    HopByHop = 0,
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17,
    IPv6 = 41,
    /// Specifies a list of one or more intermediate nodes (waypoints) that the packet must visit.
    /// Used for source routing, Mobile IPv6 route optimization, and multicast distribution.
    Routing = 43,
    /// Enables fragmentation of packets in IPv6 (which normally doesn’t allow routers to fragment).
    /// Carries fragment offset, identification, and more-fragments flag.
    Fragment = 44,
    /// Provides confidentiality (encryption), optional authentication, and integrity protection.
    /// Used in IPsec VPNs.
    ESP = 50,
    /// Provides integrity, authentication, and optional anti-replay protection for IPv6 packets.
    /// Used in IPsec for secure communications. Does not provide encryption.
    AH = 51,
    /// IPv6 Protocol version of ICMP
    ICMPv6 = 58,
    /// Indicates the end of the header chain.
    /// Used when no upper-layer protocol exists (e.g., ICMPv6 errors).
    NoNext = 59,
    /// Contains optional information intended only for the final destination node(s).
    /// Can appear twice: before a routing header (intermediate) or before the upper-layer header (final).
    /// Examples: home address option for Mobile IPv6.
    DestOpts = 60,
    Mobility = 135,
    ///Provides a cryptographic identifier for a host, decoupling host identity from IP addresses.
    ///Enables mobility, multi-homing, and secure host-to-host communication without changing IP addresses.
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
pub const ExtensionHeader = union(enum) {
    hop_by_hop: HopByHop,
    dest_opts: DestinationOpts,
    frag_header: FragmentHeader,
    routing: Routing,
    esp: ESP,
    mobility: Mobility,
    host_identity: HostIdentity,
    shim6: Shim6,

    pub fn init(header_type: NextHeader, next: ?*ExtensionHeader, prev: ?*ExtensionHeader, owner: TLVOwner) ExtensionHeader {
        switch (header_type) {
            .HopByHop => {
                return ExtensionHeader{ .hop_by_hop = HopByHop{
                    .owner = owner,
                    .prev = prev,
                    .next = next,
                } };
            },
            .DestOpts => {
                return ExtensionHeader{ .dest_opts = DestinationOpts{
                    .owner = owner,
                    .prev = prev,
                    .next = next,
                } };
            },
            .Fragment => {
                return ExtensionHeader{ .frag_header = FragmentHeader{
                    .owner = owner,
                    .prev = prev,
                    .next = next,
                } };
            },
            .Routing => {
                return ExtensionHeader{ .routing = Routing{
                    .owner = owner,
                    .prev = prev,
                    .next = next,
                } };
            },
            .ESP => {
                return ExtensionHeader{ .esp = ESP{
                    .owner = owner,
                    .prev = prev,
                    .next = next,
                } };
            },
            .Mobility => {
                return ExtensionHeader{ .mobility = Mobility{
                    .owner = owner,
                    .prev = prev,
                    .next = next,
                } };
            },
            .HostIdentity => {
                return ExtensionHeader{ .host_identity = HostIdentity{
                    .owner = owner,
                    .prev = prev,
                    .next = next,
                } };
            },
            .Shim6 => {
                return ExtensionHeader{ .shim6 = Shim6{
                    .owner = owner,
                    .prev = prev,
                    .next = next,
                } };
            },
            else => {
                panic("unhandled header type: {}\n", .{header_type});
            },
        }
    }

    pub fn get_type(self: *ExtensionHeader) NextHeader {
        return switch (self.*) {
            inline else => |*ext| return ext.get_ext_type(),
        };
    }

    pub fn get_layer(self: *ExtensionHeader) *IPv6.IPv6Layer {
        return switch (self.*) {
            inline else => |*ext| ext.layer,
        };
    }

    pub fn get_length(self: *ExtensionHeader) usize {
        return switch (self.*) {
            inline else => |*ext| ext.get_length(),
        };
    }

    pub fn set_offset(self: *ExtensionHeader, offset: usize) void {
        return switch (self.*) {
            inline else => |*ext| ext.offset = offset,
        };
    }

    pub fn set_length(self: *ExtensionHeader, length: usize) void {
        return switch (self.*) {
            inline else => |*ext| ext.length = length,
        };
    }

    pub fn get_data(self: *ExtensionHeader) []const u8 {
        return switch (self.*) {
            inline else => |*ext| ext.get_data(),
        };
    }

    pub fn get_data_mut(self: *ExtensionHeader) []u8 {
        return switch (self.*) {
            inline else => |*ext| ext.get_data_mut(),
        };
    }

    pub fn next_ext(self: *ExtensionHeader) NextHeader {
        return @enumFromInt(self.get_data()[0]);
    }

    pub fn get_next(self: *ExtensionHeader) ?*ExtensionHeader {
        return switch (self.*) {
            inline else => |*ext| ext.next,
        };
    }

    pub fn set_next(self: *ExtensionHeader, next: *ExtensionHeader) void {
        return switch (self.*) {
            inline else => |*ext| ext.next = next,
        };
    }

    pub fn get_prev(self: *ExtensionHeader) ?*ExtensionHeader {
        return switch (self.*) {
            inline else => |*ext| ext.prev,
        };
    }

    pub fn set_prev(self: *ExtensionHeader, prev: *ExtensionHeader) void {
        return switch (self.*) {
            inline else => |*ext| ext.prev = prev,
        };
    }
};

pub const ExtensionHeaders = struct {
    first: ?*ExtensionHeader = null,
    last: ?*ExtensionHeader = null,
    ext_header_count: usize = 0,

    pub fn deinit(self: *ExtensionHeaders, allocator: Allocator) void {
        var cur = self.first;
        while (cur) |ext| {
            const next = ext.get_next();
            allocator.destroy(ext);
            cur = next;
        }

        self.first = null;
        self.last = null;
        self.ext_header_count = 0;
    }
};

/// Used by Hop-by-Hop and Destination.
/// Hop-by-Hop: Every router along the path process the option
/// Destination: Only the destination host processes the option
pub const OptionType = enum(u8) {
    // Padding Options
    /// Pad1 [RFC8200]
    PAD1 = 0x00,
    /// PadN [RFC8200]
    PADN = 0x01,

    // Standard Options
    /// Jumbo Payload [RFC2675]
    JUMBO_PAYLOAD = 0xC2,
    /// RPL Option [RFC9008]
    RPL = 0x23,
    /// Tunnel Encapsulation Limit [RFC2473]
    TUNNEL_ENCAPSULATION_LIMIT = 0x04,
    /// Router Alert (DEPRECATED for new protocols) [RFC2711][RFC9805]
    ROUTER_ALERT = 0x05,
    /// Quick-Start [RFC4782]
    QUICK_START = 0x26,
    /// Commercial Aerospace Lab Internet IP Security Option [RFC5570]
    CALIPSO = 0x07,
    /// SMF Duplicate Packet Detection [RFC6621]
    SMF_DPD = 0x08,
    /// Home Address [RFC6275]
    HOME_ADDRESS = 0xC9,
    /// ILNP Nonce [RFC6744]
    ILNP_NONCE = 0x8B,
    /// Line-Identification Option [RFC6788]
    LINE_IDENTIFICATION = 0x8C,
    /// MPL Option [RFC7731]
    MPL = 0x6D,
    /// IP DFF [RFC6971]
    IP_DFF = 0xEE,
    /// Performance and Diagnostic Metrics (PDM) [RFC8250]
    PDM = 0x0F,
    /// Minimum Path MTU Hop-by-Hop Option [RFC9268]
    MIN_MTU = 0x30,
    /// IOAM (Alternate marking for passive per-hop monitoring)
    IOAM = 0x11,
    /// AltMark [RFC9343]
    ALTERNATE_MARKING = 0x12,

    // Reserved for Experiments (RFC3692-style) [RFC4727]
    /// act=00, chg=0
    EXPERIMENT_1 = 0x1E,
    /// act=00, chg=1
    EXPERIMENT_2 = 0x3E,
    /// act=01, chg=0
    EXPERIMENT_3 = 0x5E,
    /// act=01, chg=1
    EXPERIMENT_4 = 0x7E,
    /// act=10, chg=0
    EXPERIMENT_5 = 0x9E,
    /// act=10, chg=1
    EXPERIMENT_6 = 0xBE,
    /// act=11, chg=0
    EXPERIMENT_7 = 0xDE,
    /// act=11, chg=1
    EXPERIMENT_8 = 0xFE,
};

pub const HopByHop = struct {
    owner: TLVOwner,
    next: ?*ExtensionHeader = null,
    prev: ?*ExtensionHeader = null,

    const MinLength = 8;

    pub fn init(owner: TLVOwner) !HopByHop {
        switch (owner) {
            .owned_buffer => {
                var self = HopByHop{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < HopByHop.MinLength) {
                    const hbh_data = try self.owner.owned_buffer.extend(buffer_len, HopByHop.MinLength);

                    @memset(hbh_data, 0);

                    hbh_data[0] = @intFromEnum(NextHeader.NoNext);
                    hbh_data[3] = 2;
                } else {
                    if (self.owner.owned_buffer.buffer.items[0] != @intFromEnum(NextHeader.HopByHop)) {
                        return error.TypeByteInvalid;
                    }
                }

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    pub fn get_offset(self: *HopByHop) usize {
        var offset: usize = 0;

        if (self.owner.is_layer_owned()) {
            offset = IPv6.IPv6HeaderSize;

            var cur = self.prev;
            while (cur) |prev| {
                offset += prev.get_length();
                cur = prev.get_prev();
            }
        }

        return offset;
    }

    pub fn get_data(self: *HopByHop) []const u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const hdr_ext_len = self.owner.get_data()[absolute_offset + 1];
        const ext_len = (@as(u16, hdr_ext_len) + 1) * 8;

        return data[absolute_offset .. absolute_offset + ext_len];
    }

    fn get_data_mut(self: *HopByHop) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const hdr_ext_len = self.get_data()[absolute_offset + 1];

        const ext_len = (@as(u16, hdr_ext_len) + 1) * 8;

        return data[absolute_offset .. absolute_offset + ext_len];
    }

    pub fn get_opt_type(self: *HopByHop) OptionType {
        return @enumFromInt(self.get_data()[2]);
    }

    pub fn set_opt_type(self: *HopByHop, opt: OptionType) void {
        self.get_data_mut()[2] = @intFromEnum(opt);
    }

    pub fn get_opt_len(self: *HopByHop) u8 {
        return self.get_data()[3];
    }

    pub fn get_opt_value(self: *HopByHop) u16 {
        return std.mem.readInt(u16, self.get_data()[4..6], .big);
    }

    pub fn set_opt_value(self: *HopByHop, val: u16) void {
        std.mem.writeInt(u16, self.get_data_mut()[4..6], val, .big);
    }

    pub fn get_pad_option(self: *HopByHop) OptionType {
        return @enumFromInt(self.get_data()[6]);
    }

    /// Provide either:
    /// 0 - PAD1
    /// 1 - PADN
    pub fn set_pad_option(self: *HopByHop, opt: u1) void {
        self.get_data_mut()[6] = opt;
    }

    pub fn get_pad_len(self: *HopByHop) u8 {
        return self.get_data()[7];
    }

    pub fn get_length(self: *HopByHop) usize {
        const hdr_ext_len = self.get_data()[1];
        const ext_len = (@as(u16, hdr_ext_len) + 1) * 8;
        return @intCast(ext_len);
    }

    pub fn get_ext_type(self: HopByHop) NextHeader {
        _ = self;
        return .HopByHop;
    }

    pub fn deinit(self: *HopByHop) void {
        self.owner.deinit();
    }
};

pub const DestinationOpts = struct {
    owner: TLVOwner,
    next: ?*ExtensionHeader = null,
    prev: ?*ExtensionHeader = null,

    const MinLength = 8;

    pub fn init(owner: TLVOwner) !DestinationOpts {
        switch (owner) {
            .owned_buffer => {
                var self = DestinationOpts{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < DestinationOpts.MinLength) {
                    const hbh_data = try self.owner.owned_buffer.extend(buffer_len, DestinationOpts.MinLength);

                    @memset(hbh_data, 0);

                    hbh_data[0] = @intFromEnum(NextHeader.NoNext);
                    hbh_data[3] = 2;
                } else {
                    if (self.owner.owned_buffer.buffer.items[0] != @intFromEnum(NextHeader.DestOpts)) {
                        return error.TypeByteInvalid;
                    }
                }

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    pub fn get_offset(self: *DestinationOpts) usize {
        var offset: usize = 0;

        if (self.owner.is_layer_owned()) {
            offset = IPv6.IPv6HeaderSize;

            var cur = self.prev;
            while (cur) |prev| {
                offset += prev.get_length();
                cur = prev.get_prev();
            }
        }

        return offset;
    }

    pub fn get_data(self: *DestinationOpts) []const u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const hdr_ext_len = self.owner.get_data()[absolute_offset + 1];
        const ext_len = (@as(u16, hdr_ext_len) + 1) * 8;

        return data[absolute_offset .. absolute_offset + ext_len];
    }

    fn get_data_mut(self: *DestinationOpts) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const hdr_ext_len = self.get_data()[absolute_offset + 1];

        const ext_len = (@as(u16, hdr_ext_len) + 1) * 8;

        return data[absolute_offset .. absolute_offset + ext_len];
    }

    pub fn get_opt_type(self: *DestinationOpts) OptionType {
        return @enumFromInt(self.get_data()[2]);
    }

    pub fn set_opt_type(self: *DestinationOpts, opt: OptionType) void {
        self.get_data_mut()[2] = @intFromEnum(opt);
    }

    pub fn get_opt_len(self: *DestinationOpts) u8 {
        return self.get_data()[3];
    }

    pub fn get_opt_value(self: *DestinationOpts) u16 {
        return std.mem.readInt(u16, self.get_data()[4..6], .big);
    }

    pub fn set_opt_value(self: *DestinationOpts, val: u16) void {
        std.mem.writeInt(u16, self.get_data_mut()[4..6], val, .big);
    }

    pub fn get_pad_option(self: *DestinationOpts) OptionType {
        return @enumFromInt(self.get_data()[6]);
    }

    /// Provide either:
    /// 0 - PAD1
    /// 1 - PADN
    pub fn set_pad_option(self: *DestinationOpts, opt: u1) void {
        self.get_data_mut()[6] = opt;
    }

    pub fn get_pad_len(self: *DestinationOpts) u8 {
        return self.get_data()[7];
    }

    pub fn get_length(self: *DestinationOpts) usize {
        const hdr_ext_len = self.get_data()[1];
        const ext_len = (@as(u16, hdr_ext_len) + 1) * 8;
        return @intCast(ext_len);
    }

    pub fn get_ext_type(self: DestinationOpts) NextHeader {
        _ = self;
        return .DestOpts;
    }

    pub fn deinit(self: *DestinationOpts) void {
        self.owner.deinit();
    }
};

// IPv6 Fragment Header
const FragmentHeader = struct {
    //   next_header: u8 = 0,
    //   reserved: u8 = 0,
    //   fragment_off_flags: u16 = 0,
    //   identification: u32 = 0,

    owner: TLVOwner,
    next: ?*ExtensionHeader = null,
    prev: ?*ExtensionHeader = null,

    const IPV6_FRAG_OFFSET_MASK: u16 = 0xfff8; // top 13 bits
    const IPV6_FRAG_RES_MASK: u16 = 0x0006; // next 2 bits
    const IPV6_FRAG_M_MASK: u16 = 0x0001; // last bit

    pub fn init(owner: TLVOwner) FragmentHeader {
        return FragmentHeader{ .owner = owner };
    }

    fn get_offset(self: *FragmentHeader) usize {
        var offset: usize = 0;

        if (self.owner.is_layer_owned()) {
            offset = IPv6.IPv6HeaderSize;

            var cur = self.prev;
            while (cur) |prev| {
                offset += prev.get_length();
                cur = prev.get_prev();
            }
        }

        return offset;
    }

    pub fn get_length(self: *FragmentHeader) usize {
        const hdr_ext_len = self.get_data()[1];
        const ext_len = (@as(u16, hdr_ext_len) + 1) * 8;
        return @intCast(ext_len);
    }

    pub fn get_data(self: *FragmentHeader) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const hdr_ext_len = self.owner.get_data()[offset + 1];
        const ext_len = (@as(u16, hdr_ext_len) + 1) * 8;

        return data[offset .. offset + ext_len];
    }

    fn get_data_mut(self: *FragmentHeader) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const hdr_ext_len = self.get_data()[absolute_offset + 1];

        const ext_len = (@as(u16, hdr_ext_len) + 1) * 8;

        return data[absolute_offset .. absolute_offset + ext_len];
    }

    pub fn getFragmentOffset(self: *FragmentHeader) u13 {
        const v = std.mem.readInt(u16, &self.get_data()[2..4], .big);
        return @intCast((v & IPV6_FRAG_OFFSET_MASK) >> 3);
    }

    pub fn setFragmentOffset(self: *FragmentHeader, offset: u13) void {
        const v: u16 = std.mem.bytesToValue(u16, self.get_data_mut()[2..4]);

        // clear old offset
        v &= ~IPV6_FRAG_OFFSET_MASK;

        // set new offset (shifted into position)
        v |= (@as(u16, offset) << 3) & IPV6_FRAG_OFFSET_MASK;

        //self.fragment_off_flags = @byteSwap(v);
    }

    pub fn getMoreFragments(self: *FragmentHeader) bool {
        const v = std.mem.readInt(u16, &self.get_data()[2..4], .big);
        return (v & IPV6_FRAG_M_MASK) != 0;
    }

    pub fn setMoreFragments(self: *FragmentHeader, more: bool) void {
        var v = std.mem.bytesAsValue(u16, &self.get_data()[2..4]);

        // clear flag
        v &= ~IPV6_FRAG_M_MASK;

        // set if needed
        if (more) {
            v |= IPV6_FRAG_M_MASK;
        }
    }

    pub fn get_ext_type(self: FragmentHeader) NextHeader {
        _ = self;
        return .Fragment;
    }
};

pub const AuthenticationHeader = struct {
    owner: TLVOwner,
    next: ?*ExtensionHeader = null,
    prev: ?*ExtensionHeader = null,

    const SPI_OFFSET = 4;
    const SEQ_NUM_OFFSET = 8;
    const ICV_OFFSET = 12;

    pub fn init(owner: TLVOwner) AuthenticationHeader {
        return AuthenticationHeader{ .owner = owner };
    }

    fn get_offset(self: *AuthenticationHeader) usize {
        var offset: usize = 0;

        if (self.owner.is_layer_owned()) {
            offset = IPv6.IPv6HeaderSize;

            var cur = self.prev;
            while (cur) |prev| {
                offset += prev.get_length();
                cur = prev.get_prev();
            }
        }

        return offset;
    }

    pub fn get_length(self: *AuthenticationHeader) usize {
        const hdr_ext_len = self.get_data()[1];
        const ext_len = (@as(u16, hdr_ext_len) + 1) * 8;
        return @intCast(ext_len);
    }

    pub fn get_data(self: *AuthenticationHeader) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const hdr_ext_len = self.owner.get_data()[offset + 1];
        const ext_len = (@as(u16, hdr_ext_len) + 1) * 8;

        return data[offset .. offset + ext_len];
    }

    fn get_data_mut(self: *AuthenticationHeader) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const hdr_ext_len = self.get_data()[absolute_offset + 1];

        const ext_len = (@as(u16, hdr_ext_len) + 1) * 8;

        return data[absolute_offset .. absolute_offset + ext_len];
    }

    pub fn get_payload_len(self: *AuthenticationHeader) u8 {
        return self.get_data()[1];
    }

    /// Get the Security Parameters Index
    pub fn get_spi(self: *AuthenticationHeader) u32 {
        return std.mem.readInt(u32, &self.get_data[AuthenticationHeader.SPI_OFFSET..8], .big);
    }

    pub fn get_seq_num(self: *AuthenticationHeader) u32 {
        return std.mem.readInt(u32, &self.get_data[AuthenticationHeader.SEQ_NUM_OFFSET..12], .big);
    }

    pub fn get_icv(self: *AuthenticationHeader) []const u8 {
        return self.get_data[AuthenticationHeader.ICV_OFFSET .. AuthenticationHeader.ICV_OFFSET + self.get_payload_len()];
    }

    pub fn get_ext_type(self: AuthenticationHeader) NextHeader {
        _ = self;
        return .AH;
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

// IPv6 Routing Header
pub const Routing = struct {
    owner: TLVOwner,
    next: ?*ExtensionHeader = null,
    prev: ?*ExtensionHeader = null,

    const MIN_LENGTH = 8;

    pub fn init(owner: TLVOwner) Routing {
        return Routing{ .owner = owner };
    }

    fn get_offset(self: *Routing) usize {
        var offset: usize = 0;

        if (self.owner.is_layer_owned()) {
            offset = IPv6.IPv6HeaderSize;

            var cur = self.prev;
            while (cur) |prev| {
                offset += prev.get_length();
                cur = prev.get_prev();
            }
        }

        return offset;
    }

    pub fn get_data(self: *Routing) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const hdr_ext_len = self.owner.get_data()[offset + 1];
        const ext_len = (@as(u16, hdr_ext_len) + 1) * 8;

        return data[offset .. offset + ext_len];
    }

    fn get_data_mut(self: *Routing) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const hdr_ext_len = self.get_data()[absolute_offset + 1];

        const ext_len = (@as(u16, hdr_ext_len) + 1) * 8;

        return data[absolute_offset .. absolute_offset + ext_len];
    }

    pub fn get_length(self: *Routing) usize {
        const hdr_ext_len = self.get_data()[1];
        const ext_len = (@as(u16, hdr_ext_len) + 1) * 8;
        return @intCast(ext_len);
    }

    pub fn get_routing_type(self: *Routing) RoutingType {
        return @enumFromInt(self.get_data()[2]);
    }

    pub fn set_routing_type(self: *Routing, rt: RoutingType) void {
        self.get_data_mut()[2] = @intFromEnum(rt);
    }

    pub fn get_segments_left(self: *Routing) u8 {
        return self.get_data()[3];
    }

    pub fn set_segments_left(self: *Routing, left: u8) void {
        self.get_data_mut()[3] = left;
    }

    pub fn get_ext_type(self: Routing) NextHeader {
        _ = self;
        return .Routing;
    }
};

// ESP (Encapsulating Security Payload)
pub const ESP = struct {
    owner: TLVOwner,
    next: ?*ExtensionHeader = null,
    prev: ?*ExtensionHeader = null,

    const SPI_OFFSET = 0;
    const SEQ_NUM_OFFSET = 4;

    pub fn init(owner: TLVOwner) ESP {
        return ESP{ .owner = owner };
    }

    fn get_offset(self: *ESP) usize {
        var offset: usize = 0;

        if (self.owner.is_layer_owned()) {
            offset = IPv6.IPv6HeaderSize;

            var cur = self.prev;
            while (cur) |prev| {
                offset += prev.get_length();
                cur = prev.get_prev();
            }
        }

        return offset;
    }

    pub fn get_data(self: *ESP) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        // ESP header is 8 bytes + variable payload + trailer
        return data[offset..];
    }

    fn get_data_mut(self: *ESP) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        return data[absolute_offset..];
    }

    pub fn get_length(self: *ESP) usize {
        // ESP length is variable, determined by the data
        return self.get_data().len;
    }

    /// Get the Security Parameters Index
    pub fn get_spi(self: *ESP) u32 {
        return std.mem.readInt(u32, self.get_data()[ESP.SPI_OFFSET..ESP.SEQ_NUM_OFFSET], .big);
    }

    /// Get the sequence number
    pub fn get_seq_num(self: *ESP) u32 {
        return std.mem.readInt(u32, self.get_data()[ESP.SEQ_NUM_OFFSET..8], .big);
    }

    /// Get the encrypted payload
    pub fn get_payload(self: *ESP) []const u8 {
        return self.get_data()[8..];
    }

    pub fn get_ext_type(self: ESP) NextHeader {
        _ = self;
        return .ESP;
    }
};

// Mobility Header (Mobile IPv6)
pub const Mobility = struct {
    owner: TLVOwner,
    next: ?*ExtensionHeader = null,
    prev: ?*ExtensionHeader = null,

    const MIN_LENGTH = 8;

    pub fn init(owner: TLVOwner) Mobility {
        return Mobility{ .owner = owner };
    }

    fn get_offset(self: *Mobility) usize {
        var offset: usize = 0;

        if (self.owner.is_layer_owned()) {
            offset = IPv6.IPv6HeaderSize;

            var cur = self.prev;
            while (cur) |prev| {
                offset += prev.get_length();
                cur = prev.get_prev();
            }
        }

        return offset;
    }

    pub fn get_data(self: *Mobility) []const u8 {
        const data = self.owner.get_data();
        const offset: usize = self.get_offset();
        return data[offset..];
    }

    fn get_data_mut(self: *Mobility) []u8 {
        const data = self.owner.get_data();
        const absolute_offset: usize = self.get_offset();
        return data[absolute_offset..];
    }

    pub fn get_length(self: *Mobility) usize {
        return self.get_data().len;
    }

    pub fn get_mobility_type(self: *Mobility) u8 {
        return self.get_data()[0];
    }

    pub fn get_checksum(self: *Mobility) u16 {
        return std.mem.readInt(u16, self.get_data()[2..4], .big);
    }

    pub fn get_ext_type(self: Mobility) NextHeader {
        _ = self;
        return .Mobility;
    }
};

// Host Identity Protocol
pub const HostIdentity = struct {
    owner: TLVOwner,
    next: ?*ExtensionHeader = null,
    prev: ?*ExtensionHeader = null,

    pub fn init(owner: TLVOwner) HostIdentity {
        return HostIdentity{ .owner = owner };
    }

    fn get_offset(self: *HostIdentity) usize {
        var offset: usize = 0;

        if (self.owner.is_layer_owned()) {
            offset = IPv6.IPv6HeaderSize;

            var cur = self.prev;
            while (cur) |prev| {
                offset += prev.get_length();
                cur = prev.get_prev();
            }
        }

        return offset;
    }

    pub fn get_data(self: *HostIdentity) []const u8 {
        const data = self.owner.get_data();
        const offset: usize = self.get_offset();
        return data[offset..];
    }

    fn get_data_mut(self: *HostIdentity) []u8 {
        const data = self.owner.get_data();
        const absolute_offset: usize = self.get_offset();
        return data[absolute_offset..];
    }

    pub fn get_length(self: *HostIdentity) usize {
        return self.get_data().len;
    }

    pub fn get_ext_type(self: HostIdentity) NextHeader {
        _ = self;
        return .HostIdentity;
    }
};

// Shim6 Protocol
pub const Shim6 = struct {
    owner: TLVOwner,
    next: ?*ExtensionHeader = null,
    prev: ?*ExtensionHeader = null,

    pub fn init(owner: TLVOwner) Shim6 {
        return Shim6{ .owner = owner };
    }

    fn get_offset(self: *Shim6) usize {
        var offset: usize = 0;

        if (self.owner.is_layer_owned()) {
            offset = IPv6.IPv6HeaderSize;

            var cur = self.prev;
            while (cur) |prev| {
                offset += prev.get_length();
                cur = prev.get_prev();
            }
        }

        return offset;
    }

    pub fn get_data(self: *Shim6) []const u8 {
        const data = self.owner.get_data();
        const offset: usize = self.get_offset();
        return data[offset..];
    }

    fn get_data_mut(self: *Shim6) []u8 {
        const data = self.owner.get_data();
        const absolute_offset: usize = self.get_offset();
        return data[absolute_offset..];
    }

    pub fn get_length(self: *Shim6) usize {
        return self.get_data().len;
    }

    pub fn get_ext_type(self: Shim6) NextHeader {
        _ = self;
        return .Shim6;
    }
};
