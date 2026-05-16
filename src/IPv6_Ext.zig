const std = @import("std");
const IPv6 = @import("IPv6.zig");

// IPv6 Next Header Types
pub const NextHeader = enum(u8) {
    ///Contains optional information that must be examined by every node along the packet’s path. Examples: Router Alert option, jumbo payload option. Used for network services like multicast routing or diagnostic tools.
    HopByHop = 0,
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17,
    IPv6 = 41,
    ///Specifies a list of one or more intermediate nodes (waypoints) that the packet must visit. Used for source routing, Mobile IPv6 route optimization, and multicast distribution.
    Routing = 43,
    ///Enables fragmentation of packets in IPv6 (which normally doesn’t allow routers to fragment). Carries fragment offset, identification, and more-fragments flag.
    Fragment = 44,
    ///Provides confidentiality (encryption), optional authentication, and integrity protection. Used in IPsec VPNs.
    ESP = 50,
    ///Provides integrity, authentication, and optional anti-replay protection for IPv6 packets. Used in IPsec for secure communications. Does not provide encryption.
    AH = 51,
    /// IPv6 Protocol version of ICMP
    ICMPv6 = 58,
    ///Indicates the end of the header chain. Used when no upper-layer protocol exists (e.g., ICMPv6 errors).
    NoNext = 59,
    ///Contains optional information intended only for the final destination node(s). Can appear twice: before a routing header (intermediate) or before the upper-layer header (final). Examples: home address option for Mobile IPv6.
    DestOpts = 60,
    ///Supports Mobile IPv6 operations, including binding updates, home agent registration, and mobility signaling.
    Mobility = 135,
    ///Provides a cryptographic identifier for a host, decoupling host identity from IP addresses. Enables mobility, multi-homing, and secure host-to-host communication without changing IP addresses.
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
    hbh: HopByHop,
    dst: DestinationOpts,
    // TODO: add RoutingHeader next

    pub fn init(header_type: NextHeader, offset: usize, length: usize, layer: *IPv6.IPv6Layer) ExtensionHeader {
        switch (header_type) {
            .HopByHop => {
                return ExtensionHeader{ .hbh = HopByHop.init(offset, length, layer) };
            },
            .DestOpts => {
                return ExtensionHeader{ .dst = DestinationOpts.init(offset, length, layer) };
            },
            else => {
                std.debug.panic("unhandled.\n", .{});
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

    pub fn get_offset(self: *ExtensionHeader) usize {
        return switch (self.*) {
            inline else => |*ext| ext.offset,
        };
    }

    pub fn get_length(self: *ExtensionHeader) usize {
        return switch (self.*) {
            inline else => |*ext| ext.length,
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

    pub fn get_next_extension(self: *ExtensionHeader) ?*ExtensionHeader {
        return switch (self.*) {
            inline else => |*ext| ext.next_ext,
        };
    }

    pub fn set_next_extension(self: *ExtensionHeader, next: *ExtensionHeader) void {
        return switch (self.*) {
            inline else => |*ext| ext.next_ext = next,
        };
    }
};

pub const OptionType = enum(u8) {
    // Padding Options
    PAD1 = 0x00, // Pad1 [RFC8200]
    PADN = 0x01, // PadN [RFC8200]

    // Standard Options
    JUMBO_PAYLOAD = 0xC2, // Jumbo Payload [RFC2675]
    RPL = 0x23, // RPL Option [RFC9008]
    // 0x63 is DEPRECATED (RPL Option) [RFC6553][RFC9008]

    TUNNEL_ENCAPSULATION_LIMIT = 0x04, // Tunnel Encapsulation Limit [RFC2473]
    ROUTER_ALERT = 0x05, // Router Alert (DEPRECATED for new protocols) [RFC2711][RFC9805]

    QUICK_START = 0x26, // Quick-Start [RFC4782]
    CALIPSO = 0x07, // Commercial Aerospace Lab Internet IP Security Option [RFC5570]
    SMF_DPD = 0x08, // SMF Duplicate Packet Detection [RFC6621]
    HOME_ADDRESS = 0xC9, // Home Address [RFC6275]
    // 0x8A is DEPRECATED (Endpoint Identification)

    ILNP_NONCE = 0x8B, // ILNP Nonce [RFC6744]
    LINE_IDENTIFICATION = 0x8C, // Line-Identification Option [RFC6788]
    // 0x4D is DEPRECATED

    MPL = 0x6D, // MPL Option [RFC7731]
    IP_DFF = 0xEE, // IP DFF [RFC6971]
    PDM = 0x0F, // Performance and Diagnostic Metrics (PDM) [RFC8250]
    MIN_MTU = 0x30, // Minimum Path MTU Hop-by-Hop Option [RFC9268]

    IOAM = 0x11, // IOAM (Alternate marking for passive per-hop monitoring)
    // 0x31 is an alternative for IOAM (with second-highest bit set)

    ALTERNATE_MARKING = 0x12, // AltMark [RFC9343]

    // Reserved for Experiments (RFC3692-style) [RFC4727]
    EXPERIMENT_1 = 0x1E, // act=00, chg=0
    EXPERIMENT_2 = 0x3E, // act=00, chg=1
    EXPERIMENT_3 = 0x5E, // act=01, chg=0
    EXPERIMENT_4 = 0x7E, // act=01, chg=1
    EXPERIMENT_5 = 0x9E, // act=10, chg=0
    EXPERIMENT_6 = 0xBE, // act=10, chg=1
    EXPERIMENT_7 = 0xDE, // act=11, chg=0
    EXPERIMENT_8 = 0xFE, // act=11, chg=1
};

pub const HopByHop = struct {
    offset: usize,
    length: usize,
    ext_length: u8, // Length in 8-octet units, not including first 8 octets
    next_ext: ?*ExtensionHeader = null,
    layer: *IPv6.IPv6Layer,
    const header_type: NextHeader = NextHeader.HopByHop;

    pub fn init(offset: usize, length: usize, layer: *IPv6.IPv6Layer) HopByHop {
        return HopByHop{ .offset = offset, .length = length, .ext_length = @intCast(length), .layer = layer };
    }

    pub fn get_data(self: *HopByHop) []const u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *HopByHop) []u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_action(self: *HopByHop) OptionType {
        return @enumFromInt(self.get_data()[2]);
    }

    pub fn set_action(self: *HopByHop, opt: OptionType) void {
        self.get_data_mut()[2] = @intFromEnum(opt);
    }

    pub fn get_ext_type(self: HopByHop) NextHeader {
        _ = self;
        return HopByHop.header_type;
    }
};

pub const DestinationOpts = struct {
    offset: usize,
    length: usize,
    ext_length: u8, // Length in 8-octet units, not including first 8 octets
    next_ext: ?*ExtensionHeader = null,
    layer: *IPv6.IPv6Layer,
    const header_type: NextHeader = NextHeader.DestOpts;

    pub fn init(offset: usize, length: usize, layer: *IPv6.IPv6Layer) DestinationOpts {
        return DestinationOpts{ .offset = offset, .length = length, .ext_length = @intCast(length), .layer = layer };
    }

    pub fn get_data(self: *DestinationOpts) []const u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *DestinationOpts) []u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_action(self: *DestinationOpts) OptionType {
        return @enumFromInt(self.get_data()[2]);
    }

    pub fn set_action(self: *DestinationOpts, opt: OptionType) void {
        self.get_data_mut()[2] = @intFromEnum(opt);
    }

    pub fn get_ext_type(self: DestinationOpts) NextHeader {
        _ = self;
        return DestinationOpts.header_type;
    }
};
