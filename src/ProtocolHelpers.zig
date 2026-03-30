const activeTag = @import("std").meta.activeTag;
const print = @import("std").debug.print;

const Packet = @import("Packet.zig");
const Eth = @import("Eth.zig");
const IPv4 = @import("IPv4.zig");
const IPv6 = @import("IPv6.zig");
const UDP = @import("UDPLayer.zig");
const TCP = @import("TCP.zig");
const ARP = @import("ARP.zig");

pub const ApplicationProtocols = enum(u16) {
    HTTP = 80,
    DNS = 53,
    Generic = 0,
};

pub const TransportProtocols = enum(u8) {
    TCP = 6,
    UDP = 17,
    Generic = 0,
};

pub const NetworkProtocols = enum(u4) {
    ICMP = 1,
    IPv4 = 4,
    IPv6 = 6,
    ARP = 7,
    Generic = 0,
};

pub const EthType = enum(u16) {
    IP = 0x0800,
    ARP = 0x0806,
    ETHBRIDGE = 0x6558,
    REVARP = 0x8035,
    AT = 0x809B,
    AARP = 0x80F3,
    VLAN = 0x8100,
    IPX = 0x8137,
    IPV6 = 0x86DD,
    LOOPBACK = 0x9000,
    PPPOED = 0x8863,
    PPPOES = 0x8864,
    MPLS = 0x8847,
    PPP = 0x880B,
    ROCEV1 = 0x8915,
    IEEE_802_1AD = 0x88A8,
    WAKE_ON_LAN = 0x0842,
};

pub const LinkLayerProtocols = enum(u16) { // these should be renamed to LinkLayerTypes
    NULL = 0, // Loopback (BSD/macOS)
    ETHERNET = 1, // Ethernet (most common)
    RAW = 101, // Raw IP (no link header)
    // Point-to-point / tunnels
    PPP = 9,
    PPP_ETHER = 51, // PPPoE
    // Wireless
    IEEE802_11 = 105, // WiFi
    IEEE802_11_RADIOTAP = 127, // WiFi + metadata (monitor mode)
    // Linux-specific captures
    LINUX_SLL = 113, // "cooked" capture (tcpdump on Linux)
    LINUX_SLL2 = 276, // newer version
    // Less common but still seen
    LOOP = 108, // Loopback (OpenBSD)
    SLIP = 8, // legacy serial IP
    INVALID = 0xFFFF,
};

pub const LayerProtocols = union(enum) {
    LinkLayer: LinkLayerProtocols,
    Network: NetworkProtocols,
    Transport: TransportProtocols,
    Application: ApplicationProtocols,
};

pub fn comparePayloads(a: LayerProtocols, b: LayerProtocols) bool {
    const tag_a = activeTag(a);
    const tag_b = activeTag(b);

    if (tag_a != tag_b) return false;

    return switch (tag_a) {
        .LinkLayer => a.LinkLayer == b.LinkLayer,
        .Network => a.Network == b.Network,
        .Transport => a.Transport == b.Transport,
        .Application => a.Application == b.Application,
    };
}

pub fn get_next_layer_type(
    layer_protocol: LayerProtocols,
) ?(*const fn ([]u8) LayerError!Packet.Layer) {
    switch (layer_protocol) {
        .LinkLayer => |protocol| switch (protocol) {
            .ETHERNET => {
                return Eth.get_next_layer_type;
            },
            else => {
                //next_layer = LayerProtocols{ .Network = .Generic };
                return null;
            },
        },
        .Network => |protocol| switch (protocol) {
            .ICMP => {
                // the icmp layer has already been created at this point and it cannot "normally" contain any preceeding layers so just return
                return null;
            },
            .IPv4 => {
                return IPv4.get_next_layer_type;
            },
            .IPv6 => {
                return IPv6.get_next_layer_type;
            },
            .ARP => {
                // the arp layer has already been created at this point and it cannot "normally" contain any preceeding layers so just return
                return null;
            },
            .Generic => {
                // we cannot parse a generic network layer. magic might be implemented in the future
                return null;
            },
        },
        .Transport => |protocol| switch (protocol) {
            .TCP => {
                return TCP.get_next_layer_type;
            },
            .UDP => {
                return UDP.get_next_layer_type;
            },
            .Generic => {
                //next_layer = LayerProtocols{ .Transport = .Generic };
                return null;
            },
        },
        .Application => |protocol| switch (protocol) {
            .DNS => {
                //next_layer = LayerProtocols{ .Application = .Generic };
                return null;
            },
            .HTTP => {
                //next_layer = LayerProtocols{ .Application = .Generic };
                return null;
            },
            .Generic => {
                return null;
            },
        },
    }
}

pub const LayerError = error{ OutOfMemory, BufferTooSmall, MisalignedBuffer, EmptyPayload };

pub fn get_layer_type_enum(value: type) !LayerProtocols {
    switch (value) {
        Eth.EthLayer => return LayerProtocols{ .LinkLayer = .ETHERNET },
        IPv4.IPv4Layer => return LayerProtocols{ .Network = .IPv4 },
        IPv6.IPv6Layer => return LayerProtocols{ .Network = .IPv6 },
        UDP.UDPLayer => return LayerProtocols{ .Transport = .UDP },
        ARP.ArpLayer => return LayerProtocols{ .Network = .ARP },
        else => return error.LayerInvalid,
    }
}

pub fn get_layer_to_string(protocol: LayerProtocols) !fn (*anyopaque) []const u8 {
    switch (protocol) {
        LayerProtocols{ .LinkLayer = .ETHERNET } => {
            return @ptrCast(Eth.EthLayer.to_string);
        },
        LayerProtocols{ .Network = .IPv4 } => {
            return @ptrCast(IPv4.IPv4Layer.to_string);
        },
        LayerProtocols{ .Transport = .UDP } => {
            return @ptrCast(UDP.UDPLayer.to_string);
        },
        else => return error.LayerInvalid,
    }
}

pub fn get_layer_init(choice: type) !*const fn ([]u8) LayerError!choice {
    switch (choice) {
        Eth.EthLayer => return Eth.EthLayer.init,
        IPv4.IPv4Layer => return IPv4.IPv4Layer.init,
        IPv6.IPv6Layer => return IPv6.IPv6Layer.init,
        UDP.UDPLayer => return UDP.UDPLayer.init,
        ARP.ArpLayer => return ARP.ArpLayer.init,
        else => return error.LayerInvalid,
    }
}

pub fn get_layer_size(protocol: LayerProtocols) usize {
    print("get layer size called for {any}\n", .{protocol});
    return switch (protocol) {
        .LinkLayer => |link_proto| switch (link_proto) {
            .ETHERNET => return @sizeOf(Eth.EthHeader),

            else => return 0,
        },

        .Network => |net_proto| switch (net_proto) {
            .IPv4 => return @sizeOf(IPv4.IPv4Header),
            .IPv6 => return @sizeOf(IPv6.IPv6Header),
            .ARP => return @sizeOf(ARP.ArpHeader),
            else => return 0,
        },

        .Transport => |trans_proto| switch (trans_proto) {
            .UDP => return @sizeOf(UDP.UDPHeader),
            else => return 0,
        },

        else => return 0,
    };
}

pub fn get_layer_alignment(protocol: LayerProtocols) usize {
    print("get layer alignment called for: {any}\n", .{protocol});
    return switch (protocol) {
        .LinkLayer => |link_proto| switch (link_proto) {
            .ETHERNET => return @alignOf(Eth.EthHeader),
            else => return 2,
        },

        .Network => |net_proto| switch (net_proto) {
            .IPv4 => return @alignOf(IPv4.IPv4Header),
            .IPv6 => return @alignOf(IPv6.IPv6Header),
            .ARP => return @alignOf(ARP.ArpHeader),
            else => return 2,
        },

        .Transport => |trans_proto| switch (trans_proto) {
            .UDP => return @alignOf(UDP.UDPHeader),
            else => {
                return 2;
            },
        },

        else => return 1,
    };
}

pub fn get_header(protocol: LayerProtocols) type {
    return switch (protocol) {
        .LinkLayer => |link_proto| switch (link_proto) {
            .ETHERNET => return Eth.EthHeader,
            else => return 0,
        },

        .Network => |net_proto| switch (net_proto) {
            .IPv4 => return IPv4.IPv4Header,
            else => return 0,
        },

        .Transport => |trans_proto| switch (trans_proto) {
            .UDP => return UDP.UDPHeader,
            else => return 0,
        },

        else => return 0,
    };
}
