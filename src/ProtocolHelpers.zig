const activeTag = @import("std").meta.activeTag;

const Eth = @import("Eth.zig");
const IPv4 = @import("IPv4.zig");
const UDP = @import("UDPLayer.zig");

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
    Generic = 0,
};

pub const LinkLayerProtocols = enum(u16) {
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

pub const LayerError = error{ OutOfMemory, BufferTooSmall, MisalignedBuffer };

pub fn get_layer_type_enum(value: type) !LayerProtocols {
    switch (value) {
        Eth.EthLayer => return LayerProtocols{ .LinkLayer = .ETHERNET },
        IPv4.IPv4Layer => return LayerProtocols{ .Network = .IPv4 },
        UDP.UDPLayer => return LayerProtocols{ .Transport = .UDP },
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
        UDP.UDPLayer => return UDP.UDPLayer.init,
        else => return error.LayerInvalid,
    }
}

pub fn get_layer_size(protocol: LayerProtocols) usize {
    return switch (protocol) {
        .LinkLayer => |link_proto| switch (link_proto) {
            .ETHERNET => return @sizeOf(Eth.EthHeader),

            else => return 0,
        },

        .Network => |net_proto| switch (net_proto) {
            .IPv4 => return @sizeOf(IPv4.IPv4Header),
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
    return switch (protocol) {
        .LinkLayer => |link_proto| switch (link_proto) {
            .ETHERNET => return @alignOf(Eth.EthHeader),
            else => return 2,
        },

        .Network => |net_proto| switch (net_proto) {
            .IPv4 => return @alignOf(IPv4.IPv4Header),
            else => return 2,
        },

        .Transport => |trans_proto| switch (trans_proto) {
            .UDP => return @alignOf(UDP.UDPHeader),
            else => {
                return 2;
            },
        },

        else => return 2,
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
