const std = @import("std");
const activeTag = @import("std").meta.activeTag;
const print = @import("std").debug.print;

const Packet = @import("Packet.zig");
const Layer = @import("Packet.zig").Layer;
const Eth = @import("Eth.zig");
const IPv4 = @import("IPv4.zig");
const IPv6 = @import("IPv6.zig");
const UDP = @import("UDP.zig");
const TCP = @import("TCP.zig");
const ARP = @import("ARP.zig");
const ICMP = @import("ICMP.zig");
const GenericLayer = @import("GenericLayer.zig");

const LayerOwner = @import("Layer.zig").LayerOwner;

const Allocator = @import("std").mem.Allocator;

const RawData = @import("RawData.zig").RawData;

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

pub const IPProtocol = enum(u8) {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
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
    PPP = 9,
    PPP_ETHER = 51, // PPPoE
    IEEE802_11 = 105, // WiFi
    IEEE802_11_RADIOTAP = 127, // WiFi + metadata (monitor mode)
    LINUX_SLL = 113, // "cooked" capture (tcpdump on Linux)
    LINUX_SLL2 = 276, // newer version
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

pub const LayerError = error{ OutOfMemory, BufferTooSmall, MisalignedBuffer, EmptyPayload, InvalidOperation, LayerInvalid };

pub fn get_layer_type_enum(value: type) !LayerProtocols {
    switch (value) {
        Eth.EthLayer => return LayerProtocols{ .LinkLayer = .ETHERNET },
        IPv4.IPv4Layer => return LayerProtocols{ .Network = .IPv4 },
        IPv6.IPv6Layer => return LayerProtocols{ .Network = .IPv6 },
        UDP.UDPLayer => return LayerProtocols{ .Transport = .UDP },
        TCP.TCPLayer => return LayerProtocols{ .Transport = .TCP },
        ARP.ARPLayer => return LayerProtocols{ .Network = .ARP },
        ICMP.ICMPLayer => return LayerProtocols{ .Network = .ICMP },
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
            .ICMP => return @sizeOf(ICMP.ICMPHeader),
            else => return 0,
        },

        .Transport => |trans_proto| switch (trans_proto) {
            .UDP => return @sizeOf(UDP.UDPHeader),
            .TCP => return @sizeOf(TCP.TCPHeader),
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
            .ICMP => return @alignOf(ICMP.ICMPHeader),
            else => return 2,
        },

        .Transport => |trans_proto| switch (trans_proto) {
            .UDP => return @alignOf(UDP.UDPHeader),
            .TCP => return @alignOf(TCP.TCPHeader),
            else => {
                return 2;
            },
        },

        else => return 1, // not sure why I'm using 1 here
    };
}

pub const LayerImpl = union(enum) {
    ethLayer: Eth.EthLayer,
    ipv4Layer: IPv4.IPv4Layer,
    //   ipv6Layer: IPv6.IPv6Layer,
    udpLayer: UDP.UDPLayer,
    tcpLayer: TCP.TCPLayer,
    arpLayer: ARP.ARPLayer,
    icmpLayer: ICMP.ICMPLayer,
    genericAppLayer: GenericLayer.ApplicationLayer,

    pub fn init(choice: type, owner: LayerOwner) LayerError!LayerImpl {
        switch (choice) {
            Eth.EthLayer => return LayerImpl{ .ethLayer = try Eth.EthLayer.init(owner) },
            IPv4.IPv4Layer => return LayerImpl{ .ipv4Layer = try IPv4.IPv4Layer.init(owner) },
            //           IPv6.IPv6Layer => return IPv6.IPv6Layer.init(owner),
            UDP.UDPLayer => return LayerImpl{ .udpLayer = try UDP.UDPLayer.init(owner) },
            TCP.TCPLayer => return LayerImpl{ .tcpLayer = try TCP.TCPLayer.init(owner) },
            ARP.ARPLayer => return LayerImpl{ .arpLayer = try ARP.ARPLayer.init(owner) },
            ICMP.ICMPLayer => return LayerImpl{ .icmpLayer = try ICMP.ICMPLayer.init(owner) },
            GenericLayer.ApplicationLayer => return LayerImpl{ .genericAppLayer = try GenericLayer.ApplicationLayer.init(owner) },
            else => return LayerError.LayerInvalid,
        }
    }

    pub fn reinit(self: *LayerImpl, owner: LayerOwner) LayerError!void {
        const new_instance = switch (self.*) {
            .ethLayer => LayerImpl{ .ethLayer = try Eth.EthLayer.init(owner) },
            .ipv4Layer => LayerImpl{ .ipv4Layer = try IPv4.IPv4Layer.init(owner) },
            // .ipv6Layer => |*layer| try LayerImpl{ .ipv6Layer = try IPv6.IPv6Layer.init(owner) },
            .udpLayer => LayerImpl{ .udpLayer = try UDP.UDPLayer.init(owner) },
            .tcpLayer => LayerImpl{ .tcpLayer = try TCP.TCPLayer.init(owner) },
            .arpLayer => LayerImpl{ .arpLayer = try ARP.ARPLayer.init(owner) },
            .icmpLayer => LayerImpl{ .icmpLayer = try ICMP.ICMPLayer.init(owner) },
            .genericAppLayer => LayerImpl{ .genericAppLayer = try GenericLayer.ApplicationLayer.init(owner) },
        };
        self.* = new_instance;
    }

    pub fn get_next_layer(self: *LayerImpl, next_layer: *Packet.Layer) !?LayerImpl {
        return switch (self.*) {
            inline else => |*layer| try layer.get_next_layer_type(next_layer),
        };
    }

    pub fn get_protocol(self: *LayerImpl) !LayerProtocols {
        return switch (self.*) {
            inline else => |*layer| layer.get_protocol(),
        };
    }

    pub fn ptr(self: *LayerImpl) *anyopaque {
        return switch (self.*) {
            inline else => |*layer| @ptrCast(layer),
        };
    }

    pub fn to_string(self: *LayerImpl, allocator: Allocator) []const u8 {
        return switch (self.*) {
            inline else => |*layer| layer.to_string(allocator),
        };
    }

    pub fn get_data(self: *LayerImpl) RawData {
        return switch (self.*) {
            inline else => |*layer| layer.get_data(),
        };
    }

    pub fn get_payload(self: *LayerImpl) ?[]const u8 {
        return switch (self.*) {
            inline else => |*layer| layer.get_payload(),
        };
    }
};
