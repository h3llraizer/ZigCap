const std = @import("std");
const activeTag = @import("std").meta.activeTag;
const print = @import("std").debug.print;

const Packet = @import("Packet.zig");
const Eth = @import("Eth.zig");
const IPv4 = @import("IPv4.zig");
const IPv6 = @import("IPv6.zig");
const UDP = @import("UDPLayer.zig");
const TCP = @import("TCP.zig");
const ARP = @import("ARP.zig");
const ICMP = @import("ICMP.zig");
const GenericLayer = @import("GenericLayer.zig");

const LayerOwner = @import("Layer.zig").LayerOwner;

const Allocator = @import("std").mem.Allocator;

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
                print("icmp skip.\n", .{});
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

pub const LayerError = error{ OutOfMemory, BufferTooSmall, MisalignedBuffer, EmptyPayload, InvalidOperation };

pub fn get_layer_type_enum(value: type) !LayerProtocols {
    switch (value) {
        Eth.EthLayer => return LayerProtocols{ .LinkLayer = .ETHERNET },
        IPv4.IPv4Layer => return LayerProtocols{ .Network = .IPv4 },
        IPv6.IPv6Layer => return LayerProtocols{ .Network = .IPv6 },
        UDP.UDPLayer => return LayerProtocols{ .Transport = .UDP },
        TCP.TCPLayer => return LayerProtocols{ .Transport = .TCP },
        ARP.ArpLayer => return LayerProtocols{ .Network = .ARP },
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

pub fn get_layer_init(choice: type) !*const fn (LayerOwner) LayerError!choice {
    switch (choice) {
        Eth.EthLayer => return Eth.EthLayer.init,
        IPv4.IPv4Layer => return IPv4.IPv4Layer.init,
        IPv6.IPv6Layer => return IPv6.IPv6Layer.init,
        UDP.UDPLayer => return UDP.UDPLayer.init,
        TCP.TCPLayer => return TCP.TCPLayer.init,
        ARP.ArpLayer => return ARP.ArpLayer.init,
        ICMP.ICMPLayer => return ICMP.ICMPLayer.init,
        GenericLayer.ApplicationLayer => return GenericLayer.ApplicationLayer.init,
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
// not in use
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

fn compare_impl(a: *LayerImpl, b: *LayerImpl) bool {
    return a.get_data() == b.get_data();
}

pub const LayerImpl = union(enum) {
    ethLayer: Eth.EthLayer,
    ipv4Layer: IPv4.IPv4Layer,
    //   ipv6Layer: IPv6.IPv6Layer,
    udpLayer: UDP.UDPLayer,
    tcpLayer: TCP.TCPLayer,
    //   arpLayer: ARP.ArpLayer,
    //   icmpLayer: ICMP.ICMPLayer,
    genericAppLayer: GenericLayer.ApplicationLayer,

    pub fn init(choice: type, owner: LayerOwner) LayerError!LayerImpl {
        switch (choice) {
            Eth.EthLayer => return LayerImpl{ .ethLayer = try Eth.EthLayer.init(owner) },
            IPv4.IPv4Layer => return LayerImpl{ .ipv4Layer = try IPv4.IPv4Layer.init(owner) },
            //           IPv6.IPv6Layer => return IPv6.IPv6Layer.init(owner),
            UDP.UDPLayer => return LayerImpl{ .udpLayer = try UDP.UDPLayer.init(owner) },
            TCP.TCPLayer => return TCP.TCPLayer.init(owner),
            //           ARP.ArpLayer => return ARP.ArpLayer.init(owner),
            //           ICMP.ICMPLayer => return ICMP.ICMPLayer.init(owner),
            GenericLayer.ApplicationLayer => return LayerImpl{ .genericAppLayer = try GenericLayer.ApplicationLayer.init(owner) },
            else => return error.LayerInvalid,
        }
    }

    pub fn reinit(self: *LayerImpl, owner: LayerOwner) LayerError!void {
        const new_instance = switch (self.*) {
            .ethLayer => LayerImpl{ .ethLayer = try Eth.EthLayer.init(owner) },
            .ipv4Layer => LayerImpl{ .ipv4Layer = try IPv4.IPv4Layer.init(owner) },
            // .ipv6Layer => |*layer| try LayerImpl{ .ipv6Layer = try IPv6.IPv6Layer.init(owner) },
            .udpLayer => LayerImpl{ .udpLayer = try UDP.UDPLayer.init(owner) },
            .tcpLayer => LayerImpl{ .tcpLayer = try TCP.TCPLayer.init(owner) },
            // .arpLayer => |*layer| try LayerImpl{ .arpLayer = try ARP.ArpLayer.init(owner) },
            // .icmpLayer => |*layer| try LayerImpl{ .icmpLayer = try ICMP.ICMPLayer.init(owner) },
            .genericAppLayer => LayerImpl{ .genericAppLayer = try GenericLayer.ApplicationLayer.init(owner) },
        };
        self.* = new_instance;
    }

    pub fn get_protocol(self: *LayerImpl) !LayerProtocols {
        switch (self.*) {
            .ethLayer => return LayerProtocols{ .LinkLayer = .ETHERNET },
            .ipv4Layer => return LayerProtocols{ .Network = .IPv4 },
            .udpLayer => return LayerProtocols{ .Transport = .UDP },
            .udpLayer => return LayerProtocols{ .Transport = .UDP },
            .genericAppLayer => return LayerProtocols{ .Application = .Generic },
        }
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

    pub fn get_data(self: *LayerImpl) []const u8 {
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
