const std = @import("std");
const Packet = @import("Packet.zig");
const Layer = @import("Packet.zig").Layer;
const Eth = @import("Eth.zig");
const LoopBack = @import("Loopback.zig");

const IPv4 = @import("IPv4.zig");
const IPv6 = @import("IPv6.zig");
const UDP = @import("UDP.zig");
const TCP = @import("TCP.zig");
const ARP = @import("ARP.zig");
const ICMP = @import("ICMP.zig");
const GenericLayer = @import("GenericLayer.zig");

const LayerOwner = @import("Layer.zig").LayerOwner;

const Allocator = std.mem.Allocator;

const RawData = @import("RawData.zig").RawData;

const LayerError = @import("ProtocolHelpers.zig").LayerError;

const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;

pub const LayerIface = union(enum) {
    ethLayer: Eth.EthLayer,
    //  loopbackLayer: LoopBack.LoopBackLayer,
    ipv4Layer: IPv4.IPv4Layer,
    //  ipv6Layer: IPv6.IPv6Layer,
    udpLayer: UDP.UDPLayer,
    //  tcpLayer: TCP.TCPLayer,
    //  arpLayer: ARP.ARPLayer,
    //  icmpLayer: ICMP.ICMPLayer,
    genericAppLayer: GenericLayer.ApplicationLayer,

    pub fn init(choice: type, owner: LayerOwner) LayerError!LayerIface {
        switch (choice) {
            Eth.EthLayer => return LayerIface{ .ethLayer = try Eth.EthLayer.init(owner) },
            //         LoopBack.LoopBackLayer => return LayerIface{ .loopbackLayer = try LoopBack.LoopBackLayer.init(owner) },
            IPv4.IPv4Layer => return LayerIface{ .ipv4Layer = try IPv4.IPv4Layer.init(owner) },
            //         IPv6.IPv6Layer => return LayerIface{ .ipv6Layer = try IPv6.IPv6Layer.init(owner) },
            UDP.UDPLayer => return LayerIface{ .udpLayer = try UDP.UDPLayer.init(owner) },
            //         TCP.TCPLayer => return LayerIface{ .tcpLayer = try TCP.TCPLayer.init(owner) },
            //         ARP.ARPLayer => return LayerIface{ .arpLayer = try ARP.ARPLayer.init(owner) },
            //         ICMP.ICMPLayer => return LayerIface{ .icmpLayer = try ICMP.ICMPLayer.init(owner) },
            GenericLayer.ApplicationLayer => return LayerIface{ .genericAppLayer = try GenericLayer.ApplicationLayer.init(owner) },
            else => return LayerError.LayerInvalid,
        }
    }

    pub fn reinit(self: *LayerIface, owner: LayerOwner) LayerError!void {
        const new_instance = switch (self.*) {
            .ethLayer => LayerIface{ .ethLayer = try Eth.EthLayer.init(owner) },
            //        .loopbackLayer => LayerIface{ .loopbackLayer = try LoopBack.LoopBackLayer.init(owner) },
            .ipv4Layer => LayerIface{ .ipv4Layer = try IPv4.IPv4Layer.init(owner) },
            //        .ipv6Layer => LayerIface{ .ipv6Layer = try IPv6.IPv6Layer.init(owner) },
            .udpLayer => LayerIface{ .udpLayer = try UDP.UDPLayer.init(owner) },
            //        .tcpLayer => LayerIface{ .tcpLayer = try TCP.TCPLayer.init(owner) },
            //        .arpLayer => LayerIface{ .arpLayer = try ARP.ARPLayer.init(owner) },
            //        .icmpLayer => LayerIface{ .icmpLayer = try ICMP.ICMPLayer.init(owner) },
            .genericAppLayer => LayerIface{ .genericAppLayer = try GenericLayer.ApplicationLayer.init(owner) },
        };
        self.* = new_instance;
    }

    pub fn get_next_layer(self: *LayerIface, next_layer: *Packet.Layer) !?LayerIface {
        return switch (self.*) {
            inline else => |*layer| try layer.get_next_layer_type(next_layer),
        };
    }

    pub fn get_protocol(self: *LayerIface) !tcp_ip_protocol {
        return switch (self.*) {
            inline else => |*layer| layer.get_protocol(),
        };
    }

    pub fn ptr(self: *LayerIface) *anyopaque {
        return switch (self.*) {
            inline else => |*layer| @ptrCast(layer),
        };
    }

    pub fn to_string(self: *LayerIface, allocator: Allocator) []const u8 {
        return switch (self.*) {
            inline else => |*layer| layer.to_string(allocator),
        };
    }

    pub fn get_data(self: *LayerIface) []u8 {
        return switch (self.*) {
            inline else => |*layer| layer.get_data(),
        };
    }

    pub fn get_payload(self: *LayerIface) ?[]const u8 {
        return switch (self.*) {
            inline else => |*layer| layer.get_payload(),
        };
    }
};
