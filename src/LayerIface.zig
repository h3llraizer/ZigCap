const std = @import("std");
const Packet = @import("Packet.zig");
const Layer = @import("Packet.zig").Layer;
const Eth = @import("Eth.zig");
const Loopback = @import("Loopback.zig");
const DHCP = @import("DHCP.zig");
const IPv4 = @import("IPv4.zig");
const IPv6 = @import("IPv6.zig");
const UDP = @import("UDP.zig");
const TCP = @import("TCP.zig");
const ARP = @import("ARP.zig");
const ICMP = @import("ICMP.zig");
const DNS = @import("DNS.zig");
const GenericLayer = @import("GenericLayer.zig");
const VLAN = @import("VLAN.zig");
const IGMP = @import("IGMP.zig");
const LayerError = @import("ProtocolEnums.zig").LayerError;
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;
const LayerOwner = @import("Owner.zig").LayerOwner;

const Allocator = std.mem.Allocator;

pub fn init_layer(concrete_type: anytype, owner: LayerOwner, header: anytype, default_hdr: anytype) !concrete_type {
    switch (owner) {
        .packet_layer => {
            return concrete_type{
                .owner = owner,
            };
        },
        .owned_buffer => {
            var self = concrete_type{ .owner = owner };
            const buffer_len = owner.get_data().len;

            if (buffer_len < @sizeOf(header)) {
                const diff = @sizeOf(header) - buffer_len;

                const ipv4_data = try self.owner.extend_layer(buffer_len, diff);

                @memset(ipv4_data, 0);

                @memcpy(ipv4_data[0..@sizeOf(header)], std.mem.asBytes(&default_hdr));
            }

            return self;
        },
    }
}

pub fn get_mutable_header(header: anytype, data: []u8) *header {
    const aligned_ptr: [*]align(@alignOf(header)) u8 = @alignCast(data.ptr);
    return @ptrCast(aligned_ptr);
}

pub const LayerIface = union(enum) {
    ethLayer: Eth.EthLayer,
    vlanLayer: VLAN.VLANLayer,
    loopbackLayer: Loopback.LoopbackLayer,
    ipv4Layer: IPv4.IPv4Layer,
    ipv6Layer: IPv6.IPv6Layer,
    udpLayer: UDP.UDPLayer,
    tcpLayer: TCP.TCPLayer,
    arpLayer: ARP.ARPLayer,
    icmpLayer: ICMP.ICMPLayer,
    dnsLayer: DNS.DNSLayer,
    dhcpLayer: DHCP.DHCPLayer,
    igmpv3Layer: IGMP.IGMPv3Layer,
    genericAppLayer: GenericLayer.ApplicationLayer,

    /// inits the layer
    /// copies the owner struct - dont try to get the layer buffer from your original owner struct
    pub fn init(choice: type, owner: LayerOwner) LayerError!LayerIface {
        switch (choice) {
            Loopback.LoopbackLayer => return LayerIface{ .loopbackLayer = try Loopback.LoopbackLayer.init(owner) },
            Eth.EthLayer => return LayerIface{ .ethLayer = try Eth.EthLayer.init(owner) },
            VLAN.VLANLayer => return LayerIface{ .vlanLayer = try VLAN.VLANLayer.init(owner) },
            IPv4.IPv4Layer => return LayerIface{ .ipv4Layer = try IPv4.IPv4Layer.init(owner) },
            IPv6.IPv6Layer => return LayerIface{ .ipv6Layer = try IPv6.IPv6Layer.init(owner) },
            UDP.UDPLayer => return LayerIface{ .udpLayer = try UDP.UDPLayer.init(owner) },
            TCP.TCPLayer => return LayerIface{ .tcpLayer = try TCP.TCPLayer.init(owner) },
            ARP.ARPLayer => return LayerIface{ .arpLayer = try ARP.ARPLayer.init(owner) },
            ICMP.ICMPLayer => return LayerIface{ .icmpLayer = try ICMP.ICMPLayer.init(owner) },
            DNS.DNSLayer => return LayerIface{ .dnsLayer = try DNS.DNSLayer.init(owner) },
            DHCP.DHCPLayer => return LayerIface{ .dhcpLayer = try DHCP.DHCPLayer.init(owner) },
            IGMP.IGMPv3Layer => return LayerIface{ .igmpv3Layer = try IGMP.IGMPv3Layer.init(owner) },
            GenericLayer.ApplicationLayer => return LayerIface{ .genericAppLayer = try GenericLayer.ApplicationLayer.init(owner) },
            else => return LayerError.LayerInvalid,
        }
    }

    pub fn reinit(self: *LayerIface, owner: LayerOwner) LayerError!void {
        const new_instance = switch (self.*) {
            .loopbackLayer => LayerIface{ .loopbackLayer = try Loopback.LoopbackLayer.init(owner) },
            .ethLayer => LayerIface{ .ethLayer = try Eth.EthLayer.init(owner) },
            .vlanLayer => LayerIface{ .vlanLayer = try VLAN.VLANLayer.init(owner) },
            .ipv4Layer => LayerIface{ .ipv4Layer = try IPv4.IPv4Layer.init(owner) },
            .ipv6Layer => LayerIface{ .ipv6Layer = try IPv6.IPv6Layer.init(owner) },
            .udpLayer => LayerIface{ .udpLayer = try UDP.UDPLayer.init(owner) },
            .tcpLayer => LayerIface{ .tcpLayer = try TCP.TCPLayer.init(owner) },
            .arpLayer => LayerIface{ .arpLayer = try ARP.ARPLayer.init(owner) },
            .icmpLayer => LayerIface{ .icmpLayer = try ICMP.ICMPLayer.init(owner) },
            .dnsLayer => LayerIface{ .dnsLayer = try DNS.DNSLayer.init(owner) },
            .dhcpLayer => LayerIface{ .dhcpLayer = try DHCP.DHCPLayer.init(owner) },
            .igmpv3Layer => LayerIface{ .igmpv3Layer = try IGMP.IGMPv3Layer.init(owner) },
            .genericAppLayer => LayerIface{ .genericAppLayer = try GenericLayer.ApplicationLayer.init(owner) },
        };
        self.* = new_instance;
    }

    /// calls the concrete layers get_next_layer method.
    /// mostly used for Packet to accumulate all layers from slices
    /// can be used when a layer is standalone but isn't recommended
    pub fn get_next_layer(self: *LayerIface, next_layer: *Packet.Layer) LayerError!?LayerIface {
        return switch (self.*) {
            inline else => |*layer| try layer.get_next_layer_type(next_layer),
        };
    }

    /// returns the protocol of the concrete layer which it's interfacing over
    /// e.g. TCPLayer is tcp_ip_protocol.tcp
    pub fn get_protocol(self: *LayerIface) tcp_ip_protocol {
        return switch (self.*) {
            inline else => |*layer| layer.get_protocol(),
        };
    }

    pub fn get_owner(self: *LayerIface) *LayerOwner {
        return switch (self.*) {
            inline else => |*layer| &layer.owner,
        };
    }

    pub fn validate_layer(self: *LayerIface) void {
        return switch (self.*) {
            inline else => |*layer| layer.validate_layer(),
        };
    }

    /// returns the ptr to the concrete layer
    pub fn ptr(self: *LayerIface) *anyopaque {
        return switch (self.*) {
            inline else => |*layer| @ptrCast(layer),
        };
    }

    /// calls the concrete layers to_string method
    /// caller needs to free
    pub fn to_string(self: *LayerIface, allocator: Allocator) []const u8 {
        return switch (self.*) {
            inline else => |*layer| layer.to_string(allocator),
        };
    }

    /// return the data (header+payload) from the layer.
    /// depending on if the layer is owned by a Packet then the Packet will get the layers data using it's offset in the packet buffer
    /// if the layer is standalone (with owned_buffer owner) then the data from the buffer is just returned
    pub fn get_data(self: *LayerIface) []u8 {
        return switch (self.*) {
            inline else => |*layer| layer.get_data(),
        };
    }

    /// return the payload (data[hdr_len..]) from the layer.
    /// depending on if the layer is owned by a Packet then the Packet will get the layers payload using it's offset+length in the packet buffer
    /// if the layer is standalone (with owned_buffer owner) then it will always return an empty slice
    pub fn get_payload(self: *LayerIface) []const u8 {
        return switch (self.*) {
            inline else => |*layer| layer.get_payload(),
        };
    }

    /// calls the concrete layers deinit method.
    /// only deinit's standalone layers
    /// does nothing for Packet owned layers
    pub fn deinit(self: *LayerIface) void {
        return switch (self.*) {
            inline else => |*layer| layer.deinit(),
        };
    }
};
