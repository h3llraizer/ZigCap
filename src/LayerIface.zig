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

/// TODO: move allocator to end of args
pub fn init_layer(concrete_type: anytype, allocator: Allocator, header: anytype, default_hdr: anytype) !concrete_type {
    var owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    const header_bytes = try owner.extend_layer(0, @sizeOf(header));

    @memset(header_bytes, 0);

    @memcpy(header_bytes[0..@sizeOf(header)], std.mem.asBytes(&default_hdr));

    const self = concrete_type{ .owner = owner };

    return self;
}

/// copies header from slice
pub fn initFromSlice(
    slice: []u8,
    layer_type: anytype,
    actual_hdr_len: usize,
    min_header: usize,
    max_header: usize,
    allocator: Allocator,
) LayerError!layer_type {
    if (slice.len < min_header) return LayerError.BufferTooSmall;
    if (actual_hdr_len > max_header or actual_hdr_len > slice.len) return LayerError.LayerMalformed;
    var owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
    const hdr_bytes = try owner.extend_layer(0, actual_hdr_len);
    @memmove(hdr_bytes[0..actual_hdr_len], slice[0..actual_hdr_len]);
    return .{ .owner = owner };
}

pub fn get_mutable_header(header: anytype, data: []u8) *header {
    const aligned_ptr: [*]align(@alignOf(header)) u8 = @alignCast(data.ptr);
    return @ptrCast(aligned_ptr);
}

/// TODO: Rename to Layer - rename Layer in Packet to something else?
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
    /// TODO: maybe use tcp_ip_protocol instead of type
    pub fn init(choice: type, allocator: Allocator) LayerError!LayerIface {
        switch (choice) {
            Loopback.LoopbackLayer => return LayerIface{ .loopbackLayer = try Loopback.LoopbackLayer.init(allocator) },
            Eth.EthLayer => return LayerIface{ .ethLayer = try Eth.EthLayer.init(allocator) },
            VLAN.VLANLayer => return LayerIface{ .vlanLayer = try VLAN.VLANLayer.init(allocator) },
            IPv4.IPv4Layer => return LayerIface{ .ipv4Layer = try IPv4.IPv4Layer.init(allocator) },
            IPv6.IPv6Layer => return LayerIface{ .ipv6Layer = try IPv6.IPv6Layer.init(allocator) },
            UDP.UDPLayer => return LayerIface{ .udpLayer = try UDP.UDPLayer.init(allocator) },
            TCP.TCPLayer => return LayerIface{ .tcpLayer = try TCP.TCPLayer.init(allocator) },
            ARP.ARPLayer => return LayerIface{ .arpLayer = try ARP.ARPLayer.init(allocator) },
            ICMP.ICMPLayer => return LayerIface{ .icmpLayer = try ICMP.ICMPLayer.init(allocator) },
            DNS.DNSLayer => return LayerIface{ .dnsLayer = try DNS.DNSLayer.init(allocator) },
            DHCP.DHCPLayer => return LayerIface{ .dhcpLayer = try DHCP.DHCPLayer.init(allocator) },
            IGMP.IGMPv3Layer => return LayerIface{ .igmpv3Layer = try IGMP.IGMPv3Layer.init(allocator) },
            GenericLayer.ApplicationLayer => return LayerIface{
                .genericAppLayer = try GenericLayer.ApplicationLayer.init(allocator),
            },
            else => return LayerError.LayerInvalid,
        }
    }

    pub fn initFromSlice(choice: type, slice: []u8, allocator: Allocator) LayerError!LayerIface {
        switch (choice) {
            Loopback.LoopbackLayer => return LayerIface{ .loopbackLayer = try Loopback.LoopbackLayer.initFromSlice(slice, allocator) },
            Eth.EthLayer => return LayerIface{ .ethLayer = try Eth.EthLayer.initFromSlice(slice, allocator) },
            VLAN.VLANLayer => return LayerIface{ .vlanLayer = try VLAN.VLANLayer.initFromSlice(slice, allocator) },
            IPv4.IPv4Layer => return LayerIface{ .ipv4Layer = try IPv4.IPv4Layer.initFromSlice(slice, allocator) },
            IPv6.IPv6Layer => return LayerIface{ .ipv6Layer = try IPv6.IPv6Layer.initFromSlice(slice, allocator) },
            UDP.UDPLayer => return LayerIface{ .udpLayer = try UDP.UDPLayer.initFromSlice(slice, allocator) },
            TCP.TCPLayer => return LayerIface{ .tcpLayer = try TCP.TCPLayer.initFromSlice(slice, allocator) },
            ARP.ARPLayer => return LayerIface{ .arpLayer = try ARP.ARPLayer.initFromSlice(slice, allocator) },
            ICMP.ICMPLayer => return LayerIface{ .icmpLayer = try ICMP.ICMPLayer.initFromSlice(slice, allocator) },
            DNS.DNSLayer => return LayerIface{ .dnsLayer = try DNS.DNSLayer.initFromSlice(slice, allocator) },
            DHCP.DHCPLayer => return LayerIface{ .dhcpLayer = try DHCP.DHCPLayer.initFromSlice(slice, allocator) },
            IGMP.IGMPv3Layer => return LayerIface{ .igmpv3Layer = try IGMP.IGMPv3Layer.initFromSlice(slice, allocator) },
            GenericLayer.ApplicationLayer => return LayerIface{
                .genericAppLayer = try GenericLayer.ApplicationLayer.initFromSlice(slice, allocator),
            },
            else => return LayerError.LayerInvalid,
        }
    }

    pub fn reinit(self: *LayerIface, owner: LayerOwner) LayerError!void {
        const new_instance = switch (self.*) {
            .loopbackLayer => LayerIface{ .loopbackLayer = .{ .owner = owner } },
            .ethLayer => LayerIface{ .ethLayer = .{ .owner = owner } },
            .vlanLayer => LayerIface{ .vlanLayer = .{ .owner = owner } },
            .ipv4Layer => LayerIface{ .ipv4Layer = .{ .owner = owner } },
            .ipv6Layer => LayerIface{ .ipv6Layer = .{ .owner = owner } },
            .udpLayer => LayerIface{ .udpLayer = .{ .owner = owner } },
            .tcpLayer => LayerIface{ .tcpLayer = .{ .owner = owner } },
            .arpLayer => LayerIface{ .arpLayer = .{ .owner = owner } },
            .icmpLayer => LayerIface{ .icmpLayer = .{ .owner = owner } },
            .dnsLayer => LayerIface{ .dnsLayer = .{ .owner = owner } },
            .dhcpLayer => LayerIface{ .dhcpLayer = .{ .owner = owner } },
            .igmpv3Layer => LayerIface{ .igmpv3Layer = .{ .owner = owner } },
            .genericAppLayer => LayerIface{ .genericAppLayer = .{ .owner = owner } },
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
