const std = @import("std");
const Packet = @import("Packet.zig");
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
const PacketLayer = @import("PacketLayer.zig").Layer;

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

pub const Layer = union(enum) {
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
    pub fn init(choice: type, allocator: Allocator) LayerError!Layer {
        switch (choice) {
            Loopback.LoopbackLayer => return Layer{ .loopbackLayer = try Loopback.LoopbackLayer.init(allocator) },
            Eth.EthLayer => return Layer{ .ethLayer = try Eth.EthLayer.init(allocator) },
            VLAN.VLANLayer => return Layer{ .vlanLayer = try VLAN.VLANLayer.init(allocator) },
            IPv4.IPv4Layer => return Layer{ .ipv4Layer = try IPv4.IPv4Layer.init(allocator) },
            IPv6.IPv6Layer => return Layer{ .ipv6Layer = try IPv6.IPv6Layer.init(allocator) },
            UDP.UDPLayer => return Layer{ .udpLayer = try UDP.UDPLayer.init(allocator) },
            TCP.TCPLayer => return Layer{ .tcpLayer = try TCP.TCPLayer.init(allocator) },
            ARP.ARPLayer => return Layer{ .arpLayer = try ARP.ARPLayer.init(allocator) },
            ICMP.ICMPLayer => return Layer{ .icmpLayer = try ICMP.ICMPLayer.init(allocator) },
            DNS.DNSLayer => return Layer{ .dnsLayer = try DNS.DNSLayer.init(allocator) },
            DHCP.DHCPLayer => return Layer{ .dhcpLayer = try DHCP.DHCPLayer.init(allocator) },
            IGMP.IGMPv3Layer => return Layer{ .igmpv3Layer = try IGMP.IGMPv3Layer.init(allocator) },
            GenericLayer.ApplicationLayer => return Layer{
                .genericAppLayer = try GenericLayer.ApplicationLayer.init(allocator),
            },
            else => return LayerError.LayerInvalid,
        }
    }

    pub fn initFromSlice(choice: type, slice: []u8, allocator: Allocator) LayerError!Layer {
        switch (choice) {
            Loopback.LoopbackLayer => return Layer{ .loopbackLayer = try Loopback.LoopbackLayer.initFromSlice(slice, allocator) },
            Eth.EthLayer => return Layer{ .ethLayer = try Eth.EthLayer.initFromSlice(slice, allocator) },
            VLAN.VLANLayer => return Layer{ .vlanLayer = try VLAN.VLANLayer.initFromSlice(slice, allocator) },
            IPv4.IPv4Layer => return Layer{ .ipv4Layer = try IPv4.IPv4Layer.initFromSlice(slice, allocator) },
            IPv6.IPv6Layer => return Layer{ .ipv6Layer = try IPv6.IPv6Layer.initFromSlice(slice, allocator) },
            UDP.UDPLayer => return Layer{ .udpLayer = try UDP.UDPLayer.initFromSlice(slice, allocator) },
            TCP.TCPLayer => return Layer{ .tcpLayer = try TCP.TCPLayer.initFromSlice(slice, allocator) },
            ARP.ARPLayer => return Layer{ .arpLayer = try ARP.ARPLayer.initFromSlice(slice, allocator) },
            ICMP.ICMPLayer => return Layer{ .icmpLayer = try ICMP.ICMPLayer.initFromSlice(slice, allocator) },
            DNS.DNSLayer => return Layer{ .dnsLayer = try DNS.DNSLayer.initFromSlice(slice, allocator) },
            DHCP.DHCPLayer => return Layer{ .dhcpLayer = try DHCP.DHCPLayer.initFromSlice(slice, allocator) },
            IGMP.IGMPv3Layer => return Layer{ .igmpv3Layer = try IGMP.IGMPv3Layer.initFromSlice(slice, allocator) },
            GenericLayer.ApplicationLayer => return Layer{
                .genericAppLayer = try GenericLayer.ApplicationLayer.initFromSlice(slice, allocator),
            },
            else => return LayerError.LayerInvalid,
        }
    }

    pub fn reinit(self: *Layer, owner: LayerOwner) LayerError!void {
        const new_instance = switch (self.*) {
            .loopbackLayer => Layer{ .loopbackLayer = .{ .owner = owner } },
            .ethLayer => Layer{ .ethLayer = .{ .owner = owner } },
            .vlanLayer => Layer{ .vlanLayer = .{ .owner = owner } },
            .ipv4Layer => Layer{ .ipv4Layer = .{ .owner = owner } },
            .ipv6Layer => Layer{ .ipv6Layer = .{ .owner = owner } },
            .udpLayer => Layer{ .udpLayer = .{ .owner = owner } },
            .tcpLayer => Layer{ .tcpLayer = .{ .owner = owner } },
            .arpLayer => Layer{ .arpLayer = .{ .owner = owner } },
            .icmpLayer => Layer{ .icmpLayer = .{ .owner = owner } },
            .dnsLayer => Layer{ .dnsLayer = .{ .owner = owner } },
            .dhcpLayer => Layer{ .dhcpLayer = .{ .owner = owner } },
            .igmpv3Layer => Layer{ .igmpv3Layer = .{ .owner = owner } },
            .genericAppLayer => Layer{ .genericAppLayer = .{ .owner = owner } },
        };
        self.* = new_instance;
    }

    /// calls the concrete layers get_next_layer method.
    /// mostly used by Packet to accumulate all layers from slices
    /// can be used when a layer is standalone but isn't recommended
    pub fn get_next_layer(self: *Layer, next_layer: *PacketLayer) LayerError!?Layer {
        return switch (self.*) {
            inline else => |*layer| try layer.get_next_layer_type(next_layer),
        };
    }

    /// returns the protocol of the concrete layer which it's interfacing over
    /// e.g. TCPLayer is tcp_ip_protocol.tcp
    pub fn get_protocol(self: Layer) tcp_ip_protocol {
        return switch (self) {
            inline else => |layer| layer.get_protocol(),
        };
    }

    pub fn get_owner(self: *Layer) *LayerOwner {
        return switch (self.*) {
            inline else => |*layer| &layer.owner,
        };
    }

    pub fn validate_layer(self: *Layer) void {
        return switch (self.*) {
            inline else => |*layer| layer.validate_layer(),
        };
    }

    /// calls the concrete layers to_string method
    /// caller needs to free
    pub fn to_string(self: *Layer, allocator: Allocator) ![]const u8 {
        return switch (self.*) {
            inline else => |*layer| layer.to_string(allocator),
        };
    }

    /// return the data (header+payload) from the layer.
    /// depending on if the layer is owned by a Packet then the Packet will get the layers data using it's offset in the packet buffer
    /// if the layer is standalone (with owned_buffer owner) then the data from the buffer is just returned
    pub fn get_data(self: *Layer) []u8 {
        return switch (self.*) {
            inline else => |*layer| layer.get_data(),
        };
    }

    /// return the payload (data[hdr_len..]) from the layer.
    /// depending on if the layer is owned by a Packet then the Packet will get the layers payload using it's offset+length in the packet buffer
    /// if the layer is standalone (with owned_buffer owner) then it will always return an empty slice
    pub fn get_payload(self: *Layer) []const u8 {
        return switch (self.*) {
            inline else => |*layer| layer.get_payload(),
        };
    }

    /// calls the concrete layers deinit method.
    /// only deinit's standalone layers
    /// does nothing for Packet owned layers
    pub fn deinit(self: *Layer) void {
        return switch (self.*) {
            inline else => |*layer| layer.deinit(),
        };
    }
};
