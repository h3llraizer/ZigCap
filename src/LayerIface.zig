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

/// soon to be converted to a vtable style polymorphic interface to handle protocol plugins
pub const LayerIface = union(enum) {
    ethLayer: Eth.EthLayer,
    vlanLayer: VLAN.VlanLayer,
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
            Eth.EthLayer => return LayerIface{ .ethLayer = try Eth.EthLayer.init(owner) },
            VLAN.VlanLayer => return LayerIface{ .vlanLayer = try VLAN.VlanLayer.init(owner) },
            Loopback.LoopbackLayer => return LayerIface{ .loopbackLayer = try Loopback.LoopbackLayer.init(owner) },
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
            .ethLayer => LayerIface{ .ethLayer = try Eth.EthLayer.init(owner) },
            .vlanLayer => LayerIface{ .vlanLayer = try VLAN.VlanLayer.init(owner) },
            .loopbackLayer => LayerIface{ .loopbackLayer = try Loopback.LoopbackLayer.init(owner) },
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
    /// if the layer is standalone (with owned_buffer owner) then it will always return null
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

// Layer interface using vtable polymorphism - currently unused in the library
pub const LayerInterface = struct {
    impl: *anyopaque,
    v_get_next_layer_type: *const fn (*anyopaque, *Packet.Layer) LayerError!?LayerIface,
    v_get_protocol: *const fn (*anyopaque) tcp_ip_protocol,
    v_to_string: *const fn (*anyopaque, Allocator) []const u8,
    v_get_data: *const fn (*anyopaque) []u8,
    v_get_payload: *const fn (*anyopaque) []const u8,
    v_deinit: *const fn (*anyopaque) void,

    /// Creates a LayerInterface from any concrete layer implementation
    pub fn implBy(impl_obj: anytype) LayerInterface {
        const T = @TypeOf(impl_obj);
        const delegate = LayerDelegate(T);
        return .{
            .impl = @ptrCast(impl_obj),
            .v_get_next_layer_type = delegate.get_next_layer_type,
            .v_get_protocol = delegate.get_protocol,
            .v_to_string = delegate.to_string,
            .v_get_data = delegate.get_data,
            .v_get_payload = delegate.get_payload,
            .v_deinit = delegate.deinit,
        };
    }

    // Public interface methods
    pub fn get_next_layer_type(self: *LayerInterface, next_layer: *Packet.Layer) LayerError!?LayerIface {
        return self.v_get_next_layer_type(self.impl, next_layer);
    }

    pub fn get_protocol(self: *LayerInterface) tcp_ip_protocol {
        return self.v_get_protocol(self.impl);
    }

    pub fn to_string(self: *LayerInterface, allocator: Allocator) []const u8 {
        return self.v_to_string(self.impl, allocator);
    }

    pub fn get_data(self: *LayerInterface) []u8 {
        return self.v_get_data(self.impl);
    }

    pub fn get_payload(self: *LayerInterface) []const u8 {
        return self.v_get_payload(self.impl);
    }

    /// Calls the concrete layers deinit method.
    /// if you call the concrete layers and this interfaces deinit you will double free the underlying buffer
    pub fn deinit(self: *LayerInterface) void {
        return self.v_deinit(self.impl);
    }
};

/// Delegate to convert opaque pointer back to concrete type
inline fn LayerDelegate(comptime T: type) type {
    return struct {
        fn get_next_layer_type(impl: *anyopaque, next_layer: *Packet.Layer) LayerError!?LayerIface {
            const self = @as(T, @ptrCast(@alignCast(impl)));
            return try self.get_next_layer_type(next_layer);
        }

        fn get_protocol(impl: *anyopaque) tcp_ip_protocol {
            const self = @as(T, @ptrCast(@alignCast(impl)));
            return self.get_protocol();
        }

        fn to_string(impl: *anyopaque, allocator: Allocator) []const u8 {
            const self = @as(T, @ptrCast(@alignCast(impl)));
            return self.to_string(allocator);
        }

        fn get_data(impl: *anyopaque) []u8 {
            const self = @as(T, @ptrCast(@alignCast(impl)));
            return self.get_data();
        }

        fn get_payload(impl: *anyopaque) []const u8 {
            const self = @as(T, @ptrCast(@alignCast(impl)));
            return self.get_payload();
        }

        fn deinit(impl: *anyopaque) void {
            const self = @as(T, @ptrCast(@alignCast(impl)));
            self.deinit();
        }
    };
}

/// Helper to cast opaque pointer to concrete type
pub fn TPtr(T: type, opaque_ptr: *anyopaque) *T {
    return @as(*T, @ptrCast(@alignCast(opaque_ptr)));
}
