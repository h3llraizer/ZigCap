// src/lib.zig - Main entry point for ZigCap library
const std = @import("std");

// This will be your public API
pub const Version = struct {
    major: u32,
    minor: u32,
    patch: u32,
};

pub const version = Version{
    .major = 0,
    .minor = 1,
    .patch = 0,
};
pub const Eth = @import("Eth.zig");
pub const VLAN = @import("VLAN.zig");
pub const Loopback = @import("Loopback.zig");
pub const ARP = @import("ARP.zig");
pub const DHCP = @import("DHCP.zig");
pub const DNS = @import("DNS.zig");
pub const ICMP = @import("ICMP.zig");
pub const IGMP = @import("IGMP.zig");
pub const IPv4 = @import("IPv4.zig");
pub const IPv6 = @import("IPv6.zig");
pub const IPAddress = @import("IPAddress.zig").IPAddress;
pub const Packet = @import("Packet.zig").Packet;
pub const TCP = @import("TCP.zig");
pub const UDP = @import("UDP.zig");
pub const ApplicationLayer = @import("GenericLayer.zig").ApplicationLayer;
pub const TransportLayer = @import("TransportLayer.zig").TransportLayer;
pub const ProtocolEnums = @import("ProtocolEnums.zig");
pub const Owner = @import("Owner.zig");
pub const Layer = @import("LayerIface.zig").Layer;
pub const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;
pub const PcapWrapper = @import("PcapWrapper.zig");
pub const WinDivertWrapper = @import("WinDivertWrapper.zig");
pub const Buffer = @import("Buffer.zig");
