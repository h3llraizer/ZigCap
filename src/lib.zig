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

pub const ARP = @import("ARP.zig");
pub const DNS = @import("DNS.zig");
pub const Eth = @import("Eth.zig");
pub const ICMP = @import("ICMP.zig");
pub const IPv4 = @import("IPv4.zig");
pub const IPv6 = @import("IPv6.zig");
pub const Packet = @import("Packet.zig");
pub const TCP = @import("TCP.zig");
pub const UDP = @import("UDP.zig");
pub const RawData = @import("RawData.zig").RawData;
pub const ProtocolHelpers = @import("ProtocolHelpers.zig");
pub const Layer = @import("Layer.zig");
