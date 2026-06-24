const std = @import("std");
const Packet = @import("Packet.zig");
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;
const LayerError = @import("ProtocolEnums.zig").LayerError;
const NullLinkType = @import("ProtocolEnums.zig").NullLinkType;
const Layer = @import("LayerIface.zig").Layer;
const init_layer = @import("LayerIface.zig").init_layer;
const initLayerFromSlice = @import("LayerIface.zig").initFromSlice;
const IPVersion = @import("ProtocolEnums.zig").IPVersions;
const IPv4Layer = @import("IPv4.zig").IPv4Layer;
const IPv4Header = @import("IPv4.zig").IPv4Header;
const IPv4 = @import("IPv4.zig");
const IPv6 = @import("IPv6.zig");
const ARP = @import("ARP.zig");
const Owner = @import("Owner.zig");

const GenericLayer = @import("GenericLayer.zig");

const PacketLayer = @import("PacketLayer.zig").Layer;

const print = std.debug.print;
const Allocator = std.mem.Allocator;
const panic = std.debug.panic;
const LayerOwner = Owner.LayerOwner;
const IPv6HeaderSize = IPv6.IPv6HeaderSize;

const LoopbackHeaderSize = 4;

const default_hdr = LoopbackHeader{
    .protocol_type = .{0x00} ** 4,
};

pub const LoopbackHeader = extern struct {
    protocol_type: [4]u8,

    pub fn get_protocol_type(self: *const LoopbackHeader) NullLinkType {
        return @enumFromInt(self.protocol_type[0]);
    }

    pub fn set_protocol_type(self: *const LoopbackHeader, null_link_type: NullLinkType) void {
        self.protocol_type[0] = @intFromEnum(null_link_type);
    }
};

pub const LoopbackLayer = struct {
    owner: LayerOwner,
    const Protocol = tcp_ip_protocol.loopback;

    pub fn init(allocator: Allocator) LayerError!LoopbackLayer {
        return try init_layer(LoopbackLayer, allocator, LoopbackHeader, default_hdr);
    }

    pub fn initFromSlice(slice: []u8, allocator: Allocator) LayerError!LoopbackLayer {
        if (slice.len < LoopbackHeaderSize) return LayerError.BufferTooSmall;

        const hdr_len = LoopbackHeaderSize;

        return try initLayerFromSlice(slice, LoopbackLayer, hdr_len, LoopbackHeaderSize, LoopbackHeaderSize, allocator);
    }

    fn get_mutable_header(self: *const LoopbackLayer) *LoopbackHeader {
        const data = self.get_data();
        return @ptrCast(data.ptr);
    }

    fn get_immutable_header(self: *const LoopbackLayer) *const LoopbackHeader {
        const data: []const u8 = self.get_data();

        if (data.len < LoopbackHeaderSize) {
            panic("Loopback Raw Data len ({}) less than LoopbackHeaderSize", .{data.len});
        }

        return @ptrCast(data.ptr);
    }

    pub fn get_data(self: *const LoopbackLayer) []u8 {
        return self.owner.get_data();
    }

    /// return mutable slice of the payload
    pub fn get_payload(self: *const LoopbackLayer) []const u8 { // needs to return RawData
        const data = self.get_data();
        if (data.len > LoopbackHeaderSize) {
            return data[LoopbackHeaderSize..];
        } else {
            return "";
        }
    }

    pub fn get_next_layer_type(self: *LoopbackLayer, layer: *PacketLayer) LayerError!?Layer {
        const hdr = self.get_immutable_header();
        const protocol_type = hdr.get_protocol_type();

        const data = self.get_data();

        switch (protocol_type) {
            .IPv4 => {
                if (data.len <= LoopbackHeaderSize) {
                    return null;
                }

                const ihl_byte = data[LoopbackHeaderSize];
                const ip_version = ihl_byte >> 4;
                const hdr_len = (ihl_byte & 0x0F) * 4;

                if (ip_version == @intFromEnum(IPVersion.IPv4)) {
                    if (hdr_len < IPv4.MinHeaderLength or hdr_len > IPv4.MaxHeaderLength) {
                        return Layer{ .genericAppLayer = .{ .owner = .{ .packet_layer = layer } } };
                    }

                    return Layer{ .ipv4Layer = .{ .owner = .{ .packet_layer = layer } } };
                }

                if (ip_version == @intFromEnum(IPVersion.IPv6)) {
                    return null;
                } else {
                    return null;
                }
            },
            //           LoopbackType.IPV6 => {
            //               return try Layer.init(IPv6.IPv6Layer, LayerOwner{ .packet_layer = layer });
            //           },

            else => {
                return null;
            },
        }
    }

    pub fn validate_layer(self: *LoopbackLayer) void {
        _ = self;
        return;
    }

    pub fn to_string(self: *LoopbackLayer, allocator: Allocator) []const u8 {
        _ = self;
        _ = allocator;
        return "loopback layer.\n";
    }

    pub fn get_protocol(self: *LoopbackLayer) tcp_ip_protocol {
        _ = self;
        return LoopbackLayer.Protocol;
    }

    pub fn deinit(self: *LoopbackLayer) void {
        self.owner.deinit();
    }
};
