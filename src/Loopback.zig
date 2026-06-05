const std = @import("std");
const Packet = @import("Packet.zig");
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;
const LayerError = @import("ProtocolEnums.zig").LayerError;
const NullLinkType = @import("ProtocolEnums.zig").NullLinkType;
const LayerIface = @import("LayerIface.zig").LayerIface;
const IPVersion = @import("ProtocolEnums.zig").IPVersions;
const IPv4Layer = @import("IPv4.zig").IPv4Layer;
const IPv4Header = @import("IPv4.zig").IPv4Header;
const IPv4 = @import("IPv4.zig");
const IPv6 = @import("IPv6.zig");
const ARP = @import("ARP.zig");
const Owner = @import("Owner.zig");

const GenericLayer = @import("GenericLayer.zig");

const print = std.debug.print;
const Allocator = std.mem.Allocator;
const panic = std.debug.panic;
const LayerOwner = Owner.LayerOwner;
const IPv6HeaderSize = IPv6.IPv6HeaderSize;

const LoopbackHeaderSize = 4;

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

    pub fn init(owner: LayerOwner) LayerError!LoopbackLayer {
        switch (owner) {
            .packet_layer => {
                return LoopbackLayer{
                    .owner = owner,
                };
            },
            .owned_buffer => {
                var self = LoopbackLayer{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < LoopbackHeaderSize) {
                    const diff = LoopbackHeaderSize - buffer_len;
                    const lb_data = try self.owner.owned_buffer.extend(buffer_len, diff);

                    @memset(lb_data, 0);
                }

                return self;
            },
        }
    }

    fn get_mutable_header(self: *const LoopbackLayer) *LoopbackHeader {
        const data = self.get_data();
        const aligned_ptr: [*]align(@alignOf(LoopbackHeader)) u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    fn get_immutable_header(self: *const LoopbackLayer) *const LoopbackHeader {
        const data: []const u8 = self.get_data();

        if (data.len < LoopbackHeaderSize) {
            panic("Loopback Raw Data len ({}) less than LoopbackHeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(LoopbackHeader)) const u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
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

    pub fn get_next_layer_type(self: *LoopbackLayer, layer: *Packet.Layer) LayerError!?LayerIface {
        const hdr = self.get_immutable_header();
        const protocol_type = hdr.get_protocol_type();

        const data = self.get_data();

        print("{x}\n", .{data});

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
                        return try LayerIface.init(GenericLayer.ApplicationLayer, LayerOwner{ .packet_layer = layer });
                    }

                    return try LayerIface.init(IPv4.IPv4Layer, LayerOwner{ .packet_layer = layer });
                }

                if (ip_version == @intFromEnum(IPVersion.IPv6)) {
                    return null;
                } else {
                    return null;
                }
            },
            //           LoopbackType.IPV6 => {
            //               return try LayerIface.init(IPv6.IPv6Layer, LayerOwner{ .packet_layer = layer });
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
