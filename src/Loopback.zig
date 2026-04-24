const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

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
const IPv6HeaderSize = @import("IPv6.zig").IPv6HeaderSize;
const ARP = @import("ARP.zig");

const Layer = @import("Layer.zig");
const LayerOwner = Layer.LayerOwner;
const AllocatorOwner = Layer.AllocatorOwned;

const GenericLayer = @import("GenericLayer.zig");

const RawData = @import("RawData.zig").RawData;

const panic = std.debug.panic;

const LoopBackHeaderSize = 4;

pub const LoopBackHeader = extern struct {
    protocol_type: [4]u8,

    pub fn get_protocol_type(self: *const LoopBackHeader) NullLinkType {
        return @enumFromInt(self.protocol_type[0]);
    }

    pub fn set_protocol_type(self: *const LoopBackHeader, null_link_type: NullLinkType) void {
        self.protocol_type[0] = @intFromEnum(null_link_type);
    }
};

pub const LoopBackLayer = struct {
    owner: LayerOwner,
    const Protocol = tcp_ip_protocol.loopback;

    pub fn init(owner: LayerOwner) LayerError!LoopBackLayer {
        switch (owner) {
            .packet_layer => {
                return LoopBackLayer{
                    .owner = owner,
                };
            },
            .allocator_owned => {
                var self = LoopBackLayer{ .owner = owner };
                // Allocate directly into the struct's data field
                if (owner.allocator_owned.data.len < LoopBackHeaderSize) {
                    self.owner.allocator_owned.data = try self.owner.allocator_owned.allocator.alloc(u8, LoopBackHeaderSize);
                }

                //var header = LoopBackHeader.init_default();
                //@memcpy(self.owner.allocator_owned.data[0..@sizeOf(LoopBackHeader)], std.mem.asBytes(&header));

                return self;
            },
            .immutable_layer => return {
                return LoopBackLayer{ .owner = owner };
            },
        }
    }

    fn get_mutable_header(self: *const LoopBackLayer) *LoopBackHeader {
        const data = self.get_data();
        const aligned_ptr: [*]align(@alignOf(LoopBackHeader)) u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    fn get_immutable_header(self: *const LoopBackLayer) *const LoopBackHeader {
        const data: []const u8 = self.get_data();

        if (data.len < LoopBackHeaderSize) {
            panic("LoopBack Raw Data len ({}) less than LoopBackHeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(LoopBackHeader)) const u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn get_data(self: *const LoopBackLayer) []u8 {
        switch (self.owner) {
            .packet_layer => {
                print("getting data from packet.\n", .{});

                return self.owner.packet_layer.get_data(); // Layer in packet - it might be mutable or immutable

            },
            .allocator_owned => {
                return RawData{ .mutable = self.owner.allocator_owned.data }; // standalone layer - it is mutable by default
            },
            .immutable_layer => {
                return RawData{ .immutable = self.owner.immutable_layer.raw_data };
            },
        }
    }

    /// return mutable slice of the payload
    pub fn get_payload(self: *const LoopBackLayer) []const u8 { // needs to return RawData
        const data = self.get_data();
        if (data.len > LoopBackHeaderSize) {
            return data[LoopBackHeaderSize..];
        } else {
            return "";
        }
    }

    pub fn get_next_layer_type(self: *LoopBackLayer, layer: *Packet.Layer) !?LayerIface {
        const hdr = self.get_immutable_header();
        const protocol_type = hdr.get_protocol_type();

        const data = self.get_data();

        print("{x}\n", .{data});

        switch (protocol_type) {
            .IPv4 => {
                if (data.len <= LoopBackHeaderSize) {
                    return null;
                }

                const ihl_byte = data[LoopBackHeaderSize];
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
            //           LoopBackType.IPV6 => {
            //               return try LayerIface.init(IPv6.IPv6Layer, LayerOwner{ .packet_layer = layer });
            //           },

            else => {
                return null;
            },
        }
    }

    pub fn to_string(self: *LoopBackLayer, allocator: Allocator) []const u8 {
        _ = self;
        _ = allocator;
        const str: []const u8 = "loopback layer.\n";
        return str;
    }

    pub fn get_protocol(self: *LoopBackLayer) tcp_ip_protocol {
        _ = self;
        return LoopBackLayer.Protocol;
    }
};
