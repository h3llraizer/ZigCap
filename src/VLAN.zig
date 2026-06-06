const std = @import("std");
const Packet = @import("Packet.zig");
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;
const ProtocolEnums = @import("ProtocolEnums.zig");
const LayerIface = @import("LayerIface.zig").LayerIface;
const init_layer = @import("LayerIface.zig").init_layer;
const IPv4 = @import("IPv4.zig");
const IPv6 = @import("IPv6.zig");
const ARP = @import("ARP.zig");
const Owner = @import("Owner.zig");
const GenericLayer = @import("GenericLayer.zig");
const Eth = @import("Eth.zig");

const print = std.debug.print;
const Allocator = std.mem.Allocator;
const panic = std.debug.panic;
const LayerError = ProtocolEnums.LayerError;
const IPVersion = ProtocolEnums.IPVersions;
const LayerOwner = Owner.LayerOwner;
const EthType = Eth.EthType;
const IPv6HeaderSize = IPv6.IPv6HeaderSize;
const IPv4Header = IPv4.IPv4Header;

const VlanHeaderSize = 4;

const default_hdr = VlanHeader{
    .tci = 0,
    .tpi = 0,
};

pub const VlanHeader = extern struct {
    tci: u16, // Tag Control Information
    tpi: u16, // Tag Protocol Identifier

    comptime {
        if (@sizeOf(VlanHeader) != 4) {
            @compileError("VlanHeader must be 4 bytes, got " ++ @typeName(@sizeOf(VlanHeader)));
        }
    }

    pub fn init_default() VlanHeader {
        return .{
            .tci = 0,
            .tpi = 0,
        };
    }

    pub fn set_tpi(self: *VlanHeader, tpi: EthType) void {
        self.tpi = @byteSwap(@intFromEnum(tpi));
    }

    pub fn get_tpi(self: *const VlanHeader) EthType {
        return @enumFromInt(@byteSwap(self.tpi));
    }

    pub fn set_tci(self: *VlanHeader, tci: u16) void {
        self.tci = tci;
    }

    pub fn get_tci(self: *const VlanHeader) u16 {
        return self.tci;
    }
};

pub const VlanLayer = struct {
    owner: LayerOwner,
    const Protocol = tcp_ip_protocol.vlan;

    pub fn init(owner: LayerOwner) LayerError!VlanLayer {
        return try init_layer(VlanLayer, owner, VlanHeader, default_hdr);
    }

    pub fn zero_hdr() []u8 {
        var header = VlanHeader.init_default();
        var data: []u8 = undefined;
        @memcpy(data[0..@sizeOf(VlanHeader)], std.mem.asBytes(&header));
        return data;
    }

    pub fn get_mutable_header(self: *const VlanLayer) *VlanHeader {
        const data = self.get_data();
        const aligned_ptr: [*]align(@alignOf(VlanHeader)) u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn get_immutable_header(self: *const VlanLayer) *const VlanHeader {
        const data: []const u8 = self.get_data();

        if (data.len < VlanHeaderSize) {
            panic("Vlan Raw Data len ({}) less than VlanHeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(VlanHeader)) const u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn to_string(self: *const VlanLayer, allocator: Allocator) []const u8 {
        const hdr = self.get_immutable_header();

        const eth_type = hdr.get_tpi();

        const eth_type_str = @tagName(eth_type);

        const result = std.fmt.allocPrint(
            allocator,
            "VlanLayer: VlanType: {s}, tci: {}\n",
            .{ eth_type_str, hdr.tci },
        ) catch |err| {
            std.debug.print("allocPrint failed: {s}\n", .{@errorName(err)});
            return "";
        };

        return result;
    }

    /// get slice of data (hdr+payload)
    pub fn get_data(self: *const VlanLayer) []u8 {
        return self.owner.get_data();
    }

    /// return mutable slice of the payload
    pub fn get_payload(self: *VlanLayer) []const u8 {
        const data = self.get_data();

        if (data.len > VlanHeaderSize) {
            return data[VlanHeaderSize..]; // return remaining bytes after the header
        } else {
            return "";
        }
    }

    pub fn validate_layer(self: *VlanLayer) void {
        _ = self;
    }

    /// return the next layer protocol type
    pub fn get_next_layer_type(self: *VlanLayer, layer: *Packet.Layer) LayerError!?LayerIface {
        const hdr = self.get_immutable_header();
        const eth_type = hdr.get_tpi();

        const data = self.get_payload();

        if (data.len == 0) {
            return null;
        }

        switch (eth_type) {
            EthType.IP => {
                const ihl_byte = data[0];
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
                    print("unknown IP type.\n", .{});
                    return null;
                }
            },
            EthType.IPV6 => {
                return try LayerIface.init(IPv6.IPv6Layer, LayerOwner{ .packet_layer = layer });
            },
            EthType.ARP => {
                return try LayerIface.init(ARP.ARPLayer, LayerOwner{ .packet_layer = layer });
            },
            else => {
                print("couldn't get Eth {any} protocol.\n", .{eth_type});
                return null;
            },
        }
    }

    pub fn get_protocol(self: *VlanLayer) tcp_ip_protocol {
        _ = self;
        return VlanLayer.Protocol;
    }

    pub fn deinit(self: *VlanLayer) void {
        self.owner.deinit();
    }
};
