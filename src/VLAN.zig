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

const VLANHeaderSize = 4;

const default_hdr = VLANHeader.init_default();

pub const VLANHeader = extern struct {
    tci: [2]u8, // Tag Control Information
    tpi: [2]u8, // Tag Protocol Identifier

    comptime {
        if (@sizeOf(VLANHeader) != 4) {
            @compileError("VLANHeader must be 4 bytes, got " ++ @typeName(@sizeOf(VLANHeader)));
        }
    }

    pub fn init_default() VLANHeader {
        return .{
            .tci = .{0} ** 2,
            .tpi = .{0} ** 2,
        };
    }

    pub fn set_tpi(self: *VLANHeader, tpi: EthType) void {
        std.mem.writeInt(u16, &self.tpi, @intFromEnum(tpi), .big);
    }

    pub fn get_tpi(self: *const VLANHeader) EthType {
        return @enumFromInt(std.mem.readInt(u16, &self.tpi, .big));
    }

    pub fn set_tci(self: *VLANHeader, tci: u16) void {
        std.mem.writeInt(u16, &self.tci, tci, .big);
    }

    pub fn get_tci(self: *const VLANHeader) u16 {
        return std.mem.readInt(u16, &self.tci, .big);
    }
};

pub const VLANLayer = struct {
    owner: LayerOwner,

    pub fn init(owner: LayerOwner) LayerError!VLANLayer {
        return try init_layer(VLANLayer, owner, VLANHeader, default_hdr);
    }

    pub fn zero_hdr() []u8 {
        var header = VLANHeader.init_default();
        var data: []u8 = undefined;
        @memcpy(data[0..@sizeOf(VLANHeader)], std.mem.asBytes(&header));
        return data;
    }

    pub fn get_mutable_header(self: *const VLANLayer) *VLANHeader {
        const data = self.get_data();
        const aligned_ptr: [*]align(@alignOf(VLANHeader)) u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn get_immutable_header(self: *const VLANLayer) *const VLANHeader {
        const data: []const u8 = self.get_data();

        if (data.len < VLANHeaderSize) {
            panic("VLAN Raw Data len ({}) less than VLANHeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(VLANHeader)) const u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn to_string(self: *const VLANLayer, allocator: Allocator) []const u8 {
        const hdr = self.get_immutable_header();

        const eth_type = hdr.get_tpi();

        const eth_type_str = @tagName(eth_type);

        const result = std.fmt.allocPrint(
            allocator,
            "VLANLayer: VLANType: {s}, tci: {}\n",
            .{ eth_type_str, hdr.get_tci() },
        ) catch |err| {
            std.debug.print("allocPrint failed: {s}\n", .{@errorName(err)});
            return "";
        };

        return result;
    }

    /// get slice of data (hdr+payload)
    pub fn get_data(self: *const VLANLayer) []u8 {
        return self.owner.get_data();
    }

    /// return mutable slice of the payload
    pub fn get_payload(self: *VLANLayer) []const u8 {
        const data = self.get_data();

        if (data.len > VLANHeaderSize) {
            return data[VLANHeaderSize..]; // return remaining bytes after the header
        } else {
            return "";
        }
    }

    pub fn validate_layer(self: *VLANLayer) void {
        if (self.owner.is_packet_owned()) {
            if (self.owner.packet_layer.next_layer) |next_layer| {
                const protocol = next_layer.layer_iface.get_protocol();

                const hdr = self.get_mutable_header();

                switch (protocol) {
                    .ipv4 => hdr.set_tpi(.IP),
                    .ipv6 => hdr.set_tpi(.IPV6),
                    .arp => hdr.set_tpi(.ARP),
                    .loopback => hdr.set_tpi(.LOOPBACK),
                    else => {},
                }
            }
        }
    }

    /// return the next layer protocol type
    pub fn get_next_layer_type(self: *VLANLayer, layer: *Packet.Layer) LayerError!?LayerIface {
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

    pub fn get_protocol(self: *VLANLayer) tcp_ip_protocol {
        _ = self;
        return tcp_ip_protocol.vlan;
    }

    pub fn deinit(self: *VLANLayer) void {
        self.owner.deinit();
    }
};
