const std = @import("std");
const print = std.debug.print;
const panic = std.debug.panic;

const Eth = @import("Eth.zig");
const IPv4 = @import("IPv4.zig");
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;

const Allocator = std.mem.Allocator;

const LayerOwner = @import("Layer.zig").LayerOwner;
const LayerError = @import("ProtocolEnums.zig").LayerError;
const RawData = @import("RawData.zig").RawData;

const LayerIface = @import("LayerIface.zig").LayerIface;

const Layer = @import("Packet.zig").Layer;

pub const ARPHeaderSize = 28; // ARP header size (without Ethernet header)

pub const ARPOpcode = enum(u16) {
    Request = 1,
    Reply = 2,
    RarpRequest = 3,
    RarpReply = 4,
    DrarpRequest = 5,
    DrarpReply = 6,
    DrarpError = 7,
    InarpRequest = 8,
    InarpReply = 9,
    ARPNak = 10,
    _,

    pub fn to_network(self: ARPOpcode) u16 {
        return @byteSwap(@intFromEnum(self));
    }

    pub fn from_network(value: u16) ARPOpcode {
        const host_value = @byteSwap(value);
        return @enumFromInt(host_value);
    }
};

/// Protocol-type values in ARP Header is identical to EthType in EthHeader
pub const PTYPE = Eth.EthType;

// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
pub const HWTYPE = enum(u16) {
    Eth = 1,
};

// Use extern struct for exact 28-byte layout (standard ARP header)
pub const ARPHeader = extern struct {
    hardware_type: u16, // Hardware type (1 = Ethernet)
    protocol_type: u16, // Protocol type (0x0800 = IPv4)
    hardware_size: u8, // Hardware address size (6 for MAC)
    protocol_size: u8, // Protocol address size (4 for IPv4)
    opcode: u16, // Operation (1 = request, 2 = reply)
    sender_mac: [6]u8, // Sender hardware address
    sender_ip: [4]u8, // Sender protocol address
    target_mac: [6]u8, // Target hardware address
    target_ip: [4]u8, // Target protocol address

    comptime {
        if (@sizeOf(ARPHeader) != 28) {
            @compileError("ARPHeader must be 28 bytes, got " ++ @typeName(@sizeOf(ARPHeader)));
        }
    }

    pub fn init_default() ARPHeader {
        return .{
            .hardware_type = @byteSwap(@intFromEnum(HWTYPE.Eth)),
            .protocol_type = @byteSwap(@intFromEnum(PTYPE.IP)),
            .hardware_size = 6,
            .protocol_size = 4,
            .opcode = 0,
            .sender_mac = [_]u8{0} ** 6,
            .sender_ip = [_]u8{0} ** 4,
            .target_mac = [_]u8{0} ** 6,
            .target_ip = [_]u8{0} ** 4,
        };
    }

    pub fn init_request(sender_mac: Eth.MacAddress, sender_ip: IPv4.IPv4Address, target_ip: IPv4.IPv4Address) ARPHeader {
        return .{
            .hardware_type = @byteSwap(@intFromEnum(HWTYPE.Eth)),
            .protocol_type = @byteSwap(@intFromEnum(PTYPE.IP)),
            .hardware_size = 6,
            .protocol_size = 4,
            .opcode = ARPOpcode.Request.to_network(),
            .sender_mac = sender_mac.addr,
            .sender_ip = sender_ip.addr,
            .target_mac = [_]u8{0} ** 6,
            .target_ip = target_ip.addr,
        };
    }

    pub fn init_reply(sender_mac: Eth.MacAddress, sender_ip: IPv4.IPv4Address, target_mac: Eth.MacAddress, target_ip: IPv4.IPv4Address) ARPHeader {
        return .{
            .hardware_type = @byteSwap(@intFromEnum(HWTYPE.Eth)),
            .protocol_type = @byteSwap(@intFromEnum(PTYPE.IP)),
            .hardware_size = 6,
            .protocol_size = 4,
            .opcode = ARPOpcode.Reply.to_network(),
            .sender_mac = sender_mac.addr,
            .sender_ip = sender_ip.addr,
            .target_mac = target_mac.addr,
            .target_ip = target_ip.addr,
        };
    }

    pub fn set_hardware_type(self: *ARPHeader, hw_type: HWTYPE) void {
        self.hardware_type = @byteSwap(@intFromEnum(hw_type));
    }

    pub fn get_hardware_type(self: *const ARPHeader) HWTYPE {
        return @enumFromInt(@byteSwap(self.hardware_type));
    }

    pub fn set_protocol_type(self: *ARPHeader, proto_type: PTYPE) void {
        self.protocol_type = @byteSwap(@intFromEnum(proto_type));
    }

    pub fn get_protocol_type(self: *const ARPHeader) PTYPE {
        return @enumFromInt(@byteSwap(self.protocol_type));
    }

    pub fn set_hardware_size(self: *ARPHeader, size: u8) void {
        self.hardware_size = size;
    }

    pub fn get_hardware_size(self: *const ARPHeader) u8 {
        return self.hardware_size;
    }

    pub fn set_protocol_size(self: *ARPHeader, size: u8) void {
        self.protocol_size = size;
    }

    pub fn get_protocol_size(self: *const ARPHeader) u8 {
        return self.protocol_size;
    }

    pub fn set_opcode(self: *ARPHeader, opcode: ARPOpcode) void {
        self.opcode = opcode.to_network();
    }

    pub fn get_opcode(self: *const ARPHeader) ARPOpcode {
        return ARPOpcode.from_network(self.opcode);
    }

    pub fn set_sender_mac(self: *ARPHeader, mac: Eth.MacAddress) void {
        self.sender_mac = mac.addr;
    }

    pub fn get_sender_mac(self: *const ARPHeader) Eth.MacAddress {
        return Eth.MacAddress.init_from_array(self.sender_mac);
    }

    pub fn set_sender_ip(self: *ARPHeader, ip: IPv4.IPv4Address) void {
        self.sender_ip = ip.array;
    }

    pub fn get_sender_ip(self: *const ARPHeader) IPv4.IPv4Address {
        return IPv4.IPv4Address.init_from_array(self.sender_ip);
    }

    pub fn set_target_mac(self: *ARPHeader, mac: Eth.MacAddress) void {
        self.target_mac = mac.addr;
    }

    pub fn get_target_mac(self: *const ARPHeader) Eth.MacAddress {
        return Eth.MacAddress.init_from_array(self.target_mac);
    }

    pub fn set_target_ip(self: *ARPHeader, ip: IPv4.IPv4Address) void {
        self.target_ip = ip.array;
    }

    pub fn get_target_ip(self: *const ARPHeader) IPv4.IPv4Address {
        return IPv4.IPv4Address.init_from_array(self.target_ip);
    }

    pub fn is_request(self: *const ARPHeader) bool {
        return self.get_opcode() == .Request;
    }

    pub fn is_reply(self: *const ARPHeader) bool {
        return self.get_opcode() == .Reply;
    }

    pub fn is_standard_arp(self: *const ARPHeader) bool {
        const op = self.get_opcode();
        return op == .Request or op == .Reply;
    }
};

pub const ARPLayer = struct {
    owner: LayerOwner,
    const Protocol = tcp_ip_protocol.arp;

    pub fn init(owner: LayerOwner) LayerError!ARPLayer {
        switch (owner) {
            .packet_layer => {
                return ARPLayer{
                    .owner = owner,
                };
            },
            .owned_buffer => {
                var self = ARPLayer{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < ARPHeaderSize) {
                    const arp_data = try self.owner.owned_buffer.extend(buffer_len, ARPHeaderSize);

                    @memset(arp_data, 0);

                    var header = ARPHeader.init_default();

                    @memcpy(arp_data[0..ARPHeaderSize], std.mem.asBytes(&header));
                }

                return self;
            },
        }
    }

    pub fn get_mutable_header(self: *ARPLayer) *ARPHeader {
        const data = self.get_data();

        if (data.len < ARPHeaderSize) {
            panic("ARP data len ({}) less than ARPHeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(ARPHeader)) u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn get_immutable_header(self: *const ARPLayer) *const ARPHeader {
        const data: []const u8 = self.get_data();

        if (data.len < ARPHeaderSize) {
            panic("ARP data len ({}) less than ARPHeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(ARPHeader)) const u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    /// returns mutable slice of data (hdr+payload).
    /// this will likely be made private in future to avoid accidental mutations
    pub fn get_data(self: *const ARPLayer) []u8 {
        switch (self.owner) {
            .packet_layer => |layer| {
                return layer.get_data(); // Layer in packet - it might be mutable or immutable
            },
            .owned_buffer => |*buffer| {
                return buffer.buffer.items; // standalone layer - it is mutable by default
            },
        }
    }

    /// return mutable slice of the payload (ARP has no payload beyond the header)
    pub fn get_payload(self: *ARPLayer) []const u8 {
        _ = self;
        return "";
    }

    pub fn get_sender_mac(self: *ARPLayer) Eth.MacAddress {
        const hdr = self.get_immutable_header();
        return hdr.get_sender_mac();
    }

    pub fn set_sender_mac(self: *ARPLayer, mac: Eth.MacAddress) void {
        const hdr = self.get_mutable_header();
        return hdr.set_sender_mac(mac);
    }

    pub fn get_target_mac(self: *ARPLayer) Eth.MacAddress {
        const hdr = self.get_immutable_header();
        return hdr.get_target_mac();
    }

    pub fn set_target_mac(self: *ARPLayer, mac: Eth.MacAddress) void {
        const hdr = self.get_mutable_header();
        return hdr.set_target_mac(mac);
    }

    pub fn get_sender_ip(self: *ARPLayer) IPv4.IPv4Address {
        const hdr = self.get_immutable_header();
        return hdr.get_sender_ip();
    }

    pub fn set_sender_ip(self: *ARPLayer, ip: IPv4.IPv4Address) void {
        const hdr = self.get_mutable_header();
        return hdr.set_sender_ip(ip);
    }

    pub fn get_target_ip(self: *ARPLayer) IPv4.IPv4Address {
        const hdr = self.get_immutable_header();
        return hdr.get_target_ip();
    }

    pub fn set_target_ip(self: *ARPLayer, ip: IPv4.IPv4Address) void {
        const hdr = self.get_mutable_header();
        return hdr.set_target_ip(ip);
    }

    pub fn get_opcode(self: *ARPLayer) ARPOpcode {
        const hdr = self.get_immutable_header();
        return hdr.get_opcode();
    }

    pub fn set_opcode(self: *ARPLayer, op_code: ARPOpcode) void {
        const hdr = self.get_mutable_header();
        return hdr.set_opcode(op_code);
    }

    pub fn is_request(self: *ARPLayer) bool {
        const hdr = self.get_immutable_header();
        return hdr.is_request();
    }

    pub fn is_reply(self: *ARPLayer) bool {
        const hdr = self.get_immutable_header();
        return hdr.is_reply();
    }

    pub fn to_string(self: *ARPLayer, allocator: Allocator) []const u8 {
        const hdr = self.get_immutable_header();

        const sender_mac = hdr.get_sender_mac().to_string(allocator) catch |err| blk: {
            std.debug.print("sender_mac to_string failed: {s}\n", .{@errorName(err)});
            break :blk "";
        };
        defer if (sender_mac.len != 0) allocator.free(sender_mac);

        const sender_ip = hdr.get_sender_ip().to_string(allocator) catch |err| blk: {
            std.debug.print("sender_ip to_string failed: {s}\n", .{@errorName(err)});
            break :blk "";
        };
        defer if (sender_ip.len != 0) allocator.free(sender_ip);

        const target_mac = hdr.get_target_mac().to_string(allocator) catch |err| blk: {
            print("target_mac to_string failed: {s}\n", .{@errorName(err)});
            break :blk "";
        };
        defer if (target_mac.len != 0) allocator.free(target_mac);

        const target_ip = hdr.get_target_ip().to_string(allocator) catch |err| blk: {
            std.debug.print("target_ip to_string failed: {s}\n", .{@errorName(err)});
            break :blk "";
        };
        defer if (target_ip.len != 0) allocator.free(target_ip);

        const opcode = if (hdr.is_request()) "Request" else if (hdr.is_reply()) "Reply" else "Unknown";

        const ptype = hdr.get_protocol_type();
        const hwtype = hdr.get_hardware_type();

        const result = std.fmt.allocPrint(
            allocator,
            "ARP {s}: ptype: {s}, hwtype: {s}, sender_mac: {s}, sender_ip: {s}, target_mac: {s}, target_ip: {s}",
            .{ opcode, @tagName(ptype), @tagName(hwtype), sender_mac, sender_ip, target_mac, target_ip },
        ) catch |err| {
            std.debug.print("allocPrint failed: {s}\n", .{@errorName(err)});
            return "";
        };

        return result;
    }

    pub fn validate_layer(self: *ARPLayer) void {
        _ = self;
    }

    /// return the next layer protocol type (ARP doesn't have a next layer)
    pub fn get_next_layer_type(self: *ARPLayer, layer: *Layer) !?LayerIface {
        _ = self;
        _ = layer;
        return null;
    }

    pub fn get_protocol(self: *ARPLayer) tcp_ip_protocol {
        _ = self;
        return ARPLayer.Protocol;
    }

    pub fn deinit(self: *ARPLayer) void {
        switch (self.owner) {
            .packet_layer => {
                return; // Layer in packet - don't free
            },
            .owned_buffer => |*buffer| {
                return buffer.deinit(); // standalone layer - it is mutable by default
            },
        }
    }
};
