const std = @import("std");
const Eth = @import("Eth.zig");
const IPv4 = @import("IPv4.zig");
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;
const LayerOwner = @import("Owner.zig").LayerOwner;
const LayerError = @import("ProtocolEnums.zig").LayerError;
const Layer = @import("LayerIface.zig").Layer;
const init_layer = @import("LayerIface.zig").init_layer;
const initLayerFromSlice = @import("LayerIface.zig").initFromSlice;

const PacketLayer = @import("PacketLayer.zig").Layer;

const Allocator = std.mem.Allocator;
const print = std.debug.print;
const panic = std.debug.panic;

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

const default_hdr = ARPHeader.init_default();

// Use extern struct for exact 28-byte layout (standard ARP header)
pub const ARPHeader = extern struct {
    hardware_type: [2]u8, // Hardware type (1 = Ethernet)
    protocol_type: [2]u8, // Protocol type (0x0800 = IPv4)
    hardware_size: u8, // Hardware address size (6 for MAC)
    protocol_size: u8, // Protocol address size (4 for IPv4)
    opcode: [2]u8, // Operation (1 = request, 2 = reply)
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
        var arp_hdr: ARPHeader = .{
            .hardware_type = .{0} ** 2,
            .protocol_type = .{0} ** 2,
            .hardware_size = 6,
            .protocol_size = 4,
            .opcode = .{0} ** 2,
            .sender_mac = [_]u8{0} ** 6,
            .sender_ip = [_]u8{0} ** 4,
            .target_mac = [_]u8{0} ** 6,
            .target_ip = [_]u8{0} ** 4,
        };

        arp_hdr.set_hardware_type(HWTYPE.Eth);
        arp_hdr.set_protocol_type(PTYPE.IP);

        return arp_hdr;
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
        const hw_t: u16 = @intFromEnum(hw_type);

        std.mem.writeInt(u16, &self.hardware_type, hw_t, .big);
    }

    pub fn get_hardware_type(self: *const ARPHeader) HWTYPE {
        return @enumFromInt(std.mem.readInt(u16, &self.hardware_type, .big));
    }

    pub fn set_protocol_type(self: *ARPHeader, proto_type: PTYPE) void {
        std.mem.writeInt(u16, &self.protocol_type, @intFromEnum(proto_type), .big);
    }

    pub fn get_protocol_type(self: *const ARPHeader) PTYPE {
        return @enumFromInt(std.mem.readInt(u16, &self.protocol_type, .big));
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
        std.mem.writeInt(u16, &self.opcode, @intFromEnum(opcode), .big);
    }

    pub fn get_opcode(self: *const ARPHeader) ARPOpcode {
        return @enumFromInt(std.mem.readInt(u16, &self.opcode, .big));
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

    pub fn init(allocator: Allocator) LayerError!ARPLayer {
        return try init_layer(ARPLayer, allocator, ARPHeader, default_hdr);
    }

    pub fn initFromSlice(slice: []u8, allocator: Allocator) LayerError!ARPLayer {
        if (slice.len < ARPHeaderSize) return LayerError.BufferTooSmall;

        const hdr_len = ARPHeaderSize;

        return try initLayerFromSlice(slice, ARPLayer, hdr_len, ARPHeaderSize, ARPHeaderSize, allocator);
    }

    pub fn get_mutable_header(self: *ARPLayer) *ARPHeader {
        const data = self.get_data();

        if (data.len < ARPHeaderSize) {
            panic("ARP data len ({}) less than ARPHeaderSize", .{data.len});
        }

        return @ptrCast(data.ptr);
    }

    pub fn get_immutable_header(self: *const ARPLayer) *const ARPHeader {
        const data: []const u8 = self.get_data();

        if (data.len < ARPHeaderSize) {
            panic("ARP data len ({}) less than ARPHeaderSize", .{data.len});
        }

        return @ptrCast(data.ptr);
    }

    /// returns mutable slice of data (hdr+payload).
    /// this will likely be made private in future to avoid accidental mutations
    pub fn get_data(self: *const ARPLayer) []u8 {
        return self.owner.get_data();
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
    pub fn get_next_layer_type(self: *ARPLayer, layer: *PacketLayer) LayerError!?Layer {
        _ = self;
        _ = layer;
        return null;
    }

    pub fn get_protocol(self: *ARPLayer) tcp_ip_protocol {
        _ = self;
        return ARPLayer.Protocol;
    }

    pub fn deinit(self: *ARPLayer) void {
        self.owner.deinit();
    }
};
