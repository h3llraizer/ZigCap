const std = @import("std");
const print = std.debug.print;

const Eth = @import("Eth.zig");
const IPv4 = @import("IPv4.zig");
const LayerProtocols = @import("ProtocolHelpers.zig");

const Allocator = std.mem.Allocator;

pub const ArpHeaderSize = 28; // ARP header size (without Ethernet header)

pub const ArpOpcode = enum(u16) {
    Request = 1,
    Reply = 2,
    RarpRequest = 3,
    RarpReply = 4,
    DrarpRequest = 5,
    DrarpReply = 6,
    DrarpError = 7,
    InarpRequest = 8,
    InarpReply = 9,
    ArpNak = 10,
    _,

    pub fn to_network(self: ArpOpcode) u16 {
        return @byteSwap(@intFromEnum(self));
    }

    pub fn from_network(value: u16) ArpOpcode {
        const host_value = @byteSwap(value);
        return @enumFromInt(host_value);
    }
};

// Use extern struct for exact 28-byte layout (standard ARP header)
pub const ArpHeader = extern struct {
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
        if (@sizeOf(ArpHeader) != 28) {
            @compileError("ArpHeader must be 28 bytes, got " ++ @typeName(@sizeOf(ArpHeader)));
        }
    }

    pub fn init_default() ArpHeader {
        return .{
            .hardware_type = 0,
            .protocol_type = 0,
            .hardware_size = 0,
            .protocol_size = 0,
            .opcode = 0,
            .sender_mac = [_]u8{0} ** 6,
            .sender_ip = [_]u8{0} ** 4,
            .target_mac = [_]u8{0} ** 6,
            .target_ip = [_]u8{0} ** 4,
        };
    }

    pub fn init_request(sender_mac: Eth.MacAddress, sender_ip: IPv4.IPv4Address, target_ip: IPv4.IPv4Address) ArpHeader {
        return .{
            .hardware_type = @byteSwap(1),
            .protocol_type = @byteSwap(0x0800),
            .hardware_size = 6,
            .protocol_size = 4,
            .opcode = ArpOpcode.Request.to_network(),
            .sender_mac = sender_mac.addr,
            .sender_ip = sender_ip.addr,
            .target_mac = [_]u8{0} ** 6,
            .target_ip = target_ip.addr,
        };
    }

    pub fn init_reply(sender_mac: Eth.MacAddress, sender_ip: IPv4.IPv4Address, target_mac: Eth.MacAddress, target_ip: IPv4.IPv4Address) ArpHeader {
        return .{
            .hardware_type = @byteSwap(1),
            .protocol_type = @byteSwap(0x0800),
            .hardware_size = 6,
            .protocol_size = 4,
            .opcode = ArpOpcode.Reply.to_network(),
            .sender_mac = sender_mac.addr,
            .sender_ip = sender_ip.addr,
            .target_mac = target_mac.addr,
            .target_ip = target_ip.addr,
        };
    }

    pub fn set_hardware_type(self: *ArpHeader, hw_type: u16) void {
        self.hardware_type = @byteSwap(hw_type);
    }

    pub fn get_hardware_type(self: *const ArpHeader) u16 {
        return @byteSwap(self.hardware_type);
    }

    pub fn set_protocol_type(self: *ArpHeader, proto_type: u16) void {
        self.protocol_type = @byteSwap(proto_type);
    }

    pub fn get_protocol_type(self: *const ArpHeader) u16 {
        return @byteSwap(self.protocol_type);
    }

    pub fn set_opcode(self: *ArpHeader, opcode: ArpOpcode) void {
        self.opcode = opcode.to_network();
    }

    pub fn get_opcode(self: *const ArpHeader) ArpOpcode {
        return ArpOpcode.from_network(self.opcode);
    }

    pub fn set_sender_mac(self: *ArpHeader, mac: Eth.MacAddress) void {
        self.sender_mac = mac.addr;
    }

    pub fn get_sender_mac(self: *const ArpHeader) Eth.MacAddress {
        return Eth.MacAddress.init_from_array(self.sender_mac);
    }

    pub fn set_sender_ip(self: *ArpHeader, ip: IPv4.IPv4Address) void {
        self.sender_ip = ip.addr;
    }

    pub fn get_sender_ip(self: *const ArpHeader) IPv4.IPv4Address {
        return IPv4.IPv4Address.init_from_array(self.sender_ip);
    }

    pub fn set_target_mac(self: *ArpHeader, mac: Eth.MacAddress) void {
        self.target_mac = mac.addr;
    }

    pub fn get_target_mac(self: *const ArpHeader) Eth.MacAddress {
        return Eth.MacAddress.init_from_array(self.target_mac);
    }

    pub fn set_target_ip(self: *ArpHeader, ip: IPv4.IPv4Address) void {
        self.target_ip = ip.addr;
    }

    pub fn get_target_ip(self: *const ArpHeader) IPv4.IPv4Address {
        return IPv4.IPv4Address.init_from_array(self.target_ip);
    }

    pub fn is_request(self: *const ArpHeader) bool {
        return self.get_opcode() == .Request;
    }

    pub fn is_reply(self: *const ArpHeader) bool {
        return self.get_opcode() == .Reply;
    }

    pub fn is_standard_arp(self: *const ArpHeader) bool {
        const op = self.get_opcode();
        return op == .Request or op == .Reply;
    }
};

pub const ArpLayer = struct {
    data: []u8, // ethhdr + arphdr + padding (if any)
    const Protocol = LayerProtocols{ .LinkLayer = .ARP };

    pub fn init(buffer: []u8) LayerProtocols.LayerError!ArpLayer {
        if (buffer.len < ArpHeaderSize) {
            return LayerProtocols.LayerError.BufferTooSmall;
        }

        const alignment = @alignOf(ArpHeader);
        const addr = @intFromPtr(buffer.ptr);

        if (addr % alignment != 0) {
            return LayerProtocols.LayerError.MisalignedBuffer;
        }

        return ArpLayer{ .data = buffer };
    }

    pub fn print_data(self: *ArpLayer) !void {
        print("{x}\n", .{self.data});
    }

    pub fn get_header(self: *ArpLayer) *ArpHeader {
        // Use alignCast to ensure proper alignment
        const aligned_ptr: [*]align(@alignOf(ArpHeader)) u8 = @alignCast(self.data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn to_string(self: *ArpLayer, allocator: Allocator) []const u8 {
        const hdr = self.get_header();

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
            std.debug.print("target_mac to_string failed: {s}\n", .{@errorName(err)});
            break :blk "";
        };
        defer if (target_mac.len != 0) allocator.free(target_mac);

        const target_ip = hdr.get_target_ip().to_string(allocator) catch |err| blk: {
            std.debug.print("target_ip to_string failed: {s}\n", .{@errorName(err)});
            break :blk "";
        };
        defer if (target_ip.len != 0) allocator.free(target_ip);

        const opcode = if (hdr.is_request()) "Request" else if (hdr.is_reply()) "Reply" else "Unknown";

        const result = std.fmt.allocPrint(
            allocator,
            "ARP {s}: sender_mac: {s}, sender_ip: {s}, target_mac: {s}, target_ip: {s}",
            .{ opcode, sender_mac, sender_ip, target_mac, target_ip },
        ) catch |err| {
            std.debug.print("allocPrint failed: {s}\n", .{@errorName(err)});
            return "";
        };

        return result;
    }

    /// get slice of data (ethhdr+arphdr+payload)
    pub fn get_data(self: *ArpLayer) []u8 {
        return self.data;
    }

    /// return mutable slice of the payload (ARP has no payload beyond the header)
    pub fn get_payload(self: *ArpLayer) []u8 {
        return self.data[0..];
    }

    /// return the next layer protocol type (ARP doesn't have a next layer)
    pub fn get_next_layer_type(self: *ArpLayer) LayerProtocols {
        _ = self;
        return LayerProtocols{ .Network = .Generic };
    }

    pub fn get_sender_mac(self: *ArpLayer) Eth.MacAddress {
        const hdr = self.get_header();
        return hdr.get_sender_mac();
    }

    pub fn get_target_mac(self: *ArpLayer) Eth.MacAddress {
        const hdr = self.get_header();
        return hdr.get_target_mac();
    }

    pub fn get_sender_ip(self: *ArpLayer) IPv4.IPv4Address {
        const hdr = self.get_header();
        return hdr.get_sender_ip();
    }

    pub fn get_target_ip(self: *ArpLayer) IPv4.IPv4Address {
        const hdr = self.get_header();
        return hdr.get_target_ip();
    }

    pub fn get_opcode(self: *ArpLayer) u16 {
        const hdr = self.get_header();
        return hdr.get_opcode();
    }

    pub fn is_request(self: *ArpLayer) bool {
        const hdr = self.get_header();
        return hdr.is_request();
    }

    pub fn is_reply(self: *ArpLayer) bool {
        const hdr = self.get_header();
        return hdr.is_reply();
    }

    pub fn get_protocol(self: *ArpLayer) LayerProtocols {
        _ = self;
        return ArpLayer.Protocol;
    }

    pub fn deinit(self: *ArpLayer, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};
