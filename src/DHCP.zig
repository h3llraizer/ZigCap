const std = @import("std");
const print = std.debug.print;
const panic = std.debug.panic;
const Allocator = std.mem.Allocator;

const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;
const LayerOwner = @import("Layer.zig").LayerOwner;
const LayerError = @import("ProtocolEnums.zig").LayerError;
const LayerIface = @import("LayerIface.zig").LayerIface;
const Layer = @import("Packet.zig").Layer;
const IPv4Address = @import("IPv4.zig").IPv4Address;
const Eth = @import("Eth.zig");

pub const HWTYPE = enum(u8) {
    Eth = 0x1,
};

pub const OPCode = enum(u8) {
    BootRequest = 1, // Client -> Server
    BootReply = 2, // Server -> Client
};

pub const DHCPHeaderSize = 240; // Minimum size

pub const MessageType = enum(u8) {
    DHCPDISCOVER = 1, //       Client broadcasts to find available DHCP servers.
    DHCPOFFER = 2, //       Server offers an IP address to the client.
    DHCPREQUEST = 3, //       Client requests to accept the offered IP address.
    DHCPDECLINE = 4, //       Client rejects the offered IP address (if in use).
    DHCPACK = 5, //       Server confirms the lease assignment to the client.
    DHCPNAK = 6, //       Server rejects the renewal or invalid request.
    DHCPRELEASE = 7, //       Client releases the current IP address back to the server.
    DHCPINFORM = 8, //       Client requests options only (for static IPs).

    pub fn get_value(self: MessageType) u8 {
        return @intFromEnum(self);
    }
};

pub const SubnetMask = enum(u8) {
    n0 = 0,
    n1 = 1,
    n2 = 2,
    n3 = 3,
    n4 = 4,
    n5 = 5,
    n6 = 6,
    n7 = 7,
    n8 = 8,
    n9 = 9,
    n10 = 10,
    n11 = 11,
    n12 = 12,
    n13 = 13,
    n14 = 14,
    n15 = 15,
    n16 = 16,
    n17 = 17,
    n18 = 18,
    n19 = 19,
    n20 = 20,
    n21 = 21,
    n22 = 22,
    n23 = 23,
    n24 = 24,
    n25 = 25,
    n26 = 26,
    n27 = 27,
    n28 = 28,
    n29 = 29,
    n30 = 30,
    n31 = 31,
    n32 = 32,

    /// return the mask as a full u32 value
    pub fn toU32(self: SubnetMask) u32 {
        const p: u32 = @intCast(@intFromEnum(self));

        return if (p == 0)
            0
        else
            (~@as(u32, 0)) << @intCast(32 - p);
    }

    /// returns full IPv4 subnet mask e.g. 255.255.255.0
    pub fn get_value(self: SubnetMask) u32 {
        return @byteSwap(IPv4Address.init_from_u32(self.toU32()).to_u32());
    }
};

pub const DNSServer = struct {
    ip: IPv4Address,

    pub fn get_value(self: DNSServer) u32 {
        return @byteSwap(self.ip.to_u32());
    }
};

pub const Router = struct {
    ip: IPv4Address,

    pub fn get_value(self: Router) u32 {
        return @byteSwap(self.ip.to_u32());
    }
};

pub const LeaseTime = struct {
    time: u32,

    pub fn get_value(self: LeaseTime) u32 {
        return @byteSwap(self.time);
    }
};

pub const OptionValues = union(enum) {
    msgType: MessageType,
    subnetMask: SubnetMask,
    dnsServer: DNSServer,
    router: Router,
    leaseTime: LeaseTime,

    pub fn get_value(self: OptionValues) u64 {
        return switch (self) {
            inline else => |val| val.get_value(),
        };
    }

    pub fn get_opt_length(self: OptionValues) usize {
        return switch (self) {
            .msgType => return @sizeOf(u8),
            .subnetMask => return @sizeOf(u32),
            .dnsServer => return @sizeOf(u32),
            .leaseTime => return @sizeOf(u32),
            .router => return @sizeOf(u32),
        };
    }
};

pub const Option = enum(u8) {
    Pad = 0,
    SubnetMask = 1,
    Router = 3,
    DomainNameServer = 6,
    RequestedIPAddress = 50,
    IPAddressLeaseTime = 51,
    DHCPMessageType = 53,
    ServerIdentifier = 54,
    ParameterRequestList = 55,
    End = 255,
};

pub const DHCPHeader = extern struct {
    op: u8, // Message op code / message type
    htype: u8, // Hardware address type
    hlen: u8, // Hardware address length
    hops: u8, // Client sets to zero, optionally used by relay agents

    xid: u32, // Transaction ID
    secs: u16, // Seconds elapsed
    flags: u16, // Flags

    ciaddr: u32, // Client IP address - the IP the client already has
    yiaddr: u32, // 'your' (client) IP address - the IP address given by the server in responses
    siaddr: u32, // IP address of next server to use
    giaddr: u32, // Relay agent IP address - routers IP on the clients subnet (if DHCP server is on different subnet this is used)

    chaddr: [16]u8, // Client hardware address
    sname: [64]u8, // Optional server host name
    file: [128]u8, // Boot file name

    magic_cookie: u32, // Should be 0x63825363
    //    options: [312]u8, // Optional parameters field

    pub fn init_default() DHCPHeader {
        return DHCPHeader{
            .op = @intFromEnum(OPCode.BootRequest),
            .htype = 1, // Ethernet
            .hlen = 6, // MAC address length
            .hops = 0,
            .xid = 0,
            .secs = 0,
            .flags = 0,
            .ciaddr = 0,
            .yiaddr = 0,
            .siaddr = 0,
            .giaddr = 0,
            .chaddr = [_]u8{0} ** 16,
            .sname = [_]u8{0} ** 64,
            .file = [_]u8{0} ** 128,
            .magic_cookie = @byteSwap(@as(u32, 0x63825363)),
            //           .options = [_]u8{0} ** 312,
        };
    }

    // OP getters/setters
    pub fn set_op(self: *DHCPHeader, op: OPCode) void {
        self.op = @intFromEnum(op);
    }

    pub fn get_op(self: *const DHCPHeader) OPCode {
        return @enumFromInt(self.op);
    }

    // Hardware type getters/setters
    pub fn set_htype(self: *DHCPHeader, htype: HWTYPE) void {
        self.htype = @intFromEnum(htype);
    }

    pub fn get_htype(self: *const DHCPHeader) HWTYPE {
        return @enumFromInt(self.htype);
    }

    // Hardware length getters/setters
    pub fn set_hlen(self: *DHCPHeader, hlen: u8) void {
        self.hlen = hlen;
    }

    pub fn get_hlen(self: *const DHCPHeader) u8 {
        return self.hlen;
    }

    // Hops getters/setters
    pub fn set_hops(self: *DHCPHeader, hops: u8) void {
        self.hops = hops;
    }

    pub fn get_hops(self: *const DHCPHeader) u8 {
        return self.hops;
    }

    // Transaction ID getters/setters
    pub fn set_xid(self: *DHCPHeader, xid: u32) void {
        self.xid = @byteSwap(xid);
    }

    pub fn get_xid(self: *const DHCPHeader) u32 {
        return @byteSwap(self.xid);
    }

    // Set seconds - sets a BE
    pub fn set_secs(self: *DHCPHeader, secs: u16) void {
        self.secs = @byteSwap(secs);
    }

    pub fn get_secs(self: *const DHCPHeader) u16 {
        return @byteSwap(self.secs);
    }

    // Flags getters/setters
    pub fn set_flags(self: *DHCPHeader, flags: u16) void {
        self.flags = @byteSwap(flags);
    }

    pub fn get_flags(self: *const DHCPHeader) u16 {
        return @byteSwap(self.flags);
    }

    // Client IP getters/setters
    pub fn set_ciaddr(self: *DHCPHeader, ciaddr: IPv4Address) void {
        self.ciaddr = @byteSwap(ciaddr.to_u32());
    }

    pub fn get_ciaddr(self: *const DHCPHeader) IPv4Address {
        return IPv4Address.init_from_u32(@byteSwap(self.ciaddr));
    }

    // Your IP getters/setters
    pub fn set_yiaddr(self: *DHCPHeader, yiaddr: IPv4Address) void {
        self.yiaddr = @byteSwap(yiaddr.to_u32());
    }

    pub fn get_yiaddr(self: *const DHCPHeader) IPv4Address {
        return IPv4Address.init_from_u32(self.yiaddr);
    }

    // Server IP getters/setters
    pub fn set_siaddr(self: *DHCPHeader, siaddr: IPv4Address) void {
        self.siaddr = @byteSwap(siaddr.to_u32());
    }

    pub fn get_siaddr(self: *const DHCPHeader) IPv4Address {
        return IPv4Address.init_from_u32(@byteSwap(self.siaddr));
    }

    // Gateway IP getters/setters
    pub fn set_giaddr(self: *DHCPHeader, giaddr: IPv4Address) void {
        self.giaddr = @byteSwap(giaddr.to_u32());
    }

    pub fn get_giaddr(self: *const DHCPHeader) IPv4Address {
        return IPv4Address.init_from_u32(self.giaddr);
    }

    // Client hardware address getters/setters
    pub fn set_chaddr(self: *DHCPHeader, chaddr: Eth.MacAddress) void {
        @memmove(self.chaddr[0..6], &chaddr.addr);
    }

    pub fn get_chaddr(self: *const DHCPHeader) Eth.MacAddress {
        var eth_addr_byte: [6]u8 = .{0} ** 6;
        @memmove(&eth_addr_byte, self.chaddr[0..6]);
        return Eth.MacAddress.init_from_array(eth_addr_byte);
    }

    // Server name getters/setters
    pub fn set_sname(self: *DHCPHeader, server_name: []const u8) !void {
        if (server_name.len > 64) {
            return error.ServerNameTooLong;
        }
        @memset(&self.sname, 0);

        @memmove(self.sname[0..server_name.len], server_name[0..]);
    }

    pub fn get_sname(self: *const DHCPHeader) []const u8 {
        return &self.sname;
    }

    // Boot file name getters/setters
    pub fn set_file(self: *DHCPHeader, filename: []const u8) !void {
        if (filename.len > 128) {
            return error.FileNameTooLong;
        }

        @memset(&self.file, 0);

        @memmove(self.file[0..filename.len], filename[0..]);
    }

    pub fn get_file(self: *const DHCPHeader) []const u8 {
        return &self.file;
    }

    // Magic cookie getters/setters
    pub fn set_magic_cookie(self: *DHCPHeader, cookie: u32) void {
        self.magic_cookie = @byteSwap(cookie);
    }

    pub fn get_magic_cookie(self: *const DHCPHeader) u32 {
        return @byteSwap(self.magic_cookie);
    }

    // Options getters/setters
    //   pub fn set_options(self: *DHCPHeader, options: [312]u8) void {
    //       self.options = options;
    //   }
    //
    //   pub fn get_options(self: *const DHCPHeader) [312]u8 {
    //       return self.options;
    //   }

    // Helper methods
    pub fn is_boot_request(self: *const DHCPHeader) bool {
        return self.get_op() == .BootRequest;
    }

    pub fn is_boot_reply(self: *const DHCPHeader) bool {
        return self.get_op() == .BootReply;
    }

    pub fn set_broadcast_flag(self: *DHCPHeader) void {
        self.flags |= 0x8000; // Set broadcast flag
    }

    pub fn clear_broadcast_flag(self: *DHCPHeader) void {
        self.flags &= 0x7FFF; // Clear broadcast flag
    }

    pub fn is_broadcast(self: *const DHCPHeader) bool {
        return (self.flags & 0x8000) != 0;
    }
};

pub const DHCPLayer = struct {
    owner: LayerOwner,
    const Protocol = tcp_ip_protocol.arp;

    pub fn init(owner: LayerOwner) LayerError!DHCPLayer {
        switch (owner) {
            .packet_layer => {
                return DHCPLayer{
                    .owner = owner,
                };
            },
            .owned_buffer => {
                var self = DHCPLayer{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < DHCPHeaderSize) {
                    const dhcp_data = try self.owner.owned_buffer.extend(buffer_len, DHCPHeaderSize);

                    @memset(dhcp_data, 0);

                    var header = DHCPHeader.init_default();

                    @memcpy(dhcp_data[0..DHCPHeaderSize], std.mem.asBytes(&header));
                }

                return self;
            },
        }
    }

    pub fn get_mutable_header(self: *DHCPLayer) *DHCPHeader {
        const data = self.get_data();

        if (data.len < DHCPHeaderSize) {
            std.debug.panic("DHCP data len ({}) less than DHCPHeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(DHCPHeader)) u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn get_immutable_header(self: *const DHCPLayer) *const DHCPHeader {
        const data: []const u8 = self.get_data();

        if (data.len < DHCPHeaderSize) {
            std.debug.panic("DHCP data len ({}) less than DHCPHeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(DHCPHeader)) const u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    fn extend_payload(self: *DHCPLayer, offset: usize, extend_len: usize) ![]u8 {
        var buf: []u8 = undefined;
        switch (self.owner) {
            .packet_layer => |layer| {
                buf = try layer.packet.extend_layer(layer, extend_len); // TODO: extend at offset instead
            },
            .owned_buffer => |*buffer| {
                buf = try buffer.extend(offset, extend_len);
            },
        }

        return buf;
    }

    fn fitUnsigned(n: u64) usize {
        if (n <= 0xFF) return 1;
        if (n <= 0xFFFF) return 2;
        if (n <= 0xFFFFFFFF) return 4;
        return 8;
    }

    pub fn add_option(self: *DHCPLayer, opt: Option, value: OptionValues) !void {
        const data = self.get_data();
        const opt_length = value.get_opt_length();
        var opt_buf = try self.extend_payload(
            data.len, // last byte - //TODO: handle last byte
            1 + 1 + opt_length, // opcode, len byte, opt_length
        );
        opt_buf[0] = @intFromEnum(opt); // opt byte
        opt_buf[1] = @intCast(opt_length); // length byte

        const fit = fitUnsigned(value.get_value());

        const val = value.get_value();

        const tmp = std.mem.toBytes(val);

        @memmove(opt_buf[2..], tmp[0..fit]);
    }

    /// returns mutable slice of data (hdr+payload).
    /// this will likely be made private in future to avoid accidental mutations
    pub fn get_data(self: *const DHCPLayer) []u8 {
        return self.owner.get_data();
    }

    pub fn get_payload(self: *DHCPLayer) []const u8 {
        _ = self;
        return "";
    }

    pub fn to_string(self: *const DHCPLayer, allocator: std.mem.Allocator) []const u8 {
        const hdr = self.get_immutable_header();

        const op_str = switch (hdr.get_op()) {
            OPCode.BootRequest => "BootRequest",
            OPCode.BootReply => "BootReply",
        };

        const htype_str = switch (hdr.get_htype()) {
            HWTYPE.Eth => "Ethernet",
            // Add other HWTYPE cases as needed
        };

        // Helper function to catch errors and return empty string
        const catch_err = struct {
            fn call(alloc: std.mem.Allocator, comptime fmt: []const u8, args: anytype) []const u8 {
                return std.fmt.allocPrint(alloc, fmt, args) catch return "";
            }
        }.call;

        _ = catch_err;

        const ciaddr_str = hdr.get_ciaddr().to_string(allocator) catch return "";
        defer if (ciaddr_str.len > 0) allocator.free(ciaddr_str);

        const yiaddr_str = hdr.get_yiaddr().to_string(allocator) catch return "";
        defer if (yiaddr_str.len > 0) allocator.free(yiaddr_str);

        const siaddr_str = hdr.get_siaddr().to_string(allocator) catch return "";
        defer if (siaddr_str.len > 0) allocator.free(siaddr_str);

        const giaddr_str = hdr.get_giaddr().to_string(allocator) catch return "";
        defer if (giaddr_str.len > 0) allocator.free(giaddr_str);

        const chaddr_str = hdr.get_chaddr().to_string(allocator) catch return "";
        defer if (chaddr_str.len > 0) allocator.free(chaddr_str);

        // Convert sname (C string) to slice
        //       const sname_slice = std.mem.sliceTo(&hdr.sname, 0);
        //       const sname_str = if (sname_slice.len > 0)
        //           std.utf8.allocConcat(allocator, "'", .{ sname_slice, "'" }) catch return ""
        //       else
        //           allocator.dupe(u8, "null") catch return "";
        //       defer if (sname_str.len > 0) allocator.free(sname_str);
        //
        //       // Convert file (C string) to slice
        //       const file_slice = std.mem.sliceTo(&hdr.file, 0);
        //       const file_str = if (file_slice.len > 0)
        //           std.utf8.allocConcat(allocator, "'", .{ file_slice, "'" }) catch return ""
        //       else
        //           allocator.dupe(u8, "null") catch return "";
        //       defer if (file_str.len > 0) allocator.free(file_str);

        const result = std.fmt.allocPrint(allocator,
            \\DHCPHeader {{
            \\  op: {s} 
            \\  htype: {s}
            \\  hlen: {any}
            \\  hops: {any}
            \\  xid: 0x{X:0>8}
            \\  secs: {any}
            \\  flags: 0x{X:0>4} 
            \\  ciaddr: {s}
            \\  yiaddr: {s}
            \\  siaddr: {s}
            \\  giaddr: {s}
            \\  chaddr: {s}
            \\  magic_cookie: 0x{X:0>8}
            \\}}
        , .{
            op_str,
            htype_str,
            hdr.get_hlen(),
            hdr.get_hops(),
            hdr.get_xid(),
            hdr.get_secs(),
            hdr.get_flags(),
            ciaddr_str,
            yiaddr_str,
            siaddr_str,
            giaddr_str,
            chaddr_str,
            hdr.get_magic_cookie(),
        }) catch return "";

        return result;
    }

    pub fn validate_layer(self: *DHCPLayer) void {
        const data = self.get_data();
        if (data[data.len - 1] != 0xff) {
            var end_byte = self.extend_payload(data.len, 1) catch {
                print("failed to extend packet.\n", .{});
                return;
            };

            end_byte[0] = 0xff;
        }
    }

    /// return the next layer protocol type (DHCP doesn't have a next layer)
    pub fn get_next_layer_type(self: *DHCPLayer, layer: *Layer) !?LayerIface {
        _ = self;
        _ = layer;
        return null;
    }

    pub fn get_protocol(self: *DHCPLayer) tcp_ip_protocol {
        _ = self;
        return DHCPLayer.Protocol;
    }

    pub fn deinit(self: *DHCPLayer) void {
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
