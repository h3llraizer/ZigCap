const std = @import("std");
const IPv4Address = @import("IPv4.zig").IPv4Address;
const IPv6Address = @import("IPv6.zig").IPv6Address;

const link_layer_type = @import("ProtocolEnums.zig").link_layer_type;

const pcap = @cImport({
    //@cDefine("WIN32", "1"); // needed on Windows
    @cInclude("pcap.h");
});

const print = std.debug.print;
const Allocator = std.mem.Allocator;
const MAX_PATH = std.os.windows.MAX_PATH;
const allocPrint = std.fmt.allocPrint;

const ver = pcap.pcap_lib_version();

const u_short = u16;
const u_long = u32;

const in_addr = extern struct {
    S_addr: u_long, // IPv4 address
};

const sockaddr_in = extern struct {
    sin_family: u_short,
    sin_port: u_short,
    sin_addr: in_addr,
    sin_zero: [8]u8,
};

const in6_addr = extern struct {
    u: [16]u8, // IPv6 address
};

const sockaddr_in6 = extern struct {
    sin6_family: u_short,
    sin6_port: u_short,
    sin6_flowinfo: u_long,
    sin6_addr: in6_addr,
    sin6_scope_id: u_long,
};

pub const IPAddress = union(enum) {
    v4: IPv4Address,
    v6: IPv6Address,

    pub fn eql(self: IPAddress, other: IPAddress) bool {
        return switch (self) {
            .v4 => |a| switch (other) {
                .v4 => |b| a.to_u32() == b.to_u32(),
                .v6 => false,
            },
            .v6 => |a| switch (other) {
                .v6 => |b| std.mem.eql(u8, &a.array, &b.array),
                .v4 => false,
            },
        };
    }
};

pub const PcapError = error{
    DeviceOpenFailed,
    FilterParseFailed,
    FilterSetFailed,
    DeviceNotOpen,
    FindAllDevsFailed,
};

pub const Interface = struct {
    name: []const u8,
    desc: []const u8,
    ips: std.ArrayList(IPAddress), // interfaces can have more than one IP and they could be v4 or v6
    handle: ?*pcap.pcap_t = null,
    link_type: ?link_layer_type, // store enum
    allocator: Allocator,

    pub fn init(name: []const u8, desc: []const u8, ips: std.ArrayList(IPAddress), allocator: Allocator) Allocator.Error!Interface {
        const name_copy = try allocator.alloc(u8, name.len);
        @memmove(name_copy, name);

        const desc_copy = try allocator.alloc(u8, desc.len);
        @memmove(desc_copy, desc);

        return Interface{
            .name = name_copy,
            .desc = desc_copy,
            .ips = ips,
            .link_type = null,
            .allocator = allocator,
        };
    }

    pub fn send(self: *Interface, pkt_buf: []const u8) !void {
        if (self.handle) |h| {
            const res = pcap.pcap_sendpacket(h, pkt_buf.ptr, @intCast(pkt_buf.len));
            if (res != 0) {
                return error.PacketSendFailed;
            }
        } else {
            return error.DeviceNotOpen;
        }
    }

    pub fn open(self: *Interface, allocator: Allocator) (PcapError || Allocator.Error)!void {
        var errbuf: [256:0]u8 = .{0} ** 256;

        const c_name = try allocator.dupeZ(u8, self.name);
        defer allocator.free(c_name);

        const handle = pcap.pcap_open_live(c_name, 65535, 1, 1000, &errbuf);

        if (handle == null) {
            print("Failed to open device {s}: {s}\n", .{ self.name, &errbuf });
            return PcapError.DeviceOpenFailed;
        }

        self.handle = handle;
        self.link_type = @enumFromInt(pcap.pcap_datalink(handle));
    }

    pub fn isOpened(self: Interface) bool {
        if (self.handle != null) {
            return true;
        }
        return false;
    }

    /// caller needs to free returned slice
    pub fn to_string(self: Interface, allocator: Allocator) []const u8 { // TODO: Return error on allocPrint fail
        const s = allocPrint(allocator, "Name: {s} Description: {s}", .{ self.name, self.desc }) catch |err| {
            return @errorName(err);
        };

        return s;
    }

    pub fn print_name(self: Interface) void {
        print("{s}\n", .{self.desc});
    }

    pub fn set_filter(self: *Interface, filter_str: []const u8) PcapError!void {
        var fp: pcap.bpf_program = .{};
        const net: pcap.bpf_u_int32 = 0;

        if (self.handle) |handle| {
            if (pcap.pcap_compile(handle, &fp, filter_str.ptr, 0, net) == -1) {
                return PcapError.FilterParseFailed;
            } else {
                if (pcap.pcap_setfilter(handle, &fp) == -1) {
                    return PcapError.FilterSetFailed;
                }
            }
        } else {
            return PcapError.DeviceNotOpen;
        }
    }

    pub fn capture_one_raw(self: Interface, allocator: Allocator) Allocator.Error!?[]u8 {
        var header: [*c]pcap.struct_pcap_pkthdr = null;
        var pkt_ptr: [*c]const u8 = null;

        var res: c_int = 0;

        if (self.handle) |handle| {
            while (res <= 0) {
                res = pcap.pcap_next_ex(handle, &header, &pkt_ptr);
            }
        }

        if (header) |h| {
            const captured: []u8 = try allocator.alloc(u8, h.*.len);
            @memmove(captured, pkt_ptr);
            return captured;
        }

        return null;
    }

    pub fn deinit(self: *Interface) void {
        //if (self.handle) {
        //        pcap.pcap_close(self.handle);
        //       }
        self.allocator.free(self.name);
        self.allocator.free(self.desc);
        self.ips.deinit(self.allocator);
    }
};

pub const Interfaces = struct {
    error_buffer: [256:0]u8 = .{0} ** 256,
    pcap_iface: ?*pcap.pcap_if,
    iface_list: std.ArrayList(Interface),
    allocator: Allocator,

    pub fn init(allocator: Allocator) PcapError!Interfaces {
        var errbuf: [256:0]u8 = .{0} ** 256;
        var alldevs: ?*pcap.pcap_if = null;

        if (pcap.pcap_findalldevs(&alldevs, &errbuf) != 0) {
            std.debug.print("pcap_findalldevs failed: {s}\n", .{&errbuf});
            return PcapError.FindAllDevsFailed; // <-- throw an error
        }

        return Interfaces{
            .pcap_iface = alldevs,
            .error_buffer = errbuf,
            .iface_list = .empty,
            .allocator = allocator,
        };
    }

    fn extractIPs(self: Interfaces, addresses_ptr: ?*pcap.pcap_addr) Allocator.Error!std.ArrayList(IPAddress) {
        var ips_list: std.ArrayList(IPAddress) = .empty;

        var address_ptr = addresses_ptr;
        while (address_ptr) |addr| {
            if (addr.*.addr) |sa| {
                if (sa.*.sa_family == 2) { // AF_INET
                    const ipv4: *sockaddr_in = @ptrCast(@alignCast(sa));

                    const host_u32 = std.mem.bigToNative(u32, ipv4.sin_addr.S_addr);

                    var octets: [4]u8 = @bitCast(host_u32);

                    std.mem.reverse(u8, &octets);

                    const ip_address = IPv4Address.init_from_u32(host_u32);

                    try ips_list.append(self.allocator, IPAddress{ .v4 = ip_address });
                }

                if (sa.*.sa_family == 23) { // AF_INET6
                    const ip: *sockaddr_in6 = @ptrCast(@alignCast(sa));

                    const host: [16]u8 = ip.sin6_addr.u;

                    const ip_address = IPv6Address.init_from_array(host);

                    try ips_list.append(self.allocator, IPAddress{ .v6 = ip_address });
                }
            }
            address_ptr = addr.next;
        }

        return ips_list;
    }

    /// Appends all available interfaces to iface_list
    /// Doesn't open for capturing specifically
    pub fn get_all(self: *Interfaces) Allocator.Error!std.ArrayList(Interface) {
        var iface_list: std.ArrayList(Interface) = .empty;
        var dev = self.*.pcap_iface;

        const na: []const u8 = "na";

        while (dev) |d| : (dev = d.next) {
            var buffer: [MAX_PATH]u8 = undefined;
            var name: []u8 = buffer[0..0];

            if (d.name) |dev_name| {
                const name_len = std.mem.len(dev_name);
                name = buffer[0..name_len];
                @memmove(name, dev_name[0..name_len]);
            } else {
                name = buffer[0..na.len];
                @memmove(name, na);
            }

            var desc_buffer: [MAX_PATH]u8 = undefined;

            var desc: []u8 = desc_buffer[0..0];

            if (d.description) |dev_desc| {
                const desc_len = std.mem.len(dev_desc);
                desc = desc_buffer[0..desc_len];
                @memmove(desc, dev_desc[0..desc_len]);
            } else {
                desc = desc_buffer[0..na.len];
                @memmove(desc, na);
            }

            var ips = try self.extractIPs(d.addresses);
            defer ips.deinit(self.allocator);

            const iface = try Interface.init(name, desc, try ips.clone(self.allocator), self.allocator);

            try iface_list.append(self.allocator, iface);
        }

        self.iface_list = iface_list;

        return iface_list;
    }

    pub fn find_by_desc(self: Interfaces, wifiIfaceDesc: []u8) ?*Interface {
        for (self.iface_list.items) |iface| {
            if (std.mem.eql(u8, std.mem.sliceTo(wifiIfaceDesc, 0), std.mem.sliceTo(iface.desc, 0))) {
                return &iface;
            }
        }

        return null;
    }

    pub fn find_by_ip(self: Interfaces, ip: IPAddress) ?*Interface {
        for (self.iface_list.items) |*iface| {
            for (iface.ips.items) |ip_address| {
                if (ip_address.eql(ip)) return iface;
            }
        }

        return null;
    }

    pub fn deinit(self: *Interfaces) void {
        //if (self.alldevs) |d| pcap.pcap_freealldevs(d); // not sure what this was but make sure it doesn't leak
        for (self.iface_list.items) |*iface| {
            iface.deinit();
        }

        self.iface_list.deinit(self.allocator);
    }
};

pub fn readPackets(handle: *pcap.pcap_t, cb: fn ([]u8, Allocator) void, allocator: Allocator) !void {
    var header: ?*pcap.pcap_pkthdr = null;
    var packet: [*c]const u8 = null;

    var result: c_int = 0;

    while (true) {
        result = pcap.pcap_next_ex(handle, &header, &packet);

        if (result < 0) break;
        if (result == 0) continue;

        const h = header.?;

        //std.debug.print("Packet length: {}\n", .{h.len});

        const cap_len: usize = @intCast(h.caplen);
        const data = packet[0..cap_len];

        const pkt_data: []u8 = try allocator.alloc(u8, cap_len);

        @memmove(pkt_data, data);

        cb(pkt_data, allocator);
    }
}

pub fn read_pcap(filepath: []const u8, cb: fn ([]u8, Allocator) void, allocator: Allocator) !void {
    var errbuf: [256:0]u8 = .{0} ** 256;

    const pcap_handle: *pcap.pcap_t = pcap.pcap_open_offline(filepath.ptr, &errbuf) orelse {
        return error.FailedToOpen;
    };

    defer pcap.pcap_close(pcap_handle);

    try readPackets(pcap_handle, cb, allocator);
}
