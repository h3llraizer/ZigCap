const std = @import("std");
const print = std.debug.print;
const RawPacket = @import("PacketStructs.zig").RawPacket;
const MAX_PATH = std.os.windows.MAX_PATH;
const allocPrint = std.fmt.allocPrint;

const u_short = u16;
const u_long = u32;

pub const sockaddr = extern struct {
    sa_family: u_short,
    sa_data: [14]u8,
};

pub const in_addr = extern struct {
    S_addr: u_long, // IPv4 address
};

pub const sockaddr_in = extern struct {
    sin_family: u_short,
    sin_port: u_short,
    sin_addr: in_addr,
    sin_zero: [8]u8,
};

pub const in6_addr = extern struct {
    u: [16]u8, // IPv6 address
};

pub const sockaddr_in6 = extern struct {
    sin6_family: u_short,
    sin6_port: u_short,
    sin6_flowinfo: u_long,
    sin6_addr: in6_addr,
    sin6_scope_id: u_long,
};

pub const pcap_addr = extern struct {
    next: ?*pcap_addr,
    addr: ?*sockaddr,
    netmask: ?*sockaddr,
    broadaddr: ?*sockaddr,
    dstaddr: ?*sockaddr,
};

const PcapIf = extern struct { next: ?*PcapIf, name: ?[*:0]const u8, description: ?[*:0]const u8, addresses: ?*pcap_addr, flags: u32 };

pub const PcapT = opaque {}; // opaque pointer for pcap_t*

extern fn pcap_lib_version() callconv(.c) ?[*:0]const u8;
extern fn pcap_findalldevs(alldevs: *?*PcapIf, errbuf: [*:0]u8) callconv(.c) c_int;

extern fn pcap_freealldevs(alldevs: *PcapIf) callconv(.c) void;

extern fn pcap_open_live(device: [*:0]const u8, snaplen: c_int, promisc: c_int, to_ms: c_int, errbuf: [*:0]u8) callconv(.c) ?*PcapT;
extern fn pcap_next_ex(handle: *PcapT, header: **PcapPktHeader, pkt_data: **u8) callconv(.c) c_int;
extern fn pcap_close(handle: *PcapT) callconv(.c) void;

// packet header
pub const PcapPktHeader = extern struct {
    ts_sec: c_int,
    ts_usec: c_int,
    caplen: c_int,
    len: c_int,
};

pub const IPv4 = struct {
    asBytes: [4]u8,
    asString: []const u8,

    pub fn init(bytes: [4]u8, allocator: *std.mem.Allocator) !IPv4 {
        const string = try allocPrint(allocator.*, "{}.{}.{}.{}", .{ bytes[0], bytes[1], bytes[2], bytes[3] });

        return IPv4{ .asBytes = bytes, .asString = string };
    }

    pub fn toString(self: IPv4) []const u8 {
        return self.asString;
    }
};

pub const Interface = struct {
    name: []u8,
    desc: []u8,
    ipv4: std.ArrayList(IPv4),
    handle: ?*PcapT = null,

    pub fn init(name: []const u8, desc: []const u8, ipv4: std.ArrayList(IPv4), allocator: *std.mem.Allocator) !Interface {
        const name_copy = try allocator.alloc(u8, name.len);
        std.mem.copyForwards(u8, name_copy, name);

        const desc_copy = try allocator.alloc(u8, desc.len);
        std.mem.copyForwards(u8, desc_copy, desc);

        return Interface{
            .name = name_copy,
            .desc = desc_copy,
            .ipv4 = ipv4,
            .handle = undefined,
        };
    }

    pub fn open(self: *Interface, allocator: *std.mem.Allocator) !void {
        var errbuf: [256:0]u8 = .{0} ** 256;

        const c_name = try allocator.dupeZ(u8, self.name);
        defer allocator.free(c_name);

        const handle = pcap_open_live(c_name, 65535, 1, 1000, &errbuf);

        if (handle == null) {
            print("Failed to open device {s}: {s}\n", .{ self.name, &errbuf });
            return;
        }

        self.handle = handle;
    }

    pub fn isOpened(self: Interface) bool {
        print("Checking {s}\n", .{self.desc});
        if (self.handle != null) {
            return true;
        }
        return false;
    }

    pub fn toString(self: Interface, allocator: *std.mem.Allocator) []const u8 {
        const s = allocPrint(allocator.*, "Name: {s} Description: {s}", .{ self.name, self.desc }) catch |err| {
            return @errorName(err);
        };

        return s;
    }

    pub fn print_name(self: Interface) void {
        print("{s}\n", .{self.desc});
    }

    pub fn capture(self: Interface, callback_fn: fn (*RawPacket) void) !void {
        var header: ?*PcapPktHeader = undefined;

        var raw_packet = RawPacket.init();

        var captured: usize = 0;

        var buffer: [65536]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&buffer);
        const allocator = fba.allocator();

        var total: usize = 0;

        var pkt_ptr: ?*u8 = undefined; // this is the pointer passed to pcap (pcap takes the pointer and does its' own allocation procedure)

        while (total >= 0) : (captured += 1) {
            const res = pcap_next_ex(self.handle.?, &header.?, &pkt_ptr.?);

            if (res <= 0) {
                std.debug.print("[ERR] Timeout or no packet.\n", .{});
                continue;
            }
            if (pkt_ptr) |raw_pkt| {
                const h = header.?; // non-null

                raw_packet.timestamp_ms = @intCast(h.ts_usec);

                raw_packet.timestamp_s = @intCast(h.ts_sec);

                raw_packet.raw_len = h.len;

                const memory = try allocator.alloc(u8, @intCast(h.len));

                defer allocator.free(memory);

                @memmove(memory.ptr, std.mem.asBytes(raw_pkt));

                total += @intCast(raw_packet.raw_len);

                callback_fn(&raw_packet);

                print("Alloc'd 1 {d} byte packet in fixed buffer. ptr: 0x{x}. BufSize: {any}\n", .{ raw_packet.raw_len, @intFromPtr(memory.ptr), memory.len });
            }
        }
    }

    pub fn deinit(self: Interface) !void {
        if (self.handle) {
            pcap_close(self.handle);
        }
    }
};

pub const InterfacesError = error{
    PcapFindAllDevsFailed,
};

pub const Interfaces = struct {
    error_buffer: [256:0]u8 = .{0} ** 256,
    pcap: ?*PcapIf,
    list: std.ArrayList(Interface),

    pub fn init() !Interfaces {
        var errbuf: [256:0]u8 = .{0} ** 256;
        var alldevs: ?*PcapIf = null;

        if (pcap_findalldevs(&alldevs, &errbuf) != 0) {
            std.debug.print("pcap_findalldevs failed: {s}\n", .{&errbuf});
            return InterfacesError.PcapFindAllDevsFailed; // <-- throw an error
        }

        return Interfaces{
            .pcap = alldevs,
            .error_buffer = errbuf,
            .list = undefined,
        };
    }

    fn extractIPs(addresses_ptr: ?*pcap_addr, allocator: *std.mem.Allocator) !std.ArrayList(IPv4) {
        var ips_list: std.ArrayList(IPv4) = .empty;

        var address_ptr = addresses_ptr;
        while (address_ptr) |addr| {
            if (addr.addr) |sa| {
                if (sa.sa_family == 2) { // AF_INET
                    const ipv4: *sockaddr_in = @ptrCast(@alignCast(sa)); //@ptrCast(sa);
                    //print("IPv4 SinAddr: {any}\n", .{ipv4.sin_addr.S_addr});

                    const host_u32 = std.mem.bigToNative(u32, ipv4.sin_addr.S_addr);

                    var octets: [4]u8 = @bitCast(host_u32);

                    std.mem.reverse(u8, &octets);

                    const ip_address = IPv4.init(octets, allocator) catch continue;

                    try ips_list.append(allocator.*, ip_address);
                } //else if (sa.sa_family == 23) { // AF_INET6
                // const ipv6: *sockaddr_in6 = @ptrCast(sa);
                //print("IPv6 SinAddr: {any}", .{ipv6.sin_addr});
                // ipv6.sin6_addr.u
                //}
            }
            address_ptr = addr.next;
        }

        return ips_list;
    }

    pub fn list_all(self: *Interfaces, allocator: *std.mem.Allocator) !std.ArrayList(Interface) {
        var iface_list: std.ArrayList(Interface) = .empty;
        var dev = self.*.pcap;

        const na: []const u8 = "na";

        while (dev) |d| : (dev = d.next) {
            var buffer: [MAX_PATH]u8 = undefined;
            var name: []u8 = buffer[0..0];

            if (d.name) |dev_name| {
                const name_len = std.mem.len(dev_name);
                name = buffer[0..name_len];
                std.mem.copyForwards(u8, name, dev_name[0..name_len]);
            } else {
                name = buffer[0..na.len];
                std.mem.copyForwards(u8, name, na);
            }

            var desc_buffer: [MAX_PATH]u8 = undefined;

            var desc: []u8 = desc_buffer[0..0];

            if (d.description) |dev_desc| {
                const desc_len = std.mem.len(dev_desc);
                desc = desc_buffer[0..desc_len];
                std.mem.copyForwards(u8, desc, dev_desc[0..desc_len]);
            } else {
                desc = desc_buffer[0..na.len];
                std.mem.copyForwards(u8, desc, na);
            }

            const ips = try extractIPs(d.addresses, allocator);

            const iface = try Interface.init(name, desc, ips, allocator);

            try iface_list.append(allocator.*, iface);
        }

        self.*.list = iface_list;

        return iface_list;
    }

    pub fn find_by_desc(self: Interfaces, wifiIfaceDesc: []u8) ?*Interface {
        for (self.list.items) |iface| {
            if (std.mem.eql(u8, std.mem.sliceTo(wifiIfaceDesc, 0), std.mem.sliceTo(iface.desc, 0))) {
                return &iface;
            }
        }

        return null;
    }

    pub fn find_by_ip(
        self: Interfaces,
        ip: []const u8,
    ) ?*Interface {
        for (self.list.items) |*iface| {
            for (iface.ipv4.items) |ip_address| {
                if (std.mem.eql(u8, ip, ip_address.toString())) {
                    return iface;
                }
            }
        }

        return null;
    }

    pub fn deinit(self: Interfaces) !void {
        if (self.alldevs) |d| pcap_freealldevs(d);
    }
};
