const std = @import("std");
const print = std.debug.print;
const RawPacket = @import("PacketStructs.zig").RawPacket;

const PcapIf = extern struct { next: ?*PcapIf, name: ?[*:0]const u8, description: ?[*:0]const u8, addresses: ?*anyopaque, flags: u32 };
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

pub const Interface = struct {
    name: [*:0]const u8,
    desc: [*:0]const u8,
    handle: *PcapT,

    pub fn capture(self: Interface) !void {
        var header: ?*PcapPktHeader = undefined;

        var raw_packet = RawPacket.init();

        var captured: usize = 0;

        var buffer: [65536]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&buffer);
        const allocator = fba.allocator();

        var total: usize = 0;

        var pkt_ptr: ?*u8 = undefined; // this is the pointer passed to pcap (pcap takes the pointer and does its' own allocation procedure)

        while (total >= 0) : (captured += 1) {
            const res = pcap_next_ex(self.handle, &header.?, &pkt_ptr.?);

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

                print("Alloc'd 1 {d} byte packet in fixed buffer. ptr: 0x{x}. BufSize: {any}\n", .{ raw_packet.raw_len, @intFromPtr(memory.ptr), memory.len });
            }
        }
    }

    pub fn deinit(self: Interface) !void {
        pcap_close(self.handle);
    }
};

pub const Interfaces = struct {
    error_buffer: [256:0]u8 = .{0} ** 256,
    pcap: ?*PcapIf,

    pub fn init() ?Interfaces {
        var errbuf: [256:0]u8 = .{0} ** 256;
        var alldevs: ?*PcapIf = null;

        if (pcap_findalldevs(&alldevs, &errbuf) != 0) {
            std.debug.print("pcap_findalldevs failed: {s}\n", .{&errbuf});
            return null;
        }

        return Interfaces{
            .pcap = alldevs,
            .error_buffer = errbuf,
        };
    }

    pub fn array_list(self: Interfaces, allocator: *std.mem.Allocator) !std.ArrayList([*:0]const u8) {
        var list: std.ArrayList([*:0]const u8) = .empty;
        var dev = self.pcap;
        while (dev) |d| : (dev = d.next) {
            //const name = d.name orelse "(no name)";
            const desc = d.description orelse "(no description)";
            try list.append(allocator.*, desc);
        }

        return list;
    }

    pub fn find(self: Interfaces, wifiIfaceDesc: [*:0]const u8) ?([*:0]const u8) {
        var dev = self.alldevs;
        while (dev) |d| : (dev = d.next) {
            const name = d.name orelse "(no name)";
            const desc = d.description orelse "(no description)";

            if (std.mem.eql(u8, std.mem.sliceTo(wifiIfaceDesc, 0), std.mem.sliceTo(desc, 0))) {
                return name;
            }
        }

        return null;
    }

    pub fn open(device_name: [*:0]const u8) ?Interface {
        var errbuf: [256:0]u8 = .{0} ** 256;
        const handle = pcap_open_live(device_name, 65535, 1, 1000, &errbuf);

        if (handle == null) {
            std.debug.print("Failed to open device {s}: {s}\n", .{ device_name, &errbuf });
            return null;
        }

        return Interface{ .name = device_name, .handle = handle.? };
    }

    pub fn deinit(self: Interfaces) !void {
        if (self.alldevs) |d| pcap_freealldevs(d);
    }
};
