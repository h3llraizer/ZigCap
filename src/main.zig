const std = @import("std");
const print = std.debug.print;

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

pub const EthHeader = struct {
    dst: [6]u8,
    src: [6]u8,
    ethertype: u16, // network byte order (big-endian)
};

pub const RawPacket = struct {
    timestamp_s: u32,
    timestamp_ms: u32,
    raw_data: *u8,
    raw_len: c_int,

    pub fn init() RawPacket {
        var p: RawPacket = undefined;
        p.raw_data = undefined;
        p.timestamp_s = undefined;
        p.timestamp_ms = undefined;

        return p;
    }

    pub fn copyInit(buf: [*]u8, len: usize, timestamp_sec: u32, timestamp_msec: u32) RawPacket {
        var p: RawPacket = undefined;
        const n = @min(len, 65536);
        for (buf, 0..n) |byte, index| {
            p.raw[index] = byte;
        }

        p.raw_len = len;

        p.timestamp_s = timestamp_sec;
        p.timestamp_ms = timestamp_msec;
        return p;
    }
};

pub const Packet = struct {
    raw_packet: *RawPacket,

    pub fn init(rawPacket: *RawPacket) Packet {
        var p: Packet = undefined;
        p.raw_packet = rawPacket; // pointer back to the original raw_packet

        // parse packet here

        return p;
    }

    pub fn printEthHeader(self: Packet) void {
        if (self.raw_len < @sizeOf(EthHeader)) {
            print("Packet too short!\n", .{});
            return;
        }

        //const header: *EthHeader = @alignCast(self.raw_data);

        //const header: *EthHeader = @ptrCast(self.raw_data);

        //const header: *EthHeader = @ptrCast(@alignCast(@alignOf(self.raw_data)));

        // Step 1: ensure pointer alignment
        //const aligned_ptr: *EthHeader = @alignCast(self.raw_data);

        // Step 2: cast to target struct
        //const header: *EthHeader = @ptrCast(aligned_ptr);

        //const offset = @offsetOf(*EthHeader, self.raw_data);

        //print("offsetof ethheader: {d}", .{offset});

        //print("Src MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n", .{ header.src[0], header.src[1], header.src[2], header.src[3], header.src[4], header.src[5] });

        // print("Dst MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n", .{ header.dst[0], header.dst[1], header.dst[2], header.dst[3], header.dst[4], header.dst[5] });

        // const ethertype = std.mem.bigEndianToHost(u16, header.ethertype);
        // print("EtherType: 0x{:04x}\n", .{ethertype});
    }
};

const PacketArena = struct {
    arena: std.heap.ArenaAllocator,

    pub fn init(backing_allocator: std.mem.Allocator) PacketArena {
        return PacketArena{
            .arena = std.heap.ArenaAllocator.init(backing_allocator),
        };
    }

    pub fn deinit(self: *PacketArena) void {
        _ = self.arena.deinit();
    }

    pub fn allocOne(self: *PacketArena, packet: RawPacket) !*RawPacket {
        const p = try self.arena.allocator().create(RawPacket);
        p.* = packet; // copy into arena
        return p;
    }
};

fn openInterface(device_name: [*:0]const u8) ?*PcapT {
    var errbuf: [256:0]u8 = .{0} ** 256;
    const handle = pcap_open_live(device_name, 65535, 1, 1000, &errbuf);
    if (handle == null) {
        std.debug.print("Failed to open device {s}: {s}\n", .{ device_name, &errbuf });
        return null;
    }
    return handle;
}

fn capturePackets(handle: *PcapT, packetArena: *PacketArena, size: usize) !void {
    var header: ?*PcapPktHeader = null;

    var raw_packet = RawPacket.init();

    var captured: usize = 0;

    while (captured < size) : (captured += 1) {
        const res = pcap_next_ex(handle, &header.?, &raw_packet.raw_data);
        if (res <= 0) continue; // timeout or no packet
        const h = header.?; // non-null

        raw_packet.timestamp_ms = @intCast(h.ts_usec);

        raw_packet.timestamp_s = @intCast(h.ts_sec);

        raw_packet.raw_len = h.len;

        const packetPtr = try packetArena.allocOne(raw_packet);

        print("Alloc'd 1 {d} byte packet to the arena. ptr: {*}\n", .{ raw_packet.raw_len, packetPtr });
    }
}

fn capture(handle: *PcapT) !void {
    var header: ?*PcapPktHeader = undefined;

    var raw_packet = RawPacket.init();

    var captured: usize = 0;

    var buffer: [65536]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&buffer);
    const allocator = fba.allocator();

    var total: usize = 0;

    var pkt_ptr: ?*u8 = undefined; // this is the pointer passed to pcap (pcap takes the pointer and does its' own allocation procedure)

    while (total >= 0) : (captured += 1) {
        const res = pcap_next_ex(handle, &header.?, &pkt_ptr.?);

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

pub fn main() !void {
    print("starting...", .{});
    var packetArena = PacketArena.init(std.heap.page_allocator);
    defer packetArena.deinit();

    const wifiIfaceDesc: [*:0]const u8 = "Intel(R) Dual Band Wireless-AC 3165";

    var wifiIfaceName: ?[*:0]const u8 = undefined;

    const allocator = std.heap.page_allocator;

    var errbuf: [256:0]u8 = .{0} ** 256;
    var alldevs: ?*PcapIf = null;

    if (pcap_findalldevs(&alldevs, &errbuf) != 0) {
        std.debug.print("pcap_findalldevs failed: {s}\n", .{&errbuf});
        return;
    }

    defer if (alldevs) |d| pcap_freealldevs(d);

    var list: std.ArrayList([*:0]const u8) = .empty;

    defer list.deinit(allocator);

    std.debug.print("Available capture devices:\n", .{});

    var dev = alldevs;
    while (dev) |d| : (dev = d.next) {
        const name = d.name orelse "(no name)";
        const desc = d.description orelse "(no description)";
        try list.append(allocator, desc);
        //std.debug.print(" - {s}: {s}\n", .{ name, desc });

        if (std.mem.eql(u8, std.mem.sliceTo(wifiIfaceDesc, 0), std.mem.sliceTo(desc, 0))) {
            wifiIfaceName = name;
        }
    }

    print("{s}\n", .{wifiIfaceName.?});

    const handle = openInterface(wifiIfaceName.?) orelse return;
    defer pcap_close(handle);

    print("Opened device.\n", .{});

    try capture(handle);
}

//zig build-exe src\main.zig -I"C:\Users\user\Downloads\npcap-sdk-1.15\Include" -I"%INCLUDE%" -L"C:\Users\user\Downloads\npcap-sdk-1.15\Lib\x64" -lPacket -lwpcap
