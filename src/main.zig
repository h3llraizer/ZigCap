const std = @import("std");

//const c_int = i32;

// const PcapIf = extern struct {
//     next: ?*PcapIf,
//     name: ?[*:0]const u8,
//     description: ?[*:0]const u8,
//     addresses: ?*anyopaque,
//     flags: u32,
// };

// pub const PcapT = opaque {}; // opaque pointer for pcap_t*

// extern fn pcap_lib_version() callconv(.c) ?[*:0]const u8;
// extern fn pcap_findalldevs(alldevs: *?*PcapIf, errbuf: *u8) callconv(.c) c_int;
// extern fn pcap_freealldevs(alldevs: *PcapIf) callconv(.c) void;
// extern fn pcap_open_live(device: [*:0]const u8, snaplen: c_int, promisc: c_int, to_ms: c_int, errbuf: [*:0]u8) callconv(.c) ?*PcapT;
// extern fn pcap_next_ex(handle: *PcapT, header: **PcapPktHeader, pkt_data: **u8) callconv(.c) c_int;
// extern fn pcap_close(handle: *PcapT) callconv(.c) void;

// // packet header
// pub const PcapPktHeader = extern struct {
//     ts_sec: c_int,
//     ts_usec: c_int,
//     caplen: c_int,
//     len: c_int,
// };

// // packet
// pub const Packet = struct {
//     timestamp_sec: u32,
//     timestamp_usec: u32,
//     data: []u8,
// };

// fn openInterface(device_name: []const u8) ?*PcapT {
//     var errbuf: [256]u8 = undefined;
//     const handle = pcap_open_live(device_name, 65535, 1, 1000, &errbuf);
//     if (handle == null) {
//         std.debug.print("Failed to open device {s}: {s}\n", .{ device_name, &errbuf });
//         return null;
//     }
//     return handle;
// }

// fn capturePackets(allocator: *std.mem.Allocator, handle: *PcapT, count: usize) !std.ArrayList(Packet) {
//     var packets = std.ArrayList(Packet).init(allocator);

//     var header: ?*PcapPktHeader = null;
//     var data: ?*u8 = null;

//     var captured: usize = 0;

//     while (captured < count) : (captured += 1) {
//         const res = pcap_next_ex(handle, &header, &data);
//         if (res <= 0) continue; // timeout or no packet
//         const h = header.?; // non-null
//         const d = data.?; // non-null
//         try packets.append(Packet{
//             .timestamp_sec = h.ts_sec,
//             .timestamp_usec = h.ts_usec,
//             .data = d[0..h.caplen],
//         });
//     }

//     return packets;
// }

// fn printPacketSizes(packets: std.ArrayList(Packet)) void {
//     for (packets.items) |pkt| {
//         std.debug.print("Packet: {d} bytes\n", .{pkt.data.len});
//     }
// }

const PcapIf = extern struct {
    next: ?*PcapIf,
    name: ?[*:0]const u8,
    description: ?[*:0]const u8,
    addresses: ?*anyopaque,
    flags: u32,
};

extern fn pcap_lib_version() callconv(.c) ?[*:0]const u8;
extern fn pcap_findalldevs(
    alldevs: *?*PcapIf,
    errbuf: [*:0]u8,
) callconv(.c) c_int;

extern fn pcap_freealldevs(alldevs: *PcapIf) callconv(.c) void;

pub fn main() void {
    var errbuf: [256:0]u8 = .{0} ** 256;
    var alldevs: ?*PcapIf = null;

    if (pcap_findalldevs(&alldevs, &errbuf) != 0) {
        std.debug.print("pcap_findalldevs failed: {s}\n", .{&errbuf});
        return;
    }

    defer if (alldevs) |d| pcap_freealldevs(d);

    std.debug.print("Available capture devices:\n", .{});

    var dev = alldevs;
    while (dev) |d| : (dev = d.next) {
        const name = d.name orelse "(no name)";
        const desc = d.description orelse "(no description)";
        std.debug.print(" - {s}: {s}\n", .{ name, desc });
    }
}

// pub fn main() !void {
//     //const allocator = std.heap.page_allocator;

//     // 1. Get devices
//     var errbuf: u8 = undefined;
//     var alldevs: ?*PcapIf = null;
//     if (pcap_findalldevs(&alldevs, &errbuf) != 0) {
//         std.debug.print("Error getting devices: {any}\n", .{errbuf});
//         return;
//     }

//     defer if (alldevs) |d| pcap_freealldevs(d);

//     const first_dev = alldevs.?; // just take first device
//     const dev_name = first_dev.name orelse "(no name)";
//     std.debug.print("Opening device: {s}\n", .{dev_name});

//     // 2. Open device
//     //const handle = openInterface(dev_name) orelse return;
//     //defer pcap_close(handle);

//     // 3. Capture packets (e.g., 5 packets)
//     //const packets = try capturePackets(allocator, handle, 5);

//     // 4. Print packet sizes
//     //printPacketSizes(packets);

//     // 5. Clean up
//     //packets.deinit();
// }

//zig build-exe src\main.zig -I"C:\Users\user\Downloads\npcap-sdk-1.15\Include" -I"%INCLUDE%" -L"C:\Users\user\Downloads\npcap-sdk-1.15\Lib\x64" -lPacket -lwpcap
