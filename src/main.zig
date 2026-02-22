const std = @import("std");
const print = std.debug.print;
const PacketStructs = @import("PacketStructs.zig");
const PcapWrapper = @import("PcapWrapper.zig");

pub fn packet_callback(raw_packet: *PacketStructs.RawPacket) void {
    print("Packet received. Length: {any}\n", .{raw_packet.raw_len});
}

pub fn main() !void {
    const pcap_file: []const u8 = "C:\\users\\user\\captures\\udp_traffic.pcap";
    var allocator = std.heap.page_allocator;
    try PcapWrapper.parse_pcap_file(pcap_file, &allocator, packet_callback);
}

pub fn live() void {
    print("starting...\n", .{});

    const ip: []const u8 = "192.168.1.225";

    var allocator = std.heap.page_allocator;

    var interfaces = PcapWrapper.Interfaces.init() catch |err| {
        print("Failed to init interfaces: {s}.\n", .{@errorName(err)});
        return err;
    };

    const device_list = try interfaces.list_all(&allocator);

    if (device_list.items.len > 0) {
        const main_iface = interfaces.find_by_ip(ip);
        if (main_iface) |iface| {
            print("Found:\n{s}\n", .{iface.toString(&allocator)});

            try iface.*.open(&allocator);

            if (iface.*.isOpened()) {
                print("Device is open.\n", .{});
            } else {
                print("Device not open.\n", .{});
            }

            try iface.*.capture(packet_callback);
        }
    }
}
