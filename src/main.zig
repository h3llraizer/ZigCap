const std = @import("std");
const print = std.debug.print;
const PacketStructs = @import("PacketStructs.zig");
const PcapWrapper = @import("PcapWrapper.zig");
const Packet = PacketStructs.Packet;
const EthLayer = PacketStructs.EthLayer;

pub fn packet_callback(raw_packet: *PacketStructs.RawPacket, allocator: *std.mem.Allocator) void {
    print("Packet received. Length: {any}\n", .{raw_packet.raw_len});

    defer raw_packet.deinit(allocator);

    const packet: *Packet = allocator.create(Packet) catch |err| {
        print("Error creating packet: {s}\n", .{@errorName(err)});
        return;
    };

    packet.* = Packet.init(raw_packet);

    const eth: *EthLayer = allocator.create(EthLayer) catch |err| {
        print("{s}\n", .{@errorName(err)});
        return;
    };

    const ethlayer: ?EthLayer = packet.get_eth_layer();

    if (ethlayer) |e| {
        eth.* = e;
    } else {
        print("No eth layer.\n", .{});
        return;
    }

    eth.to_string(allocator);
    //

    //pkt.raw_packet.print_bytes(14);

    //var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    //var str_allocator = gpa.allocator();
    //
    //    const eth_layer: ?*PacketStructs.EthLayer = packet.get_eth_layer(allocator);
    //
    //    if (eth_layer) |layer| {
    //        layer.to_string(&str_allocator);
    //        //print("{any}\n", .{layer.eth_header});
    //    }
}

//
//pub fn main() !void {
//    const pcap_file: []const u8 = "C:\\users\\user\\captures\\udp_traffic.pcap";
//    var allocator = std.heap.page_allocator;
//    try PcapWrapper.parse_pcap_file(pcap_file, &allocator, packet_callback);
//}

pub fn main() !void {
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

            var buffer: [131072]u8 = undefined;
            var fba: std.heap.FixedBufferAllocator = .init(&buffer);
            var alloc = fba.allocator();
            try iface.*.capture(packet_callback, &alloc);
        }
    }
}
