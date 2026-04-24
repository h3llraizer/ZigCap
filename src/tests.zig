// src/tests.zig
const std = @import("std");
const zigcap = @import("lib.zig");
const print = std.debug.print;
const expect = std.testing.expect;

const Packet = zigcap.Packet.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const Layer = zigcap.Packet.Layer;
const LayerOwner = zigcap.Layer.LayerOwner;
const tcp_ip_protocol = zigcap.tcp_ip_protocol;
const IPProtocol = zigcap.ProtocolEnums.IPProtocol;
const IPv4 = @import("IPv4.zig");
const IPv6 = @import("IPv6.zig");
const Eth = @import("Eth.zig");
const UDP = @import("UDP.zig");
const TCP = @import("TCP.zig");
const ARP = @import("ARP.zig");
const ICMP = @import("ICMP.zig");
const ApplicationLayer = @import("GenericLayer.zig").ApplicationLayer;
const LayerIface = @import("LayerIface.zig").LayerIface;
const LayerInterface = @import("LayerIface.zig").LayerInterface;

const PcapWrapper = @import("PcapWrapper.zig");

const alignment_check = @import("Helpers.zig").alignment_check;

const DNS = @import("DNS.zig");

const Buffer = @import("Buffer.zig").Buffer;

test "library version" {
    try std.testing.expect(zigcap.version.major == 0);
    try std.testing.expect(zigcap.version.minor == 1);
    try std.testing.expect(zigcap.version.patch == 0);
}

pub fn send_packet(buf: []u8) !void {
    var wifi_interface = try open_pcap() orelse {
        return error.FailedToOpen;
    };

    try wifi_interface.send(buf);

    print("No error during send.\n", .{});
}

pub fn open_pcap() !?*PcapWrapper.Interface {
    print("starting...\n", .{});

    const ip: IPv4.IPv4Address = try IPv4.IPv4Address.init_from_string("192.168.1.225");

    const allocator = std.heap.page_allocator;

    var interfaces = PcapWrapper.Interfaces.init(allocator) catch |err| {
        print("Failed to init interfaces: {s}.\n", .{@errorName(err)});
        return err;
    };

    const device_list = try interfaces.list_all();

    if (device_list.items.len > 0) {
        const main_iface = try interfaces.find_by_ip(ip);
        if (main_iface) |iface| {
            try iface.open(allocator);

            if (iface.isOpened()) {
                return iface;
            } else {
                return null;
            }
        } else {
            return null;
        }
    } else {
        return null;
    }
}

test "iface" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    var eth_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    defer eth_layer_owner.owned_buffer.buffer.deinit(allocator);

    var eth_layer: Eth.EthLayer = try Eth.EthLayer.init(eth_layer_owner);
    defer eth_layer.deinit();

    var eth_hdr = eth_layer.get_mutable_header();

    eth_hdr.set_eth_type(Eth.EthType.IP);

    try expect(eth_hdr.get_eth_type() == Eth.EthType.IP);

    eth_hdr.set_dst_mac(try Eth.MacAddress.init_from_string("38:06:e6:92:63:ac"));

    eth_hdr.set_src_mac(try Eth.MacAddress.init_from_string("14:4f:8a:a4:15:7d"));

    var layer_iface = LayerInterface.implBy(&eth_layer);
    //defer layer_iface.deinit();

    print("{x}\n", .{layer_iface.get_data()});

    eth_hdr.set_src_mac(try Eth.MacAddress.init_from_string("1B:2B:3B:4B:5B:6B"));

    print("{x}\n", .{layer_iface.get_data()});

    const str = layer_iface.to_string(allocator);
    defer allocator.free(str);
    print("{s}\n", .{str});
}
