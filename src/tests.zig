// src/tests.zig
const std = @import("std");
const zigcap = @import("lib.zig");
const print = std.debug.print;
const expect = std.testing.expect;

const RawData = zigcap.RawData;
const Packet = zigcap.Packet.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const Layer = zigcap.Packet.Layer;
const LayerOwner = zigcap.Layer.LayerOwner;
const tcp_ip_protocol = zigcap.tcp_ip_protocol;
const IPProtocol = zigcap.ProtocolEnums.IPProtocol;
const IPv4 = @import("IPv4.zig");
const Eth = @import("Eth.zig");
const UDP = @import("UDP.zig");
const ApplicationLayer = @import("GenericLayer.zig").ApplicationLayer;
const LayerIface = @import("LayerIface.zig").LayerIface;

const PcapWrapper = @import("PcapWrapper.zig");

const alignment_check = @import("Helpers.zig").alignment_check;

const DNS = @import("DNS.zig");

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

test "dns build" {
    //   var backing_buffer: [1024]u8 = undefined;
    //
    //   var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);
    //
    //   const allocator = fba.allocator();
    //
    //   var dns_layer: DNS.DNSLayer = try DNS.DNSLayer.create(allocator, 100);
    //
    //   try dns_layer.add_query("ziggit.dev", DNS.QueryType.A, DNS.DnsClass.IN, allocator);
    //
    //   var query = dns_layer.get_first_query();
    //   while (query) |q| {
    //       print("{s}\n", .{q.qname});
    //       query = q.next;
    //   }

    return error.SkipZigTest;
}

test "sniff with pcap" {
    var backing_buffer: [1024]u8 = undefined;

    var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);

    const allocator = fba.allocator();

    if (try open_pcap()) |iface| {
        const capture_buf: ?[]align(2) u8 = try iface.capture_one_raw(allocator);
        if (capture_buf) |buf| {
            //print("Captured: {x}\n", .{buf});
            //allocator.free(buf);
            var packet = try Packet.create(allocator, std.heap.page_allocator);
            try packet.from_raw(buf, link_layer_type.ETHERNET);
            try packet.to_string(std.heap.page_allocator);
        } else {
            print("no capture data.\n", .{});
        }
    }
}

test "build independant eth layer" {
    var eth_layer_owner = LayerOwner{ .owned_buffer = .init_empty(std.heap.page_allocator) };

    defer eth_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);

    var eth_layer: Eth.EthLayer = try Eth.EthLayer.init(eth_layer_owner);

    eth_layer.set_eth_type(Eth.EthType.IP);

    try expect(try eth_layer.get_eth_type() == Eth.EthType.IP);

    eth_layer.set_dst_mac(try Eth.MacAddress.init_from_string("1A:2A:3A:4A:5A:6A"));

    eth_layer.set_src_mac(try Eth.MacAddress.init_from_string("1B:2B:3B:4B:5B:6B"));
}

test "build independant ipv4 layer" {
    var ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(std.heap.page_allocator) };

    defer ipv4_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);

    var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);

    ipv4_layer_iface.ipv4Layer.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));

    ipv4_layer_iface.ipv4Layer.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.2"));

    ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);

    ipv4_layer_iface.ipv4Layer.set_ttl(64);

    //  print("{s}\n", .{ipv4_layer_iface.to_string(std.heap.page_allocator)});
}

test "ipv4 option parse" {
    print("========================== START ==========================\n", .{});
    print("ipv4 option parse\n", .{});
    var backing_buffer: [1024]u8 = undefined;

    var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);

    const allocator = fba.allocator();

    var ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    defer ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);

    var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);

    ipv4_layer_iface.ipv4Layer.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.225"));

    ipv4_layer_iface.ipv4Layer.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.254"));

    ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);

    ipv4_layer_iface.ipv4Layer.set_ttl(64);

    var record_route_op: [15]u8 align(2) = [_]u8{
        0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    };

    //   print("record_route_op len: {}\n", .{record_route_op.len});

    var op = try IPv4.IPOption.init(IPv4.IPOptionType.RecordRoute, &record_route_op);

    _ = &op;

    //op.swap_byte(1, 0x0F);

    op.set_len(15);

    //try op.pad_nop(op.data.len, 4, allocator);

    try ipv4_layer_iface.ipv4Layer.add_option(op, allocator);

    try ipv4_layer_iface.ipv4Layer.calculate_checksum();

    //print("{s}\n", .{ipv4_layer_iface.to_string(allocator)});

    const ipv4_data = ipv4_layer_iface.get_data();

    _ = &ipv4_data;

    print("IPv4: ({}) {x}\n", .{ ipv4_data.len, ipv4_data });

    const ipv4_ops = ipv4_layer_iface.ipv4Layer.get_options();

    _ = &ipv4_ops;

    print("IPv4 Record Route Option as bytes: ({}) {x}\n", .{ ipv4_ops.len, ipv4_ops });

    print("========================== END ==========================\n", .{});
}

test "build udp layer independant" {
    var udp_layer_owner = LayerOwner{ .owned_buffer = .init_empty(std.heap.page_allocator) };

    defer udp_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);

    var udp_layer_iface: LayerIface = try LayerIface.init(UDP.UDPLayer, udp_layer_owner);

    _ = &udp_layer_iface;

    udp_layer_iface.udpLayer.set_src_port(1024);
    udp_layer_iface.udpLayer.set_dst_port(53);

    //   print("{s}\n", .{udp_layer_iface.to_string(std.heap.page_allocator)});
}

test "build generic layer independant" {
    const page_allocator = std.heap.page_allocator;
    var app_layer_owner = LayerOwner{ .owned_buffer = .init_empty(page_allocator) };

    defer app_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);

    var app_layer_iface: LayerIface = try LayerIface.init(ApplicationLayer, app_layer_owner);

    try app_layer_iface.genericAppLayer.set_payload("hello");

    //    print("app layer data: {s}\n", .{app_layer_iface.to_string(page_allocator)});
}

test "build ipv4 layer with Router Alert option" {
    //   print("========================== START ==========================\n", .{});
    //   print("build ipv4 layer with Router Alert option\n", .{});
    //   var backing_buffer: [1024]u8 = undefined;
    //
    //   var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);
    //
    //   const allocator = fba.allocator();
    //
    //   var ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
    //
    //   defer ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);
    //
    //   var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);
    //
    //   ipv4_layer_iface.ipv4Layer.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.225"));
    //
    //   ipv4_layer_iface.ipv4Layer.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.254"));
    //
    //   ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);
    //
    //   ipv4_layer_iface.ipv4Layer.set_ttl(1);
    //
    //   var router_alert_op = [2]u8{ 0x00, 0x00 };
    //
    //   const op = try IPv4.IPOption.init(IPv4.IPOptionType.RouterAlert, &router_alert_op);
    //
    //   const op_bytes = try op.toBytes(allocator);
    //
    //   try expect(op_bytes[0] == 0x94);
    //   try expect(op_bytes[1] == 0x04);
    //   try expect(op_bytes[2] == 0x00);
    //   try expect(op_bytes[3] == 0x00);
    //
    //   try ipv4_layer_iface.ipv4Layer.add_option(op, allocator);
    //   print("option added.\n", .{});
    //
    //   //      const ipv4_hdr: *IPv4.IPv4Header = ipv4_layer_iface.ipv4Layer.get_mutable_header();
    //
    //   //ipv4_layer_iface.ipv4Layer.calculate_checksum();
    //   //       print("ihl: {any}\n", .{ipv4_hdr.get_ihl()});
    //   //        print("{s}\n", .{ipv4_layer_iface.ipv4Layer.to_string(std.heap.page_allocator)});
    //
    //   var ipv4_slice = ipv4_layer_iface.ipv4Layer.get_data();
    //   print("{x} ({})\n", .{ ipv4_slice, ipv4_slice.len });
    //
    //   try expect(ipv4_slice.len == 24);
    //
    //   try ipv4_layer_iface.ipv4Layer.remove_all_options();
    //
    //   ipv4_slice = ipv4_layer_iface.ipv4Layer.get_data();
    //   print("{x} ({})\n", .{ ipv4_slice, ipv4_slice.len });
    //
    //   print("========================== END ==========================\n", .{});
}

test "ipv4 layer in complete packet with Router Alert option" {
    //   print("========================== START ==========================\n", .{});
    //   print("ipv4 layer in complete packet with Router Alert option\n", .{});
    //   var backing_buffer: [1024]u8 = undefined;
    //
    //   var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);
    //
    //   const allocator = fba.allocator();
    //
    //   var ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
    //
    //   defer ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);
    //
    //   var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);
    //
    //   ipv4_layer_iface.ipv4Layer.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.225"));
    //
    //   ipv4_layer_iface.ipv4Layer.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.254"));
    //
    //   ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);
    //
    //   ipv4_layer_iface.ipv4Layer.set_ttl(1);
    //
    //   var router_alert_op = [2]u8{ 0x00, 0x00 };
    //
    //   const op = try IPv4.IPOption.init(IPv4.IPOptionType.RouterAlert, &router_alert_op);
    //
    //   const op_bytes = try op.toBytes(allocator);
    //
    //   try expect(op_bytes[0] == 0x94);
    //   try expect(op_bytes[1] == 0x04);
    //   try expect(op_bytes[2] == 0x00);
    //   try expect(op_bytes[3] == 0x00);
    //
    //   var packet = try Packet.create(allocator, allocator);
    //
    //   const eth_layer_owner = LayerOwner{ .owned_buffer = .init_empty(std.heap.page_allocator) };
    //
    //   //defer eth_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);
    //
    //   var eth_layer_iface: LayerIface = try LayerIface.init(Eth.EthLayer, eth_layer_owner); // making a copy of owner?
    //
    //   eth_layer_iface.ethLayer.set_eth_type(Eth.EthType.IP);
    //
    //   try expect(try eth_layer_iface.ethLayer.get_eth_type() == Eth.EthType.IP);
    //
    //   eth_layer_iface.ethLayer.set_dst_mac(try Eth.MacAddress.init_from_string("38:06:e6:92:63:ac"));
    //
    //   eth_layer_iface.ethLayer.set_src_mac(try Eth.MacAddress.init_from_string("14:4f:8a:a4:15:7d"));
    //
    //   var udp_layer_owner = LayerOwner{ .owned_buffer = .init_empty(std.heap.page_allocator) };
    //
    //   defer udp_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);
    //
    //   var udp_layer_iface: LayerIface = try LayerIface.init(UDP.UDPLayer, udp_layer_owner);
    //
    //   udp_layer_iface.udpLayer.set_src_port(1024);
    //   udp_layer_iface.udpLayer.set_dst_port(5005);
    //
    //   const page_allocator = std.heap.page_allocator;
    //   var app_layer_owner = LayerOwner{ .owned_buffer = .init_empty(page_allocator) };
    //
    //   defer app_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);
    //
    //   var app_layer_iface: LayerIface = try LayerIface.init(ApplicationLayer, app_layer_owner);
    //
    //   try app_layer_iface.genericAppLayer.set_payload("hello");
    //
    //   try expect(try packet.add_layer(&eth_layer_iface));
    //
    //   try expect(try packet.add_layer(&ipv4_layer_iface));
    //
    //   try expect(try packet.add_layer(&udp_layer_iface));
    //
    //   try expect(try packet.add_layer(&app_layer_iface));
    //
    //   print("layer count: {}\n", .{packet.get_layer_count()});
    //
    //   var pkt_data = packet.buffer.buffer.items;
    //
    //   print("packet: ({}) {x}\n", .{ pkt_data.len, pkt_data });
    //
    //   packet.print_layers_meta();
    //
    //   if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4_layer| {
    //       if (ipv4_layer.get_payload()) |payload| {
    //           print("ipv4 payload: ({}) {x}\n", .{ payload.len, payload });
    //       }
    //       print("{s}\n", .{ipv4_layer.to_string(std.heap.page_allocator)});
    //       try ipv4_layer.add_option(op, allocator);
    //
    //       print("option added.\n", .{});
    //
    //       packet.print_layers_meta();
    //
    //       pkt_data = packet.buffer.buffer.items;
    //
    //       print("packet: ({}) {x}\n", .{ pkt_data.len, pkt_data });
    //
    //       if (ipv4_layer.get_payload()) |payload| {
    //           print("ipv4 payload: ({}) {x}\n", .{ payload.len, payload });
    //       }
    //
    //       print("hdr len: {}\n", .{ipv4_layer.get_header_len()});
    //
    //       //try ipv4_layer.remove_all_options();
    //   }
    //
    //   pkt_data = packet.buffer.buffer.items;
    //
    //   print("packet: ({}) {x}\n", .{ pkt_data.len, pkt_data });
    //
    //   packet.print_layers_meta();
    //
    //   if (packet.get_layer_of_type(UDP.UDPLayer)) |udp| {
    //       udp.calculate_checksum();
    //   }
    //
    //   if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4| {
    //       ipv4.calculate_checksum();
    //   }
    //
    //   try packet.to_string(page_allocator);
    //
    //   //    try send_packet(packet.buffer.buffer.items);
    //
    //   print("========================== END OF ==========================\n", .{});

    //    try packet.to_string(page_allocator);
}

test "build ipv4 packet with Record Route option" {
    print("========================== START ==========================\n", .{});
    print("build ipv4 packet with Record Route option\n", .{});
    var backing_buffer: [1024]u8 = undefined;

    var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);

    const allocator = fba.allocator();

    var ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    defer ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);

    var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);

    ipv4_layer_iface.ipv4Layer.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.225"));

    ipv4_layer_iface.ipv4Layer.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.227"));

    ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);

    ipv4_layer_iface.ipv4Layer.set_ttl(64);

    var record_route_op: [15]u8 align(2) = [_]u8{
        0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    };

    print("record_route_op len: {}\n", .{record_route_op.len});

    var op = try IPv4.IPOption.init(IPv4.IPOptionType.RecordRoute, &record_route_op);

    _ = &op;

    //op.swap_byte(1, 0x0F);

    op.set_len(15);

    //try op.pad_nop(op.data.len, 4, allocator);

    //try ipv4_layer_iface.ipv4Layer.add_option(op, allocator);

    //var ipv4_layer = ipv4_layer_iface.ipv4Layer; // DO NOT DO THIS - it creates a copy and invalidates the concrete layer which you add later

    var packet = try Packet.create(allocator, allocator);

    const eth_layer_owner = LayerOwner{ .owned_buffer = .init_empty(std.heap.page_allocator) };

    //defer eth_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);

    var eth_layer_iface: LayerIface = try LayerIface.init(Eth.EthLayer, eth_layer_owner); // making a copy of owner?

    eth_layer_iface.ethLayer.set_eth_type(Eth.EthType.IP);

    try expect(try eth_layer_iface.ethLayer.get_eth_type() == Eth.EthType.IP);

    eth_layer_iface.ethLayer.set_dst_mac(try Eth.MacAddress.init_from_string("38:06:e6:92:63:ac"));

    eth_layer_iface.ethLayer.set_src_mac(try Eth.MacAddress.init_from_string("14:4f:8a:a4:15:7d"));

    var udp_layer_owner = LayerOwner{ .owned_buffer = .init_empty(std.heap.page_allocator) };

    defer udp_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);

    var udp_layer_iface: LayerIface = try LayerIface.init(UDP.UDPLayer, udp_layer_owner);

    udp_layer_iface.udpLayer.set_src_port(1024);
    udp_layer_iface.udpLayer.set_dst_port(56052);

    const page_allocator = std.heap.page_allocator;
    var app_layer_owner = LayerOwner{ .owned_buffer = .init_empty(page_allocator) };

    defer app_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);

    var app_layer_iface: LayerIface = try LayerIface.init(ApplicationLayer, app_layer_owner);

    try app_layer_iface.genericAppLayer.set_payload("hello");

    try expect(try packet.add_layer(&eth_layer_iface));

    try expect(try packet.add_layer(&ipv4_layer_iface));

    try expect(try packet.add_layer(&udp_layer_iface));

    try expect(try packet.add_layer(&app_layer_iface));

    print("layer count: {}\n", .{packet.get_layer_count()});

    var pkt_data = packet.buffer.buffer.items;

    print("packet: ({}) {x}\n", .{ pkt_data.len, pkt_data });

    packet.print_layers_meta();

    //   if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4_layer| {
    //       if (ipv4_layer.get_payload()) |payload| {
    //           print("ipv4 payload: ({}) {x}\n", .{ payload.len, payload });
    //       }
    //       print("{s}\n", .{ipv4_layer.to_string(std.heap.page_allocator)});
    //       try ipv4_layer.add_option(op, allocator);
    //
    //       print("option added.\n", .{});
    //
    //       packet.print_layers_meta();
    //
    //       pkt_data = packet.buffer.buffer.items;
    //
    //       print("packet: ({}) {x}\n", .{ pkt_data.len, pkt_data });
    //
    //       if (ipv4_layer.get_payload()) |payload| {
    //           print("ipv4 payload: ({}) {x}\n", .{ payload.len, payload });
    //       }
    //
    //       print("hdr len: {}\n", .{ipv4_layer.get_header_len()});
    //
    //       //try ipv4_layer.remove_all_options();
    //   }

    //   if (try packet.search_layers(tcp_ip_protocol.ipv4)) |ipv4| {
    //       const hdr_len = ipv4.layer_iface.ipv4Layer.get_header_len();
    //
    //       const pad_bytes: usize = 4 - (hdr_len % 4);
    //
    //       print("hdr len: {}\n", .{hdr_len});
    //
    //       print("required padding: {}\n", .{pad_bytes});
    //
    //       const pad: []u8 = try packet.extend_layer(ipv4, 3);
    //       @memset(pad, 0);
    //   }

    pkt_data = packet.buffer.buffer.items;

    print("packet: ({}) {x}\n", .{ pkt_data.len, pkt_data });

    if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4| {
        //try ipv4.pad_buffer();
        try ipv4.add_option(op, allocator);
    }

    packet.print_layers_meta();

    if (packet.get_layer_of_type(UDP.UDPLayer)) |udp| {
        udp.calculate_checksum();
    }

    if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4| {
        try ipv4.calculate_checksum();
        print("IPv4 total length: {}\n", .{ipv4.get_length()});
        const ops = ipv4.get_options();
        print("ops: ({}) {x}\n", .{ ops.len, ops });
    }

    packet.print_layers_meta();

    pkt_data = packet.buffer.buffer.items;

    print("packet: ({}) {x}\n", .{ pkt_data.len, pkt_data });

    if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4| {
        _ = ipv4;
    }

    //try packet.to_string(page_allocator);

    //try send_packet(packet.buffer.buffer.items);

    //   print("size of Buffer: {}\n", .{@sizeOf(Buffer)});
    //   print("size of IPOption: {}\n", .{@sizeOf(IPv4.IPOption)});
    //   print("size of IPOptionType: {}\n", .{@sizeOf(IPv4.IPOptionType)});
    //   print("size of u8: {}\n", .{@sizeOf(u8)});
    //   print("size of []u8: {}\n", .{@sizeOf([]u8)});

    if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4| {
        try ipv4.zero_hdr();
        print("{s}\n", .{ipv4.to_string(page_allocator)});
    } else {
        print("ipv4 layer not found.\n", .{});
    }

    packet.print_layers_meta();

    pkt_data = packet.buffer.buffer.items;

    print("packet: ({}) {x}\n", .{ pkt_data.len, pkt_data });

    print("========================== END ==========================\n", .{});
}

test "build ipv4 layer with Record Route option" {
    //   print("========================== START ==========================\n", .{});
    //   var backing_buffer: [1024]u8 = undefined;
    //
    //   var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);
    //
    //   const allocator = fba.allocator();
    //
    //   var ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
    //
    //   defer ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);
    //
    //   var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);
    //
    //   ipv4_layer_iface.ipv4Layer.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.225"));
    //
    //   ipv4_layer_iface.ipv4Layer.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.254"));
    //
    //   ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);
    //
    //   ipv4_layer_iface.ipv4Layer.set_ttl(64);
    //
    //   var record_route_op = [_]u8{ 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    //
    //   //    print("record_route_op len: {}\n", .{record_route_op.len});
    //
    //   const op = try IPv4.IPOption.init(IPv4.IPOptionType.RecordRoute, &record_route_op);
    //
    //   const op_bytes = try op.toBytes(allocator);
    //
    //   _ = op_bytes;
    //
    //   //var ipv4_layer = ipv4_layer_iface.ipv4Layer; // DO NOT DO THIS - it creates a copy and invalidates the concrete layer which you add later
    //
    //   //    try ipv4_layer.add_option(op, allocator); // bug here causes packet add_layer to use stale ptr
    //
    //   const ipv4_hdr: *IPv4.IPv4Header = ipv4_layer_iface.ipv4Layer.get_mutable_header();
    //
    //   _ = ipv4_hdr;
    //
    //   //    print("ihl: {any}\n", .{ipv4_hdr.get_ihl()});
    //   //    print("{s}\n", .{ipv4_layer_iface.ipv4Layer.to_string(std.heap.page_allocator)});
    //   const ipv4_slice = ipv4_layer_iface.ipv4Layer.get_data();
    //
    //   _ = ipv4_slice;
    //   //    print("{x} ({})\n", .{ ipv4_slice, ipv4_slice.len });
    //
    //   //    print("ihl: {}\n", .{ipv4_hdr.get_ihl()});
    //
    //   //    try ipv4_layer_iface.ipv4Layer.remove_all_options();
    //
    //   //    print("ihl: {any}\n", .{ipv4_hdr.get_ihl()});
    //   //    print("{s}\n", .{ipv4_layer_iface.ipv4Layer.to_string(std.heap.page_allocator)});
    //   const trimmed = ipv4_layer_iface.ipv4Layer.get_data();
    //   _ = trimmed;
    //   //    print("{x} ({})\n", .{ trimmed, trimmed.len });
    //
    //   var packet = try Packet.create(allocator, allocator);
    //
    //   try expect(try packet.add_layer(&ipv4_layer_iface));
    //
    //   //    print("added IPv4 layer to packet.\n", .{});
    //
    //   //packet.print_layers_meta();
    //
    //   if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ip_layer| {
    //       _ = ip_layer;
    //       //try ip_layer.add_option(op, allocator);
    //       //
    //       //const ipv4_hdr: *IPv4.IPv4Header = ipv4_layer.get_mutable_header();
    //       //
    //       //       ipv4_layer.calculate_checksum();
    //       //print("ihl: {any}\n", .{ipv4_hdr.get_ihl()});
    //       //       print("{s}\n", .{ipv4_layer.to_string(std.heap.page_allocator)});
    //       //       const ip_slice = ip_layer.get_data();
    //       //       print("{x} ({})\n", .{ ip_slice, ip_slice.len });
    //       //
    //       //       //        print("ihl: {}\n", .{ipv4_hdr.get_ihl()});
    //       //
    //       //try ip_layer.remove_all_options();
    //       //
    //       //       //        print("current hdr length: {}\n", .{ipv4_layer.get_header_len()});
    //       //
    //       //       //        try expect(ipv4_slice.len == 24);
    //   }
    //
    //   //packet.print_layers_meta();
    print("========================== END ==========================\n", .{});
}

test "add IPv4 layer after mutation" {
    //  var backing_buffer: [1024]u8 = undefined;

    //  var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);

    //  const allocator = fba.allocator();

    //  var ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    //  defer ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);

    //  var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);

    //  ipv4_layer_iface.ipv4Layer.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.225"));

    //  ipv4_layer_iface.ipv4Layer.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.254"));

    //  ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);

    //  ipv4_layer_iface.ipv4Layer.set_ttl(64);

    //  var record_route_op = [_]u8{ 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    //  //   print("record_route_op len: {}\n", .{record_route_op.len});

    //  const op = try IPv4.IPOption.init(IPv4.IPOptionType.RecordRoute, &record_route_op);

    //  const op_bytes = try op.toBytes(allocator);

    //  _ = op_bytes;

    //  try ipv4_layer_iface.ipv4Layer.add_option(op, allocator);

    //  var packet = try Packet.create(allocator, allocator);

    //  try expect(try packet.add_layer(&ipv4_layer_iface));

    //  //    packet.print_layers_meta();

    //  if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ip_layer| {
    //      const ip_slice = ip_layer.get_data();
    //      _ = ip_slice;
    //      try ip_layer.remove_all_options();
    //  }

    //    packet.print_layers_meta();
}

test "build eth,ipv4,udp,generic_app packet" {
    //   //const page_allocator = std.heap.page_allocator;
    //
    //   var backing_buffer: [1024]u8 = undefined;
    //
    //   var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);
    //
    //   const allocator = fba.allocator();
    //
    //   var eth_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
    //
    //   defer eth_layer_owner.owned_buffer.buffer.deinit(allocator);
    //
    //   var eth_layer_iface: LayerIface = try LayerIface.init(Eth.EthLayer, (eth_layer_owner));
    //
    //   eth_layer_iface.ethLayer.set_eth_type(Eth.EthType.IP);
    //
    //   try expect(try eth_layer_iface.ethLayer.get_eth_type() == Eth.EthType.IP);
    //
    //   eth_layer_iface.ethLayer.set_dst_mac(try Eth.MacAddress.init_from_string("38:06:e6:92:63:ac"));
    //
    //   eth_layer_iface.ethLayer.set_src_mac(try Eth.MacAddress.init_from_string("14:4f:8a:a4:15:7d"));
    //
    //   //    print("{s}\n", .{eth_layer_iface.ethLayer.to_string(page_allocator)});
    //
    //   var ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
    //
    //   defer ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);
    //
    //   var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, eth_layer_owner);
    //
    //   ipv4_layer_iface.ipv4Layer.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.225"));
    //
    //   ipv4_layer_iface.ipv4Layer.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.254"));
    //
    //   ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);
    //
    //   ipv4_layer_iface.ipv4Layer.set_ttl(64);
    //
    //   //    print("{s}\n", .{ipv4_layer_iface.to_string(std.heap.page_allocator)});
    //
    //   var udp_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
    //
    //   defer udp_layer_owner.owned_buffer.buffer.deinit(allocator);
    //
    //   var udp_layer_iface: LayerIface = try LayerIface.init(UDP.UDPLayer, eth_layer_owner);
    //
    //   _ = &udp_layer_iface;
    //
    //   udp_layer_iface.udpLayer.set_src_port(1024);
    //   udp_layer_iface.udpLayer.set_dst_port(5005);
    //
    //   //   print("{s}\n", .{udp_layer_iface.to_string(std.heap.page_allocator)});
    //
    //   var app_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
    //
    //   defer app_layer_owner.owned_buffer.buffer.deinit(allocator);
    //
    //   var app_layer_iface: LayerIface = try LayerIface.init(ApplicationLayer, eth_layer_owner);
    //
    //   try app_layer_iface.genericAppLayer.set_payload("hello");
    //
    //   //  print("app layer data: {s}\n", .{app_layer_iface.to_string(page_allocator)});
    //
    //   try app_layer_iface.genericAppLayer.delete_payload_data();
    //
    //   var packet = try Packet.create(allocator, allocator);
    //
    //   defer packet.deinit();
    //
    //   try expect(try packet.add_layer(&eth_layer_iface));
    //   try expect(try packet.add_layer(&ipv4_layer_iface));
    //   try expect(try packet.add_layer(&udp_layer_iface));
    //   try expect(try packet.add_layer(&app_layer_iface));
    //
    //   //try packet.to_string(page_allocator);
    //
    //   if (packet.get_layer_of_type(Eth.EthLayer)) |eth| {
    //       eth.set_eth_type(Eth.EthType.ARP);
    //   }
    //
    //   if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4| {
    //       ipv4.set_ttl(128);
    //       ipv4.calculate_length();
    //   }
    //
    //   if (packet.get_layer_of_type(ApplicationLayer)) |app| {
    //       try app.set_payload("hello new world");
    //
    //       //        print("{s}\n", .{app.to_string(page_allocator)});
    //   }
    //
    //   //try packet.to_string(page_allocator);
    //
    //   if (try packet.search_layers(tcp_ip_protocol.ipv4)) |ipv4| {
    //       var new_ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
    //       defer new_ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);
    //       var ip_layer = try packet.extract_layer(ipv4, &eth_layer_owner) orelse {
    //           print("failed to extract ip layer.\n", .{});
    //           return;
    //       };
    //
    //       ip_layer.ipv4Layer.set_ip_proto(IPProtocol.UDP);
    //
    //       const eth = try packet.search_layers(tcp_ip_protocol.eth) orelse {
    //           print("could not find eth layer.\n", .{});
    //           return;
    //       };
    //       try expect(try eth.layer_iface.get_protocol() == tcp_ip_protocol.eth);
    //       try expect(try packet.insert_layer(eth, &ip_layer));
    //   }
    //
    //   if (packet.get_layer_of_type(Eth.EthLayer)) |eth| {
    //       eth.set_eth_type(Eth.EthType.IP);
    //   }
    //
    //   if (packet.get_layer_of_type(UDP.UDPLayer)) |udp| {
    //       udp.calculate_checksum();
    //   }
    //
    //   if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4| {
    //       ipv4.calculate_checksum();
    //       //print("ipv4 length: {}\n", .{ipv4.get_length()});
    //   }

    //try packet.to_string(page_allocator);

    //packet.print_layers_meta();

    //print("({}) {x}\n", .{ packet.buffer.buffer.items.len, packet.buffer.buffer.items });

    //    try send_packet(packet.buffer.buffer.items);

    //const end_index = fba.end_index;
    //
    //print("Backing buffer: {x} ({})\n", .{ backing_buffer[0..end_index], end_index });
}

test "build packet" {
    const page_allocator = std.heap.page_allocator;

    var backing_buffer: [1024]u8 = undefined;

    var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);

    const allocator = fba.allocator();

    var eth_layer_owner = LayerOwner{ .owned_buffer = .init_empty(std.heap.page_allocator) };

    _ = &eth_layer_owner;

    defer eth_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);

    var eth_layer: Eth.EthLayer = try Eth.EthLayer.init(eth_layer_owner);

    eth_layer.set_eth_type(Eth.EthType.IP);

    try expect(try eth_layer.get_eth_type() == Eth.EthType.IP);

    eth_layer.set_dst_mac(try Eth.MacAddress.init_from_string("1A:2A:3A:4A:5A:6A"));

    eth_layer.set_src_mac(try Eth.MacAddress.init_from_string("1B:2B:3B:4B:5B:6B"));

    var packet = try Packet.create(allocator, page_allocator);

    _ = &packet;

    var eth_iface = try LayerIface.init(Eth.EthLayer, eth_layer.owner); // zero-copy LayerIface init over existing eth_layer

    eth_layer.set_eth_type(Eth.EthType.ARP); // this is working on the original created layer

    try expect(try eth_iface.ethLayer.get_eth_type() == Eth.EthType.ARP);

    // print("{s}\n", .{eth_iface.ethLayer.to_string(page_allocator)});

    _ = try packet.add_layer(&eth_iface);

    var ethlayer: *Eth.EthLayer = packet.get_layer_of_type(Eth.EthLayer) orelse {
        print("failed to get eth layer.\n", .{});
        return;
    };

    _ = &ethlayer;

    ethlayer.set_eth_type(Eth.EthType.IP);

    try expect(try ethlayer.get_eth_type() != try eth_layer.get_eth_type());

    //  print("{s}\n", .{ethlayer.to_string(page_allocator)});

    //packet.print_layers_meta();

    //    print("packet: {x}\n", .{packet.buffer.buffer.items});
}

test "remove_eth" {
    //   const udp_raw = [47]u8{ 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x21, 0xb5, 0xba, 0x0, 0x0, 0x80, 0x11, 0xff, 0xe1, 0xc0, 0xa8, 0x1, 0xe1, 0xc0, 0xa8, 0x1, 0xfe, 0xe8, 0xd9, 0x13, 0x8d, 0x0, 0xd, 0x3a, 0x6b, 0x68, 0x65, 0x6c, 0x6c, 0x6f };
    //
    //   _ = &udp_raw;
    //
    //   var backing_buffer: [1024]u8 = undefined;
    //
    //   var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);
    //   const allocator = fba.allocator();
    //
    //   const page_allocator = std.heap.page_allocator;
    //
    //   const raw: []u8 = try allocator.alloc(u8, udp_raw.len);
    //
    //   std.mem.copyForwards(u8, raw, udp_raw[0..]);
    //
    //   var packet = try Packet.create(allocator, page_allocator);
    //
    //   print("raw: ({}) {x}\n", .{ raw.len, raw });
    //
    //   try packet.from_raw(raw, link_layer_type.ETHERNET);
    //
    //   var eth_layer_in_packet: *Layer = try packet.search_layers(tcp_ip_protocol.eth) orelse {
    //       print("could not find eth layer.\n", .{});
    //       return;
    //   };
    //
    //   _ = &eth_layer_in_packet;
    //
    //   print("eth layer len: {}\n", .{eth_layer_in_packet.length});
    //
    //   eth_layer_in_packet.to_string(page_allocator);
    //
    //   var ip_layer_in_packet: *Layer = try packet.search_layers(tcp_ip_protocol.ipv4) orelse {
    //       print("could not find ip layer.\n", .{});
    //       return;
    //   };
    //
    //   _ = &ip_layer_in_packet;
    //
    //   print("ip layer len: {}\n", .{ip_layer_in_packet.length});
    //
    //   packet.print_layers_meta();
    //
    //   ip_layer_in_packet.to_string(page_allocator);
    //
    //   var ipv4_layer: *IPv4.IPv4Layer = packet.get_layer_of_type(IPv4.IPv4Layer) orelse {
    //       print("could not get IPv4 layer.\n", .{});
    //       return;
    //   };
    //
    //   print("{s}\n", .{ipv4_layer.to_string(page_allocator)});
    //
    //   var udp_layer_in_packet: *Layer = try packet.search_layers(tcp_ip_protocol.udp) orelse {
    //       print("could not find ip layer.\n", .{});
    //       return;
    //   };
    //
    //   //   udp_layer_in_packet.layer_iface.udpLayer.set_dst_port(53);
    //   //   udp_layer_in_packet.layer_iface.udpLayer.set_src_port(1234);
    //
    //   udp_layer_in_packet.to_string(page_allocator);
    //
    //   _ = try packet.delete_layer(eth_layer_in_packet);
    //
    //   packet.print_layers_meta();
    //
    //   print("raw: ({}) {x}\n", .{ packet.buffer.buffer.items.len, packet.buffer.buffer.items });

    //
    //   try expect(packet.raw_data.get_len() == udp_raw.len);
    //
    //   var layer_owner = LayerOwner{ .allocator_owned = .{ .allocator = page_allocator, .data = undefined } };
    //
    //   _ = &layer_owner;
    //
    //   const ip_layer: *Layer = try packet.search_layers(tcp_ip_protocol.ipv4) orelse {
    //       print("could not find layer.\n", .{});
    //       return;
    //   };
    //
    //   try expect(try packet.delete_layer(ip_layer));
    //
    //   try expect(packet.get_layer_of_type(IPv4.IPv4Layer) == null);
    //
    //   try expect(packet.raw_data.get_len() == 27); // 27 is size of this test packet's raw data len minus the 20 byte IPv4 layer (which was deleted)
    //
    //   const eth_layer: *Layer = try packet.search_layers(tcp_ip_protocol.eth) orelse {
    //       print("could not find eth layer.\n", .{});
    //       return;
    //   };
    //
    //   var eth_layer_iface: LayerIface = try packet.extract_layer(eth_layer, &layer_owner) orelse {
    //       print("failed to extract layer.\n", .{});
    //       return;
    //   };
    //
    //   const expected_dst_mac = try Eth.MacAddress.init_from_string("38:06:E6:92:63:AC");
    //   const expected_src_mac = try Eth.MacAddress.init_from_string("14:4F:8A:A4:15:7D");
    //   try expect(eth_layer_iface.ethLayer.get_dst_mac().to_u48() == expected_dst_mac.to_u48());
    //   try expect(eth_layer_iface.ethLayer.get_src_mac().to_u48() == expected_src_mac.to_u48());
    //   try expect(try eth_layer_iface.ethLayer.get_eth_type() == Eth.EthType.IP);
    //
    //   const last_layer: *Layer = packet.get_last_layer() orelse {
    //       return;
    //   };
    //
    //   try expect(try last_layer.layer_iface.get_protocol() == tcp_ip_protocol.generic);
    //
    //   var g_layer_owner = LayerOwner{ .allocator_owned = .{ .allocator = page_allocator, .data = undefined } };
    //
    //   var generic_layer_iface: LayerIface = try packet.extract_layer(last_layer, &g_layer_owner) orelse {
    //       print("failed to extract layer.\n", .{});
    //       return;
    //   };
    //
    //   try expect(generic_layer_iface.get_data().get_len() == 5);
    //
    //   if (packet.first_layer) |first| {
    //       //        print("{any}\n", .{first});
    //       _ = try packet.delete_layer(first);
    //   }
    //
    //   try packet.print_layers_metad();
    //
    //   try expect(packet.raw_data.get_len() == 0);
    //
    //   try expect(try packet.add_layer(&eth_layer_iface)); // add the previously extracted eth layer back
    //
    //   const ip_layer_owner = LayerOwner{ .allocator_owned = .{ .allocator = page_allocator, .data = undefined } };
    //
    //   var ipv4_layer_iface = try LayerIface.init(IPv4.IPv4Layer, ip_layer_owner);
    //
    //   ipv4_layer_iface.ipv4Layer.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));
    //   ipv4_layer_iface.ipv4Layer.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.2"));
    //   ipv4_layer_iface.ipv4Layer.set_transport_type(IPProtocol.UDP);
    //
    //   print("({}) {x}\n", .{ packet.raw_data.get_immutable().len, packet.raw_data.get_immutable() });
    //
    //   try expect(try packet.add_layer(&ipv4_layer_iface));
    //
    //   print("({}) {x}\n", .{ packet.raw_data.get_immutable().len, packet.raw_data.get_immutable() });
    //
    //   var ipv4_layer: *IPv4.IPv4Layer = packet.get_layer_of_type(IPv4.IPv4Layer) orelse {
    //       return;
    //   };
    //
    //   try expect(ipv4_layer.get_dst_ip().to_u32() == ipv4_layer_iface.ipv4Layer.get_dst_ip().to_u32());
    //   try expect(ipv4_layer.get_src_ip().to_u32() == ipv4_layer_iface.ipv4Layer.get_src_ip().to_u32());
    //   try expect(try ipv4_layer.get_transport_type() == try ipv4_layer_iface.ipv4Layer.get_transport_type());
    //
    //   print("({}) {x}\n", .{ packet.raw_data.get_immutable().len, packet.raw_data.get_immutable() });
    //
    //   ipv4_layer_iface.ipv4Layer.set_src_ip(try IPv4.IPv4Address.init_from_string("10.1.2.3"));
    //   ipv4_layer_iface.ipv4Layer.set_dst_ip(try IPv4.IPv4Address.init_from_string("10.1.2.4"));
    //   ipv4_layer_iface.ipv4Layer.set_transport_type(IPProtocol.TCP);
    //
    //   print("({}) {x}\n", .{ packet.raw_data.get_immutable().len, packet.raw_data.get_immutable() });
    //
    //   try expect(ipv4_layer.get_dst_ip().to_u32() == ipv4_layer_iface.ipv4Layer.get_dst_ip().to_u32());
    //   try expect(ipv4_layer.get_src_ip().to_u32() == ipv4_layer_iface.ipv4Layer.get_src_ip().to_u32());
    //   try expect(try ipv4_layer.get_transport_type() == try ipv4_layer_iface.ipv4Layer.get_transport_type());
    //
    //   ipv4_layer.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.0.1"));
    //   ipv4_layer.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.0.2"));
    //   ipv4_layer.set_transport_type(IPProtocol.ICMP);
    //
    //   print("({}) {x}\n", .{ packet.raw_data.get_immutable().len, packet.raw_data.get_immutable() });
    //
    //   try expect(ipv4_layer.get_dst_ip().to_u32() == ipv4_layer_iface.ipv4Layer.get_dst_ip().to_u32());
    //   try expect(ipv4_layer.get_src_ip().to_u32() == ipv4_layer_iface.ipv4Layer.get_src_ip().to_u32());
    //   try expect(try ipv4_layer.get_transport_type() == try ipv4_layer_iface.ipv4Layer.get_transport_type());
    //
    //   ipv4_layer.calculate_length();
    //   try expect(ipv4_layer.get_length() == ipv4_layer.get_data().get_len());
    //
    //   //   try expect(try packet.add_layer(&generic_layer_iface));
    //   //
    //   //   const udp_layer_owner = LayerOwner{ .allocator_owned = .{ .allocator = page_allocator, .data = undefined } };
    //   //
    //   //   var udp_layer_iface = try LayerIface.init(UDP.UDPLayer, udp_layer_owner);
    //   //
    //   //   udp_layer_iface.udpLayer.set_dst_port(53);
    //   //   udp_layer_iface.udpLayer.set_src_port(1024);
    //   //
    //   //   //print("ip layer owner layer: {*}\n", .{ipv4_layer.owner.packet_layer});
    //   //
    //   const ip4_layer = try packet.search_layers(tcp_ip_protocol.ipv4) orelse {
    //       return;
    //   };
    //   //
    //   //   //    _ = ip4_layer;
    //   //
    //   //   //try expect(try packet.insert_layer(ip4_layer, &udp_layer_iface));
    //   //   //_ = try packet.insert_layer(null, &udp_layer_iface);
    //   //
    //   //   print("IP4 payload: {x}\n", .{ip4_layer.get_payload()});
    //
    //   const pos = try packet.find_by_layer(ip4_layer);
    //
    //   print("{any}\n", .{pos});
    //
    //   packet.print_layers();
    //
    //   print("({}) {x}\n", .{ packet.raw_data.get_immutable().len, packet.raw_data.get_immutable() });
    //
    //   print("end index: {}\n", .{fba.end_index});

    // remember to test get_layer_of_type (x) and then extract layer and check if x uses the new owner and not packet
}

const ipv4_with_ops = [_]u8{
    // ========== ETHERNET HEADER (14 bytes) ==========
    // Destination MAC (broadcast: ff:ff:ff:ff:ff:ff)
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    // Source MAC (example: 00:11:22:33:44:55)
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    // EtherType (IPv4 = 0x0800)
    0x08, 0x00,

    // ========== IPv4 HEADER WITH OPTIONS (28 bytes) ==========
    // Version (4) + IHL (7 words = 28 bytes)
    0x47,
    // DSCP + ECN (default 0)
    0x00,
    // Total Length (20 IPv4 header + 8 options + 8 UDP + 12 payload = 48 bytes)
    0x00, 0x30,
    // Identification (0xabcd)
    0xab, 0xcd,
    // Flags (0x40 = Don't Fragment) + Fragment Offset (0)
    0x40, 0x00,
    // TTL (64)
    0x40,
    // Protocol (UDP = 17)
    0x11,
    // Header Checksum (calculated as 0x1234 placeholder - replace with actual)
    0x12, 0x34,
    // Source Address (192.168.1.100)
    192,  168,  1,    100,
    // Destination Address (192.168.1.200)
    192,  168,  1,    200,

    // IPv4 OPTIONS (8 bytes)
    // Option 1: Record Route (type=7, len=3, pointer=4)
     0x07, 0x03,
    0x04,
    // Option 2: Timestamp (type=68, len=4, flags=1, overflow=0)
    0x44, 0x04, 0x01, 0x00,
    // Option 3: No-Operation padding (for 4-byte alignment - already aligned)
    // None needed as we're at exactly 28 bytes (7 * 4)

    // ========== UDP HEADER (8 bytes) ==========
    // Source Port (12345)
    0x30,
    0x39,
    // Destination Port (54321)
    0xd4, 0x31,
    // UDP Length (8 header + 12 payload = 20 bytes)
    0x00, 0x14,
    // UDP Checksum (0x0000 = disabled for simplicity, or calculate)
    0x00,
    0x00,

    // ========== GENERIC PAYLOAD (12 bytes) ==========
    // ASCII: "HELLO UDP!"
    0x48, 0x45, 0x4c, 0x4c, 0x4f,
    0x20, 0x55, 0x44, 0x50, 0x21,
    // Extra padding bytes
    0xde,
    0xad,
};

const null_ipv4_udp = [_]u8{ 0x2, 0x0, 0x0, 0x0, 0x45, 0x0, 0x0, 0x48, 0xcd, 0x56, 0x0, 0x0, 0x80, 0x11, 0xda, 0xfc, 0xc0, 0xa8, 0x88, 0x1, 0xc0, 0xa8, 0x88, 0xff, 0xe1, 0x15, 0xe1, 0x15, 0x0, 0x34, 0xb0, 0xee, 0x53, 0x70, 0x6f, 0x74, 0x55, 0x64, 0x70, 0x30, 0x24, 0x8d, 0x51, 0x4c, 0xed, 0x5d, 0xa3, 0x52, 0x0, 0x1, 0x0, 0x4, 0x48, 0x95, 0xc2, 0x3, 0xcd, 0x88, 0xe6, 0xa0, 0x46, 0x3d, 0x42, 0x5f, 0x2b, 0xfd, 0x38, 0x99, 0xd8, 0xdd, 0xd6, 0x60, 0x2e, 0x19, 0xe1, 0xc3 };

const ipv6_dns_no_eth = [_]u8{ 0x60, 0x8, 0x5a, 0x43, 0x0, 0x23, 0x11, 0x40, 0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa6, 0x61, 0x8f, 0x26, 0x87, 0xeb, 0xbe, 0x60, 0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3a, 0x6, 0xe6, 0xff, 0xfe, 0x92, 0x63, 0xac, 0xdb, 0xe4, 0x0, 0x35, 0x0, 0x23, 0x26, 0x20, 0x4f, 0xa0, 0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4, 0x77, 0x70, 0x61, 0x64, 0x4, 0x68, 0x6f, 0x6d, 0x65, 0x0, 0x0, 0x1, 0x0, 0x1 };

const raw_ipv4_packet = [_]u8{
    // IPv4 Header (20 bytes)
    0x45, // Version (4) + IHL (5 = 20 bytes)
    0x00, // DSCP/ECN
    0x00, 0x1c, // Total Length = 28 bytes (20 header + 8 payload)
    0x12, 0x34, // Identification
    0x00, 0x00, // Flags + Fragment Offset
    0x40, // TTL = 64
    0x11, // Protocol = 17 (UDP)
    0x00, 0x00, // Header checksum (set to 0 for simplicity)

    // Source IP (192.168.1.1)
    0xc0, 0xa8,
    0x01, 0x01,

    // Destination IP (192.168.1.2)
    0xc0, 0xa8,
    0x01, 0x02,

    // Payload (8 bytes — pretend UDP or just raw data)
    0xde, 0xad,
    0xbe, 0xef,
    0xca, 0xfe,
    0xba, 0xbe,
};

const http_req_loopback: [76]u8 = .{ 0x18, 0x0, 0x0, 0x0, 0x60, 0x3, 0x55, 0xf8, 0x0, 0x20, 0x6, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0xb5, 0x47, 0x0, 0x50, 0xe3, 0xad, 0x6a, 0xe6, 0x0, 0x0, 0x0, 0x0, 0x80, 0x2, 0xff, 0xff, 0x70, 0xd3, 0x0, 0x0, 0x2, 0x4, 0xff, 0xc3, 0x1, 0x3, 0x3, 0x8, 0x1, 0x1, 0x4, 0x2 };

const icmp_loopback: [64]u8 = .{ 0x2, 0x0, 0x0, 0x0, 0x45, 0x0, 0x0, 0x3c, 0xd4, 0xea, 0x0, 0x0, 0x80, 0x1, 0x67, 0xd4, 0x7f, 0x0, 0x0, 0x1, 0x7f, 0x0, 0x0, 0x1, 0x8, 0x0, 0xf, 0xf7, 0x0, 0x1, 0x3d, 0x64, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69 };

const raw_dns: [87]u8 = .{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x8, 0x0, 0x45, 0x0, 0x0, 0x49, 0x5d, 0xf7, 0x40, 0x0, 0x40, 0x11, 0x57, 0x7d, 0xc0, 0xa8, 0x1, 0xfe, 0xc0, 0xa8, 0x1, 0xe1, 0x0, 0x35, 0xfd, 0xdf, 0x0, 0x35, 0x9d, 0xff, 0x3a, 0xd0, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x7, 0x7a, 0x69, 0x67, 0x6c, 0x61, 0x6e, 0x67, 0x3, 0x6f, 0x72, 0x67, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1, 0x2c, 0x0, 0x4, 0x41, 0x6d, 0x69, 0xb2 };

const http_raw = [148]u8{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x20, 0x35, 0x43, 0x5e, 0xdd, 0x17, 0x8, 0x0, 0x45, 0x0, 0x0, 0x86, 0x17, 0x3, 0x40, 0x0, 0x40, 0x6, 0x9e, 0x8f, 0xc0, 0xa8, 0x1, 0xae, 0xc0, 0xa8, 0x1, 0xe1, 0xdd, 0xd6, 0xf7, 0x7d, 0x4f, 0x90, 0xa1, 0x3b, 0x23, 0x25, 0x46, 0x9b, 0x50, 0x18, 0x7, 0x64, 0xc1, 0x1a, 0x0, 0x0, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0xd, 0xa, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x78, 0x6d, 0x6c, 0xd, 0xa, 0x41, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x55, 0x52, 0x4c, 0x3a, 0x20, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x31, 0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x31, 0x2e, 0x31, 0x37, 0x34, 0x3a, 0x35, 0x36, 0x37, 0x38, 0x39, 0x2f, 0x61, 0x70, 0x70, 0x73, 0x2f, 0xd, 0xa, 0xd, 0xa };

const tcp_syn_raw = [66]u8{ 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x34, 0x25, 0x20, 0x40, 0x0, 0x80, 0x6, 0x50, 0x74, 0xc0, 0xa8, 0x1, 0xe1, 0xc0, 0xa8, 0x1, 0xfe, 0xa7, 0xe, 0x15, 0xb3, 0xdb, 0xb7, 0xfb, 0x41, 0x0, 0x0, 0x0, 0x0, 0x80, 0x2, 0xff, 0xff, 0x56, 0x25, 0x0, 0x0, 0x2, 0x4, 0x5, 0xb4, 0x1, 0x3, 0x3, 0x8, 0x1, 0x1, 0x4, 0x2 };

const icmp_request_raw = [74]u8{ 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x3c, 0x71, 0xdc, 0x0, 0x0, 0x80, 0x1, 0xf5, 0xef, 0xc0, 0xa8, 0x1, 0xe1, 0x8e, 0xfa, 0x81, 0x71, 0x8, 0x0, 0x4d, 0x5a, 0x0, 0x1, 0x0, 0x1, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69 };

const ipv6_dns_request_raw = [89]u8{ 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x86, 0xdd, 0x60, 0x8, 0x5a, 0x43, 0x0, 0x23, 0x11, 0x40, 0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa6, 0x61, 0x8f, 0x26, 0x87, 0xeb, 0xbe, 0x60, 0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3a, 0x6, 0xe6, 0xff, 0xfe, 0x92, 0x63, 0xac, 0xdb, 0xe4, 0x0, 0x35, 0x0, 0x23, 0x26, 0x20, 0x4f, 0xa0, 0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4, 0x77, 0x70, 0x61, 0x64, 0x4, 0x68, 0x6f, 0x6d, 0x65, 0x0, 0x0, 0x1, 0x0, 0x1 };

const arp_request_raw = [60]u8{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x8, 0x6, 0x0, 0x1, 0x8, 0x0, 0x6, 0x4, 0x0, 0x1, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0xc0, 0xa8, 0x1, 0xfe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc0, 0xa8, 0x1, 0xe1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

const raw_udp: [42]u8 = .{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x8, 0x0, 0x45, 0x0, 0x0, 0x49, 0x5d, 0xf7, 0x40, 0x0, 0x40, 0x11, 0x57, 0x7d, 0xc0, 0xa8, 0x1, 0xfe, 0xc0, 0xa8, 0x1, 0xe1, 0x0, 0x35, 0xfd, 0xdf, 0x0, 0x35, 0x9d, 0xff };
