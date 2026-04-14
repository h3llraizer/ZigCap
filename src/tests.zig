// src/tests.zig
const std = @import("std");
const zigcap = @import("lib.zig");
const print = std.debug.print;
const expect = std.testing.expect;

const RawData = zigcap.RawData;
const Packet = zigcap.Packet.Packet;
const link_layer_type = zigcap.ProtocolEnums.zig.link_layer_type;
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

test "sniff with pcap" {
    //   if (try open_pcap()) |iface| {
    //       iface.capture();
    //   }
    //   const allocator = std.heap.page_allocator;
    //
    //   var interfaces = try PcapWrapper.Interfaces.init(allocator);
    //
    //   const iface = try interfaces.find_by_ip(try IPv4.IPv4Address.init_from_string("192.168.1.225"));
    //
    //   if (iface) |ifc| {
    //       print("found ifc: {any}\n", .{ifc});
    //   } else {
    //       print("failed to find iface.\n", .{});
    //   }
    //
    //   const ifaces: std.ArrayList(PcapWrapper.Interface) = try interfaces.list_all();
    //
    //   print("{any}\n", .{ifaces});
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

test "build eth,ipv4,udp,generic_app packet" {
    const page_allocator = std.heap.page_allocator;

    var backing_buffer: [1024]u8 = undefined;

    var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);

    const allocator = fba.allocator();

    var eth_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    defer eth_layer_owner.owned_buffer.buffer.deinit(allocator);

    var eth_layer_iface: LayerIface = try LayerIface.init(Eth.EthLayer, (eth_layer_owner));

    eth_layer_iface.ethLayer.set_eth_type(Eth.EthType.IP);

    try expect(try eth_layer_iface.ethLayer.get_eth_type() == Eth.EthType.IP);

    eth_layer_iface.ethLayer.set_dst_mac(try Eth.MacAddress.init_from_string("1A:2A:3A:4A:5A:6A"));

    eth_layer_iface.ethLayer.set_src_mac(try Eth.MacAddress.init_from_string("1B:2B:3B:4B:5B:6B"));

    //    print("{s}\n", .{eth_layer_iface.ethLayer.to_string(page_allocator)});

    var ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    defer ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);

    var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);

    ipv4_layer_iface.ipv4Layer.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));

    ipv4_layer_iface.ipv4Layer.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.2"));

    ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);

    ipv4_layer_iface.ipv4Layer.set_ttl(64);

    //    print("{s}\n", .{ipv4_layer_iface.to_string(std.heap.page_allocator)});

    var udp_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    defer udp_layer_owner.owned_buffer.buffer.deinit(allocator);

    var udp_layer_iface: LayerIface = try LayerIface.init(UDP.UDPLayer, udp_layer_owner);

    _ = &udp_layer_iface;

    udp_layer_iface.udpLayer.set_src_port(1024);
    udp_layer_iface.udpLayer.set_dst_port(53);

    //   print("{s}\n", .{udp_layer_iface.to_string(std.heap.page_allocator)});

    var app_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    defer app_layer_owner.owned_buffer.buffer.deinit(allocator);

    var app_layer_iface: LayerIface = try LayerIface.init(ApplicationLayer, app_layer_owner);

    try app_layer_iface.genericAppLayer.set_payload("hello");

    //  print("app layer data: {s}\n", .{app_layer_iface.to_string(page_allocator)});

    try app_layer_iface.genericAppLayer.delete_payload_data();

    var packet = try Packet.create(allocator, allocator);

    defer packet.deinit();

    try expect(try packet.add_layer(&eth_layer_iface));
    try expect(try packet.add_layer(&ipv4_layer_iface));
    try expect(try packet.add_layer(&udp_layer_iface));
    try expect(try packet.add_layer(&app_layer_iface));

    try packet.to_string(page_allocator);

    if (packet.get_layer_of_type(Eth.EthLayer)) |eth| {
        eth.set_eth_type(Eth.EthType.ARP);
    }

    if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4| {
        ipv4.set_ttl(128);
        ipv4.calculate_length();
    }

    if (packet.get_layer_of_type(ApplicationLayer)) |app| {
        try app.set_payload("hello new world");

        //        print("{s}\n", .{app.to_string(page_allocator)});
    }

    try packet.to_string(page_allocator);

    if (try packet.search_layers(tcp_ip_protocol.ipv4)) |ipv4| {
        var new_ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
        defer new_ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);
        var ip_layer = try packet.extract_layer(ipv4, &new_ipv4_layer_owner) orelse {
            print("failed to extract ip layer.\n", .{});
            return;
        };

        print("extracted ipv4 layer: {x}\n", .{ip_layer.get_data()});

        //       const ipv4_slice = new_ipv4_layer_owner.owned_buffer.buffer.items;
        //
        //       //const aligned_slice: []align(2) u8 = try allocator.alignedAlloc(u8, std.mem.Alignment.of(IPv4.IPv4Header), ipv4_slice.len);
        //
        //       const aligned_slice: []align(2) u8 = try allocator.alignedAlloc(u8, std.mem.Alignment.@"2", ipv4_slice.len);
        //
        //       @memmove(aligned_slice, ipv4_slice);
        //
        //       print("{x} ({})\n", .{ aligned_slice, aligned_slice.len });
        //
        //       const ipv4_hdr_alignment: usize = @alignOf(IPv4.IPv4Header);
        //
        //       print("ipv4 hdr alignment: {}\n", .{ipv4_hdr_alignment});
        //
        //       print("eth hdr alignment: {}\n", .{@alignOf(Eth.EthHeader)});
        //
        //       //        var aligned_ipv4: std.array_list.Aligned(u8, std.mem.Alignment.of(IPv4.IPv4Header)) = .fromOwnedSlice(aligned_slice);
        //
        //       var aligned_ipv4: std.array_list.Aligned(u8, std.mem.Alignment.@"2") = .fromOwnedSlice(aligned_slice);
        //
        //       _ = &aligned_ipv4;
        //
        //       const alignment = alignment_check(aligned_slice, ipv4_hdr_alignment);
        //
        //       print("alignment: {}\n", .{alignment});
        //
        //       const aligned_ptr: [*]align(@alignOf(IPv4.IPv4Header)) u8 = @alignCast(aligned_ipv4.items.ptr);
        //       const ipv4_hdr: *IPv4.IPv4Header = @ptrCast(aligned_ptr);
        //
        //       print("{any}\n", .{ipv4_hdr});

        //const end_index = fba.end_index;

        //print("Backing buffer: {x}\n", .{backing_buffer[0..end_index]});

        //        _ = ip_layer.ipv4Layer.get_dst_ip();

        ip_layer.ipv4Layer.set_ip_proto(IPProtocol.UDP);

        print("extracted: {s}\n", .{ip_layer.to_string(page_allocator)});

        const eth = try packet.search_layers(tcp_ip_protocol.eth) orelse {
            print("could not find eth layer.\n", .{});
            return;
        };
        try expect(try eth.layer_iface.get_protocol() == tcp_ip_protocol.eth);
        try expect(try packet.insert_layer(eth, &ip_layer));
    }

    packet.print_layers_meta();

    print("({}) {x}\n", .{ packet.buffer.buffer.items.len, packet.buffer.buffer.items });
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

    packet.print_layers_meta();

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
