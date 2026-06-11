const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const Packet = zigcap.Packet.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const LayerOwner = zigcap.Owner.LayerOwner;
const LayerIface = zigcap.LayerIface;
const ARP = zigcap.ARP;
const IPv4 = zigcap.IPv4;
const Eth = zigcap.Eth;
const UDP = zigcap.UDP;
const ApplicationLayer = zigcap.ApplicationLayer;
const IPProtocol = zigcap.ProtocolEnums.IPProtocol;
const tcp_ip_protocol = zigcap.tcp_ip_protocol;

const samples = @import("capture_samples.zig");

test "build arp request packet" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    var arp_layer_iface = try LayerIface.init(ARP.ARPLayer, owner);
    defer arp_layer_iface.deinit();

    arp_layer_iface.arpLayer.set_sender_ip(try IPv4.IPv4Address.init_from_string("192.168.1.225"));
    arp_layer_iface.arpLayer.set_target_ip(try IPv4.IPv4Address.init_from_string("192.168.1.254"));

    arp_layer_iface.arpLayer.set_sender_mac(try Eth.MacAddress.init_from_string("14:4F:8A:A4:15:7D"));
    arp_layer_iface.arpLayer.set_target_mac(try Eth.MacAddress.init_from_string("FF:FF:FF:FF:FF:FF"));

    arp_layer_iface.arpLayer.set_opcode(ARP.ARPOpcode.Request);

    var arp_hdr = arp_layer_iface.arpLayer.get_mutable_header();

    arp_hdr.set_hardware_type(ARP.HWTYPE.Eth);
    arp_hdr.set_protocol_type(ARP.PTYPE.IP);
    //   arp_hdr.set_hardware_size(6);
    //   arp_hdr.set_protocol_size(4);

    var eth_layer_iface: LayerIface = try LayerIface.init(Eth.EthLayer, owner);
    defer eth_layer_iface.deinit();

    var eth_hdr = eth_layer_iface.ethLayer.get_mutable_header();

    eth_hdr.set_eth_type(Eth.EthType.ARP);

    try expect(eth_hdr.get_eth_type() == Eth.EthType.ARP);

    eth_hdr.set_dst_mac(try Eth.MacAddress.init_from_string("FF:FF:FF:FF:FF:FF"));

    eth_hdr.set_src_mac(try Eth.MacAddress.init_from_string("14:4F:8A:A4:15:7D"));

    var packet = Packet.create(allocator, allocator);
    defer packet.deinit();

    _ = try packet.add_layer(&eth_layer_iface);

    _ = try packet.add_layer(&arp_layer_iface);

    ////packet.print_layers_meta();

    //    try send_packet(packet.buffer.buffer.items);
}

test "build arp reply packet" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    var arp_layer_iface = try LayerIface.init(ARP.ARPLayer, owner);
    defer arp_layer_iface.deinit();

    arp_layer_iface.arpLayer.set_sender_ip(try IPv4.IPv4Address.init_from_string("192.168.1.225"));
    arp_layer_iface.arpLayer.set_target_ip(try IPv4.IPv4Address.init_from_string("192.168.1.254"));

    arp_layer_iface.arpLayer.set_sender_mac(try Eth.MacAddress.init_from_string("14:4F:8A:A4:15:7D"));
    arp_layer_iface.arpLayer.set_target_mac(try Eth.MacAddress.init_from_string("38:06:e6:92:63:ac"));

    arp_layer_iface.arpLayer.set_opcode(ARP.ARPOpcode.Reply);

    var arp_hdr = arp_layer_iface.arpLayer.get_mutable_header();

    arp_hdr.set_hardware_type(ARP.HWTYPE.Eth);
    arp_hdr.set_protocol_type(ARP.PTYPE.IP);
    arp_hdr.set_hardware_size(6);
    arp_hdr.set_protocol_size(4);

    var eth_layer_iface: LayerIface = try LayerIface.init(Eth.EthLayer, owner);
    defer eth_layer_iface.deinit();

    var eth_hdr = eth_layer_iface.ethLayer.get_mutable_header();

    eth_hdr.set_eth_type(Eth.EthType.ARP);

    try expect(eth_hdr.get_eth_type() == Eth.EthType.ARP);

    eth_hdr.set_dst_mac(try Eth.MacAddress.init_from_string("38:06:e6:92:63:ac"));

    eth_hdr.set_src_mac(try Eth.MacAddress.init_from_string("14:4F:8A:A4:15:7D"));

    var packet = Packet.create(allocator, allocator);
    defer packet.deinit();

    _ = try packet.add_layer(&eth_layer_iface);

    _ = try packet.add_layer(&arp_layer_iface);

    //   print("size of LayerIface: {}\n", .{@sizeOf(LayerIface)});
    //   print("size of LayerInterface: {}\n", .{@sizeOf(LayerInterface)});
    //   print("size of Layer: {}\n", .{@sizeOf(Layer)});

    ////packet.print_layers_meta();

    //try send_packet(packet.buffer.buffer.items);
}

test "IPv4 Packet Router Alert option" {
    //   print("========================== START ==========================\n", .{});
    //   print("ipv4 layer in complete packet with Router Alert option\n", .{});
    var backing_buffer: [1024]u8 = undefined;

    var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);

    const allocator = fba.allocator();

    var ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    defer ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);

    var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);

    var ipv4_hdr = ipv4_layer_iface.ipv4Layer.get_mutable_header();

    ipv4_hdr.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.225"));

    ipv4_hdr.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.254"));

    ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);

    ipv4_hdr.set_ttl(1);

    var router_alert_op: [2]u8  = [_]u8{ 0x00, 0x00 };

    const op = try IPv4.IPOption.init(IPv4.IPOptionType.RouterAlert, &router_alert_op);

    const op_bytes = try op.toBytes(allocator);

    try expect(op_bytes[0] == 0x94);
    try expect(op_bytes[1] == 0x04);
    try expect(op_bytes[2] == 0x00);
    try expect(op_bytes[3] == 0x00);

    var packet = Packet.create(allocator, allocator);

    const eth_layer_owner = LayerOwner{ .owned_buffer = .init_empty(std.heap.page_allocator) };

    var eth_layer_iface: LayerIface = try LayerIface.init(Eth.EthLayer, eth_layer_owner); // making a copy of owner?

    var eth_hdr = eth_layer_iface.ethLayer.get_mutable_header();

    eth_hdr.set_eth_type(Eth.EthType.IP);

    try expect(eth_hdr.get_eth_type() == Eth.EthType.IP);

    eth_hdr.set_dst_mac(try Eth.MacAddress.init_from_string("38:06:e6:92:63:ac"));

    eth_hdr.set_src_mac(try Eth.MacAddress.init_from_string("14:4f:8a:a4:15:7d"));

    var udp_layer_owner = LayerOwner{ .owned_buffer = .init_empty(std.heap.page_allocator) };

    defer udp_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);

    var udp_layer_iface: LayerIface = try LayerIface.init(UDP.UDPLayer, udp_layer_owner);

    var udp_hdr = udp_layer_iface.udpLayer.get_mutable_header();

    udp_hdr.set_src_port(1024);
    udp_hdr.set_dst_port(5005);

    const page_allocator = std.heap.page_allocator;
    var app_layer_owner = LayerOwner{ .owned_buffer = .init_empty(page_allocator) };

    defer app_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);

    var app_layer_iface: LayerIface = try LayerIface.init(ApplicationLayer, app_layer_owner);

    try app_layer_iface.genericAppLayer.set_payload("hello");

    try expect(try packet.add_layer(&eth_layer_iface));

    try expect(try packet.add_layer(&ipv4_layer_iface));

    try expect(try packet.add_layer(&udp_layer_iface));

    try expect(try packet.add_layer(&app_layer_iface));

    var pkt_data = packet.buffer.buffer.items;

    //packet.print_layers_meta();

    if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4_layer| {
        try ipv4_layer.add_option(op, allocator);

        //packet.print_layers_meta();

        pkt_data = packet.buffer.buffer.items;
    }

    pkt_data = packet.buffer.buffer.items;

    //packet.print_layers_meta();

    if (packet.get_layer_of_type(UDP.UDPLayer)) |udp| {
        udp.validate_layer();
    }

    if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4| {
        ipv4.validate_layer();
    }

    //   print("========================== END ==========================\n", .{});
}

test "build ipv4 packet with Record Route option" {
    //  print("========================== START ==========================\n", .{});
    //  print("build ipv4 packet with Record Route option\n", .{});
    var backing_buffer: [1024]u8 = undefined;

    var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);

    const allocator = fba.allocator();

    var ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    defer ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);

    var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);

    var ipv4_hdr = ipv4_layer_iface.ipv4Layer.get_mutable_header();

    ipv4_hdr.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.225"));

    ipv4_hdr.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.254"));

    ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);

    ipv4_hdr.set_ttl(64);

    var record_route_op: [15]u8  = [_]u8{
        0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    };

    var op = try IPv4.IPOption.init(IPv4.IPOptionType.RecordRoute, &record_route_op);

    op.set_len(15);

    var packet = Packet.create(allocator, allocator);

    const eth_layer_owner = LayerOwner{ .owned_buffer = .init_empty(std.heap.page_allocator) };

    var eth_layer_iface: LayerIface = try LayerIface.init(Eth.EthLayer, eth_layer_owner); // making a copy of owner?

    var eth_hdr = eth_layer_iface.ethLayer.get_mutable_header();

    eth_hdr.set_eth_type(Eth.EthType.IP);

    try expect(eth_hdr.get_eth_type() == Eth.EthType.IP);

    eth_hdr.set_dst_mac(try Eth.MacAddress.init_from_string("38:06:e6:92:63:ac"));

    eth_hdr.set_src_mac(try Eth.MacAddress.init_from_string("14:4f:8a:a4:15:7d"));

    var udp_layer_owner = LayerOwner{ .owned_buffer = .init_empty(std.heap.page_allocator) };

    defer udp_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);

    var udp_layer_iface: LayerIface = try LayerIface.init(UDP.UDPLayer, udp_layer_owner);

    var udp_hdr = udp_layer_iface.udpLayer.get_mutable_header();

    udp_hdr.set_src_port(1024);
    udp_hdr.set_dst_port(5005);

    const page_allocator = std.heap.page_allocator;
    var app_layer_owner = LayerOwner{ .owned_buffer = .init_empty(page_allocator) };

    defer app_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);

    var app_layer_iface: LayerIface = try LayerIface.init(ApplicationLayer, app_layer_owner);

    try app_layer_iface.genericAppLayer.set_payload("hello");

    try expect(try packet.add_layer(&eth_layer_iface));

    try expect(try packet.add_layer(&ipv4_layer_iface));

    try expect(try packet.add_layer(&udp_layer_iface));

    try expect(try packet.add_layer(&app_layer_iface));

    var pkt_data = packet.buffer.buffer.items;

    pkt_data = packet.buffer.buffer.items;

    if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4| {
        try ipv4.add_option(op, allocator);
    }

    if (packet.get_layer_of_type(UDP.UDPLayer)) |udp| {
        udp.validate_layer();
    }

    if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4| {
        ipv4.validate_layer();
    }

    pkt_data = packet.buffer.buffer.items;

    if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4| {
        _ = ipv4;
    }

    //if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4| {
    //    try ipv4.zero_hdr(); // not valid
    //} else {
    //    print("ipv4 layer not found.\n", .{});
    //}

    pkt_data = packet.buffer.buffer.items;

    //    print("========================== END ==========================\n", .{});
}

test "build eth,ipv4,udp,generic_app packet" {
    //   print("========================== START ==========================\n", .{});
    //   print("build eth,ipv4,udp,generic_app packet\n", .{});

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var eth_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    defer eth_layer_owner.owned_buffer.buffer.deinit(allocator);

    var eth_layer_iface: LayerIface = try LayerIface.init(Eth.EthLayer, (eth_layer_owner));
    defer eth_layer_iface.deinit();

    var eth_hdr = eth_layer_iface.ethLayer.get_mutable_header();

    eth_hdr.set_eth_type(Eth.EthType.IP);

    try expect(eth_hdr.get_eth_type() == Eth.EthType.IP);

    eth_hdr.set_dst_mac(try Eth.MacAddress.init_from_string("38:06:e6:92:63:ac"));

    eth_hdr.set_src_mac(try Eth.MacAddress.init_from_string("14:4f:8a:a4:15:7d"));

    var ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    defer ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);

    var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, eth_layer_owner);
    defer ipv4_layer_iface.deinit();

    var ipv4_hdr = ipv4_layer_iface.ipv4Layer.get_mutable_header();

    ipv4_hdr.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.225"));

    ipv4_hdr.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.254"));

    ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);

    ipv4_hdr.set_ttl(64);

    var udp_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    defer udp_layer_owner.owned_buffer.buffer.deinit(allocator);

    var udp_layer_iface: LayerIface = try LayerIface.init(UDP.UDPLayer, eth_layer_owner);
    defer udp_layer_iface.deinit();

    var udp_hdr = udp_layer_iface.udpLayer.get_mutable_header();

    udp_hdr.set_src_port(1024);
    udp_hdr.set_dst_port(5005);

    var app_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    defer app_layer_owner.owned_buffer.buffer.deinit(allocator);

    var app_layer_iface: LayerIface = try LayerIface.init(ApplicationLayer, eth_layer_owner);
    defer app_layer_iface.deinit();

    try app_layer_iface.genericAppLayer.set_payload("hello");

    try app_layer_iface.genericAppLayer.delete_payload_data();

    var packet = Packet.create(allocator, allocator);
    defer packet.deinit();

    try expect(try packet.add_layer(&eth_layer_iface));
    try expect(try packet.add_layer(&ipv4_layer_iface));
    try expect(try packet.add_layer(&udp_layer_iface));
    try expect(try packet.add_layer(&app_layer_iface));

    if (packet.get_layer_of_type(Eth.EthLayer)) |eth| {
        var hdr = eth.get_mutable_header();
        hdr.set_eth_type(Eth.EthType.ARP);
    }

    if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4| {
        ipv4.get_mutable_header().set_ttl(128);
        ipv4.calculate_length();
    }

    if (packet.get_layer_of_type(ApplicationLayer)) |app| {
        try app.set_payload("hello new world");
    }

    if (packet.search_layers(tcp_ip_protocol.ipv4)) |ipv4| {
        var new_ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
        defer new_ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);
        var ip_layer = try packet.extract_layer(ipv4, &eth_layer_owner) orelse {
            print("failed to extract ip layer.\n", .{});
            return;
        };

        ip_layer.ipv4Layer.set_ip_proto(IPProtocol.UDP);

        const eth = packet.search_layers(tcp_ip_protocol.eth) orelse {
            print("could not find eth layer.\n", .{});
            return;
        };
        try expect(eth.layer_iface.get_protocol() == tcp_ip_protocol.eth);
        try expect(try packet.insert_layer(eth, &ip_layer));
    }

    if (packet.get_layer_of_type(Eth.EthLayer)) |eth| {
        var hdr = eth.get_mutable_header();
        hdr.set_eth_type(Eth.EthType.IP);
    }

    if (packet.get_layer_of_type(UDP.UDPLayer)) |udp| {
        udp.validate_layer();
    }

    if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4| {
        ipv4.validate_layer();
    }

    //   print("========================== END ==========================\n", .{});
}
