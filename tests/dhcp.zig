const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const LayerOwner = zigcap.Layer.LayerOwner;
const LayerIface = zigcap.LayerIface;
const DHCP = zigcap.DHCP;
const Eth = zigcap.Eth;
const UDP = zigcap.UDP;
const IPv4 = zigcap.IPv4;
const Packet = zigcap.Packet.Packet;
const IPProtocol = zigcap.ProtocolEnums.IPProtocol;

fn create_random_u32() !u32 {
    var prng: std.Random.DefaultPrng = .init(blk: {
        var seed: u64 = undefined;
        try std.posix.getrandom(std.mem.asBytes(&seed));
        break :blk seed;
    });

    const rand = prng.random();

    const c = rand.int(u32);

    return c;
}

test "build dhcp packet" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;

    const allocator = debug_allocator.allocator();

    var packet = try Packet.create(allocator, allocator);

    const tmp_buf: LayerOwner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    var eth_iface = try LayerIface.init(Eth.EthLayer, tmp_buf);
    defer eth_iface.deinit();
    var eth_hdr = eth_iface.ethLayer.get_mutable_header();
    eth_hdr.set_eth_type(Eth.EthType.IP);
    eth_hdr.set_src_mac(try Eth.MacAddress.init_from_string("00:e0:4c:68:00:6c"));
    eth_hdr.set_dst_mac(try Eth.MacAddress.init_from_string("ff:ff:ff:ff:ff:ff"));

    var ipv4_iface = try LayerIface.init(IPv4.IPv4Layer, tmp_buf);

    ipv4_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);
    defer ipv4_iface.deinit();
    var ipv4_hdr = ipv4_iface.ipv4Layer.get_mutable_header();
    ipv4_hdr.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.0.2"));
    ipv4_hdr.set_dst_ip(try IPv4.IPv4Address.init_from_string("255.255.255.255"));

    var udp_iface = try LayerIface.init(UDP.UDPLayer, tmp_buf);
    defer udp_iface.deinit();
    var udp_hdr = udp_iface.udpLayer.get_mutable_header();
    udp_hdr.set_dst_port(67);
    udp_hdr.set_src_port(68);

    var dhcp_layer_iface = try LayerIface.init(DHCP.DHCPLayer, tmp_buf);

    defer dhcp_layer_iface.deinit();

    const dhcp_hdr: *DHCP.DHCPHeader = dhcp_layer_iface.dhcpLayer.get_mutable_header();

    dhcp_hdr.set_op(DHCP.OPCode.BootRequest);
    dhcp_hdr.set_htype(DHCP.HWTYPE.Eth);
    dhcp_hdr.set_xid(try create_random_u32());

    dhcp_hdr.set_ciaddr(try IPv4.IPv4Address.init_from_string("192.168.0.2"));

    dhcp_hdr.set_chaddr(try Eth.MacAddress.init_from_string("00:e0:4c:68:00:6c"));

    print("dhcp data: {x}\n", .{dhcp_layer_iface.get_data()});

    const req = DHCP.OptionValues{ .msgType = .DHCPREQUEST };

    try dhcp_layer_iface.dhcpLayer.add_option(DHCP.Option.DHCPMessageType, req);

    //    const opts = std.enums.values(DHCP.Option);

    const ops = [_]DHCP.Option{DHCP.Option.DomainName};

    try dhcp_layer_iface.dhcpLayer.set_parameter_request_list(&ops);

    try dhcp_layer_iface.dhcpLayer.remove_param_option(DHCP.Option.DomainName);

    dhcp_layer_iface.dhcpLayer.print_all_opts();

    _ = try packet.add_layer(&eth_iface);
    _ = try packet.add_layer(&ipv4_iface);
    _ = try packet.add_layer(&udp_iface);
    _ = try packet.add_layer(&dhcp_layer_iface);

    packet.print_layers_meta();

    packet.validate_packet();

    print("{x}\n", .{packet.get_raw()});

    packet.print_layers_meta();

    if (packet.get_layer_of_type(DHCP.DHCPLayer)) |dhcp_layer| {
        if (dhcp_layer.eop_added()) |eop| {
            print("eop found: {}\n", .{eop});

            try dhcp_layer.set_parameter_request_list(&ops);

            //try dhcp_layer.remove_param_option(DHCP.Option.DomainName);
        } else {
            print("no eop.\n", .{});
        }
    } else {
        print("NO DHCP LAYER.\n", .{});
    }

    packet.print_layers_meta();
}

test "parse dhcp layer" {
    //   const dhcp_req_raw: [316]u8 = [_]u8{ 0x1, 0x1, 0x6, 0x0, 0xfd, 0xef, 0xab, 0x7d, 0x0, 0x0, 0x0, 0x0, 0xc0, 0xa8, 0x1, 0xe1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x63, 0x82, 0x53, 0x63, 0x35, 0x1, 0x3, 0x3d, 0x7, 0x1, 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0xc, 0xf, 0x44, 0x45, 0x53, 0x4b, 0x54, 0x4f, 0x50, 0x2d, 0x35, 0x4c, 0x36, 0x55, 0x41, 0x31, 0x34, 0x51, 0x12, 0x0, 0x0, 0x0, 0x44, 0x45, 0x53, 0x4b, 0x54, 0x4f, 0x50, 0x2d, 0x35, 0x4c, 0x36, 0x55, 0x41, 0x31, 0x34, 0x3c, 0x8, 0x4d, 0x53, 0x46, 0x54, 0x20, 0x35, 0x2e, 0x30, 0x37, 0xe, 0x1, 0x3, 0x6, 0xf, 0x1f, 0x21, 0x2b, 0x2c, 0x2e, 0x2f, 0x77, 0x79, 0xf9, 0xfc, 0xff };
    //
    //   var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    //   defer _ = debug_allocator.deinit();
    //
    //   const allocator = debug_allocator.allocator();
    //
    //   const dhcp_buf = try allocator.alignedAlloc(u8, std.mem.Alignment.@"2", dhcp_req_raw.len);
    //   @memmove(dhcp_buf, dhcp_req_raw[0..]);
    //
    //   const dhcp_owner: LayerOwner = LayerOwner{ .owned_buffer = try .init(dhcp_buf, allocator) };
    //
    //   var dhcp_layer_iface: LayerIface = try LayerIface.init(DHCP.DHCPLayer, dhcp_owner);
    //   defer dhcp_layer_iface.deinit();
    //
    //   const dhcp_hdr: *DHCP.DHCPHeader = dhcp_layer_iface.dhcpLayer.get_mutable_header();
    //
    //   const y_ip = try dhcp_hdr.get_yiaddr().to_string(allocator);
    //   defer allocator.free(y_ip);
    //
    //   const ci_ip = try dhcp_hdr.get_ciaddr().to_string(allocator);
    //   defer allocator.free(ci_ip);
    //
    //   const si_ip = try dhcp_hdr.get_siaddr().to_string(allocator);
    //   defer allocator.free(si_ip);
    //
    //   const str = dhcp_layer_iface.to_string(allocator);
    //   defer allocator.free(str);
    //
    //   if (dhcp_layer_iface.dhcpLayer.find_op(DHCP.Option.Router)) |op_offset| {
    //       print("router offset: {}\n", .{op_offset});
    //   } else {
    //       print("no router offset found.\n", .{});
    //   }
    //
    //   dhcp_layer_iface.dhcpLayer.print_all_opts();
}
