const std = @import("std");
const zigcap = @import("zigcap");

const print = std.debug.print;
const expect = std.testing.expect;

const Packet = zigcap.Packet.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const LayerOwner = zigcap.Layer.LayerOwner;
const TLVOwner = zigcap.Layer.TLVOwner;
const LayerIface = zigcap.LayerIface;
const ARP = zigcap.ARP;
const IPv4 = zigcap.IPv4;

const Eth = zigcap.Eth;
const IPProtocol = zigcap.ProtocolEnums.IPProtocol;

test "build rr opt" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const tmp_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    const tlv_owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };

    var opt = IPv4.IPv4Options.IPv4Options.init(IPv4.IPOptionType.StrictSourceRoute, tlv_owner, 3, null, null);
    defer opt.deinit();

    try opt.strict_route.add_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));
    try opt.strict_route.add_ip(try IPv4.IPv4Address.init_from_string("10.1.1.1"));
    try opt.strict_route.add_ip(try IPv4.IPv4Address.init_from_string("172.78.9.3"));

    const ips = try opt.strict_route.get_ip_list(allocator) orelse {
        //print("no ips.\n", .{});
        return;
    };

    defer allocator.free(ips);

    //print("got {} ips\n", .{ips.len});

    //print("opt: {x}\n", .{opt.strict_route.get_data()});

    //print("ip count: {}\n", .{opt.strict_route.get_ip_count()});

    try opt.strict_route.remove_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));

    const ip_list = try opt.strict_route.get_ip_list(allocator) orelse {
        //print("no ips.\n", .{});
        return;
    };

    defer allocator.free(ip_list);

    for (ip_list) |ip| {
        const str = try ip.to_string(allocator);
        //print("{s}\n", .{str});
        allocator.free(str);
    }

    //print("opt: {x}\n", .{opt.strict_route.get_data()});

    var ipv4_layer: IPv4.IPv4Layer = try IPv4.IPv4Layer.init(tmp_owner);
    defer ipv4_layer.deinit();

    try ipv4_layer.add_option(&opt);

    var cur: ?*IPv4.IPv4Options.IPv4Options = try ipv4_layer.get_ip_opts(allocator);

    var count: usize = 0;
    while (cur) |option| {
        count += 1;
        print("count: {}\n", .{count});
        const prev = option.get_prev();
        print("{any}\n", .{option});
        print("{x}\n", .{option.get_data()});
        allocator.destroy(option);
        cur = prev;
    }

    //print("ipv4: {x}\n", .{ipv4_layer.get_data()});
}

test "build ra opt" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const tlv_owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };
    var tmp_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    defer tmp_owner.deinit();

    var opt = IPv4.IPv4Options.IPv4Options.init(IPv4.IPOptionType.RouterAlert, tlv_owner, 4, null, null);
    defer opt.deinit();

    try opt.router_alert.set_ra_val(0x0000);

    print("op data: {x}\n", .{opt.get_data()});

    var ipv4_layer: IPv4.IPv4Layer = try IPv4.IPv4Layer.init(tmp_owner);
    defer ipv4_layer.deinit();

    try ipv4_layer.add_option(&opt);

    print("ipv4: ({}) {x}\n", .{ ipv4_layer.get_data().len, ipv4_layer.get_data() });

    var ra_opt = ipv4_layer.get_first_op() orelse {
        try expect(false);
        return;
    };

    try ra_opt.router_alert.set_ra_val(0x4321);

    print("ra_opt data: {x}\n", .{ra_opt.get_data()});
}
