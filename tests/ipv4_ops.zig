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

    var opt = IPv4.IPv4Option.init(IPv4.IPOptionType.RecordRoute, tlv_owner, 3, null, null);
    defer opt.deinit();

    try opt.record_route.add_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));
    try opt.record_route.add_ip(try IPv4.IPv4Address.init_from_string("10.1.1.1"));
    try opt.record_route.add_ip(try IPv4.IPv4Address.init_from_string("172.78.9.3"));

    const ips = try opt.record_route.get_ip_list(allocator) orelse {
        try expect(false); // no ips found
        return;
    };

    defer allocator.free(ips);

    try expect(opt.record_route.get_ip_count() == 3);

    try expect(opt.record_route.get_ip_count() == ips.len);

    try opt.record_route.remove_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));

    const ip_list = try opt.record_route.get_ip_list(allocator) orelse {
        try expect(false); // ip list not found
        return;
    };

    defer allocator.free(ip_list);

    for (ip_list) |ip| {
        const str = try ip.to_string(allocator);
        allocator.free(str);
    }

    var ipv4_layer: IPv4.IPv4Layer = try IPv4.IPv4Layer.init(tmp_owner);
    defer ipv4_layer.deinit();

    try ipv4_layer.add_option(&opt);

    var cur: ?*IPv4.IPv4Option = try ipv4_layer.get_ip_opts(allocator);

    var count: usize = 0;
    while (cur) |option| {
        count += 1;
        const prev = option.get_prev();
        try expect(option.get_opt_type() == IPv4.IPOptionType.RecordRoute);
        allocator.destroy(option);
        cur = prev;
    }

    try expect(count == 1);

    try expect(ipv4_layer.get_data().len == 32);
}

test "build lsr opt" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const tmp_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    const tlv_owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };

    var opt = IPv4.IPv4Option.init(IPv4.IPOptionType.LooseSourceRoute, tlv_owner, 3, null, null);
    defer opt.deinit();

    try opt.loose_route.add_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));
    try opt.loose_route.add_ip(try IPv4.IPv4Address.init_from_string("10.1.1.1"));
    try opt.loose_route.add_ip(try IPv4.IPv4Address.init_from_string("172.78.9.3"));

    const ips = try opt.loose_route.get_ip_list(allocator) orelse {
        try expect(false); // no ips found
        return;
    };

    defer allocator.free(ips);

    try expect(opt.loose_route.get_ip_count() == 3);

    try expect(opt.loose_route.get_ip_count() == ips.len);

    try opt.loose_route.remove_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));

    const ip_list = try opt.loose_route.get_ip_list(allocator) orelse {
        try expect(false); // ip list not found
        return;
    };

    defer allocator.free(ip_list);

    for (ip_list) |ip| {
        const str = try ip.to_string(allocator);
        allocator.free(str);
    }

    var ipv4_layer: IPv4.IPv4Layer = try IPv4.IPv4Layer.init(tmp_owner);
    defer ipv4_layer.deinit();

    try ipv4_layer.add_option(&opt);

    var cur: ?*IPv4.IPv4Option = try ipv4_layer.get_ip_opts(allocator);

    var count: usize = 0;
    while (cur) |option| {
        count += 1;
        const prev = option.get_prev();
        try expect(option.get_opt_type() == IPv4.IPOptionType.LooseSourceRoute);
        allocator.destroy(option);
        cur = prev;
    }

    try expect(count == 1);

    try expect(ipv4_layer.get_data().len == 32);
}

test "build ssr opt" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const tmp_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    const tlv_owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };

    var opt = IPv4.IPv4Option.init(IPv4.IPOptionType.StrictSourceRoute, tlv_owner, 3, null, null);
    defer opt.deinit();

    try opt.strict_route.add_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));
    try opt.strict_route.add_ip(try IPv4.IPv4Address.init_from_string("10.1.1.1"));
    try opt.strict_route.add_ip(try IPv4.IPv4Address.init_from_string("172.78.9.3"));

    const ips = try opt.strict_route.get_ip_list(allocator) orelse {
        try expect(false); // no ips found
        return;
    };

    defer allocator.free(ips);

    try expect(opt.strict_route.get_ip_count() == 3);

    try expect(opt.strict_route.get_ip_count() == ips.len);

    try opt.strict_route.remove_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));

    const ip_list = try opt.strict_route.get_ip_list(allocator) orelse {
        try expect(false); // ip list not found
        return;
    };

    defer allocator.free(ip_list);

    for (ip_list) |ip| {
        const str = try ip.to_string(allocator);
        allocator.free(str);
    }

    var ipv4_layer: IPv4.IPv4Layer = try IPv4.IPv4Layer.init(tmp_owner);
    defer ipv4_layer.deinit();

    try ipv4_layer.add_option(&opt);

    var cur: ?*IPv4.IPv4Option = try ipv4_layer.get_ip_opts(allocator);

    var count: usize = 0;
    while (cur) |option| {
        count += 1;
        const prev = option.get_prev();
        try expect(option.get_opt_type() == IPv4.IPOptionType.StrictSourceRoute);
        allocator.destroy(option);
        cur = prev;
    }

    try expect(count == 1);

    try expect(ipv4_layer.get_data().len == 32);
}

test "build ra opt" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const tlv_owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };
    var tmp_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    defer tmp_owner.deinit();

    var opt = IPv4.IPv4Option.init(IPv4.IPOptionType.RouterAlert, tlv_owner, 4, null, null);
    defer opt.deinit();

    try opt.router_alert.set_ra_val(0x0000);

    var ipv4_layer: IPv4.IPv4Layer = try IPv4.IPv4Layer.init(tmp_owner);
    defer ipv4_layer.deinit();

    try ipv4_layer.add_option(&opt);

    var ra_opt = ipv4_layer.get_first_op() orelse {
        try expect(false);
        return;
    };

    try ra_opt.router_alert.set_ra_val(0x4321);
}
