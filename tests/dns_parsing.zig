const std = @import("std");
const expect = std.testing.expect;
const zigcap = @import("zigcap");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const DNS = zigcap.DNS;
const Packet = zigcap.Packet.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const LayerOwner = zigcap.Layer.LayerOwner;
const LayerIface = zigcap.LayerIface;

fn add_query(domain: []const u8, dns_layer_iface: *LayerIface) !void {
    try dns_layer_iface.dnsLayer.add_query(domain, DNS.QueryType.A, DNS.DnsClass.IN);
}

test "build dns query layer" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const tmp_buf: LayerOwner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    var dns_layer_iface = try LayerIface.init(DNS.DNSLayer, tmp_buf);
    defer dns_layer_iface.deinit();

    const ziggit_dev_domain: []const u8 = "ziggit.dev";
    const ziggit_net_domain: []const u8 = "ziggit.net";
    const ziggit_org_domain: []const u8 = "ziggit.org";

    try add_query(ziggit_dev_domain, &dns_layer_iface);
    try add_query(ziggit_net_domain, &dns_layer_iface);
    try add_query(ziggit_org_domain, &dns_layer_iface);

    var q_list = try dns_layer_iface.dnsLayer.get_queries(allocator) orelse {
        try expect(false); // no dns queries
        return;
    };

    defer q_list.deinit(allocator);

    var query_for_remove: ?*DNS.Query = null;

    var q = q_list.first;
    while (q) |query| {
        //        print("{} {} ", .{ query.qtype, query.qclass });
        const qname = try query.decode_qname(allocator);
        defer allocator.free(qname);
        //       print("{s}\n", .{qname});

        if (std.mem.eql(u8, ziggit_net_domain, qname)) {
            query_for_remove = query;
        }
        q = query.next_query;
    }

    //  print("pre remove: {}\n", .{dns_layer_iface.get_data().len});

    if (query_for_remove) |query| {
        try dns_layer_iface.dnsLayer.remove_query(query);
    }

    // print("post remove: {}\n", .{dns_layer_iface.get_data().len});
}

test "parse dns response layer" {
    const dns_a_resp: [135]u8 align(2) = [_]u8{ 0xfa, 0x60, 0x81, 0x80, 0x0, 0x1, 0x0, 0x6, 0x0, 0x0, 0x0, 0x1, 0x6, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x8b, 0x0, 0x4, 0x8e, 0xfa, 0x97, 0x8b, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x8b, 0x0, 0x4, 0x8e, 0xfa, 0x97, 0x71, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x8b, 0x0, 0x4, 0x8e, 0xfa, 0x97, 0x66, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x8b, 0x0, 0x4, 0x8e, 0xfa, 0x97, 0x65, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x8b, 0x0, 0x4, 0x8e, 0xfa, 0x97, 0x64, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x8b, 0x0, 0x4, 0x8e, 0xfa, 0x97, 0x8a, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const dns_buf = try allocator.alignedAlloc(u8, std.mem.Alignment.@"2", dns_a_resp.len);
    @memmove(dns_buf, dns_a_resp[0..]);

    const dns_owner: LayerOwner = LayerOwner{ .owned_buffer = try .init(dns_buf, allocator) };

    var dns_layer = try LayerIface.init(DNS.DNSLayer, dns_owner);
    defer dns_layer.deinit();

    //   if (try dns_layer.dnsLayer.find_last_q_offset()) |offset| {
    //       print("last query offset: {}\n", .{offset});
    //   } else {
    //       print("failed to find last query offset.\n", .{});
    //       return;
    //   }

    var q_list = try dns_layer.dnsLayer.get_queries(allocator) orelse {
        try expect(false); // no dns quuries
        return;
    };

    defer q_list.deinit(allocator);

    var q = q_list.first;
    while (q) |query| {
        //    print("{} {} ", .{ query.qtype, query.qclass });
        const qname = try query.decode_qname(allocator);
        defer allocator.free(qname);
        //   print("{s}\n", .{qname});
        q = query.next_query;
    }

    var ans_list = try dns_layer.dnsLayer.get_answers(allocator) orelse {
        try expect(false); // no dns answers
        return;
    };

    defer ans_list.deinit(allocator);

    var cur: ?*DNS.AnswerRecord = ans_list.first;
    while (cur) |ans| {
        const name = try ans.get_name(allocator);
        defer allocator.free(name);
        //       print("{s} {any} {any} ", .{ name, ans.get_rr_type(), ans.get_class_type() });

        if (ans.get_rr_type() == DNS.QueryType.A) {
            const ip = ans.a.get_ip() orelse {
                //              print("(no ip)\n", .{});
                cur = ans.get_next_record();
                continue;
            };

            const ip_str = try ip.to_string(allocator);
            defer allocator.free(ip_str);
            //         print("{s}\n", .{ip_str});
        }
        cur = ans.get_next_record();
    }
}

test "parse dns response" {
    const dns_ns_response: [173]u8 = [_]u8{ 0x3a, 0xc2, 0x81, 0x80, 0x0, 0x1, 0x0, 0x4, 0x0, 0x0, 0x0, 0x1, 0xf, 0x73, 0x6f, 0x75, 0x74, 0x68, 0x77, 0x65, 0x73, 0x74, 0x2d, 0x73, 0x69, 0x74, 0x65, 0x73, 0x2, 0x63, 0x6f, 0x2, 0x75, 0x6b, 0x0, 0x0, 0x2, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x2, 0x0, 0x1, 0x0, 0x0, 0x3, 0x45, 0x0, 0x13, 0x6, 0x6e, 0x73, 0x31, 0x30, 0x38, 0x33, 0x6, 0x75, 0x69, 0x2d, 0x64, 0x6e, 0x73, 0x3, 0x62, 0x69, 0x7a, 0x0, 0xc0, 0xc, 0x0, 0x2, 0x0, 0x1, 0x0, 0x0, 0x3, 0x45, 0x0, 0x13, 0x6, 0x6e, 0x73, 0x31, 0x31, 0x31, 0x30, 0x6, 0x75, 0x69, 0x2d, 0x64, 0x6e, 0x73, 0x3, 0x6f, 0x72, 0x67, 0x0, 0xc0, 0xc, 0x0, 0x2, 0x0, 0x1, 0x0, 0x0, 0x3, 0x45, 0x0, 0x13, 0x6, 0x6e, 0x73, 0x31, 0x30, 0x36, 0x35, 0x6, 0x75, 0x69, 0x2d, 0x64, 0x6e, 0x73, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0xc0, 0xc, 0x0, 0x2, 0x0, 0x1, 0x0, 0x0, 0x3, 0x45, 0x0, 0x12, 0x6, 0x6e, 0x73, 0x31, 0x31, 0x31, 0x32, 0x6, 0x75, 0x69, 0x2d, 0x64, 0x6e, 0x73, 0x2, 0x64, 0x65, 0x0, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const dns_buf = try allocator.alignedAlloc(u8, std.mem.Alignment.@"2", dns_ns_response.len);
    @memmove(dns_buf, dns_ns_response[0..]);

    const dns_owner: LayerOwner = LayerOwner{ .owned_buffer = try .init(dns_buf, allocator) };

    var dns_layer = try LayerIface.init(DNS.DNSLayer, dns_owner);
    defer dns_layer.deinit();

    var ans_list = try dns_layer.dnsLayer.get_answers(allocator) orelse {
        try expect(false); // no dns answers
        return;
    };

    defer ans_list.deinit(allocator);

    var cur: ?*DNS.AnswerRecord = ans_list.first;
    while (cur) |ans| {
        const name = try ans.get_name(allocator);
        defer allocator.free(name);
        print("{s} {any} {any} ", .{ name, ans.get_rr_type(), ans.get_class_type() });

        if (ans.get_rr_type() == DNS.QueryType.NS) {
            const ns = ans.ns.decode_ns_name(allocator) catch {
                print("-", .{});
                cur = ans.get_next_record();
                continue;
            };

            defer allocator.free(ns);

            print("{s}", .{ns});
        }
        print("\n", .{});
        cur = ans.get_next_record();
    }
}
