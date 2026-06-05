const std = @import("std");
const expect = std.testing.expect;
const zigcap = @import("zigcap");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const DNS = zigcap.DNS;
const IPv4 = zigcap.IPv4;
const Packet = zigcap.Packet.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const LayerOwner = zigcap.Owner.LayerOwner;
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
        const qname = try query.decode_qname(allocator);
        defer allocator.free(qname);

        if (std.mem.eql(u8, ziggit_net_domain, qname)) {
            query_for_remove = query;
        }
        q = query.next_query;
    }

    if (query_for_remove) |query| {
        try dns_layer_iface.dnsLayer.remove_query(query);
    }
}
test "build dns response layer" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const tmp_buf: LayerOwner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    var dns_layer_iface = try LayerIface.init(DNS.DNSLayer, tmp_buf);
    defer dns_layer_iface.deinit();

    const ebay_www_domain: []const u8 = "www.ebay.com";

    try dns_layer_iface.dnsLayer.add_query(ebay_www_domain, DNS.QueryType.A, DNS.DnsClass.IN);

    var q_list = try dns_layer_iface.dnsLayer.get_queries(allocator) orelse {
        try expect(false); // no dns queries
        return;
    };

    defer q_list.deinit(allocator);

    //if (try dns_layer_iface.dnsLayer.find_last_ans_offset()) |last| {
    //    print("last answer offset: {}\n", .{last});
    //} else {
    //    print("failed to find last answer offset.\n", .{});
    //}

    try dns_layer_iface.dnsLayer.add_answer(ebay_www_domain, DNS.QueryType.CNAME, DNS.DnsClass.IN, 205, "www.ebay.com.ebaycdn.net");

    var ans_list = try dns_layer_iface.dnsLayer.get_answers(allocator) orelse {
        try expect(false); // no dns answers
        return;
    };

    defer ans_list.deinit(allocator);

    var cur: ?*DNS.AnswerRecord = ans_list.first;
    while (cur) |ans| {
        const name = try ans.get_name(allocator);
        defer allocator.free(name);
        //      print("{s} {any} {any} ttl: {} ", .{ name, ans.get_rr_type(), ans.get_class_type(), ans.get_ttl() });

        if (ans.get_rr_type() == DNS.QueryType.CNAME) {
            const cname = ans.cname.decode_cname(allocator) catch |err| {
                print("({s})\n", .{@errorName(err)});
                //                print("raw: ({}) {x}\n", .{ ans.get_data().len, ans.get_data() });
                cur = ans.get_next_record();
                continue;
            };

            defer allocator.free(cname);
            //            print("{s}\n", .{cname});
        }

        cur = ans.get_next_record();
    }
}

test "build dns a response layer" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const tmp_buf: LayerOwner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    var dns_layer_iface = try LayerIface.init(DNS.DNSLayer, tmp_buf);
    defer dns_layer_iface.deinit();

    const ebay_www_domain: []const u8 = "www.ebay.com";

    try dns_layer_iface.dnsLayer.add_query(ebay_www_domain, DNS.QueryType.A, DNS.DnsClass.IN);

    var q_list = try dns_layer_iface.dnsLayer.get_queries(allocator) orelse {
        try expect(false); // no dns queries
        return;
    };

    defer q_list.deinit(allocator);

    //if (try dns_layer_iface.dnsLayer.find_last_ans_offset()) |last| {
    //    print("last answer offset: {}\n", .{last});
    //} else {
    //    print("failed to find last answer offset.\n", .{});
    //}

    const ip = try IPv4.IPv4Address.init_from_string("95.100.104.10");

    try dns_layer_iface.dnsLayer.add_answer(ebay_www_domain, DNS.QueryType.A, DNS.DnsClass.IN, 128, &ip.array);

    var ans_list = try dns_layer_iface.dnsLayer.get_answers(allocator) orelse {
        try expect(false); // no dns answers
        return;
    };

    defer ans_list.deinit(allocator);

    var cur: ?*DNS.AnswerRecord = ans_list.first;
    while (cur) |ans| {
        const name = try ans.get_name(allocator);
        defer allocator.free(name);
        //    print("{s} {any} {any} ttl: {} ", .{ name, ans.get_rr_type(), ans.get_class_type(), ans.get_ttl() });

        if (ans.get_rr_type() == DNS.QueryType.A) {
            ans.a.set_ip(try IPv4.IPv4Address.init_from_string("192.168.1.111"));

            const ip_addr = ans.a.get_ip() orelse {
                //           print("-\n", .{});
                cur = ans.get_next_record();
                continue;
            };

            //      print("{x} ", .{&ip_addr.array});

            const ip_str = try ip_addr.to_string(allocator);

            defer allocator.free(ip_str);
            //     print("{s}\n", .{ip_str});
        }

        cur = ans.get_next_record();
    }
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

    var q_list = try dns_layer.dnsLayer.get_queries(allocator) orelse {
        try expect(false); // no dns quuries
        return;
    };

    defer q_list.deinit(allocator);

    var q = q_list.first;
    while (q) |query| {
        const qname = try query.decode_qname(allocator);
        defer allocator.free(qname);
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
        if (ans.get_rr_type() == DNS.QueryType.A) {
            const ip = ans.a.get_ip() orelse {
                cur = ans.get_next_record();
                continue;
            };

            const ip_str = try ip.to_string(allocator);
            defer allocator.free(ip_str);
        }
        cur = ans.get_next_record();
    }
}

test "parse dns response" {
    const dns_ns_response: [173]u8 = [_]u8{ 0x3a, 0xc2, 0x81, 0x80, 0x0, 0x1, 0x0, 0x4, 0x0, 0x0, 0x0, 0x1, 0xf, 0x73, 0x6f, 0x75, 0x74, 0x68, 0x77, 0x65, 0x73, 0x74, 0x2d, 0x73, 0x69, 0x74, 0x65, 0x73, 0x2, 0x63, 0x6f, 0x2, 0x75, 0x6b, 0x0, 0x0, 0x2, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x2, 0x0, 0x1, 0x0, 0x0, 0x3, 0x45, 0x0, 0x13, 0x6, 0x6e, 0x73, 0x31, 0x30, 0x38, 0x33, 0x6, 0x75, 0x69, 0x2d, 0x64, 0x6e, 0x73, 0x3, 0x62, 0x69, 0x7a, 0x0, 0xc0, 0xc, 0x0, 0x2, 0x0, 0x1, 0x0, 0x0, 0x3, 0x45, 0x0, 0x13, 0x6, 0x6e, 0x73, 0x31, 0x31, 0x31, 0x30, 0x6, 0x75, 0x69, 0x2d, 0x64, 0x6e, 0x73, 0x3, 0x6f, 0x72, 0x67, 0x0, 0xc0, 0xc, 0x0, 0x2, 0x0, 0x1, 0x0, 0x0, 0x3, 0x45, 0x0, 0x13, 0x6, 0x6e, 0x73, 0x31, 0x30, 0x36, 0x35, 0x6, 0x75, 0x69, 0x2d, 0x64, 0x6e, 0x73, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0xc0, 0xc, 0x0, 0x2, 0x0, 0x1, 0x0, 0x0, 0x3, 0x45, 0x0, 0x12, 0x6, 0x6e, 0x73, 0x31, 0x31, 0x31, 0x32, 0x6, 0x75, 0x69, 0x2d, 0x64, 0x6e, 0x73, 0x2, 0x64, 0x65, 0x0, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    defer _ = debug_allocator.detectLeaks();

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

        if (ans.get_rr_type() == DNS.QueryType.NS) {
            const ns_name = ans.ns.decode_ns_name(allocator) catch {
                cur = ans.get_next_record();
                continue;
            };

            defer allocator.free(ns_name);
        }
        cur = ans.get_next_record();
    }
}

test "parse cname response" {
    const dns_cname_response: [234]u8 = [_]u8{ 0xaa, 0xbf, 0x81, 0x80, 0x0, 0x1, 0x0, 0x8, 0x0, 0x0, 0x0, 0x1, 0x3, 0x77, 0x77, 0x77, 0x4, 0x65, 0x62, 0x61, 0x79, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x0, 0xcd, 0x0, 0x1a, 0x3, 0x77, 0x77, 0x77, 0x4, 0x65, 0x62, 0x61, 0x79, 0x3, 0x63, 0x6f, 0x6d, 0x7, 0x65, 0x62, 0x61, 0x79, 0x63, 0x64, 0x6e, 0x3, 0x6e, 0x65, 0x74, 0x0, 0xc0, 0x2a, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x0, 0xcd, 0x0, 0x1d, 0x9, 0x73, 0x6c, 0x6f, 0x74, 0x38, 0x38, 0x31, 0x36, 0x37, 0x4, 0x65, 0x62, 0x61, 0x79, 0x3, 0x63, 0x6f, 0x6d, 0x7, 0x65, 0x64, 0x67, 0x65, 0x6b, 0x65, 0x79, 0xc0, 0x3f, 0xc0, 0x50, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x3, 0x35, 0x0, 0x16, 0x6, 0x65, 0x38, 0x38, 0x31, 0x36, 0x37, 0x1, 0x61, 0xa, 0x61, 0x6b, 0x61, 0x6d, 0x61, 0x69, 0x65, 0x64, 0x67, 0x65, 0xc0, 0x3f, 0xc0, 0x79, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x14, 0x0, 0x4, 0x2, 0x15, 0x40, 0xc, 0xc0, 0x79, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x14, 0x0, 0x4, 0x2, 0x15, 0x40, 0xe, 0xc0, 0x79, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x14, 0x0, 0x4, 0x2, 0x15, 0x40, 0x16, 0xc0, 0x79, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x14, 0x0, 0x4, 0x2, 0x15, 0x40, 0x5, 0xc0, 0x79, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x14, 0x0, 0x4, 0x2, 0x15, 0x40, 0x13, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const dns_buf = try allocator.alignedAlloc(u8, std.mem.Alignment.@"2", dns_cname_response.len);
    @memmove(dns_buf, dns_cname_response[0..]);

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
        if (ans.get_rr_type() == DNS.QueryType.CNAME) {
            const name = try ans.get_name(allocator);
            defer allocator.free(name);

            const cname = ans.cname.decode_cname(allocator) catch {
                cur = ans.get_next_record();
                continue;
            };

            defer allocator.free(cname);
        }
        cur = ans.get_next_record();
    }
}

test "parse https w ar response" {
    const dns_https_aa_resp: [146]u8 = [_]u8{ 0x96, 0xaa, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0xd, 0x67, 0x65, 0x77, 0x31, 0x2d, 0x73, 0x70, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x7, 0x73, 0x70, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x41, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x0, 0x81, 0x0, 0x1a, 0xd, 0x65, 0x64, 0x67, 0x65, 0x2d, 0x77, 0x65, 0x62, 0x2d, 0x67, 0x65, 0x77, 0x31, 0x9, 0x64, 0x75, 0x61, 0x6c, 0x2d, 0x67, 0x73, 0x6c, 0x62, 0xc0, 0x1a, 0xc0, 0x45, 0x0, 0x6, 0x0, 0x1, 0x0, 0x0, 0x2, 0xda, 0x0, 0x35, 0x4, 0x64, 0x6e, 0x73, 0x31, 0x3, 0x70, 0x30, 0x35, 0x5, 0x6e, 0x73, 0x6f, 0x6e, 0x65, 0x3, 0x6e, 0x65, 0x74, 0x0, 0xa, 0x68, 0x6f, 0x73, 0x74, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0xc0, 0x66, 0x62, 0x2b, 0x8b, 0x48, 0x0, 0x0, 0xa8, 0xc0, 0x0, 0x0, 0x1c, 0x20, 0x0, 0x12, 0x75, 0x0, 0x0, 0x0, 0xe, 0x10 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const dns_buf = try allocator.alignedAlloc(u8, std.mem.Alignment.@"2", dns_https_aa_resp.len);
    @memmove(dns_buf, dns_https_aa_resp[0..]);

    const dns_owner: LayerOwner = LayerOwner{ .owned_buffer = try .init(dns_buf, allocator) };

    var dns_layer = try LayerIface.init(DNS.DNSLayer, dns_owner);
    defer dns_layer.deinit();

    var ans_list = try dns_layer.dnsLayer.get_auth_answers(allocator) orelse {
        try expect(false); // no dns answers
        return;
    };

    defer ans_list.deinit(allocator);

    try expect(ans_list.answer_count == 1);

    var cur: ?*DNS.AnswerRecord = ans_list.first;
    while (cur) |ans| {
        if (ans.get_rr_type() == DNS.QueryType.SOA) {
            const name = try ans.get_name(allocator);
            defer allocator.free(name);

            const mname = ans.soa.get_mname(allocator) catch {
                cur = ans.get_next_record();
                continue;
            };

            defer allocator.free(mname);

            const rname = ans.soa.get_rname(allocator) catch {
                cur = ans.get_next_record();
                print("\n", .{});
                continue;
            };

            defer allocator.free(rname);

            const serial = ans.soa.get_serial();

            try expect(serial == 1647020872);

            const ref_int = ans.soa.get_refresh_interval();

            try expect(ref_int == 43200);

            const rtry_int = ans.soa.get_retry_interval();

            try expect(rtry_int == 7200);

            const expire_limit = ans.soa.get_expire_limit();

            try expect(expire_limit == 1209600);

            const min_ttl = ans.soa.get_minimum_ttl();

            try expect(min_ttl == 3600);
        }
        cur = ans.get_next_record();
    }
}
