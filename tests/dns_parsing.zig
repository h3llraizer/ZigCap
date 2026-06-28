const std = @import("std");
const expect = std.testing.expect;
const zigcap = @import("zigcap");
const print = std.debug.print;
const eql = std.mem.eql;
const Allocator = std.mem.Allocator;

const DNS = zigcap.DNS;
const IPv4 = zigcap.IPv4;
const Packet = zigcap.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const LayerOwner = zigcap.Owner.LayerOwner;
const Layer = zigcap.Layer;

test "build dns query layer" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    var dns_layer_iface = try Layer.init(DNS.DNSLayer, allocator);
    defer dns_layer_iface.deinit();

    const ziggit_dev_domain: []const u8 = try DNS.encode_name("ziggit.dev", allocator);
    defer allocator.free(ziggit_dev_domain);

    const ziggit_net_domain: []const u8 = try DNS.encode_name("ziggit.net", allocator);
    defer allocator.free(ziggit_net_domain);

    const ziggit_org_domain: []const u8 = try DNS.encode_name("ziggit.org", allocator);
    defer allocator.free(ziggit_org_domain);

    var zig_query = try DNS.Query.init(ziggit_dev_domain, .A, .IN, allocator);
    defer zig_query.deinit();

    try dns_layer_iface.dnsLayer.add_query(&zig_query);

    try zig_query.set_name(ziggit_net_domain);

    try dns_layer_iface.dnsLayer.add_query(&zig_query);

    try zig_query.set_name(ziggit_org_domain);

    try dns_layer_iface.dnsLayer.add_query(&zig_query);

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

    var dns_layer_iface = try Layer.init(DNS.DNSLayer, allocator);
    defer dns_layer_iface.deinit();

    const ebay_www_domain: []const u8 = try DNS.encode_name("www.ebay.com", allocator);
    defer allocator.free(ebay_www_domain);

    var query = try DNS.Query.init(ebay_www_domain, .A, .IN, allocator);
    defer query.deinit();

    try dns_layer_iface.dnsLayer.add_query(&query);

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
            const cname = ans.cname.get_cname(allocator) catch |err| {
                print("({s})\n", .{@errorName(err)});
                //                print("raw: ({}) {x}\n", .{ ans.get_data().len, ans.get_data() });
                cur = ans.next();
                continue;
            };

            defer allocator.free(cname);
            //            print("{s}\n", .{cname});
        }

        cur = ans.next();
    }
}

test "build dns a response layer" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    var dns_layer_iface = try Layer.init(DNS.DNSLayer, allocator);
    defer dns_layer_iface.deinit();

    const ebay_www_domain: []const u8 = try DNS.encode_name("www.ebay.com", allocator);
    defer allocator.free(ebay_www_domain);

    var query = try DNS.Query.init(ebay_www_domain, .A, .IN, allocator);
    defer query.deinit();

    try dns_layer_iface.dnsLayer.add_query(&query);

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

            const ip_addr = ans.a.get_ip();

            //      print("{x} ", .{&ip_addr.array});

            const ip_str = try ip_addr.to_string(allocator);

            defer allocator.free(ip_str);
            //     print("{s}\n", .{ip_str});
        }

        cur = ans.next();
    }
}

test "parse dns response layer" {
    var dns_a_resp = [_]u8{ 0xfa, 0x60, 0x81, 0x80, 0x0, 0x1, 0x0, 0x6, 0x0, 0x0, 0x0, 0x1, 0x6, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x8b, 0x0, 0x4, 0x8e, 0xfa, 0x97, 0x8b, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x8b, 0x0, 0x4, 0x8e, 0xfa, 0x97, 0x71, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x8b, 0x0, 0x4, 0x8e, 0xfa, 0x97, 0x66, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x8b, 0x0, 0x4, 0x8e, 0xfa, 0x97, 0x65, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x8b, 0x0, 0x4, 0x8e, 0xfa, 0x97, 0x64, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x8b, 0x0, 0x4, 0x8e, 0xfa, 0x97, 0x8a, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    var dns_layer = try DNS.DNSLayer.initFromSlice(dns_a_resp[0..], allocator);
    defer dns_layer.deinit();

    var q_list = try dns_layer.get_queries(allocator) orelse {
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

    var ans_list = try dns_layer.get_answers(allocator) orelse {
        try expect(false); // no dns answers
        return;
    };

    defer ans_list.deinit(allocator);

    var cur: ?*DNS.AnswerRecord = ans_list.first;
    while (cur) |ans| {
        const name = try ans.get_name(allocator);
        defer allocator.free(name);
        if (ans.get_rr_type() == DNS.QueryType.A) {
            const ip = ans.a.get_ip();

            const ip_str = try ip.to_string(allocator);
            defer allocator.free(ip_str);
        }
        cur = ans.next();
    }
}

test "parse dns response" {
    var dns_ns_response = [_]u8{ 0x3a, 0xc2, 0x81, 0x80, 0x0, 0x1, 0x0, 0x4, 0x0, 0x0, 0x0, 0x1, 0xf, 0x73, 0x6f, 0x75, 0x74, 0x68, 0x77, 0x65, 0x73, 0x74, 0x2d, 0x73, 0x69, 0x74, 0x65, 0x73, 0x2, 0x63, 0x6f, 0x2, 0x75, 0x6b, 0x0, 0x0, 0x2, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x2, 0x0, 0x1, 0x0, 0x0, 0x3, 0x45, 0x0, 0x13, 0x6, 0x6e, 0x73, 0x31, 0x30, 0x38, 0x33, 0x6, 0x75, 0x69, 0x2d, 0x64, 0x6e, 0x73, 0x3, 0x62, 0x69, 0x7a, 0x0, 0xc0, 0xc, 0x0, 0x2, 0x0, 0x1, 0x0, 0x0, 0x3, 0x45, 0x0, 0x13, 0x6, 0x6e, 0x73, 0x31, 0x31, 0x31, 0x30, 0x6, 0x75, 0x69, 0x2d, 0x64, 0x6e, 0x73, 0x3, 0x6f, 0x72, 0x67, 0x0, 0xc0, 0xc, 0x0, 0x2, 0x0, 0x1, 0x0, 0x0, 0x3, 0x45, 0x0, 0x13, 0x6, 0x6e, 0x73, 0x31, 0x30, 0x36, 0x35, 0x6, 0x75, 0x69, 0x2d, 0x64, 0x6e, 0x73, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0xc0, 0xc, 0x0, 0x2, 0x0, 0x1, 0x0, 0x0, 0x3, 0x45, 0x0, 0x12, 0x6, 0x6e, 0x73, 0x31, 0x31, 0x31, 0x32, 0x6, 0x75, 0x69, 0x2d, 0x64, 0x6e, 0x73, 0x2, 0x64, 0x65, 0x0, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var dns_layer = try DNS.DNSLayer.initFromSlice(dns_ns_response[0..], allocator);
    defer dns_layer.deinit();

    var ans_list = try dns_layer.get_answers(allocator) orelse {
        try expect(false); // no dns answers
        return;
    };

    defer ans_list.deinit(allocator);

    const nameservers: [4][]const u8 = .{
        "ns1083.ui-dns.biz",
        "ns1110.ui-dns.org",
        "ns1065.ui-dns.com",
        "ns1112.ui-dns.de",
    };

    try expect(ans_list.answer_count == 4);

    var count: usize = 0;

    var cur: ?*DNS.AnswerRecord = ans_list.first;
    while (cur) |ans| {
        const name = try ans.get_name(allocator);
        defer allocator.free(name);

        if (ans.get_rr_type() == DNS.QueryType.NS) {
            const ns_name = ans.ns.decode_ns_name(allocator) catch {
                cur = ans.next();
                continue;
            };

            try expect(eql(u8, ns_name, nameservers[count]));

            defer allocator.free(ns_name);
        }
        count += 1;
        cur = ans.next();
    }

    try expect(count == 4);
}

test "parse cname response" {
    var dns_cname_response = [_]u8{ 0xaa, 0xbf, 0x81, 0x80, 0x0, 0x1, 0x0, 0x8, 0x0, 0x0, 0x0, 0x1, 0x3, 0x77, 0x77, 0x77, 0x4, 0x65, 0x62, 0x61, 0x79, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x0, 0xcd, 0x0, 0x1a, 0x3, 0x77, 0x77, 0x77, 0x4, 0x65, 0x62, 0x61, 0x79, 0x3, 0x63, 0x6f, 0x6d, 0x7, 0x65, 0x62, 0x61, 0x79, 0x63, 0x64, 0x6e, 0x3, 0x6e, 0x65, 0x74, 0x0, 0xc0, 0x2a, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x0, 0xcd, 0x0, 0x1d, 0x9, 0x73, 0x6c, 0x6f, 0x74, 0x38, 0x38, 0x31, 0x36, 0x37, 0x4, 0x65, 0x62, 0x61, 0x79, 0x3, 0x63, 0x6f, 0x6d, 0x7, 0x65, 0x64, 0x67, 0x65, 0x6b, 0x65, 0x79, 0xc0, 0x3f, 0xc0, 0x50, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x3, 0x35, 0x0, 0x16, 0x6, 0x65, 0x38, 0x38, 0x31, 0x36, 0x37, 0x1, 0x61, 0xa, 0x61, 0x6b, 0x61, 0x6d, 0x61, 0x69, 0x65, 0x64, 0x67, 0x65, 0xc0, 0x3f, 0xc0, 0x79, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x14, 0x0, 0x4, 0x2, 0x15, 0x40, 0xc, 0xc0, 0x79, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x14, 0x0, 0x4, 0x2, 0x15, 0x40, 0xe, 0xc0, 0x79, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x14, 0x0, 0x4, 0x2, 0x15, 0x40, 0x16, 0xc0, 0x79, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x14, 0x0, 0x4, 0x2, 0x15, 0x40, 0x5, 0xc0, 0x79, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x14, 0x0, 0x4, 0x2, 0x15, 0x40, 0x13, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var dns_layer = try DNS.DNSLayer.initFromSlice(dns_cname_response[0..], allocator);
    defer dns_layer.deinit();

    var ans_list = try dns_layer.get_answers(allocator) orelse {
        try expect(false); // no dns answers
        return;
    };

    defer ans_list.deinit(allocator);

    var cur: ?*DNS.AnswerRecord = ans_list.first;
    while (cur) |ans| {
        if (ans.get_rr_type() == DNS.QueryType.CNAME) {
            const name = try ans.get_name(allocator);
            defer allocator.free(name);

            const cname = ans.cname.get_cname(allocator) catch {
                cur = ans.next();
                continue;
            };

            defer allocator.free(cname);
        }
        cur = ans.next();
    }
}

test "parse https w ar response" {
    var dns_https_aa_resp = [_]u8{ 0x96, 0xaa, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0xd, 0x67, 0x65, 0x77, 0x31, 0x2d, 0x73, 0x70, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x7, 0x73, 0x70, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x41, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x0, 0x81, 0x0, 0x1a, 0xd, 0x65, 0x64, 0x67, 0x65, 0x2d, 0x77, 0x65, 0x62, 0x2d, 0x67, 0x65, 0x77, 0x31, 0x9, 0x64, 0x75, 0x61, 0x6c, 0x2d, 0x67, 0x73, 0x6c, 0x62, 0xc0, 0x1a, 0xc0, 0x45, 0x0, 0x6, 0x0, 0x1, 0x0, 0x0, 0x2, 0xda, 0x0, 0x35, 0x4, 0x64, 0x6e, 0x73, 0x31, 0x3, 0x70, 0x30, 0x35, 0x5, 0x6e, 0x73, 0x6f, 0x6e, 0x65, 0x3, 0x6e, 0x65, 0x74, 0x0, 0xa, 0x68, 0x6f, 0x73, 0x74, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0xc0, 0x66, 0x62, 0x2b, 0x8b, 0x48, 0x0, 0x0, 0xa8, 0xc0, 0x0, 0x0, 0x1c, 0x20, 0x0, 0x12, 0x75, 0x0, 0x0, 0x0, 0xe, 0x10 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var dns_layer = try DNS.DNSLayer.initFromSlice(dns_https_aa_resp[0..], allocator);
    defer dns_layer.deinit();

    const hdr = dns_layer.get_immutable_header();

    //print("{any}\n", .{hdr});

    const nrcount = hdr.get_nscount();

    try expect(nrcount == 1);

    var queries = try dns_layer.get_queries(allocator) orelse {
        try expect(false); // no dns queries
        return;
    };

    defer queries.deinit(allocator);

    var qcur: ?*DNS.Query = queries.first;

    while (qcur) |query| {
        const name = try query.decode_qname(allocator);
        //  print("Query: {s}\n", .{name});
        defer allocator.free(name);

        try expect(std.mem.eql(u8, name, "gew1-spclient.spotify.com"));

        //    print("{any}\n", .{query.qtype});

        qcur = query.next_query;
    }

    var ans_list = try dns_layer.get_auth_answers(allocator) orelse {
        try expect(false); // no dns answers
        return;
    };

    defer ans_list.deinit(allocator);

    try expect(ans_list.answer_count == 1);

    var cur: ?*DNS.AnswerRecord = ans_list.first;
    while (cur) |ans| {
        //print("SOA: \n", .{});
        if (ans.get_rr_type() == DNS.QueryType.SOA) {
            const name = try ans.get_name(allocator);
            defer allocator.free(name);

            //print("\tNAME: {s}\n", .{name});

            const mname = try ans.soa.get_mname(allocator);

            defer allocator.free(mname);

            //print("\tMNAME: {s}\n", .{mname});

            const rname = try ans.soa.get_rname(allocator);

            //print("\tRNAME: {s}\n", .{rname});

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
        cur = ans.next();
    }
}

test "build dns query soa layer" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    var dns_layer_iface = try Layer.init(DNS.DNSLayer, allocator);
    defer dns_layer_iface.deinit();

    const ziggit_dev_domain: []const u8 = try DNS.encode_name("ziggit.dev", allocator);
    defer allocator.free(ziggit_dev_domain);

    var zig_query = try DNS.Query.init(ziggit_dev_domain, .SOA, .IN, allocator);
    defer zig_query.deinit();

    try dns_layer_iface.dnsLayer.add_query(&zig_query);

    var q_list = try dns_layer_iface.dnsLayer.get_queries(allocator) orelse {
        try expect(false); // no dns queries
        return;
    };

    defer q_list.deinit(allocator);

    var q = q_list.first;
    while (q) |query| {
        const qname = try query.decode_qname(allocator);
        defer allocator.free(qname);

        q = query.next_query;
    }

    try dns_layer_iface.dnsLayer.add_answer(ziggit_dev_domain, DNS.QueryType.SOA, DNS.DnsClass.IN, 128, "server.com");

    var answers = try dns_layer_iface.dnsLayer.get_answers(allocator) orelse {
        try expect(false); // no answers
        return;
    };

    defer answers.deinit(allocator);

    var answer = answers.first orelse {
        try expect(false); // no first answer
        return;
    };

    try expect(answer.get_rr_type() == .SOA);

    try expect(answer.get_ttl() == 128);
}

test "parse https spotify domain" {
    var raw = [_]u8{ 0x6, 0xea, 0x81, 0x80, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0xd, 0x65, 0x64, 0x67, 0x65, 0x2d, 0x77, 0x65, 0x62, 0x2d, 0x67, 0x65, 0x77, 0x31, 0x9, 0x64, 0x75, 0x61, 0x6c, 0x2d, 0x67, 0x73, 0x6c, 0x62, 0x7, 0x73, 0x70, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x41, 0x0, 0x1, 0xc0, 0x1a, 0x0, 0x6, 0x0, 0x1, 0x0, 0x0, 0x3, 0x74, 0x0, 0x35, 0x4, 0x64, 0x6e, 0x73, 0x31, 0x3, 0x70, 0x30, 0x35, 0x5, 0x6e, 0x73, 0x6f, 0x6e, 0x65, 0x3, 0x6e, 0x65, 0x74, 0x0, 0xa, 0x68, 0x6f, 0x73, 0x74, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0xc0, 0x4a, 0x62, 0x2b, 0x8b, 0x48, 0x0, 0x0, 0xa8, 0xc0, 0x0, 0x0, 0x1c, 0x20, 0x0, 0x12, 0x75, 0x0, 0x0, 0x0, 0xe, 0x10, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var dns_layer = try DNS.DNSLayer.initFromSlice(raw[0..], allocator);
    defer dns_layer.deinit();

    var queries = try dns_layer.get_queries(allocator) orelse {
        try expect(false); // no dns queries
        return;
    };

    defer queries.deinit(allocator);

    var qcur: ?*DNS.Query = queries.first;

    while (qcur) |query| {
        const name = try query.decode_qname(allocator);
        //print("Query: {s}\n", .{name});
        defer allocator.free(name);

        //    try expect(std.mem.eql(u8, name, "gew1-spclient.spotify.com"));

        //print("{any}\n", .{query.qtype});

        qcur = query.next_query;
    }

    const nscount = dns_layer.get_immutable_header().get_nscount();

    if (nscount == 0) {
        try expect(false); // nscount is 0
        return;
    }

    var ans_list = try dns_layer.get_auth_answers(allocator) orelse {
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

            const mname = try ans.soa.get_mname(allocator);

            defer allocator.free(mname);

            const rname = try ans.soa.get_rname(allocator);

            defer allocator.free(rname);

            const serial = ans.soa.get_serial();

            try expect(serial == 1647020872);

            const ref_int = ans.soa.get_refresh_interval();

            try expect(ref_int == 43200);

            const retry_int = ans.soa.get_retry_interval();

            try expect(retry_int == 7200);

            const expire_limit = ans.soa.get_expire_limit();

            try expect(expire_limit == 1209600);

            const min_ttl = ans.soa.get_minimum_ttl();

            try expect(min_ttl == 3600);
        }
        cur = ans.next();
    }
}

test "decompression" {
    var data = [_]u8{ 0xa8, 0x22, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x3, 0x77, 0x77, 0x77, 0x7, 0x73, 0x70, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x2, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x1, 0x23, 0x0, 0x1c, 0x3, 0x61, 0x74, 0x63, 0x7, 0x73, 0x70, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x3, 0x6d, 0x61, 0x70, 0x6, 0x66, 0x61, 0x73, 0x74, 0x6c, 0x79, 0x3, 0x6e, 0x65, 0x74, 0x0, 0xc0, 0x3d, 0x0, 0x6, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1e, 0x0, 0x2e, 0x3, 0x6e, 0x73, 0x31, 0xc0, 0x3d, 0xa, 0x68, 0x6f, 0x73, 0x74, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x6, 0x66, 0x61, 0x73, 0x74, 0x6c, 0x79, 0xc0, 0x18, 0x78, 0x39, 0xc6, 0x29, 0x0, 0x0, 0xe, 0x10, 0x0, 0x0, 0x2, 0x58, 0x0, 0x9, 0x3a, 0x80, 0x0, 0x0, 0x0, 0x1e };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var dns_layer = try DNS.DNSLayer.initFromSlice(data[0..], allocator);
    defer dns_layer.deinit();

    var queries = try dns_layer.get_queries(allocator) orelse {
        try expect(false); // failed to get queries - expected one
        return;
    };

    defer queries.deinit(allocator);

    try expect(queries.query_count == 1);

    try expect(queries.first != null);

    var query = queries.first.?; // unwrap

    const qname = try query.decode_qname(allocator);
    try expect(eql(u8, qname, "www.spotify.com"));
    allocator.free(qname);

    try expect(query.qtype == .NS);
    try expect(query.qclass == .IN);

    var answers = try dns_layer.get_answers(allocator) orelse {
        try expect(false); // failed to get answers - expected 1
        return;
    };

    defer answers.deinit(allocator);

    var answer = answers.first;
    while (answer) |ans| {
        answer = ans.next();
    }

    var auth_answers = try dns_layer.get_auth_answers(allocator) orelse {
        try expect(false); // failed to get auth answers - expected 1
        return;
    };

    defer auth_answers.deinit(allocator);

    var auth_answer = auth_answers.first;
    while (auth_answer) |ans| {
        const name = try ans.get_name(allocator);
        //print("{s}\n", .{name});
        allocator.free(name);
        auth_answer = ans.next();
    }
}
