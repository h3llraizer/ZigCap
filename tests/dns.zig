const std = @import("std");
const expect = std.testing.expect;
const zigcap = @import("zigcap");

const print = std.debug.print;

const eql = std.mem.eql;

const Allocator = std.mem.Allocator;

const DNS = zigcap.DNS;
const Packet = zigcap.Packet.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const Layer = zigcap.Packet.Layer;
const LayerOwner = zigcap.Owner.LayerOwner;
const tcp_ip_protocol = zigcap.tcp_ip_protocol;
const IPProtocol = zigcap.ProtocolEnums.IPProtocol;
const IPv4 = zigcap.IPv4;
const IPv6 = zigcap.IPv6;
const IPAddress = zigcap.IPAddress;

const LayerIface = zigcap.LayerIface;

test "generic record" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const name = try DNS.encode_name("google.com", allocator);
    defer allocator.free(name);

    var grec: DNS.GenericRecord = try .init(name, allocator);
    defer grec.deinit();

    try expect(grec.get_rd_len() == (@sizeOf(u8) * 2));

    grec.set_rr_type(.A);

    grec.set_class(.IN);

    grec.set_ttl(137);

    const expected = &[_]u8{
        6, 'g', 'o', 'o', 'g', 'l', 'e',
        3, 'c', 'o', 'm', 0,
    };

    try expect(eql(u8, grec.get_data()[0..name.len], expected));

    const aname = try grec.get_name(allocator);
    defer allocator.free(aname);

    try expect(eql(u8, aname, "google.com"));

    const ip = try IPv4.IPv4Address.init_from_string("8.8.8.8");

    try grec.set_rdata(&ip.array);

    const str = try grec.to_string(allocator);
    defer allocator.free(str);

    try expect(eql(u8, grec.get_rdata(), &ip.array));

    try expect(grec.get_rr_type() == .A);

    try expect(grec.get_class() == .IN);

    try expect(grec.get_ttl() == 137);

    try expect(grec.get_rd_len() == ip.array.len);

    const ipv6_bytes = &[_]u8{ 0x2a, 0x0, 0x14, 0x50, 0x40, 0x9, 0xc, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x65 };

    const ipv6 = IPv6.IPv6Address.init_from_array(ipv6_bytes.*);

    grec.set_rr_type(.AAAA);

    try grec.set_rdata(&ipv6.array);

    try expect(eql(u8, grec.get_rdata(), &ipv6.array));

    try expect(grec.get_rr_type() == .AAAA);

    try expect(grec.get_class() == .IN);

    try expect(grec.get_ttl() == 137);

    try expect(grec.get_rd_len() == ipv6.array.len);

    grec.set_class(.ANY);

    grec.set_ttl(360);

    try expect(grec.get_class() == .ANY);

    try expect(grec.get_ttl() == 360);

    try grec.set_rdata(&ip.array);

    try expect(eql(u8, grec.get_rdata(), &ip.array));

    try expect(grec.get_rr_type() != .A);

    try expect(grec.get_class() == .ANY);

    try expect(grec.get_ttl() == 360);

    try expect(grec.get_rd_len() == ip.array.len);

    const expected_len = (expected.len +
        DNS.QUERY_TYPE_LENGTH +
        DNS.CLASS_TYPE_LENGTH +
        DNS.TTL_LENGTH +
        DNS.RD_LENGTH +
        ip.array.len);

    try expect(grec.get_data().len == expected_len);

    const arec: *DNS.ARecord = grec.as(DNS.ARecord);

    const cf_ip = try IPv4.IPv4Address.init_from_string("1.1.1.1");

    arec.set_ip(cf_ip);

    try expect(eql(u8, grec.get_rdata(), &cf_ip.array));

    try expect(grec.get_rd_len() == cf_ip.array.len);

    const cf_name = try DNS.encode_name("cloudflare.com", allocator);
    defer allocator.free(cf_name);

    const cf_expected = &[_]u8{
        10, 'c', 'l', 'o', 'u', 'd', 'f', 'l', 'a', 'r', 'e',
        3,  'c', 'o', 'm', 0,
    };

    try expect(eql(u8, cf_name, cf_expected));

    try grec.set_name(cf_name);

    const clf_name = try grec.get_name(allocator);
    defer allocator.free(clf_name);

    try expect(eql(u8, clf_name, "cloudflare.com"));

    var gen_rec = DNS.AnswerRecord{ .generic = grec };

    const tmp_owner: LayerOwner = .{ .owned_buffer = .init_empty(allocator) };

    var dns_layer: DNS.DNSLayer = try .init(tmp_owner);
    defer dns_layer.deinit();

    try dns_layer.add_ans(&gen_rec);

    try expect(dns_layer.get_immutable_header().get_ancount() == 1);
    try expect(dns_layer.get_data().len == (DNS.DNSHeaderSize + grec.get_data().len));

    var answers = try dns_layer.get_answers(allocator) orelse {
        try expect(false); // no answers
        return;
    };

    try expect(answers.answer_count == 1);

    var answer = answers.first;
    while (answer) |ans| {
        try expect(eql(u8, ans.get_data(), grec.get_data()));
        try expect(ans.get_next_record() == null);
        answer = ans.get_next_record();
    }

    answers.deinit(allocator);

    var cf_query = try DNS.Query.init(cf_name, .A, .IN, allocator);
    defer cf_query.deinit();

    try dns_layer.add_query(&cf_query);

    try expect(dns_layer.get_immutable_header().get_qdcount() == 1);

    var queries = try dns_layer.get_queries(allocator) orelse {
        try expect(false); // no queries
        return;
    };

    defer queries.deinit(allocator);

    try expect(queries.query_count == 1);

    var query = queries.first;
    while (query) |q| {
        try expect(q.get_qtype() == .A);
        try expect(q.get_class() == .IN);
        q.set_qtype(.SOA);
        q.set_class(.IN);
        try expect(q.get_qtype() == .SOA);
        try expect(q.get_class() == .IN);

        const google_com = try DNS.encode_name("google.com", allocator);
        defer allocator.free(google_com);

        try q.set_name(google_com);

        const qname = try q.decode_qname(allocator);
        defer allocator.free(qname);
        try expect(eql(u8, "google.com", qname));

        try expect(q.next_query == null);
        if (q.next_query == null) break;
        query = q.next_query;
    }

    try dns_layer.remove_query(query.?);

    const gname = try cf_query.decode_qname(allocator);
    try expect(eql(u8, gname, "cloudflare.com"));
    allocator.free(gname);

    try dns_layer.add_query(&cf_query);

    try expect(dns_layer.get_immutable_header().get_qdcount() == 1);
}

test "dns build" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const dns_owner: LayerOwner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    var dns_layer: DNS.DNSLayer = try DNS.DNSLayer.init(dns_owner);
    defer dns_layer.deinit();

    var dns_header = dns_layer.get_mutable_header();

    dns_header.set_id(1234);

    dns_header.set_qr(false);

    try expect(dns_header.get_qdcount() == 0);

    const ziggit_dev_domain: []const u8 = try DNS.encode_name("ziggit.dev", allocator);
    defer allocator.free(ziggit_dev_domain);

    var ziggit_dev_query = try DNS.Query.init(ziggit_dev_domain, .A, .IN, allocator);
    defer ziggit_dev_query.deinit();

    try dns_layer.add_query(&ziggit_dev_query);

    try expect(dns_header.get_qdcount() == 1);

    const google_domain: []const u8 = try DNS.encode_name("google.com", allocator);
    defer allocator.free(google_domain);

    var google_domain_query = try DNS.Query.init(google_domain, .A, .IN, allocator);
    defer google_domain_query.deinit();

    try dns_layer.add_query(&google_domain_query);

    try expect(dns_header.get_qdcount() == 2);
}

test "parse dns query raw" {
    const ziggit_dev_a_q: [51]u8 = [_]u8{
        0x33, 0x72, 0x1,  0x20, 0x0,  0x1,  0x0,  0x0,  0x0,  0x0,  0x0,  0x1, // header

        0x6,  0x7a, 0x69, 0x67, 0x67, 0x69, 0x74, 0x3,  0x64, 0x65, 0x76, 0x0,
        0x0,  0x1,  0x0,  0x1,  0x0,  0x0,  0x29, 0x4,  0xd0, 0x0,  0x0,  0x0,
        0x0,  0x0,  0xc,  0x0,  0xa,  0x0,  0x8,  0x7e, 0xa2, 0x7f, 0xc7, 0xf8,
        0xde, 0x4a, 0x38,
    };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const dns_buf = try allocator.alloc(u8, ziggit_dev_a_q.len);
    @memmove(dns_buf, ziggit_dev_a_q[0..]);

    const dns_owner: LayerOwner = LayerOwner{ .owned_buffer = try .init(dns_buf, allocator) };

    var dns_layer = try LayerIface.init(DNS.DNSLayer, dns_owner);
    defer dns_layer.deinit();

    const dns_header: *const DNS.DNSHeader = dns_layer.dnsLayer.get_immutable_header();

    try expect(dns_header.get_qdcount() == 1);

    var queries = try dns_layer.dnsLayer.get_queries(allocator) orelse {
        try expect(false); // failed to get dns queries
        return;
    };

    defer queries.deinit(allocator);

    const someother_com = try DNS.encode_name("someother.com", allocator);
    defer allocator.free(someother_com);

    var someother_com_query = try DNS.Query.init(someother_com, .SOA, .IN, allocator);
    defer someother_com_query.deinit();

    try queries.add_query(&someother_com_query, allocator);

    try expect(queries.query_count == 2);

    var query = queries.first;

    while (query) |q| {
        const q_data = q.get_data();

        const qname = try DNS.decode_name(allocator, q_data);
        defer allocator.free(qname);

        query = q.next_query;

        try queries.remove_query(q, allocator);
    }

    try expect(queries.query_count == 0);
    try expect(dns_layer.dnsLayer.get_immutable_header().get_qdcount() == 0);

    const ziggit_dev_domain: []const u8 = try DNS.encode_name("ziggit.dev", allocator);
    defer allocator.free(ziggit_dev_domain);

    var ziggit_dev_query = try DNS.Query.init(ziggit_dev_domain, .A, .IN, allocator);
    defer ziggit_dev_query.deinit();

    try queries.add_query(&ziggit_dev_query, allocator);

    query = queries.first;

    while (query) |q| {
        const str = try q.decode_qname(allocator);
        //print("{s} {any} {any} \n", .{ str, q.qtype, q.qclass });
        allocator.free(str);
        query = q.next_query;
    }

    try expect(queries.query_count == 1);
    try expect(dns_layer.dnsLayer.get_immutable_header().get_qdcount() == 1);

    try expect(dns_layer.get_data().len == ziggit_dev_a_q.len);

    var answers = try dns_layer.dnsLayer.get_answers(allocator) orelse {
        try expect(false);
        return;
    };

    defer answers.deinit(allocator);
}

test "build a record" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const name = try DNS.encode_name("dns.google.com", allocator);
    defer allocator.free(name);

    const ip = try IPv4.IPv4Address.init_from_string("8.8.8.8");

    var record = try DNS.ARecord.init(name, .IN, 300, ip, allocator);
    defer record.deinit();

    try expect(record.get_rr_type() == .A);
    try expect(record.get_class() == .IN);
    try expect(record.get_ttl() == 300);

    try expect(eql(u8, &record.get_ip().array, &ip.array));

    const decoded_name = try record.get_name(allocator);
    defer allocator.free(decoded_name);
    try expect(eql(u8, decoded_name, "dns.google.com"));

    const str = try record.to_string(allocator);
    //   print("{s}\n", .{str});
    allocator.free(str);
}

test "build aaaa record" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const name = try DNS.encode_name("dns.google.com", allocator);
    defer allocator.free(name);

    const ip = try IPv6.IPv6Address.init_from_string("2001:4860:4860:0000:0000:0000:0000:8888");

    var record = try DNS.AAAARecord.init(name, .IN, 300, ip, allocator);
    defer record.deinit();

    try expect(record.get_rr_type() == .AAAA);
    try expect(record.get_class() == .IN);
    try expect(record.get_ttl() == 300);

    const ip_str = try record.get_ipv6().to_string(allocator);
    defer allocator.free(ip_str);

    try expect(eql(u8, &record.get_ipv6().array, &ip.array));

    const decoded_name = try record.get_name(allocator);
    defer allocator.free(decoded_name);
    try expect(eql(u8, decoded_name, "dns.google.com"));

    const str = try record.to_string(allocator);
    //    print("{s}\n", .{str});
    allocator.free(str);
}

test "build soa record" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const name = try DNS.encode_name("google.com", allocator);
    defer allocator.free(name);

    const ns_server = try DNS.encode_name("ns1.google.com", allocator);
    defer allocator.free(ns_server);

    const resp_mbox = try DNS.encode_name("dns-admin.google.com", allocator);
    defer allocator.free(resp_mbox);

    const ttl = 300;
    const serial = 933628625;
    const refresh_interval = 900;
    const retry_interval = 900;
    const expire_limit = 1800;
    const min_ttl = 60;

    var record = try DNS.SOARecord.init(
        name,
        .IN,
        ttl, // ttl
        ns_server, // name-server
        resp_mbox, // responsible mailbox
        serial, // serial
        refresh_interval, //
        retry_interval,
        expire_limit,
        min_ttl,
        allocator,
    );
    defer record.deinit();

    try expect(record.get_rr_type() == .SOA);
    try expect(record.get_class() == .IN);
    try expect(record.get_ttl() == 300);

    const decoded_name = try record.get_name(allocator);
    defer allocator.free(decoded_name);
    try expect(eql(u8, decoded_name, "google.com"));

    try expect(record.get_rd_len() == ns_server.len + resp_mbox.len +
        DNS.SOARecord.SERIAL_NUMBER_LENGTH +
        DNS.SOARecord.REFRESH_INTERVAL_LENGTH +
        DNS.SOARecord.RETRY_INTERVAL_LENGTH +
        DNS.SOARecord.EXPIRE_LIMIT_LENGTH +
        DNS.SOARecord.MIN_TTL_LENGTH);

    const ns = try record.get_mname(allocator);
    defer allocator.free(ns);

    try expect(eql(u8, ns, "ns1.google.com"));

    const rname = try record.get_rname(allocator);
    defer allocator.free(rname);

    try expect(eql(u8, rname, "dns-admin.google.com"));

    try expect(record.get_serial() == serial);
    try expect(record.get_refresh_interval() == refresh_interval);
    try expect(record.get_retry_interval() == retry_interval);
    try expect(record.get_expire_limit() == expire_limit);
    try expect(record.get_minimum_ttl() == min_ttl);

    const cf_name = try DNS.encode_name("cloudflare.com", allocator);
    defer allocator.free(cf_name);

    try record.set_name(cf_name);

    const new_name = try record.get_name(allocator);
    defer allocator.free(new_name);

    try expect(eql(u8, new_name, "cloudflare.com"));

    const cf_ns_name = try DNS.encode_name("ns3.cloudflare.com", allocator);
    defer allocator.free(cf_ns_name);

    try record.set_mname(cf_ns_name);

    const cf_mname = try record.get_mname(allocator);
    defer allocator.free(cf_mname);

    try expect(eql(u8, cf_mname, "ns3.cloudflare.com"));

    try record.set_mname(ns_server);

    const goog_mname = try record.get_mname(allocator);
    defer allocator.free(goog_mname);

    try expect(eql(u8, goog_mname, "ns1.google.com"));

    const cf_rname = try DNS.encode_name("dns.cloudflare.com", allocator);
    defer allocator.free(cf_rname);

    try record.set_rname(cf_rname);

    const cf_rname_dec = try record.get_rname(allocator);
    defer allocator.free(cf_rname_dec);

    try expect(eql(u8, cf_rname_dec, "dns.cloudflare.com"));

    try expect(record.get_serial() == serial);
    try expect(record.get_refresh_interval() == refresh_interval);
    try expect(record.get_retry_interval() == retry_interval);
    try expect(record.get_expire_limit() == expire_limit);
    try expect(record.get_minimum_ttl() == min_ttl);

    const str = try record.to_string(allocator);
    defer allocator.free(str);
    print("{s}\n", .{str});
}

test "build ns record" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const name = try DNS.encode_name("google.com", allocator);
    defer allocator.free(name);

    const ns_server = try DNS.encode_name("ns1.google.com", allocator);
    defer allocator.free(ns_server);

    var record = try DNS.NSRecord.init(name, .IN, 300, ns_server, allocator);
    defer record.deinit();

    const name_dec = try record.get_name(allocator);
    defer allocator.free(name_dec);

    try expect(eql(u8, name_dec, "google.com"));

    try expect(record.get_rr_type() == .NS);
    try expect(record.get_class() == .IN);
    try expect(record.get_ttl() == 300);
    try expect(record.get_rd_len() == ns_server.len);

    const ns_server_dec = try record.decode_ns_name(allocator);
    defer allocator.free(ns_server_dec);

    try expect(eql(u8, ns_server_dec, "ns1.google.com"));

    const cf_ns_name = try DNS.encode_name("ns3.cloudflare.com", allocator);
    defer allocator.free(cf_ns_name);

    try record.set_ns_name(cf_ns_name);

    const cf_ns_name_dec = try record.decode_ns_name(allocator);
    defer allocator.free(cf_ns_name_dec);

    try expect(eql(u8, cf_ns_name_dec, "ns3.cloudflare.com"));

    const cf_name = try DNS.encode_name("cloudflare.com", allocator);
    defer allocator.free(cf_name);

    try record.set_name(cf_name);

    const cf_name_dec = try record.get_name(allocator);
    defer allocator.free(cf_name_dec);

    try expect(eql(u8, cf_name_dec, "cloudflare.com"));

    try expect(record.get_rr_type() == .NS);
    try expect(record.get_class() == .IN);
    try expect(record.get_ttl() == 300);
    try expect(record.get_rd_len() == cf_ns_name.len);

    record.set_ttl(600);
    record.set_class(.ANY);

    try expect(record.get_class() == .ANY);
    try expect(record.get_ttl() == 600);

    const str = try record.to_string(allocator);
    defer allocator.free(str);
    print("{s}\n", .{str});
}

test "build txt record" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const name = try DNS.encode_name("google.com", allocator);
    defer allocator.free(name);

    const txt_rec = try DNS.encode_name("asv=894f6d1f9f83bcf44e4b1bc40bc1c4aa", allocator);
    defer allocator.free(txt_rec);

    var record = try DNS.TXTRecord.init(name, .IN, 300, txt_rec, allocator);
    defer record.deinit();

    const name_dec = try record.get_name(allocator);
    defer allocator.free(name_dec);

    try expect(eql(u8, name_dec, "google.com"));

    const txt_dec = try record.get_txt(allocator);
    defer allocator.free(txt_dec);

    const cf_name = try DNS.encode_name("cloudflare.com", allocator);
    defer allocator.free(cf_name);

    try record.set_name(cf_name);

    try expect(eql(u8, txt_dec, "asv=894f6d1f9f83bcf44e4b1bc40bc1c4aa"));

    try expect(record.get_class() == .IN);

    try expect(record.get_ttl() == 300);

    try expect(record.get_txt_len() == txt_rec.len);

    try expect(record.get_rd_len() == txt_rec.len + 1);

    const str = try record.to_string(allocator);
    defer allocator.free(str);
    print("{s}\n", .{str});
}

test "build mx record" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const name = try DNS.encode_name("cloudflare.com", allocator);
    defer allocator.free(name);

    const mx_domain = try DNS.encode_name("mxa-canary.global.inbound.cf-emailsecurity.net", allocator);
    defer allocator.free(mx_domain);

    const class_in = DNS.DnsClass.IN;
    const ttl: u32 = 36;
    const preference: u16 = 5;

    var record = try DNS.MXRecord.init(name, class_in, ttl, preference, mx_domain, allocator);
    defer record.deinit();

    const name_dec = try record.get_name(allocator);
    defer allocator.free(name_dec);

    try expect(eql(u8, name_dec, "cloudflare.com"));

    try expect(record.get_rr_type() == .MX);
    try expect(record.get_class() == .IN);
    try expect(record.get_ttl() == ttl);
    try expect(record.get_preference() == preference);
    try expect(record.get_rd_len() == mx_domain.len + DNS.MXRecord.MX_PREFERENCE_VALUE_LENGTH);

    const mx_domain_dec = try record.get_mx_domain(allocator);
    defer allocator.free(mx_domain_dec);

    try expect(eql(u8, mx_domain_dec, "mxa-canary.global.inbound.cf-emailsecurity.net"));

    const expected_len = (name.len +
        mx_domain.len +
        DNS.QUERY_TYPE_LENGTH +
        DNS.CLASS_TYPE_LENGTH +
        DNS.TTL_LENGTH +
        DNS.RD_LENGTH +
        DNS.MXRecord.MX_PREFERENCE_VALUE_LENGTH);

    try expect(record.get_data().len == expected_len);

    const google_name = try DNS.encode_name("google.com", allocator);
    defer allocator.free(google_name);

    try expect(record.get_rr_type() == .MX);
    try expect(record.get_class() == .IN);
    try expect(record.get_ttl() == ttl);

    try record.set_name(google_name);

    const google_name_dec = try record.get_name(allocator);
    defer allocator.free(google_name_dec);

    try expect(eql(u8, google_name_dec, "google.com"));

    try expect(record.get_data().len == (google_name.len +
        mx_domain.len +
        DNS.QUERY_TYPE_LENGTH +
        DNS.CLASS_TYPE_LENGTH +
        DNS.TTL_LENGTH +
        DNS.RD_LENGTH +
        DNS.MXRecord.MX_PREFERENCE_VALUE_LENGTH));

    try expect(record.get_rr_type() == .MX);
    try expect(record.get_class() == .IN);
    try expect(record.get_ttl() == ttl);
    try expect(record.get_preference() == preference);

    const google_mx_domain = try DNS.encode_name("mx.google.com", allocator);
    defer allocator.free(google_mx_domain);

    try record.set_mx_domain(google_mx_domain);

    const google_mx_dec = try record.get_mx_domain(allocator);
    defer allocator.free(google_mx_dec);

    try expect(eql(u8, google_mx_dec, "mx.google.com"));

    try expect(record.get_rr_type() == .MX);
    try expect(record.get_class() == .IN);
    try expect(record.get_ttl() == ttl);

    record.set_preference(10);

    try expect(record.get_preference() == 10);

    const str = try record.to_string(allocator);
    defer allocator.free(str);
    print("{s}\n", .{str});
}

test "build ipv4 ptr query name" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const ip = try IPv4.IPv4Address.init_from_string("142.251.30.113");

    const ip_ptr = try DNS.encode_ip_ptr_query(IPAddress{ .ipv4 = ip }, allocator);
    defer allocator.free(ip_ptr);

    const ip_ptr_dec = try DNS.decode_ip_ptr_query(ip_ptr, allocator);
    defer allocator.free(ip_ptr_dec);

    try expect(eql(u8, ip_ptr_dec, "113.30.251.142.in-addr.arpa"));

    const ip_from_ptr = try DNS.extract_ip_from_ptr(ip_ptr_dec);

    try expect(eql(u8, &ip.array, &ip_from_ptr.ipv4.array));

    const ip_str = try ip_from_ptr.to_string(allocator);
    defer allocator.free(ip_str);
}

test "build ipv6 ptr query name" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const ip = try IPv6.IPv6Address.init_from_string("2a00:1450:4009:0c17:0000:0000:0000:0065");
    const ip_str = try ip.to_string(allocator);
    defer allocator.free(ip_str);

    const ip_ptr = try DNS.encode_ip_ptr_query(IPAddress{ .ipv6 = ip }, allocator);
    defer allocator.free(ip_ptr);

    const ip_ptr_dec = try DNS.decode_ip_ptr_query(ip_ptr, allocator);
    defer allocator.free(ip_ptr_dec);

    try expect(eql(u8, ip_ptr_dec, "5.6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.1.c.0.9.0.0.4.0.5.4.1.0.0.a.2.ip6.arpa"));

    const ip_from_ptr = try DNS.extract_ip_from_ptr(ip_ptr_dec);

    const ipv6_str = try ip_from_ptr.to_string(allocator);
    defer allocator.free(ipv6_str);

    try expect(eql(u8, &ip.array, &ip_from_ptr.ipv6.array));
}

test "build ptr record" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const ip = try IPv4.IPv4Address.init_from_string("142.251.30.113");

    const ip_ptr = try DNS.encode_ip_ptr_query(IPAddress{ .ipv4 = ip }, allocator);
    defer allocator.free(ip_ptr);

    const domain = try DNS.encode_name("sv-in-f113.1e100.net", allocator);
    defer allocator.free(domain);

    var record = try DNS.PTRRecord.init(ip_ptr, .IN, 300, domain, allocator);
    defer record.deinit();

    const domain_dec = try record.get_domain(allocator);
    defer allocator.free(domain_dec);

    try expect(eql(u8, domain_dec, "sv-in-f113.1e100.net"));

    const ptr_name_dec = try record.get_name(allocator);
    defer allocator.free(ptr_name_dec);

    const ip_from_ptr: IPAddress = try DNS.extract_ip_from_ptr(ptr_name_dec);

    const ip_str = try ip_from_ptr.ipv4.to_string(allocator);
    defer allocator.free(ip_str);

    try expect(record.get_rr_type() == .PTR);
    try expect(record.get_class() == .IN);
    try expect(record.get_ttl() == 300);
    try expect(record.get_rd_len() == domain.len);

    const ziggit_domain = try DNS.encode_name("ziggit.dev", allocator);
    defer allocator.free(ziggit_domain);

    try record.set_domain(ziggit_domain);

    const ziggit_domain_dec = try record.get_domain(allocator);
    defer allocator.free(ziggit_domain_dec);

    try expect(eql(u8, ziggit_domain_dec, "ziggit.dev"));

    try expect(record.get_rr_type() == .PTR);
    try expect(record.get_class() == .IN);
    try expect(record.get_ttl() == 300);
    try expect(record.get_rd_len() == ziggit_domain.len);

    const ziggit_ip = IPAddress{ .ipv4 = try IPv4.IPv4Address.init_from_string("170.187.203.77") };

    const ziggit_ip_ptr_q = try DNS.encode_ip_ptr_query(ziggit_ip, allocator);
    defer allocator.free(ziggit_ip_ptr_q);

    try record.set_name(ziggit_ip_ptr_q);

    const ziggit_ptr_name_dec = try record.get_name(allocator);
    defer allocator.free(ziggit_ptr_name_dec);

    const ziggit_ip_from_decoded = try DNS.extract_ip_from_ptr(ziggit_ptr_name_dec);

    try expect(eql(u8, &ziggit_ip.ipv4.array, &ziggit_ip_from_decoded.ipv4.array));

    const str = try record.to_string(allocator);
    defer allocator.free(str);
    print("{s}\n", .{str});
}

test "build cname record" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const name = try DNS.encode_name("idcta.api.bbc.co.uk", allocator);
    defer allocator.free(name);

    const cname = try DNS.encode_name("idcta-cdn.api.bbc.co.uk.edgekey.net", allocator);
    defer allocator.free(cname);

    var record = try DNS.CNAMERecord.init(name, .IN, 300, cname, allocator);
    defer record.deinit();

    const name_dec = try record.get_name(allocator);
    defer allocator.free(name_dec);

    try expect(eql(u8, name_dec, "idcta.api.bbc.co.uk"));

    try expect(record.get_rr_type() == .CNAME);
    try expect(record.get_class() == .IN);
    try expect(record.get_ttl() == 300);
    try expect(record.get_rd_len() == cname.len);

    const cname_dec = try record.get_cname(allocator);
    defer allocator.free(cname_dec);

    try expect(eql(u8, cname_dec, "idcta-cdn.api.bbc.co.uk.edgekey.net"));

    const bbc_cname = try DNS.encode_name("www.bbc.co.uk.pri.bbc.co.uk", allocator);
    defer allocator.free(bbc_cname);

    try record.set_cname(bbc_cname);

    const bbc_cname_dec = try record.get_cname(allocator);
    defer allocator.free(bbc_cname_dec);

    try expect(eql(u8, bbc_cname_dec, "www.bbc.co.uk.pri.bbc.co.uk"));

    try expect(eql(u8, name_dec, "idcta.api.bbc.co.uk"));

    try expect(record.get_rr_type() == .CNAME);
    try expect(record.get_class() == .IN);
    try expect(record.get_ttl() == 300);
    try expect(record.get_rd_len() == bbc_cname.len);

    const bbc_name = try DNS.encode_name("bbc.co.uk", allocator);
    defer allocator.free(bbc_name);

    try record.set_name(bbc_name);

    const bbc_name_dec = try record.get_name(allocator);
    defer allocator.free(bbc_name_dec);

    try expect(eql(u8, bbc_name_dec, "bbc.co.uk"));

    try expect(record.get_rr_type() == .CNAME);
    try expect(record.get_class() == .IN);
    try expect(record.get_ttl() == 300);
    try expect(record.get_rd_len() == bbc_cname.len);

    record.set_ttl(200);
    record.set_class(.ANY);

    try expect(record.get_rr_type() == .CNAME);
    try expect(record.get_class() == .ANY);
    try expect(record.get_ttl() == 200);
    try expect(record.get_rd_len() == bbc_cname.len);

    const str = try record.to_string(allocator);
    defer allocator.free(str);

    //print("{s}\n", .{str});
}

test "parse dns A response raw" {
    const google_a_resp: [135]u8 = [_]u8{ 0x72, 0x43, 0x81, 0x80, 0x0, 0x1, 0x0, 0x6, 0x0, 0x0, 0x0, 0x1, 0x6, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x45, 0x0, 0x4, 0x8e, 0xfa, 0x81, 0x8b, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x45, 0x0, 0x4, 0x8e, 0xfa, 0x81, 0x66, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x45, 0x0, 0x4, 0x8e, 0xfa, 0x81, 0x8a, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x45, 0x0, 0x4, 0x8e, 0xfa, 0x81, 0x64, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x45, 0x0, 0x4, 0x8e, 0xfa, 0x81, 0x71, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x45, 0x0, 0x4, 0x8e, 0xfa, 0x81, 0x65, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    //    print("parsing google A response.\n", .{});

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const dns_buf = try allocator.alloc(u8, google_a_resp.len);
    @memmove(dns_buf, google_a_resp[0..]);

    const dns_owner: LayerOwner = LayerOwner{ .owned_buffer = try .init(dns_buf, allocator) };

    var dns_layer = try LayerIface.init(DNS.DNSLayer, dns_owner);
    defer dns_layer.deinit();

    const dns_header: *const DNS.DNSHeader = dns_layer.dnsLayer.get_immutable_header();

    try expect(dns_header.get_qdcount() == 1);

    try expect(dns_layer.get_data().len == 135);

    var queries = try dns_layer.dnsLayer.get_queries(allocator) orelse {
        try expect(false); // failed to get queries
        return;
    };

    defer queries.deinit(allocator);

    var answers = try dns_layer.dnsLayer.get_answers(allocator) orelse {
        try expect(false); // failed to get answers
        return;
    };

    defer answers.deinit(allocator);

    var query = queries.first;

    while (query) |q| {
        const qname = try q.decode_qname(allocator);
        defer allocator.free(qname);

        //       print("{s}\n", .{qname});
        query = q.next_query;
    }

    try expect(dns_header.get_ancount() == 6);

    try expect(answers.answer_count != 0);

    var answer = answers.first;
    while (answer) |ans| {
        try expect(ans.get_rr_type() == .A);
        try expect(ans.get_class_type() == .IN);

        const ip = ans.a.get_ip();
        const ip_str = try ip.to_string(allocator);
        defer allocator.free(ip_str);

        var name = try ans.get_name(allocator); // get name from the tagged union
        try expect(eql(u8, name, "google.com")); // confirm match
        allocator.free(name);

        name = try ans.a.get_name(allocator); // get name from the concrete type
        try expect(eql(u8, name, "google.com")); // confirm match
        allocator.free(name);

        ans.a.set_class(.ANY);

        const new_ip = try IPv4.IPv4Address.init_from_string("1.2.3.4");

        ans.a.set_ip(new_ip);
        const new_ipv4 = ans.a.get_ip();
        const new_ip_str = try new_ipv4.to_string(allocator);
        defer allocator.free(new_ip_str);
        try expect(ans.a.get_ttl() == 69);

        ans.a.set_ttl(70); // check concrete ttl set works

        try expect(ans.a.get_ttl() == 70);

        ans.a.set_ttl(69); // change back to original

        try expect(ans.get_ttl() == 69);

        ans.set_ttl(128); // modify the ttl via tagged union

        try expect(ans.get_ttl() == 128);

        answer = ans.get_next_record();
    }

    // although the IPs were changed, the length of the overall DNSLayer should not have changed
    //try expect(dns_layer.get_data().len == 135);
}

test "parse dns AAAA response raw" {
    const cloudflare_aaaa_resp: []const u8 = &.{ 0xd5, 0xf5, 0x81, 0x80, 0x0, 0x1, 0x0, 0x2, 0x0, 0x0, 0x0, 0x1, 0xa, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x6c, 0x61, 0x72, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1c, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x1c, 0x0, 0x1, 0x0, 0x0, 0x0, 0xad, 0x0, 0x10, 0x26, 0x6, 0x47, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x68, 0x10, 0x85, 0xe5, 0xc0, 0xc, 0x0, 0x1c, 0x0, 0x1, 0x0, 0x0, 0x0, 0xad, 0x0, 0x10, 0x26, 0x6, 0x47, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x68, 0x10, 0x84, 0xe5, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const dns_buf = try allocator.alloc(u8, cloudflare_aaaa_resp.len);
    @memmove(dns_buf, cloudflare_aaaa_resp[0..]);

    const dns_owner: LayerOwner = LayerOwner{ .owned_buffer = try .init(dns_buf, allocator) };

    var dns_layer = try LayerIface.init(DNS.DNSLayer, dns_owner);
    defer dns_layer.deinit();

    const dns_header: *const DNS.DNSHeader = dns_layer.dnsLayer.get_immutable_header();

    try expect(dns_header.get_qdcount() == 1);

    var queries = try dns_layer.dnsLayer.get_queries(allocator) orelse {
        try expect(false); //failed to get queries
        return;
    };

    defer queries.deinit(allocator);

    var answers = try dns_layer.dnsLayer.get_answers(allocator) orelse {
        try expect(false); //failed to get answers
        return;
    };

    defer answers.deinit(allocator);

    var query = queries.first;

    while (query) |q| {
        const qname = try q.decode_qname(allocator);
        defer allocator.free(qname);

        try expect(std.mem.eql(u8, qname, "cloudflare.com"));

        query = q.next_query;
    }

    try expect(queries.query_count != 0);

    var answer = answers.first;
    while (answer) |ans| {
        //print("answer: offset={} length={} {any} {any}\n", .{ ans.get_offset(), ans.get_length(), ans.get_rr_type(), ans.get_class_type() });

        const ipv6 = ans.aaaa.get_ipv6();
        const ip_str = try ipv6.to_string(allocator);
        defer allocator.free(ip_str);

        //   print("{s}\n", .{ip_str});

        const new_ipv6 = IPv6.IPv6Address.init_from_array(.{ 0x26, 0x20, 0x1, 0xec, 0x0, 0x50, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x12 });

        ans.aaaa.set_ipv6(new_ipv6);

        const ipv6_m = ans.aaaa.get_ipv6();
        const new_ipv6_str = try ipv6_m.to_string(allocator);
        defer allocator.free(new_ipv6_str);

        try expect(std.mem.eql(u8, &ipv6_m.array, &new_ipv6.array));

        answer = ans.get_next_record();
    }
}

test "parse ebay CNAME response" {
    const ebay_cname_resp: [181]u8 = [_]u8{
        // ========== DNS HEADER (12 bytes) ==========
        0x4e, 0xf9, // Transaction ID: 0x4ef9 (random query identifier)
        0x81, 0x80, // Flags: QR=1 (response), OpCode=0 (query), AA=0, TC=0, RD=1 (recursion desired), RA=1 (recursion available), Z=0, RCODE=0 (no error)
        0x0, 0x1, // QDCOUNT: 1 question
        0x0, 0x5, // ANCOUNT: 5 answer records
        0x0, 0x0, // NSCOUNT: 0 authority records
        0x0, 0x0, // ARCOUNT: 0 additional records

        // ========== QUESTION SECTION ==========
        // QNAME: www.ebay.co.uk (encoded as length-prefixed labels)
        0x3, // Length of first label: 3
        0x77, 0x77, 0x77, // "www"
        0x4, // Length of second label: 4
        0x65, 0x62, 0x61, 0x79, // "ebay"
        0x2, // Length of third label: 2
        0x63, 0x6f, // "co"
        0x2, // Length of fourth label: 2
        0x75, 0x6b, // "uk"
        0x0, // End of QNAME (root label)
        0x0, 0x1, // QTYPE: A (IPv4 address record)
        0x0, 0x1, // QCLASS: IN (Internet class)

        // ========== ANSWER SECTION (5 resource records) ==========

        // RR 1: CNAME record for www.ebay.co.uk
        0xc0, 0x0c, // NAME: Pointer to offset 0x0c (back to "www.ebay.co.uk" in question)
        0x0, 0x5, // TYPE: CNAME (canonical name alias)
        0x0, 0x1, // CLASS: IN
        0x0, 0x0, 0x0, 0xbc, // TTL: 188 seconds (0xbc = 188)
        0x0, 0x1c, // RDLENGTH: 28 bytes for RDATA
        // RDATA: www.ebay.co.uk -> www.ebay.co.uk.edgekey.net
        0x3, 0x77, 0x77, 0x77, // "www"
        0x4, 0x65, 0x62, 0x61, 0x79, // "ebay"
        0x2, 0x63, 0x6f, // "co"
        0x2, 0x75, 0x6b, // "uk"
        0x7, 0x65, 0x62, 0x61, 0x79, 0x63, 0x64, 0x6e, // "ebaycdn"
        0x3, 0x6e, 0x65, 0x74, // "net"
        0x0, // End of name

        // RR 2: Another CNAME (chaining)
        0xc0, 0x2c, // NAME: Pointer to offset 0x2c (previous CNAME target)
        0x0, 0x5, // TYPE: CNAME
        0x0, 0x1, // CLASS: IN
        0x0, 0x0, 0x0, 0xbc, // TTL: 188 seconds
        0x0, 0x1e, // RDLENGTH: 30 bytes
        // RDATA: alias to slot348525.ebay.com.edgekey.net
        0xa, 0x73, 0x6c, 0x6f, 0x74, 0x33, 0x34, 0x38, 0x35, 0x32, 0x35, // "slot348525"
        0x4, 0x65, 0x62, 0x61, 0x79, // "ebay"
        0x3, 0x63, 0x6f, 0x6d, // "com"
        0x7, 0x65, 0x64, 0x67, 0x65, 0x6b, 0x65, 0x79, // "edgekey"
        0xc0, 0x43, // Pointer to offset 0x43 (".net" from earlier)

        // RR 3: Yet another CNAME
        0xc0, 0x54, // NAME: Pointer to offset 0x54 (previous target)
        0x0, 0x5, // TYPE: CNAME
        0x0, 0x1, // CLASS: IN
        0x0, 0x0, 0x3, 0x36, // TTL: 822 seconds (0x336 = 822)
        0x0, 0x17, // RDLENGTH: 23 bytes
        // RDATA: alias to e348525.a.akamaiedge.net
        0x7, 0x65, 0x33, 0x34, 0x38, 0x35, 0x32, 0x35, // "e348525"
        0x1, 0x61, // "a"
        0xa, 0x61, 0x6b, 0x61, 0x6d, 0x61, 0x69, 0x65, 0x64, 0x67, 0x65, // "akamaiedge"
        0xc0, 0x43, // Pointer to offset 0x43 (".net")

        // RR 4: A record (IPv4) for the final CNAME target
        0xc0, 0x7e, // NAME: Pointer to offset 0x7e ("e348525.a.akamaiedge.net")
        0x0, 0x1, // TYPE: A (IPv4 address)
        0x0, 0x1, // CLASS: IN
        0x0, 0x0, 0x0, 0x14, // TTL: 20 seconds (0x14 = 20)
        0x0, 0x4, // RDLENGTH: 4 bytes (IPv4 address)
        0x2, 0x13, 0xf8, 0x89, // IP: 2.19.248.137

        // RR 5: Another A record (load balancing - second IP)
        0xc0, 0x7e, // NAME: Pointer to same name as RR 4
        0x0, 0x1, // TYPE: A
        0x0, 0x1, // CLASS: IN
        0x0, 0x0, 0x0, 0x14, // TTL: 20 seconds
        0x0, 0x4, // RDLENGTH: 4 bytes
        0x2, 0x13, 0xf8, 0x97, // IP: 2.19.248.151
    };

    //print("parsing ebay CNAME response.\n", .{});

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const dns_buf = try allocator.alloc(u8, ebay_cname_resp.len);
    @memmove(dns_buf, ebay_cname_resp[0..]);

    const dns_owner: LayerOwner = LayerOwner{ .owned_buffer = try .init(dns_buf, allocator) };

    var dns_layer = try LayerIface.init(DNS.DNSLayer, dns_owner);
    defer dns_layer.deinit();

    const dns_header: *const DNS.DNSHeader = dns_layer.dnsLayer.get_immutable_header();

    try expect(dns_header.get_qdcount() == 1);

    // print("{x}\n", .{dns_layer.get_data()});

    var queries = try dns_layer.dnsLayer.get_queries(allocator) orelse {
        try expect(false); // failed to get queries
        return;
    };

    defer queries.deinit(allocator);

    var answers = try dns_layer.dnsLayer.get_answers(allocator) orelse {
        try expect(false); // failed to get answers
        return;
    };

    defer answers.deinit(allocator);

    var query = queries.first;

    if (query) |q| {
        const qname = try q.decode_qname(allocator);
        defer allocator.free(qname);

        try expect(std.mem.eql(u8, qname, "www.ebay.co.uk"));

        query = q.next_query;
    }

    try expect(answers.answer_count == 5);

    try expect(answers.first != null);

    var cname_count: usize = 0;
    var a_count: usize = 0;
    var answer = answers.first;
    while (answer) |ans| {
        if (ans.get_rr_type() == DNS.QueryType.CNAME) {
            cname_count += 1;
            const cname = try ans.cname.get_cname(allocator);
            defer allocator.free(cname);

            if (cname_count == 1) {
                try expect(std.mem.eql(u8, cname, "www.ebay.co.uk.ebaycdn.net"));
                const name = try ans.cname.get_name(allocator);
                defer allocator.free(name);

                try expect(std.mem.eql(u8, name, "www.ebay.co.uk"));
            }

            if (cname_count == 2) {
                try expect(std.mem.eql(u8, cname, "slot348525.ebay.com.edgekey.net"));
                const name = try ans.cname.get_name(allocator);
                defer allocator.free(name);
                try expect(std.mem.eql(u8, name, "www.ebay.co.uk.ebaycdn.net"));
            }

            if (cname_count == 3) {
                try expect(std.mem.eql(u8, cname, "e348525.a.akamaiedge.net"));

                const name = try ans.cname.get_name(allocator); // TODO: why is this causing infinite loop
                defer allocator.free(name);

                try expect(std.mem.eql(u8, name, "slot348525.ebay.com.edgekey.net"));
            }
        }

        if (ans.get_rr_type() == DNS.QueryType.A) {
            a_count += 1;
            const ipv4_address = ans.a.get_ip();
            const ip_addr_str = try ipv4_address.to_string(allocator);
            defer allocator.free(ip_addr_str);
            if (a_count == 1) {
                try expect(std.mem.eql(u8, ip_addr_str, "2.19.248.137"));
            }

            if (a_count == 2) {
                try expect(std.mem.eql(u8, ip_addr_str, "2.19.248.151"));
            }
        }

        answer = ans.get_next_record();
    }

    //    try dns_layer.dnsLayer.decompress();
}

test "parse dns txt record response" {
    const random_org_txt_resp: [217]u8 = [_]u8{ 0xbd, 0x6c, 0x81, 0x80, 0x0, 0x1, 0x0, 0x2, 0x0, 0x0, 0x0, 0x1, 0x6, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x3, 0x6f, 0x72, 0x67, 0x0, 0x0, 0x10, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x10, 0x0, 0x1, 0x0, 0x0, 0x1, 0x2c, 0x0, 0x55, 0x54, 0x76, 0x3d, 0x73, 0x70, 0x66, 0x31, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x3a, 0x5f, 0x73, 0x70, 0x66, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x3a, 0x73, 0x70, 0x66, 0x2e, 0x6d, 0x74, 0x61, 0x73, 0x76, 0x2e, 0x6e, 0x65, 0x74, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x3a, 0x5f, 0x73, 0x70, 0x66, 0x2e, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x2e, 0x6f, 0x72, 0x67, 0x20, 0x6d, 0x78, 0x20, 0x2d, 0x61, 0x6c, 0x6c, 0xc0, 0xc, 0x0, 0x10, 0x0, 0x1, 0x0, 0x0, 0x1, 0x2c, 0x0, 0x45, 0x44, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2d, 0x73, 0x69, 0x74, 0x65, 0x2d, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x48, 0x75, 0x49, 0x47, 0x43, 0x4e, 0x6b, 0x76, 0x58, 0x4c, 0x6f, 0x4a, 0x45, 0x65, 0x5f, 0x6c, 0x68, 0x35, 0x4a, 0x36, 0x35, 0x4b, 0x72, 0x6f, 0x32, 0x48, 0x74, 0x7a, 0x59, 0x78, 0x65, 0x71, 0x36, 0x62, 0x4d, 0x57, 0x47, 0x2d, 0x78, 0x4d, 0x51, 0x78, 0x49, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    //    print("parsing random.org txt request response.\n", .{});

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const dns_buf = try allocator.alloc(u8, random_org_txt_resp.len);
    @memmove(dns_buf, random_org_txt_resp[0..]);

    const dns_owner: LayerOwner = LayerOwner{ .owned_buffer = try .init(dns_buf, allocator) };

    var dns_layer = try LayerIface.init(DNS.DNSLayer, dns_owner);
    defer dns_layer.deinit();

    const dns_header: *const DNS.DNSHeader = dns_layer.dnsLayer.get_immutable_header();

    try expect(dns_header.get_qdcount() == 1);
    try expect(dns_header.get_ancount() == 2);

    var queries = try dns_layer.dnsLayer.get_queries(allocator) orelse {
        try expect(false); // failed to get queries
        return;
    };

    defer queries.deinit(allocator);

    var answers = try dns_layer.dnsLayer.get_answers(allocator) orelse {
        try expect(false); // failed to get answers
        return;
    };

    defer answers.deinit(allocator);

    var query = queries.first;

    while (query) |q| {
        const qname = try q.decode_qname(allocator);
        defer allocator.free(qname);

        //print("{s}\n", .{qname});
        query = q.next_query;
    }

    try expect(answers.answer_count == 2);

    try expect(answers.first != null);

    var answer = answers.first;
    while (answer) |ans| {
        //  print("answer: offset={} length={} {any} {any}\n", .{
        //      ans.get_offset(),
        //      ans.get_length(),
        //      ans.get_rr_type(),
        //      ans.get_class_type(),
        //  });

        try expect(ans.get_ttl() == 300);

        if (ans.get_rr_type() == DNS.QueryType.TXT) {
            //      print("txt record: {s} \n", .{ans.txt.get_record_str()});

            const name = try ans.txt.get_name(allocator);
            defer allocator.free(name);
            //     print("name: {s}\n", .{name});
        }

        answer = ans.get_next_record();
    }
}

test "parse MX record response" {
    const google_mx_resp: [60]u8 = [_]u8{ 0x3a, 0x98, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x6, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0xf, 0x0, 0x1, 0xc0, 0xc, 0x0, 0xf, 0x0, 0x1, 0x0, 0x0, 0x1, 0x2c, 0x0, 0x9, 0x0, 0xa, 0x4, 0x73, 0x6d, 0x74, 0x70, 0xc0, 0xc, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    //   print("parsing google mx request response.\n", .{});

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const dns_buf = try allocator.alloc(u8, google_mx_resp.len);
    @memmove(dns_buf, google_mx_resp[0..]);

    const dns_owner: LayerOwner = LayerOwner{ .owned_buffer = try .init(dns_buf, allocator) };

    var dns_layer = try LayerIface.init(DNS.DNSLayer, dns_owner);
    defer dns_layer.deinit();

    const dns_header: *const DNS.DNSHeader = dns_layer.dnsLayer.get_immutable_header();

    try expect(dns_header.get_qdcount() == 1);
    try expect(dns_header.get_ancount() == 1);

    var queries = try dns_layer.dnsLayer.get_queries(allocator) orelse {
        try expect(false); // failed to get queries
        return;
    };

    defer queries.deinit(allocator);

    var answers = try dns_layer.dnsLayer.get_answers(allocator) orelse {
        try expect(false); // failed to get answers
        return;
    };

    defer answers.deinit(allocator);

    var query = queries.first;

    while (query) |q| {
        const qname = try q.decode_qname(allocator);
        defer allocator.free(qname);

        //      print("{s}\n", .{qname});
        query = q.next_query;
    }

    var answer = answers.first;
    while (answer) |ans| {
        //       print("answer: offset={} length={} {any} {any}\n", .{
        //           ans.get_offset(),
        //           ans.get_length(),
        //           ans.get_rr_type(),
        //           ans.get_class_type(),
        //       });

        try expect(ans.get_ttl() == 300);

        if (ans.get_rr_type() == DNS.QueryType.MX) {
            const mx_domain = try ans.mx.get_mx_domain(allocator);
            defer allocator.free(mx_domain);

            //print("mx domain: {s}\n", .{mx_domain});

            try expect(std.mem.eql(u8, mx_domain, "smtp.google.com"));

            //           print("mx domain: {s} \n", .{mx_domain});
        }

        answer = ans.get_next_record();
    }
}

test "parse PTR record response" {
    const google_ip_ptr_resp: [95]u8 = [_]u8{ 0x24, 0x7, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x3, 0x31, 0x33, 0x39, 0x3, 0x32, 0x32, 0x33, 0x3, 0x31, 0x37, 0x38, 0x3, 0x31, 0x39, 0x32, 0x7, 0x69, 0x6e, 0x2d, 0x61, 0x64, 0x64, 0x72, 0x4, 0x61, 0x72, 0x70, 0x61, 0x0, 0x0, 0xc, 0x0, 0x1, 0xc0, 0xc, 0x0, 0xc, 0x0, 0x1, 0x0, 0x0, 0x3, 0x98, 0x0, 0x1a, 0xe, 0x79, 0x75, 0x6c, 0x68, 0x72, 0x73, 0x2d, 0x69, 0x6e, 0x2d, 0x66, 0x31, 0x33, 0x39, 0x5, 0x31, 0x65, 0x31, 0x30, 0x30, 0x3, 0x6e, 0x65, 0x74, 0x0, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const dns_buf = try allocator.alloc(u8, google_ip_ptr_resp.len);
    @memmove(dns_buf, google_ip_ptr_resp[0..]);

    const dns_owner: LayerOwner = LayerOwner{ .owned_buffer = try .init(dns_buf, allocator) };

    var dns_layer = try LayerIface.init(DNS.DNSLayer, dns_owner);
    defer dns_layer.deinit();

    const dns_header: *const DNS.DNSHeader = dns_layer.dnsLayer.get_immutable_header();

    try expect(dns_header.get_qdcount() == 1);
    try expect(dns_header.get_ancount() == 1);

    var queries = try dns_layer.dnsLayer.get_queries(allocator) orelse {
        try expect(false); // failed to get queries
        return;
    };

    defer queries.deinit(allocator);

    var answers = try dns_layer.dnsLayer.get_answers(allocator) orelse {
        try expect(false); // failed to get answers
        return;
    };

    defer answers.deinit(allocator);

    var query = queries.first;

    while (query) |q| {
        const qname = try q.decode_qname(allocator);
        defer allocator.free(qname);

        //        print("{s}\n", .{qname});
        query = q.next_query;
    }

    var answer = answers.first;
    while (answer) |ans| {
        //    print("answer: offset={} length={} {any} {any}\n", .{
        //        ans.get_offset(),
        //        ans.get_length(),
        //        ans.get_rr_type(),
        //        ans.get_class_type(),
        //    });

        const ttl = ans.get_ttl();
        //    print("ttl : {}\n", .{ttl});
        try expect(ttl == 920);

        if (ans.get_rr_type() == DNS.QueryType.PTR) {
            const domain = try ans.ptr.get_domain(allocator);
            defer allocator.free(domain);

            //print("domain: {s} \n", .{domain});

            try expect(std.mem.eql(u8, domain, "yulhrs-in-f139.1e100.net"));
        }

        answer = ans.get_next_record();
    }
}

test "parse dns packet" {
    const cname_resp_pkt: [136]u8 = [_]u8{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x8, 0x0, 0x45, 0x0, 0x0, 0x7a, 0xea, 0xd8, 0x40, 0x0, 0x40, 0x11, 0xca, 0x6a, 0xc0, 0xa8, 0x1, 0xfe, 0xc0, 0xa8, 0x1, 0xe1, 0x0, 0x35, 0xdf, 0x65, 0x0, 0x66, 0xd6, 0x5f, 0x7f, 0xd, 0x81, 0x80, 0x0, 0x1, 0x0, 0x2, 0x0, 0x0, 0x0, 0x1, 0x3, 0x77, 0x77, 0x77, 0x5, 0x70, 0x65, 0x70, 0x73, 0x69, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x3, 0x3f, 0x0, 0x18, 0x7, 0x67, 0x32, 0x77, 0x68, 0x34, 0x39, 0x37, 0x1, 0x78, 0x8, 0x69, 0x6e, 0x63, 0x61, 0x70, 0x64, 0x6e, 0x73, 0x3, 0x6e, 0x65, 0x74, 0x0, 0xc0, 0x2b, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1e, 0x0, 0x4, 0x2d, 0xdf, 0x13, 0x84, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    _ = cname_resp_pkt;
    //  var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    //  //    defer _ = debug_allocator.deinit();

    //  var allocator = debug_allocator.allocator();

    //  const pkt_data = try allocator.alloc(u8, cname_resp_pkt.len);
    //  @memmove(pkt_data, cname_resp_pkt[0..]);

    //  var packet = Packet.create(allocator, allocator);
    //  defer packet.deinit();
    //  try packet.from_raw(pkt_data, link_layer_type.ETHERNET);
}
