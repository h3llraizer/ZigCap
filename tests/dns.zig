const std = @import("std");
const expect = std.testing.expect;
const zigcap = @import("zigcap");

const print = std.debug.print;

const DNS = zigcap.DNS;
const Packet = zigcap.Packet.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const Layer = zigcap.Packet.Layer;
const LayerOwner = zigcap.Owner.LayerOwner;
const tcp_ip_protocol = zigcap.tcp_ip_protocol;
const IPProtocol = zigcap.ProtocolEnums.IPProtocol;
const IPv4 = zigcap.IPv4;
const IPv6 = zigcap.IPv6;

const LayerIface = zigcap.LayerIface;
//const LayerInterface = @import("LayerIface.zig");

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

    const ziggit_dev_domain: []const u8 = "ziggit.dev";

    try dns_layer.add_query(ziggit_dev_domain, DNS.QueryType.A, DNS.DnsClass.IN);

    try expect(dns_header.get_qdcount() == 1);

    //  try expect(dns_layer.first_query != null);
    //  if (dns_layer.first_query) |first| {
    //      const qname = try first.decode_qname(allocator);
    //      defer allocator.free(qname);
    //      try expect(std.mem.eql(u8, qname, ziggit_dev_domain));
    //  }

    const google_domain: []const u8 = "google.com";
    try dns_layer.add_query(google_domain, DNS.QueryType.A, DNS.DnsClass.IN);

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

    try queries.add_query("someother.com", DNS.QueryType.SOA, DNS.DnsClass.IN, allocator);

    try expect(queries.query_count == 2);

    var query = queries.first;

    while (query) |q| {
        const q_data = q.get_data();

        const qname = try DNS.decodeQname(allocator, q_data);
        defer allocator.free(qname);

        query = q.next_query;

        try queries.remove_query(q, allocator);
    }

    if (queries.first != null) {
        print("first query not null.\n", .{});
    }

    try expect(queries.query_count == 0);
    try expect(dns_layer.dnsLayer.get_immutable_header().get_qdcount() == 0);

    try queries.add_query("ziggit.dev", DNS.QueryType.A, DNS.DnsClass.IN, allocator);

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

    //  try answers.add_answer(
    //      queries.first,
    //  );
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
        //        print("answer: offset={} length={} {any} {any}\n", .{ ans.get_offset(), ans.get_length(), ans.get_rr_type(), ans.get_class_type() });

        print("{any} {any}\n", .{ ans.get_rr_type(), ans.get_class_type() });

        if (ans.a.get_ip()) |ip| {
            const ip_str = try ip.to_string(allocator);
            defer allocator.free(ip_str);
            print("original: {s}\n", .{ip_str});

            ans.a.set_class(.ANY);
            //print("class: {any}\n", .{try ans.a.get_class()});

            const new_ip = try IPv4.IPv4Address.init_from_string("1.2.3.4");

            ans.a.set_ip(new_ip);
            if (ans.a.get_ip()) |new_ipv4| {
                const new_ip_str = try new_ipv4.to_string(allocator);
                defer allocator.free(new_ip_str);
                print("changed: {s}\n", .{new_ip_str});
            }
        }

        print("{any} {any}\n", .{ ans.get_rr_type(), ans.get_class_type() });

        const ttl = ans.get_ttl();

        try expect(ttl == 69);

        ans.set_ttl(128); // modify the ttl value for this answer

        try expect(ans.get_ttl() == 128);

        answer = ans.get_next_record();
    }

    // although the IPs were changed, the length of the overall DNSLayer should not have changed
    try expect(dns_layer.get_data().len == 135);
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

        if (ans.aaaa.get_ipv6()) |ipv6| {
            const ip_str = try ipv6.to_string(allocator);
            defer allocator.free(ip_str);

            const new_ipv6 = IPv6.IPv6Address.init_from_array(.{ 0x26, 0x20, 0x1, 0xec, 0x0, 0x50, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x12 });

            ans.aaaa.set_ipv6(new_ipv6);

            if (ans.aaaa.get_ipv6()) |ipv6_m| {
                const new_ipv6_str = try ipv6_m.to_string(allocator);
                defer allocator.free(new_ipv6_str);

                try expect(std.mem.eql(u8, &ipv6_m.array, &new_ipv6.array));
            }
        }

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
            const cname = try ans.cname.decode_cname(allocator);
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
            try expect(ans.a.get_ip() != null);
            if (ans.a.get_ip()) |ipv4_address| {
                const ip_addr_str = try ipv4_address.to_string(allocator);
                defer allocator.free(ip_addr_str);
                if (a_count == 1) {
                    try expect(std.mem.eql(u8, ip_addr_str, "2.19.248.137"));
                }

                if (a_count == 2) {
                    try expect(std.mem.eql(u8, ip_addr_str, "2.19.248.151"));
                }
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
            const domain = try ans.ptr.get_name(allocator);
            defer allocator.free(domain);

            try expect(std.mem.eql(u8, domain, "yulhrs-in-f139.1e100.net"));

            //print("domain: {s} \n", .{domain});
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
