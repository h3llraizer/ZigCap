// src/tests.zig
const std = @import("std");
const zigcap = @import("lib.zig");
const print = std.debug.print;
const expect = std.testing.expect;

const RawData = zigcap.RawData;
const Packet = zigcap.Packet.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const Layer = zigcap.Packet.Layer;
const LayerOwner = zigcap.Layer.LayerOwner;
const tcp_ip_protocol = zigcap.tcp_ip_protocol;
const IPProtocol = zigcap.ProtocolEnums.IPProtocol;
const IPv4 = @import("IPv4.zig");
const Eth = @import("Eth.zig");
const UDP = @import("UDP.zig");
const ARP = @import("ARP.zig");
const ICMP = @import("ICMP.zig");
const ApplicationLayer = @import("GenericLayer.zig").ApplicationLayer;
const LayerIface = @import("LayerIface.zig").LayerIface;

const PcapWrapper = @import("PcapWrapper.zig");

const alignment_check = @import("Helpers.zig").alignment_check;

const DNS = @import("DNS.zig");

const Buffer = @import("Buffer.zig").Buffer;

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

test "dns build" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const dns_owner: LayerOwner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    var dns_layer: DNS.DNSLayer = try DNS.DNSLayer.init(dns_owner);
    defer dns_layer.deinit();

    var dns_header = dns_layer.get_mutable_header();

    dns_header.set_id(1234);

    var dns_flags = dns_header.get_flags();
    dns_flags.rd = 1;

    try expect(dns_layer.get_query_count() == 0);

    const ziggit_dev_domain: []const u8 = "ziggit.dev";

    var dns_query = try DNS.DNSQuery.init(ziggit_dev_domain, DNS.QueryType.A, DNS.DnsClass.IN, allocator);
    defer dns_query.deinit();
    try dns_layer.addQuery(&dns_query);

    try expect(dns_layer.get_query_count() == 1);

    try expect(dns_layer.first_query != null);
    if (dns_layer.first_query) |first| {
        const qname = try DNS.decodeQname(allocator, first.get_data());
        defer allocator.free(qname);
        try expect(std.mem.eql(u8, qname, ziggit_dev_domain));
    }

    const google_domain: []const u8 = "google.com";
    var dns_query1 = try DNS.DNSQuery.init(google_domain, DNS.QueryType.A, DNS.DnsClass.IN, allocator);
    defer dns_query1.deinit();
    try dns_layer.addQuery(&dns_query1);

    try expect(dns_layer.get_query_count() == 2);

    //    print("{x}\n", .{dns_layer.get_data()});

    var query = dns_layer.first_query;
    while (query) |q| {
        const q_data = q.get_data();
        //       print("q_data: {x}\n", .{q_data});

        const qname = try DNS.decodeQname(allocator, q_data);
        defer allocator.free(qname);

        //      print("{s}\n", .{qname});
        query = q.next_query;
    }
}

test "parse dns query raw" {
    const ziggit_dev_a_q: [51]u8 align(2) = [_]u8{ 0x33, 0x72, 0x1, 0x20, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x6, 0x7a, 0x69, 0x67, 0x67, 0x69, 0x74, 0x3, 0x64, 0x65, 0x76, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x29, 0x4, 0xd0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x0, 0xa, 0x0, 0x8, 0x7e, 0xa2, 0x7f, 0xc7, 0xf8, 0xde, 0x4a, 0x38 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const dns_buf = try allocator.alignedAlloc(u8, std.mem.Alignment.@"2", ziggit_dev_a_q.len);
    @memmove(dns_buf, ziggit_dev_a_q[0..]);
    //    defer allocator.free(dns_buf);

    const dns_owner: LayerOwner = LayerOwner{ .owned_buffer = try .init(dns_buf, allocator) };
    //defer dns_owner.owned_buffer.deinit();

    var dns_layer = try LayerIface.init(DNS.DNSLayer, dns_owner);
    defer dns_layer.deinit();
    try dns_layer.dnsLayer.get_queries();
    //    try dns_layer.dnsLayer.get_answers();

    //   print("dns layer init'd.\n", .{});
    //
    //   print("dns_layer_iface: {x}\n", .{dns_layer.get_data()});
    //   print("dns_layer: {x}\n", .{dns_layer.dnsLayer.get_data()});

    const query_count = dns_layer.dnsLayer.get_query_count();

    try expect(query_count == 1);

    //   print("query count: {}\n", .{query_count});

    var query = dns_layer.dnsLayer.first_query;

    // dns_layer.dnsLayer.print_queries_meta();

    if (query) |q| {
        const data = dns_layer.get_data();
        const slice = data[q.offset .. q.offset + q.length];
        _ = slice;
        const q_data = q.get_data();
        _ = q_data;
    }

    while (query) |q| {
        const q_data = q.get_data();

        const qname = try DNS.decodeQname(allocator, q_data);
        defer allocator.free(qname);

        query = q.next_query;
    }

    try expect(dns_layer.dnsLayer.first_answer == null);
}

test "parse dns A response raw" {
    const google_a_resp: [135]u8 align(2) = [_]u8{ 0x72, 0x43, 0x81, 0x80, 0x0, 0x1, 0x0, 0x6, 0x0, 0x0, 0x0, 0x1, 0x6, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x45, 0x0, 0x4, 0x8e, 0xfa, 0x81, 0x8b, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x45, 0x0, 0x4, 0x8e, 0xfa, 0x81, 0x66, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x45, 0x0, 0x4, 0x8e, 0xfa, 0x81, 0x8a, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x45, 0x0, 0x4, 0x8e, 0xfa, 0x81, 0x64, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x45, 0x0, 0x4, 0x8e, 0xfa, 0x81, 0x71, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x45, 0x0, 0x4, 0x8e, 0xfa, 0x81, 0x65, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const dns_buf = try allocator.alignedAlloc(u8, std.mem.Alignment.@"2", google_a_resp.len);
    @memmove(dns_buf, google_a_resp[0..]);

    const dns_owner: LayerOwner = LayerOwner{ .owned_buffer = try .init(dns_buf, allocator) };

    var dns_layer = try LayerIface.init(DNS.DNSLayer, dns_owner);
    defer dns_layer.deinit();

    try dns_layer.dnsLayer.get_queries();
    try dns_layer.dnsLayer.get_answers();

    const query_count = dns_layer.dnsLayer.get_query_count();

    try expect(query_count == 1);

    var query = dns_layer.dnsLayer.first_query;

    while (query) |q| {
        const q_data = q.get_data();

        const qname = try DNS.decodeQname(allocator, q_data);
        defer allocator.free(qname);

        print("{s}\n", .{qname});
        query = q.next_query;
    }

    try expect(dns_layer.dnsLayer.get_answer_count() == 6);

    try expect(dns_layer.dnsLayer.first_answer != null);

    var answer = dns_layer.dnsLayer.first_answer;
    while (answer) |ans| {
        print("answer: offset={} length={} {any} {any}\n", .{ ans.get_offset(), ans.get_length(), ans.get_rr_type(), ans.get_class_type() });
        if (ans.a.get_ip()) |ip| {
            const ip_str = try ip.to_string(allocator);
            defer allocator.free(ip_str);
            print("{s}\n", .{ip_str});
        }

        const ttl = ans.get_ttl();

        try expect(ttl == 69);

        ans.set_ttl(128); // modify the ttl value for this answer

        try expect(ans.get_ttl() == 128);

        answer = ans.get_next_record();
    }
}

test "parse dns AAAA response raw" {
    const cloudflare_aaaa_resp: [99]u8 align(2) = [_]u8{ 0xd5, 0xf5, 0x81, 0x80, 0x0, 0x1, 0x0, 0x2, 0x0, 0x0, 0x0, 0x1, 0xa, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x6c, 0x61, 0x72, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1c, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x1c, 0x0, 0x1, 0x0, 0x0, 0x0, 0xad, 0x0, 0x10, 0x26, 0x6, 0x47, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x68, 0x10, 0x85, 0xe5, 0xc0, 0xc, 0x0, 0x1c, 0x0, 0x1, 0x0, 0x0, 0x0, 0xad, 0x0, 0x10, 0x26, 0x6, 0x47, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x68, 0x10, 0x84, 0xe5, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const dns_buf = try allocator.alignedAlloc(u8, std.mem.Alignment.@"2", cloudflare_aaaa_resp.len);
    @memmove(dns_buf, cloudflare_aaaa_resp[0..]);

    const dns_owner: LayerOwner = LayerOwner{ .owned_buffer = try .init(dns_buf, allocator) };

    var dns_layer = try LayerIface.init(DNS.DNSLayer, dns_owner);
    defer dns_layer.deinit();

    try dns_layer.dnsLayer.get_queries();
    try dns_layer.dnsLayer.get_answers();

    //  const query_count = dns_layer.dnsLayer.get_query_count();

    //   try expect(query_count == 1);

    var query = dns_layer.dnsLayer.first_query;

    while (query) |q| {
        const q_data = q.get_data();

        const qname = try DNS.decodeQname(allocator, q_data);
        defer allocator.free(qname);

        print("{s}\n", .{qname});
        query = q.next_query;
    }

    //    try expect(dns_layer.dnsLayer.get_answer_count() == 6);

    try expect(dns_layer.dnsLayer.first_answer != null);

    var answer = dns_layer.dnsLayer.first_answer;
    while (answer) |ans| {
        print("answer: offset={} length={} {any} {any}\n", .{ ans.get_offset(), ans.get_length(), ans.get_rr_type(), ans.get_class_type() });

        if (ans.aaaa.get_ipv6()) |ipv6| {
            const ip_str = try ipv6.to_string(allocator);
            defer allocator.free(ip_str);
            print("{s}\n", .{ip_str});
        }

        answer = ans.get_next_record();
    }
}

test "parse ebay CNAME response" {
    const ebay_cname_resp: [181]u8 align(2) = [_]u8{ 0x4e, 0xf9, 0x81, 0x80, 0x0, 0x1, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x3, 0x77, 0x77, 0x77, 0x4, 0x65, 0x62, 0x61, 0x79, 0x2, 0x63, 0x6f, 0x2, 0x75, 0x6b, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x0, 0xbc, 0x0, 0x1c, 0x3, 0x77, 0x77, 0x77, 0x4, 0x65, 0x62, 0x61, 0x79, 0x2, 0x63, 0x6f, 0x2, 0x75, 0x6b, 0x7, 0x65, 0x62, 0x61, 0x79, 0x63, 0x64, 0x6e, 0x3, 0x6e, 0x65, 0x74, 0x0, 0xc0, 0x2c, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x0, 0xbc, 0x0, 0x1e, 0xa, 0x73, 0x6c, 0x6f, 0x74, 0x33, 0x34, 0x38, 0x35, 0x32, 0x35, 0x4, 0x65, 0x62, 0x61, 0x79, 0x3, 0x63, 0x6f, 0x6d, 0x7, 0x65, 0x64, 0x67, 0x65, 0x6b, 0x65, 0x79, 0xc0, 0x43, 0xc0, 0x54, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x3, 0x36, 0x0, 0x17, 0x7, 0x65, 0x33, 0x34, 0x38, 0x35, 0x32, 0x35, 0x1, 0x61, 0xa, 0x61, 0x6b, 0x61, 0x6d, 0x61, 0x69, 0x65, 0x64, 0x67, 0x65, 0xc0, 0x43, 0xc0, 0x7e, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x14, 0x0, 0x4, 0x2, 0x13, 0xf8, 0x89, 0xc0, 0x7e, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x14, 0x0, 0x4, 0x2, 0x13, 0xf8, 0x97 };

    print("parsing ebay CNAME response.\n", .{});

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const dns_buf = try allocator.alignedAlloc(u8, std.mem.Alignment.@"2", ebay_cname_resp.len);
    @memmove(dns_buf, ebay_cname_resp[0..]);

    const dns_owner: LayerOwner = LayerOwner{ .owned_buffer = try .init(dns_buf, allocator) };

    var dns_layer = try LayerIface.init(DNS.DNSLayer, dns_owner);
    defer dns_layer.deinit();

    try dns_layer.dnsLayer.get_queries();
    try dns_layer.dnsLayer.get_answers();

    //  const query_count = dns_layer.dnsLayer.get_query_count();

    //   try expect(query_count == 1);

    var query = dns_layer.dnsLayer.first_query;

    while (query) |q| {
        const q_data = q.get_data();

        const qname = try DNS.decodeQname(allocator, q_data);
        defer allocator.free(qname);

        print("{s}\n", .{qname});
        query = q.next_query;
    }

    try expect(dns_layer.dnsLayer.get_answer_count() == 5);

    try expect(dns_layer.dnsLayer.first_answer != null);

    // www.ebay.co.uk.ebaycdn.net
    // slot348525.ebay.com.edgekey.net
    // e348525.a.akamaiedge.net

    var answer = dns_layer.dnsLayer.first_answer;
    while (answer) |ans| {
        print("answer: offset={} length={} {any} {any}\n", .{
            ans.get_offset(),
            ans.get_length(),
            ans.get_rr_type(),
            ans.get_class_type(),
        });

        print("ttl: {}\n", .{ans.get_ttl()});

        if (ans.get_rr_type() == DNS.QueryType.CNAME) {
            const cname = try ans.cname.decode_cname(allocator);
            defer allocator.free(cname);
            print("cname decoded: {s}\n", .{cname});
        }

        answer = ans.get_next_record();
    }
}

test "build arp layer" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;

    var allocator = debug_allocator.allocator();

    const arp_owner: LayerOwner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    var arp_layer_iface = try LayerIface.init(ARP.ARPLayer, arp_owner);

    defer _ = debug_allocator.detectLeaks();
    defer arp_layer_iface.deinit();

    arp_layer_iface.arpLayer.set_sender_ip(try IPv4.IPv4Address.init_from_string("192.168.1.225"));
    arp_layer_iface.arpLayer.set_target_ip(try IPv4.IPv4Address.init_from_string("192.168.1.254"));

    arp_layer_iface.arpLayer.set_sender_mac(try Eth.MacAddress.init_from_string("14:4F:8A:A4:15:7D"));
    arp_layer_iface.arpLayer.set_target_mac(try Eth.MacAddress.init_from_string("FF:FF:FF:FF:FF:FF"));

    arp_layer_iface.arpLayer.set_opcode(ARP.ARPOpcode.Request);

    try expect(arp_layer_iface.arpLayer.get_opcode() == ARP.ARPOpcode.Request);

    const str = arp_layer_iface.to_string(allocator);
    defer allocator.free(str);

    //print("{s}\n", .{str});

}

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

    var packet = try Packet.create(allocator, allocator);
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

    var packet = try Packet.create(allocator, allocator);
    defer packet.deinit();

    _ = try packet.add_layer(&eth_layer_iface);

    _ = try packet.add_layer(&arp_layer_iface);

    ////packet.print_layers_meta();

    //try send_packet(packet.buffer.buffer.items);
}

test "build icmp request" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    var icmp_layer_iface: LayerIface = try LayerIface.init(ICMP.ICMPLayer, owner);

    defer icmp_layer_iface.deinit();
}

test "parse icmp packet" {
    var backing_buffer: [1024]u8 = undefined;

    var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);

    const allocator = fba.allocator();

    var copied = try allocator.alloc(u8, icmp_request_raw.len);

    @memmove(copied, icmp_request_raw[0..]);

    var packet = try Packet.create(allocator, allocator);
    defer packet.deinit();

    packet.from_raw(copied[0..], link_layer_type.ETHERNET) catch |err| {
        print("{s}\n", .{@errorName(err)});
    };

    //packet.print_layers_meta();

}

test "build independant eth layer" {
    var eth_layer_owner = LayerOwner{ .owned_buffer = .init_empty(std.heap.page_allocator) };

    defer eth_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);

    var eth_layer: Eth.EthLayer = try Eth.EthLayer.init(eth_layer_owner);

    var eth_hdr = eth_layer.get_mutable_header();

    eth_hdr.set_eth_type(Eth.EthType.IP);

    try expect(eth_hdr.get_eth_type() == Eth.EthType.IP);

    eth_hdr.set_dst_mac(try Eth.MacAddress.init_from_string("1A:2A:3A:4A:5A:6A"));

    eth_hdr.set_src_mac(try Eth.MacAddress.init_from_string("1B:2B:3B:4B:5B:6B"));
}

test "build independant ipv4 layer" {
    var ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(std.heap.page_allocator) };

    defer ipv4_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);

    var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);

    var ipv4_hdr = ipv4_layer_iface.ipv4Layer.get_mutable_header();

    ipv4_hdr.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));

    ipv4_hdr.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.2"));

    ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);

    ipv4_hdr.set_ttl(64);
}

test "ipv4 option parse" {
    print("========================== START ==========================\n", .{});
    print("ipv4 option parse\n", .{});

    var backing_buffer: [1024]u8 = undefined;

    var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);

    const allocator = fba.allocator();

    var ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    defer ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);

    var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer_owner);

    var ipv4_hdr = ipv4_layer_iface.ipv4Layer.get_mutable_header();

    ipv4_hdr.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));

    ipv4_hdr.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.2"));

    ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.UDP);

    ipv4_hdr.set_ttl(64);

    var record_route_op: [15]u8 align(2) = [_]u8{
        0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    };

    var op = try IPv4.IPOption.init(IPv4.IPOptionType.RecordRoute, &record_route_op);

    op.set_len(15);

    try ipv4_layer_iface.ipv4Layer.add_option(op, allocator);

    try ipv4_layer_iface.ipv4Layer.calculate_checksum();

    print("========================== END ==========================\n", .{});
}

test "build udp layer independant" {
    print("========================== START ==========================\n", .{});
    print("build udp layer independant\n", .{});
    var udp_layer_owner = LayerOwner{ .owned_buffer = .init_empty(std.heap.page_allocator) };

    defer udp_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);

    var udp_layer_iface: LayerIface = try LayerIface.init(UDP.UDPLayer, udp_layer_owner);

    var udp_hdr = udp_layer_iface.udpLayer.get_mutable_header();

    udp_hdr.set_src_port(1024);
    udp_hdr.set_dst_port(53);

    print("========================== END ==========================\n", .{});
}

test "build generic layer independant" {
    print("========================== START ==========================\n", .{});
    print("build generic layer independant\n", .{});
    const page_allocator = std.heap.page_allocator;
    var app_layer_owner = LayerOwner{ .owned_buffer = .init_empty(page_allocator) };

    defer app_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);

    var app_layer_iface: LayerIface = try LayerIface.init(ApplicationLayer, app_layer_owner);

    try app_layer_iface.genericAppLayer.set_payload("hello");

    //    print("app layer data: {s}\n", .{app_layer_iface.to_string(page_allocator)});
    print("========================== END ==========================\n", .{});
}

test "build ipv4 layer with Router Alert option" {
    print("========================== START ==========================\n", .{});
    print("build ipv4 layer with Router Alert option\n", .{});
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

    var router_alert_op: [2]u8 align(2) = [_]u8{ 0x00, 0x00 };

    const op = try IPv4.IPOption.init(IPv4.IPOptionType.RouterAlert, &router_alert_op);

    const op_bytes = try op.toBytes(allocator);

    try expect(op_bytes[0] == 0x94);
    try expect(op_bytes[1] == 0x04);
    try expect(op_bytes[2] == 0x00);
    try expect(op_bytes[3] == 0x00);

    try ipv4_layer_iface.ipv4Layer.add_option(op, allocator);

    var ipv4_slice = ipv4_layer_iface.ipv4Layer.get_data();

    try expect(ipv4_slice.len == 24);

    try ipv4_layer_iface.ipv4Layer.remove_all_options();

    ipv4_slice = ipv4_layer_iface.ipv4Layer.get_data();

    print("========================== END ==========================\n", .{});
}

test "ipv4 layer in complete packet with Router Alert option" {
    print("========================== START ==========================\n", .{});
    print("ipv4 layer in complete packet with Router Alert option\n", .{});
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

    var router_alert_op: [2]u8 align(2) = [_]u8{ 0x00, 0x00 };

    const op = try IPv4.IPOption.init(IPv4.IPOptionType.RouterAlert, &router_alert_op);

    const op_bytes = try op.toBytes(allocator);

    try expect(op_bytes[0] == 0x94);
    try expect(op_bytes[1] == 0x04);
    try expect(op_bytes[2] == 0x00);
    try expect(op_bytes[3] == 0x00);

    var packet = try Packet.create(allocator, allocator);

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
        udp.calculate_checksum();
    }

    if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4| {
        try ipv4.calculate_checksum();
    }

    print("========================== END ==========================\n", .{});
}

test "build ipv4 packet with Record Route option" {
    print("========================== START ==========================\n", .{});
    print("build ipv4 packet with Record Route option\n", .{});
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

    var record_route_op: [15]u8 align(2) = [_]u8{
        0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    };

    var op = try IPv4.IPOption.init(IPv4.IPOptionType.RecordRoute, &record_route_op);

    op.set_len(15);

    var packet = try Packet.create(allocator, allocator);

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
        udp.calculate_checksum();
    }

    if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4| {
        try ipv4.calculate_checksum();
    }

    pkt_data = packet.buffer.buffer.items;

    if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4| {
        _ = ipv4;
    }

    if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4| {
        try ipv4.zero_hdr();
    } else {
        print("ipv4 layer not found.\n", .{});
    }

    pkt_data = packet.buffer.buffer.items;

    print("========================== END ==========================\n", .{});
}

test "build ipv4 layer with Record Route option" {
    print("========================== START ==========================\n", .{});
    print("build ipv4 layer with Record Route option\n", .{});
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

    var record_route_op: [15]u8 align(2) = [_]u8{
        0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    };

    const op = try IPv4.IPOption.init(IPv4.IPOptionType.RecordRoute, &record_route_op);

    try ipv4_layer_iface.ipv4Layer.add_option(op, allocator);

    var packet = try Packet.create(allocator, allocator);

    try expect(try packet.add_layer(&ipv4_layer_iface));

    print("========================== END ==========================\n", .{});
}

test "build eth,ipv4,udp,generic_app packet" {
    print("========================== START ==========================\n", .{});
    print("build eth,ipv4,udp,generic_app packet\n", .{});

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

    var packet = try Packet.create(allocator, allocator);
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

    if (try packet.search_layers(tcp_ip_protocol.ipv4)) |ipv4| {
        var new_ipv4_layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
        defer new_ipv4_layer_owner.owned_buffer.buffer.deinit(allocator);
        var ip_layer = try packet.extract_layer(ipv4, &eth_layer_owner) orelse {
            print("failed to extract ip layer.\n", .{});
            return;
        };

        ip_layer.ipv4Layer.set_ip_proto(IPProtocol.UDP);

        const eth = try packet.search_layers(tcp_ip_protocol.eth) orelse {
            print("could not find eth layer.\n", .{});
            return;
        };
        try expect(try eth.layer_iface.get_protocol() == tcp_ip_protocol.eth);
        try expect(try packet.insert_layer(eth, &ip_layer));
    }

    if (packet.get_layer_of_type(Eth.EthLayer)) |eth| {
        var hdr = eth.get_mutable_header();
        hdr.set_eth_type(Eth.EthType.IP);
    }

    if (packet.get_layer_of_type(UDP.UDPLayer)) |udp| {
        udp.calculate_checksum();
    }

    if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4| {
        try ipv4.calculate_checksum();
    }

    print("========================== END ==========================\n", .{});
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
