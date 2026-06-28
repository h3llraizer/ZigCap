const std = @import("std");
const zigcap = @import("zigcap");

const Allocator = std.mem.Allocator;

const Eth = zigcap.Eth;
const IPv4 = zigcap.IPv4;
const UDP = zigcap.UDP;
const DNS = zigcap.DNS;
const Packet = zigcap.Packet;
const Layer = zigcap.Layer;
const Pcap = zigcap.PcapWrapper;
const IPAddress = Pcap.IPAddress;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;

const help: []const []const u8 = &[_][]const u8{
    "Usage: dns-request <src_ip> <src_mac> <dst_ip> <dst_mac> <domain_name> <QTYPE> <QCLASS>",
    "<src_ip> - the IPv4 address of the interface you want to send/receive from.",
    "<src_mac> - the MAC address of the interface you want to send/receive from.",
    "<dst_ip> - the IPv4 address of the DNS Server you want to use.",
    "<dst_mac> - the MAC address for the EthLayer (likely your gateway's MAC).",
    "<domain_name> - the DNS name you are querying.",
    "<QTYPE> - query type (A, AAAA, MX, TXT, SOA, etc).",
    "<QCLASS> - query class (IN, ANY, etc).",
    "Example: dns-request 192.168.1.2 98:33:44:55:aa:55 8.8.8.8 33:fe:90:99:22:1a ziggit.dev A IN",
};

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (std.mem.eql(u8, args[1], "-h") or std.mem.eql(u8, args[1], "--help")) {
        for (help) |hs| {
            std.debug.print("{s}\n", .{hs});
        }

        return;
    }

    if (args.len < 8) {
        std.debug.print("Not enough args supplied.\n", .{});
        for (help) |hs| {
            std.debug.print("{s}\n", .{hs});
        }

        return;
    }

    const provided_ip = args[1];
    const provided_mac = args[2];
    const provided_dst_ip = args[3];
    const provided_dst_mac = args[4];
    const name = args[5];
    const provided_qtype = args[6];
    const provided_qclass = args[7];

    const src_ip = IPv4.IPv4Address.init_from_string(provided_ip) catch |err| {
        std.debug.print("Source IPv4 Address invalid: {s}.\n", .{@errorName(err)});
        return;
    };

    const src_mac = Eth.MacAddress.init_from_string(provided_mac) catch |err| {
        std.debug.print("Source Mac Address invalid: {s}.\n", .{@errorName(err)});
        return;
    };

    var ifaces = Pcap.Interfaces.init(allocator) catch |err| {
        std.debug.print("Failed to open interfaces: {s}\n", .{@errorName(err)});
        return;
    };
    defer ifaces.deinit();

    _ = ifaces.get_all() catch |err| {
        std.debug.print("Failed to open interfaces: {s}\n", .{@errorName(err)});
        return;
    };

    var iface = ifaces.find_by_ip(IPAddress{ .v4 = src_ip }) orelse {
        std.debug.print("Failed to find interface with the IPv4 Address provided.\n", .{});
        return;
    };

    iface.open(allocator) catch |err| {
        std.debug.print("Failed to open interface: {s}\n", .{@errorName(err)});
        return;
    };

    const dst_ip = IPv4.IPv4Address.init_from_string(provided_dst_ip) catch |err| {
        std.debug.print("Destination IPv4 Address invalid: {s}.\n", .{@errorName(err)});
        return;
    };

    const dst_mac = Eth.MacAddress.init_from_string(provided_dst_mac) catch |err| {
        std.debug.print("Destination Mac Address invalid: {s}.\n", .{@errorName(err)});
        return;
    };

    const qtypes = std.enums.values(DNS.QueryType);

    var qtype: DNS.QueryType = @enumFromInt(0);

    var qtype_valid: bool = false;

    for (qtypes) |qt| {
        if (std.mem.eql(u8, @tagName(qt), provided_qtype)) {
            qtype = qt;
            qtype_valid = true;
            break;
        }
    }

    if (!qtype_valid) {
        std.debug.print("Query Type invalid. Valid Query types are:\n", .{});
        for (qtypes) |qt| {
            std.debug.print("{s}\n", .{@tagName(qt)});
        }
    }

    const qclasses = std.enums.values(DNS.DnsClass);

    var qclass: DNS.DnsClass = @enumFromInt(0);

    var qclass_valid: bool = false;

    for (qclasses) |qc| {
        if (std.mem.eql(u8, @tagName(qc), provided_qclass)) {
            qclass = qc;
            qclass_valid = true;
            break;
        }
    }

    if (!qclass_valid) {
        std.debug.print("Query Class invalid. Valid Query classes are:\n", .{});
        for (qclasses) |qc| {
            std.debug.print("{s}\n", .{@tagName(qc)});
        }
    }

    var eth_layer = try Eth.EthLayer.init(allocator);
    defer eth_layer.deinit();

    const eth_hdr: *Eth.EthHeader = eth_layer.get_mutable_header();

    eth_hdr.set_src_mac(src_mac);
    eth_hdr.set_dst_mac(dst_mac);
    eth_hdr.set_eth_type(.IP);

    var ipv4_layer = try IPv4.IPv4Layer.init(allocator);
    defer ipv4_layer.deinit();

    const ipv4_hdr: *IPv4.IPv4Header = ipv4_layer.get_mutable_header();

    ipv4_hdr.set_src_ip(src_ip);
    ipv4_hdr.set_dst_ip(dst_ip);

    var udp_layer = try UDP.UDPLayer.init(allocator);
    defer udp_layer.deinit();

    const udp_hdr: *UDP.UDPHeader = udp_layer.get_mutable_header();
    udp_hdr.set_dst_port(53);
    udp_hdr.set_src_port(1024);

    var dns_layer = try DNS.DNSLayer.init(allocator);
    defer dns_layer.deinit();

    const dns_hdr: *DNS.DNSHeader = dns_layer.get_mutable_header();

    dns_hdr.set_id(1234);

    dns_hdr.set_rd(true);

    const encoded_name = try DNS.encode_name(name, allocator);
    defer allocator.free(encoded_name);

    var query = try DNS.Query.init(encoded_name, qtype, qclass, allocator);
    defer query.deinit();

    try dns_layer.add_query(&query);

    var packet = Packet.create(allocator, allocator);
    defer packet.deinit();

    var layer = Layer{ .ethLayer = eth_layer };

    try packet.add_layer(&layer);

    layer = Layer{ .ipv4Layer = ipv4_layer };

    try packet.add_layer(&layer);

    layer = Layer{ .udpLayer = udp_layer };

    try packet.add_layer(&layer);

    layer = Layer{ .dnsLayer = dns_layer };

    try packet.add_layer(&layer);

    packet.validate_packet();

    var capture_thread: std.Thread = try .spawn(.{}, capture_response, .{ iface, src_ip, dst_ip, 1024, 54, 1234, allocator });
    defer capture_thread.join();

    try iface.send(packet.get_raw());
}

fn capture_response(iface: *Pcap.Interface, src_ip: IPv4.IPv4Address, dst_ip: IPv4.IPv4Address, src_port: u16, dst_port: u16, tx_id: u16, allocator: Allocator) !void {
    while (true) {
        const rcv_buf = try iface.capture_one_raw(allocator) orelse continue;
        var packet = Packet.create(allocator, allocator);
        defer packet.deinit();

        try packet.fromSlice(rcv_buf, link_layer_type.ETHERNET, null);

        if (packet.has_protocol_layer(.dns)) {
            var ipv4_layer: IPv4.IPv4Layer = packet.get_layer_of_type(IPv4.IPv4Layer) orelse {
                std.debug.print("no ipv4 layer.\n", .{});
                continue;
            };

            var ipv4_hdr: *const IPv4.IPv4Header = ipv4_layer.get_immutable_header();

            if (!std.mem.eql(u8, &ipv4_hdr.get_src_ip().array, &dst_ip.array)) continue;

            if (!std.mem.eql(u8, &ipv4_hdr.get_dst_ip().array, &src_ip.array)) continue;

            var udp_layer = packet.get_layer_of_type(UDP.UDPLayer) orelse {
                std.debug.print("no udp layer.\n", .{});
                continue;
            };

            const udp_hdr: *const UDP.UDPHeader = udp_layer.get_immutable_header();

            if (udp_hdr.get_src_port() != dst_port and udp_hdr.get_dst_port() != src_port) continue;

            var dns_layer: DNS.DNSLayer = packet.get_layer_of_type(DNS.DNSLayer) orelse {
                std.debug.print("no dns layer.\n", .{});
                continue;
            };

            const dns_hdr: *const DNS.DNSHeader = dns_layer.get_immutable_header();

            if (dns_hdr.get_id() != tx_id) {
                std.debug.print("tx_id mismatch.\n", .{});
                continue;
            }

            try print_query_section(&dns_layer, allocator);
            try print_answer_section(&dns_layer, allocator);
            try print_auth_section(&dns_layer, allocator);

            break;
        }
    }
}

fn print_query_section(dns_layer: *DNS.DNSLayer, allocator: Allocator) !void {
    var queries: DNS.Queries = try dns_layer.get_queries(allocator) orelse {
        return;
    };

    defer queries.deinit(allocator);

    var query = queries.first;
    if (query != null) std.debug.print("\nQUESTION SECTION:\n", .{});
    while (query) |q| {
        const str = try q.to_string(allocator);
        std.debug.print("{s}\n", .{str});
        allocator.free(str);
        query = q.next_query;
    }
}

fn print_answer_section(dns_layer: *DNS.DNSLayer, allocator: Allocator) !void {
    var answers: DNS.AnswerRecords = try dns_layer.get_answers(allocator) orelse {
        return;
    };

    defer answers.deinit(allocator);

    var answer = answers.first;

    if (answer != null) std.debug.print("\nANSWER SECTION:\n", .{});
    while (answer) |ans| {
        const str = try ans.to_string(allocator);
        std.debug.print("{s}\n", .{str});
        allocator.free(str);
        answer = ans.next();
    }
}

fn print_auth_section(dns_layer: *DNS.DNSLayer, allocator: Allocator) !void {
    var auth_answers: DNS.AnswerRecords = try dns_layer.get_auth_answers(allocator) orelse {
        return;
    };

    defer auth_answers.deinit(allocator);

    var auth_answer = auth_answers.first;
    if (auth_answer != null) std.debug.print("\nAUTHORITY SECTION:\n", .{});
    while (auth_answer) |ans| {
        const str = try ans.to_string(allocator);
        std.debug.print("{s}\n", .{str});
        allocator.free(str);
        auth_answer = ans.next();
    }
}
