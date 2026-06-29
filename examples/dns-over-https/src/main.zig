const std = @import("std");

const c = @cImport({
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("stddef.h");
    @cInclude("arpa/inet.h");
    @cInclude("linux/netfilter.h");
    @cInclude("libnetfilter_queue/libnetfilter_queue.h");
    @cInclude("curl/curl.h");
});

const zigcap = @import("zigcap");

const Packet = zigcap.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const IPv4 = zigcap.IPv4;
const IPv6 = zigcap.IPv6;
const UDP = zigcap.UDP;
const DNS = zigcap.DNS;
const Layer = zigcap.Layer;
const LayerOwner = zigcap.Owner.LayerOwner;

const print = std.debug.print;
const Allocator = std.mem.Allocator;

// Stack allocator
var backing_buffer: [4096]u8 = .{0x00} ** 4096;
var fba: std.heap.FixedBufferAllocator = .init(&backing_buffer);
const allocator = fba.allocator();

// CURL consts and vars
var curl: ?*anyopaque = null;
const DEFAULT_URL = "https://1.1.1.1/dns-query";

// Wrapper around std.ArrayList
const ResponseBuffer = struct {
    data: std.ArrayList(u8),
};

// no free's do anything meaningful in this context because FixedBufferAllocator is in use

fn curlWriteCallback(ptr: ?*anyopaque, size: usize, nmemb: usize, userdata: ?*anyopaque) callconv(.c) usize {
    const real_size = size * nmemb;

    const resp: *ResponseBuffer = @ptrCast(@alignCast(userdata.?));
    const bytes: [*]u8 = @ptrCast(ptr);

    resp.data.appendSlice(allocator, bytes[0..real_size]) catch return 0;

    return real_size;
}

fn get_dns_response(query: []u8) ![]u8 {

    // ---- raw DNS wireformat body ----
    _ = c.curl_easy_setopt(curl, c.CURLOPT_POSTFIELDS, query.ptr);
    _ = c.curl_easy_setopt(curl, c.CURLOPT_POSTFIELDSIZE, @as(c_long, @intCast(query.len)));

    // ---- headers ----
    var headers = c.curl_slist_append(null, "content-type: application/dns-message");
    headers = c.curl_slist_append(headers, "accept: application/dns-message");
    defer c.curl_slist_free_all(headers);

    _ = c.curl_easy_setopt(curl, c.CURLOPT_HTTPHEADER, headers);

    var response = ResponseBuffer{ .data = .empty };

    _ = c.curl_easy_setopt(curl, c.CURLOPT_WRITEFUNCTION, curlWriteCallback);
    _ = c.curl_easy_setopt(curl, c.CURLOPT_WRITEDATA, &response);

    const res = c.curl_easy_perform(curl);
    if (res != c.CURLE_OK) {
        return error.RequestFailed;
    }

    //var namelookup: f64 = 0;
    var connect: f64 = 0;
    var appconnect: f64 = 0;
    var starttransfer: f64 = 0;
    var total: f64 = 0;

    //_ = c.curl_easy_getinfo(curl, c.CURLINFO_NAMELOOKUP_TIME, &namelookup);
    _ = c.curl_easy_getinfo(curl, c.CURLINFO_CONNECT_TIME, &connect);
    _ = c.curl_easy_getinfo(curl, c.CURLINFO_APPCONNECT_TIME, &appconnect);
    _ = c.curl_easy_getinfo(curl, c.CURLINFO_STARTTRANSFER_TIME, &starttransfer);
    _ = c.curl_easy_getinfo(curl, c.CURLINFO_TOTAL_TIME, &total);

    //print("DNS: {d} ms\n", .{namelookup * 1000});
    print("Connect: {d} ms\n", .{connect * 1000});
    print("TLS: {d} ms\n", .{appconnect * 1000});
    print("TTFB: {d} ms\n", .{starttransfer * 1000});
    print("Total: {d} ms\n", .{total * 1000});

    return response.data.toOwnedSlice(allocator);
}

fn mutate_packet(data: []u8) ![]const u8 {
    //defer _ = debug_allocator.detectLeaks();
    const buf = try allocator.alloc(u8, data.len);
    @memmove(buf, data);

    var packet = Packet.create(allocator, allocator);
    defer packet.deinit();

    try packet.fromSlice(buf, link_layer_type.RAW, null);

    if (!packet.has_protocol_layer(.dns)) {
        return packet.buffer.buffer.toOwnedSlice(allocator);
    }

    var dns_layer = packet.get_layer_of_type(DNS.DNSLayer) orelse {
        return packet.buffer.buffer.toOwnedSlice(allocator);
    };

    const dns_hdr: *DNS.DNSHeader = dns_layer.get_mutable_header();

    if (dns_hdr.get_qr()) {
        return packet.buffer.buffer.toOwnedSlice(allocator);
    }

    var queries: DNS.Queries = try dns_layer.get_queries(allocator) orelse {
        return packet.buffer.buffer.toOwnedSlice(allocator);
    };

    defer queries.deinit(allocator);

    var query = queries.first;
    while (query) |q| {
        const str = try q.to_string(allocator);
        print("{s}\n", .{str});

        query = q.next_query;
    }

    const ans_layer = try get_dns_response(dns_layer.get_data());

    var new_dns_layer = try DNS.DNSLayer.initFromSlice(ans_layer, allocator);
    defer new_dns_layer.deinit();

    var layer = Layer{ .dnsLayer = new_dns_layer };

    _ = try packet.delete_layer(Layer{ .dnsLayer = dns_layer });

    try packet.add_layer(&layer);

    if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ipv4_layer| {
        const ipv4_header: *IPv4.IPv4Header = ipv4_layer.get_mutable_header();

        const src_ip = ipv4_header.get_src_ip();
        const dst_ip = ipv4_header.get_dst_ip();

        ipv4_header.set_src_ip(dst_ip);
        ipv4_header.set_dst_ip(src_ip);
    }

    if (packet.get_layer_of_type(UDP.UDPLayer)) |udp_layer| {
        const udp_header: *UDP.UDPHeader = udp_layer.get_mutable_header();

        const src_port = udp_header.get_src_port();
        const dst_port = udp_header.get_dst_port();

        udp_header.set_src_port(dst_port);
        udp_header.set_dst_port(src_port);
    }

    packet.validate_packet();

    return try packet.buffer.buffer.toOwnedSlice(allocator);
}

fn nfq_callback(
    qh: ?*c.struct_nfq_q_handle,
    nfmsg: ?*c.struct_nfgenmsg,
    nfa: ?*c.struct_nfq_data,
    data: ?*anyopaque,
) callconv(.c) c_int {
    //defer _ = debug_allocator.detectLeaks();

    defer fba.reset();

    var timer = std.time.Timer.start() catch null;

    _ = &timer;

    if (timer) |*t| {
        defer t.reset();
        defer print("Entire process time: {}\n", .{t.read()});
    }

    const ph = c.nfq_get_msg_packet_hdr(nfa);
    if (ph == null) return c.NF_ACCEPT;

    _ = nfmsg;
    _ = data;

    const id: u32 = @intCast(c.ntohl(ph.*.packet_id));

    var payload_ptr: [*c]u8 = undefined;

    const len = c.nfq_get_payload(nfa, &payload_ptr);

    const pkt: []u8 = payload_ptr[0..@intCast(len)];

    const copy = mutate_packet(pkt) catch |err| {
        print("{s}\n", .{@errorName(err)});
        return 0;
    };

    const res = c.nfq_set_verdict(qh, id, c.NF_ACCEPT, @intCast(copy.len), copy.ptr);

    return res;
}

pub fn main() !void {
    curl = c.curl_easy_init();
    if (curl == null) {
        print("curl init failed\n", .{});
        return;
    }
    defer c.curl_easy_cleanup(curl);

    _ = c.curl_easy_setopt(curl, c.CURLOPT_HTTP_VERSION, c.CURL_HTTP_VERSION_2_0);

    // ---- URL ----
    _ = c.curl_easy_setopt(curl, c.CURLOPT_URL, DEFAULT_URL);

    // ---- POST ----
    _ = c.curl_easy_setopt(curl, c.CURLOPT_POST, @as(c_long, 1));

    const h = c.nfq_open();
    if (h == null) {
        print("nfq_open failed\n", .{});
        return;
    }

    const qh = c.nfq_create_queue(h, 0, nfq_callback, null);
    if (qh == null) {
        print("nfq_create_queue failed\n", .{});
        _ = c.nfq_close(h);
        return;
    }

    if (c.nfq_set_mode(qh, c.NFQNL_COPY_PACKET, 0xffff) < 0) {
        print("nfq_set_mode failed\n", .{});
        _ = c.nfq_destroy_queue(qh);
        _ = c.nfq_close(h);
        return;
    }

    const fd = c.nfq_fd(h);

    var buf: [4096]u8 = .{0x00} ** 4096;

    while (true) {
        const rv = try std.posix.recv(fd, buf[0..], 0);
        if (rv >= 0) {
            _ = c.nfq_handle_packet(h, &buf, @intCast(rv));
        }
    }

    _ = c.nfq_destroy_queue(qh);
    _ = c.nfq_close(h);
}
