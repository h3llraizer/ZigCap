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

// constants
const dns_ip = IPv4.IPv4Address.init_from_array(.{ 1, 1, 1, 1 });

const google_dns_ip = IPv4.IPv4Address.init_from_array(.{ 8, 8, 8, 8 });

const google_dns_ipv6 = IPv6.IPv6Address.init_from_array(.{
    0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88,
});

var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
const allocator = debug_allocator.allocator();

var curl: ?*anyopaque = null;

const ResponseBuffer = struct {
    data: std.ArrayList(u8),
};

fn curlWriteCallback(ptr: ?*anyopaque, size: usize, nmemb: usize, userdata: ?*anyopaque) callconv(.c) usize {
    const real_size = size * nmemb;

    const resp: *ResponseBuffer = @ptrCast(@alignCast(userdata.?));
    const bytes: [*]u8 = @ptrCast(ptr);

    resp.data.appendSlice(allocator, bytes[0..real_size]) catch return 0;

    return real_size;
}

fn get_dns_response(query: []u8) ![]u8 {
    // ---- Force HTTP/2 (optional but matches CLI) ----
    _ = c.curl_easy_setopt(curl, c.CURLOPT_HTTP_VERSION, c.CURL_HTTP_VERSION_2_0);

    // ---- URL ----
    _ = c.curl_easy_setopt(curl, c.CURLOPT_URL, "https://1.1.1.1/dns-query");

    // ---- POST ----
    _ = c.curl_easy_setopt(curl, c.CURLOPT_POST, @as(c_long, 1));

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

    return response.data.toOwnedSlice(allocator);
}

fn ip_change(ipv4_layer: *IPv4.IPv4Layer) void {
    const ipv4_header: *IPv4.IPv4Header = ipv4_layer.get_mutable_header();

    if (std.mem.eql(u8, &ipv4_header.get_dst_ip().array, &.{ 8, 8, 8, 8 })) {
        ipv4_header.set_dst_ip(dns_ip);
    }

    if (std.mem.eql(u8, &ipv4_header.get_src_ip().array, &dns_ip.array)) {
        ipv4_header.set_src_ip(IPv4.IPv4Address.init_from_array(.{ 8, 8, 8, 8 }));
    }
}

fn mutate_packet(data: []u8) ![]const u8 {
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
        allocator.free(str);

        query = q.next_query;
    }

    const ans_layer = try get_dns_response(dns_layer.get_data());

    var new_dns_layer = try DNS.DNSLayer.initFromSlice(ans_layer, allocator);
    defer new_dns_layer.deinit();

    allocator.free(ans_layer);

    var layer = Layer{ .dnsLayer = new_dns_layer };

    if (!dns_layer.owner.is_packet_owned()) {
        @panic("invalid ownership of dns layer.\n");
    }

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

fn nfq_callback(qh: ?*c.struct_nfq_q_handle, nfmsg: ?*c.struct_nfgenmsg, nfa: ?*c.struct_nfq_data, data: ?*anyopaque) callconv(.c) c_int {
    defer _ = debug_allocator.detectLeaks();

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

    defer allocator.free(copy);

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

    var buf: [4096]u8 = undefined;

    while (true) {
        const rv = try std.posix.recv(fd, buf[0..], 0);
        if (rv >= 0) {
            _ = c.nfq_handle_packet(h, &buf, @intCast(rv));
        }
    }

    _ = c.nfq_destroy_queue(qh);
    _ = c.nfq_close(h);
}

//   fn cb(
//       qh: ?*c.struct_nfq_q_handle,
//       nfmsg: ?*c.struct_nfgenmsg,
//       nfa: ?*c.struct_nfq_data,
//       data: ?*anyopaque,
//   ) callconv(.c) c_int {
//       const ph = c.nfq_get_msg_packet_hdr(nfa);
//       if (ph == null) return c.NF_ACCEPT;
//
//       _ = nfmsg;
//       _ = data;
//
//       const id: u32 = @intCast(c.ntohl(ph.*.packet_id));
//
//       var payload_ptr: [*c]u8 = undefined;
//
//       const len = c.nfq_get_payload(nfa, &payload_ptr);
//
//       const pkt: []u8 = payload_ptr[0..@intCast(len)];
//
//       const ipv4_header: *IPv4.IPv4Header = @ptrCast(pkt.ptr);
//
//       if (std.mem.eql(u8, &ipv4_header.get_dst_ip().array, &.{ 8, 8, 8, 8 })) {
//           ipv4_header.set_dst_ip(dns_ip);
//
//           ipv4_header.calculate_checksum(pkt[0..20]);
//
//           const udp_header: *UDP.UDPHeader = @ptrCast(pkt[20..]);
//           udp_header.calculate_checksum(
//               ipv4_header.get_src_ip().array,
//               ipv4_header.get_dst_ip().array,
//               pkt[28..],
//           );
//       }
//
//       if (std.mem.eql(u8, &ipv4_header.get_src_ip().array, &dns_ip.array)) {
//           ipv4_header.set_src_ip(IPv4.IPv4Address.init_from_array(.{ 8, 8, 8, 8 }));
//
//           ipv4_header.calculate_checksum(pkt[0..20]);
//
//           const udp_header: *UDP.UDPHeader = @ptrCast(pkt[20..]);
//           udp_header.calculate_checksum(
//               ipv4_header.get_src_ip().array,
//               ipv4_header.get_dst_ip().array,
//               pkt[28..],
//           );
//       }
//
//       return c.nfq_set_verdict(qh, id, c.NF_ACCEPT, @intCast(len), pkt.ptr);
//   }
