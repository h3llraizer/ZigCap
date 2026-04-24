const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const Packet = zigcap.Packet.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const tcp_ip_protocol = zigcap.tcp_ip_protocol;

const DNS = zigcap.DNS;

test "parse dns packet" {
    const ziggit_dev_a_resp: [97]u8 = [_]u8{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x8, 0x0, 0x45, 0x0, 0x0, 0x53, 0xd, 0x2a, 0x40, 0x0, 0x40, 0x11, 0xa8, 0x40, 0xc0, 0xa8, 0x1, 0xfe, 0xc0, 0xa8, 0x1, 0xe1, 0x0, 0x35, 0xee, 0x99, 0x0, 0x3f, 0x26, 0xd1, 0x5a, 0xf2, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x6, 0x7a, 0x69, 0x67, 0x67, 0x69, 0x74, 0x3, 0x64, 0x65, 0x76, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x3, 0x56, 0x0, 0x4, 0xaa, 0xbb, 0xcb, 0x4d, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const allocator = debug_allocator.allocator();

    var raw_packet_buffer: std.array_list.Aligned(u8, std.mem.Alignment.@"2") = .empty;
    //    defer raw_packet_buffer.deinit(allocator); - doesn't need to be called because Packet takes ownership but it is still safe to do so

    try raw_packet_buffer.appendSlice(allocator, &ziggit_dev_a_resp);

    const original_raw_packet_buffer_len = raw_packet_buffer.items.len;

    var packet = try Packet.create(allocator, allocator);
    try packet.from_raw(allocator, &raw_packet_buffer, link_layer_type.ETHERNET, null);
    defer packet.deinit();

    try expect(packet.get_layer_count() == 4);

    packet.print_layers_meta();

    if (packet.first_layer) |first| {
        print("first layer data: {x}\n", .{first.get_data()});
    }

    try expect(packet.last_layer.?.layer_iface.get_protocol() == tcp_ip_protocol.dns);

    const dns_layer: *DNS.DNSLayer = packet.get_layer_of_type(DNS.DNSLayer) orelse {
        try expect(false); // packet did not have DNS layer
        return;
    };

    const hdr = dns_layer.get_immutable_header();
    print("{any}\n", .{hdr});

    //    try dns_layer.get_queries();
    try dns_layer.get_answers();

    var count: usize = 0;
    var cur = dns_layer.first_answer;
    try expect(dns_layer.first_answer != null);
    while (cur) |answer| {
        count += 1;
        const name = try answer.get_name(allocator);
        defer allocator.free(name);
        print("{}. {s} {any} {any} ", .{ count, name, answer.get_rr_type(), answer.get_class_type() });

        if (answer.get_rr_type() == DNS.QueryType.A) {
            const ip = answer.a.get_ip() orelse {
                print("(null)\n", .{});
                cur = answer.get_next_record();
                continue;
            };

            const ip_str = try ip.to_string(allocator);
            defer allocator.free(ip_str);
            print("{s}", .{ip_str});
        }

        print("\n", .{});

        cur = answer.get_next_record();
    }

    print("end of parsing of DNS packet.\n", .{});

    print("original_raw_packet_buffer_len: {}\n", .{original_raw_packet_buffer_len});

    const original_raw_packet_buffer = raw_packet_buffer.items;

    try expect(original_raw_packet_buffer.len == 0);

    print("packet buf: {}\n", .{packet.get_raw().len});

    print("original: {x}\n", .{raw_packet_buffer.items});
}
