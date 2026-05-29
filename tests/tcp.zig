const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const LayerOwner = zigcap.Layer.LayerOwner;
const LayerIface = zigcap.LayerIface;
const TCP = zigcap.TCP;

test "parse tcp layer" {
    const tcp_syn_req: [40]u8 align(2) = [40]u8{ 0x30, 0x39, 0x0, 0x50, 0x0, 0x0, 0x3, 0xe8, 0x0, 0x0, 0x0, 0x0, 0xa0, 0x2, 0x20, 0x0, 0x2c, 0x3d, 0x0, 0x0, 0x2, 0x4, 0x5, 0xb4, 0x3, 0x3, 0x7, 0x8, 0xa, 0x6a, 0x18, 0xc3, 0x25, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var tcp_buf = try allocator.alignedAlloc(u8, std.mem.Alignment.@"2", tcp_syn_req.len);
    @memmove(tcp_buf[0..], tcp_syn_req[0..]);

    const tcp_owner: LayerOwner = LayerOwner{ .owned_buffer = try .init(tcp_buf, allocator) };
    // deinit'ing here causes stale ptr issue - this buffer gets mutated and attempts to free the original allocation - if an allocation mutation happens (size is increased or decreased), the allocator still has the original size so attempts to free a stale ptr or doesn't free the correct length. // TODO: Note this in docs

    var tcp_layer = try LayerIface.init(TCP.TCPLayer, tcp_owner);
    defer tcp_layer.deinit();

    var tcp_hdr = tcp_layer.tcpLayer.get_immutable_header();

    try expect(tcp_hdr.get_src_port() == 12345);
    try expect(tcp_hdr.get_dst_port() == 80);
    //try expect(tcp_hdr.get_seq_num() == 0xe8030000);
    print("seq num: {x}\n", .{tcp_hdr.get_seq_num()});
    try expect(tcp_hdr.get_ack_num() == 0);
    try expect(tcp_hdr.get_window() == 8192);
    try expect(tcp_hdr.get_checksum() == 11325);
    try expect(tcp_hdr.get_urgent_ptr() == 0);

    const tcp_flags = tcp_hdr.get_flags_immutable();

    try expect(tcp_flags.cwr == 0);
    try expect(tcp_flags.ece == 0);
    try expect(tcp_flags.urg == 0);
    try expect(tcp_flags.ack == 0);
    try expect(tcp_flags.psh == 0);
    try expect(tcp_flags.rst == 0);
    try expect(tcp_flags.syn == 1);
    try expect(tcp_flags.fin == 0);

    const hdr_length = tcp_hdr.get_hdr_length();

    try expect(hdr_length == 40);

    tcp_layer.tcpLayer.parse_tcp_options();

    //  const opt_buf = tcp_layer.tcpLayer.get_opt_buf();

    //  print("opt buf: ({}) {x}\n", .{ opt_buf.len, opt_buf });

    _ = tcp_layer.tcpLayer.has_option(.MSS);

    try tcp_layer.tcpLayer.remove_option(.MSS);

    const mss_val = [2]u8{ 0x05, 0xb4 };

    //_ = mss_val;

    try tcp_layer.tcpLayer.add_option(.MSS, &mss_val);

    //    try tcp_layer.tcpLayer.add_option(.NOP, null);

    print("option removed.\n", .{});

    print("has mss option: {any}\n", .{tcp_layer.tcpLayer.has_option(.MSS)});

    print("opt buf: ({}) {x}\n", .{ tcp_layer.tcpLayer.get_opt_buf().len, tcp_layer.tcpLayer.get_opt_buf() });

    if (tcp_layer.tcpLayer.get_opt_data(.WS)) |ws| {
        print("ws: {x}\n", .{ws});
    } else {
        print("ws data not found.\n", .{});
    }

    if (tcp_layer.tcpLayer.get_opt_data(.TS)) |ts| {
        print("ts: {x}\n", .{ts});
    } else {
        print("ts data not found.\n", .{});
    }

    if (tcp_layer.tcpLayer.get_opt_data(.MSS)) |mss| {
        print("mss: {x}\n", .{mss});
    } else {
        print("mss data not found.\n", .{});
    }

    //try expect(tcp_layer.tcpLayer.get_immutable_header().get_hdr_length() == 36);

    //    tcp_layer.tcpLayer.validate_layer(); // doesn't do anything for independant layer currently

    //try expect(tcp_layer.tcpLayer.get_immutable_header().get_checksum() == 10193);
}

test "build tcp layer independant" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const layer_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    var tcp_layer_iface: LayerIface = try LayerIface.init(TCP.TCPLayer, layer_owner);
    defer tcp_layer_iface.deinit();

    var tcp_hdr = tcp_layer_iface.tcpLayer.get_mutable_header();

    tcp_hdr.set_dst_port(1024);
    tcp_hdr.set_src_port(5005);
    tcp_hdr.set_seq_num(1234);

    //  print("seq_num: {}\n", .{tcp_hdr.get_seq_num()});

    tcp_hdr.set_window(8989);

    //    print("window: {}\n", .{tcp_hdr.get_window()});

    tcp_hdr.set_urgent_ptr(5);

    //    print("urgent_ptr: {}\n", .{tcp_hdr.get_urgent_ptr()});
}

test "tcp options" {
    //   const tcp_options = std.enums.values(TCP.TCPOption);
    //
    //   for (tcp_options) |option| {
    //       print("{any} (0x{x})\n", .{ option, @intFromEnum(option) });
    //   }
}
