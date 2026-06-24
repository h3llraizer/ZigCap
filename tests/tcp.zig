const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const LayerOwner = zigcap.Owner.LayerOwner;
const Layer = zigcap.Layer;
const TCP = zigcap.TCP;

test "parse tcp layer" {
    var tcp_syn_req = [40]u8{ 0x30, 0x39, 0x0, 0x50, 0x0, 0x0, 0x3, 0xe8, 0x0, 0x0, 0x0, 0x0, 0xa0, 0x2, 0x20, 0x0, 0x2c, 0x3d, 0x0, 0x0, 0x2, 0x4, 0x5, 0xb4, 0x3, 0x3, 0x7, 0x8, 0xa, 0x6a, 0x18, 0xc3, 0x25, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var tcp_layer = try TCP.TCPLayer.initFromSlice(tcp_syn_req[0..], allocator);
    defer tcp_layer.deinit();

    var tcp_hdr = tcp_layer.get_immutable_header();

    try expect(tcp_hdr.get_src_port() == 12345);
    try expect(tcp_hdr.get_dst_port() == 80);
    //try expect(tcp_hdr.get_seq_num() == 0xe8030000);
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

    try expect(tcp_layer.has_option(.MSS));

    try expect(tcp_layer.has_option(.WS));

    try expect(tcp_layer.has_option(.TS));

    try tcp_layer.remove_option(.MSS);

    try tcp_layer.add_option(.MSS, &TCP.TCPOption.encode_mss(1460));

    if (tcp_layer.get_opt_data(.WS)) |ws| {
        try expect(TCP.TCPOption.decode_ws(ws[0]) == 128);
    } else {
        try expect(false); // failed to get ws data
    }

    if (tcp_layer.get_opt_data(.TS)) |ts| {
        const ts_vals = TCP.TCPOption.decode_ts(ts);

        try expect(ts_vals[0] == 1780007717);
        try expect(ts_vals[1] == 0);
    } else {
        try expect(false); // failed to get ts data
    }

    if (tcp_layer.get_opt_data(.MSS)) |mss| {
        try expect(TCP.TCPOption.decode_mss(mss) == 1460);
    } else {
        try expect(false); // failed to get mss data
    }

    const tsvals = TCP.TCPOption.encode_ts(1780007717, 0);

    _ = tsvals;

    try expect(TCP.TCPOption.encode_ws(128) == 7);

    try expect(tcp_layer.get_immutable_header().get_hdr_length() == 40);
}

test "build tcp layer independant" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var tcp_layer_iface: Layer = try Layer.init(TCP.TCPLayer, allocator);
    defer tcp_layer_iface.deinit();

    var tcp_hdr = tcp_layer_iface.tcpLayer.get_mutable_header();

    tcp_hdr.set_dst_port(1024);
    tcp_hdr.set_src_port(5005);
    tcp_hdr.set_seq_num(1234);

    //  print("seq_num: {}\n", .{tcp_hdr.get_seq_num()});

    tcp_hdr.set_window(8989);

    //    print("window: {}\n", .{tcp_hdr.get_window()});

    tcp_hdr.set_urgent_ptr(5);

    try expect(tcp_hdr.get_dst_port() == 1024);

    try expect(tcp_hdr.get_src_port() == 5005);

    //try expect(tcp_hdr.get_seq_num() == 1234);

    try expect(tcp_hdr.get_window() == 8989);

    try expect(tcp_hdr.get_urgent_ptr() == 5);

    //print("tcp hdr len: {}\n", .{tcp_hdr.get_hdr_length()});

    //    print("urgent_ptr: {}\n", .{tcp_hdr.get_urgent_ptr()});
}

test "tcp options" {
    //   const tcp_options = std.enums.values(TCP.TCPOption);
    //
    //   for (tcp_options) |option| {
    //       print("{any} (0x{x})\n", .{ option, @intFromEnum(option) });
    //   }
}
