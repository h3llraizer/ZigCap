const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const LayerOwner = zigcap.Layer.LayerOwner;
const LayerIface = zigcap.LayerIface;
const TCP = zigcap.TCP;

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
