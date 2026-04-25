const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const LayerOwner = zigcap.Layer.LayerOwner;
const LayerIface = zigcap.LayerIface;
const TCP = zigcap.TCP;

test "parse tcp layer" {
    const tcp_syn_req: [32]u8 align(2) = [_]u8{
        // ----- TCP Header (20 bytes minimum, but options extend to 32 bytes total) -----

        // Source Port (2 bytes) - 0x7f91 = 32657
        0x7f, 0x91, // Src Port: 32657

        // Destination Port (2 bytes) - 0x138d = 5005
        0x13, 0x8d, // Dst Port: 5005

        // Sequence Number (4 bytes) - 0xe44b4aa5
        0xe4, 0x4b, 0x4a, 0xa5, //

        // Acknowledgment Number (4 bytes) - 0x00000000 (zero for SYN)
        0x00, 0x00, 0x00, 0x00, // Ack Number: 0 (SYN doesn't acknowledge anything)

        // Data Offset (4 bits) + Reserved (3 bits) + Flags (9 bits, but 8 shown)
        // 0x80 = 128 decimal = binary: 1000 0000
        // Bits: data offset (4 bits = 8) + reserved (3 bits = 0) + flags include SYN
        0x80, // Offset=8 (32-byte header) + Reserved=0 + flags (NS/CWR/ECE/URG/ACK/PSH/RST/SYN/FIN)
        // With SYN flag set (the 0x02 bit would be in next byte typically)

        // Flags continued + Window Size
        // 0x02 = SYN flag set, 0xff = window size high byte, 0xff = window size low byte
        0x02, // TCP flags: SYN=1, all other flags 0
        0xff, 0xff, // Window Size: 65535 (maximum window)

        // TCP Checksum (2 bytes) - 0x27d1 = 10193
        0x27, 0xd1, // Checksum (covers TCP header + data)

        // Urgent Pointer (2 bytes) - 0x0000 (not used for SYN)
        0x00, 0x00, // Urgent Pointer: 0

        // ----- TCP Options (12 bytes, making total header 32 bytes) -----

        // Option 1: Maximum Segment Size (MSS)
        0x02, // Kind=2 (MSS option)
        0x04, // Length=4 bytes total (including Kind & Length)
        0x05, 0xb4, // MSS value: 0x05b4 = 1460 bytes

        // Option 2: Window Scale (WS)
        0x01, // Kind=1 (No-Operation padding, often precedes WS)
        0x03, // Kind=3 (Window Scale option)
        0x03, // Length=3 bytes total
        0x08, // Shift count = 8 (window scale factor of 256)

        // Option 3: Timestamp (TS) - usually 10 bytes, but might be truncated or SACK
        0x01, // Kind=1 (No-Operation padding)
        0x01, // Kind=1 (No-Operation padding again)
        0x04, // Kind=4 (SACK Permitted option)
        0x02, // Length=2 bytes total (SACK permitted)

        // Note: This leaves 2 bytes unaccounted for (maybe padding to 32 bytes)
        // A complete TCP timestamp option would be 10 bytes: 0x08, 0x0a, [4 bytes TSval], [4 bytes TSecr]
    };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const tcp_buf = try allocator.alignedAlloc(u8, std.mem.Alignment.@"2", tcp_syn_req.len);
    @memmove(tcp_buf, tcp_syn_req[0..]);

    var tcp_owner: LayerOwner = LayerOwner{ .owned_buffer = try .init(tcp_buf, allocator) };
    defer _ = tcp_owner.owned_buffer.deinit();

    var tcp_layer = try LayerIface.init(TCP.TCPLayer, tcp_owner);

    var tcp_hdr = tcp_layer.tcpLayer.get_immutable_header();

    print("src_port: {}\n", .{tcp_hdr.get_src_port()});
    print("dst_port: {}\n", .{tcp_hdr.get_dst_port()});
    print("seq_num: {}\n", .{tcp_hdr.get_seq_num()});
    print("ack_num: {}\n", .{tcp_hdr.get_ack_num()});
    print("window: {}\n", .{tcp_hdr.get_window()});
    print("checksum: {x}\n", .{tcp_hdr.get_checksum()});
    print("urgent_ptr: {}\n", .{tcp_hdr.get_urgent_ptr()});

    const tcp_flags = tcp_hdr.get_flags_immutable();

    print("{any}\n", .{tcp_flags});

    const hdr_length = tcp_hdr.get_hdr_length();

    print("length: {}\n", .{hdr_length});

    tcp_layer.tcpLayer.parse_tcp_options();
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
