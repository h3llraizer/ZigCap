const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const PcapWrapper = zigcap.PcapWrapper;
const IPv4 = zigcap.IPv4;

test "open network interface using PcapWrapper" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;

    print("starting...\n", .{});

    const allocator = debug_allocator.allocator();

    const wifi_iface_addr = try IPv4.IPv4Address.init_from_string("192.168.1.225");

    var wifi_iface = try PcapWrapper.open_pcap(wifi_iface_addr, allocator) orelse {
        print("failed to open interface.\n", .{});
        try expect(false); // failed to open interface
        return;
    };

    const str = wifi_iface.to_string(allocator);
    defer allocator.free(str);
}

//   pub fn send_packet(buf: []u8) !void {
//       var wifi_interface = try open_pcap() orelse {
//           return error.FailedToOpen;
//       };
//
//       try wifi_interface.send(buf);
//
//       print("No error during send.\n", .{});
//   }
