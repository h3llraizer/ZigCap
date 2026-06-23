const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const LayerOwner = zigcap.Owner.LayerOwner;
const LayerIface = zigcap.LayerIface;
const Eth = zigcap.Eth;
const ARP = zigcap.ARP;
const IPv4 = zigcap.IPv4;

test "init arplayer from slice" {
    var data = [_]u8{ 0x0, 0x1, 0x8, 0x0, 0x6, 0x4, 0x0, 0x1, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0xc0, 0xa8, 0x1, 0xfe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc0, 0xa8, 0x1, 0xe1 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var arp_layer: ARP.ARPLayer = try ARP.ARPLayer.initFromSlice(data[0..], allocator);
    defer arp_layer.deinit();

    const hdr = arp_layer.get_immutable_header();

    try expect(hdr.get_hardware_type() == .Eth);
    try expect(hdr.get_protocol_type() == .IP);
    try expect(hdr.get_hardware_size() == 6);
    try expect(hdr.get_protocol_size() == 4);
    try expect(hdr.get_opcode() == .Request);
    try expect(std.mem.eql(u8, &hdr.get_sender_mac().addr, &(try Eth.MacAddress.init_from_string("38:06:e6:92:63:ac")).addr));

    try expect(std.mem.eql(u8, &hdr.get_sender_ip().array, &(try IPv4.IPv4Address.init_from_string("192.168.1.254")).array));

    try expect(std.mem.eql(u8, &hdr.get_target_mac().addr, &(try Eth.MacAddress.init_from_string("00:00:00:00:00:00")).addr));

    try expect(std.mem.eql(u8, &hdr.get_target_ip().array, &(try IPv4.IPv4Address.init_from_string("192.168.1.225")).array));
}

test "build arp layer" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    var allocator = debug_allocator.allocator();

    var arp_layer_iface = try LayerIface.init(ARP.ARPLayer, allocator);
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
