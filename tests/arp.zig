const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const LayerOwner = zigcap.Layer.LayerOwner;
const LayerIface = zigcap.LayerIface;
const Eth = zigcap.Eth;
const ARP = zigcap.ARP;
const IPv4 = zigcap.IPv4;

test "build arp layer" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;

    var allocator = debug_allocator.allocator();

    const arp_owner: LayerOwner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    var arp_layer_iface = try LayerIface.init(ARP.ARPLayer, arp_owner);

    defer _ = debug_allocator.detectLeaks();
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
