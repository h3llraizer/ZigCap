const std = @import("std");
const zigcap = @import("zigcap");

const Packet = zigcap.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const LayerOwner = zigcap.Owner.LayerOwner;
const TLVOwner = zigcap.Owner.TLVOwner;
const Layer = zigcap.Layer;
const IPv4 = zigcap.IPv4;
const Eth = zigcap.Eth;
const UDP = zigcap.UDP;

const print = std.debug.print;
const expect = std.testing.expect;

const IPProtocol = zigcap.ProtocolEnums.IPProtocol;

pub fn get_mutable_header(header: anytype, data: []u8) *header {
    const aligned_ptr: [*]align(@alignOf(header)) u8 = @alignCast(data.ptr);
    return @ptrCast(aligned_ptr);
}

test "ipv4 init" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var ipv4_layer: IPv4.IPv4Layer = try IPv4.IPv4Layer.init(allocator);

    defer ipv4_layer.deinit();

    //print("{x}\n", .{ipv4_layer.owner.get_data()});

    //print("{x}\n", .{ipv4_layer.get_data()});

    var str = try ipv4_layer.to_string(allocator);
    //print("{s}\n", .{str});
    allocator.free(str);

    var ipv4_layer_iface: Layer = try Layer.init(IPv4.IPv4Layer, allocator);

    defer ipv4_layer_iface.deinit();

    //print("{x}\n", .{ipv4_layer_iface.get_data()});

    str = try ipv4_layer_iface.to_string(allocator);
    //print("{s}\n", .{str});
    allocator.free(str);

    const ipv4_header: *IPv4.IPv4Header = get_mutable_header(IPv4.IPv4Header, ipv4_layer_iface.get_data());
    const str_h = try ipv4_header.to_string(allocator);
    //print("{s}\n", .{str_h});
    allocator.free(str_h);
}
