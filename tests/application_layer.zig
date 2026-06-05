const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const LayerOwner = zigcap.Owner.LayerOwner;
const LayerIface = zigcap.LayerIface;
const ApplicationLayer = zigcap.ApplicationLayer;

test "build generic layer independant" {
    //  print("========================== START ==========================\n", .{});
    //  print("build generic layer independant\n", .{});
    const page_allocator = std.heap.page_allocator;
    var app_layer_owner = LayerOwner{ .owned_buffer = .init_empty(page_allocator) };

    defer app_layer_owner.owned_buffer.buffer.deinit(std.heap.page_allocator);

    var app_layer_iface: LayerIface = try LayerIface.init(ApplicationLayer, app_layer_owner);

    try app_layer_iface.genericAppLayer.set_payload("hello");

    //    print("app layer data: {s}\n", .{app_layer_iface.to_string(page_allocator)});
    //  print("========================== END ==========================\n", .{});
}
