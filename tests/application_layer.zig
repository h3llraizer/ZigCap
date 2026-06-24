const std = @import("std");
const print = std.debug.print;
const expect = std.testing.expect;

const zigcap = @import("zigcap");

const LayerOwner = zigcap.Owner.LayerOwner;
const Layer = zigcap.Layer;
const ApplicationLayer = zigcap.ApplicationLayer;

test "build generic layer independant" {
    //  print("========================== START ==========================\n", .{});
    //  print("build generic layer independant\n", .{});
    var dba: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dba.detectLeaks();

    const allocator = dba.allocator();

    var app_layer_iface: Layer = try Layer.init(ApplicationLayer, allocator);
    defer app_layer_iface.deinit();

    try app_layer_iface.genericAppLayer.set_payload("hello");

    //    print("app layer data: {s}\n", .{app_layer_iface.to_string(page_allocator)});
    //  print("========================== END ==========================\n", .{});
}
