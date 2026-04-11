// src/demo.zig
const std = @import("std");
const zigcap = @import("lib.zig");

pub fn main() !void {
    std.debug.print("ZigCap Demo\n", .{});
    std.debug.print("Version: {d}.{d}.{d}\n", .{
        zigcap.version.major,
        zigcap.version.minor,
        zigcap.version.patch,
    });

    zigcap.init();
    defer zigcap.deinit();

    std.debug.print("ZigCap initialized successfully!\n", .{});
}
