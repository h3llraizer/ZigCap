const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "packetcapture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    exe.addIncludePath(.{
        .cwd_relative = "C:/Users/user/Downloads/npcap-sdk-1.15/Include",
    });

    exe.addLibraryPath(.{
        .cwd_relative = "C:/Users/user/Downloads/npcap-sdk-1.15/Lib/x64",
    });

    // ---- Link libraries ----
    exe.linkSystemLibrary("Packet");
    exe.linkSystemLibrary("wpcap");
    exe.linkSystemLibrary("ws2_32");
    exe.linkSystemLibrary("Advapi32");

    b.installArtifact(exe);

    // `zig build run`
    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    b.step("run", "Run the app").dependOn(&run_cmd.step);
}
