const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // =========================
    // ZigCap module (public API)
    // =========================
    const mod = b.addModule("zigcap", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // Optional C library artifact
    const lib = b.addLibrary(.{
        .name = "zigcap",
        .linkage = .static,
        .root_module = mod,
    });

    // important line
    const npcap_path =
        b.option([]const u8, "npcap-sdk", "Path to Npcap SDK") orelse "third_party/npcap-sdk-1.15";

    const include_path = b.pathJoin(&.{ npcap_path, "Include" });
    const lib_path = b.pathJoin(&.{ npcap_path, "Lib", "x64" });

    mod.addIncludePath(.{ .cwd_relative = include_path });
    mod.addLibraryPath(.{ .cwd_relative = lib_path });

    mod.linkSystemLibrary("wpcap", .{});
    mod.linkSystemLibrary("Packet", .{});

    b.installArtifact(lib);

    // =========================
    // TESTS
    // =========================
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    // IMPORTANT: give tests access to your library module
    tests.root_module.addImport("zigcap", mod);

    tests.addIncludePath(.{ .cwd_relative = include_path });
    tests.addLibraryPath(.{ .cwd_relative = lib_path });

    tests.linkSystemLibrary("wpcap");
    tests.linkSystemLibrary("Packet");

    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run ZigCap tests");
    test_step.dependOn(&run_tests.step);
}
