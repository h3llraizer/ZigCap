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

    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run ZigCap tests");
    test_step.dependOn(&run_tests.step);
}
