const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // =========================
    // ZigCap module (public API)
    // =========================
    const mod = b.addModule("zigcap", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const lib = b.addLibrary(.{
        .name = "zigcap",
        .linkage = .static,
        .root_module = mod,
    });

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    // Check the target OS
    if (target.result.os.tag == .windows) {
        // Add Windows-specific build logic here
        std.debug.print("Building for Windows\n", .{});

        const npcap_path =
            b.option([]const u8, "npcap-sdk", "Path to Npcap SDK") orelse "third_party/npcap-sdk-1.15";

        const np_include_path = b.pathJoin(&.{ npcap_path, "Include" });
        const np_lib_path = b.pathJoin(&.{ npcap_path, "Lib", "x64" });

        mod.addIncludePath(.{ .cwd_relative = np_include_path });
        mod.addLibraryPath(.{ .cwd_relative = np_lib_path });

        mod.linkSystemLibrary("wpcap", .{});
        mod.linkSystemLibrary("Packet", .{});

        const wind_path =
            b.option([]const u8, "wind_sdk", "Path to WinDivert SDK") orelse "third_party/WinDivert-2.2.2-A/";

        const wd_include_path = b.pathJoin(&.{ wind_path, "include" });
        const wd_lib_path = b.pathJoin(&.{ wind_path, "x64" });

        mod.addIncludePath(.{ .cwd_relative = wd_include_path });
        mod.addLibraryPath(.{ .cwd_relative = wd_lib_path });

        mod.linkSystemLibrary("ws2_32", .{});
        mod.linkSystemLibrary("Advapi32", .{});
        mod.linkSystemLibrary("WinDivert", .{});
        mod.linkSystemLibrary("iphlpapi", .{});

        tests.root_module.addImport("zigcap", mod);

        tests.addIncludePath(.{ .cwd_relative = np_include_path });
        tests.addLibraryPath(.{ .cwd_relative = np_lib_path });

        tests.linkSystemLibrary("wpcap");
        tests.linkSystemLibrary("Packet");

        tests.addIncludePath(.{ .cwd_relative = wd_include_path });
        tests.addLibraryPath(.{ .cwd_relative = wd_lib_path });

        tests.linkSystemLibrary("ws2_32");
        tests.linkSystemLibrary("Advapi32");
        tests.linkSystemLibrary("WinDivert");
        tests.linkSystemLibrary("iphlpapi");
    } else if (target.result.os.tag == .linux) {
        std.debug.print("Building for Linux\n", .{});
        mod.linkSystemLibrary("pcap", .{});
    } else if (target.result.os.tag == .macos) {
        std.debug.print("Building for macOS\n", .{});
    }
    // Create documentation
    const install_docs = b.addInstallDirectory(.{
        .source_dir = lib.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });

    const docs_step = b.step("docs", "Install docs into zig-out/docs");
    docs_step.dependOn(&install_docs.step);

    b.installArtifact(lib);

    // =========================
    // TESTS
    // =========================

    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run ZigCap tests");
    test_step.dependOn(&run_tests.step);
}
