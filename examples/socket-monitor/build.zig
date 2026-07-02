const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const zigcap = b.addModule("zigcap", .{
        .root_source_file = b.path("../../src/root.zig"),
    });

    zigcap.addAfterIncludePath(.{
        .cwd_relative = "../../third_party/WinDivert-2.2.2-A/include/",
    });

    const mod = b.addModule("socket-monitor", .{
        .root_source_file = b.path("src/root.zig"),

        .target = target,

        .imports = &.{
            .{ .name = "zigcap", .module = zigcap },
        },

        .link_libc = true,
    });

    const exe = b.addExecutable(.{
        .name = "socket-monitor",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),

            .target = target,
            .optimize = optimize,

            .link_libc = true,

            .imports = &.{
                .{ .name = "socket-monitor", .module = mod },
                .{ .name = "zigcap", .module = zigcap },
            },
        }),
    });

    if (target.result.os.tag == .windows) {
        exe.addLibraryPath(.{
            .cwd_relative = "../../third_party/WinDivert-2.2.2-A/x64/",
        });

        exe.linkSystemLibrary("WinDivert");
    }

    exe.addIncludePath(.{
        .cwd_relative = "../../third_party/WinDivert-2.2.2-A/x64/",
    });

    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");

    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const mod_tests = b.addTest(.{
        .root_module = mod,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });

    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
}
