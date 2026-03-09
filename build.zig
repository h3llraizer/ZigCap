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
            .link_libc = true,
        }),
    });
    exe.addIncludePath(.{
        .cwd_relative = "third_party/WinDivert-2.2.2-A/include",
    });

    exe.addLibraryPath(.{
        .cwd_relative = "third_party/WinDivert-2.2.2-A/x64",
    });

    exe.addIncludePath(.{
        .cwd_relative = "third_party/npcap-sdk-1.15/Include",
    });

    exe.addLibraryPath(.{
        .cwd_relative = "third_party/npcap-sdk-1.15/Lib/x64",
    });

    // ---- Link libraries ----
    exe.linkSystemLibrary("Packet");
    exe.linkSystemLibrary("wpcap");
    exe.linkSystemLibrary("ws2_32");
    exe.linkSystemLibrary("Advapi32");
    exe.linkSystemLibrary("WinDivert");
    exe.linkSystemLibrary("iphlpapi");

    // Install WinDivert.dll next to the executable
    const windivert_dll = b.addInstallFile(
        b.path("third_party/WinDivert-2.2.2-A/x64/WinDivert.dll"),
        "bin/WinDivert.dll",
    );

    // Ensure DLL installs when you run `zig build`
    b.getInstallStep().dependOn(&windivert_dll.step);

    // Install WinDivert.dll next to the executable
    const windivert_driver = b.addInstallFile(
        b.path("third_party/WinDivert-2.2.2-A/x64/WinDivert64.sys"),
        "bin/WinDivert64.sys",
    );

    // Ensure DLL installs when you run `zig build`
    b.getInstallStep().dependOn(&windivert_driver.step);

    b.installArtifact(exe);

    // `zig build run`
    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    b.step("run", "Run the app").dependOn(&run_cmd.step);
}
