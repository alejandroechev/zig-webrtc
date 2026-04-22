const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main library module
    const mod = b.addModule("zig-webrtc", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // OpenSSL paths (Windows)
    mod.addIncludePath(.{ .cwd_relative = "C:/Program Files/OpenSSL-Win64/include" });
    mod.addObjectFile(.{ .cwd_relative = "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD/libssl.lib" });
    mod.addObjectFile(.{ .cwd_relative = "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD/libcrypto.lib" });

    // Winsock2 (for transport module)
    mod.linkSystemLibrary("ws2_32", .{});

    // Static library artifact
    const lib = b.addLibrary(.{
        .name = "zig-webrtc",
        .root_module = mod,
    });
    b.installArtifact(lib);

    // Tests
    const lib_unit_tests = b.addTest(.{
        .root_module = mod,
    });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    // Example executable
    const exe = b.addExecutable(.{
        .name = "zig-webrtc-example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "zig-webrtc", .module = mod },
            },
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    const run_step = b.step("run", "Run the example");
    run_step.dependOn(&run_cmd.step);

    // Interop agent executable (stdin/stdout signaling bridge)
    const interop_exe = b.addExecutable(.{
        .name = "zig-webrtc-interop",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/interop/agent.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "zig-webrtc", .module = mod },
            },
        }),
    });
    b.installArtifact(interop_exe);

    const interop_run = b.addRunArtifact(interop_exe);
    const interop_step = b.step("interop", "Run the interop agent");
    interop_step.dependOn(&interop_run.step);
}
