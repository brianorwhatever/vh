const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const vhlog = b.addModule("vhlog", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "vh-log-driver",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vhlog", .module = vhlog }},
        }),
    });
    b.installArtifact(exe);

    const tests = b.addTest(.{ .root_module = vhlog });
    const run_tests = b.addRunArtifact(tests);
    // The vector tests read ../../vectors relative to this package.
    run_tests.setCwd(b.path("."));
    const test_step = b.step("test", "Run unit, end-to-end and vector tests");
    test_step.dependOn(&run_tests.step);
}
