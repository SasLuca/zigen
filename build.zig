const std = @import("std");

const build_root: []const u8 = struct
{
    fn getBuildRoot() []const u8
    {
        return std.fs.path.dirname(@src().file).?;
    }
}.getBuildRoot();

pub fn getPackage(name: []const u8) std.build.Pkg
{
    return std.build.Pkg{
        .name = name,
        .path = .{ .path = build_root ++ "/src/zigen.zig" },
        .dependencies = null, // null by default, but can be set to a slice of `std.build.Pkg`s that your package depends on.
    };
}

pub fn basicExample(b: *std.build.Builder, name: []const u8) *std.build.LibExeObjStep
{
    const exe = b.addExecutable(name, build_root ++ "/examples/basic-example.zig");
    exe.addPackage(getPackage("zigen"));
    return exe;
}

pub fn build(b: *std.build.Builder) void 
{
    std.debug.assert((std.fs.path.relative(b.allocator, b.build_root, build_root) catch unreachable).len == 0);
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const tls_test = b.step("test", "Run unit tests directly.");
    const tls_test_exe = b.step("test-exe", "Produce unit test executable.");
    const tls_basic_example = b.step("basic-example", "Produce basic example executable.");
    const opt_run = b.option(bool, "run", "Run targeted exe(s).") orelse false;

    tls_test_exe.dependOn(b.getInstallStep());
    tls_basic_example.dependOn(b.getInstallStep());

    const basic_example_exe = basicExample(b, "zigen-basic-example");
    const basic_example_exe_run = basic_example_exe.run();
    basic_example_exe.setBuildMode(mode);
    basic_example_exe.setTarget(target);
    basic_example_exe.install();
    tls_basic_example.dependOn(&basic_example_exe.step);
    if (opt_run) tls_basic_example.dependOn(&basic_example_exe_run.step);

    const test_exe = b.addTestExe("test", build_root ++ "/src/zigen.zig");
    const test_exe_run = test_exe.run();
    test_exe.setBuildMode(mode);
    test_exe.setTarget(target);
    test_exe.install();
    tls_test_exe.dependOn(&test_exe.step);
    if (opt_run) tls_test_exe.dependOn(&test_exe_run.step);

    const test_runner = b.addTest("src/zigen.zig");
    test_runner.setBuildMode(mode);
    test_runner.setTarget(target);
    tls_test.dependOn(&test_runner.step);
}
