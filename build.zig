const std = @import("std");

pub fn libbpfGetDependency(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Dependency {
    const libbpf_dep = b.dependency(
        "libbpf",
        .{
            .target = target,
            .optimize = optimize,
        },
    );

    return libbpf_dep;
}

pub fn libvaxisGetDependency(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Dependency {
    const libvaxis_dep = b.dependency("vaxis", .{
        .target = target,
        .optimize = optimize,
    });

    return libvaxis_dep;
}

pub fn libbpfGetSourceDependency(b: *std.Build) *std.Build.Dependency {
    return b.dependency("libbpf_src", .{});
}

pub fn vmlinuxGetSourceDependency(b: *std.Build) *std.Build.Dependency {
    return b.dependency("vmlinux_src", .{});
}

pub fn ebpfAddIncludePaths(b: *std.Build, mod: *std.Build.Module) void {
    mod.addIncludePath(b.path("src/bpf"));
}

pub fn ebpfModuleFromCSource(b: *std.Build, target: std.Build.ResolvedTarget, name: []const u8, path: []const u8) *std.Build.Module {
    const prog = b.addObject(.{
        .name = name,
        .root_module = b.createModule(.{
            .target = b.resolveTargetQuery(.{
                .cpu_arch = .bpfel,
                .os_tag = .freestanding,
            }),
            .optimize = .ReleaseFast,
            .strip = false,
        }),
    });

    prog.root_module.addCSourceFile(.{
        .file = b.path(path),
    });

    prog.root_module.addIncludePath(.{
        .dependency = .{
            .dependency = libbpfGetSourceDependency(b),
            .sub_path = "src",
        },
    });

    const arch_folder = switch (target.result.cpu.arch) {
        .x86_64 => "x86",
        .aarch64 => "arm64",
        .riscv64 => "riscv",
        .s390x => "s390x",
        .powerpc64le => "powerpc",
        .loongarch64 => "loongarch",
        else => @panic("This architecture is not supported by the vmlinux headers"),
    };

    prog.root_module.addIncludePath(.{
        .dependency = .{
            .dependency = vmlinuxGetSourceDependency(b),
            .sub_path = b.fmt("include/{s}", .{arch_folder}),
        },
    });

    const prog_obj = b.fmt("{s}.bpf.o", .{name});
    const prog_file = b.addWriteFiles();
    const prog_path = prog_file.addCopyFile(prog.getEmittedBin(), prog_obj);
    _ = prog_path;

    return b.createModule(.{
        .root_source_file = prog_file.add(
            b.fmt("{s}.zig", .{name}),
            b.fmt("pub const bytecode: []const u8 align(64) = @embedFile(\"{s}\");", .{prog_obj}),
        ),
    });
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const libbpf = libbpfGetDependency(b, target, optimize);
    const libvaxis = libvaxisGetDependency(b, target, optimize);

    const profileStreamingModule = ebpfModuleFromCSource(b, target, "profile_streaming", "src/bpf/profile_streaming.bpf.c");

    const mod = b.addModule("flametui", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "profile_streaming", .module = profileStreamingModule },
        },
        .link_libcpp = true,
    });

    ebpfAddIncludePaths(b, mod);
    mod.linkLibrary(libbpf.artifact("bpf"));
    mod.addImport("vaxis", libvaxis.module("vaxis"));

    // our program
    const exe = b.addExecutable(.{
        .name = "flametui",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "flametui", .module = mod },
            },
        }),
    });
    exe.root_module.addIncludePath(b.path("src"));

    b.installArtifact(exe);

    const lib_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "profile_streaming", .module = profileStreamingModule },
            },
        }),
    });

    lib_tests.root_module.linkLibrary(libbpf.artifact("bpf"));
    ebpfAddIncludePaths(b, lib_tests.root_module);

    const run_tests = b.addRunArtifact(lib_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
