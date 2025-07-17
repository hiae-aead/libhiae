const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseFast });
    const version = std.SemanticVersion.parse("0.1.0") catch unreachable;

    const lib = b.addLibrary(.{
        .name = "hiae",
        .version = version,
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .strip = true,
        }),
    });

    lib.linkLibC();

    lib.addIncludePath(b.path("include"));

    const source_files = &.{
        "src/hiae/HiAE_aesni.c",
        "src/hiae/HiAE_arm.c",
        "src/hiae/HiAE_arm_sha3.c",
        "src/hiae/HiAE_arm.c",
        "src/hiae/HiAE_software.c",
        "src/hiae/HiAE_stream.c",
        "src/hiae/HiAE_vaes_avx512.c",
        "src/hiae/HiAE.c",

        "src/hiaex2/HiAEx2_arm.c",
        "src/hiaex2/HiAEx2_arm_sha3.c",
        "src/hiaex2/HiAEx2_software.c",
        "src/hiaex2/HiAEx2_vaes_avx2.c",
        "src/hiaex2/HiAEx2_stream.c",
        "src/hiaex2/HiAEx2.c",

        "src/hiaex4/HiAEx4_arm.c",
        "src/hiaex4/HiAEx4_arm_sha3.c",
        "src/hiaex4/HiAEx4_software.c",
        "src/hiaex4/HiAEx4_vaes_avx512.c",
        "src/hiaex4/HiAEx4_stream.c",
        "src/hiaex4/HiAEx4.c",
    };

    lib.addCSourceFiles(.{ .files = source_files });

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(lib);

    b.installDirectory(.{
        .install_dir = .header,
        .install_subdir = "",
        .source_dir = b.path("include"),
    });

    const function_test_source_files = &.{
        "test/function_test.c",
    };
    const functions_test = b.addExecutable(.{
        .name = "function_test",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .strip = false,
        }),
    });
    functions_test.addCSourceFiles(.{ .files = function_test_source_files });
    functions_test.linkLibC();
    functions_test.addIncludePath(b.path("include"));
    functions_test.linkLibrary(lib);

    const test_vectors_test_source_files = &.{
        "test/test_vectors_ietf.c",
    };
    const test_vectors_test = b.addExecutable(.{
        .name = "test_vectors_ietf",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .strip = false,
        }),
    });
    test_vectors_test.addCSourceFiles(.{ .files = test_vectors_test_source_files });
    test_vectors_test.linkLibC();
    test_vectors_test.addIncludePath(b.path("include"));
    test_vectors_test.linkLibrary(lib);

    const test_vectors_hiaex2_test_source_files = &.{
        "test/test_vectors_hiaex2.c",
    };
    const test_vectors_hiaex2_test = b.addExecutable(.{
        .name = "test_vectors_hiaex2",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .strip = false,
        }),
    });
    test_vectors_hiaex2_test.addCSourceFiles(.{ .files = test_vectors_hiaex2_test_source_files });
    test_vectors_hiaex2_test.linkLibC();
    test_vectors_hiaex2_test.addIncludePath(b.path("include"));
    test_vectors_hiaex2_test.linkLibrary(lib);

    const stream_test_source_files = &.{
        "test/test_stream.c",
    };
    const stream_test = b.addExecutable(.{
        .name = "test_stream",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .strip = false,
        }),
    });
    stream_test.addCSourceFiles(.{ .files = stream_test_source_files });
    stream_test.linkLibC();
    stream_test.addIncludePath(b.path("include"));
    stream_test.linkLibrary(lib);

    const performance_test_source_files = &.{
        "test/performance_test.c",
    };
    const performance_test = b.addExecutable(.{
        .name = "perf_test",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .strip = false,
        }),
    });
    performance_test.addCSourceFiles(.{ .files = performance_test_source_files });
    performance_test.linkLibC();
    performance_test.addIncludePath(b.path("include"));
    performance_test.linkLibrary(lib);

    b.installArtifact(functions_test);
    b.installArtifact(test_vectors_test);
    b.installArtifact(test_vectors_hiaex2_test);
    b.installArtifact(stream_test);
    b.installArtifact(performance_test);

    const performance_x2_test_source_files = &.{
        "test/performance_x2_test.c",
    };
    const performance_x2_test = b.addExecutable(.{
        .name = "perf_x2_test",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .strip = false,
        }),
    });
    performance_x2_test.addCSourceFiles(.{ .files = performance_x2_test_source_files });
    performance_x2_test.linkLibC();
    performance_x2_test.addIncludePath(b.path("include"));
    performance_x2_test.linkLibrary(lib);

    const performance_x4_test_source_files = &.{
        "test/performance_x4_test.c",
    };
    const performance_x4_test = b.addExecutable(.{
        .name = "perf_x4_test",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .strip = false,
        }),
    });
    performance_x4_test.addCSourceFiles(.{ .files = performance_x4_test_source_files });
    performance_x4_test.linkLibC();
    performance_x4_test.addIncludePath(b.path("include"));
    performance_x4_test.linkLibrary(lib);

    b.installArtifact(functions_test);
    b.installArtifact(test_vectors_test);
    b.installArtifact(stream_test);
    b.installArtifact(performance_test);
    b.installArtifact(performance_x2_test);
    b.installArtifact(performance_x4_test);
}
