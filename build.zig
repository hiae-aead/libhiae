const std = @import("std");

pub fn build(b: *std.Build) void {
    var target = b.standardTargetOptions(.{});
    const optimize = .ReleaseFast;
    const version = std.SemanticVersion.parse("0.2.4") catch unreachable;

    // Use -Dwasm-relaxed-simd=false to keep baseline SIMD128 only.
    const wasm_relaxed = b.option(
        bool,
        "wasm-relaxed-simd",
        "Use relaxed SIMD on WebAssembly targets (default: true)",
    ) orelse true;
    if (target.result.cpu.arch.isWasm() and target.query.cpu_model == .determined_by_arch_os) {
        var query = target.query;
        query.cpu_features_add.addFeature(@intFromEnum(std.Target.wasm.Feature.simd128));
        if (wasm_relaxed) {
            query.cpu_features_add.addFeature(@intFromEnum(std.Target.wasm.Feature.relaxed_simd));
        }
        target = b.resolveTargetQuery(query);
    }

    const lib_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .strip = true,
        .link_libc = true,
    });

    const lib = b.addLibrary(.{
        .name = "hiae",
        .version = version,
        .linkage = .static,
        .root_module = lib_mod,
    });

    lib_mod.addIncludePath(b.path("include"));

    const source_files = &.{
        "src/hiae/HiAE_aesni.c",
        "src/hiae/HiAE_arm.c",
        "src/hiae/HiAE_arm_sha3.c",
        "src/hiae/HiAE_software.c",
        "src/hiae/HiAE_stream.c",
        "src/hiae/HiAE_vaes_avx512.c",
        "src/hiae/HiAE.c",

        "src/hiaex2/HiAEx2_arm.c",
        "src/hiaex2/HiAEx2_arm_sha3.c",
        "src/hiaex2/HiAEx2_software.c",
        "src/hiaex2/HiAEx2_vaes_avx2.c",
        "src/hiaex2/HiAEx2_aesni_avx.c",
        "src/hiaex2/HiAEx2_stream.c",
        "src/hiaex2/HiAEx2.c",

        "src/hiaex4/HiAEx4_arm.c",
        "src/hiaex4/HiAEx4_arm_sha3.c",
        "src/hiaex4/HiAEx4_software.c",
        "src/hiaex4/HiAEx4_vaes_avx512.c",
        "src/hiaex4/HiAEx4_stream.c",
        "src/hiaex4/HiAEx4.c",
    };

    lib_mod.addCSourceFiles(.{ .files = source_files });

    b.installArtifact(lib);

    b.installDirectory(.{
        .install_dir = .header,
        .install_subdir = "",
        .source_dir = b.path("include"),
    });

    const TestSpec = struct { name: []const u8, src: []const u8, run: bool };
    const test_specs = [_]TestSpec{
        .{ .name = "function_test", .src = "test/function_test.c", .run = true },
        .{ .name = "test_vectors_ietf", .src = "test/test_vectors_ietf.c", .run = true },
        .{ .name = "test_vectors_hiaex2", .src = "test/test_vectors_hiaex2.c", .run = true },
        .{ .name = "test_stream", .src = "test/test_stream.c", .run = true },
        .{ .name = "perf_test", .src = "test/performance_test.c", .run = false },
        .{ .name = "perf_x2_test", .src = "test/performance_x2_test.c", .run = false },
        .{ .name = "perf_x4_test", .src = "test/performance_x4_test.c", .run = false },
    };

    const test_step = b.step("test", "Run all tests");

    for (test_specs) |spec| {
        const exe_mod = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .strip = false,
            .link_libc = true,
        });
        exe_mod.addCSourceFile(.{ .file = b.path(spec.src), .flags = &.{} });
        exe_mod.addIncludePath(b.path("include"));
        exe_mod.linkLibrary(lib);

        const exe = b.addExecutable(.{
            .name = spec.name,
            .root_module = exe_mod,
        });
        b.installArtifact(exe);

        if (spec.run) {
            const run = b.addRunArtifact(exe);
            test_step.dependOn(&run.step);
        }
    }
}
