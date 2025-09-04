const std = @import("std");
const benchmark = @import("benchmark.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== ZISP PARSER BENCHMARK ===\n\n", .{});

    // File benchmarks (RealisticLang over sample JS files)
    std.debug.print("=== GENERATED BENCHMARKS (BenchLang) ===\n", .{});
    std.debug.print("Name                 | Size     | Time (ns)  | Status  | Throughput | Memory  \n", .{});
    std.debug.print("---------------------|----------|------------|---------|------------|----------\n", .{});

    var bench = benchmark.Benchmark.init(allocator);
    defer bench.deinit();

    // Generate increasing sizes of valid BenchLang programs
    const small = try makeProgram(allocator, 200);
    defer allocator.free(small);
    try bench.benchmarkString("small-200", small, 1);

    const medium = try makeProgram(allocator, 2000);
    defer allocator.free(medium);
    try bench.benchmarkString("medium-2k", medium, 1);

    const large = try makeProgram(allocator, 10000);
    defer allocator.free(large);
    try bench.benchmarkString("large-10k", large, 1);

    bench.printSummary();

    // Run stress tests using BenchLang snippets
    try stressTestBench(allocator);

    std.debug.print("\nBenchmark completed!\n", .{});
}

// Build a valid BenchLang program consisting of `count` alternating statements.
fn makeProgram(allocator: std.mem.Allocator, count: usize) ![]u8 {
    var buf = std.array_list.Managed(u8).init(allocator);
    errdefer buf.deinit();
    for (0..count) |i| {
        try buf.writer().print("let n{d} = {d};\n", .{ i, i });
        try buf.writer().print("call_{d}(a: {d}, b: {d});\n", .{ i, i, i });
    }
    return buf.toOwnedSlice();
}

// Stress tests tailored for BenchLang Program grammar
pub fn stressTestBench(allocator: std.mem.Allocator) !void {
    std.debug.print("\n=== STRESS TESTS (BenchLang) ===\n", .{});
    std.debug.print("Pattern              | Size     | Time (ns)  | Status  | Throughput | Memory   | Iterations\n", .{});
    std.debug.print("---------------------|----------|------------|---------|------------|----------|----------\n", .{});

    var bench = benchmark.Benchmark.init(allocator);
    defer bench.deinit();

    try bench.benchmarkString("VarDecl", "let x = 42;", 5000);
    try bench.benchmarkString("FuncCall", "add(1, 2);", 5000);
    try bench.benchmarkString("NamedArgs", "test(a: 1, b: 2);", 5000);

    bench.printSummary();
}
