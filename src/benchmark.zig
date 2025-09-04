const std = @import("std");
const parse = @import("parse.zig");
const bench_grammar = @import("bench_grammar.zig");

// Use the focused BenchLang grammar for stable, non-trivial benchmarks
const VM = parse.InlineVm(bench_grammar.BenchLang, .{ .debug = parse.SilentDebug });

pub const BenchmarkResult = struct {
    name: []const u8,
    file_size: usize,
    parse_time_ns: u64,
    success: bool,
    throughput_mb_per_sec: f64,
    memory_used: usize,
};

pub const Benchmark = struct {
    allocator: std.mem.Allocator,
    results: std.ArrayList(BenchmarkResult),

    pub fn init(allocator: std.mem.Allocator) Benchmark {
        return Benchmark{
            .allocator = allocator,
            .results = std.ArrayList(BenchmarkResult){},
        };
    }

    pub fn deinit(self: *Benchmark) void {
        self.results.deinit(self.allocator);
    }

    pub fn benchmarkFile(self: *Benchmark, name: []const u8, file_path: []const u8) !void {
        // Read the file
        const file = std.fs.cwd().openFile(file_path, .{}) catch |err| {
            std.debug.print("Error opening {s}: {}\n", .{ file_path, err });
            return;
        };
        defer file.close();

        const file_size = try file.getEndPos();
        const content = try file.readToEndAlloc(self.allocator, std.math.maxInt(usize));
        defer self.allocator.free(content);

        // Use a simple memory tracking approach
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const arena_alloc = arena.allocator();

        // Benchmark the parsing
        const start_time = std.time.nanoTimestamp();
        
        const success = VM.parseFully(arena_alloc, content, .auto_continue) catch false;
        
        const end_time = std.time.nanoTimestamp();
        const parse_time_ns = @as(u64, @intCast(end_time - start_time));

        // Calculate throughput (MB/s)
        const throughput_mb_per_sec = if (parse_time_ns > 0)
            (@as(f64, @floatFromInt(file_size)) / (1024.0 * 1024.0)) / (@as(f64, @floatFromInt(parse_time_ns)) / 1_000_000_000.0)
        else
            0.0;

        const result = BenchmarkResult{
            .name = name,
            .file_size = file_size,
            .parse_time_ns = parse_time_ns,
            .success = success,
            .throughput_mb_per_sec = throughput_mb_per_sec,
            .memory_used = 0, // Arena doesn't track individual allocations
        };

        try self.results.append(self.allocator, result);

        std.debug.print("{s:15} | {d:8} bytes | {d:10} ns | {s:7} | {d:8.2} MB/s | {d:8} bytes\n", .{
            name,
            file_size,
            parse_time_ns,
            if (success) "SUCCESS" else "FAILED",
            throughput_mb_per_sec,
            0, // Memory usage not tracked
        });
    }

    pub fn benchmarkString(self: *Benchmark, name: []const u8, content: []const u8, iterations: u32) !void {
        var total_time_ns: u64 = 0;
        var successful_parses: u32 = 0;
        var total_memory_used: usize = 0;

        for (0..iterations) |_| {
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            const arena_alloc = arena.allocator();

            const start_time = std.time.nanoTimestamp();
            
            const success = VM.parseFully(arena_alloc, content, .auto_continue) catch false;
            
            const end_time = std.time.nanoTimestamp();
            
            total_time_ns += @as(u64, @intCast(end_time - start_time));
            total_memory_used += 0; // Not tracking individual allocations
            if (success) successful_parses += 1;
        }

        const avg_time_ns = total_time_ns / iterations;
        const avg_memory_used = total_memory_used / iterations;
        const success_rate = (@as(f64, @floatFromInt(successful_parses)) / @as(f64, @floatFromInt(iterations))) * 100.0;

        // Calculate throughput (MB/s) based on average time
        const throughput_mb_per_sec = if (avg_time_ns > 0)
            (@as(f64, @floatFromInt(content.len)) / (1024.0 * 1024.0)) / (@as(f64, @floatFromInt(avg_time_ns)) / 1_000_000_000.0)
        else
            0.0;

        const result = BenchmarkResult{
            .name = name,
            .file_size = content.len,
            .parse_time_ns = avg_time_ns,
            .success = successful_parses == iterations,
            .throughput_mb_per_sec = throughput_mb_per_sec,
            .memory_used = avg_memory_used,
        };

        try self.results.append(self.allocator, result);

        std.debug.print("{s:15} | {d:8} bytes | {d:10} ns | {d:5.1}% | {d:8.2} MB/s | {d:8} bytes | {d} iter\n", .{
            name,
            content.len,
            avg_time_ns,
            success_rate,
            throughput_mb_per_sec,
            avg_memory_used,
            iterations,
        });
    }

    pub fn printSummary(self: *Benchmark) void {
        if (self.results.items.len == 0) {
            std.debug.print("No benchmark results to summarize.\n", .{});
            return;
        }

        var total_throughput: f64 = 0.0;
        var successful_benchmarks: u32 = 0;
        var total_memory: usize = 0;

        std.debug.print("\n=== BENCHMARK SUMMARY ===\n", .{});
        for (self.results.items) |result| {
            if (result.success) {
                total_throughput += result.throughput_mb_per_sec;
                successful_benchmarks += 1;
            }
            total_memory += result.memory_used;
        }

        const avg_throughput = if (successful_benchmarks > 0) 
            total_throughput / @as(f64, @floatFromInt(successful_benchmarks))
        else 
            0.0;

        const avg_memory = total_memory / self.results.items.len;

        std.debug.print("Total benchmarks: {}\n", .{self.results.items.len});
        std.debug.print("Successful: {} ({d:.1}%)\n", .{
            successful_benchmarks,
            (@as(f64, @floatFromInt(successful_benchmarks)) / @as(f64, @floatFromInt(self.results.items.len))) * 100.0
        });
        std.debug.print("Average throughput: {d:.2} MB/s\n", .{avg_throughput});
        std.debug.print("Average memory usage: {} bytes\n", .{avg_memory});
    }
};

// Stress test with various input patterns
pub fn stressTest(allocator: std.mem.Allocator) !void {
    std.debug.print("\n=== STRESS TESTS ===\n", .{});
    std.debug.print("Pattern         | Size     | Time (ns)  | Status  | Throughput | Memory   | Iterations\n", .{});
    std.debug.print("----------------|----------|------------|---------|------------|----------|----------\n", .{});

    var benchmark = Benchmark.init(allocator);
    defer benchmark.deinit();

    // Test statements compatible with RealisticLang Program
    try benchmark.benchmarkString("Simple Call", "func(123);", 10000);
    try benchmark.benchmarkString("Multi Args", "add(1, 2, 3);", 5000);
    try benchmark.benchmarkString("Named Args", "test(a: 1, b: 2);", 5000);

    benchmark.printSummary();
}

test "benchmark realistic grammar" {
    const allocator = std.testing.allocator;
    
    var benchmark = Benchmark.init(allocator);
    defer benchmark.deinit();

    // Test simple statements with semicolons
    try benchmark.benchmarkString("VarDecl", "let x = 42;", 500);
    try benchmark.benchmarkString("CallStmt", "  call(1, 2);  ", 500);

    benchmark.printSummary();
}
