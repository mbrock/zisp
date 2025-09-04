const std = @import("std");
const parse = @import("parse.zig");
const bench_grammar = @import("bench_grammar.zig");

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    
    // Test with trace debug to see what's happening (BenchLang)
    const VM = parse.InlineVm(bench_grammar.BenchLang, .{ .debug = parse.TraceDebug });

    std.debug.print("=== Testing: 'let x = 42;' ===\n", .{});
    _ = VM.parseFully(gpa, "let x = 42;", .auto_continue) catch false;

    std.debug.print("\n=== Testing: 'call(a: 1, b: 2);' ===\n", .{});
    _ = VM.parseFully(gpa, "call(a: 1, b: 2);", .auto_continue) catch false;
}
