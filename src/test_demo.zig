const std = @import("std");
const parse = @import("parse.zig");

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    
    // Test simple expressions that should work with Demo grammar
    const tests = [_][]const u8{
        "foo(42)",
        "add(1, 2)", 
        "test()",
        "call(a: 5)",
    };
    
    const VM = parse.InlineVm(parse.Demo, .{ .debug = parse.SilentDebug });
    
    for (tests) |test_input| {
        std.debug.print("Testing: '{s}' -> ", .{test_input});
        const success = VM.parseFully(gpa, test_input, .auto_continue) catch false;
        std.debug.print("{s}\n", .{if (success) "SUCCESS" else "FAILED"});
    }
}