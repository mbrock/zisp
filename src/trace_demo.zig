const std = @import("std");
const peg = @import("peg.zig");
const vm = @import("vm.zig");
const trace = @import("trace.zig");

// Simple backtracking grammar to demonstrate memoization
const DemoGrammar = struct {
    const R = std.meta.DeclEnum(@This());

    // S ::= A 'x' | A 'y'
    pub fn S(
        _: union(enum) {
            ax: struct {
                a: peg.Call(R.A),
                x: peg.CharSet("x"),
            },
            ay: struct {
                a: peg.Call(R.A),
                y: peg.CharSet("y"),
            },
        },
    ) void {}

    // A ::= 'a' A | 'a'
    pub fn A(
        _: union(enum) {
            recursive: struct {
                a: peg.CharSet("a"),
                rest: peg.Call(R.A),
            },
            base: peg.CharSet("a"),
        },
    ) void {}
};

pub fn main() !void {
    const TestVM = vm.VM(DemoGrammar);

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buf: [4096]u8 = undefined;
    const stdout_file = std.fs.File.stdout();
    var stdout_writer = stdout_file.writer(&stdout_buf);
    const stdout = &stdout_writer.interface;
    const tty = std.Io.tty.detectConfig(stdout_file);

    const input = "aaay";

    // Create VM and trace without memoization
    var machine1 = try TestVM.initAlloc(input, allocator, 16, 16, 256);
    defer machine1.deinit(allocator);
    try trace.trace(&machine1, stdout, tty);
    
    // Create VM with memoization and trace
    var machine2 = try TestVM.initAlloc(input, allocator, 16, 16, 256);
    defer machine2.deinit(allocator);
    var memo = TestVM.MemoTable.init(allocator);
    defer memo.deinit();
    machine2.memo = &memo;
    try trace.trace(&machine2, stdout, tty);
    
    // Show the difference in step counts
    const no_memo = try TestVM.countSteps(input, allocator);
    const with_memo = try TestVM.countStepsWithMemo(input, allocator);
    
    try stdout.print("\nSummary:\n", .{});
    try stdout.print("  Without memoization: {d} steps\n", .{no_memo});
    try stdout.print("  With memoization: {d} steps ({d} saved)\n", .{with_memo.steps, no_memo - with_memo.steps});
    try stdout.print("  Cache hits: {d}\n", .{with_memo.hits});
    
    try stdout.flush();
}
