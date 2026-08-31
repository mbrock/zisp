const std = @import("std");
const peg = @import("peg.zig");
const vm = @import("vm.zig");
const trace = @import("trace.zig");

// Simple backtracking grammar to demonstrate memoization
const DemoGrammar = struct {
    const R = std.meta.DeclEnum(@This());

    // S ::= A 'x' | A 'y'
    pub const S = peg.Match(union(enum) {
        ax: peg.Call(.ax),
        ay: peg.Call(.ay),
    });

    pub const ax = peg.Match(struct {
        a: peg.Call(R.A),
        x: peg.CharSet("x", .one),
    });

    pub const ay = peg.Match(struct {
        a: peg.Call(R.A),
        y: peg.CharSet("y", .one),
    });

    // A ::= 'a' A | 'a'
    pub const A = peg.Match(union(enum) {
        recursive: peg.Call(.recursive),
        base: peg.Call(.base),
    });

    pub const recursive = peg.Match(struct {
        a: peg.CharSet("a", .one),
        rest: peg.Call(R.A),
    });

    pub const base = peg.CharSet("a", .one);
};

pub fn main(init: std.process.Init) !void {
    const TestVM = vm.VM(DemoGrammar);

    const allocator = init.gpa;

    var stdout_buf: [4096]u8 = undefined;
    const stdout_file = std.Io.File.stdout();
    var stdout_writer = stdout_file.writer(init.io, &stdout_buf);
    const stdout = &stdout_writer.interface;
    const no_color = if (init.environ_map.get("NO_COLOR")) |value| value.len > 0 else false;
    const force_color = if (init.environ_map.get("CLICOLOR_FORCE")) |value| value.len > 0 else false;
    const tty = try std.Io.Terminal.Mode.detect(init.io, stdout_file, no_color, force_color);

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
    try stdout.print("  With memoization: {d} steps ({d} saved)\n", .{ with_memo.steps, no_memo - with_memo.steps });
    try stdout.print("  Cache hits: {d}\n", .{with_memo.hits});

    try stdout.flush();
}
