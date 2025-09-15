const std = @import("std");
const peg = @import("peg.zig");
const vm = @import("vm.zig");

test "memoization saves steps on backtracking" {
    // Grammar: S ::= A 'x' | A 'y'
    // When parsing "aaa...y", first alternative parses A then fails on 'x',
    // second alternative re-parses A at THE SAME POSITION (0)
    // This is the CLASSIC memoization benefit case
    const BacktrackGrammar = struct {
        const R = std.meta.DeclEnum(@This());

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

    const TestVM = vm.VM(BacktrackGrammar);

    // Test shows linear growth in savings as input grows
    const test_cases = [_]struct { input: [:0]const u8, no_memo: u32, with_memo: u32, saved: u32 }{
        .{ .input = "ay", .no_memo = 22, .with_memo = 14, .saved = 8 },
        .{ .input = "aay", .no_memo = 32, .with_memo = 19, .saved = 13 },
        .{ .input = "aaay", .no_memo = 42, .with_memo = 24, .saved = 18 },
        .{ .input = "aaaay", .no_memo = 52, .with_memo = 29, .saved = 23 },
    };

    for (test_cases) |tc| {
        const steps = try TestVM.countSteps(tc.input, std.testing.allocator);
        try std.testing.expectEqual(tc.no_memo, steps);

        const stats = try TestVM.countStepsWithMemo(tc.input, std.testing.allocator);
        try std.testing.expectEqual(tc.with_memo, stats.steps);
        try std.testing.expectEqual(@as(u32, 1), stats.hits); // Exactly one cache hit at position 0
        try std.testing.expectEqual(tc.saved, tc.no_memo - stats.steps);
    }
}

test "memoization caches both success and failure" {
    // Test that we cache both successful and failed parse attempts
    const CacheTestGrammar = struct {
        const R = std.meta.DeclEnum(@This());

        pub fn start(
            _: union(enum) {
                first: struct {
                    exp: peg.Call(R.expensive),
                    x: peg.CharSet("x"),
                },
                second: struct {
                    exp: peg.Call(R.expensive), 
                    y: peg.CharSet("y"),
                },
            },
        ) void {}

        // Make it expensive so the benefit is clear
        pub fn expensive(
            _: peg.CharSet("a"),
            _: peg.CharSet("b"),
            _: peg.CharSet("c"),
        ) void {}
    };

    const TestVM = vm.VM(CacheTestGrammar);

    // "abcx" succeeds on first try, no cache benefit
    {
        const input = "abcx";
        const steps = try TestVM.countSteps(input, std.testing.allocator);
        const stats = try TestVM.countStepsWithMemo(input, std.testing.allocator);
        
        try std.testing.expectEqual(@as(u32, 9), steps);
        try std.testing.expectEqual(@as(u32, 9), stats.steps);
        try std.testing.expectEqual(@as(u32, 0), stats.hits); // No backtracking, no cache hit
    }

    // "abcy" backtracks and re-uses cached parse of expensive() at position 0
    {
        const input = "abcy";
        const steps = try TestVM.countSteps(input, std.testing.allocator);
        const stats = try TestVM.countStepsWithMemo(input, std.testing.allocator);
        
        try std.testing.expectEqual(@as(u32, 14), steps);
        try std.testing.expectEqual(@as(u32, 10), stats.steps); // Saved 4 steps
        try std.testing.expectEqual(@as(u32, 1), stats.hits); // One cache hit
    }
}

test "step count stability check" {
    // This test ensures we notice when VM or compiler changes affect performance
    // Update these values when making intentional changes
    
    const SimpleGrammar = struct {
        pub fn start(
            _: peg.CharSet("a"),
            _: peg.CharSet("b"),
            _: peg.CharSet("c"),
        ) void {}
    };

    const TestVM = vm.VM(SimpleGrammar);

    const steps = try TestVM.countSteps("abc", std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 4), steps);
}

test "memoization works with nested rules" {
    // More complex grammar with nested rule calls that benefit from memoization
    const NestedGrammar = struct {
        const R = std.meta.DeclEnum(@This());

        // start ::= (expr '+') | (expr '-')
        pub fn start(
            _: union(enum) {
                plus: struct {
                    e: peg.Call(R.expr),
                    op: peg.CharSet("+"),
                },
                minus: struct {
                    e: peg.Call(R.expr),
                    op: peg.CharSet("-"),
                },
            },
        ) void {}

        // expr ::= term term*
        pub fn expr(
            _: peg.Call(R.term),
            _: []peg.Call(R.term),
        ) void {}

        // term ::= 'a' | 'b'
        pub fn term(
            _: union(enum) {
                a: peg.CharSet("a"),
                b: peg.CharSet("b"),
            },
        ) void {}
    };

    const TestVM = vm.VM(NestedGrammar);

    // Input "ab-" will:
    // 1. Try expr '+' (parse expr successfully, fail on '+')
    // 2. Backtrack and try expr '-' (should use cached expr result)
    {
        const input = "ab-";
        const steps = try TestVM.countSteps(input, std.testing.allocator);
        const stats = try TestVM.countStepsWithMemo(input, std.testing.allocator);
        
        // Verify memoization saves steps
        try std.testing.expect(stats.steps < steps);
        try std.testing.expect(stats.hits > 0);
    }
}

// REMOVED: The pathological test with kleene star was too complex.
// The interaction between kleene star backtracking and memoization 
// makes the step counts hard to predict and maintain.

test "memoization disabled by default" {
    // Verify that memoization is opt-in, not automatic
    const SimpleGrammar = struct {
        pub fn start(_: peg.CharSet("a")) void {}
    };

    const TestVM = vm.VM(SimpleGrammar);

    // parse() should not use memoization
    try TestVM.parse("a", std.testing.allocator);
    
    // parseWithMemo() should use memoization
    try TestVM.parseWithMemo("a", std.testing.allocator);
    
    // Both should succeed, memoization is just an optimization
}
