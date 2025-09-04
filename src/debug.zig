const std = @import("std");

// Generic helpers bound to a Program type P (from ProgramFor(Grammar)).
// Provides formatting and rule metadata used by debuggers and the VM.
pub fn DebugSupport(comptime P: type) type {
    return struct {
        pub fn formatOp(op: P.OpT, writer: anytype) !void {
            switch (op) {
                .Char => |c| {
                    if (c == ' ') try writer.print("'\\s'", .{})
                    else if (c == '\t') try writer.print("'\\t'", .{})
                    else if (c == '\n') try writer.print("'\\n'", .{})
                    else if (c == '\r') try writer.print("'\\r'", .{})
                    else try writer.print("'{c}'", .{c});
                },
                .String => |s| try writer.print("\x1b[92m\"{s}\"\x1b[0m", .{s}),
                .SkipWS => try writer.print("\x1b[94mWS\x1b[0m", .{}),
                .Ident => try writer.print("\x1b[94mIDENT\x1b[0m", .{}),
                .Number => try writer.print("\x1b[94mNUMBER\x1b[0m", .{}),
                .EndInput => try writer.print("\x1b[94mEOF\x1b[0m", .{}),
                .ChoiceRel => |d| try writer.print("\x1b[95malt{[s]s}{[d]d}\x1b[0m", .{ .s = if (d >= 0) "+" else "", .d = d }),
                .CommitRel => |d| try writer.print("\x1b[95mcut{[s]s}{[d]d}\x1b[0m", .{ .s = if (d >= 0) "+" else "", .d = d }),
                .Call => |r| try writer.print("\x1b[96m→{s}\x1b[0m", .{@tagName(r)}),
                .Ret => try writer.print("\x1b[93mret\x1b[0m", .{}),
                .Fail => try writer.print("\x1b[91mfail\x1b[0m", .{}),
                .Accept => try writer.print("\x1b[92mACCEPT\x1b[0m", .{}),
            }
        }

        pub fn formatInput(input: []const u8, pos: usize, writer: anytype) !void {
            if (pos >= input.len) {
                try writer.print("⟪EOF⟫", .{});
                return;
            }

            const start = if (pos >= 5) pos - 5 else 0;
            const end = @min(pos + 15, input.len);
            const before = input[start..pos];
            const at = input[pos];
            const after = input[pos + 1 .. end];

            try writer.print("…{s}", .{before});

            if (at == ' ') try writer.print("⎵", .{})
            else if (at == '\t') try writer.print("⇥", .{})
            else if (at == '\n') try writer.print("⏎", .{})
            else if (at == '\r') try writer.print("⏎", .{})
            else try writer.print("{c}", .{at});

            try writer.print("{s}…", .{after});
        }

        pub fn ipToRuleName(ip: usize) []const u8 {
            const rules = comptime std.enums.values(P.RuleT);
            comptime var i: usize = 0;
            inline for (rules) |rule| {
                const rule_start = P.rule_ip[i];
                const rule_end = if (i + 1 < rules.len) P.rule_ip[i + 1] else P.code.len;
                if (ip >= rule_start and ip < rule_end) {
                    return @tagName(rule);
                }
                i += 1;
            }
            return "?";
        }

        pub fn ipToRuleOffset(ip: usize) usize {
            const rules = comptime std.enums.values(P.RuleT);
            comptime var i: usize = 0;
            inline for (rules) |_| {
                const rule_start = P.rule_ip[i];
                const rule_end = if (i + 1 < rules.len) P.rule_ip[i + 1] else P.code.len;
                if (ip >= rule_start and ip < rule_end) {
                    return ip - rule_start;
                }
                i += 1;
            }
            return ip;
        }

        // Accept any slice type whose items have an `ip: usize` field.
        pub fn formatTrail(trail: anytype, writer: anytype) !void {
            const T = @TypeOf(trail);
            _ = T; // generic duck-typed over .ip field
            if (trail.len == 0) return;

            try writer.print("[", .{});
            var i: usize = 0;
            for (trail) |bt| {
                if (i > 0) try writer.print(",", .{});
                const rule_name = ipToRuleName(bt.ip);
                const offset = ipToRuleOffset(bt.ip);
                try writer.print("{s}+{}", .{ rule_name, offset });
                i += 1;
            }
            try writer.print("↺]", .{});
        }

        pub fn getRuleBounds(ip: usize) struct { start: usize, end: usize } {
            const rules = comptime std.enums.values(P.RuleT);
            comptime var i: usize = 0;
            inline for (rules) |_| {
                const rule_start = P.rule_ip[i];
                const rule_end = if (i + 1 < rules.len) P.rule_ip[i + 1] else P.code.len;
                if (ip >= rule_start and ip < rule_end) {
                    return .{ .start = rule_start, .end = rule_end };
                }
                i += 1;
            }
            return .{ .start = 0, .end = 0 };
        }

        pub fn renderGrammarState(ip: usize, writer: anytype) !void {
            const rule_name = ipToRuleName(ip);
            const off = ipToRuleOffset(ip);
            const bounds = getRuleBounds(ip);

            try writer.print("{s}[{}]: ", .{ rule_name, off });
            var idx: usize = bounds.start;
            while (idx < bounds.end) : (idx += 1) {
                if (idx == ip) try writer.print("[", .{});
                try formatOp(P.code[idx], writer);
                if (idx == ip) try writer.print("]", .{});
                if (idx + 1 < bounds.end) try writer.print(" ", .{});
            }
        }
    };
}

/// Silent debug handler (no output)
pub const SilentDebug = struct {
    pub const wantsTrail = false;
    pub fn onOp(op: anytype, depth: usize, ip: usize, input_pos: usize, input: []const u8, trail: []const u8) void {
        _ = op;
        _ = depth;
        _ = ip;
        _ = input_pos;
        _ = input;
        _ = trail;
    }
    pub fn onConsume(consumed: []const u8, kind: []const u8, depth: usize) void {
        _ = consumed;
        _ = kind;
        _ = depth;
    }
    pub fn onBacktrack(to_ip: usize, to_pos: usize, depth: usize) void {
        _ = to_ip;
        _ = to_pos;
        _ = depth;
    }
    pub fn onFail() void {}
};

/// Verbose debug handler (with colored output)
pub const VerboseDebug = struct {
    pub const wantsTrail = true;
    pub fn onOp(op: anytype, depth: usize, _: usize, input_pos: usize, input: []const u8, trail: []const u8) void {
        std.debug.lockStdErr();
        defer std.debug.unlockStdErr();

        // Print tree structure with proper indentation
        std.debug.print("\x1b[90m", .{});
        if (depth == 0) {
            std.debug.print("  ", .{});
        } else if (depth == 1) {
            std.debug.print("├─", .{});
        } else {
            for (0..depth - 1) |_| std.debug.print("│ ", .{});
            std.debug.print("├─", .{});
        }
        std.debug.print("\x1b[0m ", .{});

        // Print operation with color
        switch (op) {
            .Call => |rule| std.debug.print("\x1b[96m→ {s}\x1b[0m\n", .{@tagName(rule)}),
            .Ret => std.debug.print("\x1b[93m← return\x1b[0m\n", .{}),
            .ChoiceRel => |offset| std.debug.print("\x1b[95mtry alternative at +{}\x1b[0m\n", .{offset}),
            .CommitRel => |offset| std.debug.print("\x1b[95mcommit choice, jump +{}\x1b[0m\n", .{offset}),
            .Fail => std.debug.print("\x1b[91m✗ fail\x1b[0m\n", .{}),
            .Char => |c| std.debug.print("\x1b[92m'{c}'\x1b[0m\n", .{c}),
            .String => |s| std.debug.print("\x1b[92m\"{s}\"\x1b[0m\n", .{s}),
            .SkipWS => std.debug.print("\x1b[94m⟪whitespace⟫\x1b[0m\n", .{}),
            .Ident => std.debug.print("\x1b[94m⟪identifier⟫\x1b[0m\n", .{}),
            .Number => std.debug.print("\x1b[94m⟪number⟫\x1b[0m\n", .{}),
            .EndInput => std.debug.print("\x1b[94m⟪end-of-input⟫\x1b[0m\n", .{}),
            .Accept => std.debug.print("\x1b[92m✓ accept\x1b[0m\n", .{}),
        }

        // Print input position
        std.debug.print("\x1b[90m", .{});
        if (depth == 0) {
            std.debug.print("    ", .{});
        } else {
            for (0..depth - 1) |_| std.debug.print("│ ", .{});
            std.debug.print("│   ", .{});
        }
        std.debug.print("\x1b[0m\x1b[90m→\x1b[0m ", .{});

        // Display input preview
        if (input_pos < input.len) {
            const remaining = input[input_pos..];
            const display_len = @min(remaining.len, 10);
            std.debug.print("\x1b[97m…{s}", .{remaining[0..display_len]});
            if (display_len < remaining.len) std.debug.print("…", .{});
            std.debug.print("\x1b[0m", .{});
        } else {
            std.debug.print("\x1b[97m⟪EOF⟫\x1b[0m", .{});
        }

        // Print backtrack trail if present
        if (trail.len > 0) {
            std.debug.print("\n\x1b[90m", .{});
            if (depth == 0) {
                std.debug.print("    ", .{});
            } else {
                for (0..depth - 1) |_| std.debug.print("│ ", .{});
                std.debug.print("│   ", .{});
            }
            std.debug.print("\x1b[0m\x1b[90m↺\x1b[0m \x1b[33m", .{});
            std.debug.print("{s}", .{trail});
            std.debug.print("\x1b[0m", .{});
        }

        std.debug.print("\n", .{});
    }

    pub fn onConsume(consumed: []const u8, kind: []const u8, depth: usize) void {
        std.debug.lockStdErr();
        defer std.debug.unlockStdErr();

        std.debug.print("\x1b[90m", .{});
        if (depth == 0) {
            std.debug.print("    ", .{});
        } else {
            for (0..depth - 1) |_| std.debug.print("│ ", .{});
            std.debug.print("│   ", .{});
        }

        if (std.mem.eql(u8, kind, "char")) {
            std.debug.print("\x1b[0m\x1b[92m✓ consumed '{s}'\x1b[0m\n", .{consumed});
        } else if (std.mem.eql(u8, kind, "string")) {
            std.debug.print("\x1b[0m\x1b[92m✓ consumed \"{s}\"\x1b[0m\n", .{consumed});
        } else if (std.mem.eql(u8, kind, "whitespace")) {
            const count = consumed.len;
            std.debug.print("\x1b[0m\x1b[92m✓ skipped {} whitespace\x1b[0m\n", .{count});
        } else {
            std.debug.print("\x1b[0m\x1b[92m✓ consumed {s} '{s}'\x1b[0m\n", .{ kind, consumed });
        }
    }

    pub fn onBacktrack(to_ip: usize, to_pos: usize, depth: usize) void {
        _ = to_ip;
        _ = to_pos;
        _ = depth;
        // Could add backtrack visualization here if needed
    }

    pub fn onFail() void {
        // Could add fail visualization here if needed
    }
};

/// Rich, structured debug handler focused on grammar troubleshooting
/// - Shows rule call stack (tracked via Call/Ret)
/// - Highlights expected vs. got at the input cursor
/// - Displays input context with a caret and safe whitespace glyphs
/// - Summarizes failure with furthest-point information
pub const TraceDebug = struct {
    pub const wantsTrail = true;
    // Simple global state — tests are sequential, VM is single-threaded.
    var stack: [64][]const u8 = undefined;
    var sp: usize = 0;

    var furthest_pos: usize = 0;

    fn reset() void {
        sp = 0;
        furthest_pos = 0;
    }

    fn indent(depth: usize) void {
        if (depth == 0) {
            return;
        }
        for (0..depth) |_| std.debug.print("│ ", .{});
    }

    fn glyph(b: u8) u8 {
        // Keep ASCII-only glyphs to avoid multi-byte chars in a single codepoint.
        return switch (b) {
            ' ' => ' ',
            9, 10, 13 => ' ', // tab, nl, cr
            else => b,
        };
    }

    fn showInputContext(input: []const u8, pos: usize) void {
        std.debug.print("\x1b[90m", .{});
        if (pos >= input.len) {
            std.debug.print("…⟪EOF⟫…", .{});
            std.debug.print("\x1b[0m", .{});
            return;
        }

        const start = if (pos >= 10) pos - 10 else 0;
        const end = @min(pos + 15, input.len);
        std.debug.print("…", .{});
        var i: usize = start;
        while (i < end) : (i += 1) {
            if (i == pos) {
                std.debug.print("\x1b[93m^\x1b[0m\x1b[90m", .{});
            }
            const ch = glyph(input[i]);
            std.debug.print("{c}", .{ch});
        }
        if (end < input.len) std.debug.print("…", .{});
        std.debug.print("\x1b[0m", .{});
    }

    fn fmtOp(op: anytype, input: []const u8, pos: usize) void {
        switch (op) {
            .Call => |r| std.debug.print("\x1b[96m→ {s}\x1b[0m", .{@tagName(r)}),
            .Ret => std.debug.print("\x1b[93m← return\x1b[0m", .{}),
            .ChoiceRel => |d| std.debug.print("\x1b[95mchoice +{}\x1b[0m", .{d}),
            .CommitRel => |d| std.debug.print("\x1b[95mcommit +{}\x1b[0m", .{d}),
            .Fail => std.debug.print("\x1b[91m✗ fail\x1b[0m", .{}),
            .Accept => std.debug.print("\x1b[92m✓ accept\x1b[0m", .{}),
            .EndInput => {
                if (pos >= input.len) {
                    std.debug.print("\x1b[92mEOF\x1b[0m", .{});
                } else {
                    std.debug.print("\x1b[91mexpect EOF, got more\x1b[0m", .{});
                }
            },
            .Char => |c| {
                if (pos >= input.len) {
                    std.debug.print("\x1b[91mexpect '{c}', got EOF\x1b[0m", .{c});
                } else {
                    if (input[pos] == c) std.debug.print("\x1b[92m'{c}'✓\x1b[0m", .{c}) else std.debug.print("\x1b[91mexpect '{c}', got '{c}'\x1b[0m", .{ c, input[pos] });
                }
            },
            .String => |s| {
                if (pos + s.len <= input.len and std.mem.eql(u8, input[pos .. pos + s.len], s)) {
                    std.debug.print("\x1b[92m\"{s}\"✓\x1b[0m", .{s});
                } else {
                    std.debug.print("\x1b[91mexpect \"{s}\"\x1b[0m", .{s});
                }
            },
            .SkipWS => std.debug.print("\x1b[94m⟪whitespace⟫\x1b[0m", .{}),
            .Ident => std.debug.print("\x1b[94m⟪identifier⟫\x1b[0m", .{}),
            .Number => std.debug.print("\x1b[94m⟪number⟫\x1b[0m", .{}),
        }
    }

    pub fn onOp(op: anytype, depth: usize, _: usize, input_pos: usize, input: []const u8, trail: []const u8) void {
        std.debug.lockStdErr();
        defer std.debug.unlockStdErr();

        // Maintain a simple call stack for nicer indentation
        switch (op) {
            .Call => |r| {
                if (sp < stack.len) stack[sp] = @tagName(r);
                sp += 1;
            },
            .Ret => {
                if (sp > 0) sp -= 1;
            },
            else => {},
        }

        // Track furthest input position encountered
        if (input_pos > furthest_pos) furthest_pos = input_pos;

        const d = @min(depth, sp);

        // Print current op and input context
        indent(d);
        fmtOp(op, input, input_pos);
        std.debug.print("  ", .{});
        showInputContext(input, input_pos);

        // show trail if present
        if (trail.len > 0) {
            std.debug.print("  \x1b[90m↺\x1b[0m \x1b[33m{s}\x1b[0m", .{trail});
        }
        std.debug.print("\n", .{});
    }

    pub fn onConsume(consumed: []const u8, kind: []const u8, depth: usize) void {
        std.debug.lockStdErr();
        defer std.debug.unlockStdErr();

        const d = @min(depth, sp);
        indent(d);
        if (std.mem.eql(u8, kind, "whitespace")) {
            std.debug.print("\x1b[92m✓ skipped {d} ws\x1b[0m\n", .{consumed.len});
            return;
        }
        std.debug.print("\x1b[92m✓ consumed {s} \"{s}\"\x1b[0m\n", .{ kind, consumed });
    }

    pub fn onBacktrack(_: usize, to_pos: usize, depth: usize) void {
        std.debug.lockStdErr();
        defer std.debug.unlockStdErr();
        const d = @min(depth, sp);
        indent(d);
        std.debug.print("\x1b[91m↺ backtrack to pos {}\x1b[0m\n", .{to_pos});
    }

    pub fn onFail() void {
        std.debug.lockStdErr();
        defer std.debug.unlockStdErr();
        std.debug.print("\x1b[1;31mParse failed\x1b[0m", .{});
        std.debug.print(" at furthest pos {}\n", .{furthest_pos});
    }
};

/// Concise state-by-state grammar-focused debug output
/// Prints one line per VM step with the rule and highlighted opcode.
pub const StateDebug = struct {
    pub const wantsTrail = true;
    fn showInput(input: []const u8, pos: usize) void {
        std.debug.print(" | ", .{});
        if (pos >= input.len) {
            std.debug.print("⟪EOF⟫", .{});
            return;
        }
        const start = if (pos >= 8) pos - 8 else 0;
        const end = @min(pos + 12, input.len);
        std.debug.print("…", .{});
        var i: usize = start;
        while (i < end) : (i += 1) {
            if (i == pos) std.debug.print("^", .{});
            const b = input[i];
            switch (b) {
                ' ', 9, 10, 13 => std.debug.print(" ", .{}),
                else => std.debug.print("{c}", .{b}),
            }
        }
        if (end < input.len) std.debug.print("…", .{});
    }

    pub fn onState(rule_name: []const u8, _: usize, _: usize, grammar: []const u8, input_pos: usize, input: []const u8) void {
        _ = rule_name; // already included in grammar line
        std.debug.lockStdErr();
        defer std.debug.unlockStdErr();
        std.debug.print("{s}", .{grammar});
        showInput(input, input_pos);
        std.debug.print("\n", .{});
    }

    pub fn onOp(op: anytype, depth: usize, ip: usize, input_pos: usize, input: []const u8, trail: []const u8) void {
        // Intentionally minimal to avoid tree noise
        _ = op;
        _ = depth;
        _ = ip;
        _ = input_pos;
        _ = input;
        _ = trail;
    }
    pub fn onConsume(consumed: []const u8, kind: []const u8, depth: usize) void {
        _ = consumed;
        _ = kind;
        _ = depth; // keep quiet
    }
    pub fn onBacktrack(to_ip: usize, to_pos: usize, depth: usize) void {
        _ = to_ip;
        _ = to_pos;
        _ = depth; // keep quiet
    }
    pub fn onFail() void {}
};
