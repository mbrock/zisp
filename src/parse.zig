const std = @import("std");

comptime {
    // Allow large compile-time code generation for grammars and helpers.
    @setEvalBranchQuota(200000);
}

pub const Input = struct {
    data: []const u8,
    cur: usize = 0,

    pub fn init(_: std.mem.Allocator, src: []const u8) Input {
        return .{ .data = src };
    }
    pub fn deinit(self: *Input) void {
        _ = self;
    }

    pub fn ensure(self: *Input, from: usize, n: usize) !bool {
        return from + n <= self.data.len;
    }
    pub fn atEnd(self: *Input) !bool {
        return self.cur >= self.data.len;
    }
    pub fn peek(self: *Input) !?u8 {
        if (self.cur >= self.data.len) return null;
        return self.data[self.cur];
    }
    pub fn take(self: *Input) !?u8 {
        if (self.cur >= self.data.len) return null;
        const b = self.data[self.cur];
        self.cur += 1;
        return b;
    }
};

pub fn ProgramFor(comptime G: type) type {
    return struct {
        // Determine types from the grammar without requiring a public 'C'.
        const Rule = std.meta.DeclEnum(G);
        const FirstRuleArrT = @TypeOf(@field(G, @tagName(Rule.Start)));
        const Op = switch (@typeInfo(FirstRuleArrT)) {
            .array => |a| a.child,
            else => @compileError("Grammar Start rule must be an array of ops"),
        };
        const E = std.enums.values(Rule);

        inline fn ruleBody(comptime nm: Rule) [RuleSize(nm)]Op {
            const raw = @field(G, @tagName(nm));
            const RawT = @TypeOf(raw);
            return switch (@typeInfo(RawT)) {
                .array => |a| if (a.child == Op) raw else .{},
                else => .{},
            };
        }

        fn GetCodeSize() usize {
            var sz: usize = 0;
            for (E) |f| sz += ruleBody(f).len;
            return sz;
        }

        fn RuleSize(r: Rule) usize {
            const raw = @field(G, @tagName(r));
            const RawT = @TypeOf(raw);
            return switch (@typeInfo(RawT)) {
                .array => |a| if (a.child == Op) a.len else 0,
                else => 0,
            };
        }

        pub const CodeSize = GetCodeSize();

        inline fn RuleCode() struct { ips: [E.len]usize, ops: [CodeSize]Op } {
            comptime var ips: [E.len]usize = undefined;
            comptime var ops: []const Op = &.{};
            comptime var off: usize = 0;

            for (E) |f| {
                ips[@intFromEnum(f)] = off;
                ops = ops ++ ruleBody(f);
                off += RuleSize(f);
            }
            return .{ .ips = ips, .ops = ops[0..CodeSize].* };
        }

        // Find Start IP from enum
        const StartIp = rule_ip[@intCast(@intFromEnum(Rule.Start))];

        pub const OpT = Op;
        pub const RuleT = Rule;
        pub const rule_ip = RuleCode().ips;
        pub const code = RuleCode().ops;
        pub const start_ip = StartIp;
    };
}

const ExecMode = enum { auto_continue, yield_each };

pub fn InlineVm(comptime Grammar: type, comptime config: struct { debug: type = SilentDebug }) type {
    const P = ProgramFor(Grammar);

    const Backtrack = struct {
        ip: usize,
        pos: usize,
        vsp: usize,
        csp: usize,
    };

    return struct {
        const Machine = @This();

        gpa: std.mem.Allocator,
        input: Input,

        ip: usize = P.start_ip,
        trail: std.ArrayList(Backtrack) = .empty,
        call: std.ArrayList(struct { ip: usize }) = .empty, // return ip stack
        vstack: std.ArrayList(u8) = .empty, // captures if you add them

        pub fn init(alloc: std.mem.Allocator, src: []const u8) Machine {
            return .{
                .gpa = alloc,
                .input = Input.init(alloc, src),
            };
        }

        pub fn deinit(self: *Machine) void {
            self.vstack.deinit(self.gpa);
            self.call.deinit(self.gpa);
            self.trail.deinit(self.gpa);
            self.input.deinit();
        }

        pub const Status = enum { Ok, Fail, Running };

        fn formatOp(op: P.OpT, writer: anytype) !void {
            switch (op) {
                .Char => |c| {
                    if (c == ' ') try writer.print("'\\s'", .{}) else if (c == '\t') try writer.print("'\\t'", .{}) else if (c == '\n') try writer.print("'\\n'", .{}) else if (c == '\r') try writer.print("'\\r'", .{}) else try writer.print("'{c}'", .{c});
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

        fn formatInput(input: []const u8, pos: usize, writer: anytype) !void {
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

            if (at == ' ') try writer.print("⎵", .{}) else if (at == '\t') try writer.print("⇥", .{}) else if (at == '\n') try writer.print("⏎", .{}) else if (at == '\r') try writer.print("⏎", .{}) else try writer.print("{c}", .{at});

            try writer.print("{s}…", .{after});
        }

        fn ipToRuleName(ip: usize) []const u8 {
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

        fn ipToRuleOffset(ip: usize) usize {
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

        fn formatTrail(trail: []const Backtrack, writer: anytype) !void {
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

        fn getRuleBounds(ip: usize) struct { start: usize, end: usize } {
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

        fn renderGrammarState(ip: usize, writer: anytype) !void {
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

        pub fn tick(self: *Machine, comptime _: ExecMode) !Status {
            const BACKTRACK = P.code.len;
            vm: switch (self.ip) {
                BACKTRACK => {
                    if (self.trail.pop()) |bt| {
                        config.debug.onBacktrack(bt.ip, bt.pos, @min(self.call.items.len, 8));
                        self.input.cur = bt.pos;
                        self.vstack.shrinkRetainingCapacity(bt.vsp);
                        self.call.shrinkRetainingCapacity(bt.csp);
                        continue :vm bt.ip;
                    } else {
                        config.debug.onFail();
                        return .Fail;
                    }
                },
                inline 0...P.code.len - 1 => |k| {
                    const op = comptime P.code[k];
                    const next = k + 1;

                    const depth = @min(self.call.items.len, 8);

                    // Format trail with rule names (only for verbose debuggers)
                    const formatted_trail: []const u8 = blk: {
                        if (comptime @hasDecl(config.debug, "wantsTrail") and config.debug.wantsTrail) {
                            var trail_buf: [200]u8 = undefined;
                            var trail_fbs = std.io.fixedBufferStream(&trail_buf);
                            try formatTrail(self.trail.items, trail_fbs.writer());
                            break :blk trail_fbs.getWritten();
                        } else {
                            break :blk &[_]u8{};
                        }
                    };

                    // Optional concise state callback (for StateDebug)
                    if (comptime @hasDecl(config.debug, "onState")) {
                        var gb: [512]u8 = undefined;
                        var gfb = std.io.fixedBufferStream(&gb);
                        try renderGrammarState(k, gfb.writer());
                        const gline = gfb.getWritten();
                        const rn = ipToRuleName(k);
                        const ro = ipToRuleOffset(k);
                        config.debug.onState(rn, ro, k, gline, self.input.cur, self.input.data);
                    }

                    config.debug.onOp(op, depth, k, self.input.cur, self.input.data, formatted_trail);

                    switch (op) {
                        inline .Char => |c| {
                            const old_pos = self.input.cur;
                            if (try self.input.take()) |got| {
                                if (got != c) {
                                    self.input.cur = old_pos; // restore position
                                    continue :vm BACKTRACK;
                                }
                                var consumed: [1]u8 = .{got};
                                config.debug.onConsume(&consumed, "char", depth);
                                continue :vm next;
                            } else {
                                continue :vm BACKTRACK;
                            }
                        },
                        inline .String => |lit| {
                            if (!try self.input.ensure(self.input.cur, lit.len))
                                continue :vm BACKTRACK;

                            const got = self.input.data[self.input.cur .. self.input.cur + lit.len];

                            if (!std.mem.eql(u8, got, lit))
                                continue :vm BACKTRACK;

                            self.input.cur += lit.len;
                            config.debug.onConsume(got, "string", depth);
                            continue :vm next;
                        },
                        inline .SkipWS => {
                            const start_pos = self.input.cur;
                            while (true) {
                                const mb = try self.input.peek();
                                if (mb) |b| switch (b) {
                                    ' ', '\t', '\r', '\n' => _ = try self.input.take(),
                                    else => break,
                                } else break;
                            }
                            if (self.input.cur > start_pos) {
                                const consumed = self.input.data[start_pos..self.input.cur];
                                config.debug.onConsume(consumed, "whitespace", depth);
                            }
                            continue :vm next;
                        },
                        inline .Ident => {
                            const start_pos = self.input.cur;
                            const mb = try self.input.peek() orelse continue :vm BACKTRACK;
                            const is0 = (mb >= 'A' and mb <= 'Z') or (mb >= 'a' and mb <= 'z') or mb == '_';
                            if (!is0) continue :vm BACKTRACK;

                            _ = try self.input.take();
                            while (true) {
                                const m2 = try self.input.peek();
                                if (m2) |b| {
                                    const ok = (b >= 'A' and b <= 'Z') or (b >= 'a' and b <= 'z') or b == '_' or (b >= '0' and b <= '9');
                                    if (!ok) break;
                                    _ = try self.input.take();
                                } else break;
                            }

                            const ident = self.input.data[start_pos..self.input.cur];
                            config.debug.onConsume(ident, "identifier", depth);
                            continue :vm next;
                        },
                        inline .Number => {
                            const start_pos = self.input.cur;
                            var n: usize = 0;
                            while (true) {
                                const mb = try self.input.peek();
                                if (mb) |b| {
                                    if (b >= '0' and b <= '9') {
                                        _ = try self.input.take();
                                        n += 1;
                                    } else break;
                                } else break;
                            }
                            if (n == 0) continue :vm BACKTRACK;

                            const number = self.input.data[start_pos..self.input.cur];
                            config.debug.onConsume(number, "number", depth);
                            continue :vm next;
                        },

                        inline .ChoiceRel => |d| {
                            try self.trail.append(self.gpa, .{
                                .ip = comptime @as(usize, @intCast(@as(isize, @intCast(k)) + 1 + d)),
                                .pos = self.input.cur,
                                .vsp = self.vstack.items.len,
                                .csp = self.call.items.len,
                            });

                            continue :vm next;
                        },

                        inline .CommitRel => |d| {
                            if (self.trail.items.len != 0) _ = self.trail.pop();
                            continue :vm (comptime @as(usize, @intCast(@as(isize, k) + 1 + d)));
                        },

                        inline .Call => |r| {
                            try self.call.append(self.gpa, .{ .ip = next });
                            continue :vm P.rule_ip[@intCast(@intFromEnum(r))];
                        },

                        .Ret => if (self.call.pop()) |ret|
                            continue :vm ret.ip
                        else
                            return error.InvalidRet,

                        .EndInput => if (!try self.input.atEnd())
                            continue :vm BACKTRACK
                        else
                            continue :vm next,

                        .Fail => continue :vm BACKTRACK,
                        .Accept => return .Ok,
                    }
                },

                else => return error.InvalidIP,
            }
        }

        pub fn parseFully(alloc: std.mem.Allocator, src: []const u8, comptime mode: ExecMode) !bool {
            var m = @This().init(alloc, src);
            defer m.deinit();
            switch (mode) {
                .yield_each => {
                    foo: while (true) {
                        const st = try m.tick(.yield_each);

                        switch (st) {
                            .Running => continue :foo,
                            .Ok => return true,
                            .Fail => return false,
                        }
                    }
                },

                .auto_continue => {
                    switch (try m.tick(.auto_continue)) {
                        .Ok => return true,
                        .Fail => return false,
                        .Running => std.debug.panic("auto_continue should not return Running", .{}),
                    }
                },
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
                } else if (input[pos] == c) {
                    std.debug.print("\x1b[92m'{c}'✓\x1b[0m", .{c});
                } else {
                    std.debug.print("\x1b[91mexpect '{c}', got '{c}'\x1b[0m", .{ c, input[pos] });
                }
            },
            .String => |s| {
                const remain = if (pos < input.len) input[pos..] else input[input.len..input.len];
                const matchable = remain.len >= s.len and std.mem.eql(u8, remain[0..s.len], s);
                if (matchable) {
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

    pub fn onOp(op: anytype, depth: usize, _ip: usize, input_pos: usize, input: []const u8, trail: []const u8) void {
        _ = _ip;
        _ = depth;
        // Reset heuristically when starting a new parse (first Start call)
        if (sp == 0) switch (op) {
            .Call => |r| if (std.mem.eql(u8, @tagName(r), "Start")) {
                reset();
                std.debug.print("\n\x1b[1m=== Parse Trace ===\x1b[0m\n", .{});
            },
            else => {},
        };

        if (input_pos > furthest_pos) furthest_pos = input_pos;

        std.debug.lockStdErr();
        defer std.debug.unlockStdErr();

        // Maintain our own rule stack for clarity
        switch (op) {
            .Call => |r| {
                indent(sp);
                std.debug.print("┌ ", .{});
                fmtOp(op, input, input_pos);
                std.debug.print("\n", .{});

                if (sp < stack.len) {
                    stack[sp] = @tagName(r);
                    sp += 1;
                }

                indent(sp);
                std.debug.print("→ ", .{});
                showInputContext(input, input_pos);
                if (trail.len > 0) {
                    std.debug.print("  \x1b[90m{[t]s}\x1b[0m", .{ .t = trail });
                }
                std.debug.print("\n", .{});
                return;
            },
            .Ret => {
                if (sp > 0) sp -= 1;
                indent(sp);
                std.debug.print("└ ", .{});
                fmtOp(op, input, input_pos);
                std.debug.print("\n", .{});
                return;
            },
            else => {},
        }

        // Default op line
        indent(sp);
        std.debug.print("• ", .{});
        fmtOp(op, input, input_pos);
        std.debug.print("\n", .{});

        // Show input context and trail for non-structural ops
        indent(sp);
        std.debug.print("  ", .{});
        showInputContext(input, input_pos);
        if (trail.len > 0) {
            std.debug.print("  \x1b[90m{[t]s}\x1b[0m", .{ .t = trail });
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

/// Grammar-specific combinators + Op generator
pub fn Combinators(comptime G: type, comptime config: struct { debug: type = SilentDebug }) type {
    const debug = config.debug;
    _ = debug; // Use the debug parameter
    return struct {
        pub const Rule = std.meta.DeclEnum(G);

        pub const Op = union(enum) {
            // control
            ChoiceRel: i32,
            CommitRel: i32,
            Fail: void,
            // calls
            Call: Rule,
            Ret: void,
            // terminals
            Char: u8,
            String: []const u8,
            SkipWS: void,
            Ident: void,
            Number: void,
            EndInput: void,
            // accept
            Accept: void,
        };

        pub const WS = op1(.{ .SkipWS = {} });
        pub const IDENT = op1(.{ .Ident = {} });
        pub const NUMBER = op1(.{ .Number = {} });
        pub const END = op1(.{ .EndInput = {} });
        pub const ACCEPT = op1(.{ .Accept = {} });
        pub const RET = op1(.{ .Ret = {} });

        pub inline fn OpN(comptime n: usize) type {
            return [n]Op;
        }

        pub const Op1 = [1]Op;

        pub inline fn op1(comptime o: Op) Op1 {
            return [1]Op{o};
        }

        pub inline fn CH(comptime c: u8) Op1 {
            return op1(.{ .Char = c });
        }
        pub inline fn STR(comptime s: []const u8) Op1 {
            return op1(.{ .String = s });
        }

        pub inline fn Call(comptime r: Rule) Op1 {
            return op1(.{ .Call = r });
        }

        fn sizeSum(comptime parts: anytype) comptime_int {
            var sum = 0;
            inline for (parts) |p| sum += p.len;
            return sum;
        }

        pub inline fn seq(comptime parts: anytype) OpN(sizeSum(parts)) {
            comptime {
                @setEvalBranchQuota(200000);
            }
            comptime var out: OpN(sizeSum(parts)) = .{undefined} ** sizeSum(parts);
            var i: usize = 0;

            inline for (parts) |p| {
                inline for (p) |item| {
                    out[i] = item;
                    i += 1;
                }
            }

            return out;
        }

        // Ordered choice across many alts: alt(.{A,B,C}) := A / B / C with PEG backtracking.
        pub inline fn or2(comptime A: anytype, comptime B: anytype) OpN(A.len + B.len + 2) {
            comptime {
                @setEvalBranchQuota(200000);
            }
            const j_alt: i32 = comptime @intCast(A.len + 1);
            const j_end: i32 = comptime @intCast(B.len);

            return op1(.{ .ChoiceRel = j_alt }) ++ A ++
                op1(.{ .CommitRel = j_end }) ++ B;
        }

        pub inline fn many0(comptime X: anytype) OpN(X.len + 2) {
            comptime {
                @setEvalBranchQuota(200000);
            }
            const to_end = X.len + 1; // from ChoiceRel next to end
            const back = -@as(i32, @intCast(X.len + 2)); // from CommitRel back to ChoiceRel
            return op1(.{ .ChoiceRel = @intCast(to_end) }) ++ X ++
                op1(.{ .CommitRel = back });
        }

        pub inline fn alt(comptime parts: anytype) OpN(sizeSum(parts) + (parts.len - 1) * 2) {
            comptime {
                @setEvalBranchQuota(200000);
            }
            if (parts.len < 2) @compileError("alt needs at least 2 parts");

            // Precompute lengths of each alternative
            comptime var lens: [parts.len]usize = undefined;
            comptime var idx: usize = 0;
            inline for (parts) |p| {
                lens[idx] = p.len;
                idx += 1;
            }

            const total_len: usize = sizeSum(parts) + (parts.len - 1) * 2;
            var out: OpN(total_len) = .{undefined} ** total_len;
            var o: usize = 0;

            comptime var i: usize = 0;
            inline while (i < parts.len) : (i += 1) {
                // Emit commit for the previous alternative to skip the remainder
                if (i != 0) {
                    comptime var rest_len: usize = 0;
                    comptime var k: usize = i;
                    inline while (k < parts.len) : (k += 1) {
                        if (k != parts.len - 1) rest_len += 1; // ChoiceRel before alt k if not last
                        rest_len += lens[k];                  // body of alt k
                        if (k > i) rest_len += 1;             // commits at start of later alts
                    }
                    out[o] = .{ .CommitRel = @intCast(rest_len) };
                    o += 1;
                }

                // Choice into current alternative if not the last
                if (i != parts.len - 1) {
                    out[o] = .{ .ChoiceRel = @intCast(lens[i] + 1) };
                    o += 1;
                }

                // Emit body for current alt
                inline for (parts[i]) |item| {
                    out[o] = item;
                    o += 1;
                }
            }

            return out;
        }

        pub inline fn opt(comptime X: anytype) OpN(X.len + 2) {
            comptime {
                @setEvalBranchQuota(200000);
            }
            return or2(X, .{});
        }

        // One-or-more occurrences built from many0
        pub inline fn many1(comptime X: anytype) OpN(X.len + (X.len + 2)) {
            comptime {
                @setEvalBranchQuota(200000);
            }
            return seq(.{ X, many0(X) });
        }

        // Build an alternative over a contiguous character range [lo..hi]
        pub inline fn chRange(comptime lo: u8, comptime hi: u8) [@as(usize, hi) - @as(usize, lo) + 1][1]Op {
            comptime {
                @setEvalBranchQuota(200000);
            }
            const N: usize = @as(usize, hi) - @as(usize, lo) + 1;
            var out: [N][1]Op = undefined;
            var i: usize = 0;
            comptime var c: u8 = lo;
            inline while (c <= hi) : (c += 1) {
                out[i] = CH(c);
                i += 1;
            }
            return out;
        }

        // Character class from multiple ranges. Example:
        // classRanges(.{ .{ 'a','z' }, .{ 'A','Z' }, .{ '0','9' } })
        pub inline fn classRanges(comptime ranges: anytype) OpN(block: {
            var count: usize = 0;
            var idx: usize = 0;
            while (idx < ranges.len) : (idx += 1) {
                const r = ranges[idx];
                count += @as(usize, r[1]) - @as(usize, r[0]) + 1;
            }
            // alt emits N bodies + 2 op overhead per separator
            break :block count + (count - 1) * 2;
        }) {
            comptime {
                @setEvalBranchQuota(200000);
            }

            // Build flat list of one-char alternatives
            comptime var total: usize = 0;
            inline for (ranges) |r| total += @as(usize, r[1]) - @as(usize, r[0]) + 1;

            var alts: [total][1]Op = undefined;
            var k: usize = 0;
            inline for (ranges) |r| {
                comptime var c: u8 = r[0];
                inline while (c <= r[1]) : (c += 1) {
                    alts[k] = CH(c);
                    k += 1;
                }
            }
            return alt(alts);
        }
    };
}

pub const Demo = struct {
    const C = Combinators(@This(), .{ .debug = StateDebug });

    // Prim <- Number / Ident / '(' WS Expr WS ')'
    pub const Prim = C.alt(.{
        C.NUMBER,
        C.IDENT,
        C.seq(.{ C.CH('('), C.WS, C.Call(.Expr), C.WS, C.CH(')') }),
    }) ++ C.RET;

    // Expr <- Prim (WS '+' WS Prim)*
    pub const Expr = C.seq(.{
        C.Call(.Prim),
        C.many0(C.seq(.{ C.WS, C.CH('+'), C.WS, C.Call(.Prim) })),
        C.RET,
    });

    // Arg <- Ident WS ':' WS Expr / Expr
    pub const Arg = C.seq(.{
        C.alt(.{
            C.seq(.{ C.IDENT, C.WS, C.CH(':'), C.WS, C.Call(.Expr) }),
            C.Call(.Expr),
        }),
        C.RET,
    });

    // ArgList <- Arg (WS ',' WS Arg)*
    pub const ArgList = C.seq(.{
        C.Call(.Arg),
        C.many0(C.seq(.{ C.WS, C.CH(','), C.WS, C.Call(.Arg) })),
        C.RET,
    });

    // Call <- Ident WS '(' WS ArgList? WS ')'
    pub const Call = C.seq(.{
        C.IDENT,                 C.WS, C.CH('('), C.WS,
        C.opt(C.Call(.ArgList)), C.WS, C.CH(')'), C.RET,
    });

    // Start <- WS Call WS EOF
    pub const Start = C.seq(.{ C.WS, C.Call(.Call), C.WS, C.END, C.ACCEPT });
};

const VM = InlineVm(Demo, .{ .debug = StateDebug });

const TrivialVM = InlineVm(struct {
    const C = Combinators(@This(), .{ .debug = StateDebug });
    pub const Start = C.seq(.{ C.CH('a'), C.CH('b'), C.END, C.ACCEPT });
}, .{ .debug = StateDebug });

fn expectParse(src: []const u8) !void {
    try std.testing.expect(try VM.parseFully(std.testing.allocator, src, .auto_continue));
}

fn expectParseFail(src: []const u8) !void {
    try std.testing.expect(!try VM.parseFully(std.testing.allocator, src, .auto_continue));
}

test "expr call + plus" {
    try expectParse("foo(a)");
}
test "keyword arg" {
    try expectParse("foo(key: a)");
}
test "empty args" {
    try expectParse("foo()");
}
test "clean backtrack on Arg ambiguity then EOF fail" {
    try expectParseFail("foo(a +");
}

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    var buf: [1024]u8 = undefined;
    var reader = std.fs.File.stdin().reader(&buf);
    try reader.interface.fillMore();
    const src = try reader.interface.allocRemaining(gpa, .unlimited);
    var m = VM.init(gpa, src);
    defer m.deinit();
    switch (try m.tick(.auto_continue)) {
        .Ok => std.debug.print("Success!\n", .{}),
        .Fail => return error.Fail,
        .Running => return error.Running,
    }
}

const BalancedParens = InlineVm(struct {
    const C = Combinators(@This(), .{});

    pub const S =
        C.seq(.{
            C.CH('('), C.Call(.S), C.CH(')'),
        }) ++ C.RET;

    pub const Start = C.Call(.S) ++ C.END ++ C.ACCEPT;
});

export fn parse(src: [*]const u8, len: usize) i32 {
    var buf: [1024]u8 = undefined;
    var alloc = std.heap.FixedBufferAllocator.init(&buf);
    const gpa = alloc.allocator();
    var m = VM.init(gpa, src[0..len]);
    defer m.deinit();
    switch (m.tick(.auto_continue) catch return -1) {
        .Ok => return 0,
        .Fail => return 1,
        .Running => return 2,
    }
}

// -------------------------
// JSON grammar (ASCII-only)
// -------------------------
pub const Json = struct {
    const C = Combinators(@This(), .{ .debug = StateDebug });

    // Hex digit for \uXXXX escapes
    const HEX = C.classRanges(.{ .{ '0','9' }, .{ 'A','F' }, .{ 'a','f' } });

    // Unescaped JSON string char: any ASCII except control, '"' and '\\'
    const UnescapedChar = C.classRanges(.{ .{ ' ', '!' }, .{ '#', '[' }, .{ ']', '~' } });

    // Escaped: \\" \\ \/ \b \f \n \r \t or \uXXXX
    const SimpleEscape = C.seq(.{
        C.CH('\\'),
        C.classRanges(.{ .{ '"','"' }, .{ '\\','\\' }, .{ '/','/' }, .{ 'b','b' }, .{ 'f','f' }, .{ 'n','n' }, .{ 'r','r' }, .{ 't','t' } }),
    });
    const UnicodeEscape = C.seq(.{ C.CH('\\'), C.CH('u'), HEX, HEX, HEX, HEX });

    // String <- '"' (Unescaped / Escape)* '"'
    pub const String = C.seq(.{
        C.CH('"'),
        C.many0(C.alt(.{ UnescapedChar, SimpleEscape, UnicodeEscape })),
        C.CH('"'),
        C.RET,
    });

    // Number per JSON (no leading zeros unless exactly 0)
    // Integer <- '-'? ( '0' / [1-9] [0-9]* )
    // Frac <- ('.' [0-9]+)?  using NUMBER for [0-9]+
    // Exp  <- ([eE] [+-]? [0-9]+)?
    const DIGIT1_9 = C.classRanges(.{ .{ '1','9' } });
    const SignOpt = C.opt(C.CH('-'));
    const IntPart = C.alt(.{ C.STR("0"), C.seq(.{ DIGIT1_9, C.many0(C.NUMBER) }) });
    const FracOpt = C.opt(C.seq(.{ C.CH('.'), C.NUMBER }));
    const ExpOpt = C.opt(C.seq(.{
        C.classRanges(.{ .{ 'e','e' }, .{ 'E','E' } }),
        C.opt(C.classRanges(.{ .{ '+','+' }, .{ '-','-' } })),
        C.NUMBER,
    }));
    pub const Number = C.seq(.{ SignOpt, IntPart, FracOpt, ExpOpt, C.RET });

    // Value <- Object / Array / String / Number / 'true' / 'false' / 'null'
    pub const Value = C.alt(.{
        C.Call(.Object),
        C.Call(.Array),
        C.Call(.String),
        C.Call(.Number),
        C.STR("true"),
        C.STR("false"),
        C.STR("null"),
    }) ++ C.RET;

    // Member <- String WS ':' WS Value
    pub const Member = C.seq(.{ C.Call(.String), C.WS, C.CH(':'), C.WS, C.Call(.Value), C.RET });

    // Members <- Member (WS ',' WS Member)*
    pub const Members = C.seq(.{ C.Call(.Member), C.many0(C.seq(.{ C.WS, C.CH(','), C.WS, C.Call(.Member) })), C.RET });

    // Object <- '{' WS Members? WS '}'
    pub const Object = C.seq(.{ C.CH('{'), C.WS, C.opt(C.Call(.Members)), C.WS, C.CH('}'), C.RET });

    // Elements <- Value (WS ',' WS Value)*
    pub const Elements = C.seq(.{ C.Call(.Value), C.many0(C.seq(.{ C.WS, C.CH(','), C.WS, C.Call(.Value) })), C.RET });

    // Array <- '[' WS Elements? WS ']'
    pub const Array = C.seq(.{ C.CH('['), C.WS, C.opt(C.Call(.Elements)), C.WS, C.CH(']'), C.RET });

    // Start <- WS Value WS EOF
    pub const Start = C.seq(.{ C.WS, C.Call(.Value), C.WS, C.END, C.ACCEPT });
};

const JSON_VM = InlineVm(Json, .{ .debug = SilentDebug });

fn expectJsonOk(src: []const u8) !void {
    try std.testing.expect(try JSON_VM.parseFully(std.testing.allocator, src, .auto_continue));
}

fn expectJsonFail(src: []const u8) !void {
    try std.testing.expect(!try JSON_VM.parseFully(std.testing.allocator, src, .auto_continue));
}

test "json primitives" {
    try expectJsonOk(" true ");
    try expectJsonOk(" false ");
    try expectJsonOk(" null ");
}

test "json numbers" {
    try expectJsonOk("0");
    try expectJsonOk("-0");
    try expectJsonOk("10");
    try expectJsonOk("42\n");
    try expectJsonOk("3.14");
    try expectJsonOk("1e10");
    try expectJsonOk("1E-10");
    try expectJsonFail("01"); // no leading zeros
}

test "json strings" {
    try expectJsonOk("\"hello\"\n");
    try expectJsonOk("\"he\\nllo\"\n");
    try expectJsonOk("\"\\u0041\"\n");
}

test "json arrays and objects" {
    try expectJsonOk("[]");
    try expectJsonOk("[1, 2, 3]");
    try expectJsonOk("{\"a\": 1}");
    try expectJsonOk("{\"a\": [true, false, null]}\n");
}
