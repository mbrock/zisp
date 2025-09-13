const std = @import("std");

comptime {
    @setEvalBranchQuota(200000);
}

pub const Input = struct {};

const CharBitset = std.bit_set.ArrayBitSet(u64, 256);

pub fn ProgramFor(comptime G: type) type {
    return struct {
        const Rule = std.meta.DeclEnum(G);
        const FirstRuleArrT = @TypeOf(@field(G, @tagName(Rule.start)));
        const Op = Combinators(G).Op;
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

        pub const OpT = Op;
        pub const RuleT = Rule;
        pub const rule_ip = RuleCode().ips;
        pub const code = RuleCode().ops;
        pub const start_ip = rule_ip[@intCast(@intFromEnum(Rule.start))];
    };
}

const ExecMode = enum { auto_continue, yield_each };

pub fn VM(
    /// Grammar type
    comptime G: type,
    /// Save stack size
    comptime T: usize,
    /// Mark stack size
    comptime R: usize,
) type {
    return struct {
        const Machine = @This();

        pub const P = ProgramFor(G);

        const code = P.code;
        const codeinit = P.start_ip;

        /// A frame on the backtracking stack.
        pub const Save = extern struct {
            nextcode: u32,
            texthead: u32,
            markhead: u32,
        };

        /// A frame on the rule call stack.
        pub const Mark = extern struct {
            rulekind: u32,
            texthead: u32,
            nextcode: u32,
        };

        marklist: [R]Mark align(16) = undefined,
        savelist: [T]Save align(16) = undefined,

        codehead: u32 = codeinit,
        texthead: u32 = 0,
        markhead: u32 = 0,
        savehead: u32 = 0,

        text: [:0]const u8,

        pub fn init(src: [:0]const u8) Machine {
            return .{ .text = src };
        }

        pub fn deinit(_: *Machine) void {}

        pub const Status = enum { Ok, Fail, Running };

        pub const Packrat = struct {
            const Self = @This();
            pub const Key = struct { rulekind: u32, texthead: u32 };
            pub const Entry = struct { good: bool, next: u32 };
            pub const Auto = std.AutoHashMap(Key, Entry);

            map: *std.AutoHashMap(Key, Entry),

            hits: usize = 0,
            misses: usize = 0,

            pub fn get(self: *Self, rule: u32, pos: u32) ?Entry {
                const k = Key{ .rulekind = rule, .texthead = pos };
                if (self.map.get(k)) |e| {
                    self.hits += 1;
                    return e;
                } else {
                    self.misses += 1;
                    return null;
                }
            }

            pub fn put(self: *Self, rule: u32, pos: u32, entry: Entry) void {
                _ = self.map.put(.{ .rulekind = rule, .texthead = pos }, entry) catch return;
            }
        };

        pub fn tick(self: *Machine, comptime mode: ExecMode, backpack: ?*Packrat) !Status {
            comptime {
                @setEvalBranchQuota(200000);
            }
            const yield = mode == .yield_each;

            // This compiles to a big inlined jump table with an entry per IP.
            // In autocontinue mode, we keep jumping between these labels;
            // in yield mode, we return after each step.
            vm: switch (self.codehead) {
                inline 0...P.code.len - 1 => |codebase| {
                    const nextcode = codebase + 1;

                    // We usually advance; some branches overwrite this.
                    self.codehead = nextcode;

                    // To avoid bounds checking, the text has a zero sentinel.
                    const nextchar = self.text[self.texthead];

                    _ = switch (code[codebase]) {
                        inline .CharSet => |charmask| {
                            if (charmask.isSet(nextchar)) {
                                self.texthead += 1;
                                if (yield) return .Running else {
                                    continue :vm nextcode;
                                }
                            }
                        },

                        inline .String => |s| {
                            if (self.texthead + s.len <= self.text.len) {
                                @branchHint(.likely);

                                if (std.mem.eql(u8, self.text[self.texthead .. self.texthead + s.len], s)) {
                                    @branchHint(.unlikely);
                                    self.texthead += s.len;

                                    if (yield) return .Running else {
                                        continue :vm nextcode;
                                    }
                                }
                            }
                        },

                        inline .ChoiceRel => |d| {
                            self.savelist[self.savehead] = .{
                                .markhead = self.markhead,
                                .nextcode = @as(usize, @intCast(@as(isize, @intCast(codebase)) + 1 + d)),
                                .texthead = self.texthead,
                            };

                            self.savehead += 1;
                            if (yield) return .Running else {
                                continue :vm nextcode;
                            }
                        },

                        inline .CommitRel => |d| {
                            self.savehead -= 1;
                            const skipcode = (@as(usize, @intCast(@as(isize, codebase) + 1 + d)));
                            self.codehead = skipcode;
                            if (yield) return .Running else {
                                continue :vm skipcode;
                            }
                        },

                        inline .CommitRewindRel => |d| {
                            // Pop one backtrack frame, jump relative, and rewind
                            // the text head to the saved position. Does NOT
                            // restore markhead (unlike failure), matching CommitRel
                            // semantics besides the rewind.
                            self.savehead -= 1;
                            const s = self.savelist[self.savehead];
                            self.texthead = s.texthead;
                            const skipcode = (@as(usize, @intCast(@as(isize, codebase) + 1 + d)));
                            self.codehead = skipcode;
                            if (yield) return .Running else {
                                continue :vm skipcode;
                            }
                        },

                        inline .Call => |r| {
                            const rulekind: u32 = @intCast(@intFromEnum(r));
                            const rulecode = P.rule_ip[rulekind];
                            const memo = if (backpack != null) backpack.?.get(rulekind, self.texthead) else null;
                            if (memo) |e| {
                                if (e.good) {
                                    self.texthead = e.next;
                                    if (yield) return .Running else {
                                        continue :vm nextcode;
                                    }
                                }
                            } else {
                                // Normal call path (not cached or no cache)
                                self.markhead += 1;
                                self.marklist[self.markhead] = .{
                                    .rulekind = rulekind,
                                    .texthead = self.texthead,
                                    .nextcode = nextcode,
                                };

                                self.codehead = rulecode;

                                if (yield) return .Running else {
                                    continue :vm rulecode;
                                }
                            }
                        },

                        .Ret => {
                            if (backpack) |map| {
                                const mark = self.marklist[self.markhead];
                                const head = mark.texthead;
                                map.put(mark.rulekind, head, .{
                                    .good = true,
                                    .next = self.texthead,
                                });
                            }

                            const mark = self.marklist[self.markhead];
                            self.codehead = mark.nextcode;
                            self.markhead -= 1;

                            if (yield) return .Running else {
                                continue :vm mark.nextcode;
                            }
                        },

                        .EndInput => if (self.texthead >= self.text.len) {
                            if (yield) return .Running else {
                                continue :vm nextcode;
                            }
                        },

                        .Fail => void,
                        .Accept => return .Ok,
                    };

                    if (self.savehead != 0) {
                        // Failure with a backtrack point.
                        @branchHint(.likely);

                        self.savehead -= 1;
                        const failsave = self.savelist[self.savehead];

                        if (backpack) |map| {
                            // save failure result for any rules we are abandoning
                            var i = self.markhead;
                            while (i > failsave.markhead) : (i -= 1) {
                                const failmark = self.marklist[i];
                                map.put(failmark.rulekind, failmark.texthead, .{
                                    .good = false,
                                    .next = failmark.texthead,
                                });
                            }
                        }

                        self.codehead = failsave.nextcode;
                        self.markhead = failsave.markhead;
                        self.texthead = failsave.texthead;

                        if (yield) return .Running else continue :vm self.codehead;
                    }

                    return .Fail;
                },
                else => unreachable,
            }

            unreachable;
        }

        pub fn parseFully(
            src: [:0]const u8,
            comptime mode: ExecMode,
        ) !bool {
            var m = @This().init(src);
            defer m.deinit();
            switch (mode) {
                .yield_each => while (true) {
                    const st = try m.tick(.yield_each, null);
                    switch (st) {
                        .Running => {
                            @branchHint(.likely);
                            continue;
                        },
                        .Ok => return true,
                        .Fail => return false,
                    }
                },
                .auto_continue => switch (try m.tick(.auto_continue, null)) {
                    .Ok => return true,
                    .Fail => return false,
                    .Running => std.debug.panic("auto_continue should not return Running", .{}),
                },
            }
        }

        pub const Metrics = struct {
            steps: usize = 0, // number of tick() invocations
            max_back_height: usize = 0, // maximum trail/backtrack stack height (g)
            max_rule_height: usize = 0, // maximum rule call stack height (h)
            backtracks: usize = 0, // count of times g decreased since previous yield
            accepted: bool = false, // final acceptance state
        };

        /// Execute parse in yield_each mode gathering instrumentation metrics.
        pub fn runWithMetrics(src: [:0]const u8) !Metrics {
            var m = @This().init(src);
            defer m.deinit();
            var metrics: Metrics = .{};
            var prev_g: usize = m.savehead;
            var cache_map = @This().Packrat.Auto.init(std.heap.page_allocator);
            defer cache_map.deinit();
            var cache = @This().Packrat{ .map = &cache_map };
            while (true) {
                const st = try m.tick(.yield_each, &cache);
                metrics.steps += 1;
                // Track heights after this step
                if (m.savehead > metrics.max_back_height) metrics.max_back_height = m.savehead;
                if (m.markhead > metrics.max_rule_height) metrics.max_rule_height = m.markhead;
                if (m.savehead < prev_g) metrics.backtracks += 1;
                prev_g = m.savehead;
                switch (st) {
                    .Running => {
                        @branchHint(.likely);
                        continue;
                    },
                    .Ok => {
                        metrics.accepted = true;
                        return metrics;
                    },
                    .Fail => {
                        metrics.accepted = false;
                        return metrics;
                    },
                }
            }
        }

        pub fn runWithMetricsUncached(src: [:0]const u8) !Metrics {
            var m = @This().init(src);
            defer m.deinit();
            var metrics: Metrics = .{};
            var prev_g: usize = m.savehead;
            while (true) {
                const st = try m.tick(.yield_each, null);
                metrics.steps += 1;
                if (m.savehead > metrics.max_back_height) metrics.max_back_height = m.savehead;
                if (m.markhead > metrics.max_rule_height) metrics.max_rule_height = m.markhead;
                if (m.savehead < prev_g) metrics.backtracks += 1;
                prev_g = m.savehead;
                switch (st) {
                    .Running => {
                        @branchHint(.likely);
                        continue;
                    },
                    .Ok => {
                        metrics.accepted = true;
                        return metrics;
                    },
                    .Fail => {
                        metrics.accepted = false;
                        return metrics;
                    },
                }
            }
        }
    };
}

pub fn Combinators(comptime G: type) type {
    return struct {
        pub const Rule = std.meta.DeclEnum(G);

        pub const Op = union(enum) {
            ChoiceRel: i16,
            CommitRel: i16,
            // Pop backtrack frame, jump relative, and rewind texthead
            // to the saved position from that frame.
            CommitRewindRel: i16,
            Fail: void,
            Call: Rule,
            Ret: void,
            CharSet: CharBitset,
            String: []const u8,
            EndInput: void,
            Accept: void,
        };

        pub const space = star(charclass(" \t\n\r"));

        pub const eof = op1(.{ .EndInput = {} });
        pub const ok = op1(.{ .Accept = {} });
        pub const ret = op1(.{ .Ret = {} });

        pub inline fn OpN(comptime n: usize) type {
            return [n]Op;
        }

        pub const Op1 = [1]Op;

        pub inline fn op1(comptime o: Op) Op1 {
            return [1]Op{o};
        }

        pub inline fn char(comptime c: u8) Op1 {
            return text(ascii[c .. c + 1]);
        }

        pub inline fn text(comptime s: []const u8) Op1 {
            return op1(.{ .String = s });
        }

        pub inline fn call(comptime r: Rule) Op1 {
            return op1(.{ .Call = r });
        }

        fn sizeSum(comptime parts: anytype) comptime_int {
            var sum = 0;
            inline for (parts) |p| sum += p.len;
            return sum;
        }

        pub inline fn seq(comptime parts: anytype) OpN(sizeSum(parts)) {
            @setEvalBranchQuota(2000);
            if (parts.len < 2) @compileError("useless seq");

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

        pub inline fn star(comptime X: anytype) OpN(X.len + 2) {
            const to_end = X.len + 1; // from ChoiceRel next to end
            const back = -@as(i16, @intCast(X.len + 2)); // from CommitRel back to ChoiceRel
            return op1(.{ .ChoiceRel = @intCast(to_end) }) ++ X ++
                op1(.{ .CommitRel = back });
        }

        pub inline fn anyOf(comptime parts: anytype) OpN(sizeSum(parts) + (parts.len - 1) * 2) {
            @setEvalBranchQuota(2000);
            if (parts.len < 2) @compileError("choose needs at least 2 parts");

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
                        rest_len += lens[k]; // body of alt k
                        if (k > i) rest_len += 1; // commits at start of later alts
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
            return anyOf(.{ X, .{} });
        }

        /// Positive lookahead: succeeds iff `inner` would succeed, consumes 0 chars.
        /// Simpler encoding with CommitRewindRel:
        ///   F = save to FAIL_LABEL
        ///   inner
        ///   commit_rewind -> END   (pop F, rewind text)
        ///   FAIL_LABEL: fail      (propagate failure)
        pub inline fn lookahead(comptime inner: anytype) OpN(inner.len + 3) {
            const n = inner.len;
            const to_faillbl = n + 1; // ChoiceRel -> FAIL_LABEL (at index n+2)
            const j_to_end = 1; // CommitRewindRel from (n+1) -> END (at n+3)

            return op1(.{ .ChoiceRel = @intCast(to_faillbl + 0) }) ++ // F
                inner ++
                op1(.{ .CommitRewindRel = @intCast(j_to_end) }) ++ // -> END
                op1(.{ .Fail = {} }); // FAIL_LABEL
        }

        /// Negative lookahead: succeeds iff `inner` would fail, consumes 0 chars.
        /// Simpler encoding with CommitRewindRel:
        ///   F = save to SUCC/END
        ///   inner
        ///   commit_rewind -> FAIL_LABEL  (pop F, rewind text)
        ///   FAIL_LABEL: fail             (propagate failure)
        ///   SUCC/END: fallthrough        (success)
        pub inline fn notLookahead(comptime inner: anytype) OpN(inner.len + 3) {
            const n = inner.len;
            const to_succ = n + 2; // ChoiceRel -> SUCC/END (at index n+3)
            const j_to_fail = 0; // CommitRewindRel from (n+1) -> FAIL_LABEL (at n+2)

            return op1(.{ .ChoiceRel = @intCast(to_succ) }) ++ // F
                inner ++
                op1(.{ .CommitRewindRel = @intCast(j_to_fail) }) ++ // -> FAIL_LABEL
                op1(.{ .Fail = {} }); // FAIL_LABEL; fallthrough after this is SUCC/END
        }

        pub inline fn several(comptime X: anytype) OpN(X.len + (X.len + 2)) {
            return seq(.{ X, star(X) });
        }

        pub inline fn charclass(comptime ranges: anytype) Op1 {
            var set = CharBitset.initEmpty();

            for (ranges) |r|
                switch (@TypeOf(r)) {
                    u8, comptime_int => set.set(r),
                    else => inline for (r) |c|
                        set.set(c),
                };

            return op1(.{ .CharSet = set });
        }
    };
}

pub const ascii = blk: {
    var array: [128]u8 = undefined;
    for (0..127) |i| {
        array[i] = i;
    }
    break :blk array;
};

// -------------------------
// JSON grammar (ASCII-only)
// -------------------------
pub const JSONGrammar = struct {
    const C = Combinators(@This());

    const hexdigit = C.charclass(.{
        ascii['0' .. '9' + 1],
        ascii['A' .. 'F' + 1],
        ascii['a' .. 'f' + 1],
    });

    // any ASCII except control, '"' and '\\'
    const stringchar = C.charclass(.{
        " !",
        ascii['#' .. '[' + 1],
        ascii[']' .. '~' + 1],
    });

    const simple_escape = C.char('\\') ++ C.charclass(
        \\"\bfnrt
    );

    const uXXXX = C.text("\\u") ++ hexdigit ** 4;

    // String <- '"' (Unescaped / Escape)* '"'
    pub const String =
        C.char('"') ++
        C.star(C.anyOf(.{ stringchar, simple_escape, uXXXX })) ++
        C.char('"') ++
        C.ret;

    // Number per JSON (no leading zeros unless exactly 0)
    // Integer <- '-'? ( '0' / [1-9] [0-9]* )
    // Frac <- ('.' [0-9]+)?  using NUMBER for [0-9]+
    // Exp  <- ([eE] [+-]? [0-9]+)?
    const digit = C.several(C.charclass("0123456789"));
    const nonzerodigit = C.charclass("123456789");
    const maybe_minus = C.opt(C.char('-'));
    const integral = C.anyOf(.{ C.char('0'), nonzerodigit ++ C.star(digit) });
    const fractional = C.opt(C.seq(.{ C.char('.'), digit }));
    const scientific = C.opt(C.seq(.{ C.charclass("eE"), C.opt(C.charclass("+-")), digit }));
    pub const Number = C.seq(.{ maybe_minus, integral, fractional, scientific, C.ret });

    // Value <- Object / Array / String / Number / 'true' / 'false' / 'null'
    pub const Value = C.anyOf(.{
        C.call(.Object),
        C.call(.Array),
        C.call(.String),
        C.call(.Number),
        C.text("true"),
        C.text("false"),
        C.text("null"),
    }) ++ C.ret;

    // Member <- String WS ':' WS Value
    pub const Member = C.seq(.{
        C.call(.String),
        C.space,
        C.char(':'),
        C.space,
        C.call(.Value),
        C.ret,
    });

    // Members <- Member (WS ',' WS Member)*
    pub const Members = C.seq(.{
        C.call(.Member),
        C.star(C.seq(.{ C.space, C.char(','), C.space, C.call(.Member) })),
        C.ret,
    });

    // Object <- '{' WS Members? WS '}'
    pub const Object = C.seq(.{
        C.char('{'),
        C.space,
        C.opt(C.call(.Members)),
        C.space,
        C.char('}'),
        C.ret,
    });

    // Elements <- Value (WS ',' WS Value)*
    pub const Elements = C.seq(.{
        C.call(.Value),
        C.star(C.seq(.{ C.space, C.char(','), C.space, C.call(.Value) })),
        C.ret,
    });

    // Array <- '[' WS Elements? WS ']'
    pub const Array = C.seq(.{
        C.char('['),
        C.space,
        C.opt(C.call(.Elements)),
        C.space,
        C.char(']'),
        C.ret,
    });

    // start <- WS Value WS EOF
    pub const start = C.seq(.{
        C.space,
        C.call(.Value),
        C.space,
        C.eof,
        C.ok,
    });
};

const JSONParser = VM(JSONGrammar, 32, 32);

fn parseJSON(src: [:0]const u8) !bool {
    return JSONParser.parseFully(src, .auto_continue);
}

fn expectJsonOk(src: [:0]const u8) !void {
    try std.testing.expect(try parseJSON(src[0..src.len :0]));
}

fn expectJsonFail(src: [:0]const u8) !void {
    try std.testing.expect(!try parseJSON(src[0..src.len :0]));
}

test "JSON grammar statistics" {
    try std.testing.expectEqual(135, JSONParser.P.code.len);
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

// -------------------------
// Backtracking test grammars
// -------------------------
// We add two tiny grammars specifically designed to force the VM to backtrack:
// 1. BacktrackGrammar: an alt where the first alternative shares a long
//    prefix with the second but fails on the final character, requiring the
//    engine to rewind almost the entire input.
//       start <- ( "aaaaaaaaac" / 'a'+ 'b' ) EOF
//    Parsing "aaaaaaaaab" must explore the failing long literal then backtrack
//    and succeed via the second alternative.
// 2. GreedyGrammar: uses a greedy many0 followed by a required "ab" tail:
//       start <- 'a'* 'a' 'b' EOF   (equivalently 'a'+ 'b')
//    Implemented deliberately with many0 + explicit 'a' 'b' to force the loop
//    to over-consume and then backtrack one step so the trailing "ab" matches.
// Both grammars are intentionally small/ambiguous compared to JSON (which is
// mostly unambiguous) to exercise the backtracking machinery in tests.

pub const BacktrackGrammar = struct {
    const C = Combinators(@This());

    pub const Long = C.seq(.{ C.text("aaaaaaaaac"), C.ret });
    pub const APlusB = C.seq(.{ C.several(C.char('a')), C.char('b'), C.ret });

    pub const start = C.seq(.{
        C.anyOf(.{ C.call(.Long), C.call(.APlusB) }),
        C.eof,
        C.ok,
    });
};

pub const GreedyGrammar = struct {
    const C = Combinators(@This());
    // An ordered choice of decreasing-length strings sharing long prefixes.
    // The parser will attempt longer ones first and backtrack down.
    // We purposefully omit some lengths so inputs trigger several failures.
    const Chain = C.anyOf(.{
        C.text("aaaaaaaaab"), // 9 a's + b (too long for short inputs)
        C.text("aaaaaaab"), // 7 a's + b
        C.text("aaaaaab"), // 6 a's + b
        C.text("aaaaab"), // 5 a's + b
        C.text("aaaab"), // 4 a's + b
        C.text("aaab"), // 3 a's + b
        C.text("aab"), // 2 a's + b
        C.text("ab"), // 1 a + b
    });

    pub const start = C.seq(.{ Chain, C.eof, C.ok });
};

const BacktrackParser = VM(BacktrackGrammar, 32, 32);
const GreedyParser = VM(GreedyGrammar, 32, 32);

fn parseBacktrack(src: [:0]const u8) !bool {
    return BacktrackParser.parseFully(src, .auto_continue);
}

fn parseGreedy(src: [:0]const u8) !bool {
    return GreedyParser.parseFully(src, .auto_continue);
}

test "backtracking alt with long common prefix" {
    // Succeeds through first alternative (no backtracking)
    try std.testing.expect(try parseBacktrack("aaaaaaaaac"));
    // Fails first alt only at final char, must backtrack and take second
    try std.testing.expect(try parseBacktrack("aaaaaaaaab"));
    // Minimal second alternative
    try std.testing.expect(try parseBacktrack("ab"));
    // Negative: wrong tail
    try std.testing.expect(!try parseBacktrack("aaaaaaaaad"));
}

test "backtracking inside greedy repetition" {
    try std.testing.expect(try parseGreedy("aaaaab"));
    try std.testing.expect(try parseGreedy("ab"));
    try std.testing.expect(!try parseGreedy("aaaaa"));

    const src = "aaaaab"; // should skip 3 longer failing alts before match
    var m = GreedyParser.init(src);
    defer m.deinit();

    for (0..10) |_| {
        const st = try m.tick(.yield_each, null);
        try std.testing.expectEqual(.Running, st);
    }

    try std.testing.expectEqual(.Ok, try m.tick(.yield_each, null));
}

test "metrics collection on backtracking grammar" {
    const metrics = try BacktrackParser.runWithMetrics("aaaaaaaaab");
    try std.testing.expect(metrics.accepted);
    try std.testing.expectEqual(10, metrics.backtracks);
    try std.testing.expectEqual(1, metrics.max_back_height);
    try std.testing.expectEqual(35, metrics.steps);
}

test "metrics collection on simple json token" {
    const metrics = try JSONParser.runWithMetrics("true");
    try std.testing.expect(metrics.accepted);
    try std.testing.expectEqual(2, metrics.max_rule_height);
    try std.testing.expectEqual(27, metrics.steps);
    try std.testing.expectEqual(9, metrics.backtracks);
}

pub const BlowupGrammar = struct {
    const C = Combinators(@This());

    /// Shout ::= ('a' Shout) / 'a'
    pub const shout = C.anyOf(.{
        C.seq(.{ C.char('a'), C.call(.shout) }),
        C.char('a'),
    }) ++ C.ret;

    /// start ::= A 'b' EOF
    pub const start = C.seq(.{
        C.call(.shout),
        C.char('b'),
        C.eof,
        C.ok,
    });
};

const BlowupVM = VM(BlowupGrammar, 4096, 4096);

test "packrat blowup demonstration" {
    const n: usize = 20;
    const buf: *const [(n + 1):0]u8 = "a" ** n ++ "b";
    const metrics = try BlowupVM.runWithMetrics(buf);

    try std.testing.expect(metrics.accepted);
    try std.testing.expectEqual(107, metrics.steps);
    try std.testing.expectEqual(21, metrics.backtracks);
}

const PackratGrammar = struct {
    const C = Combinators(@This());

    pub const start = C.anyOf(.{
        C.call(.x) ++ C.eof, C.call(.x) ++ C.call(.x) ++ C.eof,
    }) ++ C.ok;

    pub const x = C.anyOf(.{
        C.char('(') ++ C.call(.x) ++ C.char(')'),
        C.char('x'),
    }) ++ C.ret;
};

fn pedometer(SomeVM: type, src: [:0]const u8, mode: enum { packrat, naive }) !usize {
    const metrics = try switch (mode) {
        .packrat => SomeVM.runWithMetrics(src),
        .naive => SomeVM.runWithMetricsUncached(src),
    };

    try std.testing.expect(metrics.accepted);
    return metrics.steps;
}

test "packrat caching benefit" {
    const PackratVM = VM(PackratGrammar, 32, 32);

    try std.testing.expectEqual(
        27,
        try pedometer(PackratVM, "(((x)))", .naive),
    );
}

test "yield mode" {
    const src = "true";
    var m = JSONParser.init(src);
    defer m.deinit();

    // First tick should execute first op and return Running
    const st1 = try m.tick(.yield_each, null);
    try std.testing.expect(st1 == .Running);

    // Keep ticking until we get a final result
    var count: usize = 1;
    while (true) : (count += 1) {
        const st = try m.tick(.yield_each, null);
        switch (st) {
            .Running => continue,
            .Ok => break,
            .Fail => return error.TestUnexpectedFailure,
        }
    }

    // Should have taken multiple steps
    try std.testing.expect(count > 1);
}

test "yield mode complex" {
    const src = "[1, 2, 3]";
    var m = JSONParser.init(src);
    defer m.deinit();

    var count: usize = 0;
    while (true) : (count += 1) {
        const st = try m.tick(.yield_each, null);
        switch (st) {
            .Running => continue,
            .Ok => break,
            .Fail => return error.TestUnexpectedFailure,
        }
    }

    try std.testing.expect(count > 10); // Should take many steps
}

pub const KeywordGrammar = struct {
    const C = Combinators(@This());
    const alnum = C.charclass(.{
        ascii['0' .. '9' + 1],
        ascii['a' .. 'z' + 1],
        ascii['A' .. 'Z' + 1],
    });

    pub const start = C.seq(.{
        C.text("if"),
        C.notLookahead(alnum),
        C.eof,
        C.ok,
    });
};

const KeywordParser = VM(KeywordGrammar, 32, 32);

fn parseKeyword(src: [:0]const u8) !bool {
    return KeywordParser.parseFully(src, .auto_continue);
}

test "negative lookahead keyword" {
    try std.testing.expect(try parseKeyword("if"));
    try std.testing.expect(!try parseKeyword("ifelse"));
    try std.testing.expect(!try parseKeyword("iff"));
    try std.testing.expect(!try parseKeyword("if1"));
}

pub const EvenIntGrammar = struct {
    const C = Combinators(@This());

    const digit = C.charclass(ascii['0' .. '9' + 1]);
    const alnum = C.charclass(.{
        ascii['0' .. '9' + 1],
        ascii['a' .. 'z' + 1],
        ascii['A' .. 'Z' + 1],
    });

    const integer = C.several(digit);
    const even_alnum = C.several(C.seq(.{ alnum, alnum }));
    const even_alnum_full = C.seq(.{ even_alnum, C.eof });

    pub const start = C.seq(.{
        C.lookahead(even_alnum_full),
        integer,
        C.eof,
        C.ok,
    });
};

const EvenIntParser = VM(EvenIntGrammar, 32, 32);

fn parseEvenInt(src: [:0]const u8) !bool {
    return EvenIntParser.parseFully(src, .auto_continue);
}

test "positive lookahead integer and even alnum" {
    try std.testing.expect(try parseEvenInt("42"));
    try std.testing.expect(try parseEvenInt("1234"));
    try std.testing.expect(!try parseEvenInt("123"));
    try std.testing.expect(!try parseEvenInt("1a"));
    try std.testing.expect(!try parseEvenInt("abcd"));
}
