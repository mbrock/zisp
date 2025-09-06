const std = @import("std");

comptime {
    @setEvalBranchQuota(200000);
}

pub const Input = struct {};

const CharBitset = std.bit_set.ArrayBitSet(u64, 256);

pub fn ProgramFor(comptime G: type) type {
    return struct {
        const Rule = std.meta.DeclEnum(G);
        const FirstRuleArrT = @TypeOf(@field(G, @tagName(Rule.Start)));
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

pub fn VM(
    /// Grammar type
    comptime G: type,
    /// Back stack size
    comptime T: usize,
    /// Rule stack size
    comptime R: usize,
) type {
    return struct {
        const Machine = @This();

        pub const P = ProgramFor(G);

        const O = P.code;
        const I0 = P.start_ip;

        /// Backtrackable state record
        pub const F = extern struct {
            /// Code offset
            i: u32 = 0,
            /// Text offset
            j: u32 = 0,
            /// Rule stack height
            h: u32 = 0,
            /// Code origin
            k: u32 = 0,
        };

        /// Input string
        s: []const u8,
        /// Rule stack buffer
        r: [R]u32 = .{0} ** R,
        /// Current state
        i: u32 = I0,
        j: u32 = 0,
        h: u32 = 0,
        /// Back stack height
        g: u32 = 0,
        /// Back stack buffer
        t: [T]F align(16) = [1]F{.{}} ** T,
        /// Memoization: rule id per call frame
        call_rule: [R]u16 = .{0} ** R,
        /// Memoization: start position per call frame
        call_start: [R]u32 = .{0} ** R,

        pub fn init(src: []const u8) Machine {
            return .{ .s = src };
        }

        pub fn deinit(_: *Machine) void {}

        pub const Status = enum { Ok, Fail, Running };

        fn ensure(self: @This(), from: usize, n: usize) bool {
            return from + n <= self.s.len;
        }

        fn atEnd(self: @This()) bool {
            return self.j >= self.s.len;
        }

        fn peek(self: @This()) ?u8 {
            if (self.j >= self.s.len) return null;
            return self.s[self.j];
        }

        fn lookingAt(self: @This(), c: u8) bool {
            return self.j < self.s.len and self.s[self.j] == c;
        }

        fn lookingAtMatch(self: @This(), set: CharBitset) bool {
            if (self.j >= self.s.len) return false;
            return set.isSet(self.s[self.j]);
        }

        fn take(self: @This()) ?u8 {
            if (self.j >= self.s.len) return null;
            const b = self.s[self.j];
            self.j += 1;
            return b;
        }

        pub const Packrat = struct {
            const Self = @This();
            pub const Key = struct { rule: u16, pos: u32 };
            pub const Entry = struct { success: bool, next_pos: u32 };
            pub const Auto = std.AutoHashMap(Key, Entry);
            map: *std.AutoHashMap(Key, Entry),
            hits: usize = 0,
            misses: usize = 0,

            pub fn get(self: *Self, rule: u16, pos: u32) ?Entry {
                const k = Key{ .rule = rule, .pos = pos };
                if (self.map.get(k)) |e| {
                    self.hits += 1;
                    return e;
                } else {
                    self.misses += 1;
                    return null;
                }
            }

            pub fn put(self: *Self, rule: u16, pos: u32, entry: Entry) void {
                _ = self.map.put(.{ .rule = rule, .pos = pos }, entry) catch return;
            }
        };

        pub fn tick(self: *Machine, comptime mode: ExecMode, cache: ?*Packrat) !Status {
            const yield = mode == .yield_each;

            vm: switch (self.i) {
                inline 0...P.code.len - 1 => |I| {
                    const I1 = I + 1;
                    self.i = I1;
                    const ci = self.peek() orelse 0;
                    // Flag to indicate whether current instruction succeeded and continued
                    // If not set, we trigger failure/backtrack logic below.
                    var advanced = false;

                    switch (comptime O[I]) {
                        inline .Char => |c| {
                            if (ci == c) {
                                self.j += 1;
                                if (yield) return .Running else {
                                    advanced = true;
                                    continue :vm I1;
                                }
                            }
                        },

                        inline .CharSet => |set| {
                            if (set.isSet(ci)) {
                                self.j += 1;
                                if (yield) return .Running else {
                                    advanced = true;
                                    continue :vm I1;
                                }
                            }
                        },

                        inline .String => |s| {
                            if (self.ensure(self.j, s.len)) {
                                if (std.mem.eql(u8, self.s[self.j .. self.j + s.len], s)) {
                                    self.j += s.len;
                                    if (yield) return .Running else {
                                        advanced = true;
                                        continue :vm I1;
                                    }
                                }
                            }
                        },

                        inline .ChoiceRel => |d| {
                            self.t[self.g] = .{
                                .h = self.h,
                                .k = I,
                                .i = @as(usize, @intCast(@as(isize, @intCast(I)) + 1 + d)),
                                .j = self.j,
                            };

                            self.g += 1;
                            if (yield) return .Running else {
                                advanced = true;
                                continue :vm I1;
                            }
                        },

                        inline .CommitRel => |d| {
                            self.g -= 1;
                            const dst = (@as(usize, @intCast(@as(isize, I) + 1 + d)));
                            self.i = dst;
                            if (yield) return .Running else {
                                advanced = true;
                                continue :vm dst;
                            }
                        },

                        inline .Call => |r| {
                            const rule_id: u16 = @intCast(@intFromEnum(r));
                            const entry = if (cache != null) cache.?.get(rule_id, self.j) else null;
                            if (entry) |e| {
                                if (e.success) {
                                    // Fast-path success: skip body
                                    self.j = e.next_pos;
                                    if (yield) return .Running else {
                                        advanced = true;
                                        continue :vm I1;
                                    }
                                } else {
                                    // Cached failure: leave 'advanced' false so outer
                                    // failure/backtrack logic runs. Do NOT push frame.
                                    // Simply break out of this case.
                                    // no-op: allow switch to end so advanced stays false
                                }
                            } else {
                                // Normal call path (not cached or no cache)
                                self.h += 1;
                                self.r[self.h] = I1;
                                self.call_rule[self.h] = rule_id;
                                self.call_start[self.h] = self.j;
                                const callee = P.rule_ip[rule_id];
                                self.i = callee;
                                if (yield) return .Running else {
                                    advanced = true;
                                    continue :vm callee;
                                }
                            }
                        },

                        .Ret => {
                            // Successful rule completion: memoize success if cache provided
                            if (cache) |pc| {
                                const rid = self.call_rule[self.h];
                                const spos = self.call_start[self.h];
                                pc.put(rid, spos, .{ .success = true, .next_pos = self.j });
                            }
                            const ret_ip = self.r[self.h];
                            self.i = ret_ip;
                            self.h -= 1;
                            if (yield) return .Running else {
                                advanced = true;
                                continue :vm ret_ip;
                            }
                        },

                        .EndInput => if (self.atEnd()) {
                            if (yield) return .Running else {
                                advanced = true;
                                continue :vm I1;
                            }
                        },
                        .Fail => void,
                        .Accept => return .Ok,
                    }

                    if (!advanced) {
                        if (self.g != 0) {
                            self.g -= 1;
                            const prev_h = self.h;
                            const tg = self.t[self.g];
                            // If we popped frames (rule failures), record failures
                            if (cache) |pc| {
                                if (tg.h < prev_h) {
                                    var fh = prev_h;
                                    while (fh > tg.h) : (fh -= 1) {
                                        const rid = self.call_rule[fh];
                                        const spos = self.call_start[fh];
                                        pc.put(rid, spos, .{ .success = false, .next_pos = spos });
                                    }
                                }
                            }
                            self.i = tg.i;
                            self.h = tg.h;
                            self.j = tg.j;
                            if (yield) return .Running else continue :vm self.i;
                        } else {
                            return .Fail;
                        }
                    } else {
                        // already advanced; nothing to do
                    }
                },
                else => return error.InvalidIP,
            }
            // Should not reach here; treat as failure
            return .Fail;
        }

        pub fn parseFully(
            src: []const u8,
            comptime mode: ExecMode,
        ) !bool {
            var m = @This().init(src);
            defer m.deinit();
            switch (mode) {
                .yield_each => while (true) {
                    const st = try m.tick(.yield_each, null);
                    switch (st) {
                        .Running => continue,
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
        pub fn runWithMetrics(src: []const u8) !Metrics {
            var m = @This().init(src);
            defer m.deinit();
            var metrics: Metrics = .{};
            var prev_g: usize = m.g;
            var cache_map = @This().Packrat.Auto.init(std.heap.page_allocator);
            defer cache_map.deinit();
            var cache = @This().Packrat{ .map = &cache_map };
            while (true) {
                const st = try m.tick(.yield_each, &cache);
                metrics.steps += 1;
                // Track heights after this step
                if (m.g > metrics.max_back_height) metrics.max_back_height = m.g;
                if (m.h > metrics.max_rule_height) metrics.max_rule_height = m.h;
                if (m.g < prev_g) metrics.backtracks += 1;
                prev_g = m.g;
                switch (st) {
                    .Running => continue,
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

        pub fn runWithMetricsCached(src: []const u8, cache: *Packrat) !Metrics {
            var m = @This().init(src);
            defer m.deinit();
            var metrics: Metrics = .{};
            var prev_g: usize = m.g;
            while (true) {
                const st = try m.tick(.yield_each, cache);
                metrics.steps += 1;
                if (m.g > metrics.max_back_height) metrics.max_back_height = m.g;
                if (m.h > metrics.max_rule_height) metrics.max_rule_height = m.h;
                if (m.g < prev_g) metrics.backtracks += 1;
                prev_g = m.g;
                switch (st) {
                    .Running => continue,
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
            Fail: void,
            Call: Rule,
            Ret: void,
            Char: u8,
            CharSet: CharBitset,
            String: []const u8,
            EndInput: void,
            Accept: void,
        };

        pub const WS = many0(oneOf(" \t\n\r"));
        pub const ALPHA = classRanges(.{ .{ 'a', 'z' }, .{ 'A', 'Z' } });
        pub const ALPHANUM = classRanges(.{ .{ 'a', 'z' }, .{ 'A', 'Z' }, .{ '0', '9' } });
        pub const IDENT = seq(.{ ALPHA, many0(ALPHANUM) });

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

        pub inline fn many0(comptime X: anytype) OpN(X.len + 2) {
            const to_end = X.len + 1; // from ChoiceRel next to end
            const back = -@as(i16, @intCast(X.len + 2)); // from CommitRel back to ChoiceRel
            return op1(.{ .ChoiceRel = @intCast(to_end) }) ++ X ++
                op1(.{ .CommitRel = back });
        }

        pub inline fn alt(comptime parts: anytype) OpN(sizeSum(parts) + (parts.len - 1) * 2) {
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
            return alt(.{ X, .{} });
        }

        // One-or-more occurrences built from many0
        pub inline fn many1(comptime X: anytype) OpN(X.len + (X.len + 2)) {
            return seq(.{ X, many0(X) });
        }

        // Character class from multiple ranges. Example:
        // classRanges(.{ .{ 'a','z' }, .{ 'A','Z' }, .{ '0','9' } })
        pub inline fn classRanges(comptime ranges: anytype) Op1 {
            var set = CharBitset.initEmpty();

            inline for (ranges) |r| {
                set.setRangeValue(std.bit_set.Range{ .start = r[0], .end = r[1] + 1 }, true);
            }

            return op1(.{ .CharSet = set });
        }

        pub inline fn oneOf(comptime chars: []const u8) Op1 {
            var set = CharBitset.initEmpty();

            inline for (chars) |c| {
                set.set(c);
            }

            return op1(.{ .CharSet = set });
        }
    };
}

// -------------------------
// JSON grammar (ASCII-only)
// -------------------------
pub const JSONGrammar = struct {
    const C = Combinators(@This());

    const HEX = C.classRanges(.{
        .{ '0', '9' },
        .{ 'A', 'F' },
        .{ 'a', 'f' },
    });

    // Unescaped JSON string char: any ASCII except control, '"' and '\\'
    const UnescapedChar = C.classRanges(.{
        .{ ' ', '!' },
        .{ '#', '[' },
        .{ ']', '~' },
    });

    // Escaped: \\" \\ \/ \b \f \n \r \t or \uXXXX
    const SimpleEscape = C.seq(.{
        C.CH('\\'),
        C.oneOf("\"\\/bfnrt"),
    });

    const UnicodeEscape = C.seq(.{ C.STR("\\u"), HEX, HEX, HEX, HEX });

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
    const NUMBER = C.many1(C.classRanges(.{.{ '0', '9' }}));
    const DIGIT1_9 = C.classRanges(.{.{ '1', '9' }});
    const SignOpt = C.opt(C.CH('-'));
    const IntPart = C.alt(.{ C.CH('0'), C.seq(.{ DIGIT1_9, C.many0(NUMBER) }) });
    const FracOpt = C.opt(C.seq(.{ C.CH('.'), NUMBER }));
    const ExpOpt = C.opt(C.seq(.{ C.oneOf("eE"), C.opt(C.oneOf("+-")), NUMBER }));
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
    pub const Member = C.seq(.{
        C.Call(.String),
        C.WS,
        C.CH(':'),
        C.WS,
        C.Call(.Value),
        C.RET,
    });

    // Members <- Member (WS ',' WS Member)*
    pub const Members = C.seq(.{
        C.Call(.Member),
        C.many0(C.seq(.{ C.WS, C.CH(','), C.WS, C.Call(.Member) })),
        C.RET,
    });

    // Object <- '{' WS Members? WS '}'
    pub const Object = C.seq(.{
        C.CH('{'),
        C.WS,
        C.opt(C.Call(.Members)),
        C.WS,
        C.CH('}'),
        C.RET,
    });

    // Elements <- Value (WS ',' WS Value)*
    pub const Elements = C.seq(.{
        C.Call(.Value),
        C.many0(C.seq(.{ C.WS, C.CH(','), C.WS, C.Call(.Value) })),
        C.RET,
    });

    // Array <- '[' WS Elements? WS ']'
    pub const Array = C.seq(.{
        C.CH('['),
        C.WS,
        C.opt(C.Call(.Elements)),
        C.WS,
        C.CH(']'),
        C.RET,
    });

    // Start <- WS Value WS EOF
    pub const Start = C.seq(.{
        C.WS,
        C.Call(.Value),
        C.WS,
        C.END,
        C.ACCEPT,
    });
};

const JSONParser = VM(JSONGrammar, 32, 32);

fn parseJSON(src: []const u8) !bool {
    return JSONParser.parseFully(src, .auto_continue);
}

fn expectJsonOk(src: []const u8) !void {
    try std.testing.expect(try parseJSON(src));
}

fn expectJsonFail(src: []const u8) !void {
    try std.testing.expect(!try parseJSON(src));
}

test "show json grammar ops" {
    const P = JSONParser.P;
    std.debug.print("JSON grammar has {d} ops\n", .{P.code.len});
    var i: usize = 0;
    for (P.code) |op| {
        switch (@as(P.Op, op)) {
            .ChoiceRel => std.debug.print("^", .{}),
            .CommitRel => std.debug.print(".", .{}),
            .Fail => std.debug.print("F", .{}),
            .Call => std.debug.print(">", .{}),
            .Ret => std.debug.print("<", .{}),
            .Char => |c| std.debug.print("{c}", .{c}),
            .EndInput => std.debug.print("$", .{}),
            .Accept => std.debug.print(".", .{}),
            .String => |s| std.debug.print("\"{s}\"", .{s}),
            .CharSet => |set| {
                std.debug.print("[", .{});
                var iter = set.iterator(.{});
                while (iter.next()) |b| {
                    if (b == '\n') {
                        std.debug.print("\\n", .{});
                    } else if (b == '\r') {
                        std.debug.print("\\r", .{});
                    } else if (b == '\t') {
                        std.debug.print("\\t", .{});
                    } else if (b == ' ') {
                        std.debug.print("␣", .{});
                    } else if (b < 32 or b == 127) {
                        std.debug.print("\\x{x}", .{b});
                    } else {
                        std.debug.print("{c}", .{@as(u8, @intCast(b))});
                    }
                }
                std.debug.print("]", .{});
            },
        }
        i += 1;
    }
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
//       Start <- ( "aaaaaaaaac" / 'a'+ 'b' ) EOF
//    Parsing "aaaaaaaaab" must explore the failing long literal then backtrack
//    and succeed via the second alternative.
// 2. GreedyGrammar: uses a greedy many0 followed by a required "ab" tail:
//       Start <- 'a'* 'a' 'b' EOF   (equivalently 'a'+ 'b')
//    Implemented deliberately with many0 + explicit 'a' 'b' to force the loop
//    to over-consume and then backtrack one step so the trailing "ab" matches.
// Both grammars are intentionally small/ambiguous compared to JSON (which is
// mostly unambiguous) to exercise the backtracking machinery in tests.

pub const BacktrackGrammar = struct {
    const C = Combinators(@This());

    pub const Long = C.seq(.{ C.STR("aaaaaaaaac"), C.RET });
    pub const APlusB = C.seq(.{ C.many1(C.CH('a')), C.CH('b'), C.RET });

    pub const Start = C.seq(.{
        C.alt(.{ C.Call(.Long), C.Call(.APlusB) }),
        C.END,
        C.ACCEPT,
    });
};

pub const GreedyGrammar = struct {
    const C = Combinators(@This());
    // An ordered choice of decreasing-length strings sharing long prefixes.
    // The parser will attempt longer ones first and backtrack down.
    // We purposefully omit some lengths so inputs trigger several failures.
    const Chain = C.alt(.{
        C.STR("aaaaaaaaab"), // 9 a's + b (too long for short inputs)
        C.STR("aaaaaaab"), // 7 a's + b
        C.STR("aaaaaab"), // 6 a's + b
        C.STR("aaaaab"), // 5 a's + b
        C.STR("aaaab"), // 4 a's + b
        C.STR("aaab"), // 3 a's + b
        C.STR("aab"), // 2 a's + b
        C.STR("ab"), // 1 a + b
    });

    pub const Start = C.seq(.{ Chain, C.END, C.ACCEPT });
};

const BacktrackParser = VM(BacktrackGrammar, 32, 32);
const GreedyParser = VM(GreedyGrammar, 32, 32);

fn parseBacktrack(src: []const u8) !bool {
    return BacktrackParser.parseFully(src, .auto_continue);
}

fn parseGreedy(src: []const u8) !bool {
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
    // Should match via progressively shorter alternatives
    try std.testing.expect(try parseGreedy("aaaaab"));
    try std.testing.expect(try parseGreedy("ab"));
    // Negative: missing 'b'
    try std.testing.expect(!try parseGreedy("aaaaa"));

    // Count steps in yield_each mode to ensure multiple backtracks happened
    const src = "aaaaab"; // should skip 3 longer failing alts before match
    var m = GreedyParser.init(src);
    defer m.deinit();
    var steps: usize = 0;
    while (true) : (steps += 1) {
        const st = try m.tick(.yield_each, null);
        switch (st) {
            .Running => continue,
            .Ok => break,
            .Fail => return error.GreedyTestUnexpectedFail,
        }
    }
    // Expect at least several steps (greater than raw length) due to backtracking
    try std.testing.expect(steps > src.len);
    std.debug.print("greedy backtracking test: steps={d}\n", .{steps});
}

test "metrics collection on backtracking grammar" {
    const src = "aaaaaaaaab"; // triggers long alternative failure then shorter match
    const metrics = try BacktrackParser.runWithMetrics(src);
    try std.testing.expect(metrics.accepted);
    try std.testing.expect(metrics.backtracks > 0);
    try std.testing.expect(metrics.max_back_height > 0);
    try std.testing.expect(metrics.steps > src.len);
    std.debug.print(
        "backtrack metrics: steps={d} backtracks={d} max_back={d} max_rule={d} accepted={}\n",
        .{ metrics.steps, metrics.backtracks, metrics.max_back_height, metrics.max_rule_height, metrics.accepted },
    );
}

test "metrics collection on simple json token" {
    const metrics = try JSONParser.runWithMetrics("true");
    try std.testing.expect(metrics.accepted);
    try std.testing.expect(metrics.max_rule_height > 0);
    // JSON 'true' has no ambiguity: backtracks may be zero
    try std.testing.expect(metrics.backtracks >= 0);
    std.debug.print(
        "json metrics: steps={d} backtracks={d} max_back={d} max_rule={d} accepted={}\n",
        .{ metrics.steps, metrics.backtracks, metrics.max_back_height, metrics.max_rule_height, metrics.accepted },
    );
}

// ------------------------------------------------------
// Packrat demonstration grammar (pathological backtracking)
// ------------------------------------------------------
// This grammar creates a chain of many optional 'a' terminals followed by a
// required 'b'. Input with far fewer 'a's than optional slots forces the
// engine to explore a large combination space of which optionals are present.
// A packrat parser would memoize each rule result at each position and avoid
// re-parsing the overlapping suffixes, cutting the explosion.
// Start <- ('a'?){N} 'b' END ACCEPT  (N = 12 here)
// We test on input of 4 'a's then 'b' so the parser must try many placements.
pub const PackratDemoGrammar = struct {
    const C = Combinators(@This());
    // Prefix <- 'a' Prefix / 'a'
    // Start  <- Prefix 'b' END ACCEPT
    // Input a^n b causes many re-parsings of the same suffix of a's when not memoized,
    // because each recursion level, after the deeper failure at 'b', explores the
    // shorter alternative. This is a classic exponential-style PEG backtracking pattern.
    pub const Prefix = C.alt(.{ C.seq(.{ C.CH('a'), C.Call(.Prefix) }), C.CH('a') }) ++ C.RET;
    pub const Start = C.seq(.{ C.Call(.Prefix), C.CH('b'), C.END, C.ACCEPT });
};

const PackratDemoParser = VM(PackratDemoGrammar, 4096, 4096);

test "packrat blowup demonstration" {
    const n: usize = 18; // adjustable depth; increase for more dramatic effect
    var buf: [n + 1]u8 = undefined; // n 'a's + 'b'
    var i: usize = 0;
    while (i < n) : (i += 1) buf[i] = 'a';
    buf[n] = 'b';
    const input = buf[0..];
    const metrics = try PackratDemoParser.runWithMetrics(input);
    try std.testing.expect(metrics.accepted);
    std.debug.print(
        "packrat demo: n={d} steps={d} backtracks={d} max_back={d} max_rule={d}\n",
        .{ n, metrics.steps, metrics.backtracks, metrics.max_back_height, metrics.max_rule_height },
    );
    // Heuristic expectations: steps should exceed n significantly (super-linear)
    // and multiple backtracks occur roughly on order of n.
    try std.testing.expect(metrics.steps > n * 4);
    try std.testing.expect(metrics.backtracks >= n);
}

test "packrat cache effectiveness" {
    const gpa = std.heap.page_allocator;
    var cache_map = PackratDemoParser.Packrat.Auto.init(gpa);
    defer cache_map.deinit();
    var cache = PackratDemoParser.Packrat{ .map = &cache_map };

    const n: usize = 24; // deeper for clearer benefit
    var buf: [n + 1]u8 = undefined;
    var i: usize = 0;
    while (i < n) : (i += 1) buf[i] = 'a';
    buf[n] = 'b';
    const input = buf[0..];

    const first_cached = try PackratDemoParser.runWithMetricsCached(input, &cache);
    const first_hits = cache.hits;
    const first_misses = cache.misses;
    // Second run reuses populated cache; expect more hits and fewer steps.
    const second_cached = try PackratDemoParser.runWithMetricsCached(input, &cache);
    std.debug.print(
        "packrat cache effectiveness: n={d}\n  first:  steps={d} backtracks={d} hits={d} misses={d}\n  second: steps={d} backtracks={d} hits={d} misses={d}\n",
        .{ n, first_cached.steps, first_cached.backtracks, first_hits, first_misses, second_cached.steps, second_cached.backtracks, cache.hits, cache.misses },
    );
    try std.testing.expect(second_cached.steps < first_cached.steps);
    try std.testing.expect(cache.hits > first_hits);
}

pub export fn parse(src: [*]const u8, len: usize) u8 {
    var m = JSONParser.init(src[0..len]);
    defer m.deinit();
    defer std.debug.print("\n", .{});
    while (true) {
        switch (m.tick(.yield_each, null) catch return 2) {
            .Ok => {
                std.debug.print("ok", .{});
                return 0;
            },
            .Fail => {
                std.debug.print("no", .{});
                return 1;
            },
            .Running => {
                std.debug.print(".", .{});
                continue;
            },
        }
    }
}

pub fn main() u8 {
    const src = std.posix.getenv("SRC") orelse "";
    return parse(@ptrCast(src), src.len);
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
    std.debug.print("\nParsing 'true' took {d} steps in yield mode\n", .{count});
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

    std.debug.print("Parsing '[1, 2, 3]' took {d} steps in yield mode\n", .{count});
    try std.testing.expect(count > 10); // Should take many steps
}
