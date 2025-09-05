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
    comptime Grammar: type,
    comptime TrailCap: usize,
    comptime StackCap: usize,
) type {
    return struct {
        pub const P = ProgramFor(Grammar);

        pub const Backtrack = struct {
            ip: u16,
            csp: u16,
            pos: u32,

            // comptime {
            //     if (@alignOf(@This()) != 8) @compileError("alignment confusion");
            //     if (@sizeOf(@This()) != 8 * 3) @compileError("size confusion");
            // }
        };

        pub const CallFrame = u16;

        const Machine = @This();

        src: []const u8,
        cur: u32 = 0,

        ip: u16 = P.start_ip,

        trailbuf: [TrailCap]Backtrack = undefined,
        trailtop: u16 = 0,
        stackbuf: [StackCap]u16 = undefined,
        stacktop: u16 = 0,

        pub fn init(
            src: []const u8,
        ) Machine {
            return .{
                .src = src,
            };
        }

        pub fn deinit(_: *Machine) void {}

        pub const Status = enum { Ok, Fail, Running };

        fn ensure(self: @This(), from: usize, n: usize) bool {
            return from + n <= self.src.len;
        }

        fn atEnd(self: @This()) bool {
            return self.cur >= self.src.len;
        }

        fn peek(self: @This()) ?u8 {
            if (self.cur >= self.src.len) return null;
            return self.src[self.cur];
        }

        fn lookingAt(self: @This(), c: u8) bool {
            return self.cur < self.src.len and self.src[self.cur] == c;
        }

        fn lookingAtMatch(self: @This(), set: CharBitset) bool {
            if (self.cur >= self.src.len) return false;
            return set.isSet(self.src[self.cur]);
        }

        fn take(self: @This()) ?u8 {
            if (self.cur >= self.src.len) return null;
            const b = self.src[self.cur];
            self.cur += 1;
            return b;
        }

        pub fn tick(self: *Machine, comptime mode: ExecMode) !Status {
            const yield = mode == .yield_each;

            vm: switch (self.ip) {
                inline 0...P.code.len - 1 => |ip| {
                    const next = ip + 1;
                    self.ip = next;

                    switch (comptime P.code[ip]) {
                        inline .Char => |c| {
                            if (self.lookingAt(c)) {
                                self.cur += 1;
                                if (yield) return .Running else continue :vm next;
                            }
                        },

                        inline .CharSet => |set| {
                            if (self.lookingAtMatch(set)) {
                                self.cur += 1;
                                if (yield) return .Running else continue :vm next;
                            }
                        },

                        inline .String => |s| {
                            if (self.ensure(self.cur, s.len)) {
                                if (std.mem.eql(u8, self.src[self.cur .. self.cur + s.len], s)) {
                                    self.cur += s.len;
                                    if (yield) return .Running else continue :vm next;
                                }
                            }
                        },

                        inline .ChoiceRel => |d| {
                            if (self.trailtop == self.trailbuf.len - 1) return error.TrailOverflow;
                            self.trailtop += 1;
                            self.trailbuf[self.trailtop] = .{
                                .ip = @as(usize, @intCast(@as(isize, @intCast(ip)) + 1 + d)),
                                .pos = self.cur,
                                .csp = self.stacktop,
                            };

                            if (yield) return .Running else continue :vm next;
                        },

                        inline .CommitRel => |d| {
                            if (self.trailtop == 0) return error.TrailUnderflow;
                            self.trailtop -= 1;
                            const dst = (@as(usize, @intCast(@as(isize, ip) + 1 + d)));
                            self.ip = dst;
                            if (yield) return .Running else continue :vm dst;
                        },

                        inline .Call => |r| {
                            if (self.stacktop == self.stackbuf.len - 1) return error.StackOverflow;
                            self.stacktop += 1;
                            self.stackbuf[self.stacktop] = ip + 1;
                            const callee = P.rule_ip[@intCast(@intFromEnum(r))];
                            self.ip = callee;
                            if (yield) return .Running else continue :vm callee;
                        },

                        .Ret => if (self.stacktop == 0)
                            return error.StackUnderflow
                        else {
                            const ret_ip = self.stackbuf[self.stacktop];
                            self.ip = ret_ip;
                            self.stacktop -= 1;
                            if (yield) return .Running else continue :vm ret_ip;
                        },

                        .EndInput => if (self.atEnd()) if (yield) return .Running else continue :vm next,
                        .Fail => void,
                        .Accept => return .Ok,
                    }

                    if (self.trailtop != 0) {
                        const bt = self.trailbuf[self.trailtop];
                        self.trailtop -= 1;
                        self.cur = bt.pos;
                        self.stacktop = bt.csp;
                        self.ip = bt.ip;
                        if (yield) return .Running else continue :vm bt.ip;
                    } else {
                        return .Fail;
                    }
                },

                else => return error.InvalidIP,
            }
        }

        pub fn parseFully(
            src: []const u8,
            comptime mode: ExecMode,
        ) !bool {
            var m = @This().init(src);
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

pub export fn parse(src: [*]const u8, len: usize) u8 {
    var m = JSONParser.init(src[0..len]);
    defer m.deinit();
    defer std.debug.print("\n", .{});
    while (true) {
        switch (m.tick(.yield_each) catch return 2) {
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
    const st1 = try m.tick(.yield_each);
    try std.testing.expect(st1 == .Running);

    // Keep ticking until we get a final result
    var count: usize = 1;
    while (true) : (count += 1) {
        const st = try m.tick(.yield_each);
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
        const st = try m.tick(.yield_each);
        switch (st) {
            .Running => continue,
            .Ok => break,
            .Fail => return error.TestUnexpectedFailure,
        }
    }

    std.debug.print("Parsing '[1, 2, 3]' took {d} steps in yield mode\n", .{count});
    try std.testing.expect(count > 10); // Should take many steps
}
