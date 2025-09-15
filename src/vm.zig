const std = @import("std");
const peg = @import("peg.zig");

pub const Mode = enum {
    Step,
    Loop,
};

pub fn VM(comptime Program: []const peg.Abs) type {
    return struct {
        const Self = @This();

        sp: u32 = 0,
        text: [:0]const u8,
        saves: BoundedStack(SaveFrame, 128) = .{},
        calls: BoundedStack(CallFrame, 32) = .{},

        pub fn init(text: [:0]const u8) Self {
            return Self{
                .text = text,
            };
        }

        pub const SaveFrame = struct {
            ip: u32,
            sp: u32,
            call_depth: u32,
        };

        pub const CallFrame = struct {
            return_ip: u32,
            rule_id: u32,
            start_sp: u32,
        };

        pub fn next(self: *Self, ip: u32, comptime mode: Mode) !(if (mode == .Loop) void else ?u32) {
            const loop = switch (mode) {
                .Step => false,
                .Loop => true,
            };

            vm: switch (ip) {
                inline 0...Program.len - 1 => |IP| {
                    const OP = Program[IP];
                    const IP1 = IP + 1;
                    const ch = self.text[self.sp];

                    switch (OP) {
                        .read => |set| {
                            if (set.isSet(ch)) {
                                self.sp += 1;
                                if (loop) continue :vm IP1 else return IP1;
                            }
                        },

                        .call => |target| {
                            try self.calls.push(.{
                                .return_ip = IP1,
                                .rule_id = target,
                                .start_sp = self.sp,
                            });

                            if (loop) continue :vm target else return target;
                        },

                        .frob => |ctrl| switch (ctrl.fx) {
                            .push => {
                                try self.saves.push(.{
                                    .ip = ctrl.ip,
                                    .sp = self.sp,
                                    .call_depth = @intCast(self.calls.len),
                                });
                                if (loop) continue :vm IP1 else return IP1;
                            },

                            .drop => {
                                _ = self.saves.pop();
                                if (loop) continue :vm ctrl.ip else return ctrl.ip;
                            },

                            .move => {
                                self.saves.items[self.saves.len - 1].sp = self.sp;
                                if (loop) continue :vm ctrl.ip else return ctrl.ip;
                            },

                            .wipe => {
                                const save = self.saves.pop().?;
                                self.sp = save.sp;
                                if (loop) continue :vm ctrl.ip else return ctrl.ip;
                            },
                        },

                        .done => {
                            if (self.calls.pop()) |frame| {
                                if (loop) continue :vm frame.return_ip else return frame.return_ip;
                            } else {
                                if (self.sp == self.text.len) {
                                    return (if (mode == .Loop) {} else null);
                                } else {
                                    return error.UnconsumedInput;
                                }
                            }
                        },

                        .over => return (if (mode == .Loop) {} else null),
                        .fail => {},
                    }

                    if (self.saves.pop()) |save| {
                        self.sp = save.sp;
                        self.calls.len = save.call_depth;

                        if (loop) continue :vm save.ip else return save.ip;
                    }

                    return error.ParseFailed;
                },
                else => return (if (mode == .Loop) {} else null),
            }
        }

        pub fn run(self: *Self) !void {
            try self.next(0, .Loop);
        }

        pub fn parse(
            text: [:0]const u8,
        ) !void {
            var vm = Self{
                .text = text,
            };
            _ = try vm.run();
        }

        pub fn countSteps(text: [:0]const u8) !u32 {
            var self = Self.init(text);
            var ip: u32 = 0;
            var count: u32 = 1;

            while (try self.next(ip, .Step)) |new_ip| {
                ip = new_ip;
                count += 1;
            }

            return count;
        }
    };
}

pub fn BoundedStack(comptime T: type, comptime capacity: usize) type {
    return struct {
        items: [capacity]T = undefined,
        len: usize = 0,

        pub fn push(self: *@This(), item: T) !void {
            if (self.len >= capacity) return error.StackOverflow;
            self.items[self.len] = item;
            self.len += 1;
        }

        pub fn pop(self: *@This()) ?T {
            if (self.len == 0) return null;
            self.len -= 1;
            return self.items[self.len];
        }
    };
}

pub const SimpleGrammar = struct {
    pub fn main(_: peg.CharSet("a"), _: peg.CharSet("b")) void {}
};

const ChoiceGrammar = struct {
    pub fn main(
        _: union(enum) {
            ab: struct { a: peg.CharSet("a"), b: peg.CharSet("b") },
            ac: struct { a: peg.CharSet("a"), c: peg.CharSet("c") },
        },
    ) void {}
};

pub const RecursiveGrammar = struct {
    pub fn main(_: peg.Call(.expr)) void {}

    pub fn expr(
        _: union(enum) {
            number: peg.Call(.number),
            parens: struct {
                open: peg.CharSet("("),
                expr: peg.Call(.expr),
                close: peg.CharSet(")"),
            },
        },
    ) void {}

    pub fn number(
        _: peg.CharRange('0', '9'),
        _: []peg.CharRange('0', '9'),
    ) void {}
};

const KleeneGrammar = struct {
    pub fn main(
        _: []peg.CharSet("a"), // Zero or more 'a's
        _: peg.CharSet("b"),
    ) void {}
};

const OptionalGrammar = struct {
    pub fn main(
        _: ?peg.CharSet("a"),
        _: peg.CharSet("b"),
    ) void {}
};

fn step(vm: anytype, ip: *u32) !bool {
    if (try vm.next(ip.*, .Step)) |new_ip| {
        ip.* = new_ip;
        return true;
    } else {
        return false;
    }
}

fn expectParseSuccess(comptime P: peg.Opcodes, text: [:0]const u8) !void {
    try VM(P).parse(text);
    _ = try VM(P).countSteps(text);
}

fn expectParseFailure(comptime P: peg.Opcodes, text: [:0]const u8) !void {
    try std.testing.expectError(error.ParseFailed, VM(P).parse(text));
    try std.testing.expectError(error.ParseFailed, VM(P).countSteps(text));
}

// Test the manual construction for now
test "basic VM iteration" {
    const TestProgram = comptime [_]peg.Abs{
        .{ .read = charSet('a') },
        .{ .read = charSet('b') },
        .over,
    };

    try expectParseSuccess(&TestProgram, "ab");
    try expectParseFailure(&TestProgram, "ac");
}

test "VM with backtracking" {
    // Program: (a b) / (a c)
    // Using rescue/commit for backtracking
    const BacktrackProgram = comptime [_]peg.Abs{
        .{ .frob = .{ .fx = .push, .ip = 4 } }, // rescue to 4
        .{ .read = charSet('a') }, // match 'a'
        .{ .read = charSet('b') }, // match 'b'
        .{ .frob = .{ .fx = .drop, .ip = 6 } }, // commit to 6
        .{ .read = charSet('a') }, // match 'a'
        .{ .read = charSet('c') }, // match 'c'
        .over,
    };

    try expectParseSuccess(&BacktrackProgram, "ab");
    try expectParseSuccess(&BacktrackProgram, "ac");
    try expectParseFailure(&BacktrackProgram, "ad");
}

test "VM event iteration" {
    const SimpleProgram = comptime [_]peg.Abs{
        .{ .read = charSet('a') },
        .{ .read = charSet('b') },
        .over,
    };

    try std.testing.expectEqual(3, try VM(&SimpleProgram).countSteps("ab"));
}

// Helper to create a charset with one character
fn charSet(comptime c: u8) std.StaticBitSet(256) {
    comptime var set = std.StaticBitSet(256).initEmpty();
    set.set(c);
    return set;
}

// Tests using the grammar compiler
test "simple grammar compilation" {
    const ops = comptime peg.compile(SimpleGrammar);

    try expectParseSuccess(ops, "ab");
    try expectParseFailure(ops, "ac");
    try expectParseFailure(ops, "a");
}

test "choice grammar compilation" {
    const ops = comptime peg.compile(ChoiceGrammar);

    try expectParseSuccess(ops, "ab");
    try expectParseSuccess(ops, "ac");
    try expectParseFailure(ops, "ad");
}

test "kleene star grammar compilation" {
    const ops = comptime peg.compile(KleeneGrammar);

    try expectParseSuccess(ops, "b");
    try expectParseSuccess(ops, "ab");
    try expectParseSuccess(ops, "aaab");
    try expectParseFailure(ops, "aaa");
}

test "optional grammar compilation" {
    const ops = comptime peg.compile(OptionalGrammar);

    try expectParseSuccess(ops, "ab");
    try expectParseSuccess(ops, "b");
    try expectParseFailure(ops, "ac");
}

test "recursive grammar compilation" {
    const ops = comptime peg.compile(RecursiveGrammar);

    try expectParseSuccess(ops, "42");
    try expectParseSuccess(ops, "(123)");
    try expectParseSuccess(ops, "((99))");
    try expectParseFailure(ops, "(42");
}

test "demo grammar from pegvmfun" {
    const ops = comptime peg.compile(peg.demoGrammar);

    try expectParseSuccess(ops, "123   ");
    try expectParseSuccess(ops, "[123 456 789]");
    try expectParseSuccess(ops, "[[1] [2]]");
    try expectParseSuccess(ops, "[]");
}
