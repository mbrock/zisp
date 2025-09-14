// Let's try to design a new Peg VM grammar "DSL" to improve on pegvm.zig's approach.
//
// The biggest problem with pegvm.zig is that grammar rules are pub const declarations
// of various specific [N]Op types, and their values are mutually recursively defined!
//
// In order to have nice tab completion and a semantic structure, we want to use the
// actual names of the rules, denote rules by actually referencing them, rather than
// indirectly mentioning them by some confusing generic auto-generated enum.
//
// So we use pointers to the rules to denote them in the calls of other rules.
// But the values of the rules are heterogenously sized arrays, so their locations
// are not trivially determined, even though they only exist in comptime!
//
// This leads to actual compiler crashes unless we very carefully control the order
// of rule definition and put explicit size annotations on certain rules,
// which is horrible.  So we need a better approach.
//
// We don't need sized arrays.  We can use slices at comptime too.
//
// And there are container items that work well with mutually recursive definitions.
// Namely, functions!
//
// So instead of a rule being a public constant opcode array, it will be a public function
// that ... what?  Returns a slice of opcodes?  Or returns a struct that contains
// a slice of opcodes?  Or takes a buffer to fill in with opcodes?
//
// This is partly an ergonomic question.  We want the grammar definitions to be as
// concise and clear as possible, like a grammar specification, without boilerplate,
// while also being valid Zig code.  So sense the functions should "make sense" to read;
// they should somehow be semantically transparent, to coin a phrase?
//
// Is a PEG rule a function, conceptually, denotationally?  A function of what?
//
// What if we think of a PEG rule definition as an action on a grammar compilation?
// Maybe it's like a compilation unit, emitting code slices that linking combines to
// a fully defined program.
//

const std = @import("std");

pub inline fn Grammar(rules: type) type {
    return struct {
        pub fn compile() []const Op {
            comptime var i = 0;
            inline for (comptime std.meta.declarations(rules)) |decl| {
                const rule = @field(rules, decl.name);
                switch (@typeInfo(@TypeOf(rule))) {
                    .@"fn" => |f| {
                        inline for (f.params) |param| {
                            if (param.type) |t| {
                                i += compile1(t).len;
                            } else {
                                @compileError("Grammar rule parameters must have types");
                            }
                        }
                    },
                    else => {
                        @compileError("Grammar rules must be functions");
                    },
                }
            }

            var ops: [i]Op = undefined;
            var pos: usize = 0;
            inline for (comptime std.meta.declarations(rules)) |decl| {
                const rule = @field(rules, decl.name);
                switch (@typeInfo(@TypeOf(rule))) {
                    .@"fn" => |f| {
                        inline for (f.params) |param| {
                            if (param.type) |t| {
                                const part = compile1(t);
                                @memmove(ops[pos..][0..part.len], part);
                                pos += part.len;
                            } else {
                                @compileError("Grammar rule parameters must have types");
                            }
                        }
                    },
                    else => {
                        @compileError("Grammar rules must be functions");
                    },
                }
            }

            return &ops;
        }

        pub fn compile1(t: type) []const Op {
            switch (@typeInfo(t)) {
                .pointer => |pt| {
                    if (pt.size == .slice) {
                        return &[1]Op{.{ .op_rescue = 1 }} ++ compile1(pt.child) ++ &[1]Op{.{ .op_commit = 1 }};
                    } else {
                        @compileError("Grammar type must be a struct of slice-returning functions");
                    }
                },
                .@"struct" => {
                    return t.compile(rules);
                },
                else => |_| {
                    @compileError("Grammar type must be a struct of slice-returning functions");
                },
            }
        }

        pub fn describe(out: *std.Io.Writer) !void {
            try out.print("Grammar {{\n", .{});
            inline for (comptime std.meta.declarations(rules)) |decl| {
                const rule = @field(rules, decl.name);
                try out.print("  {s}: ", .{decl.name});
                switch (@typeInfo(@TypeOf(rule))) {
                    .@"fn" => |f| {
                        inline for (f.params) |param| {
                            if (param.type) |t| {
                                try describeParamType(out, t);
                            } else {
                                try out.print("unknown param type\n", .{});
                            }
                            try out.print(" >> ", .{});
                        }
                    },
                    else => {
                        try out.print("unknown rule type\n", .{});
                    },
                }

                try out.print("\n", .{});
            }
            try out.print("}}\n", .{});
        }

        fn describeParamType(out: *std.Io.Writer, t: type) !void {
            switch (@typeInfo(t)) {
                .pointer => |pt| {
                    if (pt.size == .slice) {
                        try out.print("many0(", .{});
                        try describeParamType(out, pt.child);
                        try out.print(")", .{});
                    }
                },

                .@"struct" => {
                    try t.describe(out);
                },

                else => |x| try out.print("{any}", .{x}),
            }
        }
    };
}

pub const Op = union(enum) {
    op_charset: std.StaticBitSet(256),
    op_range: struct { a: u8, b: u8 },
    op_call: []const u8,
    op_rescue: comptime_int,
    op_commit: comptime_int,
    op_reject: void,
};

pub fn charset(s: []const u8) type {
    return struct {
        pub fn describe(out: *std.Io.Writer) !void {
            try out.print("charset(\"{s}\")", .{s});
        }

        pub fn compile(_: type) []const Op {
            var bs = std.bit_set.ArrayBitSet(usize, 256).initEmpty();
            for (s) |c| {
                bs.set(c);
            }
            return &[1]Op{.{ .op_charset = bs }};
        }
    };
}

pub fn range(a: u8, b: u8) type {
    return struct {
        pub fn describe(out: *std.Io.Writer) !void {
            try out.print("range('{c}'-'{d}')", .{ a, b });
        }

        pub fn compile(_: type) []const Op {
            return &[1]Op{.{ .op_range = .{ .a = a, .b = b } }};
        }
    };
}

pub fn call(r: anytype) type {
    return struct {
        pub fn describe(out: *std.Io.Writer) !void {
            try out.print("call({any})", .{&r});
        }

        pub fn compile(g: type) []const Op {
            inline for (comptime std.meta.declarations(g)) |decl| {
                if (@TypeOf(@field(g, decl.name)) == @TypeOf(r)) {
                    if (@field(g, decl.name) == r) {
                        return &[1]Op{.{ .op_call = decl.name }};
                    }
                }
            }
            @compileError("call to unknown rule " ++ @typeName(@TypeOf(r)));
        }
    };
}

pub const demoGrammar = Grammar(struct {
    pub fn skip(_: []charset(" \t\n\r")) void {}

    pub fn integer(
        d0: range('1', '9'),
        ds: []range('0', '9'),
        _: call(skip),
    ) !i32 {
        const small = try std.fmt.parseInt(i32, ds.slice, 10);
        const order = ds.len;
        return @as(i32, d0) * std.math.pow(10, order) + small;
    }
});

pub fn main() !void {
    const stdout = std.fs.File.stdout();
    var outbuf: [1024]u8 = undefined;
    var outfs = stdout.writer(&outbuf);
    var out = &outfs.interface;

    try demoGrammar.describe(out);
    try out.print("\n", .{});
    inline for (demoGrammar.compile()) |op| {
        try out.print("{any}\n", .{op});
    }
    try out.flush();
}
