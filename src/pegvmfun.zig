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

pub const demoGrammar = struct {
    // Rules define their grammatical structure entirely via parameter types.
    // The grammar compiler compiles the parameter types to opcode sequences.
    //
    // At runtime, the rule functions are actually called with arguments
    // being values of the input text that matched the parameter types.
    //
    // The return type of a rule function is the type of value that the rule
    // produces when it successfully matches input text.

    const Op = OpFor(@This());

    pub fn integer(
        _: Op.range('1', '9'),
        _: []Op.range('0', '9'),
        _: Op.call(.skip),
    ) void {}

    pub fn value(
        _: union(enum) {
            integer: Op.call(.integer),
            array: Op.call(.array),
        },
    ) void {}

    pub fn array(
        _: Op.charset("["),
        _: Op.call(.skip),
        _: []Op.call(.value),
        _: Op.call(.skip),
        _: Op.charset("]"),
    ) void {}

    pub fn skip(_: []Op.charset(" \t\n\r")) void {}
};

const AsciiCtrl = enum(u8) {
    NUL = 0x00,
    SOH = 0x01,
    STK = 0x02,
    ETX = 0x03,
    EOT = 0x04,
    ENQ = 0x05,
    ACK = 0x06,
    BEL = 0x07,
    BS = 0x08,
    @"\\t" = 0x09,
    @"\\n" = 0x0a,
    VT = 0x0b,
    NP = 0x0c,
    @"\\r" = 0x0d,
    SO = 0x0e,
    SI = 0x0f,
    DLE = 0x10,
    DC1 = 0x11,
    DC2 = 0x12,
    DC3 = 0x13,
    DC4 = 0x14,
    NAK = 0x15,
    SYN = 0x16,
    ETB = 0x17,
    CAN = 0x18,
    EM = 0x19,
    SUB = 0x1a,
    ESC = 0x1b,
    FS = 0x1c,
    GS = 0x1d,
    RS = 0x1e,
    US = 0x1f,
    SP = 0x20,
    _,
};

fn printChar(tty: std.Io.tty.Config, writer: *std.Io.Writer, c: u8) !void {
    if (std.enums.tagName(AsciiCtrl, @enumFromInt(c))) |ctrl| {
        try tty.setColor(writer, .bright_green);
        try writer.print("{s}", .{ctrl});
    } else if (c >= 33 and c < 127 and c != '\\') {
        try tty.setColor(writer, .green);
        try writer.print("{c}", .{c});
    } else {
        try tty.setColor(writer, .yellow);
        try writer.print("\\x{x:0>2}", .{c});
    }
    try tty.setColor(writer, .reset);
}

pub fn main() !void {
    const stdout_file = std.fs.File.stdout();
    var buffer: [4096]u8 = undefined;
    var stdout_writer = stdout_file.writer(&buffer);
    const stdout = &stdout_writer.interface;

    const G = comptime Grammar(demoGrammar);
    const ops = comptime G.compile(false);
    const tty = std.Io.tty.detectConfig(stdout_file);

    comptime var i = 0;
    inline for (ops) |op| {
        if (G.isStartOfRule(i)) |rule| {
            try tty.setColor(stdout, .bold);
            try stdout.print("\n&{t}:\n", .{rule});
            try tty.setColor(stdout, .reset);
        }

        try op.dump(tty, stdout, i);
        i += 1;
    }

    try stdout.flush();
}

pub inline fn Grammar(rules: type) type {
    return struct {
        const Ops = OpFor(rules);
        const Op = Ops.Rel;
        const AbsoluteOp = OpFor(rules).Abs;
        const RuleEnum = std.meta.DeclEnum(rules);
        const RuleOffsetMap = std.enums.EnumMap(RuleEnum, comptime_int);

        // Helper: Check if a declaration is a valid rule function
        fn isRuleFunction(comptime decl_type: type) bool {
            return switch (@typeInfo(decl_type)) {
                .@"fn" => true,
                else => false,
            };
        }

        // Helper: Get the function info for a rule, with validation
        fn getRuleFunctionInfo(comptime rule: anytype) std.builtin.Type.Fn {
            const T = @TypeOf(rule);
            switch (@typeInfo(T)) {
                .@"fn" => |f| return f,
                else => @compileError("Grammar rules must be functions"),
            }
        }

        // Helper: Calculate total size needed for a rule's opcodes
        fn calculateRuleSize(comptime rule: anytype) comptime_int {
            const fn_info = getRuleFunctionInfo(rule);
            var size: comptime_int = 1; // +1 for return

            inline for (fn_info.params) |param| {
                if (param.type) |param_type| {
                    size += compilePattern(param_type).len;
                } else {
                    @compileError("Grammar rule parameters must have types");
                }
            }

            return size;
        }

        // Pass 1: Calculate offsets for each rule (symbol table construction)
        fn buildRuleOffsetMap() struct { map: RuleOffsetMap, total_size: comptime_int } {
            comptime var offset_map = RuleOffsetMap.init(.{});
            comptime var current_offset: comptime_int = 0;

            inline for (comptime std.meta.tags(RuleEnum)) |rule_tag| {
                const rule_fn = @field(rules, @tagName(rule_tag));
                offset_map.put(rule_tag, current_offset);
                current_offset += calculateRuleSize(rule_fn);
            }

            return .{ .map = offset_map, .total_size = current_offset };
        }

        // Pass 2: Emit opcodes with resolved addresses (linking)
        fn emitOps(
            comptime rel: bool,
            comptime offset_map: RuleOffsetMap,
            comptime total_size: comptime_int,
        ) [total_size]OpG(RuleEnum, rel) {
            var code: [total_size]OpG(RuleEnum, rel) = undefined;
            var i: usize = 0;

            inline for (comptime std.meta.declarations(rules)) |decl| {
                const rule_fn = @field(rules, decl.name);
                if (!isRuleFunction(@TypeOf(rule_fn))) {
                    @compileError("Grammar member '" ++ decl.name ++ "' must be a function");
                }

                const fn_info = getRuleFunctionInfo(rule_fn);
                inline for (fn_info.params) |param| {
                    if (param.type) |param_type| {
                        const relative_ops = compilePattern(param_type);
                        for (relative_ops) |op| {
                            code[i] = if (rel) op else linkOpcode(op, offset_map, @intCast(i));
                            i += 1;
                        }
                    }
                }
                code[i] = .{ .ret = {} };
                i += 1;
            }

            return code;
        }

        // Helper: Apply a relative offset to an absolute address
        fn bump(base: u32, delta: i32) u32 {
            if (delta >= 0) {
                return base + @as(u32, @intCast(delta));
            } else {
                return base - @as(u32, @intCast(-delta));
            }
        }

        // Helper: Convert relative opcode to absolute opcode (resolve symbols and addresses)
        fn linkOpcode(op: Op, map: RuleOffsetMap, ip: u32) AbsoluteOp {
            return switch (op) {
                .call => |rule_tag| blk: {
                    const absolute_offset = map.getAssertContains(rule_tag);
                    break :blk .{ .call = @intCast(absolute_offset) };
                },
                .branch => |c| .{
                    .branch = .{
                        .action = c.action,
                        .offset = bump(ip + 1, c.offset),
                    },
                },
                // Non-address opcodes pass through unchanged
                inline else => |payload, tag| @unionInit(AbsoluteOp, @tagName(tag), payload),
            };
        }

        pub fn compile(comptime rel: bool) []const OpG(RuleEnum, rel) {
            const link_info = comptime buildRuleOffsetMap();
            const ops = comptime emitOps(rel, link_info.map, link_info.total_size);
            return &ops;
        }

        pub fn isStartOfRule(ip: u32) ?RuleEnum {
            const offset_map = comptime buildRuleOffsetMap().map;
            inline for (comptime std.meta.tags(RuleEnum)) |rule_tag| {
                if (offset_map.getAssertContains(rule_tag) == ip) {
                    return rule_tag;
                }
            }
            return null;
        }

        // Normalize a pattern type (e.g., []T becomes kleene(T))
        fn normalize(comptime t: type) type {
            switch (@typeInfo(t)) {
                .pointer => |ptr| {
                    if (ptr.size == .slice) {
                        return Ops.kleene(normalize(ptr.child));
                    } else {
                        @compileError("bad pattern type");
                    }
                },
                .optional => |opt| {
                    return Ops.optional(normalize(opt.child));
                },
                .@"union" => |u| {
                    if (u.tag_type != null) {
                        // Transform enum union into choice of its variants
                        var variants: [u.fields.len]type = undefined;
                        var idx: usize = 0;
                        inline for (u.fields) |field| {
                            variants[idx] = normalize(field.type);
                            idx += 1;
                        }

                        // Build nested choices
                        var choice_type = variants[0];
                        for (1..idx) |i| {
                            choice_type = Ops.choice(choice_type, variants[i]);
                        }
                        return choice_type;
                    } else {
                        @compileError("Only tagged unions (enums) are supported in grammar patterns");
                    }
                },
                // Already normalized types pass through
                else => return t,
            }
        }

        // Compile a single pattern type to opcodes
        pub fn compilePattern(comptime t: type) []const Op {
            return normalize(t).compile(rules);
        }
    };
}

pub const BranchAction = enum(u8) {
    /// Push backtrack frame, jump on fail
    cope,
    /// Pop frame and jump forward
    commit,
    /// Update frame position and jump (for loops)
    recope,
    /// Pop frame, reset text position, and jump
    rewind,
};

pub fn OpG(comptime RuleTag: type, comptime rel: bool) type {
    return union(enum) {
        /// Consume any byte that matches the bitset
        read: std.StaticBitSet(256),
        /// Call a rule (by tag or absolute address)
        call: if (rel) RuleTag else u32,
        /// Frame-manipulating instruction
        branch: struct {
            action: BranchAction,
            offset: if (rel) i32 else u32 = undefined,
        },
        /// Fail and backtrack
        fail: void,
        /// Return from rule invocation
        ret: void,
        /// Successful parse completion
        accept: void,

        fn name(op: @This()) []const u8 {
            return switch (op) {
                .branch => |x| @tagName(x.action),
                inline else => @tagName(op),
            };
        }

        pub fn dump(
            op: @This(),
            tty: std.Io.tty.Config,
            w: *std.Io.Writer,
            ip: u32,
        ) !void {
            try tty.setColor(w, .dim);
            try w.print("  0x{x:0>4}  ", .{ip});
            try tty.setColor(w, .reset);
            try w.print("{s: <6}  ", .{op.name()});

            switch (op) {
                .branch => |ctrl| {
                    if (rel == false) {
                        try tty.setColor(w, .cyan);
                        try w.print("0x{x:0>4}", .{ctrl.offset});
                    } else {
                        try tty.setColor(w, .cyan);
                        if (ctrl.offset > 0)
                            try w.writeByte('+');
                        try w.print("{d}", .{ctrl.offset});
                    }
                },
                .call => |target| {
                    if (@TypeOf(target) == u32) {
                        try tty.setColor(w, .cyan);
                        try w.print("0x{x:0>4}", .{target});
                    } else {
                        try tty.setColor(w, .blue);
                        try w.print("&{s}", .{@tagName(target)});
                    }
                },
                .read => |cs| {
                    var first = true;
                    var i: u32 = 0;
                    while (i < 256) : (i += 1) {
                        if (cs.isSet(i)) {
                            if (!first) try w.writeAll(" ");
                            first = false;

                            // Check for ranges - look ahead for consecutive characters
                            var range_end = i;
                            while (range_end + 1 < 256 and cs.isSet(range_end + 1)) : (range_end += 1) {}

                            if (range_end > i + 1) {
                                // We have a range of at least 3 characters
                                // Print start of range
                                try printChar(tty, w, @intCast(i));
                                try tty.setColor(w, .dim);
                                try w.writeAll("-");
                                try tty.setColor(w, .reset);
                                // Print end of range
                                try printChar(tty, w, @intCast(range_end));
                                i = range_end;
                            } else if (range_end == i + 1) {
                                // Just two consecutive characters - print them separately
                                try printChar(tty, w, @intCast(i));
                                try w.writeAll(" ");
                                try printChar(tty, w, @intCast(range_end));
                                i = range_end;
                            } else {
                                // Single character
                                try printChar(tty, w, @intCast(i));
                            }
                        }
                    }
                },

                inline else => {},
            }

            try tty.setColor(w, .reset);
            try w.writeAll("\n");
        }
    };
}

pub fn OpFor(comptime Rules: type) type {
    return struct {
        pub const Tag = std.meta.DeclEnum(Rules);
        pub const Rel = OpG(Tag, true);
        pub const Abs = OpG(Tag, false);

        const Op = Rel;

        pub fn charset(s: []const u8) type {
            return struct {
                pub fn compile(_: type) []const Op {
                    var bs = std.bit_set.ArrayBitSet(usize, 256).initEmpty();
                    for (s) |c| {
                        bs.set(c);
                    }
                    return &[_]Op{.{ .read = bs }};
                }
            };
        }

        pub fn range(a: u8, b: u8) type {
            return struct {
                pub fn compile(_: type) []const Op {
                    var bs = std.bit_set.ArrayBitSet(usize, 256).initEmpty();
                    for (a..b + 1) |c| {
                        bs.set(c);
                    }
                    return &[_]Op{.{ .read = bs }};
                }
            };
        }

        pub fn call(r: Tag) type {
            return struct {
                pub fn compile(_: type) []const Op {
                    return &[_]Op{.{ .call = r }};
                }
            };
        }

        pub fn Assembler(comptime max_ops: usize, comptime labels: type) type {
            const max_labels = @typeInfo(labels).@"enum".fields.len;
            return struct {
                const Self = @This();

                ops: [max_ops]Op = undefined,
                n: usize = 0,
                map: std.EnumMap(labels, i32) = std.EnumMap(labels, i32).init(.{}),
                forwards: [max_labels * 2]struct { op_index: usize, label_id: labels } = undefined,
                forward_count: usize = 0,

                pub fn mark(self: *Self, lbl: labels) *Self {
                    self.map.put(lbl, @intCast(self.n));
                    return self;
                }

                fn ctrl(self: *Self, mode: BranchAction, lbl: labels) *Self {
                    self.forwards[self.forward_count] = .{
                        .op_index = self.n,
                        .label_id = lbl,
                    };
                    self.forward_count += 1;
                    self.ops[self.n] = .{ .branch = .{ .action = mode } };
                    self.n += 1;
                    return self;
                }

                pub fn emit(self: *Self, new_ops: []const Op) *Self {
                    for (new_ops) |op| {
                        self.ops[self.n] = op;
                        self.n += 1;
                    }
                    return self;
                }

                pub fn reject(self: *Self) *Self {
                    self.ops[self.n] = .{ .fail = {} };
                    self.n += 1;
                    return self;
                }

                pub fn build(self: *Self) []const Op {
                    // Resolve forward references
                    for (0..self.forward_count) |i| {
                        const fwd = self.forwards[i];
                        const target = self.map.getAssertContains(fwd.label_id);
                        const from = @as(i32, @intCast(fwd.op_index));
                        self.ops[fwd.op_index].branch.offset = target - from - 1;
                    }

                    // Return slice of actual ops
                    const result = self.ops[0..self.n];
                    return result;
                }
            };
        }

        pub fn kleene(comptime inner: type) type {
            return struct {
                pub fn compile(g: type) []const Op {
                    const part = inner.compile(g);
                    var a = Assembler(part.len + 2, enum { loop, done }){};
                    return a
                        .mark(.loop)
                        .ctrl(.cope, .done)
                        .emit(part)
                        .ctrl(.recope, .loop)
                        .mark(.done)
                        .build();
                }
            };
        }

        pub fn optional(comptime inner: type) type {
            return struct {
                pub fn compile(g: type) []const Op {
                    const part = inner.compile(g);
                    var a = Assembler(part.len + 2, enum { done }){};
                    return a
                        .ctrl(.cope, .done)
                        .emit(part)
                        .ctrl(.commit, .done)
                        .mark(.done)
                        .build();
                }
            };
        }

        pub fn choice(comptime alt1: type, comptime alt2: type) type {
            return struct {
                pub fn compile(g: type) []const Op {
                    const ops1 = alt1.compile(g);
                    const ops2 = alt2.compile(g);
                    var a = Assembler(ops1.len + ops2.len + 2, enum { alt2, done }){};

                    return a
                        .ctrl(.cope, .alt2)
                        .emit(ops1)
                        .ctrl(.commit, .done)
                        .mark(.alt2)
                        .emit(ops2)
                        .mark(.done)
                        .build();
                }
            };
        }

        pub fn lookahead(comptime inner: type) type {
            return struct {
                pub fn compile(g: type) []const Op {
                    const part = inner.compile(g);
                    var a = Assembler(part.len + 3, enum { fail, success }){};
                    return a
                        .ctrl(.cope, .fail)
                        .emit(part)
                        .ctrl(.rewind, .success)
                        .mark(.fail)
                        .reject()
                        .mark(.success)
                        .build();
                }
            };
        }

        pub fn neglookahead(comptime inner: type) type {
            return struct {
                pub fn compile(g: type) []const Op {
                    const part = inner.compile(g);
                    var a = Assembler(part.len + 3, enum { fail, success }){};
                    return a
                        .ctrl(.cope, .success)
                        .emit(part)
                        .ctrl(.rewind, .fail)
                        .mark(.fail)
                        .reject()
                        .mark(.success)
                        .build();
                }
            };
        }
    };
}
