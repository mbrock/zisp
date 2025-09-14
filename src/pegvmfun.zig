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
    nul = 0x00,
    soh = 0x01,
    stx = 0x02,
    etx = 0x03,
    eot = 0x04,
    enq = 0x05,
    ack = 0x06,
    bel = 0x07,
    bs = 0x08,
    ht = 0x09,
    nl = 0x0a,
    vt = 0x0b,
    np = 0x0c,
    cr = 0x0d,
    so = 0x0e,
    si = 0x0f,
    dle = 0x10,
    dc1 = 0x11,
    dc2 = 0x12,
    dc3 = 0x13,
    dc4 = 0x14,
    nak = 0x15,
    syn = 0x16,
    etb = 0x17,
    can = 0x18,
    em = 0x19,
    sub = 0x1a,
    esc = 0x1b,
    fs = 0x1c,
    gs = 0x1d,
    rs = 0x1e,
    us = 0x1f,
    sp = 0x20,
    _,
};

fn printChar(writer: anytype, c: u8) !void {
    if (std.enums.tagName(AsciiCtrl, @enumFromInt(c))) |ctrl|
        try writer.print("{s}", .{ctrl})
    else if (c >= 33 and c < 127 and c != '\\')
        try writer.print("{c}", .{c})
    else
        try writer.print("\\x{x:0>2}", .{c});
}

pub fn dumpInstruction(writer: anytype, ip: u32, op: anytype) !void {
    // Print instruction address
    try writer.print("  0x{x:0>4}    ", .{ip});

    switch (op) {
        .op_ctrl => |ctrl| {
            const mode_str = switch (ctrl.mode) {
                .rescue => "RESCUE",
                .commit => "COMMIT",
                .update => "UPDATE",
                .rewind => "REWIND",
            };
            try writer.print("{s}  0x{x:0>4}\n", .{ mode_str, ctrl.offset });
        },
        .op_invoke => |target| {
            if (@TypeOf(target) == u32) {
                try writer.print("INVOKE  0x{x:0>4}\n", .{target});
            } else {
                try writer.print("INVOKE  {s}\n", .{@tagName(target)});
            }
        },
        .op_return => {
            try writer.print("RETURN\n", .{});
        },
        .op_reject => {
            try writer.print("REJECT\n", .{});
        },
        .op_accept => {
            try writer.print("ACCEPT\n", .{});
        },
        .op_charset => |cs| {
            try writer.print("CHARSET ", .{});
            var first = true;
            var i: u32 = 0;
            while (i < 256) : (i += 1) {
                if (cs.isSet(i)) {
                    if (!first) try writer.writeAll(" ");
                    first = false;

                    // Check for ranges - look ahead for consecutive characters
                    var range_end = i;
                    while (range_end + 1 < 256 and cs.isSet(range_end + 1)) : (range_end += 1) {}

                    if (range_end > i + 1) {
                        // We have a range of at least 3 characters
                        // Print start of range
                        try printChar(writer, @intCast(i));
                        try writer.writeAll("-");
                        // Print end of range
                        try printChar(writer, @intCast(range_end));
                        i = range_end;
                    } else if (range_end == i + 1) {
                        // Just two consecutive characters - print them separately
                        try printChar(writer, @intCast(i));
                        try writer.writeAll(" ");
                        try printChar(writer, @intCast(range_end));
                        i = range_end;
                    } else {
                        // Single character
                        try printChar(writer, @intCast(i));
                    }
                }
            }
            try writer.print("\n", .{});
        },
        .op_range => |r| {
            try writer.print("RANGE   ", .{});
            try printChar(writer, r.min);
            try writer.writeAll("-");
            try printChar(writer, r.max);
            try writer.print("\n", .{});
        },
    }
}

pub fn main() !void {
    const stdout_file = std.fs.File.stdout();
    var buffer: [4096]u8 = undefined;
    var stdout_writer = stdout_file.writer(&buffer);
    const stdout = &stdout_writer.interface;

    const relops = comptime Grammar(demoGrammar).compile();

    // Print header
    try stdout.print("=== PEG VM Instructions ===\n", .{});
    try stdout.print("Total: {} instructions\n\n", .{relops.len});

    // Dump each instruction with proper formatting
    inline for (relops, 0..) |op, i| {
        try dumpInstruction(stdout, @intCast(i), op);
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
            var size: comptime_int = 0;

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
        fn emitLinkedOpcodes(comptime offset_map: RuleOffsetMap, comptime total_size: comptime_int) [total_size]AbsoluteOp {
            var linked_ops: [total_size]AbsoluteOp = undefined;
            var write_position: usize = 0;

            inline for (comptime std.meta.declarations(rules)) |decl| {
                const rule_fn = @field(rules, decl.name);
                if (!isRuleFunction(@TypeOf(rule_fn))) {
                    @compileError("Grammar member '" ++ decl.name ++ "' must be a function");
                }

                const fn_info = getRuleFunctionInfo(rule_fn);
                inline for (fn_info.params) |param| {
                    if (param.type) |param_type| {
                        const relative_ops = compilePattern(param_type);

                        // Link each opcode (resolve symbolic references and relative jumps)
                        for (relative_ops) |op| {
                            linked_ops[write_position] = linkOpcode(op, offset_map, @intCast(write_position));
                            write_position += 1;
                        }
                    }
                }
            }

            return linked_ops;
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
        fn linkOpcode(op: Op, offset_map: RuleOffsetMap, current_ip: u32) AbsoluteOp {
            return switch (op) {
                .op_invoke => |rule_tag| blk: {
                    const absolute_offset = offset_map.getAssertContains(rule_tag);
                    break :blk .{ .op_invoke = @intCast(absolute_offset) };
                },
                .op_ctrl => |c| .{
                    .op_ctrl = .{
                        .mode = c.mode,
                        .offset = bump(current_ip + 1, c.offset),
                    },
                },
                // Non-address opcodes pass through unchanged
                inline else => |payload, tag| @unionInit(AbsoluteOp, @tagName(tag), payload),
            };
        }

        // Main compilation entry point
        pub fn compile() []const AbsoluteOp {
            // Two-pass compilation:
            // 1. Build symbol table (calculate offsets)
            const link_info = comptime buildRuleOffsetMap();

            // 2. Emit and link opcodes
            const linked_program = comptime emitLinkedOpcodes(link_info.map, link_info.total_size);

            return &linked_program;
        }

        // Normalize a pattern type (e.g., []T becomes kleene(T))
        fn normalizePatternType(comptime t: type) type {
            switch (@typeInfo(t)) {
                .pointer => |ptr_info| {
                    if (ptr_info.size == .slice) {
                        // Transform []T into kleene(T)
                        return Ops.kleene(normalizePatternType(ptr_info.child));
                    } else {
                        @compileError("Only slices are supported as pointer types in grammar patterns");
                    }
                },
                .optional => |opt_info| {
                    // Transform ?T into optional(T)
                    return Ops.optional(normalizePatternType(opt_info.child));
                },
                .@"union" => |union_info| {
                    if (union_info.tag_type != null) {
                        // Transform enum union into choice of its variants
                        var variants: [union_info.fields.len]type = undefined;
                        var idx: usize = 0;
                        inline for (union_info.fields) |field| {
                            variants[idx] = normalizePatternType(field.type);
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
            const normalized = normalizePatternType(t);
            // After normalization, everything is a struct with compile method
            return normalized.compile(rules);
        }
    };
}

pub const CtrlMode = enum(u8) {
    rescue, // Push backtrack frame, jump on fail
    commit, // Pop frame and jump forward
    update, // Update frame position and jump (for loops)
    rewind, // Pop frame, reset text position, and jump
};

pub fn OpG(comptime RuleTag: type, comptime rel: bool) type {
    return union(enum) {
        op_charset: std.StaticBitSet(256),
        op_range: struct { min: u8, max: u8 },
        op_invoke: if (rel) RuleTag else u32,
        op_ctrl: struct {
            mode: CtrlMode,
            offset: if (rel) i32 else u32 = undefined,
        },
        op_reject: void, // Fail current alternative
        op_return: void,
        op_accept: void,
    };
}

pub fn OpFor(comptime Rules: type) type {
    return struct {
        pub const RuleTag = std.meta.DeclEnum(Rules);
        pub const Rel = OpG(RuleTag, true);
        pub const Abs = OpG(RuleTag, false);

        const Op = Rel;

        pub fn charset(s: []const u8) type {
            return struct {
                pub fn compile(_: type) []const Op {
                    var bs = std.bit_set.ArrayBitSet(usize, 256).initEmpty();
                    for (s) |c| {
                        bs.set(c);
                    }
                    return &[_]Op{.{ .op_charset = bs }};
                }
            };
        }

        pub fn range(a: u8, b: u8) type {
            return struct {
                pub fn compile(_: type) []const Op {
                    return &[_]Op{.{ .op_range = .{ .min = a, .max = b } }};
                }
            };
        }

        pub fn call(r: RuleTag) type {
            return struct {
                pub fn compile(_: type) []const Op {
                    return &[_]Op{.{ .op_invoke = r }};
                }
            };
        }

        // Parameterized comptime assembler
        pub fn AsmComptime(comptime max_ops: usize, comptime labels: type) type {
            const max_labels = @typeInfo(labels).@"enum".fields.len;
            return struct {
                const Self = @This();

                ops: [max_ops]Op = undefined,
                op_count: usize = 0,
                labels: std.EnumMap(labels, i32) = std.EnumMap(labels, i32).init(.{}),
                forwards: [max_labels * 2]struct { op_index: usize, label_id: labels } = undefined,
                forward_count: usize = 0,

                pub fn mark(self: *Self, lbl: labels) *Self {
                    self.labels.put(lbl, @intCast(self.op_count));
                    return self;
                }

                fn addCtrl(self: *Self, mode: CtrlMode, lbl: labels) *Self {
                    self.forwards[self.forward_count] = .{
                        .op_index = self.op_count,
                        .label_id = lbl,
                    };
                    self.forward_count += 1;
                    self.ops[self.op_count] = .{ .op_ctrl = .{ .mode = mode } };
                    self.op_count += 1;
                    return self;
                }

                pub fn rescue(self: *Self, lbl: labels) *Self {
                    return self.addCtrl(.rescue, lbl);
                }

                pub fn commit(self: *Self, lbl: labels) *Self {
                    return self.addCtrl(.commit, lbl);
                }

                pub fn update(self: *Self, lbl: labels) *Self {
                    return self.addCtrl(.update, lbl);
                }

                pub fn rewind(self: *Self, lbl: labels) *Self {
                    return self.addCtrl(.rewind, lbl);
                }

                pub fn emit(self: *Self, new_ops: []const Op) *Self {
                    for (new_ops) |op| {
                        self.ops[self.op_count] = op;
                        self.op_count += 1;
                    }
                    return self;
                }

                pub fn reject(self: *Self) *Self {
                    self.ops[self.op_count] = .{ .op_reject = {} };
                    self.op_count += 1;
                    return self;
                }

                pub fn build(self: *Self) []const Op {
                    // Resolve forward references
                    for (0..self.forward_count) |i| {
                        const fwd = self.forwards[i];
                        const target = self.labels.getAssertContains(fwd.label_id);
                        const from = @as(i32, @intCast(fwd.op_index));
                        self.ops[fwd.op_index].op_ctrl.offset = target - from - 1;
                    }

                    // Return slice of actual ops
                    const result = self.ops[0..self.op_count];
                    return result;
                }
            };
        }

        // Kleene star using fluent assembly
        pub fn kleene(comptime inner: type) type {
            return struct {
                pub fn compile(g: type) []const Op {
                    const inner_ops = inner.compile(g);

                    // kleene needs: inner.len + 2 ops (rescue, update), 2 labels
                    var a = AsmComptime(inner_ops.len + 2, enum { loop, done }){};

                    return a
                        .mark(.loop)
                        .rescue(.done)
                        .emit(inner_ops)
                        .update(.loop)
                        .mark(.done)
                        .build();
                }
            };
        }

        // Optional using fluent assembly
        pub fn optional(comptime inner: type) type {
            return struct {
                pub fn compile(g: type) []const Op {
                    const inner_ops = inner.compile(g);

                    var a = AsmComptime(inner_ops.len + 2, enum { done }){};

                    return a
                        .rescue(.done)
                        .emit(inner_ops)
                        .commit(.done)
                        .mark(.done)
                        .build();
                }
            };
        }

        // Choice using fluent assembly
        pub fn choice(comptime alt1: type, comptime alt2: type) type {
            return struct {
                pub fn compile(g: type) []const Op {
                    const ops1 = alt1.compile(g);
                    const ops2 = alt2.compile(g);
                    var a = AsmComptime(ops1.len + ops2.len + 2, enum { alt2, done }){};

                    return a
                        .rescue(.alt2)
                        .emit(ops1)
                        .commit(.done)
                        .mark(.alt2)
                        .emit(ops2)
                        .mark(.done)
                        .build();
                }
            };
        }

        // Positive lookahead using fluent assembly
        pub fn lookahead(comptime inner: type) type {
            return struct {
                pub fn compile(g: type) []const Op {
                    const inner_ops = inner.compile(g);
                    var a = AsmComptime(inner_ops.len + 3, enum { fail, success }){};

                    return a
                        .rescue(.fail)
                        .emit(inner_ops)
                        .rewind(.success)
                        .mark(.fail)
                        .reject()
                        .mark(.success)
                        .build();
                }
            };
        }

        // Negative lookahead using fluent assembly
        pub fn neglookahead(comptime inner: type) type {
            return struct {
                pub fn compile(g: type) []const Op {
                    const inner_ops = inner.compile(g);
                    var a = AsmComptime(inner_ops.len + 3, enum { fail, success }){};

                    return a
                        .rescue(.success)
                        .emit(inner_ops)
                        .rewind(.fail)
                        .mark(.fail)
                        .reject()
                        .mark(.success)
                        .build();
                }
            };
        }
    };
}
