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

pub const demoGrammar = Grammar(struct {
    // Rules define their grammatical structure entirely via parameter types.
    // The grammar compiler compiles the parameter types to opcode sequences.
    //
    // At runtime, the rule functions are actually called with arguments
    // being values of the input text that matched the parameter types.
    //
    // The return type of a rule function is the type of value that the rule
    // produces when it successfully matches input text.

    pub fn integer(
        d0: range('1', '9'),
        ds: []range('0', '9'),
        _: call(skip),
    ) !i32 {
        const small = try std.fmt.parseInt(i32, ds.slice, 10);
        const order = ds.len;
        return @as(i32, d0) * std.math.pow(10, order) + small;
    }

    pub fn skip(_: []charset(" \t\n\r")) void {}
});

pub fn main() !void {
    const stdout = std.fs.File.stdout();
    var outbuf: [1024]u8 = undefined;
    var outfs = stdout.writer(&outbuf);
    var out = &outfs.interface;

    const relops = comptime demoGrammar.compile();

    inline for (relops) |op| {
        try out.print("{any}\n", .{op});
    }
    try out.flush();
}

pub inline fn Grammar(rules: type) type {
    return struct {
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
                .op_invoke => |rule_name| blk: {
                    const rule_tag = @field(RuleEnum, rule_name);
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
                        return kleene(normalizePatternType(ptr_info.child));
                    } else {
                        @compileError("Only slices are supported as pointer types in grammar patterns");
                    }
                },
                .optional => |opt_info| {
                    // Transform ?T into optional(T)
                    return optional(normalizePatternType(opt_info.child));
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

pub fn OpG(comptime rel: bool) type {
    return union(enum) {
        op_charset: std.StaticBitSet(256),
        op_range: struct { min: u8, max: u8 },
        op_invoke: if (rel) []const u8 else u32,
        op_ctrl: struct {
            mode: CtrlMode,
            offset: if (rel) i32 else u32 = undefined,
        },
        op_reject: void, // Fail current alternative
        op_return: void,
        op_accept: void,
    };
}

pub const Op = OpG(true);
pub const AbsoluteOp = OpG(false);

// Pattern combinators - all return types with a compile method

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

pub fn call(r: anytype) type {
    return struct {
        pub fn compile(g: type) []const Op {
            inline for (comptime std.meta.declarations(g)) |decl| {
                // Look up a rule's name by identity comparison on its function body.
                // Note: function bodies, not function pointers.
                // Hence known at compile time.
                if (@TypeOf(@field(g, decl.name)) == @TypeOf(r)) {
                    if (@field(g, decl.name) == r) {
                        return &[_]Op{.{ .op_invoke = decl.name }};
                    }
                }
            }

            @compileError("call to unknown rule " ++ @typeName(@TypeOf(r)));
        }
    };
}

// Label-based assembly with anonymous structs for basic blocks
pub fn assemble(comptime blocks_spec: anytype) []const Op {
    const T = @TypeOf(blocks_spec);
    const fields = @typeInfo(T).@"struct".fields;

    // Count total ops and find label positions
    comptime var total_ops: usize = 0;
    comptime var label_pos: [fields.len]usize = undefined;

    inline for (fields, 0..) |field, i| {
        label_pos[i] = total_ops;
        const block = @field(blocks_spec, field.name);
        total_ops += countOps(block);
    }

    // Emit ops with resolved jumps
    comptime var result: [total_ops]Op = undefined;
    comptime var pos: usize = 0;

    inline for (fields) |field| {
        const block = @field(blocks_spec, field.name);
        emitBlock(&result, &pos, block, fields, blocks_spec, label_pos);
    }

    return &result;
}

// Count ops in a block (excluding labels)
fn countOps(block: anytype) usize {
    const T = @TypeOf(block);
    if (T == []const Op) {
        return block.len;
    }

    var count: usize = 0;
    inline for (block) |item| {
        const ItemT = @TypeOf(item);
        if (@typeInfo(ItemT) == .pointer) {
            // Label reference - generates a control op
            count += 1;
        } else if (ItemT == []const Op) {
            count += item.len;
        } else {
            // Simple ops like reject
            count += 1;
        }
    }
    return count;
}

// Emit a block's ops with resolved label references
fn emitBlock(
    result: []Op,
    pos: *usize,
    block: anytype,
    comptime fields: anytype,
    comptime blocks_spec: anytype,
    comptime label_pos: anytype,
) void {
    const T = @TypeOf(block);

    // Simple case: block is just ops
    if (T == []const Op) {
        for (block) |op| {
            result[pos.*] = op;
            pos.* += 1;
        }
        return;
    }

    // Complex case: block with control flow
    inline for (block) |item| {
        const ItemT = @TypeOf(item);

        if (@typeInfo(ItemT) == .pointer) {
            // This is a label reference - find which field it points to
            const label_idx = findLabelIndex(item, fields, blocks_spec);
            const target_pos = label_pos[label_idx];

            // Determine control mode from context (field name prefix)
            const mode = inferControlMode(item, block);

            result[pos.*] = .{ .op_ctrl = .{
                .mode = mode,
                .offset = @intCast(@as(i64, target_pos) - @as(i64, pos.*) - 1),
            } };
            pos.* += 1;
        } else if (ItemT == []const Op) {
            // Inline ops
            for (item) |op| {
                result[pos.*] = op;
                pos.* += 1;
            }
        } else if (@hasField(ItemT, "op_reject")) {
            // Simple ops
            result[pos.*] = item;
            pos.* += 1;
        }
    }
}

// Find which label a pointer refers to
fn findLabelIndex(
    ptr: anytype,
    comptime fields: anytype,
    comptime blocks_spec: anytype,
) usize {
    inline for (fields, 0..) |field, i| {
        if (@as(*const anyopaque, ptr) == @as(*const anyopaque, &@field(blocks_spec, field.name))) {
            return i;
        }
    }
    @compileError("Label not found");
}

// Infer control mode from context
fn inferControlMode(ptr: anytype, block: anytype) CtrlMode {
    // Look at the position in the block to infer the control type
    // This is a simplified heuristic - could be made smarter
    for (block, 0..) |item, i| {
        if (@as(*const anyopaque, @ptrCast(&item)) == @as(*const anyopaque, ptr)) {
            // First control in block is usually rescue
            if (i == 0) return .rescue;
            // Last control is usually update or commit
            if (i == block.len - 1) {
                // If it points backwards, it's likely update (loop)
                // This would need actual analysis to be perfect
                return .update;
            }
            return .commit;
        }
    }
    return .rescue;
}

// Control flow helpers
pub fn rescue(comptime label: anytype) *const @TypeOf(label.*) {
    return label;
}

pub fn commit(comptime label: anytype) *const @TypeOf(label.*) {
    return label;
}

pub fn update(comptime label: anytype) *const @TypeOf(label.*) {
    return label;
}

pub fn rewind(comptime label: anytype) *const @TypeOf(label.*) {
    return label;
}

// Control instruction with explicit mode
pub const Ctrl = struct {
    mode: CtrlMode,
    target: *const anyopaque,

    pub fn rescue(target: anytype) Ctrl {
        return .{ .mode = .rescue, .target = @ptrCast(target) };
    }

    pub fn commit(target: anytype) Ctrl {
        return .{ .mode = .commit, .target = @ptrCast(target) };
    }

    pub fn update(target: anytype) Ctrl {
        return .{ .mode = .update, .target = @ptrCast(target) };
    }

    pub fn rewind(target: anytype) Ctrl {
        return .{ .mode = .rewind, .target = @ptrCast(target) };
    }
};

// Simpler assemble that works with basic blocks as struct fields
pub fn link(comptime blocks: anytype) []const Op {
    const T = @TypeOf(blocks);
    const fields = @typeInfo(T).@"struct".fields;

    // Pass 1: Count ops and find label positions
    comptime var total_ops: usize = 0;
    comptime var label_pos: [fields.len]usize = undefined;

    inline for (fields, 0..) |field, i| {
        label_pos[i] = total_ops;
        const block = @field(blocks, field.name);

        // Count ops in this block
        inline for (block) |item| {
            switch (@TypeOf(item)) {
                Ctrl => total_ops += 1,
                Op => total_ops += 1,
                []const Op => total_ops += item.len,
                else => {
                    if (@hasField(@TypeOf(item), "op_reject")) {
                        total_ops += 1;
                    }
                },
            }
        }
    }

    // Pass 2: Emit ops with resolved jumps
    comptime var result: [total_ops]Op = undefined;
    comptime var pos: usize = 0;

    inline for (fields) |field| {
        const block = @field(blocks, field.name);

        inline for (block) |item| {
            switch (@TypeOf(item)) {
                Ctrl => {
                    // Find target label
                    var target_pos: usize = 0;
                    inline for (fields, 0..) |f2, j| {
                        if (@as(*const anyopaque, @ptrCast(&@field(blocks, f2.name))) == item.target) {
                            target_pos = label_pos[j];
                            break;
                        }
                    }

                    result[pos] = .{ .op_ctrl = .{
                        .mode = item.mode,
                        .offset = @intCast(@as(i64, target_pos) - @as(i64, pos) - 1),
                    } };
                    pos += 1;
                },
                Op => {
                    result[pos] = item;
                    pos += 1;
                },
                []const Op => {
                    for (item) |op| {
                        result[pos] = op;
                        pos += 1;
                    }
                },
                else => {
                    if (@hasField(@TypeOf(item), "op_reject")) {
                        result[pos] = item;
                        pos += 1;
                    }
                },
            }
        }
    }

    return &result;
}

// Fluent builder for PEG VM assembly
pub const Asm = struct {
    ops: std.ArrayList(Op),
    labels: std.ArrayList(i32),
    forwards: std.ArrayList(struct { op_index: usize, label_id: usize }),

    pub fn init(allocator: std.mem.Allocator) Asm {
        return .{
            .ops = std.ArrayList(Op).init(allocator),
            .labels = std.ArrayList(i32).init(allocator),
            .forwards = std.ArrayList(@TypeOf(.{ .op_index = 0, .label_id = 0 })).init(allocator),
        };
    }

    // Create a new label (returns label ID)
    pub fn label(self: *Asm) usize {
        self.labels.append(-1) catch unreachable;
        return self.labels.items.len - 1;
    }

    // Mark a label at current position
    pub fn mark(self: *Asm, lbl: usize) *Asm {
        self.labels.items[lbl] = @intCast(self.ops.items.len);
        return self;
    }

    // Control flow with forward reference to label
    pub fn rescue(self: *Asm, lbl: usize) *Asm {
        const op = Op{ .op_ctrl = .{ .mode = .rescue } };
        self.forwards.append(.{ .op_index = self.ops.items.len, .label_id = lbl }) catch unreachable;
        self.ops.append(op) catch unreachable;
        return self;
    }

    pub fn commit(self: *Asm, lbl: usize) *Asm {
        const op = Op{ .op_ctrl = .{ .mode = .commit } };
        self.forwards.append(.{ .op_index = self.ops.items.len, .label_id = lbl }) catch unreachable;
        self.ops.append(op) catch unreachable;
        return self;
    }

    pub fn update(self: *Asm, lbl: usize) *Asm {
        const op = Op{ .op_ctrl = .{ .mode = .update } };
        self.forwards.append(.{ .op_index = self.ops.items.len, .label_id = lbl }) catch unreachable;
        self.ops.append(op) catch unreachable;
        return self;
    }

    pub fn rewind(self: *Asm, lbl: usize) *Asm {
        const op = Op{ .op_ctrl = .{ .mode = .rewind } };
        self.forwards.append(.{ .op_index = self.ops.items.len, .label_id = lbl }) catch unreachable;
        self.ops.append(op) catch unreachable;
        return self;
    }

    // Emit regular ops
    pub fn emit(self: *Asm, new_ops: []const Op) *Asm {
        self.ops.appendSlice(new_ops) catch unreachable;
        return self;
    }

    pub fn reject(self: *Asm) *Asm {
        self.ops.append(.{ .op_reject = {} }) catch unreachable;
        return self;
    }

    // Finalize: resolve all forward references
    pub fn build(self: *Asm) []const Op {
        // Patch all forward references
        for (self.forwards.items) |fwd| {
            const target = self.labels.items[fwd.label_id];
            const from = @as(i32, @intCast(fwd.op_index));
            self.ops.items[fwd.op_index].op_ctrl.offset = target - from - 1;
        }
        return self.ops.items;
    }
};

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
