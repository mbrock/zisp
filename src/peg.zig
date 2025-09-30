// PEG (Parsing Expression Grammar) with typed AST building
//
// Organization:
// 1. Demo Grammar - Example grammar for testing
// 2. Public API - Main entry points (compile, etc.)
// 3. AST Building Infrastructure - NodeType, NodeState, BuildContext, helpers
// 4. Forest - Typed storage for parsed AST
// 5. Grammar - Compilation and orchestration
// 6. Opcodes & VM Instructions - Low-level VM operations
// 7. Pattern Combinators - CharSet, Match, Call, Union, etc. (Public API)

const std = @import("std");
const ast = @import("ast.zig");

// ============================================================================
// DEMO GRAMMAR
// ============================================================================

pub const demoGrammar = struct {
    const R = std.meta.DeclEnum(@This());

    pub const Value = Match(union(enum) {
        integer: Call(R.Integer),
        array: Call(R.Array),
    });

    pub const Integer = Match(struct {
        d: CharRange('1', '9', .one),
        ds: CharRange('0', '9', .kleene),
        _skip: Hide(Call(R.Skip)),
    });

    pub const Array = Match(struct {
        open: Hide(CharSet("[", .one)),
        skip1: Hide(Call(R.Skip)),
        values: Kleene(R.Value),
        close: Hide(CharSet("]", .one)),
        skip2: Hide(Call(R.Skip)),
    });

    pub const Skip = CharSet(" \t\n\r", .kleene);
};

// ============================================================================
// PUBLIC API
// ============================================================================

pub inline fn compile(comptime rules: type) []const Abs {
    return Grammar(rules).compile(false);
}

// ============================================================================
// AST BUILDING - Re-exports from forest module
// ============================================================================

pub const NodeType = ast.NodeType;
pub const NodeState = ast.NodeState;
pub const BuildContext = ast.BuildContext;
pub const BuildError = ast.BuildError;
pub const NodeSlice = ast.NodeSlice;
pub const Forest = ast.Forest;

// ============================================================================
// GRAMMAR - Compilation & Orchestration
// ============================================================================

pub inline fn Grammar(rules: type) type {
    const ForestType = ast.Forest(rules);

    return struct {
        pub const RuleEnum = std.meta.DeclEnum(rules);
        const RuleOffsetMap = std.enums.EnumMap(RuleEnum, comptime_int);

        pub const Forest = ForestType;

        pub const TextRange = struct {
            start: usize,
            len: usize,
        };

        fn ruleFromName(comptime name: []const u8) RuleEnum {
            if (@hasField(RuleEnum, name)) {
                return @field(RuleEnum, name);
            }
            @compileError("Unknown grammar rule '" ++ name ++ "'");
        }

        pub fn RuleValueType(comptime rule: RuleEnum) type {
            return ForestType.RuleValueType(rule);
        }

        pub fn BuildResult(comptime _: RuleEnum) type {
            return struct {
                forest: ForestType,
                root_index: u32,
            };
        }

        fn expectCall(
            comptime rule: RuleEnum,
            ctx: *const BuildContext,
            state: *ast.NodeState,
        ) BuildError!u32 {
            return state.expectCall(ctx, @intFromEnum(rule));
        }

        fn gatherNodeSlice(
            comptime rule: RuleEnum,
            ctx: *const BuildContext,
            state: *ast.NodeState,
        ) BuildError!ast.NodeSlice {
            return state.gatherNodeSlice(ctx, @intFromEnum(rule));
        }

        fn buildNodeValue(
            comptime rule: RuleEnum,
            ctx: *const BuildContext,
            node_index: usize,
        ) BuildError!RuleValueType(rule) {
            const node = ctx.nodes[node_index];
            var state = ast.NodeState.init(node);

            const rule_pattern = @field(rules, @tagName(rule));

            const value = try rule_pattern.eval(@This(), ctx, &state);
            if (state.next_child != null or state.pos != state.end) {
                return error.InvalidAst;
            }
            return value;
        }

        // Step 1: Group nodes by rule and sort within each group
        const NodeBuckets = blk: {
            const rule_count = std.meta.tags(RuleEnum).len;
            break :blk [rule_count]std.ArrayListUnmanaged(usize);
        };

        fn groupAndSortNodesByRule(
            allocator: std.mem.Allocator,
            nodes: []const NodeType,
        ) !NodeBuckets {
            const rule_tags = comptime std.meta.tags(RuleEnum);
            const rule_count = rule_tags.len;

            var buckets: NodeBuckets = undefined;
            inline for (0..rule_count) |i| buckets[i] = .{};

            for (nodes, 0..) |node, idx| {
                const ri: usize = @intCast(node.rule_index);
                try buckets[ri].append(allocator, idx);
            }

            inline for (rule_tags, 0..) |_, ri| {
                ast.sortRuleGroup(nodes, buckets[ri].items);
            }

            return buckets;
        }

        // Step 2: Assign position within each rule's array
        fn assignNodePositions(
            allocator: std.mem.Allocator,
            node_count: usize,
            buckets: *const NodeBuckets,
        ) ![]usize {
            const rule_tags = comptime std.meta.tags(RuleEnum);

            var positions = try allocator.alloc(usize, node_count);

            inline for (rule_tags, 0..) |_, ri| {
                const slice = buckets[ri].items;
                for (slice, 0..) |node_idx, pos| positions[node_idx] = pos;
            }

            return positions;
        }

        // Step 3: Build typed forest from nodes
        fn populateForest(
            allocator: std.mem.Allocator,
            text: []const u8,
            nodes: []const NodeType,
            positions: []const usize,
            buckets: *const NodeBuckets,
        ) !ForestType {
            const rule_tags = comptime std.meta.tags(RuleEnum);

            var forest = ForestType.init();
            const ctx = BuildContext{ .text = text, .nodes = nodes, .positions = positions };

            inline for (rule_tags, 0..) |rule_tag, ri| {
                const ValueType = RuleValueType(rule_tag);
                if (@sizeOf(ValueType) == 0) continue;
                var list = &@field(forest.lists, @tagName(rule_tag));
                const slice = buckets[ri].items;
                for (slice) |node_idx| {
                    const value = try buildNodeValue(rule_tag, &ctx, node_idx);
                    try list.append(allocator, value);
                }
            }

            return forest;
        }

        pub fn buildForestForRoot(
            allocator: std.mem.Allocator,
            text: []const u8,
            nodes: []const NodeType,
            root_index: u32,
            comptime root_rule: RuleEnum,
        ) BuildError!BuildResult(root_rule) {
            const node_count = nodes.len;
            if (node_count == 0) {
                return error.InvalidAst;
            }

            // Group and sort nodes by rule
            var buckets = try groupAndSortNodesByRule(allocator, nodes);
            defer {
                const rule_count = std.meta.tags(RuleEnum).len;
                inline for (0..rule_count) |i| buckets[i].deinit(allocator);
            }

            // Assign positions within each rule's array
            const positions = try assignNodePositions(allocator, node_count, &buckets);
            defer allocator.free(positions);

            // Build the typed forest
            const result_forest = try populateForest(allocator, text, nodes, positions, &buckets);

            // Validate root and return
            const ensured_root: usize = @intCast(root_index);
            if (ensured_root >= node_count) {
                return error.InvalidAst;
            }
            const root_node = nodes[ensured_root];
            const actual_rule: RuleEnum = @enumFromInt(root_node.rule_index);
            if (actual_rule != root_rule) {
                return error.InvalidAst;
            }

            const root_idx: u32 = @intCast(positions[ensured_root]);
            return BuildResult(root_rule){ .forest = result_forest, .root_index = root_idx };
        }

        // Helper: Check if a declaration is a valid rule pattern (any type that can be normalized)
        fn isRulePattern(comptime decl_type: type) bool {
            return switch (@typeInfo(decl_type)) {
                .@"struct", .@"union", .pointer, .optional => true,
                else => @hasDecl(decl_type, "compile"),
            };
        }

        // Helper: Calculate total size needed for a rule's opcodes
        fn calculateRuleSize(comptime pattern: type) comptime_int {
            const opcodes = compilePattern(pattern);
            return opcodes.len + 1; // +1 for return
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
        ) [total_size]OpG(rel) {
            var code: [total_size]OpG(rel) = undefined;
            var i: usize = 0;

            inline for (comptime std.meta.declarations(rules)) |decl| {
                const pattern = @field(rules, decl.name);
                const relative_ops = compilePattern(pattern);
                for (relative_ops) |op| {
                    code[i] = if (rel) op else linkOpcode(op, offset_map, @intCast(i));
                    i += 1;
                }
                code[i] = .{ .done = {} };
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
        fn linkOpcode(op: Op, map: RuleOffsetMap, ip: u32) Abs {
            return switch (op) {
                .call => |rule_tag| blk: {
                    const absolute_offset = map.getAssertContains(@field(RuleEnum, rule_tag));
                    break :blk .{ .call = @intCast(absolute_offset) };
                },
                .frob => |c| .{
                    .frob = .{
                        .fx = c.fx,
                        .ip = bump(ip + 1, c.ip),
                    },
                },
                // Non-address opcodes pass through unchanged
                inline else => |payload, tag| @unionInit(Abs, @tagName(tag), payload),
            };
        }

        pub fn compile(comptime rel: bool) []const OpG(rel) {
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

        pub fn ruleContainingIp(ip: u32) ?RuleEnum {
            const info = comptime buildRuleOffsetMap();
            if (ip >= info.total_size) {
                return null;
            }

            var last_rule: ?RuleEnum = null;

            inline for (comptime std.meta.tags(RuleEnum)) |rule_tag| {
                const rule_ip: u32 = info.map.getAssertContains(rule_tag);
                if (ip >= rule_ip) {
                    last_rule = rule_tag;
                }
            }

            return last_rule;
        }

        // Compile a single pattern type to opcodes
        pub fn compilePattern(comptime t: type) []const Op {
            return t.compile(rules);
        }
    };
}

// ============================================================================
// OPCODES & VM INSTRUCTIONS
// ============================================================================

pub const FrameEffect = enum(u8) {
    /// Push backtrack frame, jump on fail
    push,
    /// Pop frame and jump forward
    drop,
    /// Update frame position and jump (for loops)
    move,
    /// Pop frame, reset text position, and jump
    wipe,
};

pub fn OpG(comptime rel: bool) type {
    return union(enum) {
        /// Consume any byte that matches the bitset (with optional repetition)
        read: struct {
            set: std.StaticBitSet(256),
            repeat: Repeat,
        },
        /// Call a rule (by tag or absolute address)
        call: if (rel) []const u8 else u32,
        /// Frame-manipulating instruction
        frob: struct {
            fx: FrameEffect,
            ip: if (rel) i32 else u32 = undefined,
        },
        /// Fail and backtrack
        fail: void,
        /// Return from rule invocation
        done: void,
        /// Successful parse completion
        over: void,
    };
}

pub const Rel = OpG(true);
pub const Abs = OpG(false);
pub const Opcodes = []const Abs;

const Op = Rel;

// ============================================================================
// PATTERN COMBINATORS - Public API for defining grammars
// ============================================================================

pub const Repeat = enum { one, kleene };

pub fn Match(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .@"struct" => Struct(T),
        .@"union" => Union(T),
        else => @compileError("expected struct or union"),
    };
}

pub fn CharSet(comptime s: []const u8, comptime repeat: Repeat) type {
    return struct {
        pub const Kind = if (repeat == .kleene) .char_slice else .char;
        offset: u32,
        len: if (repeat == .kleene) u32 else void,

        pub fn compile(_: type) []const Op {
            var bs = std.bit_set.ArrayBitSet(usize, 256).initEmpty();
            for (s) |c| {
                bs.set(c);
            }
            return &[_]Op{.{ .read = .{ .set = bs, .repeat = repeat } }};
        }

        pub fn eval(
            comptime G: type,
            ctx: *const BuildContext,
            state: *NodeState,
        ) BuildError!@This() {
            _ = G;
            const start_pos = state.pos;

            // Scan the text to find how many characters match this set
            var end_pos = start_pos;
            while (end_pos < state.end and end_pos < ctx.text.len) {
                const ch = ctx.text[end_pos];
                var matches = false;
                inline for (s) |c| {
                    if (ch == c) {
                        matches = true;
                        break;
                    }
                }
                if (matches) {
                    end_pos += 1;
                    if (repeat == .one) break; // Stop after one character for .one
                } else {
                    break; // Stop when we hit a non-matching character
                }
            }

            // For .one, we must have matched at least one character
            if (repeat == .one and end_pos == start_pos) {
                return error.InvalidAst;
            }

            state.pos = end_pos;

            const offset: u32 = @intCast(start_pos);
            if (repeat == .kleene) {
                const len: u32 = @intCast(end_pos - start_pos);
                return .{ .offset = offset, .len = len };
            } else {
                return .{ .offset = offset, .len = {} };
            }
        }
    };
}

pub fn CharRange(comptime a: u8, comptime b: u8, comptime repeat: Repeat) type {
    return struct {
        pub const Kind = if (repeat == .kleene) .char_slice else .char;
        offset: u32,
        len: if (repeat == .kleene) u32 else void,

        pub fn compile(_: type) []const Op {
            var bs = std.bit_set.ArrayBitSet(usize, 256).initEmpty();
            for (a..b + 1) |c| {
                bs.set(c);
            }
            return &[_]Op{.{ .read = .{ .set = bs, .repeat = repeat } }};
        }

        pub fn eval(
            comptime G: type,
            ctx: *const BuildContext,
            state: *NodeState,
        ) BuildError!@This() {
            _ = G;
            const start_pos = state.pos;

            // Scan the text to find how many characters match this range
            var end_pos = start_pos;
            while (end_pos < state.end and end_pos < ctx.text.len) {
                const ch = ctx.text[end_pos];
                if (ch >= a and ch <= b) {
                    end_pos += 1;
                    if (repeat == .one) break; // Stop after one character for .one
                } else {
                    break; // Stop when we hit a non-matching character
                }
            }

            // For .one, we must have matched at least one character
            if (repeat == .one and end_pos == start_pos) {
                return error.InvalidAst;
            }

            state.pos = end_pos;

            const offset: u32 = @intCast(start_pos);
            if (repeat == .kleene) {
                const len: u32 = @intCast(end_pos - start_pos);
                return .{ .offset = offset, .len = len };
            } else {
                return .{ .offset = offset, .len = {} };
            }
        }
    };
}

pub fn Call(comptime r: anytype) type {
    return struct {
        pub const Kind = .call;
        index: u32,

        pub const TargetName = if (@TypeOf(r) == []const u8) r else @tagName(r);

        pub fn compile(_: type) []const Op {
            return &[_]Op{.{
                .call = TargetName,
            }};
        }

        pub fn eval(
            comptime G: type,
            ctx: *const BuildContext,
            state: *NodeState,
        ) BuildError!@This() {
            const rule = comptime G.ruleFromName(TargetName);
            const index = try G.expectCall(rule, ctx, state);
            return .{ .index = index };
        }
    };
}

pub fn Hide(comptime pattern: type) type {
    return struct {
        pub const Kind = .hidden;
        pub fn compile(_: type) []const Op {
            return pattern.compile(pattern);
        }

        pub fn eval(
            comptime G: type,
            ctx: *const BuildContext,
            state: *NodeState,
        ) BuildError!@This() {
            _ = try pattern.eval(G, ctx, state);
            return .{};
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

        fn ctrl(self: *Self, mode: FrameEffect, lbl: labels) *Self {
            self.forwards[self.forward_count] = .{
                .op_index = self.n,
                .label_id = lbl,
            };
            self.forward_count += 1;
            self.ops[self.n] = .{ .frob = .{ .fx = mode } };
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
                self.ops[fwd.op_index].frob.ip = target - from - 1;
            }

            // Return slice of actual ops
            const result = self.ops[0..self.n];
            return result;
        }
    };
}

pub fn Kleene(comptime rule_ref: anytype) type {
    return struct {
        pub const Kind = .kleene;
        pub const RuleTag = rule_ref; // Compile-time: which rule this repeats

        offset: u32, // Starting index in the rule's forest array
        len: u32, // Number of elements

        pub fn compile(_: type) []const Op {
            // Compile as repeated call to the target rule
            const target_name = @tagName(rule_ref);
            var a = Assembler(4, enum { loop, done }){};
            return a
                .mark(.loop)
                .ctrl(.push, .done)
                .emit(&[_]Op{.{ .call = target_name }})
                .ctrl(.move, .loop)
                .mark(.done)
                .build();
        }

        pub fn eval(
            comptime G: type,
            ctx: *const BuildContext,
            state: *NodeState,
        ) BuildError!@This() {
            const slice = try G.gatherNodeSlice(rule_ref, ctx, state);
            return .{ .offset = slice.offset, .len = slice.len };
        }
    };
}

pub fn Maybe(comptime inner: type) type {
    return struct {
        value: ?inner,

        pub fn compile(g: type) []const Op {
            const part = inner.compile(g);
            var a = Assembler(part.len + 2, enum { done }){};
            return a
                .ctrl(.push, .done)
                .emit(part)
                .ctrl(.drop, .done)
                .mark(.done)
                .build();
        }

        pub fn eval(
            comptime G: type,
            ctx: *const BuildContext,
            state: *NodeState,
        ) BuildError!@This() {
            // Save the current position in case we need to backtrack
            const saved_pos = state.pos;
            const saved_child = state.next_child;

            // Try to evaluate the inner pattern
            if (inner.eval(G, ctx, state)) |value| {
                return .{ .value = value };
            } else |_| {
                // Pattern didn't match, restore state and return null
                state.pos = saved_pos;
                state.next_child = saved_child;
                return .{ .value = null };
            }
        }
    };
}

pub fn Noop() type {
    return struct {
        pub fn compile(_: type) []const Op {
            return &[_]Op{};
        }

        pub fn eval(
            comptime G: type,
            ctx: *const G.BuildContext,
            state: *G.NodeState,
        ) BuildError!@This() {
            _ = ctx;
            _ = state;
            return .{};
        }
    };
}

pub fn Struct(comptime parts: type) type {
    return struct {
        pub const Kind = .@"struct";
        value: parts,

        pub fn compile(g: type) []const Op {
            comptime var ops: []const Op = &[_]Op{};

            inline for (comptime std.meta.fields(parts)) |decl| {
                const part_type = @FieldType(parts, decl.name);
                const part_ops = part_type.compile(g);
                ops = ops ++ part_ops;
            }
            return ops;
        }

        pub fn eval(
            comptime G: type,
            ctx: *const BuildContext,
            state: *NodeState,
        ) BuildError!@This() {
            const info = @typeInfo(parts).@"struct";
            if (info.fields.len == 0) {
                return .{ .value = .{} };
            }

            var result: parts = undefined;
            inline for (info.fields) |field| {
                const FieldPatternType = @FieldType(parts, field.name);
                const field_value = try FieldPatternType.eval(G, ctx, state);
                @field(result, field.name) = field_value;
            }
            return .{ .value = result };
        }
    };
}

pub fn Union(comptime variants: type) type {
    return struct {
        pub const Kind = .@"union";
        value: variants,

        pub fn compile(g: type) []const Op {
            const info = @typeInfo(variants).@"union";

            // Enforce that all variants must be Call patterns
            inline for (info.fields) |field| {
                if (!@hasDecl(field.type, "TargetName")) {
                    @compileError("Union variant '" ++ field.name ++ "' must be a Call pattern");
                }
            }

            // Compile all variant opcodes
            comptime var variant_ops: [info.fields.len][]const Op = undefined;
            comptime var total_size = 0;
            inline for (info.fields, 0..) |field, i| {
                variant_ops[i] = field.type.compile(g);
                total_size += variant_ops[i].len;
                if (i < info.fields.len - 1) {
                    total_size += 2; // push + drop per non-last variant
                }
            }

            // Build the choice chain using comptime array
            comptime var result: [total_size]Op = undefined;
            comptime var idx: usize = 0;

            inline for (info.fields, 0..) |_, i| {
                const ops = variant_ops[i];

                if (i < info.fields.len - 1) {
                    // Not last variant - add choice point
                    result[idx] = .{ .frob = .{ .fx = .push, .ip = @intCast(ops.len + 1) } };
                    idx += 1;
                }

                // Emit variant opcodes
                inline for (ops) |op| {
                    result[idx] = op;
                    idx += 1;
                }

                if (i < info.fields.len - 1) {
                    // Not last variant - jump over remaining variants
                    comptime var remaining_size: i32 = 0;
                    inline for (i + 1..info.fields.len) |j| {
                        remaining_size += @intCast(variant_ops[j].len);
                        if (j < info.fields.len - 1) {
                            remaining_size += 2; // push + drop
                        }
                    }
                    result[idx] = .{ .frob = .{ .fx = .drop, .ip = remaining_size } };
                    idx += 1;
                }
            }

            return &result;
        }

        pub fn eval(
            comptime G: type,
            ctx: *const BuildContext,
            state: *NodeState,
        ) BuildError!@This() {
            const info = @typeInfo(variants).@"union";

            // Get the child node to determine which branch matched
            const child_idx = state.next_child orelse return error.InvalidAst;
            const child = ctx.nodes[child_idx];
            const child_rule: G.RuleEnum = @enumFromInt(child.rule_index);

            // Match child rule to union field
            inline for (info.fields) |field| {
                const field_call_rule = comptime G.ruleFromName(field.type.TargetName);
                if (child_rule == field_call_rule) {
                    const index = try G.expectCall(field_call_rule, ctx, state);
                    return .{ .value = @unionInit(variants, field.name, .{ .index = index }) };
                }
            }

            return error.InvalidAst;
        }
    };
}

pub fn Peek(comptime inner: type) type {
    return struct {
        pub fn compile(g: type) []const Op {
            const part = inner.compile(g);
            var a = Assembler(part.len + 3, enum { fail, success }){};
            return a
                .ctrl(.push, .fail)
                .emit(part)
                .ctrl(.wipe, .success)
                .mark(.fail)
                .reject()
                .mark(.success)
                .build();
        }

        pub fn eval(
            comptime G: type,
            ctx: *const BuildContext,
            state: *NodeState,
        ) BuildError!@This() {
            // Save the current state
            const saved_pos = state.pos;
            const saved_child = state.next_child;

            // Try to evaluate the inner pattern
            _ = try inner.eval(G, ctx, state);

            // Restore state (peek doesn't consume)
            state.pos = saved_pos;
            state.next_child = saved_child;

            return .{};
        }
    };
}

pub fn Shun(comptime inner: type) type {
    return struct {
        pub fn compile(g: type) []const Op {
            const part = inner.compile(g);
            var a = Assembler(part.len + 3, enum { fail, success }){};
            return a
                .ctrl(.push, .success)
                .emit(part)
                .ctrl(.wipe, .fail)
                .mark(.fail)
                .reject()
                .mark(.success)
                .build();
        }

        pub fn eval(
            comptime G: type,
            ctx: *const BuildContext,
            state: *NodeState,
        ) BuildError!@This() {
            // Save the current state
            const saved_pos = state.pos;
            const saved_child = state.next_child;

            // Try to evaluate the inner pattern
            if (inner.eval(G, ctx, state)) |_| {
                // Pattern matched - that's bad for negative lookahead
                return error.InvalidAst;
            } else |_| {
                // Pattern didn't match - that's what we want
                // Restore state (negative lookahead doesn't consume)
                state.pos = saved_pos;
                state.next_child = saved_child;
                return .{};
            }
        }
    };
}

var stdoutbuf: [4096]u8 = undefined;
const stdout_file = std.fs.File.stdout();
var stdout_writer = stdout_file.writer(&stdoutbuf);
const stdout = &stdout_writer.interface;

test "Grammar AST inference" {
    const G = Grammar(demoGrammar);

    // value is a union with integer and array variants (wrapped in a struct)
    const ValueType = G.RuleValueType(.value);
    try std.testing.expect(@typeInfo(ValueType) == .@"struct");
    try std.testing.expect(@typeInfo(@FieldType(ValueType, "value")) == .@"union");

    // integer type should be a struct (the pattern type with _ fields removed)
    const IntegerType = G.RuleValueType(.integer);
    try std.testing.expect(@typeInfo(IntegerType) == .@"struct");

    // skip type should be a struct (CharSet with kleene repeat)
    const SkipType = G.RuleValueType(.skip);
    try std.testing.expect(@typeInfo(SkipType) == .@"struct");

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var test_forest = G.Forest.init();
    defer test_forest.deinit(arena.allocator());

    try std.testing.expect(test_forest.lists.value.items.len == 0);
    // Pattern types ARE value types now - the runtime fields get populated during forest construction
}

pub fn main() !void {
    const G = demoGrammar;
    const VM = @import("vm.zig").VM;
    const trace = @import("trace.zig");

    const tty = std.Io.tty.detectConfig(stdout_file);

    try trace.dumpCode(G, stdout, tty);

    const TestVM = VM(G);

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    var vm = try TestVM.initAlloc("[[1] [2]]", allocator, 32, 32, 256);
    defer vm.deinit(allocator);

    // Use the trace function from trace.zig
    try trace.trace(&vm, stdout, tty);

    // Parse again to build the AST and print it
    var ast_vm = try TestVM.initAlloc("[[1] [2] [4096]]", allocator, 32, 32, 256);
    defer ast_vm.deinit(allocator);
    try ast_vm.run();
    try trace.dumpAst(&ast_vm, stdout, tty, allocator);
    try trace.dumpForest(&ast_vm, stdout, tty, allocator, .Array);

    try stdout.flush();
}
