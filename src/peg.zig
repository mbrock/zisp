const std = @import("std");

pub const demoGrammar = struct {
    // Rules define their grammatical structure as struct fields.
    // The grammar compiler compiles the field types to opcode sequences.
    //
    // Fields prefixed with _ are hidden from the AST (like Hide()).

    const R = std.meta.DeclEnum(@This());

    pub const value = union(enum) {
        integer: Call(R.integer),
        array: Call(R.array),
    };

    pub const integer = struct {
        d: CharRange('1', '9'),
        ds: []CharRange('0', '9'),
        _skip: Hide(Call(R.skip)),
    };

    pub const array = Seq(.{
        CharSet("["),
        Hide(Call(R.skip)),
        []Call(R.value),
        Hide(Call(R.skip)),
        CharSet("]"),
        Hide(Call(R.skip)),
    });

    pub const skip = []CharSet(" \t\n\r");
};

pub inline fn compile(comptime rules: type) []const Abs {
    return Grammar(rules).compile(false);
}

pub inline fn Grammar(rules: type) type {
    return struct {
        pub const RuleEnum = std.meta.DeclEnum(rules);
        const RuleOffsetMap = std.enums.EnumMap(RuleEnum, comptime_int);

        pub const TextRange = struct {
            start: usize,
            len: usize,
        };

        pub fn NodeRefType(comptime rule: RuleEnum) type {
            return struct {
                pub const rule_tag = rule;
                pub const node_ref_kind = .single;
                index: usize,
            };
        }

        pub fn NodeSliceType(comptime rule: RuleEnum) type {
            return struct {
                pub const rule_tag = rule;
                pub const node_ref_kind = .slice;
                start: usize,
                len: usize,
            };
        }

        fn isNodeRefType(comptime T: type) bool {
            return switch (@typeInfo(T)) {
                .@"struct" => @hasDecl(T, "node_ref_kind") and T.node_ref_kind == .single,
                else => false,
            };
        }

        fn isNodeSliceType(comptime T: type) bool {
            return switch (@typeInfo(T)) {
                .@"struct" => @hasDecl(T, "node_ref_kind") and T.node_ref_kind == .slice,
                else => false,
            };
        }

        fn ruleFromName(comptime name: []const u8) RuleEnum {
            if (@hasField(RuleEnum, name)) {
                return @field(RuleEnum, name);
            }
            @compileError("Unknown grammar rule '" ++ name ++ "'");
        }

        fn primitiveValueType(comptime t: type) type {
            if (@hasDecl(t, "Value")) {
                return t.Value;
            }
            if (@hasDecl(t, "TargetName")) {
                const name = t.TargetName;
                return NodeRefType(ruleFromName(name));
            }

            @compileError("Unsupported primitive pattern type when inferring AST value");
        }

        fn valueTypeForStruct(comptime info: std.builtin.Type.Struct) type {
            if (info.is_tuple) {
                comptime var tuple_buf: [info.fields.len]type = undefined;
                comptime var tuple_count: usize = 0;
                inline for (info.fields) |field| {
                    const field_type = valueTypeForPattern(field.type);
                    if (field_type == void) continue;
                    tuple_buf[tuple_count] = field_type;
                    tuple_count += 1;
                }
                if (tuple_count == 0) return void;
                const used = tuple_buf[0..tuple_count];
                return std.meta.Tuple(used);
            }

            comptime var fields_buf: [info.fields.len]std.builtin.Type.StructField = undefined;
            comptime var count: usize = 0;
            inline for (info.fields) |field| {
                const field_type = valueTypeForPattern(field.type);
                if (field_type == void) continue;
                fields_buf[count] = .{
                    .name = field.name,
                    .type = field_type,
                    .default_value_ptr = null,
                    .is_comptime = false,
                    .alignment = field.alignment,
                };
                count += 1;
            }

            if (count == 0) {
                return void;
            }

            const used_fields = fields_buf[0..count];
            return @Type(.{ .@"struct" = .{
                .layout = .auto,
                .backing_integer = null,
                .fields = used_fields,
                .decls = &.{},
                .is_tuple = false,
            } });
        }

        fn valueTypeForUnion(comptime info: std.builtin.Type.Union) type {
            if (info.tag_type == null) {
                @compileError("Untagged unions are not supported in grammar patterns");
            }

            comptime var fields: [info.fields.len]std.builtin.Type.UnionField = undefined;
            inline for (info.fields, 0..) |field, i| {
                const field_type = valueTypeForPattern(field.type);
                fields[i] = .{
                    .name = field.name,
                    .type = field_type,
                    .alignment = @alignOf(field_type),
                };
            }

            return @Type(.{ .@"union" = .{
                .layout = .auto,
                .tag_type = info.tag_type,
                .fields = &fields,
                .decls = &.{},
            } });
        }

        fn valueTypeForSlice(comptime child: type) type {
            const inner = valueTypeForPattern(child);

            if (inner == void) {
                return void;
            }

            if (comptime isNodeRefType(inner)) {
                return NodeSliceType(inner.rule_tag);
            }

            if (comptime isNodeSliceType(inner)) {
                return NodeSliceType(inner.rule_tag);
            }

            if (inner == u8 or inner == TextRange) {
                return TextRange;
            }

            @compileError("Unsupported slice pattern for AST inference");
        }

        fn valueTypeForPattern(comptime t: type) type {
            return switch (@typeInfo(t)) {
                .pointer => |ptr| blk: {
                    if (ptr.size == .slice) {
                        break :blk valueTypeForSlice(ptr.child);
                    }
                    @compileError("Only slice pointers are supported in grammar patterns");
                },
                .optional => |opt| ?valueTypeForPattern(opt.child),
                .@"struct" => |info| blk: {
                    if (@hasDecl(t, "TargetName") or @hasDecl(t, "Value")) {
                        break :blk primitiveValueType(t);
                    }
                    break :blk valueTypeForStruct(info);
                },
                .@"union" => |info| valueTypeForUnion(info),
                else => primitiveValueType(t),
            };
        }

        fn ruleValueType(comptime rule: RuleEnum) type {
            const rule_pattern = @field(rules, @tagName(rule));
            const pattern_type = getRulePatternType(rule_pattern);
            return valueTypeForPattern(pattern_type);
        }

        pub fn RuleValueType(comptime rule: RuleEnum) type {
            return ruleValueType(rule);
        }

        pub fn NodeListType(comptime rule: RuleEnum) type {
            const ValueType = RuleValueType(rule);
            if (@sizeOf(ValueType) == 0) {
                return struct {
                    items: []ValueType = &.{},
                    pub const empty = @This(){};
                    pub fn append(_: *@This(), _: std.mem.Allocator, _: ValueType) !void {
                        return;
                    }
                    pub fn deinit(_: *@This(), _: std.mem.Allocator) void {}
                };
            }
            return std.ArrayList(ValueType);
        }

        fn forestFieldsType() type {
            const tags = comptime std.meta.tags(RuleEnum);
            comptime var fields: [tags.len]std.builtin.Type.StructField = undefined;
            inline for (tags, 0..) |rule_tag, i| {
                const ListType = NodeListType(rule_tag);
                fields[i] = .{
                    .name = @tagName(rule_tag),
                    .type = ListType,
                    .default_value_ptr = null,
                    .is_comptime = false,
                    .alignment = @alignOf(ListType),
                };
            }

            return @Type(.{ .@"struct" = .{
                .layout = .auto,
                .backing_integer = null,
                .fields = &fields,
                .decls = &.{},
                .is_tuple = false,
            } });
        }

        pub const Forest = forestFieldsType();

        pub fn initForest() Forest {
            var forest: Forest = undefined;
            inline for (comptime std.meta.tags(RuleEnum)) |rule_tag| {
                @field(forest, @tagName(rule_tag)) = NodeListType(rule_tag).empty;
            }
            return forest;
        }

        pub fn deinitForest(forest: *Forest, allocator: std.mem.Allocator) void {
            inline for (comptime std.meta.tags(RuleEnum)) |rule_tag| {
                @field(forest.*, @tagName(rule_tag)).deinit(allocator);
            }
        }

        pub fn appendNode(
            forest: *Forest,
            allocator: std.mem.Allocator,
            comptime rule: RuleEnum,
            value: RuleValueType(rule),
        ) !NodeRefType(rule) {
            if (comptime @sizeOf(RuleValueType(rule)) == 0) {
                @compileError("Cannot append nodes for non-capturing rules");
            }
            var list = &@field(forest.*, @tagName(rule));
            try list.append(allocator, value);
            return NodeRefType(rule){ .index = list.items.len - 1 };
        }

        pub fn getNode(
            forest: *const Forest,
            comptime rule: RuleEnum,
            ref: NodeRefType(rule),
        ) *const RuleValueType(rule) {
            return &@field(forest.*, @tagName(rule)).items[ref.index];
        }

        pub const BuildError = error{ InvalidAst, UnsupportedPattern, OutOfMemory };

        pub fn BuildResult(comptime rule: RuleEnum) type {
            return struct {
                forest: Forest,
                root: NodeRefType(rule),
            };
        }

        fn NodeState(comptime NodeType: type) type {
            return struct {
                pos: usize,
                end: usize,
                next_child: ?usize,

                fn init(node: NodeType) @This() {
                    return .{
                        .pos = @intCast(node.start),
                        .end = @intCast(node.end),
                        .next_child = if (node.first_child) |fc| @intCast(fc) else null,
                    };
                }

                fn copy(self: @This()) @This() {
                    return self;
                }
            };
        }

        fn BuildContext(comptime NodeType: type) type {
            return struct {
                text: []const u8,
                nodes: []const NodeType,
                positions: []const usize,
            };
        }

        fn childToIndex(child: ?u32) ?usize {
            return if (child) |c| @intCast(c) else null;
        }

        fn stateNextBoundary(
            comptime NodeType: type,
            ctx: *const BuildContext(NodeType),
            state: NodeState(NodeType),
        ) BuildError!usize {
            if (state.next_child) |child_idx| {
                const start: usize = @intCast(ctx.nodes[child_idx].start);
                if (start > ctx.text.len) {
                    return error.InvalidAst;
                }
                return start;
            }
            if (state.end > ctx.text.len) {
                return error.InvalidAst;
            }
            return state.end;
        }

        fn expectCall(
            comptime NodeType: type,
            comptime rule: RuleEnum,
            ctx: *const BuildContext(NodeType),
            state: *NodeState(NodeType),
        ) BuildError!NodeRefType(rule) {
            const child_idx = state.next_child orelse return error.InvalidAst;
            const child = ctx.nodes[child_idx];
            if (child.rule_index != @intFromEnum(rule)) {
                return error.InvalidAst;
            }

            const start_pos: usize = @intCast(child.start);
            const end_pos: usize = @intCast(child.end);

            if (state.pos != start_pos) {
                return error.InvalidAst;
            }

            state.pos = end_pos;
            state.next_child = childToIndex(child.next_sibling);

            const index = ctx.positions[child_idx];
            return NodeRefType(rule){ .index = index };
        }

        fn gatherNodeSlice(
            comptime NodeType: type,
            comptime rule: RuleEnum,
            ctx: *const BuildContext(NodeType),
            state: *NodeState(NodeType),
        ) BuildError!NodeSliceType(rule) {
            var temp = state.copy();
            var count: usize = 0;
            var first_index: usize = 0;
            var first = true;

            while (temp.next_child) |child_idx| {
                const child = ctx.nodes[child_idx];
                if (child.rule_index != @intFromEnum(rule)) {
                    break;
                }

                const start_pos: usize = @intCast(child.start);
                const end_pos: usize = @intCast(child.end);
                if (temp.pos != start_pos) {
                    return error.InvalidAst;
                }

                const index = ctx.positions[child_idx];
                if (first) {
                    first_index = index;
                    first = false;
                } else if (index != first_index + count) {
                    return error.InvalidAst;
                }

                count += 1;
                temp.pos = end_pos;
                temp.next_child = childToIndex(child.next_sibling);
            }

            state.* = temp;
            return NodeSliceType(rule){ .start = first_index, .len = count };
        }

        fn evalPrimitive(
            comptime NodeType: type,
            comptime PatternType: type,
            ctx: *const BuildContext(NodeType),
            state: *NodeState(NodeType),
        ) BuildError!valueTypeForPattern(PatternType) {
            const ValueType = valueTypeForPattern(PatternType);
            if (ValueType == void or ValueType == u8) {
                if (state.pos >= state.end or state.pos >= ctx.text.len) {
                    return error.InvalidAst;
                }
                const ch = ctx.text[state.pos];
                state.pos += 1;
                if (ValueType == u8) {
                    return ch;
                } else {
                    return;
                }
            }

            return error.UnsupportedPattern;
        }

        fn evalSlice(
            comptime NodeType: type,
            comptime PatternType: type,
            ctx: *const BuildContext(NodeType),
            state: *NodeState(NodeType),
        ) BuildError!valueTypeForPattern(PatternType) {
            const pointer_info = @typeInfo(PatternType).pointer;
            if (pointer_info.size != .slice) {
                return error.UnsupportedPattern;
            }

            const ChildType = pointer_info.child;
            const InnerType = valueTypeForPattern(ChildType);

            if (InnerType == void) {
                if (@hasDecl(ChildType, "TargetName")) {
                    const rule = comptime ruleFromName(ChildType.TargetName);
                    _ = try gatherNodeSlice(NodeType, rule, ctx, state);
                    return;
                }
                const start = state.pos;
                const boundary = try stateNextBoundary(NodeType, ctx, state.*);
                if (boundary < start or boundary > ctx.text.len) {
                    return error.InvalidAst;
                }
                state.pos = boundary;
                return;
            }

            if (comptime isNodeRefType(InnerType)) {
                return gatherNodeSlice(NodeType, InnerType.rule_tag, ctx, state);
            }

            if (comptime isNodeSliceType(InnerType)) {
                return gatherNodeSlice(NodeType, InnerType.rule_tag, ctx, state);
            }

            if (InnerType == TextRange or InnerType == u8) {
                const start = state.pos;
                const boundary = try stateNextBoundary(NodeType, ctx, state.*);
                if (boundary < start or boundary > ctx.text.len) {
                    return error.InvalidAst;
                }
                state.pos = boundary;
                return TextRange{ .start = start, .len = boundary - start };
            }

            return error.UnsupportedPattern;
        }

        fn evalOptional(
            comptime NodeType: type,
            comptime PatternType: type,
            ctx: *const BuildContext(NodeType),
            state: *NodeState(NodeType),
        ) BuildError!?valueTypeForPattern(PatternType) {
            var temp = state.copy();
            const value = evalPattern(NodeType, PatternType, ctx, &temp) catch |err| switch (err) {
                error.InvalidAst => return null,
                else => return err,
            };
            state.* = temp;
            return value;
        }

        fn evalStruct(
            comptime NodeType: type,
            comptime PatternType: type,
            ctx: *const BuildContext(NodeType),
            state: *NodeState(NodeType),
        ) BuildError!valueTypeForPattern(PatternType) {
            const info = @typeInfo(PatternType).@"struct";
            const ValueType = valueTypeForPattern(PatternType);

            if (info.fields.len == 0) {
                return ValueType{};
            }

            var result: ValueType = undefined;

            comptime var tuple_slot: usize = 0;
            inline for (info.fields) |field| {
                const FieldPatternType = @FieldType(PatternType, field.name);
                const FieldValueType = valueTypeForPattern(FieldPatternType);
                if (FieldValueType == void) {
                    try evalPattern(NodeType, FieldPatternType, ctx, state);
                    continue;
                }
                const field_value = try evalPattern(NodeType, FieldPatternType, ctx, state);
                if (info.is_tuple) {
                    const name = std.fmt.comptimePrint("{d}", .{tuple_slot});
                    tuple_slot += 1;
                    @field(result, name) = field_value;
                } else {
                    @field(result, field.name) = field_value;
                }
            }

            return result;
        }

        fn evalUnion(
            comptime NodeType: type,
            comptime PatternType: type,
            ctx: *const BuildContext(NodeType),
            state: *NodeState(NodeType),
        ) BuildError!valueTypeForPattern(PatternType) {
            const info = @typeInfo(PatternType).@"union";
            const ValueType = valueTypeForPattern(PatternType);

            inline for (info.fields) |field| {
                var temp = state.copy();
                const FieldPatternType = field.type;
                const FieldValueType = valueTypeForPattern(FieldPatternType);
                if (FieldValueType == void) {
                    evalPattern(NodeType, FieldPatternType, ctx, &temp) catch |err| switch (err) {
                        error.InvalidAst => continue,
                        else => return err,
                    };
                    state.* = temp;
                    return @unionInit(ValueType, field.name, {});
                }
                if (evalPattern(NodeType, FieldPatternType, ctx, &temp)) |field_value| {
                    state.* = temp;
                    return @unionInit(ValueType, field.name, field_value);
                } else |err| switch (err) {
                    error.InvalidAst => {},
                    else => return err,
                }
            }

            return error.InvalidAst;
        }

        fn evalPattern(
            comptime NodeType: type,
            comptime PatternType: type,
            ctx: *const BuildContext(NodeType),
            state: *NodeState(NodeType),
        ) BuildError!valueTypeForPattern(PatternType) {
            const ValueType = valueTypeForPattern(PatternType);

            switch (@typeInfo(PatternType)) {
                .pointer => return evalSlice(NodeType, PatternType, ctx, state),
                .optional => |opt| return evalOptional(NodeType, opt.child, ctx, state),
                .@"struct" => {
                    if (@hasDecl(PatternType, "TargetName")) {
                        const rule = comptime ruleFromName(PatternType.TargetName);
                        const ref = try expectCall(NodeType, rule, ctx, state);
                        if (comptime ValueType == void) return;
                        return ref;
                    }

                    if (@hasDecl(PatternType, "Value")) {
                        return evalPrimitive(NodeType, PatternType, ctx, state);
                    }

                    return evalStruct(NodeType, PatternType, ctx, state);
                },
                .@"union" => return evalUnion(NodeType, PatternType, ctx, state),
                else => {},
            }

            return error.UnsupportedPattern;
        }

        fn buildNodeValue(
            comptime NodeType: type,
            comptime rule: RuleEnum,
            ctx: *const BuildContext(NodeType),
            node_index: usize,
        ) BuildError!RuleValueType(rule) {
            const node = ctx.nodes[node_index];
            var state = NodeState(NodeType).init(node);

            const rule_pattern = @field(rules, @tagName(rule));
            const pattern_type = getRulePatternType(rule_pattern);

            const value = try evalPattern(NodeType, pattern_type, ctx, &state);
            if (state.next_child != null or state.pos != state.end) {
                return error.InvalidAst;
            }
            return value;
        }

        // Sort node indices for a rule so siblings (same parent) stay together.
        fn sortRuleGroup(
            comptime NodeType: type,
            nodes: []const NodeType,
            parents: []const ?usize,
            items: []usize,
        ) void {
            if (items.len <= 1) return;
            const Context = struct {
                parents: []const ?usize,
                nodes: []const NodeType,

                fn lessThan(self: @This(), lhs: usize, rhs: usize) bool {
                    const pa = self.parents[lhs];
                    const pb = self.parents[rhs];
                    if (pa) |a| {
                        if (pb) |b| {
                            if (a == b) {
                                const na = self.nodes[lhs];
                                const nb = self.nodes[rhs];
                                if (na.start == nb.start) return lhs < rhs;
                                return na.start < nb.start;
                            }
                            return a < b;
                        }
                        return false;
                    }
                    if (pb != null) return true;
                    const na = self.nodes[lhs];
                    const nb = self.nodes[rhs];
                    if (na.start == nb.start) return lhs < rhs;
                    return na.start < nb.start;
                }
            };

            std.sort.block(usize, items, Context{ .parents = parents, .nodes = nodes }, Context.lessThan);
        }

        pub fn buildForestForRoot(
            comptime NodeType: type,
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

            var parents = try allocator.alloc(?usize, node_count);
            defer allocator.free(parents);
            for (parents) |*p| p.* = null;

            for (nodes, 0..) |node, idx| {
                var child_opt = node.first_child;
                while (child_opt) |child_u32| {
                    const child_idx: usize = @intCast(child_u32);
                    parents[child_idx] = idx;
                    child_opt = nodes[child_idx].next_sibling;
                }
            }

            const rule_tags = comptime std.meta.tags(RuleEnum);
            const rule_count = rule_tags.len;

            var buckets: [rule_count]std.ArrayListUnmanaged(usize) = undefined;
            inline for (0..rule_count) |i| buckets[i] = .{};
            defer {
                inline for (0..rule_count) |i| buckets[i].deinit(allocator);
            }

            for (nodes, 0..) |node, idx| {
                const ri: usize = @intCast(node.rule_index);
                try buckets[ri].append(allocator, idx);
            }

            inline for (rule_tags, 0..) |_, ri| {
                sortRuleGroup(NodeType, nodes, parents, buckets[ri].items);
            }

            var positions = try allocator.alloc(usize, node_count);
            defer allocator.free(positions);

            inline for (rule_tags, 0..) |_, ri| {
                const slice = buckets[ri].items;
                for (slice, 0..) |node_idx, pos| positions[node_idx] = pos;
            }

            var forest = initForest();
            const ctx = BuildContext(NodeType){ .text = text, .nodes = nodes, .positions = positions };

            inline for (rule_tags, 0..) |rule_tag, ri| {
                const ValueType = RuleValueType(rule_tag);
                if (@sizeOf(ValueType) == 0) continue;
                var list = &@field(forest, @tagName(rule_tag));
                const slice = buckets[ri].items;
                for (slice) |node_idx| {
                    const value = try buildNodeValue(NodeType, rule_tag, &ctx, node_idx);
                    try list.append(allocator, value);
                }
            }

            const ensured_root: usize = @intCast(root_index);
            if (ensured_root >= node_count) {
                return error.InvalidAst;
            }
            const root_node = nodes[ensured_root];
            const actual_rule: RuleEnum = @enumFromInt(root_node.rule_index);
            if (actual_rule != root_rule) {
                return error.InvalidAst;
            }

            const root_ref = NodeRefType(root_rule){ .index = positions[ensured_root] };
            return BuildResult(root_rule){ .forest = forest, .root = root_ref };
        }

        // Helper: Check if a declaration is a valid rule pattern (any type that can be normalized)
        fn isRulePattern(comptime decl_type: type) bool {
            return switch (@typeInfo(decl_type)) {
                .@"struct", .@"union", .pointer, .optional => true,
                else => @hasDecl(decl_type, "compile"),
            };
        }

        // Helper: Get the pattern type for a rule
        fn getRulePatternType(comptime rule: anytype) type {
            // Rule is already a type, not a value
            return rule;
        }

        // Helper: Calculate total size needed for a rule's opcodes
        fn calculateRuleSize(comptime rule: anytype) comptime_int {
            const pattern_type = getRulePatternType(rule);
            const opcodes = compilePattern(pattern_type);
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
                const rule_pattern = @field(rules, decl.name);
                // rule_pattern is already a type, not a value
                const pattern_type = getRulePatternType(rule_pattern);
                const relative_ops = compilePattern(pattern_type);
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
            const normalized = normalize(t);
            return normalized.compile(rules);
        }
    };
}
// Normalize a pattern type (e.g., []T becomes kleene(T))
fn normalize(comptime t: type) type {
    switch (@typeInfo(t)) {
        .pointer => |ptr| {
            if (ptr.size == .slice) {
                return Kleene(normalize(ptr.child));
            } else {
                @compileError("bad pattern type");
            }
        },
        .optional => |opt| {
            return Maybe(normalize(opt.child));
        },
        .@"struct" => {
            if (@hasDecl(t, "compile")) {
                return t;
            }

            return Struct(t);
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
                    choice_type = Choice(choice_type, variants[i]);
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
        /// Consume any byte that matches the bitset
        read: std.StaticBitSet(256),
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

pub fn CharSet(s: []const u8) type {
    return struct {
        pub const Value = void;

        pub fn compile(_: type) []const Op {
            var bs = std.bit_set.ArrayBitSet(usize, 256).initEmpty();
            for (s) |c| {
                bs.set(c);
            }
            return &[_]Op{.{ .read = bs }};
        }
    };
}

pub fn CharRange(a: u8, b: u8) type {
    return struct {
        pub const Value = void;

        pub fn compile(_: type) []const Op {
            var bs = std.bit_set.ArrayBitSet(usize, 256).initEmpty();
            for (a..b + 1) |c| {
                bs.set(c);
            }
            return &[_]Op{.{ .read = bs }};
        }
    };
}

pub fn Call(r: anytype) type {
    return struct {
        pub const TargetName = if (@TypeOf(r) == []const u8) r else @tagName(r);

        pub fn compile(_: type) []const Op {
            return &[_]Op{.{
                .call = TargetName,
            }};
        }
    };
}

pub fn Hide(comptime pattern: type) type {
    comptime {
        if (!@hasDecl(pattern, "TargetName")) {
            @compileError("Hide expects a callable pattern");
        }
    }

    return struct {
        pub const TargetName = pattern.TargetName;
        pub const Value = void;

        pub fn compile(_: type) []const Op {
            return pattern.compile(pattern);
        }
    };
}

fn tupleTypes(T: anytype) [T.len]type {
    var types: [T.len]type = undefined;
    comptime var i = 0;
    inline for (T) |t| {
        types[i] = t;
        i += 1;
    }
    return types;
}

pub fn Seq(parts: anytype) type {
    return std.meta.Tuple(&tupleTypes(parts));
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

pub fn Kleene(comptime inner: type) type {
    return struct {
        pub fn compile(g: type) []const Op {
            const part = inner.compile(g);
            var a = Assembler(part.len + 2, enum { loop, done }){};
            return a
                .mark(.loop)
                .ctrl(.push, .done)
                .emit(part)
                .ctrl(.move, .loop)
                .mark(.done)
                .build();
        }
    };
}

pub fn Maybe(comptime inner: type) type {
    return struct {
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
    };
}

pub fn Noop() type {
    return struct {
        pub const Value = void;

        pub fn compile(_: type) []const Op {
            return &[_]Op{};
        }
    };
}

pub fn Struct(comptime parts: type) type {
    return struct {
        pub fn compile(g: type) []const Op {
            comptime var ops: []const Op = &[_]Op{};

            inline for (comptime std.meta.fields(parts)) |decl| {
                const part_type = @FieldType(parts, decl.name);
                const part_ops = normalize(part_type).compile(g);
                ops = ops ++ part_ops;
            }
            return ops;
        }
    };
}

pub fn Choice(comptime alt1: type, comptime alt2: type) type {
    return struct {
        pub fn compile(g: type) []const Op {
            const ops1 = alt1.compile(g);
            const ops2 = alt2.compile(g);
            var a = Assembler(ops1.len + ops2.len + 2, enum { alt2, done }){};

            return a
                .ctrl(.push, .alt2)
                .emit(ops1)
                .ctrl(.drop, .done)
                .mark(.alt2)
                .emit(ops2)
                .mark(.done)
                .build();
        }
    };
}

pub fn Peek(comptime inner: type) type {
    return struct {
        pub const Value = void;

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
    };
}

pub fn Shun(comptime inner: type) type {
    return struct {
        pub const Value = void;

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
    };
}

var stdoutbuf: [4096]u8 = undefined;
const stdout_file = std.fs.File.stdout();
var stdout_writer = stdout_file.writer(&stdoutbuf);
const stdout = &stdout_writer.interface;

test "Grammar AST inference" {
    const G = Grammar(demoGrammar);

    const ValueType = G.RuleValueType(.value);
    const value_info = @typeInfo(ValueType).@"union";
    try std.testing.expectEqual(@as(usize, 2), value_info.fields.len);
    try std.testing.expect(std.mem.eql(u8, value_info.fields[0].name, "integer"));
    try std.testing.expect(value_info.fields[0].type == G.NodeRefType(.integer));
    try std.testing.expect(std.mem.eql(u8, value_info.fields[1].name, "array"));
    try std.testing.expect(value_info.fields[1].type == G.NodeRefType(.array));

    const ArrayType = G.RuleValueType(.array);
    const array_info = @typeInfo(ArrayType).@"struct";
    try std.testing.expect(array_info.is_tuple);
    try std.testing.expectEqual(@as(usize, 1), array_info.fields.len);
    try std.testing.expect(array_info.fields[0].type == G.NodeSliceType(.value));

    const SkipType = G.RuleValueType(.skip);
    try std.testing.expect(SkipType == void);

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var forest = G.initForest();
    defer G.deinitForest(&forest, arena.allocator());

    try std.testing.expect(forest.value.items.len == 0);
    const node_ref = try G.appendNode(&forest, arena.allocator(), .value, ValueType{ .integer = G.NodeRefType(.integer){ .index = 0 } });
    try std.testing.expect(node_ref.index == 0);
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
    var ast_vm = try TestVM.initAlloc("[[1] [2]]", allocator, 32, 32, 256);
    defer ast_vm.deinit(allocator);
    try ast_vm.run();
    try trace.dumpAst(&ast_vm, stdout, tty, allocator);
    try trace.dumpForest(&ast_vm, stdout, tty, allocator, .array);

    try stdout.flush();
}
