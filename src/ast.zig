// AST building infrastructure for PEG parsers
//
// This module provides:
// - NodeType: Raw parse tree nodes (from VM)
// - NodeState: Cursor for traversing nodes during AST construction
// - Forest: Typed storage for built AST
// - Helpers for building typed values from parse trees

const std = @import("std");

// ============================================================================
// PARSE TREE NODE TYPE
// ============================================================================

pub const NodeType = struct {
    rule_index: u32,
    start: u32,
    end: u32,
    first_child: ?u32,
    next_sibling: ?u32,
    parent: ?u32,
};

// ============================================================================
// AST BUILDING TYPES
// ============================================================================

pub const BuildContext = struct {
    text: []const u8,
    nodes: []const NodeType,
    positions: []const usize,
};

pub const BuildError = error{ InvalidAst, UnsupportedPattern, OutOfMemory };

pub const NodeSlice = struct { offset: u32, len: u32 };

// ============================================================================
// NODE STATE - Cursor for traversing parse tree
// ============================================================================

pub const NodeState = struct {
    pos: usize,
    end: usize,
    next_child: ?usize,

    pub fn init(node: NodeType) @This() {
        return .{
            .pos = @intCast(node.start),
            .end = @intCast(node.end),
            .next_child = if (node.first_child) |fc| @intCast(fc) else null,
        };
    }

    pub fn expectCall(
        self: *@This(),
        ctx: *const BuildContext,
        rule_index: u32,
    ) BuildError!u32 {
        const child_idx = self.next_child orelse return error.InvalidAst;
        const child = ctx.nodes[child_idx];
        if (child.rule_index != rule_index) {
            return error.InvalidAst;
        }

        const start_pos: usize = @intCast(child.start);
        const end_pos: usize = @intCast(child.end);

        if (self.pos != start_pos) {
            return error.InvalidAst;
        }

        self.pos = end_pos;
        self.next_child = childToIndex(child.next_sibling);

        const index = ctx.positions[child_idx];
        return @intCast(index);
    }

    pub fn gatherNodeSlice(
        self: *@This(),
        ctx: *const BuildContext,
        rule_index: u32,
    ) BuildError!NodeSlice {
        var count: usize = 0;
        var first_index: usize = 0;
        var first = true;

        while (self.next_child) |child_idx| {
            const child = ctx.nodes[child_idx];
            if (child.rule_index != rule_index) {
                break;
            }

            const start_pos: usize = @intCast(child.start);
            const end_pos: usize = @intCast(child.end);
            if (self.pos != start_pos) {
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
            self.pos = end_pos;
            self.next_child = childToIndex(child.next_sibling);
        }

        return .{ .offset = @intCast(first_index), .len = @intCast(count) };
    }
};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

pub fn childToIndex(child: ?u32) ?usize {
    return if (child) |c| @intCast(c) else null;
}

pub fn stateNextBoundary(
    ctx: *const BuildContext,
    state: NodeState,
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

// Sort node indices for a rule so siblings (same parent) stay together.
pub fn sortRuleGroup(
    nodes: []const NodeType,
    items: []usize,
) void {
    if (items.len <= 1) return;
    const Context = struct {
        nodes: []const NodeType,

        fn lessThan(self: @This(), lhs: usize, rhs: usize) bool {
            const na = self.nodes[lhs];
            const nb = self.nodes[rhs];

            const pa = na.parent;
            const pb = nb.parent;

            if (pa) |a| {
                if (pb) |b| {
                    if (a == b) {
                        // Same parent: sort by position
                        if (na.start == nb.start) return lhs < rhs;
                        return na.start < nb.start;
                    }
                    return a < b;
                }
                return false;
            }
            if (pb != null) return true;

            // No parents: sort by position
            if (na.start == nb.start) return lhs < rhs;
            return na.start < nb.start;
        }
    };

    std.sort.block(usize, items, Context{ .nodes = nodes }, Context.lessThan);
}

// ============================================================================
// FOREST - Typed AST Storage
// ============================================================================

pub fn Forest(comptime rules: type) type {
    const RuleEnum = std.meta.DeclEnum(rules);

    const Helpers = struct {
        fn RuleValueType(comptime rule: RuleEnum) type {
            const pattern = @field(rules, @tagName(rule));
            return pattern;
        }

        fn NodeListType(comptime rule: RuleEnum) type {
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
    };

    const ListsStruct = blk: {
        const rule_count = std.meta.tags(RuleEnum).len;
        var fields: [rule_count]std.builtin.Type.StructField = undefined;
        inline for (std.meta.tags(RuleEnum), 0..) |rule_tag, i| {
            const ListType = Helpers.NodeListType(rule_tag);
            fields[i] = .{
                .name = @tagName(rule_tag),
                .type = ListType,
                .default_value_ptr = null,
                .is_comptime = false,
                .alignment = @alignOf(ListType),
            };
        }
        break :blk @Type(.{ .@"struct" = .{
            .layout = .auto,
            .backing_integer = null,
            .fields = &fields,
            .decls = &.{},
            .is_tuple = false,
        } });
    };

    return struct {
        const Self = @This();

        lists: ListsStruct,

        pub fn init() Self {
            var lists: ListsStruct = undefined;
            inline for (comptime std.meta.tags(RuleEnum)) |rule_tag| {
                @field(lists, @tagName(rule_tag)) = Helpers.NodeListType(rule_tag).empty;
            }
            return .{ .lists = lists };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            inline for (comptime std.meta.tags(RuleEnum)) |rule_tag| {
                @field(self.lists, @tagName(rule_tag)).deinit(allocator);
            }
        }

        pub fn append(
            self: *Self,
            allocator: std.mem.Allocator,
            comptime rule: RuleEnum,
            value: Helpers.RuleValueType(rule),
        ) !u32 {
            if (comptime @sizeOf(Helpers.RuleValueType(rule)) == 0) {
                @compileError("Cannot append nodes for non-capturing rules");
            }
            var list = &@field(self.lists, @tagName(rule));
            try list.append(allocator, value);
            return @intCast(list.items.len - 1);
        }

        pub fn get(
            self: *const Self,
            comptime rule: RuleEnum,
            index: u32,
        ) *const Helpers.RuleValueType(rule) {
            return &@field(self.lists, @tagName(rule)).items[index];
        }

        pub fn RuleValueType(comptime rule: RuleEnum) type {
            return Helpers.RuleValueType(rule);
        }
    };
}