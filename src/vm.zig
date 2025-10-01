comptime {
    @setEvalBranchQuota(500000);
}

const std = @import("std");
const peg = @import("peg.zig");

pub const Mode = enum {
    Step,
    Loop,
};

const Node = peg.NodeType;
const NodeKind = peg.NodeKind;

pub fn VM(comptime GrammarType: type) type {
    return struct {
        const Self = @This();
        comptime {
            @setEvalBranchQuota(500000);
        }
        pub const Grammar = peg.Grammar(GrammarType);
        pub const RuleEnum = Grammar.RuleEnum;
        pub const Ops = Grammar.compile(false);

        /// Bookkeeping for a structural opcode block (anything pushed by `open`).
        pub const StructuralFrame = struct {
            kind: NodeKind, // which helper node we opened
            node_index: u32, // index into the main node array for that helper
            node_child_start: usize,
            field_start: u32, // structs only: byte offset where the current field began
            field_child_start: usize, // structs only: children gathered for the current field
        };

        // === Core Parsing State ===
        sp: u32 = 0,
        text: [:0]const u8,

        // === Backtracking Stacks ===
        saves: std.ArrayList(SaveFrame),
        calls: std.ArrayList(CallFrame),

        // === AST Construction ===
        nodes: std.ArrayList(Node),
        child_stack: std.ArrayList(u32),
        root_node: ?u32 = null,

        // === Structural tracking ===
        struct_stack: std.ArrayList(StructuralFrame),

        // === Memoization (optional) ===
        memo: ?*MemoTable = null,

        /// Snapshot for the backtracking stack. Captures both the VM position and
        /// the lengths of the node/struct stacks so we can rewind them precisely.
        pub const SaveFrame = struct {
            ip: u32,
            sp: u32,
            call_depth: u32,
            node_len: usize,
            struct_depth: usize,
            child_len: usize,
        };

        /// Call-stack frame representing an in-flight rule invocation.
        pub const CallFrame = struct {
            return_ip: u32,
            target_ip: u32,
            rule: RuleEnum,
            start_sp: u32,
            struct_depth_on_entry: usize,
            child_start: usize,
        };

        pub const MemoKey = struct {
            ip: u32,
            sp: u32,
        };

        pub const MemoEntry = struct {
            success: bool,
            end_sp: u32,
        };

        pub const MemoTable = std.AutoHashMap(MemoKey, MemoEntry);

        pub fn init(
            text: [:0]const u8,
            saves: []SaveFrame,
            calls: []CallFrame,
            nodes: []Node,
            struct_frames: []StructuralFrame,
            child_indices: []u32,
        ) Self {
            return Self{
                .sp = 0,
                .text = text,
                .saves = .initBuffer(saves),
                .calls = .initBuffer(calls),
                .nodes = .initBuffer(nodes),
                .struct_stack = .initBuffer(struct_frames),
                .child_stack = .initBuffer(child_indices),
                .memo = null,
                .root_node = null,
            };
        }

        // === AST Construction Helpers ===

        /// Link children from the child_stack to a parent node, setting up sibling relationships.
        /// Returns the first child index and truncates the child_stack back to `start`.
        fn linkChildrenToParent(self: *Self, parent_idx: u32, start: usize) ?u32 {
            // Extract the slice of child indices accumulated since `start`
            const end = self.child_stack.items.len;
            const slice = if (start < end) self.child_stack.items[start..end] else &[_]u32{};

            var first_child: ?u32 = null;
            var prev_child: ?u32 = null;

            // Wire up the doubly-linked sibling chain
            for (slice, 0..) |child_idx, i| {
                if (i == 0) first_child = child_idx;

                // Link backwards to previous sibling
                self.nodes.items[child_idx].prev_sibling = prev_child;
                // Link previous sibling forward to current
                if (prev_child) |prev| {
                    self.nodes.items[@intCast(prev)].next_sibling = child_idx;
                }
                // Last sibling has no next
                self.nodes.items[child_idx].next_sibling = null;
                // All children point up to the parent
                self.nodes.items[child_idx].parent = parent_idx;
                prev_child = child_idx;
            }

            // Pop accumulated children off the stack
            self.child_stack.items.len = if (start <= end) start else end;
            return first_child;
        }

        /// Create a new node from a completed call frame
        /// (this is the only place `kind == .rule` nodes are born).
        fn appendNode(self: *Self, frame: CallFrame, end_sp: u32) !u32 {
            const idx: u32 = @intCast(self.nodes.items.len);
            const first_child = self.linkChildrenToParent(idx, frame.child_start);

            try self.nodes.appendBounded(.{
                .kind = .rule,
                .rule_index = @intFromEnum(frame.rule),
                .start = frame.start_sp,
                .end = end_sp,
                .first_child = first_child,
                .next_sibling = null,
                .prev_sibling = null,
                .parent = null,
            });

            return idx;
        }

        fn pushChildIndex(self: *Self, value: u32) !void {
            try self.child_stack.appendBounded(value);
        }

        /// Attach a newly created node to whichever stack frame owns it.
        ///
        /// Structural opcodes (`open/next/shut`) push frames that sit "above" the
        /// call stack, so children created while inside them should land on those
        /// frames instead of on the rule call.
        fn attachChild(self: *Self, child: u32) !void {
            const struct_depth = self.struct_stack.items.len;
            if (self.calls.getLastOrNull()) |call| {
                if (struct_depth >= call.struct_depth_on_entry)
                    //  We're in a call but more importantly we're in a structure.
                    try self.pushChildIndex(child);
            } else if (struct_depth > 0)
                try self.pushChildIndex(child);
        }

        /// Close out the current field and append a wrapper node for it.
        ///
        /// Struct compilation emits `open` / (field payload) / `next` / … / `shut`.
        /// Until we see either `next` or `shut` we accumulate the payload into
        /// a slice of `child_stack` starting at `field_child_start`. When the field
        /// ends we turn that payload into a dedicated `.field` node and push that
        /// node onto the struct’s own child list.
        fn finalizeStructField(self: *Self, frame: *StructuralFrame, end_sp: u32) !void {
            const field_idx: u32 = @intCast(self.nodes.items.len);
            const first_child = self.linkChildrenToParent(field_idx, frame.field_child_start);

            try self.nodes.appendBounded(.{
                .kind = .field,
                .rule_index = 0,
                .start = frame.field_start,
                .end = end_sp,
                .first_child = first_child,
                .next_sibling = null,
                .prev_sibling = null,
                .parent = null,
            });

            try self.pushChildIndex(field_idx);

            frame.field_start = end_sp;
            frame.field_child_start = self.child_stack.items.len;
        }

        /// Roll back the node list to a previous length (used during backtracking).
        fn truncateNodes(self: *Self, new_len: usize) void {
            if (new_len >= self.nodes.items.len) return;
            self.nodes.items.len = new_len;
            if (self.root_node) |root_idx| {
                if (root_idx >= new_len) self.root_node = null;
            }
        }

        /// Restore the child stack to a previous logical length, filtering out any
        /// indices that no longer point at live nodes (can happen after backtracking
        /// truncates the node list).
        fn restoreChildStack(self: *Self, target_len: usize) void {
            if (target_len == 0) {
                self.child_stack.items.len = 0;
                return;
            }

            const current = self.child_stack.items.len;
            const limit = if (target_len < current) target_len else current;
            var write: usize = 0;
            const live_nodes = self.nodes.items.len;

            var i: usize = 0;
            while (i < limit) : (i += 1) {
                const idx = self.child_stack.items[i];
                if (idx < live_nodes) {
                    self.child_stack.items[write] = idx;
                    write += 1;
                }
            }

            self.child_stack.items.len = write;
        }

        // === VM Execution ===

        /// Execute one or more VM instructions
        pub fn next(
            self: *Self,
            ip: u32,
            comptime mode: Mode,
        ) !(if (mode == .Loop) void else ?u32) {
            const loop = switch (mode) {
                .Step => false,
                .Loop => true,
            };

            vm: switch (ip) {
                inline 0...Ops.len - 1 => |IP| {
                    @setEvalBranchQuota(10_000);

                    const OP = Ops[IP];
                    const IP1 = IP + 1;
                    const ch = self.text[self.sp];

                    switch (OP) {
                        .read => |read_op| {
                            if (read_op.repeat == .kleene) {
                                // Consume as many matching characters as possible
                                while (self.sp < self.text.len and read_op.set.isSet(self.text[self.sp])) {
                                    self.sp += 1;
                                }
                                if (loop) continue :vm IP1 else return IP1;
                            } else {
                                // Single character match (repeat == .one)
                                if (read_op.set.isSet(ch)) {
                                    self.sp += 1;
                                    if (loop) continue :vm IP1 else return IP1;
                                }
                            }
                        },

                        .text => |lit| {
                            const start: usize = @intCast(self.sp);
                            const len: usize = lit.len;
                            if (start + len <= self.text.len) {
                                const slice = self.text[start .. start + len];
                                if (std.mem.eql(u8, slice, lit)) {
                                    self.sp = @intCast(start + len);
                                    if (loop) continue :vm IP1 else return IP1;
                                }
                            }
                        },

                        .call => |target| {
                            if (self.memo) |memo| {
                                const key = MemoKey{ .ip = target, .sp = self.sp };
                                if (memo.get(key)) |entry| {
                                    if (entry.success) {
                                        self.sp = entry.end_sp;
                                        if (loop) continue :vm IP1 else return IP1;
                                    } else {
                                        if (self.saves.pop()) |save| {
                                            self.sp = save.sp;
                                            self.calls.items.len = save.call_depth;
                                            self.truncateNodes(save.node_len);
                                            self.restoreChildStack(save.child_len);
                                            if (loop) continue :vm save.ip else return save.ip;
                                        }
                                        return error.ParseFailed;
                                    }
                                }
                            }

                            const rule = Grammar.ruleContainingIp(target) orelse unreachable;

                            try self.calls.appendBounded(.{
                                .return_ip = IP1,
                                .target_ip = target,
                                .rule = rule,
                                .start_sp = self.sp,
                                .struct_depth_on_entry = self.struct_stack.items.len,
                                .child_start = self.child_stack.items.len,
                            });

                            if (loop) continue :vm target else return target;
                        },

                        .frob => |ctrl| switch (ctrl.fx) {
                            .push => {
                                try self.saves.appendBounded(.{
                                    .ip = ctrl.ip,
                                    .sp = self.sp,
                                    .call_depth = @intCast(self.calls.items.len),
                                    .node_len = self.nodes.items.len,
                                    .struct_depth = self.struct_stack.items.len,
                                    .child_len = self.child_stack.items.len,
                                });
                                if (loop) continue :vm IP1 else return IP1;
                            },

                            .drop => {
                                _ = self.saves.pop();
                                if (loop) continue :vm ctrl.ip else return ctrl.ip;
                            },

                            .move => {
                                self.saves.items[self.saves.items.len - 1].sp = self.sp;
                                self.saves.items[self.saves.items.len - 1].node_len = self.nodes.items.len;
                                self.saves.items[self.saves.items.len - 1].struct_depth = self.struct_stack.items.len;
                                self.saves.items[self.saves.items.len - 1].child_len = self.child_stack.items.len;
                                if (loop) continue :vm ctrl.ip else return ctrl.ip;
                            },

                            .wipe => {
                                const save = self.saves.pop().?;
                                self.sp = save.sp;
                                self.struct_stack.items.len = save.struct_depth;
                                self.truncateNodes(save.node_len);
                                self.restoreChildStack(save.child_len);
                                if (loop) continue :vm ctrl.ip else return ctrl.ip;
                            },
                        },

                        .done => {
                            if (self.calls.pop()) |frame| {
                                const node_index = try self.appendNode(frame, self.sp);

                                if (self.memo) |memo| {
                                    const key = MemoKey{ .ip = frame.target_ip, .sp = frame.start_sp };
                                    try memo.put(key, .{ .success = true, .end_sp = self.sp });
                                }

                                try self.attachChild(node_index);
                                if (self.calls.items.len == 0) {
                                    self.root_node = node_index;
                                }

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

                        .open => |node_kind| {
                            const node_index: u32 = @intCast(self.nodes.items.len);
                            try self.nodes.appendBounded(.{
                                .kind = node_kind,
                                .rule_index = 0,
                                .start = self.sp,
                                .end = self.sp,
                                .first_child = null,
                                .next_sibling = null,
                                .prev_sibling = null,
                                .parent = null,
                            });

                            try self.struct_stack.appendBounded(.{
                                .kind = node_kind,
                                .node_index = node_index,
                                .node_child_start = self.child_stack.items.len,
                                .field_start = self.sp,
                                .field_child_start = self.child_stack.items.len,
                            });
                            if (loop) continue :vm IP1 else return IP1;
                        },

                        .next => {
                            if (self.struct_stack.items.len > 0) {
                                const frame = &self.struct_stack.items[self.struct_stack.items.len - 1];
                                if (frame.kind == .@"struct") {
                                    try self.finalizeStructField(frame, self.sp);
                                }
                            }
                            if (loop) continue :vm IP1 else return IP1;
                        },

                        .shut => {
                            if (self.struct_stack.items.len > 0) {
                                const frame = &self.struct_stack.items[self.struct_stack.items.len - 1];
                                if (frame.kind == .@"struct") {
                                    try self.finalizeStructField(frame, self.sp);
                                }

                                const frame_data = frame.*;
                                self.struct_stack.items.len -= 1;

                                const node_usize: usize = @intCast(frame_data.node_index);
                                const first_child = self.linkChildrenToParent(frame_data.node_index, frame_data.node_child_start);

                                self.nodes.items[node_usize].end = self.sp;
                                self.nodes.items[node_usize].first_child = first_child;

                                try self.attachChild(frame_data.node_index);
                            }
                            if (loop) continue :vm IP1 else return IP1;
                        },

                        .fail => {},
                    }

                    if (self.saves.pop()) |save| {
                        if (self.memo) |memo| {
                            var i = self.calls.items.len;
                            while (i > save.call_depth) {
                                i -= 1;
                                const frame = self.calls.items[i];
                                const key = MemoKey{ .ip = frame.target_ip, .sp = frame.start_sp };
                                memo.put(key, .{ .success = false, .end_sp = frame.start_sp }) catch {};
                            }
                        }

                        self.sp = save.sp;
                        self.calls.items.len = save.call_depth;
                        self.struct_stack.items.len = save.struct_depth;
                        self.truncateNodes(save.node_len);
                        self.restoreChildStack(save.child_len);

                        if (loop) continue :vm save.ip else return save.ip;
                    }

                    return error.ParseFailed;
                },
                else => return (if (mode == .Loop) {} else null),
            }
        }

        /// Run VM until completion
        pub fn run(self: *Self) !void {
            try self.next(0, .Loop);
        }

        /// Run VM starting from a specific rule
        pub fn runFrom(self: *Self, comptime rule: RuleEnum) !void {
            const start_ip = Grammar.ruleStartIp(rule);
            try self.next(start_ip, .Loop);
        }

        // === Lifecycle & Utilities ===

        pub fn initAlloc(
            text: [:0]const u8,
            gpa: std.mem.Allocator,
            maxsaves: usize,
            maxcalls: usize,
            maxnodes: usize,
        ) !Self {
            return Self.init(
                text,
                try gpa.alloc(SaveFrame, maxsaves),
                try gpa.alloc(CallFrame, maxcalls),
                try gpa.alloc(Node, maxnodes),
                try gpa.alloc(StructuralFrame, maxsaves), // Use same capacity as saves
                try gpa.alloc(u32, maxnodes),
            );
        }

        pub fn deinit(self: *Self, gpa: std.mem.Allocator) void {
            self.saves.deinit(gpa);
            self.calls.deinit(gpa);
            self.nodes.deinit(gpa);
            self.struct_stack.deinit(gpa);
            self.child_stack.deinit(gpa);
        }

        pub fn parse(
            text: [:0]const u8,
            gpa: std.mem.Allocator,
        ) !void {
            var vm = try Self.initAlloc(text, gpa, 32, 32, 256);
            defer vm.deinit(gpa);
            _ = try vm.run();
        }

        pub fn countSteps(text: [:0]const u8, gpa: std.mem.Allocator) !u32 {
            var self = try Self.initAlloc(text, gpa, 32, 32, 256);
            defer self.deinit(gpa);

            var ip: u32 = 0;
            var count: u32 = 1;

            while (try self.next(ip, .Step)) |new_ip| {
                ip = new_ip;
                count += 1;
            }

            return count;
        }

        pub fn parseWithMemo(
            text: [:0]const u8,
            gpa: std.mem.Allocator,
        ) !void {
            var vm = try Self.initAlloc(text, gpa, 32, 32, 256);
            defer vm.deinit(gpa);

            var memo = MemoTable.init(gpa);
            defer memo.deinit();
            vm.memo = &memo;

            _ = try vm.run();
        }

        // === AST Forest Construction ===

        /// Build typed forest from parse tree
        pub fn buildForest(
            self: *const Self,
            allocator: std.mem.Allocator,
            comptime root_rule: RuleEnum,
        ) (peg.BuildError || error{NoAst})!Grammar.BuildResult(root_rule) {
            const root_index = self.root_node orelse return error.NoAst;
            const text_slice = self.text[0..self.text.len];
            return Grammar.buildForestForRoot(
                allocator,
                text_slice,
                self.nodes.items,
                root_index,
                root_rule,
            );
        }

        // === Memoization Utilities ===

        pub fn countStepsWithMemo(text: [:0]const u8, gpa: std.mem.Allocator) !struct { steps: u32, hits: u32, misses: u32 } {
            var self = try Self.initAlloc(text, gpa, 32, 32, 256);
            defer self.deinit(gpa);

            var memo = MemoTable.init(gpa);
            defer memo.deinit();
            self.memo = &memo;

            var ip: u32 = 0;
            var count: u32 = 1;
            var hits: u32 = 0;
            var misses: u32 = 0;

            while (true) {
                if (ip < Ops.len and Ops[ip] == .call) {
                    const key = MemoKey{ .ip = Ops[ip].call, .sp = self.sp };
                    if (memo.contains(key)) {
                        hits += 1;
                    } else {
                        misses += 1;
                    }
                }

                if (try self.next(ip, .Step)) |new_ip| {
                    ip = new_ip;
                    count += 1;
                } else {
                    break;
                }
            }

            return .{ .steps = count, .hits = hits, .misses = misses };
        }
    };
}

pub const SimpleGrammar = struct {
    pub const main = peg.Match(struct {
        a: peg.CharSet("a", .one),
        b: peg.CharSet("b", .one),
    });
};

const ChoiceGrammar = struct {
    const R = std.meta.DeclEnum(@This());

    pub const main = peg.Match(union(enum) {
        ab: peg.Call(.ab),
        ac: peg.Call(.ac),
    });

    pub const ab = peg.Match(struct { a: peg.CharSet("a", .one), b: peg.CharSet("b", .one) });
    pub const ac = peg.Match(struct { a: peg.CharSet("a", .one), c: peg.CharSet("c", .one) });
};

pub const RecursiveGrammar = struct {
    const R = std.meta.DeclEnum(@This());

    pub const main = peg.Call(.expr);

    pub const expr = peg.Match(union(enum) {
        number: peg.Call(.number),
        parens: peg.Call(.parens),
    });

    pub const parens = peg.Match(struct {
        open: peg.CharSet("(", .one),
        expr: peg.Call(.expr),
        close: peg.CharSet(")", .one),
    });

    pub const number = peg.Match(struct {
        first: peg.Char(peg.CharClass.range('1', '9'), .one),
        rest: peg.Char(peg.CharClass.range('0', '9'), .kleene),
    });
};

const KleeneGrammar = struct {
    const R = std.meta.DeclEnum(@This());

    pub const main = peg.Match(struct {
        a_list: peg.CharSet("a", .kleene),
        b: peg.CharSet("b", .one),
    });
};

const OptionalGrammar = struct {
    pub const main = peg.Match(struct {
        a_opt: peg.Maybe(peg.CharSet("a", .one)),
        b: peg.CharSet("b", .one),
    });
};

fn step(vm: anytype, ip: *u32) !bool {
    if (try vm.next(ip.*, .Step)) |new_ip| {
        ip.* = new_ip;
        return true;
    } else {
        return false;
    }
}

fn expectParseSuccess(comptime G: type, text: [:0]const u8) !void {
    const TestVM = VM(G);
    try TestVM.parse(text, std.testing.allocator);
    _ = try TestVM.countSteps(text, std.testing.allocator);
}

fn expectParseFailure(comptime G: type, text: [:0]const u8) !void {
    const TestVM = VM(G);
    try std.testing.expectError(error.ParseFailed, TestVM.parse(text, std.testing.allocator));
    try std.testing.expectError(error.ParseFailed, TestVM.countSteps(text, std.testing.allocator));
}

test "basic VM iteration" {
    try expectParseSuccess(SimpleGrammar, "ab");
    try expectParseFailure(SimpleGrammar, "ac");
}

test "VM with backtracking" {
    try expectParseSuccess(ChoiceGrammar, "ab");
    try expectParseSuccess(ChoiceGrammar, "ac");
    try expectParseFailure(ChoiceGrammar, "ad");
}

test "VM event iteration" {
    try std.testing.expectEqual(
        6,
        try VM(SimpleGrammar).countSteps("ab", std.testing.allocator),
    );
}

// Tests using the grammar compiler
test "simple grammar compilation" {
    try expectParseSuccess(SimpleGrammar, "ab");
    try expectParseFailure(SimpleGrammar, "ac");
    try expectParseFailure(SimpleGrammar, "a");
}

test "choice grammar compilation" {
    try expectParseSuccess(ChoiceGrammar, "ab");
    try expectParseSuccess(ChoiceGrammar, "ac");
    try expectParseFailure(ChoiceGrammar, "ad");
}

test "kleene star grammar compilation" {
    try expectParseSuccess(KleeneGrammar, "b");
    try expectParseSuccess(KleeneGrammar, "ab");
    try expectParseSuccess(KleeneGrammar, "aaab");
    try expectParseFailure(KleeneGrammar, "aaa");
}

test "optional grammar compilation" {
    try expectParseSuccess(OptionalGrammar, "ab");
    try expectParseSuccess(OptionalGrammar, "b");
    try expectParseFailure(OptionalGrammar, "ac");
}

test "recursive grammar compilation" {
    try expectParseSuccess(RecursiveGrammar, "42");
    try expectParseSuccess(RecursiveGrammar, "(123)");
    try expectParseSuccess(RecursiveGrammar, "((99))");
    try expectParseFailure(RecursiveGrammar, "(42");
}

test "demo grammar from pegvmfun" {
    try expectParseSuccess(peg.demoGrammar, "123   ");
    try expectParseSuccess(peg.demoGrammar, "[123 456 789]");
    try expectParseSuccess(peg.demoGrammar, "[[1] [2]]");
    try expectParseSuccess(peg.demoGrammar, "[]");
}

test "memoization correctness" {
    const TestVM = VM(RecursiveGrammar);

    // Both should succeed
    try TestVM.parse("((42))", std.testing.allocator);
    try TestVM.parseWithMemo("((42))", std.testing.allocator);

    // Both should fail
    try std.testing.expectError(error.ParseFailed, TestVM.parse("((42", std.testing.allocator));
    try std.testing.expectError(error.ParseFailed, TestVM.parseWithMemo("((42", std.testing.allocator));
}
