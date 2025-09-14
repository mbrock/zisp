// Simple internal iteration design - coroutines as stateful function composition
//
// Instead of complex yielding, each layer is just a stateful iterator
// that drives its inner layer and does something with the results.

const std = @import("std");
const pegvmfun = @import("pegvmfun.zig");

// Re-export for convenience
pub const Parser = ParserGen;

// Core VM - just an iterator that returns events
pub fn VM(comptime Program: []const pegvmfun.AbsoluteOp) type {
    return struct {
        const Self = @This();

        ip: u32 = 0,
        sp: u32 = 0,
        text: [:0]const u8,
        saves: BoundedStack(SaveFrame, 128) = .{},
        calls: BoundedStack(CallFrame, 32) = .{},

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

        pub const Event = union(enum) {
            invoke_rule: struct { id: u32, pos: u32 },
            return_rule: struct { id: u32, start: u32, end: u32 },
            backtrack: struct { from: u32, to: u32 },
            match: struct { pos: u32, len: u32 },
        };

        // Simple next() function - returns null when done
        pub fn next(self: *Self) !?Event {
            // The simple inline switch VM core
            switch (self.ip) {
                inline 0...Program.len - 1 => |ip| {
                    const op = Program[ip];
                    self.ip = ip + 1;
                    const ch = self.text[self.sp];

                    switch (op) {
                        .read => |set| {
                            if (set.isSet(ch)) {
                                const ev = Event{ .match = .{ .pos = self.sp, .len = 1 } };
                                self.sp += 1;
                                return ev;
                            }
                            return self.fail();
                        },

                        .call => |target| {
                            try self.calls.push(.{
                                .return_ip = self.ip,
                                .rule_id = target,
                                .start_sp = self.sp,
                            });

                            const ev = Event{ .invoke_rule = .{ .id = target, .pos = self.sp } };
                            self.ip = target;
                            return ev;
                        },

                        .branch => |ctrl| switch (ctrl.action) {
                            .push => {
                                try self.saves.push(.{
                                    .ip = ctrl.offset,
                                    .sp = self.sp,
                                    .call_depth = @intCast(self.calls.len),
                                });
                                return self.next(); // Silent, continue
                            },

                            .drop => {
                                _ = self.saves.pop();
                                self.ip = ctrl.offset;
                                return self.next(); // Silent, continue
                            },

                            .move => {
                                if (self.saves.len > 0) {
                                    self.saves.items[self.saves.len - 1].sp = self.sp;
                                }
                                self.ip = ctrl.offset;
                                return self.next();
                            },

                            .wipe => {
                                const save = self.saves.pop();
                                self.sp = save.sp;
                                self.ip = ctrl.offset;
                                return self.next();
                            },
                        },

                        .done => {
                            if (self.calls.pop()) |frame| {
                                self.ip = frame.return_ip;
                                return .{ .return_rule = .{
                                    .id = frame.rule_id,
                                    .start = frame.start_sp,
                                    .end = self.sp,
                                } };
                            } else {
                                // No more calls - we're done!
                                if (self.sp == self.text.len) {
                                    return null;
                                } else {
                                    return error.UnconsumedInput;
                                }
                            }
                        },

                        .over => return null,
                        .fail => return self.fail(),
                    }
                },
                else => return null,
            }
        }

        fn fail(self: *Self) !?Event {
            // Backtrack if we can
            if (self.saves.pop()) |save| {
                const from = self.sp;

                self.ip = save.ip;
                self.sp = save.sp;
                self.calls.len = save.call_depth;

                return .{ .backtrack = .{ .from = from, .to = save.sp } };
            }

            return error.ParseFailed;
        }

        // Simple run to completion
        pub fn run(self: *Self) !bool {
            while (try self.next()) |_| {}
            return true;
        }
    };
}

// AST builder - wraps any event source, builds tree
pub fn TreeBuilder(comptime Inner: type) type {
    return struct {
        const Self = @This();

        inner: Inner,
        nodes: std.ArrayList(Node) = .{},
        stack: std.ArrayList(u32) = .{},
        allocator: std.mem.Allocator,

        pub const Node = struct {
            rule: u32,
            start: u32,
            end: u32,
            first_child: ?u32 = null,
            next_sibling: ?u32 = null,
        };

        pub const Event = Inner.Event; // Same events flow through

        pub fn deinit(self: *Self) void {
            self.nodes.deinit(self.allocator);
            self.stack.deinit(self.allocator);
        }

        pub fn next(self: *Self) !?Event {
            while (try self.inner.next()) |event| {
                switch (event) {
                    .invoke_rule => |inv| {
                        const id = self.nodes.items.len;
                        self.nodes.append(self.allocator, .{
                            .rule = inv.id,
                            .start = inv.pos,
                            .end = 0,
                        }) catch {};
                        self.stack.append(self.allocator, @intCast(id)) catch {};
                    },

                    .return_rule => |ret| {
                        if (self.stack.pop()) |node_id| {
                            const idx = @as(usize, @intCast(node_id));
                            self.nodes.items[idx].end = ret.end;

                            // Connect to parent
                            if (self.stack.items.len > 0) {
                                const parent = self.stack.items[self.stack.items.len - 1];
                                self.nodes.items[@intCast(node_id)].next_sibling = self.nodes.items[@intCast(parent)].first_child;
                                self.nodes.items[@intCast(parent)].first_child = node_id;
                            }
                        }
                    },

                    .backtrack => |b| {
                        // Roll back nodes past backtrack point
                        while (self.stack.items.len > 0) {
                            const node_id = self.stack.items[self.stack.items.len - 1];
                            if (self.nodes.items[@intCast(node_id)].start >= b.to) {
                                _ = self.stack.pop();
                                self.nodes.shrinkRetainingCapacity(@intCast(node_id));
                            } else break;
                        }
                    },

                    else => {},
                }
                return event; // Always pass events through!
            }
            return null;
        }

        pub fn run(self: *Self) !bool {
            while (try self.next()) |_| {}
            return true;
        }

        pub fn getTree(self: *Self) ?[]const Node {
            if (self.nodes.items.len > 0) {
                return self.nodes.items;
            }
            return null;
        }
    };
}

// Beautiful composition through simple nesting!
pub fn ParserGen(comptime Grammar: type) type {
    return struct {
        const Program = Grammar.compile();
        const BaseVM = VM(Program);

        // Simple parse
        pub fn parse(text: [:0]const u8) bool {
            var vm = BaseVM{ .text = text };
            return vm.run();
        }

        // Parse with AST
        pub fn parseWithTree(text: [:0]const u8) ?[]const TreeBuilder(BaseVM).Node {
            var vm = TreeBuilder(BaseVM){ .inner = .{ .text = text } };
            _ = vm.run();
            return vm.getTree();
        }
    };
}

// The key insight: Each layer is just a stateful function that:
// 1. Has an inner iterator it drives
// 2. Intercepts/modifies/observes events
// 3. Maintains its own state
// 4. Passes events through (usually)
//
// This is just function composition with state!

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
