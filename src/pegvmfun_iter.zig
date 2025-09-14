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
        calls: BoundedStack(CallFrame, 256) = .{},
        
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
            accept: void,
            reject: void,
            invoke_rule: struct { id: u32, pos: u32 },
            return_rule: struct { id: u32, start: u32, end: u32 },
            fail_rule: struct { id: u32, pos: u32 },
            backtrack: struct { from: u32, to: u32 },
            match: struct { pos: u32, len: u32 },
        };
        
        // Simple next() function - returns null when done
        pub fn next(self: *Self) ?Event {
            // The simple inline switch VM core
            switch (self.ip) {
                inline 0...Program.len - 1 => |ip| {
                    const op = Program[ip];
                    self.ip = ip + 1;
                    const ch = self.text[self.sp];
                    
                    switch (op) {
                        .op_charset => |set| {
                            if (set.isSet(ch)) {
                                const ev = Event{ .match = .{ .pos = self.sp, .len = 1 } };
                                self.sp += 1;
                                return ev;
                            }
                            return self.fail();
                        },
                        
                        .op_range => |r| {
                            if (ch >= r.min and ch <= r.max) {
                                const ev = Event{ .match = .{ .pos = self.sp, .len = 1 } };
                                self.sp += 1;
                                return ev;
                            }
                            return self.fail();
                        },
                        
                        .op_invoke => |target| {
                            self.calls.push(.{
                                .return_ip = self.ip,
                                .rule_id = target,
                                .start_sp = self.sp,
                            }) catch unreachable;
                            
                            const ev = Event{ .invoke_rule = .{ .id = target, .pos = self.sp } };
                            self.ip = target;
                            return ev;
                        },
                        
                        .op_ctrl => |ctrl| switch (ctrl.mode) {
                            .rescue => {
                                self.saves.push(.{
                                    .ip = ctrl.offset,
                                    .sp = self.sp,
                                    .call_depth = @intCast(self.calls.len),
                                }) catch unreachable;
                                return self.next(); // Silent, continue
                            },
                            
                            .commit => {
                                _ = self.saves.pop();
                                self.ip = ctrl.offset;
                                return self.next(); // Silent, continue
                            },
                            
                            .update => {
                                if (self.saves.len > 0) {
                                    self.saves.items[self.saves.len - 1].sp = self.sp;
                                }
                                self.ip = ctrl.offset;
                                return self.next();
                            },
                            
                            .rewind => {
                                const save = self.saves.pop();
                                self.sp = save.sp;
                                self.ip = ctrl.offset;
                                return self.next();
                            },
                        },
                        
                        .op_return => {
                            const frame = self.calls.pop();
                            self.ip = frame.return_ip;
                            return .{ .return_rule = .{
                                .id = frame.rule_id,
                                .start = frame.start_sp,
                                .end = self.sp,
                            }};
                        },
                        
                        .op_accept => return .accept,
                        .op_reject => return self.fail(),
                    }
                },
                else => return null,
            }
        }
        
        fn fail(self: *Self) ?Event {
            // Check if we're failing inside a rule
            if (self.calls.len > 0) {
                const frame = self.calls.items[self.calls.len - 1];
                if (self.saves.len == 0 or self.saves.items[self.saves.len - 1].call_depth < self.calls.len) {
                    self.calls.len -= 1;
                    self.ip = frame.return_ip;
                    return .{ .fail_rule = .{ .id = frame.rule_id, .pos = self.sp } };
                }
            }
            
            // Backtrack if we can
            if (self.saves.len > 0) {
                const save = self.saves.pop();
                const from = self.sp;
                
                self.ip = save.ip;
                self.sp = save.sp;
                self.calls.len = save.call_depth;
                
                return .{ .backtrack = .{ .from = from, .to = save.sp } };
            }
            
            return .reject;
        }
        
        // Simple run to completion
        pub fn run(self: *Self) bool {
            while (self.next()) |event| {
                switch (event) {
                    .accept => return true,
                    .reject => return false,
                    else => {},
                }
            }
            return false;
        }
    };
}

// Memoizer - wraps VM, intercepts events, maintains cache
pub fn Memoizer(comptime Inner: type) type {
    return struct {
        const Self = @This();
        
        inner: Inner,
        cache: std.ArrayList(Entry) = .{},
        allocator: std.mem.Allocator,
        
        const Entry = struct {
            rule: u32,
            pos: u32,
            end: u32,
            success: bool,
        };
        
        pub const Event = Inner.Event; // Same event type!
        
        pub fn deinit(self: *Self) void {
            self.cache.deinit(self.allocator);
        }
        
        pub fn next(self: *Self) ?Event {
            // Internal iteration - we drive the inner iterator
            while (self.inner.next()) |event| {
                switch (event) {
                    .invoke_rule => |inv| {
                        // Check cache
                        for (self.cache.items) |entry| {
                            if (entry.rule == inv.id and entry.pos == inv.pos) {
                                // Skip this rule invocation!
                                const frame = self.inner.calls.pop();
                                self.inner.ip = frame.return_ip;
                                
                                if (entry.success) {
                                    self.inner.sp = entry.end;
                                    // Synthesize a return event
                                    return .{ .return_rule = .{
                                        .id = inv.id,
                                        .start = inv.pos,
                                        .end = entry.end,
                                    }};
                                } else {
                                    // Synthesize a fail event
                                    return .{ .fail_rule = .{
                                        .id = inv.id,
                                        .pos = inv.pos,
                                    }};
                                }
                            }
                        }
                        return event; // Cache miss, proceed normally
                    },
                    
                    .return_rule => |ret| {
                        // Store successful parse
                        self.storeCache(ret.id, ret.start, ret.end, true);
                        return event;
                    },
                    
                    .fail_rule => |fail| {
                        // Store failed parse
                        self.storeCache(fail.id, fail.pos, fail.pos, false);
                        return event;
                    },
                    
                    else => return event, // Pass through
                }
            }
            return null;
        }
        
        fn storeCache(self: *Self, rule: u32, pos: u32, end: u32, success: bool) void {
            if (self.cache.items.len >= 256) {
                _ = self.cache.orderedRemove(0); // LRU
            }
            self.cache.append(self.allocator, .{
                .rule = rule,
                .pos = pos,
                .end = end,
                .success = success,
            }) catch {};
        }
        
        pub fn run(self: *Self) bool {
            while (self.next()) |event| {
                switch (event) {
                    .accept => return true,
                    .reject => return false,
                    else => {},
                }
            }
            return false;
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
        
        pub fn next(self: *Self) ?Event {
            while (self.inner.next()) |event| {
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
                    
                    .fail_rule => {
                        if (self.stack.pop()) |failed| {
                            self.nodes.items.len = @intCast(failed); // Roll back
                        }
                    },
                    
                    .backtrack => |b| {
                        // Roll back nodes past backtrack point
                        while (self.stack.items.len > 0) {
                            const node_id = self.stack.items[self.stack.items.len - 1];
                            if (self.nodes.items[@intCast(node_id)].start >= b.to) {
                                _ = self.stack.pop();
                                self.nodes.items.len = @intCast(node_id);
                            } else break;
                        }
                    },
                    
                    else => {},
                }
                return event; // Always pass events through!
            }
            return null;
        }
        
        pub fn run(self: *Self) bool {
            while (self.next()) |event| {
                switch (event) {
                    .accept => return true,
                    .reject => return false,
                    else => {},
                }
            }
            return false;
        }
        
        pub fn getTree(self: *Self) ?[]const Node {
            if (self.nodes.items.len > 0) {
                return self.nodes.items;
            }
            return null;
        }
    };
}

// Logger - wraps any event source, logs events
pub fn Logger(comptime Inner: type, comptime Writer: type) type {
    return struct {
        const Self = @This();
        
        inner: Inner,
        writer: Writer,
        depth: u32 = 0,
        
        pub const Event = Inner.Event;
        
        pub fn next(self: *Self) ?Event {
            if (self.inner.next()) |event| {
                // Log based on event type
                switch (event) {
                    .invoke_rule => |inv| {
                        self.indent();
                        self.writer.print("→ Rule {} at {}\n", .{ inv.id, inv.pos }) catch {};
                        self.depth += 1;
                    },
                    .return_rule => |ret| {
                        self.depth -|= 1;
                        self.indent();
                        self.writer.print("✓ Rule {} [{}-{}]\n", .{ ret.id, ret.start, ret.end }) catch {};
                    },
                    .fail_rule => |fail| {
                        self.depth -|= 1;
                        self.indent();
                        self.writer.print("✗ Rule {} at {}\n", .{ fail.id, fail.pos }) catch {};
                    },
                    .match => |m| {
                        self.indent();
                        self.writer.print("• Match at {} ({}B)\n", .{ m.pos, m.len }) catch {};
                    },
                    .backtrack => |b| {
                        self.indent();
                        self.writer.print("↶ Backtrack {}->{}\n", .{ b.from, b.to }) catch {};
                    },
                    .accept => {
                        self.writer.print("SUCCESS\n", .{}) catch {};
                    },
                    .reject => {
                        self.writer.print("FAILURE\n", .{}) catch {};
                    },
                }
                return event;
            }
            return null;
        }
        
        fn indent(self: *Self) void {
            for (0..self.depth) |_| {
                self.writer.writeAll("  ") catch {};
            }
        }
        
        pub fn run(self: *Self) bool {
            while (self.next()) |event| {
                switch (event) {
                    .accept => return true,
                    .reject => return false,
                    else => {},
                }
            }
            return false;
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
        
        // Parse with memoization
        pub fn parseWithCache(text: [:0]const u8) bool {
            var vm = Memoizer(BaseVM){ 
                .inner = .{ .text = text } 
            };
            return vm.run();
        }
        
        // Parse with AST
        pub fn parseWithTree(text: [:0]const u8) ?[]const TreeBuilder(BaseVM).Node {
            var vm = TreeBuilder(BaseVM){ 
                .inner = .{ .text = text } 
            };
            _ = vm.run();
            return vm.getTree();
        }
        
        // Compose features!
        pub fn parseWithFeatures(text: [:0]const u8) ?[]const TreeBuilder(Memoizer(BaseVM)).Node {
            // Tree builder on top of memoizer on top of VM!
            var vm = TreeBuilder(Memoizer(BaseVM)){
                .inner = .{
                    .inner = .{ .text = text }
                }
            };
            _ = vm.run();
            return vm.getTree();
        }
        
        // Parse with logging
        pub fn parseWithLog(text: [:0]const u8, writer: anytype) bool {
            var vm = Logger(Memoizer(BaseVM), @TypeOf(writer)){
                .inner = .{
                    .inner = .{ .text = text }
                },
                .writer = writer,
            };
            return vm.run();
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
        
        pub fn pop(self: *@This()) T {
            self.len -= 1;
            return self.items[self.len];
        }
    };
}