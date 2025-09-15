// Simple internal iteration design - coroutines as stateful function composition
//
// Instead of complex yielding, each layer is just a stateful iterator
// that drives its inner layer and does something with the results.

const std = @import("std");
const pegvmfun = @import("pegvmfun.zig");

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
            called: struct { id: u32, pos: u32 },
            return_rule: struct { id: u32, start: u32, end: u32 },
            backtrack: struct { from: u32, to: u32 },
            match: struct { pos: u32, len: u32 },
        };

        // Simple next() function - returns null when done
        pub fn next(self: *Self) !?Event {
            // The simple inline switch VM core
            vm: switch (self.ip) {
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

                            const ev = Event{ .called = .{ .id = target, .pos = self.sp } };
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
                                continue :vm ip + 1;
                            },

                            .drop => {
                                _ = self.saves.pop();
                                continue :vm ctrl.offset;
                            },

                            .move => {
                                if (self.saves.len > 0) {
                                    self.saves.items[self.saves.len - 1].sp = self.sp;
                                }
                                continue :vm ctrl.offset;
                            },

                            .wipe => {
                                const save = self.saves.pop();
                                self.sp = save.sp;
                                continue :vm ctrl.offset;
                            },
                        },

                        .done => {
                            if (self.calls.pop()) |frame| {
                                self.ip = frame.return_ip;
                                return .{
                                    .return_rule = .{
                                        .id = frame.rule_id,
                                        .start = frame.start_sp,
                                        .end = self.sp,
                                    },
                                };
                            } else {
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

        pub fn parse(
            text: [:0]const u8,
        ) !void {
            var vm = Self{
                .text = text,
            };
            _ = try vm.run();
        }
    };
}

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
