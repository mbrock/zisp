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

    const R = std.meta.DeclEnum(@This());

    pub fn value(
        _: union(enum) {
            integer: Call(R.integer),
            array: Call(R.array),
        },
    ) void {}

    pub fn integer(
        _: CharRange('1', '9'),
        _: []CharRange('0', '9'),
        _: Call(R.skip),
    ) void {}

    pub fn array(_: Seq(.{
        CharSet("["),
        Call(R.skip),
        []Call(R.value),
        Call(R.skip),
        CharSet("]"),
        Call(R.skip),
    })) void {}

    pub fn skip(_: []CharSet(" \t\n\r")) void {}
};

pub inline fn compile(comptime rules: type) []const Abs {
    return Grammar(rules).compile(false);
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
        ) [total_size]OpG(rel) {
            var code: [total_size]OpG(rel) = undefined;
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

        fn name(op: @This()) []const u8 {
            return switch (op) {
                .frob => |x| @tagName(x.fx),
                inline else => @tagName(op),
            };
        }

        pub fn dump(
            op: @This(),
            tty: std.Io.tty.Config,
            w: *std.Io.Writer,
            _: u32,
        ) !void {
            try tty.setColor(w, .reset);
            try w.print("{s} ", .{op.name()});

            switch (op) {
                .frob => |ctrl| {
                    if (rel == false) {
                        try tty.setColor(w, .cyan);
                        try w.print("→{d}", .{ctrl.ip});
                    } else {
                        try tty.setColor(w, .cyan);
                        if (ctrl.ip > 0)
                            try w.writeByte('+');
                        try w.print("{d}", .{ctrl.ip});
                    }
                },
                .call => |target| {
                    if (@TypeOf(target) == u32) {
                        try tty.setColor(w, .cyan);
                        try w.print("→{d}", .{target});
                    } else {
                        try tty.setColor(w, .blue);
                        try w.print("&{s}", .{@tagName(target)});
                    }
                },
                .read => |cs| {
                    var i: u32 = 0;
                    while (i < 256) : (i += 1) {
                        if (cs.isSet(i)) {
                            // Check for ranges - look ahead for consecutive characters
                            var range_end = i;
                            while (range_end + 1 < 256 and cs.isSet(range_end + 1)) : (range_end += 1) {}

                            if (range_end > i + 1) {
                                // We have a range of at least 3 characters
                                // Print start of range
                                try printChar(tty, w, @intCast(i));
                                try tty.setColor(w, .dim);
                                try w.writeAll("⋯");
                                try tty.setColor(w, .reset);
                                // Print end of range
                                try printChar(tty, w, @intCast(range_end));
                                i = range_end;
                            } else if (range_end == i + 1) {
                                // Just two consecutive characters - print them separately
                                try printChar(tty, w, @intCast(i));
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

pub const Rel = OpG(true);
pub const Abs = OpG(false);
pub const Opcodes = []const Abs;

const Op = Rel;

pub fn CharSet(s: []const u8) type {
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

pub fn CharRange(a: u8, b: u8) type {
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

pub fn Call(r: anytype) type {
    return struct {
        pub fn compile(_: type) []const Op {
            return &[_]Op{.{
                .call = if (@TypeOf(r) == []const u8) r else @tagName(r),
            }};
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

const ctrls = [_][]const u8{
    "␀",
    "␁",
    "␂",
    "␃",
    "␄",
    "␅",
    "␆",
    "␇",
    "␈",
    "␉",
    "␤",
    "␋",
    "␌",
    "␍",
    "␎",
    "␏",
    "␐",
    "␑",
    "␒",
    "␓",
    "␔",
    "␕",
    "␖",
    "␗",
    "␘",
    "␙",
    "␚",
    "␛",
    "␜",
    "␝",
    "␞",
    "␟",
    "␠",
};

fn printChar(tty: std.Io.tty.Config, writer: *std.Io.Writer, c: u8) !void {
    if (c < ctrls.len) {
        try tty.setColor(writer, .magenta);
        try writer.print("{s}", .{ctrls[c]});
    } else if (c >= 33 and c < 127 and c != '\\') {
        try tty.setColor(writer, .yellow);
        try writer.print("{c}", .{c});
    } else {
        try tty.setColor(writer, .yellow);
        try writer.print("\\x{x:0>2}", .{c});
    }
    try tty.setColor(writer, .reset);
}

var stdoutbuf: [4096]u8 = undefined;
const stdout_file = std.fs.File.stdout();
var stdout_writer = stdout_file.writer(&stdoutbuf);
const stdout = &stdout_writer.interface;

pub fn dumpCode(T: type) !void {
    const G = comptime Grammar(T);
    const ops = comptime G.compile(false);
    const tty = std.Io.tty.detectConfig(stdout_file);

    comptime var i = 0;
    inline for (ops) |op| {
        if (G.isStartOfRule(i)) |rule| {
            try tty.setColor(stdout, .bold);
            try stdout.print("\n&{t}:\n", .{rule});
            try tty.setColor(stdout, .reset);
        }

        try stdout.print("{d: >4} ", .{i});
        try op.dump(tty, stdout, i);
        i += 1;
    }

    try stdout.flush();
}

pub fn main() !void {
    const G = demoGrammar;
    const VM = @import("vm.zig").VM;

    try dumpCode(G);

    const tty = std.Io.tty.detectConfig(stdout_file);

    const P = Grammar(G);
    const ops = comptime P.compile(false);

    const TestVM = VM(ops);

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    var vm = try TestVM.initAlloc("[[1] [2]]", allocator, 16, 16);

    try stdout.print("\n\nparsing \"{s}\"\n\n", .{vm.text});

    var sp: ?u32 = null;
    var ip: u32 = 0;
    var lastrule: ?P.RuleEnum = null;
    var justcalled = true;

    // Manually iterate through events
    while (true) {
        try tty.setColor(stdout, .reset);

        const rule = P.ruleContainingIp(ip);
        if (rule != lastrule) {
            if (justcalled) {
                try tty.setColor(stdout, .bright_blue);
                try tty.setColor(stdout, .bold);
                try stdout.print("{?t: >8} ", .{rule});
            } else {
                try tty.setColor(stdout, .dim);
                try stdout.print("{?t: >8} ", .{rule});
            }
        } else {
            try tty.setColor(stdout, .dim);
            try stdout.splatByteAll(' ', 9);
        }
        lastrule = rule;
        try tty.setColor(stdout, .reset);

        try tty.setColor(stdout, .cyan);
        try stdout.print("{d:0>4} ", .{ip});
        try tty.setColor(stdout, .reset);

        if (vm.sp != sp) {
            try tty.setColor(stdout, .bold);
            sp = vm.sp;
            if (vm.sp < vm.text.len) {
                try printChar(tty, stdout, vm.text[vm.sp]);
            } else {
                try tty.setColor(stdout, .bright_green);
                try stdout.print("⌀", .{});
            }
        } else {
            try stdout.writeAll(" ");
        }
        try tty.setColor(stdout, .reset);
        try stdout.writeAll(" ");

        try tty.setColor(stdout, .dim);
        try stdout.splatBytesAll("│", vm.calls.items.len + 1);
        try stdout.writeAll(" ");
        try tty.setColor(stdout, .reset);

        try ops[ip].dump(tty, stdout, ip);
        if (vm.next(ip, .Step)) |outcome| {
            if (outcome) |ipnext| {
                if (ops[ip] == .call) {
                    justcalled = true;
                } else {
                    justcalled = false;
                }

                ip = ipnext;
            } else {
                try tty.setColor(stdout, .bright_green);
                try stdout.print("✓\n", .{});
                try tty.setColor(stdout, .reset);
                break;
            }
        } else |e| {
            try tty.setColor(stdout, .red);
            try stdout.print("✕ {t}\n", .{e});
            break;
        }
    }

    try tty.setColor(stdout, .reset);
    try stdout.flush();
}
