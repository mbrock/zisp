const std = @import("std");
const peg = @import("peg.zig");
const ansi = @import("ansitty.zig");

const SGR = ansi.SGR;
const ColorPrinter = ansi.ColorPrinter;

const ctrls = [_][]const u8{
    "␀", "␁", "␂", "␃", "␄", "␅", "␆", "␇",
    "␈", "␉", "␤", "␋", "␌", "␍", "␎", "␏",
    "␐", "␑", "␒", "␓", "␔", "␕", "␖", "␗",
    "␘", "␙", "␚", "␛", "␜", "␝", "␞", "␟",
    "␠",
};

pub const TraceStyle = enum {
    control_char,
    literal_char,
    escape_char,
    rule_name,
    absolute_ip,
    relative_ip,
    call_ip,
    call_name,
    range_ellipsis,
    cursor,
    end_marker,
    stack_depth,
    opcode_ip,
    cache_hit,
    success,
    failure,
};

const TracePrinter = ColorPrinter(TraceStyle);

const default_trace_theme = TracePrinter.Theme.init(.{
    .control_char = SGR.fg(.magenta),
    .literal_char = SGR.fg(.yellow),
    .escape_char = SGR.fg(.yellow),
    .rule_name = SGR.attr(.bold),
    .absolute_ip = SGR.fg(.cyan),
    .relative_ip = SGR.fg(.cyan),
    .call_ip = SGR.fg(.cyan),
    .call_name = SGR.fg(.blue),
    .range_ellipsis = SGR.attr(.dim),
    .cursor = SGR.attr(.bold),
    .end_marker = SGR.fg(.green).bright(),
    .stack_depth = SGR.attr(.dim),
    .opcode_ip = SGR.fg(.cyan),
    .cache_hit = SGR.fg(.green),
    .success = SGR.fg(.green).bright(),
    .failure = SGR.fg(.red),
});

const MaxAstDepth: usize = 256;

pub fn printChar(printer: *TracePrinter, c: u8) !void {
    if (c < ctrls.len) {
        try printer.print(.control_char, "{s}", .{ctrls[c]});
    } else if (c >= 33 and c < 127 and c != '\\') {
        try printer.print(.literal_char, "{c}", .{c});
    } else {
        try printer.print(.escape_char, "\\x{x:0>2}", .{c});
    }
}

pub fn dumpOp(
    comptime rel: bool,
    op: peg.OpG(rel),
    printer: *TracePrinter,
    _: u32,
) !void {
    const writer = printer.writer;
    try writer.print("{s} ", .{switch (op) {
        .frob => |x| @tagName(x.fx),
        inline else => @tagName(op),
    }});

    switch (op) {
        .frob => |ctrl| {
            if (rel == false) {
                try printer.print(.absolute_ip, "→{d}", .{ctrl.ip});
            } else {
                if (ctrl.ip > 0) {
                    try printer.print(.relative_ip, "+{d}", .{ctrl.ip});
                } else {
                    try printer.print(.relative_ip, "{d}", .{ctrl.ip});
                }
            }
        },
        .call => |target| {
            if (@TypeOf(target) == u32) {
                try printer.print(.call_ip, "→{d}", .{target});
            } else {
                try printer.print(.call_name, "&{s}", .{@tagName(target)});
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
                        try printChar(printer, @intCast(i));
                        try printer.print(.range_ellipsis, "{s}", .{"⋯"});
                        // Print end of range
                        try printChar(printer, @intCast(range_end));
                        i = range_end;
                    } else if (range_end == i + 1) {
                        // Just two consecutive characters - print them separately
                        try printChar(printer, @intCast(i));
                        try printChar(printer, @intCast(range_end));
                        i = range_end;
                    } else {
                        // Single character
                        try printChar(printer, @intCast(i));
                    }
                }
            }
        },

        inline else => {},
    }

    try printer.reset();
    try writer.writeAll("\n");
}

pub fn dumpCode(comptime T: type, writer: *std.Io.Writer, tty: std.Io.tty.Config) !void {
    const G = comptime peg.Grammar(T);
    const ops = comptime G.compile(false);

    var printer = TracePrinter.init(writer, tty, default_trace_theme);

    comptime var i = 0;
    inline for (ops) |op| {
        if (G.isStartOfRule(i)) |rule| {
            try printer.print(.rule_name, "\n&{t}:\n", .{rule});
        }

        try writer.print("{d: >4} ", .{i});
        try dumpOp(false, op, &printer, i);
        i += 1;
    }

    try writer.flush();
}

fn traceStep(
    machine: anytype,
    ip: u32,
    last_sp: *?u32,
    printer: *TracePrinter,
    cache_hit: bool,
) !void {
    const Program = @TypeOf(machine.*).Ops;
    const writer = printer.writer;

    // Show current position in text
    if (machine.sp != last_sp.*) {
        try printer.setStyle(.cursor);
        if (machine.sp < machine.text.len) {
            try printChar(printer, machine.text[machine.sp]);
        } else {
            try printer.print(.end_marker, "⌀", .{});
        }
        last_sp.* = machine.sp;
    } else {
        try writer.writeAll(" ");
    }
    try printer.reset();
    try writer.writeAll(" ");

    // Show call stack depth
    try printer.setStyle(.stack_depth);
    try writer.splatBytesAll("│", machine.calls.items.len + 1);
    try writer.writeAll(" ");
    try printer.reset();

    // Show instruction
    try printer.print(.opcode_ip, "{d:0>4} ", .{ip});

    if (ip < Program.len) {
        if (cache_hit) {
            try printer.print(.cache_hit, "{s}", .{"⚡ "});
        }
        try dumpOp(false, Program[ip], printer, ip);
    }
}

pub fn trace(
    machine: anytype,
    writer: *std.Io.Writer,
    tty: std.Io.tty.Config,
) !void {
    const VMType = @TypeOf(machine.*);
    const Program = VMType.Ops;
    const has_memo = machine.memo != null;

    var printer = TracePrinter.init(writer, tty, default_trace_theme);

    if (has_memo) {
        try writer.print("\nParsing with memoization: \"{s}\"\n\n", .{machine.text});
    } else {
        try writer.print("\nParsing: \"{s}\"\n\n", .{machine.text});
    }

    var ip: u32 = 0;
    var last_sp: ?u32 = null;
    var step_count: u32 = 0;
    var cache_hits: u32 = 0;

    while (true) : (step_count += 1) {
        // Check for cache hit when memoization is enabled
        const is_cache_hit = if (has_memo and ip < Program.len and Program[ip] == .call) blk: {
            const key = VMType.MemoKey{ .ip = Program[ip].call, .sp = machine.sp };
            if (machine.memo.?.contains(key)) {
                cache_hits += 1;
                break :blk true;
            }
            break :blk false;
        } else false;

        try traceStep(machine, ip, &last_sp, &printer, is_cache_hit);

        // Execute step
        if (machine.next(ip, .Step)) |outcome| {
            if (outcome) |next_ip| {
                ip = next_ip;
            } else {
                if (has_memo) {
                    try printer.print(.success, "\n✓ ({d} steps, {d} hits)\n", .{ step_count + 1, cache_hits });
                } else {
                    try printer.print(.success, "\n✓ ({d} steps)\n", .{step_count + 1});
                }
                break;
            }
        } else |err| {
            try printer.print(.failure, "\n✕ {t} at step {d}\n", .{ err, step_count + 1 });
            return err;
        }
    }
}

pub fn dumpAst(machine: anytype, writer: *std.Io.Writer, gpa: std.mem.Allocator) !void {
    const VMType = @TypeOf(machine.*);
    if (machine.root_node) |root| {
        var prefix = std.BitStack.init(gpa);
        try printAstNode(VMType, machine, writer, root, true, &prefix);
    } else {
        try writer.writeAll("<no ast>\n");
    }
}

fn printAstNode(
    comptime VMType: type,
    machine: *const VMType,
    writer: *std.Io.Writer,
    index: u32,
    is_last: bool,
    prefix: *std.BitStack,
) !void {
    const node = machine.nodes.items[index];
    const depth = prefix.bit_len;

    var level: usize = 0;
    while (level < depth) : (level += 1) {
        const byte_index = level >> 3;
        const bit_index: u3 = @intCast(level & 7);
        const has_more = ((prefix.bytes.items[byte_index] >> bit_index) & 1) == 1;
        try writer.writeAll(if (has_more) "│ " else "  ");
    }
    if (depth > 0) {
        try writer.writeAll(if (is_last) "└─" else "├─");
    }

    const rule: VMType.RuleEnum = @enumFromInt(node.rule_index);
    const span = machine.text[node.start..node.end];
    try writer.print("{s} [{d}..{d}) \"{s}\"\n", .{
        @tagName(rule),
        node.start,
        node.end,
        span,
    });

    if (node.first_child) |first| {
        try prefix.push(@intFromBool(!is_last));
        var current = first;
        while (true) {
            const next = machine.nodes.items[current].next_sibling;
            try printAstNode(VMType, machine, writer, current, next == null, prefix);
            if (next) |n| {
                current = n;
            } else break;
        }
        _ = prefix.pop();
    }
}
