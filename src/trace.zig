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

pub fn dumpAst(
    machine: anytype,
    writer: *std.Io.Writer,
    tty: std.Io.tty.Config,
    gpa: std.mem.Allocator,
) !void {
    const VMType = @TypeOf(machine.*);
    if (machine.root_node) |root| {
        var prefix = std.BitStack.init(gpa);
        var printer = TracePrinter.init(writer, tty, default_trace_theme);
        try printAstNode(VMType, machine, &printer, root, true, &prefix);
    } else {
        try writer.writeAll("<no ast>\n");
    }
}

fn printAstNode(
    comptime VMType: type,
    machine: *const VMType,
    printer: *TracePrinter,
    index: u32,
    is_last: bool,
    prefix: *std.BitStack,
) !void {
    const node = machine.nodes.items[index];
    const depth = prefix.bit_len;
    const writer = printer.writer;

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
    try printer.print(.rule_name, "{s}", .{@tagName(rule)});
    try writer.writeAll(" [");
    try printer.print(.absolute_ip, "{d}", .{node.start});
    try printer.print(.range_ellipsis, "..", .{});
    try printer.print(.absolute_ip, "{d}", .{node.end});
    try writer.writeAll(") ");
    try writer.writeAll("\"");
    for (span) |ch| {
        try printChar(printer, ch);
    }
    try writer.writeAll("\"\n");

    if (node.first_child) |first| {
        try prefix.push(@intFromBool(!is_last));
        var current = first;
        while (true) {
            const next = machine.nodes.items[current].next_sibling;
            try printAstNode(VMType, machine, printer, current, next == null, prefix);
            if (next) |n| {
                current = n;
            } else break;
        }
        _ = prefix.pop();
    }
}

fn writeIndent(writer: *std.Io.Writer, depth: usize) !void {
    var i: usize = 0;
    while (i < depth) : (i += 1) {
        try writer.writeAll("  ");
    }
}

fn dumpForestValue(
    comptime VMType: type,
    forest: *const VMType.Grammar.Forest,
    printer: *TracePrinter,
    text: []const u8,
    depth: usize,
    value: anytype,
) anyerror!void {
    const Grammar = VMType.Grammar;
    const writer = printer.writer;
    const T = @TypeOf(value);

    if (T == void) {
        try writer.writeAll("\n");
        return;
    }

    // Check if it's a Call type (has TargetName and index field)
    const is_call_type = comptime switch (@typeInfo(T)) {
        .@"struct" => @hasDecl(T, "TargetName") and @hasDecl(T, "index"),
        else => false,
    };

    if (is_call_type) {
        try writer.writeAll(" ->\n");
        // Get the rule tag from the TargetName
        const rule_tag = comptime blk: {
            const name = T.TargetName;
            for (std.meta.tags(Grammar.RuleEnum)) |tag| {
                if (std.mem.eql(u8, @tagName(tag), name)) {
                    break :blk tag;
                }
            }
            @compileError("Unknown rule: " ++ T.TargetName);
        };
        try dumpForestNode(VMType, forest, printer, text, depth + 1, rule_tag, value.index);
        return;
    }

    // Check if it's a Kleene type (has RuleTag, offset, len)
    const is_kleene_type = comptime switch (@typeInfo(T)) {
        .@"struct" => @hasDecl(T, "RuleTag") and @hasDecl(T, "offset") and @hasDecl(T, "len"),
        else => false,
    };

    if (is_kleene_type) {
        try writer.print(" (len {d})\n", .{value.len});
        var i: usize = 0;
        while (i < value.len) : (i += 1) {
            try writeIndent(writer, depth + 1);
            try writer.print("[{d}]\n", .{i});
            // Dump each element in the Kleene repetition
            const rule_tag = T.RuleTag;
            const element_index = value.offset + i;
            try dumpForestNode(VMType, forest, printer, text, depth + 2, rule_tag, element_index);
        }
        return;
    }

    if (T == u8) {
        if (value >= 32 and value < 127) {
            try writer.print(" = '{c}'\n", .{value});
        } else {
            try writer.print(" = 0x{x}\n", .{value});
        }
        return;
    }

    if (T == Grammar.TextRange) {
        const start = value.start;
        const end = @min(start + value.len, text.len);
        try writer.writeAll(" = \"");
        var i: usize = start;
        while (i < end) : (i += 1) {
            try printChar(printer, text[i]);
        }
        try writer.print("\" [{d}..{d})\n", .{ start, end });
        return;
    }

    switch (@typeInfo(T)) {
        .optional => {
            if (value) |payload| {
                try writer.writeAll("\n");
                try writeIndent(writer, depth + 1);
                try writer.writeAll("? ");
                try dumpForestValue(VMType, forest, printer, text, depth + 1, payload);
            } else {
                try writer.writeAll(" (none)\n");
            }
            return;
        },
        .@"union" => |info| {
            const Tag = info.tag_type.?;
            const tag = std.meta.activeTag(value);
            try writer.print(" .{s}", .{@tagName(tag)});
            inline for (info.fields) |field| {
                if (tag == @field(Tag, field.name)) {
                    const payload = @field(value, field.name);
                    try dumpForestValue(VMType, forest, printer, text, depth, payload);
                    return;
                }
            }
            try writer.writeAll("\n");
            return;
        },
        .@"struct" => |info| {
            if (info.is_tuple) {
                try writer.writeAll("\n");
                inline for (info.fields) |field| {
                    if (comptime field.type == void) continue;
                    try writeIndent(writer, depth + 1);
                    try writer.print(".{s} = ", .{field.name});
                    const elem = @field(value, field.name);
                    try dumpForestValue(VMType, forest, printer, text, depth + 1, elem);
                }
                return;
            }

            if (info.fields.len == 0) {
                try writer.writeAll(" {}");
                try writer.writeAll("\n");
                return;
            }

            try writer.writeAll("\n");
            inline for (info.fields) |field| {
                if (comptime field.type == void) continue;
                try writeIndent(writer, depth + 1);
                try writer.print("{s}: ", .{field.name});
                const field_value = @field(value, field.name);
                try dumpForestValue(VMType, forest, printer, text, depth + 1, field_value);
            }
            return;
        },
        .int, .comptime_int => {
            try writer.print(" = {d}\n", .{value});
            return;
        },
        .bool => {
            try writer.print(" = {}\n", .{value});
            return;
        },
        .float => {
            try writer.print(" = {d}\n", .{value});
            return;
        },
        .pointer => |ptr| {
            if (ptr.size == .slice and ptr.child == u8) {
                try writer.print(" = \"{s}\"\n", .{value});
                return;
            }
        },
        else => {},
    }

    try writer.print(" = {?}\n", .{value});
}

fn dumpForestNode(
    comptime VMType: type,
    forest: *const VMType.Grammar.Forest,
    printer: *TracePrinter,
    text: []const u8,
    depth: usize,
    comptime rule: VMType.RuleEnum,
    index: u32,
) anyerror!void {
    const Grammar = VMType.Grammar;
    const writer = printer.writer;
    try writeIndent(writer, depth);
    try printer.print(.rule_name, "{s}", .{@tagName(rule)});

    const ValueType = Grammar.RuleValueType(rule);
    if (comptime ValueType == void) {
        try writer.writeAll("\n");
        return;
    }

    const value_ptr = Grammar.getNode(forest, rule, index);
    const value = value_ptr.*;
    try dumpForestValue(VMType, forest, printer, text, depth, value);
}

pub fn dumpForest(
    machine: anytype,
    writer: *std.Io.Writer,
    tty: std.Io.tty.Config,
    allocator: std.mem.Allocator,
    comptime root_rule: @TypeOf(machine.*).RuleEnum,
) !void {
    const VMType = @TypeOf(machine.*);
    const Grammar = VMType.Grammar;

    var built = try machine.buildForest(allocator, root_rule);
    defer Grammar.deinitForest(&built.forest, allocator);

    try writer.writeAll("\nTyped Forest:\n");
    var printer = TracePrinter.init(writer, tty, default_trace_theme);
    const text = machine.text[0..machine.text.len];
    try dumpForestNode(VMType, &built.forest, &printer, text, 0, root_rule, built.root_index);
    try writer.writeAll("\n");
}
