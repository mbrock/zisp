const std = @import("std");
const peg = @import("peg.zig");
const ansi = @import("ansitty.zig");

const SGR = ansi.SGR;
const ColorPrinter = ansi.ColorPrinter;
const TreePrinter = ansi.TreePrinter;

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
    variant_name,
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
    quantifier,
};

const TracePrinter = ColorPrinter(TraceStyle);

const default_trace_theme = TracePrinter.Theme.init(.{
    .control_char = SGR.fg(.magenta),
    .literal_char = SGR.fg(.yellow),
    .escape_char = SGR.fg(.yellow),
    .rule_name = SGR.fg(.green).bold(),
    .variant_name = SGR.fg(.green).bright(),
    .absolute_ip = SGR.fg(.cyan),
    .relative_ip = SGR.fg(.cyan),
    .call_ip = SGR.fg(.cyan),
    .call_name = SGR.fg(.blue),
    .range_ellipsis = SGR.attr(.dim),
    .cursor = SGR.attr(.bold),
    .end_marker = SGR.fg(.green).bright(),
    .stack_depth = SGR.attr(.dim),
    .opcode_ip = SGR.fg(.cyan),
    .quantifier = SGR.fg(.magenta).bright(),
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
        .read => |read_op| {
            var i: u32 = 0;
            while (i < 256) : (i += 1) {
                if (read_op.set.isSet(i)) {
                    // Check for ranges - look ahead for consecutive characters
                    var range_end = i;
                    while (range_end + 1 < 256 and read_op.set.isSet(range_end + 1)) : (range_end += 1) {}

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
            // Add repetition indicator
            if (read_op.repeat == .kleene) {
                try printer.print(.quantifier, "*", .{});
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
    return traceFrom(machine, writer, tty, null);
}

pub fn traceFrom(
    machine: anytype,
    writer: *std.Io.Writer,
    tty: std.Io.tty.Config,
    comptime start_rule: ?@TypeOf(machine.*).Grammar.RuleEnum,
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

    var ip: u32 = if (start_rule) |rule| VMType.Grammar.ruleStartIp(rule) else 0;
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
        try writer.flush();

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
) !void {
    const VMType = @TypeOf(machine.*);
    if (machine.root_node) |root| {
        var printer = TracePrinter.init(writer, tty, default_trace_theme);
        var tree = TreePrinter.init(writer);
        try printAstNode(VMType, machine, &printer, root, true, &tree);
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
    tree: *TreePrinter,
) !void {
    const node = machine.nodes.items[index];
    const writer = printer.writer;

    try tree.printPrefix(is_last);

    var label_style: TraceStyle = .variant_name;
    var label_text: []const u8 = undefined;

    switch (node.kind) {
        .rule => {
            const rule: VMType.RuleEnum = @enumFromInt(node.rule_index);
            label_style = .rule_name;
            label_text = @tagName(rule);
        },
        else => {
            label_style = .variant_name;
            label_text = @tagName(node.kind);
        },
    }

    const span = machine.text[node.start..node.end];
    try printer.print(label_style, "{s}", .{label_text});
    try writer.writeAll(" [");
    try printer.print(.absolute_ip, "{d}", .{node.start});
    try printer.print(.range_ellipsis, "…", .{});
    try printer.print(.absolute_ip, "{d}", .{node.end});
    try writer.writeAll(") ");
    try writer.writeAll("\"");
    for (span) |ch| {
        try printChar(printer, ch);
    }
    try writer.writeAll("\"\n");

    if (node.first_child) |first| {
        try tree.push(!is_last);
        var current = first;
        while (true) {
            const next = machine.nodes.items[current].next_sibling;
            try printAstNode(VMType, machine, printer, current, next == null, tree);
            if (next) |n| {
                current = n;
            } else break;
        }
        tree.pop();
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
    tree: *TreePrinter,
    text: []const u8,
    value: anytype,
    is_last: bool,
) anyerror!void {
    const Grammar = VMType.Grammar;
    const writer = printer.writer;
    const T = @TypeOf(value);

    if (T == void) {
        // Void values are hidden fields, skip them
        return;
    }

    // Check if the type has a Kind declaration
    const has_kind = comptime @hasDecl(T, "Kind");
    if (has_kind) {
        const kind = T.Kind;
        switch (kind) {
            .@"struct" => {
                // Struct wrapper - directly show the inner value without the wrapper
                try dumpForestValue(VMType, forest, printer, tree, text, value.value, is_last);
                return;
            },
            .@"union" => {
                // Union wrapper - directly show the inner value without the wrapper
                try dumpForestValue(VMType, forest, printer, tree, text, value.value, is_last);
                return;
            },
            .call => {
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
                try dumpForestNode(VMType, forest, printer, tree, text, rule_tag, value.index, is_last);
                return;
            },
            .kleene => {
                try printer.print(.quantifier, "{d} items\n", .{value.len});
                if (value.len > 0) {
                    try tree.push(!is_last);
                    var i: usize = 0;
                    while (i < value.len) : (i += 1) {
                        try tree.printPrefix(i == value.len - 1);
                        try writer.writeAll("[");
                        try printer.print(.absolute_ip, "{d}", .{i});
                        try writer.writeAll("] ");
                        const rule_tag = T.RuleTag;
                        const element_index: u32 = @intCast(value.offset + i);
                        const is_last_item = i == value.len - 1;
                        try dumpForestNode(VMType, forest, printer, tree, text, rule_tag, element_index, is_last_item);
                    }
                    tree.pop();
                }
                return;
            },
            .char => {
                // Single character
                const offset = value.offset;
                try writer.writeAll("'");
                try printChar(printer, text[offset]);
                try writer.writeAll("' ");
                try printer.print(.range_ellipsis, "[{d}]", .{offset});
                try writer.writeAll("\n");
                return;
            },
            .char_slice => {
                // Character slice
                const offset = value.offset;
                const len = value.len;
                if (len > 0) {
                    try writer.writeAll("\"");
                    var i: usize = 0;
                    while (i < len) : (i += 1) {
                        if (offset + i < text.len) {
                            try printChar(printer, text[offset + i]);
                        }
                    }
                    try writer.print("\" ", .{});
                    try printer.print(.range_ellipsis, "[{d}…{d})", .{ offset, offset + len });
                } else {
                    try printer.print(.failure, "(empty)", .{});
                }
                try writer.writeAll("\n");
                return;
            },
            .hidden => {
                // Hidden values should not be displayed
                return;
            },
            .maybe => {
                if (value.value == null) {
                    try printer.print(.failure, "(null)\n", .{});
                } else {
                    try dumpForestValue(VMType, forest, printer, tree, text, value.value.?, is_last);
                }
                return;
            },
            else => {
                // Unknown kind, fall through to default handling
            },
        }
    }

    switch (@typeInfo(T)) {
        .optional => {
            if (value) |payload| {
                try writer.writeAll("(some)\n");
                try tree.push(!is_last);
                try tree.printPrefix(true);
                try dumpForestValue(VMType, forest, printer, tree, text, payload, true);
                tree.pop();
            } else {
                try printer.print(.failure, "(none)", .{});
                try writer.writeAll("\n");
            }
            return;
        },
        .@"union" => |info| {
            const Tag = info.tag_type.?;
            const tag = std.meta.activeTag(value);
            try printer.print(.variant_name, ".{s}", .{@tagName(tag)});
            inline for (info.fields) |field| {
                if (tag == @field(Tag, field.name)) {
                    const payload = @field(value, field.name);
                    if (@TypeOf(payload) != void) {
                        try writer.writeAll("\n");
                        try tree.push(!is_last);
                        try tree.printPrefix(true);
                        try dumpForestValue(VMType, forest, printer, tree, text, payload, true);
                        tree.pop();
                    } else {
                        try writer.writeAll("\n");
                    }
                    return;
                }
            }
            try writer.writeAll("\n");
            return;
        },
        .@"struct" => |info| {
            // Empty struct - just skip it entirely
            if (info.fields.len == 0) {
                return;
            }

            // Count non-void, non-empty fields
            const non_void_fields = comptime blk: {
                var count: usize = 0;
                for (info.fields) |field| {
                    if (field.type == void) continue;
                    const field_info = @typeInfo(field.type);
                    if (field_info == .@"struct" and field_info.@"struct".fields.len == 0) continue;
                    count += 1;
                }
                break :blk count;
            };

            if (non_void_fields == 0) {
                return;
            }

            try writer.writeAll("\n");
            try tree.push(!is_last);

            var field_idx: usize = 0;
            inline for (info.fields) |field| {
                if (comptime field.type == void) continue;

                // Skip empty struct fields
                const field_info = @typeInfo(field.type);
                if (field_info == .@"struct" and field_info.@"struct".fields.len == 0) continue;

                const is_last_field = (field_idx == non_void_fields - 1);
                try tree.printPrefix(is_last_field);
                try printer.print(.variant_name, "{s}", .{field.name});
                try writer.writeAll(": ");
                const field_value = @field(value, field.name);
                try dumpForestValue(VMType, forest, printer, tree, text, field_value, is_last_field);
                field_idx += 1;
            }

            tree.pop();
            return;
        },
        .int, .comptime_int => {
            try printer.print(.absolute_ip, "{d}", .{value});
            try writer.writeAll("\n");
            return;
        },
        .bool => {
            if (value) {
                try printer.print(.success, "true", .{});
            } else {
                try printer.print(.failure, "false", .{});
            }
            try writer.writeAll("\n");
            return;
        },
        .float => {
            try printer.print(.absolute_ip, "{d}", .{value});
            try writer.writeAll("\n");
            return;
        },
        .pointer => |ptr| {
            if (ptr.size == .slice and ptr.child == u8) {
                try writer.writeAll("\"");
                for (value) |ch| {
                    try printChar(printer, ch);
                }
                try writer.writeAll("\"\n");
                return;
            }
        },
        else => {},
    }

    // Fallback for unexpected types
    try writer.print("({s})\n", .{@typeName(T)});
}

fn dumpForestNode(
    comptime VMType: type,
    forest: *const VMType.Grammar.Forest,
    printer: *TracePrinter,
    tree: *TreePrinter,
    text: []const u8,
    comptime rule: VMType.RuleEnum,
    index: u32,
    is_last: bool,
) anyerror!void {
    const Grammar = VMType.Grammar;
    const writer = printer.writer;
    try printer.print(.rule_name, "{s}", .{@tagName(rule)});

    const ValueType = Grammar.RuleValueType(rule);
    if (comptime ValueType == void) {
        try writer.writeAll("\n");
        return;
    }

    const value_ptr = forest.get(rule, index);
    const value = value_ptr.*;
    try writer.writeAll(": ");
    try dumpForestValue(VMType, forest, printer, tree, text, value, is_last);
}

pub fn dumpForest(
    machine: anytype,
    writer: *std.Io.Writer,
    tty: std.Io.tty.Config,
    allocator: std.mem.Allocator,
    comptime root_rule: @TypeOf(machine.*).RuleEnum,
) !void {
    const VMType = @TypeOf(machine.*);

    var built = try machine.buildForest(allocator, root_rule);
    defer built.forest.deinit(allocator);

    try writer.writeAll("\nTyped Forest:\n");
    var printer = TracePrinter.init(writer, tty, default_trace_theme);
    var tree = TreePrinter.init(writer);
    const text = machine.text[0..machine.text.len];
    try dumpForestNode(VMType, &built.forest, &printer, &tree, text, root_rule, built.root_index, true);
    try writer.writeAll("\n");
}
