const std = @import("std");
const peg = @import("peg.zig");
const vm = @import("vm.zig");

const ctrls = [_][]const u8{
    "␀", "␁", "␂", "␃", "␄", "␅", "␆", "␇",
    "␈", "␉", "␤", "␋", "␌", "␍", "␎", "␏",
    "␐", "␑", "␒", "␓", "␔", "␕", "␖", "␗",
    "␘", "␙", "␚", "␛", "␜", "␝", "␞", "␟",
    "␠",
};

fn colorPrint(
    writer: *std.Io.Writer,
    tty: std.Io.tty.Config,
    color: anytype,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    try tty.setColor(writer, color);
    defer tty.setColor(writer, .reset) catch {};
    try writer.print(fmt, args);
}

pub fn printChar(tty: std.Io.tty.Config, writer: *std.Io.Writer, c: u8) !void {
    if (c < ctrls.len) {
        try colorPrint(writer, tty, .magenta, "{s}", .{ctrls[c]});
    } else if (c >= 33 and c < 127 and c != '\\') {
        try colorPrint(writer, tty, .yellow, "{c}", .{c});
    } else {
        try colorPrint(writer, tty, .yellow, "\\x{x:0>2}", .{c});
    }
}

pub fn dumpOp(
    comptime rel: bool,
    op: peg.OpG(rel),
    tty: std.Io.tty.Config,
    w: *std.Io.Writer,
    _: u32,
) !void {
    try w.print("{s} ", .{switch (op) {
        .frob => |x| @tagName(x.fx),
        inline else => @tagName(op),
    }});

    switch (op) {
        .frob => |ctrl| {
            if (rel == false) {
                try colorPrint(w, tty, .cyan, "→{d}", .{ctrl.ip});
            } else {
                if (ctrl.ip > 0) {
                    try colorPrint(w, tty, .cyan, "+{d}", .{ctrl.ip});
                } else {
                    try colorPrint(w, tty, .cyan, "{d}", .{ctrl.ip});
                }
            }
        },
        .call => |target| {
            if (@TypeOf(target) == u32) {
                try colorPrint(w, tty, .cyan, "→{d}", .{target});
            } else {
                try colorPrint(w, tty, .blue, "&{s}", .{@tagName(target)});
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
                        try colorPrint(w, tty, .dim, "{s}", .{"⋯"});
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

pub fn dumpCode(comptime T: type, writer: *std.Io.Writer, tty: std.Io.tty.Config) !void {
    const G = comptime peg.Grammar(T);
    const ops = comptime G.compile(false);

    comptime var i = 0;
    inline for (ops) |op| {
        if (G.isStartOfRule(i)) |rule| {
            try colorPrint(writer, tty, .bold, "\n&{t}:\n", .{rule});
        }

        try writer.print("{d: >4} ", .{i});
        try dumpOp(false, op, tty, writer, i);
        i += 1;
    }

    try writer.flush();
}

fn traceStep(
    machine: anytype,
    ip: u32,
    last_sp: *?u32,
    writer: *std.Io.Writer,
    tty: std.Io.tty.Config,
    cache_hit: bool,
) !void {
    const Program = @TypeOf(machine.*).Ops;

    // Show current position in text
    if (machine.sp != last_sp.*) {
        try tty.setColor(writer, .bold);
        if (machine.sp < machine.text.len) {
            try printChar(tty, writer, machine.text[machine.sp]);
        } else {
            try colorPrint(writer, tty, .bright_green, "⌀", .{});
        }
        last_sp.* = machine.sp;
    } else {
        try writer.writeAll(" ");
    }
    try tty.setColor(writer, .reset);
    try writer.writeAll(" ");

    // Show call stack depth
    try tty.setColor(writer, .dim);
    try writer.splatBytesAll("│", machine.calls.items.len + 1);
    try writer.writeAll(" ");
    try tty.setColor(writer, .reset);

    // Show instruction
    try colorPrint(writer, tty, .cyan, "{d:0>4} ", .{ip});

    if (ip < Program.len) {
        if (cache_hit) {
            try colorPrint(writer, tty, .green, "{s}", .{"⚡ "});
        }
        try dumpOp(false, Program[ip], tty, writer, ip);
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

        try traceStep(machine, ip, &last_sp, writer, tty, is_cache_hit);

        // Execute step
        if (machine.next(ip, .Step)) |outcome| {
            if (outcome) |next_ip| {
                ip = next_ip;
            } else {
                if (has_memo) {
                    try colorPrint(writer, tty, .bright_green, "\n✓ ({d} steps, {d} hits)\n", .{ step_count + 1, cache_hits });
                } else {
                    try colorPrint(writer, tty, .bright_green, "\n✓ ({d} steps)\n", .{step_count + 1});
                }
                break;
            }
        } else |err| {
            try colorPrint(writer, tty, .red, "\n✕ {t} at step {d}\n", .{ err, step_count + 1 });
            return err;
        }
    }
}
