const std = @import("std");

pub const SGR = struct {
    attribute: ?Attr = null,
    fgcolor: ?Color = null,
    bgcolor: ?Color = null,

    pub const Attr = enum(u8) {
        reset = 0,
        bold = 1,
        dim = 2,
        italic = 3,
        underline = 4,
        blink = 5,
        reverse = 7,
    };

    pub const Color = enum(u8) {
        black = 30,
        red = 31,
        green = 32,
        yellow = 33,
        blue = 34,
        magenta = 35,
        cyan = 36,
        white = 37,
        _,

        pub fn bright(self: Color) Color {
            return @enumFromInt(@intFromEnum(self) + 60);
        }

        pub fn background(self: Color) Color {
            return @enumFromInt(@intFromEnum(self) + 10);
        }
    };

    pub fn fg(color: Color) SGR {
        return .{ .fgcolor = color };
    }

    pub fn bright(sgr: SGR) SGR {
        var next = sgr;
        if (next.fgcolor) |color|
            next.fgcolor = color.bright();
        return next;
    }

    pub fn on(sgr: SGR, color: Color) SGR {
        var next = sgr;
        next.bgcolor = color;
        return next;
    }

    pub fn attr(attribute: Attr) SGR {
        return .{ .attribute = attribute };
    }

    pub fn reset() SGR {
        return attr(.reset);
    }

    pub fn bold(sgr: SGR) SGR {
        var next = sgr;
        next.attribute = .bold;
        return next;
    }

    pub fn dim(sgr: SGR) SGR {
        var next = sgr;
        next.attribute = .dim;
        return next;
    }

    pub fn write(self: SGR, writer: *std.Io.Writer) !void {
        var first = true;
        try writer.writeAll("\x1b[");
        if (self.attribute) |attribute_value| {
            try writer.print("{d}", .{attribute_value});
            first = false;
        }
        if (self.fgcolor) |x| {
            if (!first) try writer.writeAll(";");
            try writer.print("{d}", .{x});
            first = false;
        }
        if (self.bgcolor) |x| {
            if (!first) try writer.writeAll(";");
            try writer.print("{d}", .{x.background()});
        }
        try writer.writeAll("m");
    }
};

pub fn ColorPrinter(comptime StyleEnum: type) type {
    return struct {
        const Self = @This();
        pub const Theme = std.EnumMap(StyleEnum, SGR);

        writer: *std.Io.Writer,
        tty: std.Io.tty.Config,
        theme: Theme,

        pub fn init(writer: *std.Io.Writer, tty: std.Io.tty.Config, theme: Theme) Self {
            return .{ .writer = writer, .tty = tty, .theme = theme };
        }

        pub fn print(
            self: *Self,
            style: StyleEnum,
            comptime fmt: []const u8,
            args: anytype,
        ) !void {
            try self.setStyle(style);
            defer self.reset() catch {};
            try self.writer.print(fmt, args);
        }

        pub fn setStyle(self: *Self, style: StyleEnum) !void {
            if (self.tty == .escape_codes) {
                if (self.theme.get(style)) |sgr| {
                    try sgr.write(self.writer);
                }
            }
        }

        pub fn reset(self: *Self) !void {
            if (self.tty == .escape_codes) {
                try SGR.reset().write(self.writer);
            }
        }
    };
}

pub const TreePrinter = struct {
    treesplat: BlazingFastTreeSplat = .empty,
    writer: *std.Io.Writer,

    pub fn init(writer: *std.Io.Writer) TreePrinter {
        return .{
            .writer = writer,
        };
    }

    pub fn printPrefix(self: *TreePrinter, is_last: bool) !void {
        try self.treesplat.show(self.writer, !is_last);
    }

    pub fn push(self: *TreePrinter, has_more: bool) !void {
        try self.treesplat.push(has_more);
    }

    pub fn pop(self: *TreePrinter) void {
        self.treesplat.pop();
    }
};

const BlazingFastTreeSplat = struct {
    levels: Bits = if (use_bool_vector) @splat(false) else @splat(0),
    len: std.math.IntFittingRange(0, N) = 0,

    const N = 32;
    const builtin = @import("builtin");

    // Use packed bool vector on AVX-512 (optimal with mask registers),
    // but use u8 vector on other platforms to avoid scalar bit extraction
    const use_bool_vector = builtin.cpu.arch == .x86_64 and
        std.Target.x86.featureSetHas(builtin.cpu.features, .avx512f);

    const BitsType = if (use_bool_vector) bool else u8;
    const Bits = @Vector(N, BitsType);

    const Writer = std.Io.Writer;

    pub const empty = @This(){};

    const av: @Vector(4, u8) = "  "[0..4].*;
    const bv: @Vector(4, u8) = "│ "[0..4].*;
    const au: u32 = @bitCast(av);
    const bu: u32 = @bitCast(bv);
    const aa: @Vector(N, u32) = @splat(au);
    const bb: @Vector(N, u32) = @splat(bu);

    pub fn writeUtf8Prefix(
        w: *Writer,
        bits: Bits,
        len: std.math.IntFittingRange(0, N),
    ) !void {
        const mask: @Vector(N, bool) = if (use_bool_vector)
            bits
        else
            bits != @as(@Vector(N, u8), @splat(0));
        const sv = @select(u32, mask, bb, aa);
        const bytes: [4 * N]u8 = @bitCast(sv);
        const byte_len: usize = @as(usize, len) * 4;
        try w.writeAll(bytes[0..byte_len]);
    }

    pub fn show(self: @This(), writer: *Writer, more: bool) !void {
        try writeUtf8Prefix(writer, self.levels, self.len);
        if (self.len > 0) {
            try writer.writeAll(if (!more) "└─" else "├─");
        }
    }

    pub fn push(self: *@This(), more: bool) !void {
        if (self.len + 1 >= N) return error.OutOfMemory; // lol
        self.levels[self.len] = if (use_bool_vector) more else @intFromBool(more);
        self.len += 1;
    }

    pub fn pop(self: *@This()) void {
        self.len -= 1;
    }

    test "hehe" {
        var buffer: [1024]u8 = undefined;
        var w = std.Io.Writer.fixed(&buffer);
        var bits: Bits = if (use_bool_vector) @splat(false) else @splat(0);
        bits[0] = if (use_bool_vector) true else 1;
        bits[3] = if (use_bool_vector) true else 1;

        try writeUtf8Prefix(&w, bits, 4);
        try std.testing.expectEqualStrings("│     │ ", w.buffered());
    }

    test "hehe 2" {
        var buffer: [1024]u8 = undefined;
        var w = std.Io.Writer.fixed(&buffer);

        var tree = @This().empty;
        try tree.push(true);
        try tree.push(false);
        try tree.push(false);
        try tree.push(true);
        try tree.show(&w, true);

        try std.testing.expectEqualStrings("│     │ ├─", w.buffered());
    }
};
