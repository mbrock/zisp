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
    levels: std.bit_set.IntegerBitSet(N) = std.bit_set.IntegerBitSet(N).initEmpty(),
    len: std.math.IntFittingRange(0, N) = 0,

    const N = 32;
    const Writer = std.Io.Writer;

    pub const empty = @This(){};

    const pattern_a: [4]u8 = [4]u8{ 0xe2, 0x80, 0x80, 0x20 }; // "\xe2\x80\x80 "
    const pattern_b: [4]u8 = [4]u8{ 0xe2, 0x94, 0x82, 0x20 }; // "│ "

    pub fn writeUtf8Prefix(
        w: *Writer,
        bits: std.bit_set.IntegerBitSet(N),
        len: std.math.IntFittingRange(0, N),
    ) !void {
        const n = @as(usize, @intCast(len)) * 4;
        const buffer = try w.writableSlice(n);
        for (0..len) |i| {
            const pattern = if (bits.isSet(i)) &pattern_b else &pattern_a;
            @memcpy(buffer[i * 4 ..][0..4], pattern);
        }
    }

    pub fn show(self: @This(), writer: *Writer, more: bool) !void {
        try writeUtf8Prefix(writer, self.levels, self.len);
        if (self.len > 0) {
            try writer.writeAll(if (!more) "└─" else "├─");
        }
    }

    pub fn push(self: *@This(), more: bool) !void {
        if (self.len + 1 >= N) return error.OutOfMemory;
        self.levels.setValue(self.len, more);
        self.len += 1;
    }

    pub fn pop(self: *@This()) void {
        self.len -= 1;
    }

    test "hehe" {
        var buffer: [1024]u8 = undefined;
        var w = std.Io.Writer.fixed(&buffer);
        var bits = std.bit_set.IntegerBitSet(N).initEmpty();
        bits.set(0);
        bits.set(3);

        try writeUtf8Prefix(&w, bits, 4);
        try std.testing.expectEqualStrings("│ \xe2\x80\x80 \xe2\x80\x80 │ ", w.buffered());
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

        try std.testing.expectEqualStrings("│ \xe2\x80\x80 \xe2\x80\x80 │ ├─", w.buffered());
    }
};
