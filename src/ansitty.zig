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
    prefix: std.BitStack,
    writer: *std.Io.Writer,

    pub fn init(allocator: std.mem.Allocator, writer: *std.Io.Writer) !TreePrinter {
        return .{
            .prefix = std.BitStack.init(allocator),
            .writer = writer,
        };
    }

    pub fn deinit(self: *TreePrinter) void {
        self.prefix.deinit();
    }

    pub fn printPrefix(self: *TreePrinter, is_last: bool) !void {
        const depth = self.prefix.bit_len;
        const writer = self.writer;

        var level: usize = 0;
        while (level < depth) : (level += 1) {
            const has_more = 1 == std.BitStack.peekWithState(self.prefix.bytes.items, level + 1);
            try writer.writeAll(if (has_more) "│ " else "  ");
        }
        if (depth > 0) {
            try writer.writeAll(if (is_last) "└─" else "├─");
        }
    }

    pub fn push(self: *TreePrinter, has_more: bool) !void {
        try self.prefix.push(@intFromBool(has_more));
    }

    pub fn pop(self: *TreePrinter) void {
        _ = self.prefix.pop();
    }
};
