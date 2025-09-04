comptime {
    _ = @import("parse.zig");
}

pub const parse = @import("parse.zig");
pub const grammar = @import("grammar.zig");
pub const benchmark = @import("benchmark.zig");

pub fn bufferedPrint() !void {
    std.debug.print("Zisp parser library loaded!\n", .{});
}

const std = @import("std");
