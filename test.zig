const std = @import("std");

pub fn main() !void {
    var x: i32 = 42;
    const y = 100;
    var sum = x + y;

    std.debug.print("Hello, world!\n", .{});
    std.debug.print("Sum is: {}\n", .{sum});
}