const std = @import("std");

fn flip() bool {
    return std.crypto.random.boolean();
}

pub fn bug(comptime mode: enum { yay, ugh }) !void {
    var i: bool = flip();
    vm: switch (i) {
        inline false => {
            std.debug.print("Hello, world!\n", .{});
            i = flip();
            if (mode == .ugh)
                continue :vm (i == true)
            else
                return;
        },
        inline true => {
            std.debug.print("Goodbye, world!\n", .{});
            return;
        },
    }
}

pub fn main() !void {
    try bug(.yay);
    try bug(.ugh);
}
