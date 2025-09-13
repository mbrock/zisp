const std = @import("std");
const zisp = @import("zisp");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source = "var x: i32 = 42;\n";
    const Parser = zisp.parse.VM(zisp.zigmini.ZigMiniGrammar, 1024, 256);
    var vm = Parser.init(allocator, source);
    defer vm.deinit();

    _ = try vm.parse();
    printNode(&vm, 0, 0);
}

fn printNode(vm: *Parser, idx: u32, depth: usize) void {
    const node = vm.nodes.items[idx];
    for (0..depth) |_| std.debug.print("  ", .{});
    std.debug.print("{s}", .{@tagName(node.tag)});
    switch (node.tag) {
        .Identifier, .Integer =>
            std.debug.print(" {s}", .{vm.text[node.start..node.end]}),
        else => {},
    }
    std.debug.print("\n", .{});
    var it = node.children(vm.nodes.items);
    while (it.next()) |child_idx| printNode(vm, child_idx, depth + 1);
}
