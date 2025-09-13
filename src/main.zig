const std = @import("std");
const zisp = @import("zisp");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const source = if (args.len > 1) blk: {
        const file = try std.fs.cwd().openFile(args[1], .{});
        defer file.close();
        const contents = try file.readToEndAlloc(allocator, 1024 * 1024);
        break :blk try allocator.dupeZ(u8, contents);
    } else "var x: i32 = 42;\n";

    var vm = zisp.zigmini.ZigMiniParser.init(allocator, source);
    defer vm.deinit();

    const root = try vm.parse();
    std.debug.print("Parse succeeded! Root node: {s}\n", .{@tagName(root.tag)});

    if (vm.nodes.items.len > 0) {
        std.debug.print("\nAST:\n", .{});
        printNode(&vm, 0, 0);
    }
}

fn printNode(vm: anytype, idx: u32, depth: usize) void {
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
