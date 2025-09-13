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

    // Create VM with runtime-allocated stacks
    const Parser = zisp.parse.VM(zisp.zigmini.ZigMiniGrammar);

    // Allocate stacks
    const mark_stack_size = 512;
    const save_stack_size = 256;
    const marks = try allocator.alloc(Parser.Mark, mark_stack_size);
    defer allocator.free(marks);
    const saves = try allocator.alloc(Parser.Save, save_stack_size);
    defer allocator.free(saves);

    std.debug.print("Creating VM on heap with stacks: marks={}, saves={}...\n", .{mark_stack_size, save_stack_size});
    var vm = try allocator.create(Parser);
    defer allocator.destroy(vm);
    std.debug.print("Initializing VM...\n", .{});
    vm.initPtr(allocator, source, marks, saves);
    defer vm.deinit();

    std.debug.print("Starting parse in yield mode...\n", .{});
    std.debug.print("VM size: {} bytes\n", .{@sizeOf(Parser)});
    std.debug.print("Initial codehead (P.start_ip): {}\n", .{vm.codehead});

    // Use yield mode to step through execution
    var step_count: u32 = 0;
    while (true) {
        // std.debug.print("Step {}: texthead={}, codehead={}, markhead={}, savehead={}\n",
        //     .{step_count, vm.texthead, vm.codehead, vm.markhead, vm.savehead});
        if (vm.markhead >= mark_stack_size) {
            std.debug.print("ERROR: markhead overflow! Max is {}\n", .{mark_stack_size});
            return error.StackOverflow;
        }
        const status = try vm.tick(.yield_each, null);
        step_count += 1;
        switch (status) {
            .Running => continue,
            .Ok => {
                std.debug.print("Parse succeeded after {} steps\n", .{step_count});
                break;
            },
            .Fail => {
                std.debug.print("Parse failed after {} steps\n", .{step_count});
                vm.formatError();
                return error.ParseFailed;
            },
        }
    }
    const root = vm.nodes.items[0];
    std.debug.print("Parse succeeded! Root node: {s}\n", .{@tagName(root.tag)});

    if (vm.nodes.items.len > 0) {
        std.debug.print("\nAST:\n", .{});
        printNode(vm, 0, 0);
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
