const std = @import("std");
const zisp = @import("zisp");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len > 1 and std.mem.eql(u8, args[1], "--fun")) {
        try zisp.pegvmfun.main();
        return;
    }

    // Check for --dump-pegcode flag
    if (args.len > 1 and std.mem.eql(u8, args[1], "--dump-pegcode")) {
        // Check for optional --outdir flag
        if (args.len > 3 and std.mem.eql(u8, args[2], "--outdir")) {
            try dumpPegCodeToFiles(allocator, args[3]);
        } else {
            try dumpPegCodeToStdout();
        }
        return;
    }

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

    std.debug.print("Creating VM on heap with stacks: marks={}, saves={}...\n", .{ mark_stack_size, save_stack_size });
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
    const root = vm.nodelist.items[0];
    std.debug.print("Parse succeeded! Root node: {s}\n", .{@tagName(root.tag)});

    if (vm.nodelist.items.len > 0) {
        std.debug.print("\nAST ({} nodes total):\n", .{vm.nodelist.items.len});
        for (0..vm.nodelist.items.len) |i| {
            const n = vm.nodelist.items[i];
            std.debug.print("Node {}: {s} (children: first={?}, next={?})\n", .{ i, @tagName(n.tag), n.first_child, n.next_sibling });
        }
        std.debug.print("\nTree:\n", .{});
        printNode(vm, 0, 0);
    }
}

fn printNode(vm: anytype, idx: u32, depth: usize) void {
    const node = vm.nodelist.items[idx];
    for (0..depth) |_| std.debug.print("  ", .{});
    std.debug.print("{s}", .{@tagName(node.tag)});
    switch (node.tag) {
        .Identifier, .Integer => std.debug.print(" {s}", .{vm.text[node.start..node.end]}),
        else => {},
    }
    std.debug.print("\n", .{});
    var it = node.children(vm.nodelist.items);
    while (it.next()) |child_idx| printNode(vm, child_idx, depth + 1);
}

fn dumpPegCodeToStdout() !void {
    const stdout_file = std.fs.File.stdout();
    var buffer: [4096]u8 = undefined;
    var stdout_writer = stdout_file.writer(&buffer);

    try dumpPegCode(&stdout_writer.interface);
    try stdout_writer.interface.flush();
}

fn dumpPegCodeToFiles(allocator: std.mem.Allocator, outdir: []const u8) !void {
    // Create output directory if it doesn't exist
    std.fs.cwd().makePath(outdir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const Parser = zisp.parse.VM(zisp.zigmini.ZigMiniGrammar);
    const P = Parser.P;

    // Create index file
    const index_path = try std.fmt.allocPrint(allocator, "{s}/index.txt", .{outdir});
    defer allocator.free(index_path);
    const index_file = try std.fs.cwd().createFile(index_path, .{});
    defer index_file.close();
    var index_buffer: [4096]u8 = undefined;
    var index_writer = index_file.writer(&index_buffer);

    try index_writer.interface.print("=== PEG VM Bytecode for ZigMiniGrammar ===\n\n", .{});
    try index_writer.interface.print("Total bytecode size: {} instructions\n", .{P.code.len});
    try index_writer.interface.print("Entry point: {}\n\n", .{P.start_ip});
    try index_writer.interface.print("Rules:\n", .{});

    // Helper to dump one rule
    const dumpRule = struct {
        fn dump(alloc: std.mem.Allocator, comptime rule: P.RuleT, dir: []const u8, idx_writer: anytype) !void {
            const rule_name = @tagName(rule);
            const rule_ip = P.rule_ip[@intFromEnum(rule)];

            // Find the end of this rule
            var end_ip: usize = P.code.len;
            const all_rules = comptime std.enums.values(P.RuleT);
            inline for (all_rules) |other_rule| {
                const other_ip = P.rule_ip[@intFromEnum(other_rule)];
                if (other_ip > rule_ip and other_ip < end_ip) {
                    end_ip = other_ip;
                }
            }

            // Write to index
            try idx_writer.interface.print("  {s:30} @ {:4} (size: {} ops)\n", .{ rule_name, rule_ip, end_ip - rule_ip });

            // Create file for this rule
            const filename = try std.fmt.allocPrint(alloc, "{s}/{s}.peg", .{ dir, rule_name });
            defer alloc.free(filename);
            const file = try std.fs.cwd().createFile(filename, .{});
            defer file.close();

            var buffer: [4096]u8 = undefined;
            var file_writer = file.writer(&buffer);

            // Dump instructions for this rule
            var ip = rule_ip;
            while (ip < end_ip) : (ip += 1) {
                try P.dumpInstruction(&file_writer.interface, @intCast(ip), P.code[ip]);
            }

            try file_writer.interface.flush();
        }
    }.dump;

    // Dump each rule to a separate file
    const rules = comptime std.enums.values(P.RuleT);
    inline for (rules) |rule| {
        try dumpRule(allocator, rule, outdir, &index_writer);
    }

    try index_writer.interface.flush();
    std.debug.print("Dumped {} rules to {s}/\n", .{ rules.len, outdir });
}

fn dumpPegCode(writer: *std.Io.Writer) !void {
    const Parser = zisp.parse.VM(zisp.zigmini.ZigMiniGrammar);
    const P = Parser.P;

    try writer.print("=== PEG VM Bytecode for ZigMiniGrammar ===\n\n", .{});
    try writer.print("Total bytecode size: {} instructions\n", .{P.code.len});
    try writer.print("Entry point: {}\n\n", .{P.start_ip});

    // Dump bytecode with rule sections
    var ip: u32 = 0;
    while (ip < P.code.len) : (ip += 1) {
        // Check if this IP starts a rule
        if (P.ip_to_rule[ip]) |rule_name| {
            try writer.print("\n&{s}:\n", .{rule_name});
        }

        try P.dumpInstruction(writer, ip, P.code[ip]);
    }

    try writer.print("\n=== End of bytecode ===\n", .{});
}
