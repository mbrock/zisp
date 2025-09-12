const std = @import("std");
const zisp = @import("zisp");

pub fn main() !void {
    // Example: Parse JSON from command line argument
    const allocator = std.heap.page_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    
    if (args.len < 2) {
        std.debug.print("Usage: {s} [--debug] <json-string>\n", .{args[0]});
        std.debug.print("Example: {s} '{{\"key\": \"value\"}}'\n", .{args[0]});
        std.debug.print("Debug mode: {s} --debug '[1, 2, 3]'\n", .{args[0]});
        return;
    }
    
    // Check for debug flag
    var debug_mode = false;
    var input_arg_index: usize = 1;
    
    if (std.mem.eql(u8, args[1], "--debug")) {
        debug_mode = true;
        input_arg_index = 2;
        
        if (args.len < 3) {
            std.debug.print("Error: Missing JSON string after --debug flag\n", .{});
            return;
        }
    }
    
    // Create null-terminated string for parser
    const input = try allocator.dupeZ(u8, args[input_arg_index]);
    defer allocator.free(input);
    
    const Parser = zisp.parse.VM(zisp.parse.JSONGrammar, 1024, 256);
    
    if (debug_mode) {
        // Use debug printer for detailed trace
        const stdout_file = std.fs.File.stdout();
        var buffer: [4096]u8 = undefined;
        var stdout = stdout_file.writer(&buffer);
        const result = try zisp.debug.debugParse(Parser, input, &stdout.interface);
        try stdout.interface.flush();
        
        if (result) {
            std.debug.print("\n✓ Valid JSON\n", .{});
        } else {
            std.debug.print("\n✗ Invalid JSON\n", .{});
            std.process.exit(1);
        }
    } else {
        // Normal mode - just validate
        var machine = Parser.init(input);
        defer machine.deinit();
        
        const result = try Parser.parseFully(input, .auto_continue);
        
        if (result) {
            std.debug.print("✓ Valid JSON\n", .{});
        } else {
            std.debug.print("✗ Invalid JSON\n", .{});
            std.process.exit(1);
        }
    }
}
