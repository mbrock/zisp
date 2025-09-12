const std = @import("std");
const pegvm = @import("pegvm.zig");

/// Simple debug printer that uses yield mode to trace parser execution
/// without modifying the parser code itself.
pub fn DebugPrinter(comptime Parser: type) type {
    return struct {
        const Self = @This();
        
        machine: Parser,
        writer: *std.io.Writer,
        step_count: usize = 0,
        indent: usize = 0,
        
        pub fn init(text: [:0]const u8, writer: *std.io.Writer) Self {
            return .{
                .machine = Parser.init(text),
                .writer = writer,
            };
        }
        
        pub fn deinit(self: *Self) void {
            self.machine.deinit();
        }
        
        /// Run the parser with debug output
        pub fn run(self: *Self) !Parser.Status {
            try self.writer.print("=== Parser Debug Trace ===\n", .{});
            try self.writer.print("Input: \"{s}\"\n", .{self.machine.text});
            try self.writer.print("---\n", .{});
            
            var status: Parser.Status = .Running;
            while (status == .Running) {
                // Get current state before tick
                const pos = self.machine.texthead;
                const code_pos = self.machine.codehead;
                
                // Execute one step
                status = try self.machine.tick(.yield_each, null);
                self.step_count += 1;
                
                // Print step info
                try self.printStep(pos, code_pos, status);
            }
            
            try self.writer.print("---\n", .{});
            try self.writer.print("Result: {s}\n", .{@tagName(status)});
            try self.writer.print("Steps: {d}\n", .{self.step_count});
            try self.writer.print("Final position: {d}/{d}\n", .{
                self.machine.texthead,
                self.machine.text.len,
            });
            
            return status;
        }
        
        fn printStep(self: *Self, old_pos: u32, old_code: u32, status: Parser.Status) !void {
            // Track indent based on mark stack depth
            const new_indent = self.machine.markhead;
            if (new_indent > self.indent) {
                self.indent = new_indent;
            } else if (new_indent < self.indent) {
                self.indent = new_indent;
            }
            
            // Print step number and indent
            try self.writer.print("[{d:4}] ", .{self.step_count});
            for (0..self.indent) |_| {
                try self.writer.print("  ", .{});
            }
            
            // Show operation at old code position
            if (old_code < Parser.P.code.len) {
                const op = Parser.P.code[old_code];
                try self.printOp(op);
            }
            
            // Show text progress
            if (old_pos != self.machine.texthead) {
                const consumed = self.machine.text[old_pos..self.machine.texthead];
                try self.writer.print(" → consumed: \"{s}\"", .{consumed});
            }
            
            // Show position
            try self.writer.print(" @ pos {d}", .{old_pos});
            
            // Show status changes
            if (status != .Running) {
                try self.writer.print(" [{s}]", .{@tagName(status)});
            }
            
            try self.writer.print("\n", .{});
        }
        
        fn printOp(self: *Self, op: Parser.P.OpT) !void {
            switch (op) {
                .ChoiceRel => |d| try self.writer.print("Choice(+{d})", .{d}),
                .CommitRel => |d| try self.writer.print("Commit(+{d})", .{d}),
                .Fail => try self.writer.print("Fail", .{}),
                .Call => |r| try self.writer.print("Call({s})", .{@tagName(r)}),
                .Ret => try self.writer.print("Return", .{}),
                .EndInput => try self.writer.print("EndInput", .{}),
                .Accept => try self.writer.print("Accept", .{}),
                .String => |s| try self.writer.print("String(\"{s}\")", .{s}),
                .CharSet => |_| try self.writer.print("CharSet", .{}),
            }
        }
    };
}

/// Convenience function to debug parse a string
pub fn debugParse(
    comptime Parser: type,
    text: [:0]const u8,
    writer: *std.io.Writer,
) !bool {
    var printer = DebugPrinter(Parser).init(text, writer);
    defer printer.deinit();
    const status = try printer.run();
    return status == .Ok;
}

// Example usage in tests
test "debug printer basic" {
    const JSONParser = pegvm.VM(pegvm.JSONGrammar, 1024, 256);
    
    const text = "true";
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    
    const result = try debugParse(JSONParser, text, stream.writer().any());
    try std.testing.expect(result);
    
    // Output is in buf, could assert on it if needed
}

test "debug printer complex" {
    const JSONParser = pegvm.VM(pegvm.JSONGrammar, 1024, 256);
    
    const text = "[1, 2]";
    var buf: [4096]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    
    const result = try debugParse(JSONParser, text, stream.writer().any());
    try std.testing.expect(result);
}