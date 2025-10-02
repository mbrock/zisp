const std = @import("std");
const zisp = @import("zisp");
const pegvm = zisp.vm;
const peg = zisp.peg;
const ziglang = zisp.ziglang;
const trace = zisp.trace;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len == 2) {
        var stdoutbuf: [4096]u8 = undefined;
        const stdout_file = std.fs.File.stdout();
        var stdout_writer = stdout_file.writer(&stdoutbuf);
        const stdout = &stdout_writer.interface;
        defer stdout.flush() catch {};

        const tty = std.Io.tty.detectConfig(stdout_file);

        var vm = try pegvm.VM(ziglang.ZigGrammar).initAlloc(args[1], allocator, 64, 64, 512);
        defer vm.deinit(allocator);

        try trace.traceFrom(&vm, stdout, tty, .Root);
        try trace.dumpAst(&vm, stdout, tty);
        try trace.dumpForest(&vm, stdout, tty, allocator, .FnDecl);
    }
}
