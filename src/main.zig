const std = @import("std");
const zisp = @import("zisp");
const pegvm = zisp.vm;
const peg = zisp.peg;
const ziglang = zisp.ziglang;
const trace = zisp.trace;

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    if (args.len == 2) {
        var stdoutbuf: [4096]u8 = undefined;
        const stdout_file = std.Io.File.stdout();
        var stdout_writer = stdout_file.writer(init.io, &stdoutbuf);
        const stdout = &stdout_writer.interface;
        defer stdout.flush() catch {};

        const no_color = if (init.environ_map.get("NO_COLOR")) |value| value.len > 0 else false;
        const force_color = if (init.environ_map.get("CLICOLOR_FORCE")) |value| value.len > 0 else false;
        const tty = try std.Io.Terminal.Mode.detect(init.io, stdout_file, no_color, force_color);

        var vm = try pegvm.VM(ziglang.ZigGrammar).initAlloc(args[1], allocator, 64, 64, 512);
        defer vm.deinit(allocator);

        try trace.traceFrom(&vm, stdout, tty, .Root);
        try trace.dumpAst(&vm, stdout, tty);
        try trace.dumpForest(&vm, stdout, tty, allocator, .FnDecl);
    }
}
