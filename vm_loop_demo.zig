const std = @import("std");
const peg = @import("src/peg.zig");
const vm_mod = @import("src/vm.zig");

pub fn main() !void {
    const GrammarType = peg.demoGrammar;
    const VM = vm_mod.VM(GrammarType);

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    var parser = try VM.initAlloc("[[1] [2]]", allocator, 64, 64, 512);
    defer parser.deinit(allocator);

    try parser.run();
}
