comptime {
    _ = @import("pegvm.zig");
    _ = @import("debug_printer.zig");
    _ = @import("zigparse.zig");
}

pub const parse = @import("pegvm.zig");
pub const debug = @import("debug_printer.zig");
pub const zigmini = @import("zigparse.zig");
