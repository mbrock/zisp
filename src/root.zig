comptime {
    @setEvalBranchQuota(200000);
    _ = @import("pegvm.zig");
    _ = @import("debug_printer.zig");
    _ = @import("pegvmfun.zig");
    _ = @import("pegvmfun_iter.zig");
    _ = @import("test_pegvmfun.zig");
    //    _ = @import("zigparse.zig");
}

pub const parse = @import("pegvm.zig");
pub const debug = @import("debug_printer.zig");
pub const zigmini = @import("zigparse.zig");
pub const pegvmfun = @import("pegvmfun.zig");
pub const pegvmfun_iter = @import("pegvmfun_iter.zig");
