const std = @import("std");
const parse = @import("parse.zig");

// Simple test grammar that should work
pub const SimpleGrammar = struct {
    pub const C = parse.Combinators(@This(), .{ .debug = parse.SilentDebug });

    // Simple expression: number + number
    pub const Expr = C.seq(.{
        C.NUMBER, C.WS, C.CH('+'), C.WS, C.NUMBER
    }) ++ C.RET;

    // Start <- WS Expr WS EOF
    pub const Start = C.seq(.{ C.WS, C.Call(.Expr), C.WS, C.END, C.ACCEPT });
};