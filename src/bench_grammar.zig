const parse = @import("parse.zig");

// A small but non-trivial language suitable for benchmarking.
// Supports:
// - identifiers, numbers
// - function calls with positional and named args
// - + and - infix expressions
// - variable declarations and call statements terminated by ';'
// - programs consisting of many statements
pub const BenchLang = struct {
    const C = parse.Combinators(@This(), .{ .debug = parse.SilentDebug });

    // Term <- NUMBER / IDENT / '(' WS Expr WS ')'
    pub const Term = C.alt(.{
        C.NUMBER,
        C.IDENT,
        C.seq(.{ C.CH('('), C.WS, C.Call(.Expr), C.WS, C.CH(')') }),
    }) ++ C.RET;

    // Expr <- Term  (keep simple to avoid heavy backtracking)
    pub const Expr = C.seq(.{ C.Call(.Term), C.RET });

    // Arg <- IDENT WS ':' WS Expr / Expr
    pub const Arg = C.seq(.{
        C.alt(.{
            C.seq(.{ C.IDENT, C.WS, C.CH(':'), C.WS, C.Call(.Expr) }),
            C.Call(.Expr),
        }),
        C.RET,
    });

    // ArgList <- Arg (WS ',' WS Arg)*
    pub const ArgList = C.seq(.{
        C.Call(.Arg),
        C.many0(C.seq(.{ C.WS, C.CH(','), C.WS, C.Call(.Arg) })),
        C.RET,
    });

    // Call <- IDENT WS '(' WS ArgList? WS ')'
    pub const Call = C.seq(.{
        C.IDENT, C.WS, C.CH('('), C.WS,
        C.opt(C.Call(.ArgList)),
        C.WS, C.CH(')'),
        C.RET,
    });

    // VarDecl <- 'let' WS IDENT WS '=' WS Expr WS ';'
    pub const VarDecl = C.seq(.{
        C.STR("let"), C.WS, C.IDENT, C.WS, C.CH('='), C.WS, C.Call(.Expr), C.WS, C.CH(';'),
        C.RET,
    });

    // ExprStmt <- Call WS ';'
    pub const ExprStmt = C.seq(.{ C.Call(.Call), C.WS, C.CH(';'), C.RET });

    // Stmt <- VarDecl / ExprStmt
    pub const Stmt = C.seq(.{
        C.alt(.{ C.Call(.VarDecl), C.Call(.ExprStmt) }),
        C.RET,
    });

    // Program <- WS Stmt* WS EOF
    pub const Program = C.seq(.{
        C.WS,
        C.many0(C.seq(.{ C.Call(.Stmt), C.WS })),
        C.END, C.ACCEPT,
    });

    pub const Start = C.Call(.Program);
};
