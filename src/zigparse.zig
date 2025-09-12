// TODO: ZigMiniGrammar Roadmap
// [ ] Integrate comments into whitespace (// line, multiline) and tighten spacing
// [ ] Keyword filtering for identifiers
// [ ] Call arguments and ExprList (function calls with args)
// [ ] Basic operators and precedence (+ - * / %, assignment)
// [ ] TypeExpr beyond identifiers (pointers, arrays, optionals, slices)
// [ ] Return types: full TypeExpr including error unions (expr!T)
// [ ] If/while/for statements and expressions
// [ ] ContainerDecl: minimal struct/union/enum bodies
// [ ] String and char literals
// [ ] Error set, try/catch/orelse
// [ ] Switch expression and prongs
// [ ] defer/errdefer/suspend/nosuspend blocks
// [ ] Visibility/ABI: extern/export/threadlocal/addrspace/linksection
// [ ] Builtins and @identifiers
// [ ] Top-level decls beyond fn (var/const, test, comptime)
const std = @import("std");
const pegvm = @import("pegvm.zig");

const VM = pegvm.VM;
const Combinators = pegvm.Combinators;
const ascii = pegvm.ascii;

// A very small subset of Zig’s grammar to get started.
// Goal: accept simple fn declarations, params, basic blocks,
// return statements, const/var decls, and simple expressions
// (identifiers, integers, and bare calls without arguments).
pub const ZigMiniGrammar = struct {
    const C = Combinators(@This());

    // Identifiers: [A-Za-z_][A-Za-z0-9_]* (no keyword filtering for now)
    const alpha = C.charclass(.{ ascii['a' .. 'z' + 1], ascii['A' .. 'Z' + 1], "_" });
    const digit = C.charclass(ascii['0' .. '9' + 1]);
    const alnum_us = C.charclass(.{
        ascii['a' .. 'z' + 1], ascii['A' .. 'Z' + 1], ascii['0' .. '9' + 1], "_",
    });

    // Word tokens (no trailing space baked in; sequences insert C.space as needed)
    const kw_fn = C.text("fn");
    const kw_pub = C.text("pub");
    const kw_return = C.text("return");
    const kw_const = C.text("const");
    const kw_var = C.text("var");

    // Punctuation
    const lparen = C.char('(');
    const rparen = C.char(')');
    const lbrace = C.char('{');
    const rbrace = C.char('}');
    const colon = C.char(':');
    const comma = C.char(',');
    const semicolon = C.char(';');
    const equal = C.char('=');

    // Lexical rules
    pub const Identifier = C.seq(.{ alpha, C.zeroOrMany(alnum_us), C.ret });
    pub const Integer = C.seq(.{ C.several(digit), C.ret });

    // TypeExpr (highly simplified): just an Identifier for now
    pub const TypeExpr = C.seq(.{ C.Call(.Identifier), C.ret });

    // Expr <- CallExpr / Integer / Identifier
    pub const Expr = C.anyOf(.{
        C.Call(.CallExpr),
        C.Call(.Integer),
        C.Call(.Identifier),
    }) ++ C.ret;

    // CallExpr <- Identifier WS? '(' WS? ')'   (no args yet)
    pub const CallExpr = C.seq(.{
        C.Call(.Identifier),
        C.space,
        lparen,
        C.space,
        rparen,
        C.ret,
    });

    // Param <- Identifier WS? ':' WS? TypeExpr
    pub const Param = C.seq(.{
        C.Call(.Identifier),
        C.space,
        colon,
        C.space,
        C.Call(.TypeExpr),
        C.ret,
    });

    // ParamList <- Param (WS? ',' WS? Param)*
    pub const ParamList = C.seq(.{
        C.Call(.Param),
        C.zeroOrMany(C.seq(.{ C.space, comma, C.space, C.Call(.Param) })),
        C.ret,
    });

    // ReturnStmt <- 'return' (WS Expr)?
    pub const ReturnStmt = C.seq(.{
        kw_return,
        C.space,
        C.maybe(C.Call(.Expr)),
        C.ret,
    });

    // VarDecl <- ('const' / 'var') WS Identifier (WS? '=' WS? Expr)?
    pub const VarDecl = C.seq(.{
        C.anyOf(.{ kw_const, kw_var }),
        C.space,
        C.Call(.Identifier),
        C.maybe(C.seq(.{ C.space, equal, C.space, C.Call(.Expr) })),
        C.ret,
    });

    // Statement <- ReturnStmt ';' / VarDecl ';' / Expr ';' / Block
    pub const Statement = C.anyOf(.{
        C.seq(.{ C.Call(.ReturnStmt), C.space, semicolon }),
        C.seq(.{ C.Call(.VarDecl), C.space, semicolon }),
        C.seq(.{ C.Call(.Expr), C.space, semicolon }),
        C.Call(.Block),
    }) ++ C.ret;

    // Block <- '{' WS Statement* '}'
    pub const Block = C.seq(.{
        lbrace,
        C.space,
        C.zeroOrMany(C.seq(.{ C.Call(.Statement), C.space })),
        C.space,
        rbrace,
        C.ret,
    });

    // FnDecl <- 'pub'? WS 'fn' WS Identifier WS '(' WS ParamList? WS ')' WS TypeExpr? WS Block
    pub const FnDecl = C.seq(.{
        C.maybe(C.seq(.{ kw_pub, C.space })),
        kw_fn,
        C.space,
        C.Call(.Identifier),
        C.space,
        lparen,
        C.space,
        C.maybe(C.Call(.ParamList)),
        C.space,
        rparen,
        C.space,
        C.maybe(C.Call(.TypeExpr)),
        C.space,
        C.Call(.Block),
        C.ret,
    });

    // start <- WS (FnDecl WS)* WS EOF
    pub const start = C.seq(.{
        C.space,
        C.zeroOrMany(C.seq(.{ C.Call(.FnDecl), C.space })),
        C.space,
        C.eof,
        C.ok,
    });
};

pub const ZigMiniParser = VM(ZigMiniGrammar, 1024, 256);

pub fn parseZigMini(src: [:0]const u8) !bool {
    return ZigMiniParser.parseFully(src, .auto_continue);
}

test "zig mini: empty program" {
    try std.testing.expect(try parseZigMini("\n"));
}

test "zig mini: fn without params and no return type" {
    try std.testing.expect(try parseZigMini(
        "fn main() { return; }\n",
    ));
}

test "zig mini: pub fn with params and return type identifier" {
    try std.testing.expect(try parseZigMini(
        "pub fn add(a: i32, b: i32) i32 { return a; }\n",
    ));
}

test "zig mini: var/const decls and simple expr statement" {
    const src =
        "fn f() {\n" ++
        "  const x = 42;\n" ++
        "  var y = 7;\n" ++
        "  f();\n" ++
        "}\n";
    try std.testing.expect(try parseZigMini(src));
}

test "zig mini: const decl only" {
    try std.testing.expect(try parseZigMini("fn f() { const x = 42; }\n"));
}

test "zig mini: var decl only" {
    try std.testing.expect(try parseZigMini("fn f() { var y = 7; }\n"));
}

test "zig mini: call expr stmt only" {
    try std.testing.expect(try parseZigMini("fn f() { f(); }\n"));
}

// File-based tests using @embedFile. Some are expected to pass with the
// current minimal grammar; others are known-gaps and are skipped for now.

fn parseFile(comptime path: []const u8) !bool {
    const src: [:0]const u8 = @embedFile(path);
    return parseZigMini(src);
}

test "file 001_fn_empty_block" {
    try std.testing.expect(try parseFile("test/001_fn_empty_block.zig"));
}

test "file 002_return_semicolon" {
    try std.testing.expect(try parseFile("test/002_return_semicolon.zig"));
}

test "file 003_var_const_and_call" {
    try std.testing.expect(try parseFile("test/003_var_const_and_call.zig"));
}

test "file 004_pub_fn_params_ret" {
    try std.testing.expect(try parseFile("test/004_pub_fn_params_ret.zig"));
}

test "file 005_call_with_args (skip)" {
    // Not yet supported: call arguments
    return error.SkipZigTest;
}

test "file 006_assignment (skip)" {
    // Not yet supported: assignment operators
    return error.SkipZigTest;
}

test "file 007_param_without_type (skip)" {
    // Not supported: param without type
    return error.SkipZigTest;
}

test "file 008_toplevel_var (skip)" {
    // Not supported: top-level const/var declarations
    return error.SkipZigTest;
}

test "file 009_nested_blocks" {
    try std.testing.expect(try parseFile("test/009_nested_blocks.zig"));
}

test "file 010_two_functions" {
    try std.testing.expect(try parseFile("test/010_two_functions.zig"));
}
