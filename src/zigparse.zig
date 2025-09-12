// TODO: ZigMiniGrammar Roadmap
// [x] Integrate comments into whitespace (// line) and tighten spacing
// [x] Keyword filtering for identifiers
// [x] Call arguments and ExprList (function calls with args)
// [x] Assignment (Identifier '=' Expr)
// [ ] Basic operators and precedence (+ - * / %)
// [x] TypeExpr beyond identifiers (pointers, arrays, optionals, slices)
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

    // Whitespace/comments
    // Simple line comments: // ... to end-of-line (ASCII only for now)
    const not_nl_ascii = C.charclass(.{ ascii[' ' .. '~' + 1], '\t', '\r' });
    const line_comment = C.text("//") ++ C.zeroOrMany(not_nl_ascii);
    const WS = C.zeroOrMany(C.anyOf(.{ C.charclass(" \t\n\r"), line_comment }));

    // Word tokens (no trailing space baked in; sequences insert WS as needed)
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
    const lbracket = C.char('[');
    const rbracket = C.char(']');
    const colon = C.char(':');
    const comma = C.char(',');
    const semicolon = C.char(';');
    const equal = C.char('=');

    // Lexical rules
    // Reserved words we currently recognize
    const ident_boundary = C.notLookahead(alnum_us); // next is not [A-Za-z0-9_]
    const reserved_exact = C.anyOf(.{
        C.seq(.{ C.text("fn"), ident_boundary }),
        C.seq(.{ C.text("pub"), ident_boundary }),
        C.seq(.{ C.text("return"), ident_boundary }),
        C.seq(.{ C.text("const"), ident_boundary }),
        C.seq(.{ C.text("var"), ident_boundary }),
    });

    pub const Identifier = C.seq(.{
        C.notLookahead(reserved_exact),
        alpha,
        C.zeroOrMany(alnum_us),
        C.ret,
    });
    pub const Integer = C.seq(.{ C.several(digit), C.ret });

    // Type expressions (expanded):
    //   TypeExpr <- TypePrefix* TypeAtom
    //   TypeAtom <- Identifier
    //   TypePrefix <- '?' / '*' / ('[' WS Expr WS ']' | '[' WS ']' )
    pub const TypeAtom = C.seq(.{ C.Call(.Identifier), C.ret });

    const SliceStart = C.seq(.{ lbracket, WS, rbracket });
    const ArrayStart = C.seq(.{ lbracket, WS, C.Call(.Expr), WS, rbracket });
    const BrackType = C.anyOf(.{ ArrayStart, SliceStart });

    const TypePrefix = C.anyOf(.{ C.char('?'), star: {
            const s = C.char('*');
            break :star s;
        }, BrackType });

    pub const TypeExpr = C.seq(.{ C.zeroOrMany(TypePrefix), C.Call(.TypeAtom), C.ret });

    // Primary <- CallExpr / Integer / Identifier
    pub const Primary = C.anyOf(.{
        C.Call(.CallExpr),
        C.Call(.Integer),
        C.Call(.Identifier),
    }) ++ C.ret;

    // MultiplyExpr <- Primary (WS ('*' '/' '%') WS Primary)*
    const mulop = C.charclass("*/%");
    pub const MultiplyExpr = C.seq(.{
        C.Call(.Primary),
        C.zeroOrMany(C.seq(.{ WS, mulop, WS, C.Call(.Primary) })),
        C.ret,
    });

    // AddExpr <- MultiplyExpr (WS ('+' '-') WS MultiplyExpr)*
    const addop = C.charclass("+-");
    pub const AddExpr = C.seq(.{
        C.Call(.MultiplyExpr),
        C.zeroOrMany(C.seq(.{ WS, addop, WS, C.Call(.MultiplyExpr) })),
        C.ret,
    });

    // Expr <- AddExpr
    pub const Expr = C.seq(.{ C.Call(.AddExpr), C.ret });

    // ExprList <- Expr (WS? ',' WS? Expr)*
    pub const ExprList = C.seq(.{
        C.Call(.Expr),
        C.zeroOrMany(C.seq(.{ WS, comma, WS, C.Call(.Expr) })),
        C.ret,
    });

    // CallExpr <- Identifier WS? '(' WS? ExprList? WS? ')'
    pub const CallExpr = C.seq(.{
        C.Call(.Identifier),
        WS,
        lparen,
        WS,
        C.maybe(C.Call(.ExprList)),
        WS,
        rparen,
        C.ret,
    });

    // Param <- Identifier WS? ':' WS? TypeExpr
    pub const Param = C.seq(.{
        C.Call(.Identifier),
        WS,
        colon,
        WS,
        C.Call(.TypeExpr),
        C.ret,
    });

    // ParamList <- Param (WS? ',' WS? Param)*
    pub const ParamList = C.seq(.{
        C.Call(.Param),
        C.zeroOrMany(C.seq(.{ WS, comma, WS, C.Call(.Param) })),
        C.ret,
    });

    // ReturnStmt <- 'return' (WS Expr)?
    pub const ReturnStmt = C.seq(.{
        kw_return,
        WS,
        C.maybe(C.Call(.Expr)),
        C.ret,
    });

    // VarDecl <- ('const' / 'var') WS Identifier (WS? '=' WS? Expr)?
    pub const VarDecl = C.seq(.{
        C.anyOf(.{ kw_const, kw_var }),
        WS,
        C.Call(.Identifier),
        C.maybe(C.seq(.{ WS, equal, WS, C.Call(.Expr) })),
        C.ret,
    });

    // AssignStmt <- Identifier WS '=' WS Expr
    pub const AssignStmt = C.seq(.{
        C.Call(.Identifier),
        WS,
        equal,
        WS,
        C.Call(.Expr),
        C.ret,
    });

    // Statement <- AssignStmt ';' / ReturnStmt ';' / VarDecl ';' / Expr ';' / Block
    pub const Statement = C.anyOf(.{
        C.seq(.{ C.Call(.AssignStmt), WS, semicolon }),
        C.seq(.{ C.Call(.ReturnStmt), WS, semicolon }),
        C.seq(.{ C.Call(.VarDecl), WS, semicolon }),
        C.seq(.{ C.Call(.Expr), WS, semicolon }),
        C.Call(.Block),
    }) ++ C.ret;

    // Block <- '{' WS Statement* '}'
    pub const Block = C.seq(.{
        lbrace,
        WS,
        C.zeroOrMany(C.seq(.{ C.Call(.Statement), WS })),
        WS,
        rbrace,
        C.ret,
    });

    // FnDecl <- 'pub'? WS 'fn' WS Identifier WS '(' WS ParamList? WS ')' WS TypeExpr? WS Block
    pub const FnDecl = C.seq(.{
        C.maybe(C.seq(.{ kw_pub, WS })),
        kw_fn,
        WS,
        C.Call(.Identifier),
        WS,
        lparen,
        WS,
        C.maybe(C.Call(.ParamList)),
        WS,
        rparen,
        WS,
        C.maybe(C.Call(.TypeExpr)),
        WS,
        C.Call(.Block),
        C.ret,
    });

    // start <- WS (FnDecl WS)* WS EOF
    pub const start = C.seq(.{
        WS,
        C.zeroOrMany(C.seq(.{ C.Call(.FnDecl), WS })),
        WS,
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
    try std.testing.expect(try parseFile("test/005_call_with_args.zig"));
}

test "file 006_assignment" {
    try std.testing.expect(try parseFile("test/006_assignment.zig"));
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

test "file 011_line_comments" {
    try std.testing.expect(try parseFile("test/011_line_comments.zig"));
}

test "file 012_comments_between_decls" {
    try std.testing.expect(try parseFile("test/012_comments_between_decls.zig"));
}

test "file 013_nested_call" {
    try std.testing.expect(try parseFile("test/013_nested_call.zig"));
}

test "file 014_keyword_as_identifier should fail" {
    try std.testing.expect(!try parseFile("test/014_keyword_as_identifier.zig"));
}

test "file 015_keyword_prefix_allowed" {
    try std.testing.expect(try parseFile("test/015_keyword_prefix_allowed.zig"));
}

test "file 016_addition" {
    try std.testing.expect(try parseFile("test/016_addition.zig"));
}

test "file 017_mul_precedence" {
    try std.testing.expect(try parseFile("test/017_mul_precedence.zig"));
}

test "file 018_nested_ops_calls" {
    try std.testing.expect(try parseFile("test/018_nested_ops_calls.zig"));
}

test "file 019_param_pointer" {
    try std.testing.expect(try parseFile("test/019_param_pointer.zig"));
}

test "file 020_param_slice_array" {
    try std.testing.expect(try parseFile("test/020_param_slice_array.zig"));
}

test "file 021_return_optional_ptr" {
    try std.testing.expect(try parseFile("test/021_return_optional_ptr.zig"));
}

test "file 022_complex_type_prefixes" {
    try std.testing.expect(try parseFile("test/022_complex_type_prefixes.zig"));
}
