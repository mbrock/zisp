const std = @import("std");

comptime {
    @setEvalBranchQuota(200000);
}
const pegvm = @import("pegvm.zig");

const VM = pegvm.VM;
const Combinators = pegvm.Combinators;
const ascii = pegvm.ascii;

pub const ZigMiniGrammar = struct {
    const C = Combinators(@This());

    const alpha =
        C.charclass(.{ ascii['a' .. 'z' + 1], ascii['A' .. 'Z' + 1], "_" });
    const digit =
        C.charclass(ascii['0' .. '9' + 1]);
    const alnum_us =
        C.charclass(.{
            ascii['a' .. 'z' + 1], ascii['A' .. 'Z' + 1], ascii['0' .. '9' + 1], "_",
        });
    const not_nl_ascii =
        C.charclass(.{ ascii[' ' .. '~' + 1], '\t', '\r' });

    const line_comment =
        C.text("//") ++ C.star(not_nl_ascii);

    const skip: [9]C.Op =
        C.star(C.anyOf(.{ C.charclass(" \t\n\r"), line_comment }));

    fn kw(name: []const u8) [14]C.Op {
        return C.text(name) ++ ident_boundary ++ skip;
    }

    const @"fn" = kw("fn");
    const @"pub" = kw("pub");
    const @"return" = kw("return");
    const @"const" = kw("const");
    const @"var" = kw("var");
    const @"export" = kw("export");
    const @"extern" = kw("extern");
    const @"threadlocal" = kw("threadlocal");
    const @"addrspace" = kw("addrspace");
    const @"linksection" = kw("linksection");
    const @"callconv" = kw("callconv");
    const @"align" = kw("align");
    const @"if" = kw("if");
    const @"comptime" = kw("comptime");
    const @"test" = kw("test");
    const @"else" = kw("else");
    const @"while" = kw("while");
    const @"for" = kw("for");
    const @"switch" = kw("switch");
    const @"break" = kw("break");
    const @"continue" = kw("continue");
    const @"defer" = kw("defer");
    const @"errdefer" = kw("errdefer");
    const @"suspend" = kw("suspend");
    const @"nosuspend" = kw("nosuspend");
    const @"struct" = kw("struct");
    const @"union" = kw("union");
    const @"enum" = kw("enum");
    const @"noinline" = kw("noinline");
    const @"inline" = kw("inline");
    const @"and" = kw("and");
    const @"or" = kw("or");
    const @"orelse" = kw("orelse");
    const @"try" = kw("try");
    const @"catch" = kw("catch");
    const @"error" = kw("error");

    fn op(s: []const u8, neg: []const u8) [if (neg.len == 0) 10 else 14]C.Op {
        if (neg.len == 0) {
            return C.text(s) ++ skip;
        } else {
            return C.text(s) ++ C.shun(C.charclass(neg)) ++ skip;
        }
    }

    const @"(" = op("(", "");
    const @")" = op(")", "");
    const @"{" = op("{", "");
    const @"}" = op("}", "");
    const @"[" = op("[", "");
    const @"]" = op("]", "");
    const @":" = op(":", "");
    const @"," = op(",", "");
    const @";" = op(";", "");
    const @"=" = op("=", "");
    const @"*" = op("*", "*%=|");
    const @"?" = op("?", "");
    const @"." = op(".", ".");
    const @".*" = op(".*", "");
    const @"..." = op("...", "");
    const @".?" = op(".?", "");
    const @"\\" = op("\\", "");
    const @"=>" = op("=>", "");
    const @".." = op("..", ".");
    const @"+" = op("+", "%+=|");
    const @"-" = op("-", "%=>|");
    const @"/" = op("/", "=");
    const @"%" = op("%", "=");
    const @"<<" = op("<<", "=|");
    const @">>" = op(">>", "=");
    const @"^" = op("^", "=");
    const @"|" = op("|", "|=");
    const @"==" = op("==", "");
    const @"!=" = op("!=", "");
    const @"<=" = op("<=", "");
    const @">=" = op(">=", "");
    const @"<" = op("<", "<=");
    const @">" = op(">", ">=");
    const @"!" = op("!", "=");
    const @"~" = op("~", "");
    const @"-%" = op("-%", "=");
    const @"&" = op("&", "=");

    const ident_boundary = C.shun(alnum_us); // next is not [A-Za-z0-9_]

    fn ident(name: []const u8) [5]C.Op {
        return C.text(name) ++ ident_boundary;
    }

    const reserved_exact = C.anyOf(.{
        ident("fn"),
        ident("pub"),
        ident("return"),
        ident("const"),
        ident("var"),
        ident("break"),
        ident("continue"),
        ident("defer"),
        ident("errdefer"),
        ident("suspend"),
        ident("nosuspend"),
        ident("comptime"),
        ident("test"),
        ident("export"),
        ident("extern"),
        ident("threadlocal"),
        ident("addrspace"),
        ident("linksection"),
        ident("callconv"),
        ident("if"),
        ident("else"),
        ident("while"),
        ident("for"),
        ident("switch"),
        ident("struct"),
        ident("union"),
        ident("enum"),
        ident("and"),
        ident("or"),
        ident("orelse"),
        ident("try"),
        ident("catch"),
        ident("noinline"),
        ident("error"),
        ident("inline"),
    });

    fn rule(x: anytype) [x.len + 1]C.Op {
        return x ++ C.ret;
    }

    pub const Identifier =
        rule(C.shun(reserved_exact) ++ alpha ++ C.star(alnum_us) ++ skip);

    pub const BuiltinIdentifier =
        rule(C.char('@') ++ alpha ++ C.star(alnum_us));

    pub const Integer =
        rule(C.several(digit) ++ skip);

    pub const IdentifierList = rule(
        C.call(&Identifier) ++
            C.star(@"," ++ C.call(&Identifier)) ++
            C.opt(@","),
    );

    pub const ErrorSetDecl =
        rule(@"error" ++ @"{" ++ C.opt(C.call(&IdentifierList)) ++ @"}");

    pub const TypeAtom: [8]C.Op = rule(
        C.anyOf(.{
            C.call(&Identifier),
            C.call(&ContainerExpr),
            C.call(&ErrorSetDecl),
        }),
    );

    pub const ArrayStart: [22]C.Op =
        rule(@"[" ++ C.call(&Expr) ++ @"]");

    pub const TypePrefix = rule(
        C.anyOf(.{
            @"?",
            @"*",
            C.call(&ArrayStart),
            @"[" ++ @"]",
        }),
    );

    pub const TypeCore =
        rule(C.star(C.call(&TypePrefix)) ++ C.call(&TypeAtom));

    pub const TypeExpr: [19]C.Op =
        rule(C.call(&TypeCore) ++ C.opt(@"!" ++ C.call(&TypeExpr)));

    const str_escape =
        @"\\" ++ C.charclass("nr\"t\\");
    const str_plain =
        C.charclass(.{
            ascii[' ' .. '!' + 1],
            ascii['#' .. '[' + 1],
            ascii[']' .. '~' + 1],
        });

    pub const StringLiteral = rule(
        C.char('"') ++
            C.star(C.anyOf(.{ str_escape, str_plain })) ++
            C.char('"') ++
            skip,
    );

    const chr_escape =
        @"\\" ++ C.charclass("nr't\\\"");
    const chr_plain =
        C.charclass(.{
            ascii[' ' .. '&' + 1],
            ascii['(' .. '[' + 1],
            ascii[']' .. '~' + 1],
        });

    pub const CharLiteral = rule(
        C.char('\'') ++
            C.anyOf(.{ chr_escape, chr_plain }) ++
            C.char('\'') ++
            skip,
    );

    pub const ExprInParens: [22]C.Op =
        rule(@"(" ++ C.call(&Expr) ++ @")");

    pub const LinkSection =
        rule(@"linksection" ++ C.call(&ExprInParens));
    pub const AddrSpace =
        rule(@"addrspace" ++ C.call(&ExprInParens));
    pub const CallConv =
        rule(@"callconv" ++ C.call(&ExprInParens));
    pub const ByteAlign =
        rule(@"align" ++ C.call(&ExprInParens));

    pub const ErrorLiteral =
        rule(@"error" ++ @"." ++ C.call(&Identifier));

    pub const DotIdentifier =
        rule(@"." ++ C.call(&Identifier));

    pub const Primary: [50]C.Op = rule(
        C.anyOf(.{
            C.call(&ExprInParens),
            C.call(&Block),
            C.call(&IfExpr),
            C.call(&WhileExprE),
            C.call(&ForExprE),
            C.call(&SwitchExpr),
            C.call(&ReturnExpr),
            C.call(&BreakExpr),
            C.call(&ContinueExpr),
            C.call(&ContainerExpr),
            C.call(&BuiltinIdentifier),
            C.call(&ErrorLiteral),
            C.call(&DotIdentifier),
            C.call(&Integer),
            C.call(&StringLiteral),
            C.call(&CharLiteral),
            C.call(&Identifier),
        }),
    );

    pub const FnCallArguments: [24]C.Op =
        rule(@"(" ++ C.opt(C.call(&ExprList)) ++ @")");

    pub const MemberAccess = rule(@"." ++ C.call(&Identifier));

    const sliceSuffix =
        @".." ++ C.opt(C.call(&Expr)) ++ C.opt(@":" ++ C.call(&Expr));

    pub const IndexOrSlice: [54]C.Op = rule(
        @"[" ++ C.call(&Expr) ++ C.opt(sliceSuffix) ++ @"]",
    );

    pub const OneSuffix = rule(
        C.anyOf(.{
            C.call(&FnCallArguments),
            C.call(&IndexOrSlice),
            @".*",
            @".?",
            C.call(&MemberAccess),
        }),
    );

    pub const SuffixExpr = rule(
        C.call(&Primary) ++ C.star(C.call(&OneSuffix)),
    );

    pub const ReturnExpr: [18]C.Op =
        rule(@"return" ++ C.opt(C.call(&Expr)));

    pub const LabelRef =
        rule(@":" ++ C.call(&Identifier));
    pub const LabelDef =
        rule(C.call(&Identifier) ++ @":");

    pub const BreakExpr: [21]C.Op = rule(
        @"break" ++ C.opt(C.call(&LabelRef)) ++ C.opt(C.call(&Expr)),
    );

    pub const ContinueExpr =
        rule(@"continue" ++ C.opt(C.call(&LabelRef)));

    const payloadExpr =
        C.opt(C.call(&PtrPayload)) ++ C.call(&Expr);
    const elseExpr =
        @"else" ++ payloadExpr;

    pub const IfExpr: [58]C.Op = rule(
        @"if" ++ @"(" ++ C.call(&Expr) ++ @")" ++
            payloadExpr ++
            elseExpr,
    );

    pub const WhileContinueExpr: [32]C.Op =
        rule(@":" ++ @"(" ++ C.call(&AssignExpr) ++ @")");

    pub const WhileExprE: [43]C.Op = rule(
        @"while" ++ C.call(&ExprInParens) ++
            C.opt(C.call(&PtrPayload)) ++
            C.opt(C.call(&WhileContinueExpr)) ++
            C.call(&Block) ++
            C.opt(elseExpr),
    );

    pub const ForItem: [21]C.Op = rule(
        C.call(&Expr) ++ C.opt(@".." ++ C.opt(C.call(&Expr))),
    );

    pub const ForArgumentsList = rule(
        C.call(&ForItem) ++
            C.star(@"," ++ C.call(&ForItem)) ++
            C.opt(@","),
    );

    pub const ForExprE: [60]C.Op = rule(
        @"for" ++ @"(" ++ C.call(&ForArgumentsList) ++ @")" ++
            C.opt(C.call(&PtrListPayload)) ++
            C.call(&Block) ++
            C.opt(elseExpr),
    );

    pub const CaseItem: [15]C.Op = rule(
        C.call(&Expr) ++ C.opt(@"..." ++ C.call(&Expr)),
    );

    pub const PtrPayload = rule(
        @"|" ++ C.opt(@"*") ++ C.call(&Identifier) ++ @"|",
    );

    pub const PtrIndexPayload = rule(
        @"|" ++
            C.opt(@"*") ++ C.call(&Identifier) ++
            C.opt(@"," ++ C.call(&Identifier)) ++
            @"|",
    );

    pub const PtrListPayload = rule(
        @"|" ++
            C.opt(@"*") ++ C.call(&Identifier) ++
            C.star(@"," ++ C.opt(@"*") ++ C.call(&Identifier)) ++
            C.opt(@",") ++
            @"|",
    );

    pub const Payload =
        rule(@"|" ++ C.call(&Identifier) ++ @"|");

    pub const ElseProng: [29]C.Op = rule(
        @"else" ++ @"=>" ++ C.opt(C.call(&PtrIndexPayload)) ++ C.call(&Expr),
    );

    pub const CaseProng: [45]C.Op = rule(
        C.opt(@"inline") ++
            C.call(&CaseItem) ++
            C.star(@"," ++ C.call(&CaseItem)) ++
            @"=>" ++
            C.opt(C.call(&PtrIndexPayload)) ++
            C.call(&Expr),
    );

    pub const Prong = rule(
        C.anyOf(.{
            C.call(&ElseProng),
            C.call(&CaseProng),
        }),
    );

    pub const SwitchBody = rule(
        @"{" ++
            C.opt(C.call(&Prong) ++
                C.star(@"," ++ C.call(&Prong))) ++
            @"}",
    );

    pub const SwitchExpr: [17]C.Op = rule(
        @"switch" ++ C.call(&ExprInParens) ++ C.call(&SwitchBody),
    );

    pub const FieldDecl = rule(
        C.call(&Identifier) ++ @":" ++ C.call(&TypeExpr),
    );

    pub const FieldList = rule(
        C.call(&FieldDecl) ++
            C.star(C.seq(.{ @",", C.call(&FieldDecl) })) ++
            C.opt(@","),
    );

    pub const StructBody = rule(
        @"{" ++ C.opt(C.call(&FieldList)) ++ @"}",
    );

    pub const UnionBody = StructBody;

    pub const EnumFields = rule(
        C.call(&Identifier) ++
            C.star(C.seq(.{ @",", C.call(&Identifier) })) ++
            C.opt(@","),
    );

    pub const EnumBody = rule(
        @"{" ++ C.opt(C.call(&EnumFields)) ++ @"}",
    );

    pub const ContainerExpr = rule(
        C.anyOf(.{
            C.seq(.{ @"struct", C.call(&StructBody) }),
            C.seq(.{ @"union", C.call(&UnionBody) }),
            C.seq(.{ @"enum", C.call(&EnumBody) }),
        }),
    );

    pub const PrefixExpr = rule(
        C.star(C.anyOf(.{ @"!", @"-", @"~", @"-%", @"&", @"try" })) ++
            C.call(&SuffixExpr),
    );

    pub const MultiplyExpr = rule(
        C.call(&PrefixExpr) ++
            C.star(C.anyOf(.{ @"*", @"/", @"%" }) ++ C.call(&PrefixExpr)),
    );

    pub const AddExpr = rule(
        C.call(&MultiplyExpr) ++ C.star(
            C.anyOf(.{ @"+", @"-" }) ++ C.call(&MultiplyExpr),
        ),
    );

    pub const BitShiftExpr = rule(
        C.call(&AddExpr) ++ C.star(
            C.anyOf(.{ @"<<", @">>" }) ++ C.call(&AddExpr),
        ),
    );

    pub const BitwiseExpr = rule(
        C.call(&BitShiftExpr) ++
            C.star(
                C.anyOf(.{
                    @"&",
                    @"^",
                    @"|",
                    @"orelse",
                    @"catch" ++ C.opt(C.call(&Payload)),
                }) ++
                    C.call(&BitShiftExpr),
            ),
    );

    pub const CompareExpr = rule(
        C.call(&BitwiseExpr) ++
            C.opt(
                C.anyOf(.{ @"==", @"!=", @"<=", @">=", @"<", @">" }) ++
                    C.call(&BitwiseExpr),
            ),
    );

    pub const BoolAndExpr = rule(
        C.call(&CompareExpr) ++
            C.star(@"and" ++ C.call(&CompareExpr)),
    );

    pub const Expr = rule(
        C.call(&BoolAndExpr) ++
            C.star(@"or" ++ C.call(&BoolAndExpr)),
    );

    pub const ExprList = rule(
        C.call(&Expr) ++
            C.star(@"," ++ C.call(&Expr)),
    );

    pub const CallExpr = rule(
        C.anyOf(.{ C.call(&Identifier), C.call(&BuiltinIdentifier) }) ++
            @"(" ++
            C.opt(C.call(&ExprList)) ++
            @")",
    );

    pub const Param = rule(
        C.call(&Identifier) ++ @":" ++ C.call(&TypeExpr),
    );

    pub const ParamList = rule(
        C.call(&Param) ++
            C.star(@"," ++ C.call(&Param)),
    );

    pub const ReturnStmt = rule(
        @"return" ++ C.opt(C.call(&Expr)),
    );

    // ok continue from here, claude! turn the C.seq(.{ a, b, ..., C.ret }) into rule(a ++ b ++ ...),
    // also changing inner C.seq(...) into simple ++ forms

    pub const VarDecl = C.seq(.{
        C.anyOf(.{ @"const", @"var" }),
        C.call(&Identifier),
        C.opt(C.seq(.{ @"=", C.call(&Expr) })),
        C.ret,
    });

    pub const AssignExpr = C.anyOf(.{
        C.seq(.{ C.call(&Identifier), @"=", C.call(&Expr) }),
        C.call(&Expr),
    }) ++ C.ret;

    pub const Block: [24]C.Op =
        @"{" ++ C.star(C.call(&Statement)) ++ @"}" ++ C.ret;

    pub const BlockExpr = C.seq(.{ C.opt(C.call(&LabelDef)), C.call(&Block), C.ret });
    pub const BlockExprStatement = C.anyOf(.{
        C.call(&BlockExpr),
        C.seq(.{ C.call(&AssignExpr), @";" }),
    }) ++ C.ret;

    pub const VarDeclExprStatement = C.anyOf(.{
        C.seq(.{ C.call(&VarDecl), @";" }),
        C.seq(.{ C.call(&Expr), @";" }),
    }) ++ C.ret;

    pub const Else =
        @"else" ++ C.opt(C.call(&PtrPayload)) ++ C.callRule(.Statement) ++ C.ret;

    pub const IfStatement =
        @"if" ++ @"(" ++ C.call(&Expr) ++ @")" ++ C.opt(C.call(&PtrPayload)) ++ C.anyOf(.{
            C.call(&BlockExpr) ++ C.opt(C.call(&Else)),
            C.call(&AssignExpr) ++ C.anyOf(.{ @";", C.call(&Else) }),
        }) ++ C.ret;

    pub const WhileStatement =
        @"while" ++ @"(" ++ C.call(&Expr) ++ @")" ++
        C.opt(C.call(&PtrPayload)) ++
        C.opt(C.call(&WhileContinueExpr)) ++
        C.anyOf(.{
            C.call(&BlockExpr) ++ C.opt(C.call(&Else)),
            C.call(&AssignExpr) ++ C.anyOf(.{ @";", C.call(&Else) }),
        }) ++ C.ret;

    pub const LabeledWhileStatement =
        C.opt(C.call(&LabelDef)) ++ C.call(&WhileStatement) ++ C.ret;

    pub const ForStatement =
        @"for" ++ @"(" ++ C.call(&ForArgumentsList) ++ @")" ++
        C.opt(C.call(&PtrListPayload)) ++
        C.anyOf(.{
            C.call(&BlockExpr),
            C.call(&AssignExpr) ++ @";",
        }) ++ C.ret;

    pub const LabeledForStatement =
        C.opt(C.call(&LabelDef)) ++ C.call(&ForStatement) ++ C.ret;

    pub const DeferStatement =
        @"defer" ++ C.call(&BlockExprStatement) ++ C.ret;
    pub const ErrDeferStatement =
        @"errdefer" ++ C.opt(C.call(&Payload)) ++ C.call(&BlockExprStatement) ++ C.ret;
    pub const NoSuspendStatement =
        @"nosuspend" ++ C.call(&BlockExprStatement) ++ C.ret;
    pub const SuspendStatement =
        @"suspend" ++ C.call(&BlockExprStatement) ++ C.ret;

    pub const Statement: [29]C.Op = C.anyOf(.{
        C.call(&IfStatement),
        C.call(&LabeledWhileStatement),
        C.call(&LabeledForStatement),
        C.call(&SwitchExpr),
        C.call(&DeferStatement),
        C.call(&ErrDeferStatement),
        C.call(&NoSuspendStatement),
        C.call(&SuspendStatement),
        C.call(&VarDeclExprStatement),
        C.call(&BlockExprStatement),
    }) ++ C.ret;

    pub const FnDecl = C.seq(.{
        C.opt(@"pub"),
        C.opt(C.anyOf(.{
            @"export",
            C.seq(.{ @"extern", C.opt(C.callRule(.StringLiteral)) }),
            @"inline",
            @"noinline",
        })),
        @"fn",
        C.callRule(.Identifier),
        @"(",
        C.opt(C.callRule(.ParamList)),
        @")",
        C.opt(C.callRule(.ByteAlign)),
        C.opt(C.callRule(.AddrSpace)),
        C.opt(C.callRule(.LinkSection)),
        C.opt(C.callRule(.CallConv)),
        C.opt(@"!"),
        C.callRule(.TypeExpr),
        C.call(&Block),
        C.ret,
    });

    pub const VarDeclProto = C.seq(.{
        C.anyOf(.{ @"const", @"var" }),
        C.callRule(.Identifier),
        C.opt(C.seq(.{ @":", C.callRule(.TypeExpr) })),
        C.opt(C.callRule(.ByteAlign)),
        C.opt(C.callRule(.AddrSpace)),
        C.opt(C.callRule(.LinkSection)),
        C.ret,
    });

    pub const GlobalVarDecl = C.seq(.{
        C.callRule(.VarDeclProto),
        C.opt(@"=" ++ C.callRule(.Expr)),
        @";",
        C.ret,
    });

    pub const TopVarDecl = C.seq(.{
        C.opt(@"pub"),
        C.opt(C.anyOf(.{
            @"export",
            @"extern" ++ C.opt(C.callRule(.StringLiteral)),
        })),
        C.opt(@"threadlocal"),
        C.callRule(.GlobalVarDecl),
        C.ret,
    });

    pub const TestDecl = C.seq(.{
        @"test",
        C.opt(C.anyOf(.{ C.call(&StringLiteral), C.call(&Identifier) })),
        C.call(&Block),
        C.ret,
    });

    pub const ComptimeDecl = @"comptime" ++ C.call(&Block) ++ C.ret;

    pub const start = C.seq(.{
        skip,
        C.star(C.anyOf(.{
            C.call(&FnDecl),
            C.call(&TopVarDecl),
            C.call(&TestDecl),
            C.call(&ComptimeDecl),
        })),
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
        "fn main() void { return; }\n",
    ));
}

test "zig mini: pub fn with params and return type identifier" {
    try std.testing.expect(try parseZigMini(
        "pub fn add(a: i32, b: i32) i32 { return a; }\n",
    ));
}

test "zig mini: var/const decls and simple expr statement" {
    const src =
        "fn f() void {\n" ++
        "  const x = 42;\n" ++
        "  var y = 7;\n" ++
        "  f();\n" ++
        "}\n";
    try std.testing.expect(try parseZigMini(src));
}

test "zig mini: const decl only" {
    try std.testing.expect(try parseZigMini("fn f() void { const x = 42; }\n"));
}

test "zig mini: var decl only" {
    try std.testing.expect(try parseZigMini("fn f() void { var y = 7; }\n"));
}

test "zig mini: call expr stmt only" {
    try std.testing.expect(try parseZigMini("fn f() void { f(); }\n"));
}

fn parseFile(comptime path: []const u8) !bool {
    const src: [:0]const u8 = @embedFile(path);
    if (try parseZigMini(src)) {
        return true;
    } else {
        return false;
    }
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

test "file 005_call_with_args" {
    try std.testing.expect(try parseFile("test/005_call_with_args.zig"));
}

test "file 006_assignment" {
    try std.testing.expect(try parseFile("test/006_assignment.zig"));
}

test "file 008_toplevel_var" {
    try std.testing.expect(try parseFile("test/008_toplevel_var.zig"));
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

test "file 023_toplevel_pub_var" {
    try std.testing.expect(try parseFile("test/023_toplevel_pub_var.zig"));
}

test "file 024_mixed_toplevel" {
    try std.testing.expect(try parseFile("test/024_mixed_toplevel.zig"));
}

test "file 025_struct_empty" {
    try std.testing.expect(try parseFile("test/025_struct_empty.zig"));
}

test "file 026_union_empty" {
    try std.testing.expect(try parseFile("test/026_union_empty.zig"));
}

test "file 027_enum_empty" {
    try std.testing.expect(try parseFile("test/027_enum_empty.zig"));
}

test "file 028_struct_fields_simple" {
    try std.testing.expect(try parseFile("test/028_struct_fields_simple.zig"));
}

test "file 029_enum_fields" {
    try std.testing.expect(try parseFile("test/029_enum_fields.zig"));
}

test "file 030_nested_containers" {
    try std.testing.expect(try parseFile("test/030_nested_containers.zig"));
}

test "file 031_string_basic" {
    try std.testing.expect(try parseFile("test/031_string_basic.zig"));
}

test "file 032_string_escapes" {
    try std.testing.expect(try parseFile("test/032_string_escapes.zig"));
}

test "file 033_char_basic" {
    try std.testing.expect(try parseFile("test/033_char_basic.zig"));
}

test "file 034_char_escape_quote" {
    try std.testing.expect(try parseFile("test/034_char_escape_quote.zig"));
}

test "file 035_var_string_init" {
    try std.testing.expect(try parseFile("test/035_var_string_init.zig"));
}

test "file 036_call_with_string_arg" {
    try std.testing.expect(try parseFile("test/036_call_with_string_arg.zig"));
}

test "file 037_char_in_expr" {
    try std.testing.expect(try parseFile("test/037_char_in_expr.zig"));
}

test "file 038_return_error_union" {
    try std.testing.expect(try parseFile("test/038_return_error_union.zig"));
}

test "file 039_param_error_union" {
    try std.testing.expect(try parseFile("test/039_param_error_union.zig"));
}

test "file 040_nested_error_union" {
    try std.testing.expect(try parseFile("test/040_nested_error_union.zig"));
}

test "file 041_if_simple" {
    try std.testing.expect(try parseFile("test/041_if_simple.zig"));
}

test "file 042_if_else" {
    try std.testing.expect(try parseFile("test/042_if_else.zig"));
}

test "file 043_while_simple" {
    try std.testing.expect(try parseFile("test/043_while_simple.zig"));
}

test "file 044_while_else" {
    try std.testing.expect(try parseFile("test/044_while_else.zig"));
}

test "file 045_for_simple" {
    try std.testing.expect(try parseFile("test/045_for_simple.zig"));
}

test "file 046_if_expr_value" {
    try std.testing.expect(try parseFile("test/046_if_expr_value.zig"));
}

test "file 047_while_expr_else" {
    try std.testing.expect(try parseFile("test/047_while_expr_else.zig"));
}

test "file 048_for_expr_else" {
    try std.testing.expect(try parseFile("test/048_for_expr_else.zig"));
}

test "file 049_switch_expr_minimal" {
    try std.testing.expect(try parseFile("test/049_switch_expr_minimal.zig"));
}

test "file 050_break_continue" {
    try std.testing.expect(try parseFile("test/050_break_continue.zig"));
}

test "file 051_switch_stmt_no_semicolon" {
    try std.testing.expect(try parseFile("test/051_switch_stmt_no_semicolon.zig"));
}

test "file 052_if_assign_semicolon" {
    try std.testing.expect(try parseFile("test/052_if_assign_semicolon.zig"));
}

test "file 053_while_assign_semicolon" {
    try std.testing.expect(try parseFile("test/053_while_assign_semicolon.zig"));
}

test "file 054_for_assign_semicolon" {
    try std.testing.expect(try parseFile("test/054_for_assign_semicolon.zig"));
}

test "file 055_if_payload_expr" {
    try std.testing.expect(try parseFile("test/055_if_payload_expr.zig"));
}

test "file 056_while_payload_else_expr" {
    try std.testing.expect(try parseFile("test/056_while_payload_else_expr.zig"));
}

test "file 057_for_payload_expr" {
    try std.testing.expect(try parseFile("test/057_for_payload_expr.zig"));
}

test "file 058_switch_index_payload" {
    try std.testing.expect(try parseFile("test/058_switch_index_payload.zig"));
}

test "expr: catch operator basic" {
    try std.testing.expect(try parseZigMini("fn f() void { x = y catch z; }\n"));
}

test "expr: catch with payload" {
    try std.testing.expect(try parseZigMini("fn f() void { x = y catch |e| z; }\n"));
}

test "spacing: operators without spaces" {
    try std.testing.expect(try parseZigMini("fn f() void {x=1+2*3;}\n"));
}

test "spacing: catch without space before payload" {
    try std.testing.expect(try parseZigMini("fn f() void {x=y catch|e|z;}\n"));
}

test "keyword boundary: orelse not inside identifier" {
    // This should parse as a single identifier, not as an operator.
    try std.testing.expect(try parseZigMini("fn f() void { xorelsey; }\n"));
}

test "suffix: member access" {
    try std.testing.expect(try parseZigMini("fn f() void { x = a.b; }\n"));
}

test "suffix: index access" {
    try std.testing.expect(try parseZigMini("fn f() void { x = a[0]; }\n"));
}

test "suffix: slice simple" {
    try std.testing.expect(try parseZigMini("fn f() void { x = a[0..n]; }\n"));
}

test "suffix: slice with stride" {
    try std.testing.expect(try parseZigMini("fn f() void { x = a[0..10:2]; }\n"));
}

test "suffix: slice open end" {
    try std.testing.expect(try parseZigMini("fn f() void { x = a[0..]; }\n"));
}

test "suffix: optional unwrap" {
    try std.testing.expect(try parseZigMini("fn f() void { x = y.?; }\n"));
}

test "suffix: deref" {
    try std.testing.expect(try parseZigMini("fn f() void { x = y.*; }\n"));
}

test "suffix: call chain" {
    try std.testing.expect(try parseZigMini("fn f() void { x = a.b(1,2)[1..n].* .? .c(); }\n"));
}

test "suffix: builtin call then chain" {
    try std.testing.expect(try parseZigMini("fn f() void { x = @foo()(1)[0].bar; }\n"));
}

test "switch: range prong" {
    const src =
        "fn f() void {\n" ++
        "  const x = 0;\n" ++
        "  switch (x) { 0...9 => 1, else => 0 }\n" ++
        "}\n";
    try std.testing.expect(try parseZigMini(src));
}

test "for: range single item and payload" {
    const src =
        "fn f() void {\n" ++
        "  for (0..10) |i| { }\n" ++
        "}\n";
    try std.testing.expect(try parseZigMini(src));
}

test "for: multiple items with payload list" {
    const src =
        "fn f() void {\n" ++
        "  for (0..10, 0..n,) |i, j| { }\n" ++
        "}\n";
    try std.testing.expect(try parseZigMini(src));
}

test "for: open-ended range item" {
    const src =
        "fn f() void {\n" ++
        "  for (0..) |i| { }\n" ++
        "}\n";
    try std.testing.expect(try parseZigMini(src));
}

test "while: continue expression with block" {
    const src =
        "fn f() void {\n" ++
        "  while (x) : (i = i + 1) { break; }\n" ++
        "}\n";
    try std.testing.expect(try parseZigMini(src));
}

test "while: continue expression with assign branch" {
    const src =
        "fn f() void {\n" ++
        "  while (x) : (i = i + 1) y = z;\n" ++
        "}\n";
    try std.testing.expect(try parseZigMini(src));
}

test "error: literal as expr" {
    try std.testing.expect(try parseZigMini("fn f() void { const x = error.Foo; }\n"));
}

test "error: literal with catch" {
    try std.testing.expect(try parseZigMini("fn f() void { x = y catch error.Fail; }\n"));
}

test "error: set decl in return type" {
    const src = "fn f() error{A,B}!T { return; }\n";
    try std.testing.expect(try parseZigMini(src));
}

test "error: set decl in param type" {
    const src = "fn f(e: error{ A, B, }) void {}\n";
    try std.testing.expect(try parseZigMini(src));
}

test "labels: labeled block with break value" {
    const src =
        "fn f() void {\n" ++
        "  blk: { break :blk 1; }\n" ++
        "}\n";
    try std.testing.expect(try parseZigMini(src));
}

test "labels: while labeled and continue/break labels" {
    const src =
        "fn f() void {\n" ++
        "  outer: while (0) { continue :outer; break :outer; }\n" ++
        "}\n";
    try std.testing.expect(try parseZigMini(src));
}

test "labels: for labeled and continue label" {
    const src =
        "fn f() void {\n" ++
        "  outer: for (0..10) |i| { continue :outer; }\n" ++
        "}\n";
    try std.testing.expect(try parseZigMini(src));
}

test "abi: extern fn with attrs" {
    const src =
        "extern \"c\" fn f(a: i32) align(4) addrspace(0) linksection(\".text\") callconv(.C) void { }\n";
    try std.testing.expect(try parseZigMini(src));
}

test "fn: inferred error set return" {
    try std.testing.expect(try parseZigMini("fn f() !u32 { return; }\n"));
}

test "abi: export threadlocal global with type and attrs" {
    const src =
        "export threadlocal const x: i32 align(16) addrspace(1) linksection(\".data\") = 0;\n";
    try std.testing.expect(try parseZigMini(src));
}

test "toplevel: test and comptime blocks" {
    const src =
        "test \"name\" { defer {} }\n" ++
        "comptime { var a = 1; }\n";
    try std.testing.expect(try parseZigMini(src));
}

test "stmt: defer, errdefer, suspend, nosuspend" {
    const src =
        "fn f() void {\n" ++
        "  defer { }\n" ++
        "  errdefer |e| { }\n" ++
        "  suspend { }\n" ++
        "  nosuspend { }\n" ++
        "}\n";
    try std.testing.expect(try parseZigMini(src));
}

test "switch: inline prong single item" {
    const src =
        "fn f() void {\n" ++
        "  const x = 0;\n" ++
        "  switch (x) { inline 1 => 2, else => 3 }\n" ++
        "}\n";
    try std.testing.expect(try parseZigMini(src));
}

test "switch: multiple items with range" {
    const src =
        "fn f() void {\n" ++
        "  const x = 0;\n" ++
        "  switch (x) { 0, 2...4, 9 => 1, else => 0 }\n" ++
        "}\n";
    try std.testing.expect(try parseZigMini(src));
}
