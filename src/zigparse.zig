const std = @import("std");

comptime {
    @setEvalBranchQuota(200000);
}
const pegvm = @import("pegvm.zig");

const VM = pegvm.VM;
const Combinators = pegvm.Combinators;
const ascii = pegvm.ascii;

pub const ZigMiniGrammar = struct {
    // It's very important that some rules have explicit [N]Op return types.
    // In fact, the compiler usually crashes without them.
    //
    // The byte offset to each rule must be clear to the compiler,
    // since we take their addresses.
    //
    // By putting the main recursion targets above the rules that call them,
    // sized explicitly, we can use type inference for the others.

    const C = Combinators(@This());
    const Op = C.Op;
    const one = C.call;
    const opt = C.opt;
    const star = C.star;
    const alt = C.anyOf;

    fn rule(x: anytype) [x.len + 1]Op {
        return x ++ C.ret;
    }

    pub const Statement: C.Annotated(29) = C.node(rule(
        alt(.{
            one(&IfStatement),
            one(&LabeledWhileStatement),
            one(&LabeledForStatement),
            one(&SwitchExpr),
            one(&DeferStatement),
            one(&ErrDeferStatement),
            one(&NoSuspendStatement),
            one(&SuspendStatement),
            one(&VarDeclExprStatement),
            one(&BlockExprStatement),
        }),
    ));

    pub const Block: C.Annotated(24) = C.node(rule(
        @"{" ++ star(one(&Statement)) ++ @"}",
    ));

    pub const Expr: C.Annotated(6) = C.silent(rule(
        one(&BoolAndExpr) ++
            star(one(&BoolOrOp) ++ one(&BoolAndExpr)),
    ));

    pub const TypeAtom: C.Annotated(8) = C.node(rule(
        alt(.{
            one(&Identifier),
            one(&ContainerExpr),
            one(&ErrorSetDecl),
        }),
    ));

    pub const TypeExpr: C.Annotated(19) =
        C.node(rule(one(&TypeCore) ++ opt(@"!" ++ one(&TypeExpr))));

    pub const Identifier = C.node(rule(C.shun(reserved_exact) ++ alpha ++ star(alnum_us) ++ skip));

    pub const BuiltinIdentifier = C.node(rule(C.char('@') ++ alpha ++ star(alnum_us)));

    pub const Integer = C.node(rule(C.several(digit) ++ skip));

    pub const IdentifierList = C.node(rule(
        one(&Identifier) ++
            star(@"," ++ one(&Identifier)) ++
            opt(@","),
    ));

    pub const ErrorSetDecl = C.node(rule(@"error" ++ @"{" ++ opt(one(&IdentifierList)) ++ @"}"));

    pub const AssignExpr = C.node(rule(
        alt(.{
            one(&Identifier) ++ @"=" ++ one(&Expr),
            one(&Expr),
        }),
    ));

    pub const ExprList = C.node(rule(
        one(&Expr) ++
            star(@"," ++ one(&Expr)),
    ));

    pub const ArrayStart = C.node(rule(@"[" ++ one(&Expr) ++ @"]"));

    pub const TypePrefix = C.node(rule(
        alt(.{
            @"?",
            @"*",
            one(&ArrayStart),
            @"[" ++ @"]",
        }),
    ));

    pub const TypeCore = C.node(rule(star(one(&TypePrefix)) ++ one(&TypeAtom)));

    pub const FieldDecl = C.node(rule(
        one(&Identifier) ++ @":" ++ one(&TypeExpr),
    ));

    pub const FieldList = C.node(rule(
        one(&FieldDecl) ++
            star(C.seq(.{ @",", one(&FieldDecl) })) ++
            opt(@","),
    ));

    pub const StructBody = C.node(rule(
        @"{" ++ opt(one(&FieldList)) ++ @"}",
    ));

    pub const EnumFields = C.node(rule(
        one(&Identifier) ++
            star(C.seq(.{ @",", one(&Identifier) })) ++
            opt(@","),
    ));

    pub const EnumBody = C.node(rule(
        @"{" ++ opt(one(&EnumFields)) ++ @"}",
    ));

    pub const ContainerExpr = C.node(rule(
        alt(.{
            C.seq(.{ @"struct", one(&StructBody) }),
            C.seq(.{ @"union", one(&StructBody) }),
            C.seq(.{ @"enum", one(&EnumBody) }),
        }),
    ));

    pub const ParenExpr = C.node(rule(@"(" ++ one(&Expr) ++ @")"));

    pub const LinkSection = C.node(rule(@"linksection" ++ one(&ParenExpr)));
    pub const AddrSpace = C.node(rule(@"addrspace" ++ one(&ParenExpr)));
    pub const CallConv = C.node(rule(@"callconv" ++ one(&ParenExpr)));
    pub const ByteAlign = C.node(rule(@"align" ++ one(&ParenExpr)));

    pub const ErrorLiteral = C.node(rule(@"error" ++ @"." ++ one(&Identifier)));

    pub const DotIdentifier = C.node(rule(@"." ++ one(&Identifier)));

    pub const CharLiteral = C.node(rule(
        C.char('\'') ++
            alt(.{ chr_escape, chr_plain }) ++
            C.char('\'') ++
            skip,
    ));

    pub const StringLiteral = C.node(rule(
        C.char('"') ++
            star(alt(.{ str_escape, str_plain })) ++
            C.char('"') ++
            skip,
    ));

    pub const Primary: C.Annotated(50) = C.node(rule(
        alt(.{
            one(&ParenExpr),
            one(&Block),
            one(&IfExpr),
            one(&WhileExprE),
            one(&ForExprE),
            one(&SwitchExpr),
            one(&ReturnExpr),
            one(&BreakExpr),
            one(&ContinueExpr),
            one(&ContainerExpr),
            one(&BuiltinIdentifier),
            one(&ErrorLiteral),
            one(&DotIdentifier),
            one(&Integer),
            one(&StringLiteral),
            one(&CharLiteral),
            one(&Identifier),
        }),
    ));

    pub const FnCallArguments =
        rule(@"(" ++ opt(one(&ExprList)) ++ @")");

    pub const MemberAccess = C.node(rule(@"." ++ one(&Identifier)));

    const sliceSuffix =
        @".." ++ opt(one(&Expr)) ++ opt(@":" ++ one(&Expr));

    pub const IndexOrSlice = C.node(rule(
        @"[" ++ one(&Expr) ++ opt(sliceSuffix) ++ @"]",
    ));

    pub const OneSuffix = C.node(rule(
        alt(.{
            one(&FnCallArguments),
            one(&IndexOrSlice),
            @".*",
            @".?",
            one(&MemberAccess),
        }),
    ));

    pub const SuffixExpr = C.silent(rule(
        one(&Primary) ++ star(one(&OneSuffix)),
    ));

    pub const ReturnExpr = C.node(rule(@"return" ++ opt(one(&Expr))));

    pub const LabelRef = C.node(rule(@":" ++ one(&Identifier)));
    pub const LabelDef = C.node(rule(one(&Identifier) ++ @":"));

    pub const BreakExpr = C.node(rule(
        @"break" ++ opt(one(&LabelRef)) ++ opt(one(&Expr)),
    ));

    pub const ContinueExpr = C.node(rule(@"continue" ++ opt(one(&LabelRef))));

    pub const PtrPayload = C.node(rule(
        @"|" ++ opt(@"*") ++ one(&Identifier) ++ @"|",
    ));

    pub const PtrIndexPayload = C.node(rule(
        @"|" ++
            opt(@"*") ++ one(&Identifier) ++
            opt(@"," ++ one(&Identifier)) ++
            @"|",
    ));

    pub const PtrListPayload = C.node(rule(
        @"|" ++
            opt(@"*") ++ one(&Identifier) ++
            star(@"," ++ opt(@"*") ++ one(&Identifier)) ++
            opt(@",") ++
            @"|",
    ));

    pub const Payload = C.node(rule(@"|" ++ one(&Identifier) ++ @"|"));

    pub const PayloadExpr = C.node(rule(
        opt(one(&PtrPayload)) ++ one(&Expr),
    ));

    pub const IfExpr = C.node(rule(
        @"if" ++ @"(" ++ one(&Expr) ++ @")" ++
            one(&PayloadExpr) ++
            @"else" ++ one(&Expr),
    ));

    pub const WhileContinueExpr = C.node(rule(@":" ++ @"(" ++ one(&AssignExpr) ++ @")"));

    pub const WhileExprE = C.node(rule(
        @"while" ++ one(&ParenExpr) ++
            opt(one(&PtrPayload)) ++
            opt(one(&WhileContinueExpr)) ++
            one(&Block) ++
            opt(@"else" ++ one(&Expr)),
    ));

    pub const ForItem = C.node(rule(
        one(&Expr) ++ opt(@".." ++ opt(one(&Expr))),
    ));

    pub const ForArgumentsList = C.node(rule(
        one(&ForItem) ++
            star(@"," ++ one(&ForItem)) ++
            opt(@","),
    ));

    pub const ForExprE = C.node(rule(
        @"for" ++ @"(" ++ one(&ForArgumentsList) ++ @")" ++
            opt(one(&PtrListPayload)) ++
            one(&Block) ++
            opt(@"else" ++ one(&Expr)),
    ));

    pub const CaseItem = C.node(rule(
        one(&Expr) ++ opt(@"..." ++ one(&Expr)),
    ));

    pub const ElseProng = C.node(rule(
        @"else" ++ @"=>" ++ opt(one(&PtrIndexPayload)) ++ one(&Expr),
    ));

    pub const CaseProng = C.node(rule(
        opt(@"inline") ++
            one(&CaseItem) ++
            star(@"," ++ one(&CaseItem)) ++
            @"=>" ++
            opt(one(&PtrIndexPayload)) ++
            one(&Expr),
    ));

    pub const Prong = C.node(rule(
        alt(.{
            one(&ElseProng),
            one(&CaseProng),
        }),
    ));

    pub const SwitchBody = C.node(rule(
        @"{" ++
            opt(one(&Prong) ++
                star(@"," ++ one(&Prong))) ++
            @"}",
    ));

    pub const SwitchExpr = C.node(rule(
        @"switch" ++ one(&ParenExpr) ++ one(&SwitchBody),
    ));

    pub const PrefixOp = C.node(rule(alt(.{ @"!", @"-", @"~", @"-%", @"&", @"try" })));

    pub const PrefixExpr = C.silent(rule(
        star(one(&PrefixOp)) ++
            one(&SuffixExpr),
    ));

    pub const MultiplyOp = C.node(rule(alt(.{ @"*", @"/", @"%" })));

    pub const MultiplyExpr = C.silent(rule(
        one(&PrefixExpr) ++
            star(one(&MultiplyOp) ++ one(&PrefixExpr)),
    ));

    pub const AddOp = C.node(rule(alt(.{ @"+", @"-" })));

    pub const AddExpr = C.silent(rule(
        one(&MultiplyExpr) ++ star(
            one(&AddOp) ++ one(&MultiplyExpr),
        ),
    ));

    pub const BitShiftOp = C.node(rule(alt(.{ @"<<", @">>" })));

    pub const BitShiftExpr = C.silent(rule(
        one(&AddExpr) ++ star(
            one(&BitShiftOp) ++ one(&AddExpr),
        ),
    ));

    pub const BitwiseOp = C.node(rule(alt(.{
        @"&",
        @"^",
        @"|",
        @"orelse",
        @"catch" ++ opt(one(&Payload)),
    })));

    pub const BitwiseExpr = C.silent(rule(
        one(&BitShiftExpr) ++
            star(
                one(&BitwiseOp) ++
                    one(&BitShiftExpr),
            ),
    ));

    pub const CompareOp = C.node(rule(alt(.{ @"==", @"!=", @"<=", @">=", @"<", @">" })));

    pub const CompareExpr = C.silent(rule(
        one(&BitwiseExpr) ++
            opt(
                one(&CompareOp) ++
                    one(&BitwiseExpr),
            ),
    ));

    pub const BoolAndOp = C.node(rule(@"and"));
    pub const BoolOrOp = C.node(rule(@"or"));

    pub const BoolAndExpr = C.silent(rule(
        one(&CompareExpr) ++
            star(one(&BoolAndOp) ++ one(&CompareExpr)),
    ));

    pub const CallExpr = C.node(rule(
        alt(.{ one(&Identifier), one(&BuiltinIdentifier) }) ++
            @"(" ++
            opt(one(&ExprList)) ++
            @")",
    ));

    pub const Param = C.node(rule(
        one(&Identifier) ++ @":" ++ one(&TypeExpr),
    ));

    pub const ParamList = C.node(rule(
        one(&Param) ++
            star(@"," ++ one(&Param)),
    ));

    pub const ReturnStmt = C.node(rule(
        @"return" ++ opt(one(&Expr)),
    ));

    pub const VarDecl = C.node(rule(
        alt(.{ @"const", @"var" }) ++
            one(&Identifier) ++
            opt(@"=" ++ one(&Expr)),
    ));

    pub const BlockExpr = C.node(rule(
        opt(one(&LabelDef)) ++ one(&Block),
    ));

    pub const BlockExprStatement = C.node(rule(
        alt(.{
            one(&BlockExpr),
            one(&AssignExpr) ++ @";",
        }),
    ));

    pub const VarDeclExprStatement = C.node(rule(
        alt(.{
            one(&VarDecl) ++ @";",
            one(&Expr) ++ @";",
        }),
    ));

    pub const Else = C.node(rule(
        @"else" ++ opt(one(&PtrPayload)) ++ one(&Statement),
    ));

    pub const IfStatement = C.node(rule(
        @"if" ++ @"(" ++ one(&Expr) ++ @")" ++ opt(one(&PtrPayload)) ++ alt(.{
            one(&BlockExpr) ++ opt(one(&Else)),
            one(&AssignExpr) ++ alt(.{ @";", one(&Else) }),
        }),
    ));

    pub const WhileStatement = C.node(rule(
        @"while" ++ @"(" ++ one(&Expr) ++ @")" ++
            opt(one(&PtrPayload)) ++
            opt(one(&WhileContinueExpr)) ++
            alt(.{
                one(&BlockExpr) ++ opt(one(&Else)),
                one(&AssignExpr) ++ alt(.{ @";", one(&Else) }),
            }),
    ));

    pub const LabeledWhileStatement = C.node(rule(
        opt(one(&LabelDef)) ++ one(&WhileStatement),
    ));

    pub const ForStatement = C.node(rule(
        @"for" ++ @"(" ++ one(&ForArgumentsList) ++ @")" ++
            opt(one(&PtrListPayload)) ++
            alt(.{
                one(&BlockExpr),
                one(&AssignExpr) ++ @";",
            }),
    ));

    pub const LabeledForStatement = C.node(rule(
        opt(one(&LabelDef)) ++ one(&ForStatement),
    ));

    pub const DeferStatement = C.node(rule(
        @"defer" ++ one(&BlockExprStatement),
    ));
    pub const ErrDeferStatement = C.node(rule(
        @"errdefer" ++ opt(one(&Payload)) ++ one(&BlockExprStatement),
    ));
    pub const NoSuspendStatement = C.node(rule(
        @"nosuspend" ++ one(&BlockExprStatement),
    ));
    pub const SuspendStatement = C.node(rule(
        @"suspend" ++ one(&BlockExprStatement),
    ));

    pub const FnDecl = C.node(rule(
        opt(@"pub") ++
            opt(alt(.{
                @"export",
                @"extern" ++ opt(one(&StringLiteral)),
                @"inline",
                @"noinline",
            })) ++
            @"fn" ++
            one(&Identifier) ++
            @"(" ++
            opt(one(&ParamList)) ++
            @")" ++
            opt(one(&ByteAlign)) ++
            opt(one(&AddrSpace)) ++
            opt(one(&LinkSection)) ++
            opt(one(&CallConv)) ++
            opt(@"!") ++
            one(&TypeExpr) ++
            one(&Block),
    ));

    pub const VarDeclProto = C.node(rule(
        alt(.{ @"const", @"var" }) ++
            one(&Identifier) ++
            opt(@":" ++ one(&TypeExpr)) ++
            opt(one(&ByteAlign)) ++
            opt(one(&AddrSpace)) ++
            opt(one(&LinkSection)),
    ));

    pub const GlobalVarDecl = rule(
        one(&VarDeclProto) ++
            opt(@"=" ++ one(&Expr)) ++
            @";",
    );

    pub const TopVarDecl = C.node(rule(
        opt(@"pub") ++
            opt(alt(.{
                @"export",
                @"extern" ++ opt(one(&StringLiteral)),
            })) ++
            opt(@"threadlocal") ++
            one(&GlobalVarDecl),
    ));

    pub const TestDecl = C.node(rule(
        @"test" ++
            opt(alt(.{
                one(&StringLiteral),
                one(&Identifier),
            })) ++
            one(&Block),
    ));

    pub const ComptimeDecl = C.node(rule(
        @"comptime" ++ one(&Block),
    ));

    pub const start = C.node(rule(
        skip ++
            star(alt(.{
                one(&FnDecl),
                one(&TopVarDecl),
                one(&TestDecl),
                one(&ComptimeDecl),
            })) ++
            C.eof ++
            C.ok,
    ));

    const chr_escape =
        @"\\" ++ C.charclass("nr't\\\"");
    const chr_plain =
        C.charclass(.{
            ascii[' ' .. '&' + 1],
            ascii['(' .. '[' + 1],
            ascii[']' .. '~' + 1],
        });

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
    const str_escape =
        @"\\" ++ C.charclass("nr\"t\\");
    const str_plain =
        C.charclass(.{
            ascii[' ' .. '!' + 1],
            ascii['#' .. '[' + 1],
            ascii[']' .. '~' + 1],
        });

    const line_comment =
        C.text("//") ++ star(not_nl_ascii);

    const skip: [9]Op =
        star(alt(.{ C.charclass(" \t\n\r"), line_comment }));

    fn kw(name: []const u8) [14]Op {
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

    fn op(s: []const u8, neg: []const u8) [if (neg.len == 0) 10 else 14]Op {
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

    fn ident(name: []const u8) [5]Op {
        return C.text(name) ++ ident_boundary;
    }

    const reserved_exact = alt(.{
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
};

pub const ZigMiniParser = VM(ZigMiniGrammar, 1024, 256);

pub fn parseZigMini(src: [:0]const u8) !bool {
    return ZigMiniParser.parseFully(std.testing.allocator, src, .auto_continue);
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
