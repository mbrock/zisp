// TODO: ZigMiniGrammar Roadmap (tracked subset)
// [x] Comments in whitespace (// line)
// [x] Keyword filtering for identifiers
// [x] Call arguments and ExprList
// [x] Assignment and arithmetic ops (+,-,*,/,%)
// [x] TypeExpr: ?, *, []T, [N]T; error unions (A!B)
// [x] Top-level decls: const/var (optional pub)
// [x] Containers: struct/union/enum (simple bodies)
// [x] Strings and char literals
// [x] Control flow as statements and expressions: if/while/for, switch
// [x] Payloads: if/while/for (ptr, list), switch prong index
// [x] Harmonize stmt/expr structure with official grammar (BlockExprStatement, VarDeclExprStatement)
// [x] Builtins and @identifiers
// [x] Operator/precedence: full layers incl. try/orelse/catch
// [x] Suffix ops and chains: call, member, index/slice, .*, .?
// [ ] Switch: ranges (a...b) and inline prongs
// [ ] For/while: full argument forms, continue expressions
// [ ] Error sets and error literals (error.Foo, error { ... })
// [ ] Labels and break/continue values (e.g. break :blk expr)
// [ ] Visibility/ABI extras (extern/threadlocal/addrspace/linksection)
// [ ] test/comptime blocks; defer/errdefer/suspend/nosuspend
// [ ] String/char literal completeness (unicode, multiline)
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

    const alpha = C.charclass(.{ ascii['a' .. 'z' + 1], ascii['A' .. 'Z' + 1], "_" });
    const digit = C.charclass(ascii['0' .. '9' + 1]);
    const alnum_us = C.charclass(.{
        ascii['a' .. 'z' + 1], ascii['A' .. 'Z' + 1], ascii['0' .. '9' + 1], "_",
    });

    const not_nl_ascii = C.charclass(.{ ascii[' ' .. '~' + 1], '\t', '\r' });
    const line_comment = C.text("//") ++ C.zeroOrMany(not_nl_ascii);
    const WS = C.zeroOrMany(C.anyOf(.{ C.charclass(" \t\n\r"), line_comment }));

    fn kw(name: []const u8) [14]C.Op {
        return C.text(name) ++ ident_boundary ++ WS;
    }

    const kw_fn = kw("fn");
    const kw_pub = kw("pub");
    const kw_return = kw("return");
    const kw_const = kw("const");
    const kw_var = kw("var");
    const kw_export = kw("export");
    const kw_extern = kw("extern");
    const kw_threadlocal = kw("threadlocal");
    const kw_addrspace = kw("addrspace");
    const kw_linksection = kw("linksection");
    const kw_callconv = kw("callconv");
    const kw_align = kw("align");
    const kw_if = kw("if");
    const kw_comptime = kw("comptime");
    const kw_test = kw("test");
    const kw_else = kw("else");
    const kw_while = kw("while");
    const kw_for = kw("for");
    const kw_switch = kw("switch");
    const kw_break = kw("break");
    const kw_continue = kw("continue");
    const kw_defer = kw("defer");
    const kw_errdefer = kw("errdefer");
    const kw_suspend = kw("suspend");
    const kw_nosuspend = kw("nosuspend");
    const kw_struct = kw("struct");
    const kw_union = kw("union");
    const kw_enum = kw("enum");
    const kw_noinline = kw("noinline");
    const kw_and = kw("and");
    const kw_or = kw("or");
    const kw_orelse = kw("orelse");
    const kw_try = kw("try");
    const kw_catch = kw("catch");
    const kw_inline = kw("inline");
    const kwt_and = kw("and");
    const kwt_or = kw("or");
    const kwt_orelse = kw("orelse");
    const kwt_try = kw("try");
    const kwt_catch = kw("catch");
    const kwt_inline = kw("inline");
    const kwt_error = kw("error");

    // Punctuation
    const lparen = C.char('(') ++ WS;
    const rparen = C.char(')') ++ WS;
    const lbrace = C.char('{') ++ WS;
    const rbrace = C.char('}') ++ WS;
    const lbracket = C.char('[') ++ WS;
    const rbracket = C.char(']') ++ WS;
    const colon = C.char(':') ++ WS;
    const comma = C.char(',') ++ WS;
    const semicolon = C.char(';') ++ WS;
    const equal = C.char('=') ++ WS;
    const bang = C.char('!') ++ WS;
    const pipe_ch = C.char('|') ++ WS;
    const star_ch = C.char('*') ++ WS;
    const dot = C.char('.') ++ WS;
    const dot_asterisk = C.text(".*") ++ WS;
    const dot_question = C.text(".?") ++ WS;
    const backslash = C.char('\\') ++ WS;

    const T_LPAREN = lparen;
    const T_RPAREN = C.seq(.{ rparen, WS });
    const T_LBRACE = C.seq(.{ lbrace, WS });
    const T_RBRACE = C.seq(.{ rbrace, WS });
    const T_LBRACKET = C.seq(.{ lbracket, WS });
    const T_RBRACKET = C.seq(.{ rbracket, WS });
    const T_COLON = C.seq(.{ colon, WS });
    const T_COMMA = C.seq(.{ comma, WS });
    const T_SEMI = C.seq(.{ semicolon, WS });
    const T_EQUAL = C.seq(.{ equal, WS });
    const T_EQUALRARROW = C.seq(.{ C.text("=>"), WS });

    const not_char = C.notLookahead;
    const cc = C.charclass;
    const T_PLUS = C.seq(.{ C.char('+'), not_char(cc("%+=|")), WS });
    const T_MINUS = C.seq(.{ C.char('-'), not_char(cc("%=>|")), WS });
    const T_ASTERISK = C.seq(.{ C.char('*'), not_char(cc("*%=|")), WS });
    const T_SLASH = C.seq(.{ C.char('/'), not_char(cc("=")), WS });
    const T_PERCENT = C.seq(.{ C.char('%'), not_char(cc("=")), WS });
    const T_SHL = C.seq(.{ C.text("<<"), not_char(cc("=|")), WS });
    const T_SHR = C.seq(.{ C.text(">>"), not_char(cc("=")), WS });
    const T_AND = C.seq(.{ C.char('&'), not_char(cc("=")), WS });
    const T_XOR = C.seq(.{ C.char('^'), not_char(cc("=")), WS });
    const T_OR = C.seq(.{ C.char('|'), not_char(cc("|=")), WS });
    const T_EQEQ = C.seq(.{ C.text("=="), WS });
    const T_NEQ = C.seq(.{ C.text("!="), WS });
    const T_LTE = C.seq(.{ C.text("<="), WS });
    const T_GTE = C.seq(.{ C.text(">="), WS });
    const T_LT = C.seq(.{ C.char('<'), not_char(cc("<=")), WS });
    const T_GT = C.seq(.{ C.char('>'), not_char(cc(">=")), WS });
    const T_BANG = C.seq(.{ C.char('!'), not_char(cc("=")), WS });
    const T_TILDE = C.seq(.{ C.char('~'), WS });
    const T_MINUSP = C.seq(.{ C.text("-%"), not_char(cc("=")), WS });
    const T_AMP = C.seq(.{ C.char('&'), not_char(cc("=")), WS });

    const ident_boundary = C.notLookahead(alnum_us); // next is not [A-Za-z0-9_]
    const reserved_exact = C.anyOf(.{
        C.seq(.{ C.text("fn"), ident_boundary }),
        C.seq(.{ C.text("pub"), ident_boundary }),
        C.seq(.{ C.text("return"), ident_boundary }),
        C.seq(.{ C.text("const"), ident_boundary }),
        C.seq(.{ C.text("var"), ident_boundary }),
        C.seq(.{ C.text("break"), ident_boundary }),
        C.seq(.{ C.text("continue"), ident_boundary }),
        C.seq(.{ C.text("defer"), ident_boundary }),
        C.seq(.{ C.text("errdefer"), ident_boundary }),
        C.seq(.{ C.text("suspend"), ident_boundary }),
        C.seq(.{ C.text("nosuspend"), ident_boundary }),
        C.seq(.{ C.text("comptime"), ident_boundary }),
        C.seq(.{ C.text("test"), ident_boundary }),
        C.seq(.{ C.text("export"), ident_boundary }),
        C.seq(.{ C.text("extern"), ident_boundary }),
        C.seq(.{ C.text("threadlocal"), ident_boundary }),
        C.seq(.{ C.text("addrspace"), ident_boundary }),
        C.seq(.{ C.text("linksection"), ident_boundary }),
        C.seq(.{ C.text("callconv"), ident_boundary }),
        C.seq(.{ C.text("if"), ident_boundary }),
        C.seq(.{ C.text("else"), ident_boundary }),
        C.seq(.{ C.text("while"), ident_boundary }),
        C.seq(.{ C.text("for"), ident_boundary }),
        C.seq(.{ C.text("switch"), ident_boundary }),
        C.seq(.{ C.text("struct"), ident_boundary }),
        C.seq(.{ C.text("union"), ident_boundary }),
        C.seq(.{ C.text("enum"), ident_boundary }),
        C.seq(.{ C.text("and"), ident_boundary }),
        C.seq(.{ C.text("or"), ident_boundary }),
        C.seq(.{ C.text("orelse"), ident_boundary }),
        C.seq(.{ C.text("try"), ident_boundary }),
        C.seq(.{ C.text("catch"), ident_boundary }),
        C.seq(.{ C.text("noinline"), ident_boundary }),
        C.seq(.{ C.text("error"), ident_boundary }),
        C.seq(.{ C.text("inline"), ident_boundary }),
    });

    pub const Identifier = C.seq(.{
        C.notLookahead(reserved_exact),
        alpha,
        C.zeroOrMany(alnum_us),
        WS,
        C.ret,
    });

    const at_sign = C.char('@');

    pub const BuiltinIdentifier = C.seq(.{ at_sign, alpha, C.zeroOrMany(alnum_us), C.ret });
    pub const Integer = C.seq(.{ C.several(digit), WS, C.ret });

    pub const IdentifierList = C.seq(.{
        C.Call(.Identifier),
        C.zeroOrMany(C.seq(.{ comma, C.Call(.Identifier) })),
        C.maybe(comma),
        C.ret,
    });

    pub const ErrorSetDecl = C.seq(.{ kwt_error, lbrace, C.maybe(C.Call(.IdentifierList)), rbrace, C.ret });
    pub const TypeAtom = C.anyOf(.{ C.Call(.Identifier), C.Call(.ContainerExpr), C.Call(.ErrorSetDecl) }) ++ C.ret;

    const SliceStart = C.seq(.{ lbracket, rbracket });
    const ArrayStart = C.seq(.{ lbracket, C.Call(.Expr), rbracket });
    const BrackType = C.anyOf(.{ ArrayStart, SliceStart });

    const TypePrefix = C.anyOf(.{ C.char('?'), star: {
        const s = C.char('*');
        break :star s;
    }, BrackType });

    pub const TypeCore = C.seq(.{ C.zeroOrMany(TypePrefix), C.Call(.TypeAtom), C.ret });
    pub const ErrorUnionType = C.seq(.{
        C.Call(.TypeCore),
        C.maybe(C.seq(.{ bang, C.Call(.TypeExpr) })),
        C.ret,
    });
    pub const TypeExpr = C.seq(.{ C.Call(.ErrorUnionType), C.ret });

    const str_escape = C.seq(.{ backslash, C.charclass("nr\"t\\") });
    const str_plain = C.charclass(.{ ascii[' ' .. '!' + 1], ascii['#' .. '[' + 1], ascii[']' .. '~' + 1] });
    pub const StringLiteral = C.seq(.{ C.char('"'), C.zeroOrMany(C.anyOf(.{ str_escape, str_plain })), C.char('"'), WS, C.ret });

    const chr_escape = C.seq(.{ backslash, C.charclass("nr't\\\"") });
    const chr_plain = C.charclass(.{ ascii[' ' .. '&' + 1], ascii['(' .. '[' + 1], ascii[']' .. '~' + 1] });
    pub const CharLiteral = C.seq(.{ C.char('\''), C.anyOf(.{ chr_escape, chr_plain }), C.char('\''), WS, C.ret });

    pub const LinkSection = C.seq(.{ kw_linksection, lparen, C.Call(.Expr), rparen, C.ret });
    pub const AddrSpace = C.seq(.{ kw_addrspace, lparen, C.Call(.Expr), rparen, C.ret });
    pub const CallConv = C.seq(.{ kw_callconv, lparen, C.Call(.Expr), rparen, C.ret });
    pub const ByteAlign = C.seq(.{ kw_align, lparen, C.Call(.Expr), rparen, C.ret });

    pub const GroupedExpr = C.seq(.{ lparen, C.Call(.Expr), rparen, C.ret });

    pub const ErrorLiteral = C.seq(.{ kwt_error, dot, C.Call(.Identifier), C.ret });

    pub const DotIdentifier = C.seq(.{ dot, C.Call(.Identifier), C.ret });

    pub const Primary = C.anyOf(.{
        C.Call(.GroupedExpr),
        C.Call(.Block),
        C.Call(.IfExpr),
        C.Call(.WhileExprE),
        C.Call(.ForExprE),
        C.Call(.SwitchExpr),
        C.Call(.ReturnExpr),
        C.Call(.BreakExpr),
        C.Call(.ContinueExpr),
        C.Call(.ContainerExpr),
        C.Call(.BuiltinIdentifier),
        C.Call(.ErrorLiteral),
        C.Call(.DotIdentifier),
        C.Call(.Integer),
        C.Call(.StringLiteral),
        C.Call(.CharLiteral),
        C.Call(.Identifier),
    }) ++ C.ret;

    pub const FnCallArguments = C.seq(.{ T_LPAREN, C.maybe(C.Call(.ExprList)), T_RPAREN, C.ret });

    pub const MemberAccess = C.seq(.{ dot, C.Call(.Identifier), C.ret });

    const dots2 = C.text("..") ++ WS;
    pub const IndexOrSlice = C.seq(.{
        T_LBRACKET,
        C.Call(.Expr),
        C.maybe(C.seq(.{
            dots2,
            C.maybe(C.seq(.{
                C.maybe(C.Call(.Expr)),
                C.maybe(C.seq(.{ colon, C.Call(.Expr) })),
            })),
        })),
        T_RBRACKET,
        C.ret,
    });

    pub const OneSuffix = C.anyOf(.{
        C.Call(.FnCallArguments),
        C.Call(.IndexOrSlice),
        dot_asterisk,
        dot_question,
        C.Call(.MemberAccess),
    }) ++ C.ret;

    pub const SuffixExpr = C.seq(.{
        C.Call(.Primary),
        C.zeroOrMany(C.Call(.OneSuffix)),
        C.ret,
    });

    pub const ReturnExpr = C.seq(.{ kw_return, C.maybe(C.Call(.Expr)), C.ret });

    pub const BreakLabel = C.seq(.{ colon, C.Call(.Identifier), C.ret });
    pub const BlockLabel = C.seq(.{ C.Call(.Identifier), colon, C.ret });

    pub const BreakExpr = C.seq(.{
        kw_break,
        C.maybe(C.anyOf(.{
            C.seq(.{ C.Call(.BreakLabel), C.maybe(C.Call(.Expr)) }),
            C.Call(.Expr),
        })),
        C.ret,
    });

    pub const ContinueExpr = C.seq(.{ kw_continue, C.maybe(C.Call(.BreakLabel)), C.ret });

    pub const IfExpr = C.seq(.{
        kw_if,                        lparen,        C.Call(.Expr),                                                             rparen,
        C.maybe(C.Call(.PtrPayload)), C.Call(.Expr), C.maybe(C.seq(.{ kw_else, C.maybe(C.Call(.PtrPayload)), C.Call(.Expr) })), C.ret,
    });

    pub const WhileContinueExpr = C.seq(.{ colon, lparen, C.Call(.AssignExpr), rparen, C.ret });

    pub const WhileExprE = C.seq(.{
        kw_while,                     lparen,                              C.Call(.Expr),  rparen,
        C.maybe(C.Call(.PtrPayload)), C.maybe(C.Call(.WhileContinueExpr)), C.Call(.Block), C.maybe(C.seq(.{ kw_else, C.maybe(C.Call(.PtrPayload)), C.Call(.Expr) })),
        C.ret,
    });

    pub const ForItem = C.seq(.{
        C.Call(.Expr),
        C.maybe(C.seq(.{ dots2, C.maybe(C.Call(.Expr)) })),
        C.ret,
    });

    pub const ForArgumentsList = C.seq(.{
        C.Call(.ForItem),
        C.zeroOrMany(C.seq(.{ comma, C.Call(.ForItem) })),
        C.maybe(comma),
        C.ret,
    });

    pub const ForExprE = C.seq(.{
        kw_for,                           lparen,         C.Call(.ForArgumentsList),                                                     rparen,
        C.maybe(C.Call(.PtrListPayload)), C.Call(.Block), C.maybe(C.seq(.{ kw_else, C.maybe(C.Call(.PtrListPayload)), C.Call(.Expr) })), C.ret,
    });

    const dots3 = C.text("...") ++ WS;
    pub const SwitchCaseItem = C.seq(.{
        C.Call(.Expr),
        C.maybe(C.seq(.{ dots3, C.Call(.Expr) })),
        C.ret,
    });

    pub const PtrPayload = C.seq(.{
        pipe_ch, C.maybe(star_ch), C.Call(.Identifier), pipe_ch, C.ret,
    });
    pub const PtrIndexPayload = C.seq(.{
        pipe_ch,                                         C.maybe(star_ch), C.Call(.Identifier),
        C.maybe(C.seq(.{ comma, C.Call(.Identifier) })), pipe_ch,          C.ret,
    });

    pub const PtrListPayload = C.seq(.{
        pipe_ch,                                                                C.maybe(star_ch), C.Call(.Identifier),
        C.zeroOrMany(C.seq(.{ comma, C.maybe(star_ch), C.Call(.Identifier) })), C.maybe(comma),   pipe_ch,
        C.ret,
    });

    pub const Payload = C.seq(.{ pipe_ch, C.Call(.Identifier), pipe_ch, C.ret });

    pub const SwitchProngElse = C.seq(.{ kw_else, T_EQUALRARROW, C.maybe(C.Call(.PtrIndexPayload)), C.Call(.Expr), C.ret });
    pub const SwitchProngCase = C.seq(.{
        C.maybe(kwt_inline),
        C.Call(.SwitchCaseItem),
        C.zeroOrMany(C.seq(.{ comma, C.Call(.SwitchCaseItem) })),
        T_EQUALRARROW,
        C.maybe(C.Call(.PtrIndexPayload)),
        C.Call(.Expr),
        C.ret,
    });

    pub const SwitchProng = C.anyOf(.{ C.Call(.SwitchProngElse), C.Call(.SwitchProngCase) }) ++ C.ret;

    pub const SwitchBody = C.seq(.{
        lbrace,
        C.maybe(C.seq(.{ C.Call(.SwitchProng), C.zeroOrMany(C.seq(.{ comma, C.Call(.SwitchProng) })) })),
        rbrace,
        C.ret,
    });

    pub const SwitchExpr = C.seq(.{
        kw_switch,           lparen, C.Call(.Expr), rparen, WS,
        C.Call(.SwitchBody), C.ret,
    });

    pub const FieldDecl = C.seq(.{ C.Call(.Identifier), T_COLON, C.Call(.TypeExpr), C.ret });
    pub const FieldList = C.seq(.{
        C.Call(.FieldDecl),
        C.zeroOrMany(C.seq(.{ comma, C.Call(.FieldDecl) })),
        C.maybe(comma),
        C.ret,
    });

    pub const StructBody = C.seq(.{
        lbrace, C.maybe(C.Call(.FieldList)), rbrace, C.ret,
    });

    pub const UnionBody = StructBody;

    pub const EnumFields = C.seq(.{
        C.Call(.Identifier),
        C.zeroOrMany(C.seq(.{ comma, C.Call(.Identifier) })),
        C.maybe(comma),
        C.ret,
    });

    pub const EnumBody = C.seq(.{ lbrace, C.maybe(C.Call(.EnumFields)), rbrace, C.ret });

    pub const ContainerExpr = C.anyOf(.{
        C.seq(.{ kw_struct, C.Call(.StructBody) }),
        C.seq(.{ kw_union, C.Call(.UnionBody) }),
        C.seq(.{ kw_enum, C.Call(.EnumBody) }),
    }) ++ C.ret;

    pub const PrefixExpr = C.seq(.{
        C.zeroOrMany(C.anyOf(.{ T_BANG, T_MINUS, T_TILDE, T_MINUSP, T_AMP, kwt_try })),
        C.Call(.SuffixExpr),
        C.ret,
    });

    pub const MultiplyExpr = C.seq(.{
        C.Call(.PrefixExpr),
        C.zeroOrMany(C.seq(.{ C.anyOf(.{ T_ASTERISK, T_SLASH, T_PERCENT }), C.Call(.PrefixExpr) })),
        C.ret,
    });

    pub const AddExpr = C.seq(.{
        C.Call(.MultiplyExpr),
        C.zeroOrMany(C.seq(.{ C.anyOf(.{ T_PLUS, T_MINUS }), C.Call(.MultiplyExpr) })),
        C.ret,
    });

    pub const BitShiftExpr = C.seq(.{
        C.Call(.AddExpr),
        C.zeroOrMany(C.seq(.{ C.anyOf(.{ T_SHL, T_SHR }), C.Call(.AddExpr) })),
        C.ret,
    });

    pub const BitwiseExpr = C.seq(.{
        C.Call(.BitShiftExpr),
        C.zeroOrMany(C.seq(.{
            C.anyOf(.{
                T_AND,
                T_XOR,
                T_OR,
                kwt_orelse,
                C.seq(.{ kwt_catch, C.maybe(C.Call(.Payload)) }),
            }),
            C.Call(.BitShiftExpr),
        })),
        C.ret,
    });

    pub const CompareExpr = C.seq(.{
        C.Call(.BitwiseExpr),
        C.maybe(C.seq(.{ C.anyOf(.{ T_EQEQ, T_NEQ, T_LTE, T_GTE, T_LT, T_GT }), C.Call(.BitwiseExpr) })),
        C.ret,
    });

    pub const BoolAndExpr = C.seq(.{
        C.Call(.CompareExpr),
        C.zeroOrMany(C.seq(.{ kwt_and, C.Call(.CompareExpr) })),
        C.ret,
    });

    pub const BoolOrExpr = C.seq(.{
        C.Call(.BoolAndExpr),
        C.zeroOrMany(C.seq(.{ kwt_or, C.Call(.BoolAndExpr) })),
        C.ret,
    });

    pub const Expr = C.seq(.{ C.Call(.BoolOrExpr), C.ret });

    pub const ExprList = C.seq(.{
        C.Call(.Expr),
        C.zeroOrMany(C.seq(.{ T_COMMA, C.Call(.Expr) })),
        C.ret,
    });

    pub const CallExpr = C.seq(.{
        C.anyOf(.{ C.Call(.Identifier), C.Call(.BuiltinIdentifier) }),
        lparen,
        C.maybe(C.Call(.ExprList)),
        rparen,
        C.ret,
    });

    pub const Param = C.seq(.{ C.Call(.Identifier), T_COLON, C.Call(.TypeExpr), C.ret });

    pub const ParamList = C.seq(.{
        C.Call(.Param),
        C.zeroOrMany(C.seq(.{ T_COMMA, C.Call(.Param) })),
        C.ret,
    });

    pub const ReturnStmt = C.seq(.{ kw_return, C.maybe(C.Call(.Expr)), C.ret });

    pub const VarDecl = C.seq(.{
        C.anyOf(.{ kw_const, kw_var }),
        C.Call(.Identifier),
        C.maybe(C.seq(.{ T_EQUAL, C.Call(.Expr) })),
        C.ret,
    });

    pub const AssignExpr = C.anyOf(.{
        C.seq(.{ C.Call(.Identifier), T_EQUAL, C.Call(.Expr) }),
        C.Call(.Expr),
    }) ++ C.ret;

    pub const IfStmt = C.seq(.{
        kw_if,          lparen,                                       C.Call(.Expr), rparen,
        C.Call(.Block), C.maybe(C.seq(.{ kw_else, C.Call(.Block) })), C.ret,
    });

    pub const WhileStmt = C.seq(.{
        kw_while,       lparen,                                       C.Call(.Expr), rparen,
        C.Call(.Block), C.maybe(C.seq(.{ kw_else, C.Call(.Block) })), C.ret,
    });

    pub const ForStmt = C.seq(.{
        kw_for,         lparen, C.Call(.Expr), rparen,
        C.Call(.Block), C.ret,
    });

    pub const BlockExpr = C.seq(.{ C.maybe(C.Call(.BlockLabel)), C.Call(.Block), C.ret });
    pub const BlockExprStatement = C.anyOf(.{
        C.Call(.BlockExpr),
        C.seq(.{ C.Call(.AssignExpr), semicolon }),
    }) ++ C.ret;

    pub const VarDeclExprStatement = C.anyOf(.{
        C.seq(.{ C.Call(.VarDecl), semicolon }),
        C.seq(.{ C.Call(.Expr), semicolon }),
    }) ++ C.ret;

    pub const IfStatement = C.anyOf(.{
        C.seq(.{ kw_if, lparen, C.Call(.Expr), rparen, C.maybe(C.Call(.PtrPayload)), C.Call(.BlockExpr), C.maybe(C.seq(.{ kw_else, C.maybe(C.Call(.PtrPayload)), C.Call(.Statement) })) }),
        C.seq(.{ kw_if, lparen, C.Call(.Expr), rparen, C.maybe(C.Call(.PtrPayload)), C.Call(.AssignExpr), C.anyOf(.{ semicolon, C.seq(.{ kw_else, C.maybe(C.Call(.PtrPayload)), C.Call(.Statement) }) }) }),
    }) ++ C.ret;

    pub const WhileStatement = C.anyOf(.{
        C.seq(.{ kw_while, lparen, C.Call(.Expr), rparen, C.maybe(C.Call(.PtrPayload)), C.maybe(C.Call(.WhileContinueExpr)), C.Call(.BlockExpr), C.maybe(C.seq(.{ kw_else, C.maybe(C.Call(.PtrPayload)), C.Call(.Statement) })) }),
        C.seq(.{ kw_while, lparen, C.Call(.Expr), rparen, C.maybe(C.Call(.PtrPayload)), C.maybe(C.Call(.WhileContinueExpr)), C.Call(.AssignExpr), C.anyOf(.{ semicolon, C.seq(.{ kw_else, C.maybe(C.Call(.PtrPayload)), C.Call(.Statement) }) }) }),
    }) ++ C.ret;

    pub const LabeledWhileStatement = C.seq(.{ C.maybe(C.Call(.BlockLabel)), C.Call(.WhileStatement), C.ret });

    pub const ForStatement = C.anyOf(.{
        C.seq(.{ kw_for, lparen, C.Call(.ForArgumentsList), rparen, C.maybe(C.Call(.PtrListPayload)), C.Call(.BlockExpr) }),
        C.seq(.{ kw_for, lparen, C.Call(.ForArgumentsList), rparen, C.maybe(C.Call(.PtrListPayload)), C.Call(.AssignExpr), semicolon }),
    }) ++ C.ret;

    pub const LabeledForStatement = C.seq(.{ C.maybe(C.Call(.BlockLabel)), C.Call(.ForStatement), C.ret });

    pub const DeferStatement = C.seq(.{ kw_defer, C.Call(.BlockExprStatement), C.ret });
    pub const ErrDeferStatement = C.seq(.{ kw_errdefer, C.maybe(C.Call(.Payload)), C.Call(.BlockExprStatement), C.ret });
    pub const NoSuspendStatement = C.seq(.{ kw_nosuspend, C.Call(.BlockExprStatement), C.ret });
    pub const SuspendStatement = C.seq(.{ kw_suspend, C.Call(.BlockExprStatement), C.ret });

    pub const Statement = C.anyOf(.{
        C.Call(.IfStatement),
        C.Call(.LabeledWhileStatement),
        C.Call(.LabeledForStatement),
        C.Call(.SwitchExpr),
        C.Call(.DeferStatement),
        C.Call(.ErrDeferStatement),
        C.Call(.NoSuspendStatement),
        C.Call(.SuspendStatement),
        C.Call(.VarDeclExprStatement),
        C.Call(.BlockExprStatement),
    }) ++ C.ret;

    pub const Block = C.seq(.{
        T_LBRACE,
        C.zeroOrMany(C.Call(.Statement)),
        T_RBRACE,
        C.ret,
    });

    pub const FnDecl = C.seq(.{
        C.maybe(kw_pub),
        C.maybe(C.anyOf(.{
            kw_export,
            C.seq(.{ kw_extern, C.maybe(C.Call(.StringLiteral)) }),
            kw_inline,
            kw_noinline,
        })),
        kw_fn,
        C.Call(.Identifier),
        lparen,
        C.maybe(C.Call(.ParamList)),
        rparen,
        C.maybe(C.Call(.ByteAlign)),
        C.maybe(C.Call(.AddrSpace)),
        C.maybe(C.Call(.LinkSection)),
        C.maybe(C.Call(.CallConv)),
        C.maybe(bang),
        C.Call(.TypeExpr),
        C.Call(.Block),
        C.ret,
    });

    pub const VarDeclProto = C.seq(.{
        C.anyOf(.{ kw_const, kw_var }),
        C.Call(.Identifier),
        C.maybe(C.seq(.{ colon, C.Call(.TypeExpr) })),
        C.maybe(C.Call(.ByteAlign)),
        C.maybe(C.Call(.AddrSpace)),
        C.maybe(C.Call(.LinkSection)),

        C.ret,
    });

    pub const GlobalVarDecl = C.seq(.{
        C.Call(.VarDeclProto),
        C.maybe(C.seq(.{ equal, C.Call(.Expr) })),
        semicolon,
        C.ret,
    });

    pub const TopVarDecl = C.seq(.{
        C.maybe(kw_pub),
        C.maybe(C.anyOf(.{
            kw_export,
            C.seq(.{ kw_extern, C.maybe(C.Call(.StringLiteral)) }),
        })),
        C.maybe(kw_threadlocal),
        C.Call(.GlobalVarDecl),
        C.ret,
    });

    pub const TestDecl = C.seq(.{
        kw_test,
        C.maybe(C.anyOf(.{ C.Call(.StringLiteral), C.Call(.Identifier) })),
        C.Call(.Block),
        C.ret,
    });
    pub const ComptimeDecl = C.seq(.{ kw_comptime, C.Call(.Block), C.ret });

    pub const start = C.seq(.{
        WS,
        C.zeroOrMany(C.anyOf(.{ C.Call(.FnDecl), C.Call(.TopVarDecl), C.Call(.TestDecl), C.Call(.ComptimeDecl) })),
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
