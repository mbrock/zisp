// Gradual port of Zig grammar from zigparse.zig (old pegvm API) to new peg.zig API
//
// This file incrementally translates the ZigMiniGrammar to use the new
// peg.zig pattern combinators: Match, CharSet, CharRange, Call, Kleene, etc.

comptime {
    @setEvalBranchQuota(500000);
}

const std = @import("std");
const peg = @import("peg.zig");

const Match = peg.Match;
const CharSet = peg.CharSet;
const Char = peg.Char;
const CharClass = peg.CharClass;
const Literal = peg.Literal;
const Call = peg.Call;
const Kleene = peg.Kleene;
const Maybe = peg.Maybe;
const Hide = peg.Hide;
const Shun = peg.Shun;

pub const ZigGrammar = struct {
    const R = std.meta.DeclEnum(@This());

    const AlphaLower = CharClass.range('a', 'z');
    const AlphaUpper = CharClass.range('A', 'Z');
    const Underscore = CharClass.anyOf("_");
    const Digit = CharClass.range('0', '9');

    const AlphaChar = AlphaLower.unionWith(AlphaUpper).unionWith(Underscore);
    const AlnumChar = AlphaChar.unionWith(Digit);

    // Whitespace and comments
    const NotNewline = CharClass.range(' ', '~')
        .unionWith(CharClass.anyOf("\t\r"));

    pub const LineComment = Match(struct {
        _start: Hide(Literal("//")),
        content: Char(NotNewline, .kleene),
    });

    pub const Whitespace = Match(struct {
        s: CharSet(" \t\n\r", .one),
        ss: CharSet(" \t\n\r", .kleene),
    });

    pub const SkipItem = Match(union(enum) {
        whitespace: Call(R.Whitespace),
        comment: Call(R.LineComment),
    });

    pub const Skip = Kleene(R.SkipItem);

    // ========================================================================
    // Identifiers and literals
    // ========================================================================

    pub const Identifier = Match(struct {
        // TODO: Add reserved word checking with Shun
        first: Char(AlphaChar, .one),
        rest: Char(AlnumChar, .kleene),
        _skip: Hide(Call(R.Skip)),
    });

    pub const BuiltinIdentifier = Match(struct {
        at: Hide(CharSet("@", .one)),
        first: Char(AlphaChar, .one),
        rest: Char(AlnumChar, .kleene),
    });

    pub const Integer = Match(struct {
        first: Char(Digit, .one),
        rest: Char(Digit, .kleene),
        _skip: Hide(Call(R.Skip)),
    });

    // ========================================================================
    // String and char literals
    // ========================================================================

    // Character classes for literals
    const EscapeChars = CharClass.anyOf("nr't\\\"");
    const ChrPlain = CharClass.range(' ', '&')
        .unionWith(CharClass.range('(', '['))
        .unionWith(CharClass.range(']', '~'));
    const StrPlain = CharClass.range(' ', '!')
        .unionWith(CharClass.range('#', '['))
        .unionWith(CharClass.range(']', '~'));

    pub const CharEscape = Match(struct {
        backslash: Hide(CharSet("\\", .one)),
        code: Char(EscapeChars, .one),
    });

    pub const CharPlain = Char(ChrPlain, .one);

    pub const CharContent = Match(union(enum) {
        escape: Call(R.CharEscape),
        plain: Call(R.CharPlain),
    });

    pub const CharLiteral = Match(struct {
        open: Hide(CharSet("'", .one)),
        content: Call(R.CharContent),
        close: Hide(CharSet("'", .one)),
        _skip: Hide(Call(R.Skip)),
    });

    pub const StringEscape = Match(struct {
        backslash: Hide(CharSet("\\", .one)),
        code: Char(CharClass.anyOf("nr\"t\\"), .one),
    });

    pub const StringPlain = Char(StrPlain, .one);

    pub const StringContent = Match(union(enum) {
        escape: Call(R.StringEscape),
        plain: Call(R.StringPlain),
    });

    pub const StringLiteral = Match(struct {
        open: Hide(CharSet("\"", .one)),
        content: Kleene(R.StringContent),
        close: Hide(CharSet("\"", .one)),
        _skip: Hide(Call(R.Skip)),
    });

    // ========================================================================
    // Keywords - literal + boundary check + skip
    // ========================================================================

    pub const IdentBoundary = Shun(Char(AlnumChar, .one));

    // Helper for defining keywords
    fn Kw(comptime text: []const u8) type {
        return Match(struct {
            lit: Literal(text),
            _boundary: Hide(Call(R.IdentBoundary)),
            _skip: Hide(Call(R.Skip)),
        });
    }

    pub const KwFn = Kw("fn");
    pub const KwPub = Kw("pub");
    pub const KwReturn = Kw("return");
    pub const KwConst = Kw("const");
    pub const KwVar = Kw("var");
    pub const KwIf = Kw("if");
    pub const KwElse = Kw("else");
    pub const KwWhile = Kw("while");
    pub const KwFor = Kw("for");
    pub const KwSwitch = Kw("switch");
    pub const KwStruct = Kw("struct");
    pub const KwUnion = Kw("union");
    pub const KwEnum = Kw("enum");
    pub const KwError = Kw("error");
    pub const KwDefer = Kw("defer");
    pub const KwErrdefer = Kw("errdefer");
    pub const KwSuspend = Kw("suspend");
    pub const KwNosuspend = Kw("nosuspend");
    pub const KwInline = Kw("inline");
    pub const KwComptime = Kw("comptime");
    pub const KwTest = Kw("test");
    pub const KwBreak = Kw("break");
    pub const KwContinue = Kw("continue");

    // ========================================================================
    // Operators - literal + optional negative lookahead + skip
    // ========================================================================

    // Helper for operators (no lookahead needed for simple ones)
    fn Op(comptime text: []const u8) type {
        return Match(struct {
            lit: Literal(text),
            _skip: Hide(Call(R.Skip)),
        });
    }

    pub const OpLParen = Op("(");
    pub const OpRParen = Op(")");
    pub const OpLBrace = Op("{");
    pub const OpRBrace = Op("}");
    pub const OpLBracket = Op("[");
    pub const OpRBracket = Op("]");
    pub const OpSemicolon = Op(";");
    pub const OpColon = Op(":");
    pub const OpComma = Op(",");
    pub const OpEquals = Op("=");
    pub const OpDot = Op(".");
    pub const OpPlus = Op("+");
    pub const OpMinus = Op("-");
    pub const OpStar = Op("*");
    pub const OpSlash = Op("/");
    pub const OpPercent = Op("%");
    pub const OpBang = Op("!");
    pub const OpAmpersand = Op("&");
    pub const OpPipe = Op("|");
    pub const OpCaret = Op("^");
    pub const OpLAngle = Op("<");
    pub const OpRAngle = Op(">");
    pub const OpLShift = Op("<<");
    pub const OpRShift = Op(">>");
    pub const OpEqEq = Op("==");
    pub const OpBangEq = Op("!=");
    pub const OpLtEq = Op("<=");
    pub const OpGtEq = Op(">=");
    pub const OpArrow = Op("=>");
    pub const OpDotDot = Op("..");
    pub const OpDotDotDot = Op("...");
    pub const OpQuestion = Op("?");
    pub const OpBangEqEq = Op("!==");
    pub const OpTilde = Op("~");

    // ========================================================================
    // Type expressions
    // ========================================================================

    pub const ArraySizePrefix = Match(struct {
        _open: Hide(Call(R.OpLBracket)),
        size: Call(R.Expr),
        _close: Hide(Call(R.OpRBracket)),
    });

    pub const SlicePrefix = Match(struct {
        _open: Hide(Call(R.OpLBracket)),
        _close: Hide(Call(R.OpRBracket)),
    });

    pub const TypePrefix = Match(union(enum) {
        optional: Call(R.OpQuestion),
        pointer: Call(R.OpStar),
        array_size: Call(R.ArraySizePrefix),
        slice: Call(R.SlicePrefix),
    });

    pub const ErrorSetDecl = Match(struct {
        _kw: Hide(Call(R.KwError)),
        _open: Hide(Call(R.OpLBrace)),
        identifiers: Maybe(Call(R.IdentifierList)),
        _close: Hide(Call(R.OpRBrace)),
    });

    pub const IdentifierRest = Match(struct {
        _comma: Hide(Call(R.OpComma)),
        ident: Call(R.Identifier),
    });

    pub const IdentifierList = Match(struct {
        first: Call(R.Identifier),
        rest: Kleene(R.IdentifierRest),
        trailing_comma: Maybe(Call(R.OpComma)),
    });

    pub const TypeAtom = Match(union(enum) {
        identifier: Call(R.Identifier),
        container: Call(R.ContainerExpr),
        error_set: Call(R.ErrorSetDecl),
    });

    pub const TypeCore = Match(struct {
        prefixes: Kleene(R.TypePrefix),
        atom: Call(R.TypeAtom),
    });

    pub const TypeErrorUnion = Match(struct {
        _bang: Hide(Call(R.OpBang)),
        rhs: Call(R.TypeExpr),
    });

    pub const TypeExpr = Match(struct {
        core: Call(R.TypeCore),
        error_union: Maybe(Call(R.TypeErrorUnion)),
    });

    // ========================================================================
    // Container types (struct, union, enum)
    // ========================================================================

    pub const FieldDecl = Match(struct {
        name: Call(R.Identifier),
        _colon: Hide(Call(R.OpColon)),
        type_: Call(R.TypeExpr),
    });

    pub const FieldRest = Match(struct {
        _comma: Hide(Call(R.OpComma)),
        field: Call(R.FieldDecl),
    });

    pub const FieldList = Match(struct {
        first: Call(R.FieldDecl),
        rest: Kleene(R.FieldRest),
        trailing_comma: Maybe(Call(R.OpComma)),
    });

    pub const ContainerMembers = Match(struct {
        decls: Kleene(R.ContainerDeclaration),
        fields: Maybe(Call(R.FieldList)),
    });

    pub const ContainerVarDecl = Match(struct {
        decl: Call(R.VarDecl),
        _semi: Hide(Call(R.OpSemicolon)),
    });

    pub const ContainerDeclaration = Match(union(enum) {
        fn_decl: Call(R.FnDecl),
        var_decl: Call(R.ContainerVarDecl),
    });

    pub const StructBody = Match(struct {
        _open: Hide(Call(R.OpLBrace)),
        members: Call(R.ContainerMembers),
        _close: Hide(Call(R.OpRBrace)),
    });

    pub const EnumFieldRest = Match(struct {
        _comma: Hide(Call(R.OpComma)),
        ident: Call(R.Identifier),
    });

    pub const EnumFields = Match(struct {
        first: Call(R.Identifier),
        rest: Kleene(R.EnumFieldRest),
        trailing_comma: Maybe(Call(R.OpComma)),
    });

    pub const EnumBody = Match(struct {
        _open: Hide(Call(R.OpLBrace)),
        fields: Maybe(Call(R.EnumFields)),
        _close: Hide(Call(R.OpRBrace)),
    });

    pub const StructExpr = Match(struct {
        _kw: Hide(Call(R.KwStruct)),
        body: Call(R.StructBody),
    });

    pub const UnionExpr = Match(struct {
        _kw: Hide(Call(R.KwUnion)),
        body: Call(R.StructBody),
    });

    pub const EnumExpr = Match(struct {
        _kw: Hide(Call(R.KwEnum)),
        body: Call(R.EnumBody),
    });

    pub const ContainerExpr = Match(union(enum) {
        struct_: Call(R.StructExpr),
        union_: Call(R.UnionExpr),
        enum_: Call(R.EnumExpr),
    });

    // ========================================================================
    // Payloads (for if/while/for/switch)
    // ========================================================================

    pub const Payload = Match(struct {
        _open: Hide(Call(R.OpPipe)),
        name: Call(R.Identifier),
        _close: Hide(Call(R.OpPipe)),
    });

    pub const PtrPayload = Match(struct {
        _open: Hide(Call(R.OpPipe)),
        ptr: Maybe(Call(R.OpStar)),
        name: Call(R.Identifier),
        _close: Hide(Call(R.OpPipe)),
    });

    // ========================================================================
    // Expressions - Precedence from lowest to highest
    // ========================================================================

    // Forward declaration for recursive expressions
    pub const Expr = Call(R.BoolOrExpr);

    pub const ParenExpr = Match(struct {
        _open: Hide(Call(R.OpLParen)),
        expr: Call(R.Expr),
        _close: Hide(Call(R.OpRParen)),
    });

    // Control flow expressions
    pub const ErrorLiteral = Match(struct {
        _kw: Hide(Call(R.KwError)),
        _dot: Hide(Call(R.OpDot)),
        name: Call(R.Identifier),
    });

    pub const ReturnExpr = Match(struct {
        _kw: Hide(Call(R.KwReturn)),
        value: Maybe(Call(R.Expr)),
    });

    pub const LabelRef = Match(struct {
        _colon: Hide(Call(R.OpColon)),
        name: Call(R.Identifier),
    });

    pub const BreakExpr = Match(struct {
        _kw: Hide(Call(R.KwBreak)),
        label: Maybe(Call(R.LabelRef)),
        value: Maybe(Call(R.Expr)),
    });

    pub const ContinueExpr = Match(struct {
        _kw: Hide(Call(R.KwContinue)),
        label: Maybe(Call(R.LabelRef)),
    });

    pub const IfExpr = Match(struct {
        _if: Hide(Call(R.KwIf)),
        _lparen: Hide(Call(R.OpLParen)),
        condition: Call(R.Expr),
        _rparen: Hide(Call(R.OpRParen)),
        payload: Maybe(Call(R.PtrPayload)),
        then_body: Call(R.Expr),
        _else: Hide(Call(R.KwElse)),
        else_body: Call(R.Expr),
    });

    pub const WhileContinue = Match(struct {
        _colon: Hide(Call(R.OpColon)),
        _lparen: Hide(Call(R.OpLParen)),
        expr: Call(R.Expr),
        _rparen: Hide(Call(R.OpRParen)),
    });

    pub const ElseClause = Match(struct {
        _else: Hide(Call(R.KwElse)),
        body: Call(R.Expr),
    });

    pub const WhileExpr = Match(struct {
        _while: Hide(Call(R.KwWhile)),
        _lparen: Hide(Call(R.OpLParen)),
        condition: Call(R.Expr),
        _rparen: Hide(Call(R.OpRParen)),
        payload: Maybe(Call(R.PtrPayload)),
        continue_expr: Maybe(Call(R.WhileContinue)),
        body: Call(R.Block),
        else_clause: Maybe(Call(R.ElseClause)),
    });

    pub const ForItem = Match(struct {
        expr: Call(R.Expr),
        range: Maybe(Match(struct {
            _dots: Hide(Call(R.OpDotDot)),
            end: Maybe(Call(R.Expr)),
        })),
    });

    pub const ForArgsRest = Match(struct {
        _comma: Hide(Call(R.OpComma)),
        item: Call(R.ForItem),
    });

    pub const ForArgsList = Match(struct {
        first: Call(R.ForItem),
        rest: Kleene(R.ForArgsRest),
        trailing_comma: Maybe(Call(R.OpComma)),
    });

    pub const ForExpr = Match(struct {
        _for: Hide(Call(R.KwFor)),
        _lparen: Hide(Call(R.OpLParen)),
        args: Call(R.ForArgsList),
        _rparen: Hide(Call(R.OpRParen)),
        payload: Maybe(Call(R.PtrPayload)),
        body: Call(R.Block),
        else_clause: Maybe(Match(struct {
            _else: Hide(Call(R.KwElse)),
            body: Call(R.Expr),
        })),
    });

    pub const CaseItem = Match(struct {
        value: Call(R.Expr),
        range: Maybe(Match(struct {
            _dots: Hide(Call(R.OpDotDotDot)),
            end: Call(R.Expr),
        })),
    });

    pub const SwitchElse = Match(struct {
        _else: Hide(Call(R.KwElse)),
        _arrow: Hide(Call(R.OpArrow)),
        expr: Call(R.Expr),
    });

    pub const CaseItemRest = Match(struct {
        _comma: Hide(Call(R.OpComma)),
        item: Call(R.CaseItem),
    });

    pub const SwitchCase = Match(struct {
        inline_: Maybe(Call(R.KwInline)),
        first: Call(R.CaseItem),
        rest: Kleene(R.CaseItemRest),
        _arrow: Hide(Call(R.OpArrow)),
        expr: Call(R.Expr),
    });

    pub const SwitchProng = Match(union(enum) {
        else_: Call(R.SwitchElse),
        case: Call(R.SwitchCase),
    });

    pub const SwitchProngRest = Match(struct {
        _comma: Hide(Call(R.OpComma)),
        prong: Call(R.SwitchProng),
    });

    pub const SwitchBody = Match(struct {
        _open: Hide(Call(R.OpLBrace)),
        prongs: Maybe(Match(struct {
            first: Call(R.SwitchProng),
            rest: Kleene(R.SwitchProngRest),
        })),
        _close: Hide(Call(R.OpRBrace)),
    });

    pub const SwitchExpr = Match(struct {
        _switch: Hide(Call(R.KwSwitch)),
        _lparen: Hide(Call(R.OpLParen)),
        expr: Call(R.Expr),
        _rparen: Hide(Call(R.OpRParen)),
        body: Call(R.SwitchBody),
    });

    pub const Primary = Match(union(enum) {
        paren: Call(R.ParenExpr),
        block: Call(R.Block),
        if_expr: Call(R.IfExpr),
        while_expr: Call(R.WhileExpr),
        for_expr: Call(R.ForExpr),
        switch_expr: Call(R.SwitchExpr),
        return_expr: Call(R.ReturnExpr),
        break_expr: Call(R.BreakExpr),
        continue_expr: Call(R.ContinueExpr),
        container: Call(R.ContainerExpr),
        builtin: Call(R.BuiltinIdentifier),
        error_lit: Call(R.ErrorLiteral),
        integer: Call(R.Integer),
        string: Call(R.StringLiteral),
        char: Call(R.CharLiteral),
        identifier: Call(R.Identifier),
    });

    // Suffix operators: function calls, member access, indexing
    pub const FnCallArgs = Match(struct {
        _open: Hide(Call(R.OpLParen)),
        args: Maybe(Call(R.ExprList)),
        _close: Hide(Call(R.OpRParen)),
    });

    pub const MemberAccess = Match(struct {
        _dot: Hide(Call(R.OpDot)),
        member: Call(R.Identifier),
    });

    pub const ArrayIndex = Match(struct {
        _open: Hide(Call(R.OpLBracket)),
        index: Call(R.Expr),
        _close: Hide(Call(R.OpRBracket)),
    });

    pub const Suffix = Match(union(enum) {
        call: Call(R.FnCallArgs),
        member: Call(R.MemberAccess),
        index: Call(R.ArrayIndex),
    });

    pub const SuffixExpr = Match(struct {
        base: Call(R.Primary),
        suffixes: Kleene(R.Suffix),
    });

    // Prefix operators: !, -, &, try
    pub const PrefixOp = Match(union(enum) {
        not: Call(R.OpBang),
        neg: Call(R.OpMinus),
        ref: Call(R.OpAmpersand),
        try_: Call(R.KwTry),
    });

    pub const PrefixExpr = Match(struct {
        ops: Kleene(R.PrefixOp),
        expr: Call(R.SuffixExpr),
    });

    // Multiply: *, /, %
    pub const MultiplyOp = Match(union(enum) {
        mul: Call(R.OpStar),
        div: Call(R.OpSlash),
        mod: Call(R.OpPercent),
    });

    pub const MultiplyRhs = Match(struct {
        op: Call(R.MultiplyOp),
        rhs: Call(R.PrefixExpr),
    });

    pub const MultiplyExpr = Match(struct {
        lhs: Call(R.PrefixExpr),
        rest: Kleene(R.MultiplyRhs),
    });

    // Add: +, -
    pub const AddOp = Match(union(enum) {
        add: Call(R.OpPlus),
        sub: Call(R.OpMinus),
    });

    pub const AddRhs = Match(struct {
        op: Call(R.AddOp),
        rhs: Call(R.MultiplyExpr),
    });

    pub const AddExpr = Match(struct {
        lhs: Call(R.MultiplyExpr),
        rest: Kleene(R.AddRhs),
    });

    // Bit shift: <<, >>
    pub const BitShiftOp = Match(union(enum) {
        left: Call(R.OpLShift),
        right: Call(R.OpRShift),
    });

    pub const BitShiftRhs = Match(struct {
        op: Call(R.BitShiftOp),
        rhs: Call(R.AddExpr),
    });

    pub const BitShiftExpr = Match(struct {
        lhs: Call(R.AddExpr),
        rest: Kleene(R.BitShiftRhs),
    });

    // Bitwise: &, ^, |
    pub const BitwiseOp = Match(union(enum) {
        and_: Call(R.OpAmpersand),
        xor: Call(R.OpCaret),
        or_: Call(R.OpPipe),
    });

    pub const BitwiseRhs = Match(struct {
        op: Call(R.BitwiseOp),
        rhs: Call(R.BitShiftExpr),
    });

    pub const BitwiseExpr = Match(struct {
        lhs: Call(R.BitShiftExpr),
        rest: Kleene(R.BitwiseRhs),
    });

    // Compare: ==, !=, <, >, <=, >=
    pub const CompareOp = Match(union(enum) {
        eq: Call(R.OpEqEq),
        neq: Call(R.OpBangEq),
        lt: Call(R.OpLAngle),
        gt: Call(R.OpRAngle),
        lte: Call(R.OpLtEq),
        gte: Call(R.OpGtEq),
    });

    pub const CompareRhs = Match(struct {
        op: Call(R.CompareOp),
        rhs: Call(R.BitwiseExpr),
    });

    pub const CompareExpr = Match(struct {
        lhs: Call(R.BitwiseExpr),
        rhs: Maybe(Call(R.CompareRhs)),
    });

    // Boolean and: and
    pub const KwAnd = Kw("and");
    pub const KwOr = Kw("or");
    pub const KwTry = Kw("try");

    pub const BoolAndRhs = Match(struct {
        _op: Hide(Call(R.KwAnd)),
        rhs: Call(R.CompareExpr),
    });

    pub const BoolAndExpr = Match(struct {
        lhs: Call(R.CompareExpr),
        rest: Kleene(R.BoolAndRhs),
    });

    // Boolean or: or
    pub const BoolOrRhs = Match(struct {
        _op: Hide(Call(R.KwOr)),
        rhs: Call(R.BoolAndExpr),
    });

    pub const BoolOrExpr = Match(struct {
        lhs: Call(R.BoolAndExpr),
        rest: Kleene(R.BoolOrRhs),
    });

    // Expression list (for function calls, etc.)
    pub const ExprListRest = Match(struct {
        _comma: Hide(Call(R.OpComma)),
        expr: Call(R.Expr),
    });

    pub const ExprList = Match(struct {
        first: Call(R.Expr),
        rest: Kleene(R.ExprListRest),
    });

    // ========================================================================
    // Statements and blocks
    // ========================================================================

    pub const VarDeclKeyword = Match(union(enum) {
        const_: Call(R.KwConst),
        var_: Call(R.KwVar),
    });

    pub const VarDeclType = Match(struct {
        _colon: Hide(Call(R.OpColon)),
        type_: Call(R.TypeExpr),
    });

    pub const VarDeclInit = Match(struct {
        _eq: Hide(Call(R.OpEquals)),
        value: Call(R.Expr),
    });

    pub const VarDecl = Match(struct {
        keyword: Call(R.VarDeclKeyword),
        name: Call(R.Identifier),
        type_: Maybe(Call(R.VarDeclType)),
        init: Maybe(Call(R.VarDeclInit)),
    });

    pub const ExprStmt = Match(struct {
        expr: Call(R.Expr),
        _semi: Hide(Call(R.OpSemicolon)),
    });

    pub const VarDeclStmt = Match(struct {
        decl: Call(R.VarDecl),
        _semi: Hide(Call(R.OpSemicolon)),
    });

    pub const IfStatement = Match(struct {
        _if: Hide(Call(R.KwIf)),
        _lparen: Hide(Call(R.OpLParen)),
        condition: Call(R.Expr),
        _rparen: Hide(Call(R.OpRParen)),
        payload: Maybe(Call(R.PtrPayload)),
        body: Call(R.Block),
        else_clause: Maybe(Match(struct {
            _else: Hide(Call(R.KwElse)),
            body: Call(R.Block),
        })),
    });

    pub const DeferStatement = Match(struct {
        _kw: Hide(Call(R.KwDefer)),
        expr: Call(R.Expr),
        _semi: Hide(Call(R.OpSemicolon)),
    });

    pub const Statement = Match(union(enum) {
        if_stmt: Call(R.IfStatement),
        defer_stmt: Call(R.DeferStatement),
        var_decl: Call(R.VarDeclStmt),
        expr: Call(R.ExprStmt),
    });

    pub const Block = Match(struct {
        _open: Hide(Call(R.OpLBrace)),
        statements: Kleene(R.Statement),
        _close: Hide(Call(R.OpRBrace)),
    });

    // ========================================================================
    // Function declarations
    // ========================================================================

    pub const Param = Match(struct {
        name: Call(R.Identifier),
        _colon: Hide(Call(R.OpColon)),
        type_: Call(R.TypeExpr),
    });

    pub const ParamRest = Match(struct {
        _comma: Hide(Call(R.OpComma)),
        param: Call(R.Param),
    });

    pub const ParamList = Match(struct {
        first: Call(R.Param),
        rest: Kleene(R.ParamRest),
    });

    pub const FnDecl = Match(struct {
        pub_: Maybe(Call(R.KwPub)),
        _fn: Hide(Call(R.KwFn)),
        name: Call(R.Identifier),
        _lparen: Hide(Call(R.OpLParen)),
        params: Maybe(Call(R.ParamList)),
        _rparen: Hide(Call(R.OpRParen)),
        return_type: Call(R.TypeExpr),
        body: Call(R.Block),
    });

    // ========================================================================
    // Top-level
    // ========================================================================

    pub const Root = Match(struct {
        _skip: Hide(Call(R.Skip)),
        decls: Kleene(R.FnDecl),
    });
};

// ============================================================================
// Tests - Port tests incrementally as we implement more rules
// ============================================================================

const VMFactory = @import("vm.zig").VM;
const TestVM = VMFactory(ZigGrammar);
const NodeType = peg.NodeType;

fn parseRule(comptime rule: ZigGrammar.R, input: [:0]const u8) !void {
    var saves_buf: [128]TestVM.SaveFrame = undefined;
    var calls_buf: [128]TestVM.CallFrame = undefined;
    var nodes_buf: [512]NodeType = undefined;
    var structs_buf: [128]TestVM.StructuralFrame = undefined;
    var child_buf: [512]u32 = undefined;

    var vm = TestVM.init(input, &saves_buf, &calls_buf, &nodes_buf, &structs_buf, &child_buf);
    try vm.runFrom(rule);
}

test "zig grammar: identifier" {
    try parseRule(.Identifier, "foo");
}

test "zig grammar: builtin identifier" {
    try parseRule(.BuiltinIdentifier, "@foo");
}

test "zig grammar: integer" {
    try parseRule(.Integer, "42");
}

test "zig grammar: char literal plain" {
    try parseRule(.CharLiteral, "'a'");
}

test "zig grammar: char literal escape" {
    try parseRule(.CharLiteral, "'\\n'");
}

test "zig grammar: string literal empty" {
    try parseRule(.StringLiteral, "\"\"");
}

test "zig grammar: string literal simple" {
    try parseRule(.StringLiteral, "\"hello\"");
}

test "zig grammar: string literal with escape" {
    try parseRule(.StringLiteral, "\"hello\\nworld\"");
}

test "zig grammar: return expression no value" {
    try parseRule(.ReturnExpr, "return");
}

test "zig grammar: return expression with value" {
    try parseRule(.ReturnExpr, "return 42");
}

test "zig grammar: var decl no init" {
    try parseRule(.VarDecl, "var x");
}

test "zig grammar: const decl with init" {
    try parseRule(.VarDecl, "const x = 42");
}

test "zig grammar: var decl with type" {
    try parseRule(.VarDecl, "var x: i32 = 42");
}

test "zig grammar: expr statement" {
    try parseRule(.ExprStmt, "foo;");
}

test "zig grammar: empty block" {
    try parseRule(.Block, "{}");
}

test "zig grammar: block with statement" {
    try parseRule(.Block, "{ return; }");
}

test "zig grammar: block with multiple statements" {
    try parseRule(.Block, "{ var x = 1; return x; }");
}

test "zig grammar: simple function" {
    try parseRule(.FnDecl, "fn main() void {}");
}

test "zig grammar: function with return" {
    try parseRule(.FnDecl, "fn main() void { return; }");
}

test "zig grammar: function with params" {
    try parseRule(.FnDecl, "fn add(a: i32, b: i32) i32 { return a; }");
}

test "zig grammar: pub function" {
    try parseRule(.FnDecl, "pub fn main() void {}");
}

test "zig grammar: root empty" {
    try parseRule(.Root, "");
}

test "zig grammar: root with function" {
    try parseRule(.Root, "fn main() void {}");
}

test "zig grammar: struct type" {
    try parseRule(.ContainerExpr, "struct { x: i32, y: i32 }");
}

test "zig grammar: enum type" {
    try parseRule(.ContainerExpr, "enum { A, B, C }");
}

test "zig grammar: error set" {
    try parseRule(.ErrorSetDecl, "error{OutOfMemory, InvalidInput}");
}

test "zig grammar: pointer type" {
    try parseRule(.TypeExpr, "*i32");
}

test "zig grammar: optional type" {
    try parseRule(.TypeExpr, "?i32");
}

test "zig grammar: array type" {
    try parseRule(.TypeExpr, "[10]u8");
}

test "zig grammar: error union type" {
    try parseRule(.TypeExpr, "anyerror!void");
}

test "zig grammar: addition" {
    try parseRule(.Expr, "1 + 2");
}

test "zig grammar: multiplication precedence" {
    try parseRule(.Expr, "1 + 2 * 3");
}

test "zig grammar: comparison" {
    try parseRule(.Expr, "x < 10");
}

test "zig grammar: boolean and" {
    try parseRule(.Expr, "a and b");
}

test "zig grammar: boolean or" {
    try parseRule(.Expr, "a or b");
}

test "zig grammar: function call" {
    try parseRule(.Expr, "foo()");
}

test "zig grammar: function call with args" {
    try parseRule(.Expr, "add(1, 2)");
}

test "zig grammar: member access" {
    try parseRule(.Expr, "foo.bar");
}

test "zig grammar: array index simple" {
    try parseRule(.ArrayIndex, "[0]");
}

test "zig grammar: array index" {
    try parseRule(.Expr, "arr[0]");
}

test "zig grammar: chained suffix" {
    try parseRule(.Expr, "foo.bar()[0]");
}

test "zig grammar: prefix operators" {
    try parseRule(.Expr, "!x");
}

test "zig grammar: negative" {
    try parseRule(.Expr, "-42");
}

test "zig grammar: try prefix" {
    try parseRule(.Expr, "try foo()");
}

test "zig grammar: complex expression" {
    try parseRule(.Expr, "a + b * c == d and e or f");
}

var stdoutbuf: [4096]u8 = undefined;
const stdout_file = std.fs.File.stdout();
var stdout_writer = stdout_file.writer(&stdoutbuf);
const stdout = &stdout_writer.interface;

pub fn main() !void {
    const trace = @import("trace.zig");
    const tty = std.Io.tty.detectConfig(stdout_file);

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Try to parse "[0]" as ArrayIndex rule
    var vm = try TestVM.initAlloc("[0]", allocator, 64, 64, 512);
    defer vm.deinit(allocator);

    try trace.traceFrom(&vm, stdout, tty, .Root);
    try stdout.flush();
}
