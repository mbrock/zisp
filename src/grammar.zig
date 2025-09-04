const std = @import("std");
const parse = @import("parse.zig");

// More realistic grammar for a simple programming language
pub const RealisticLang = struct {
    const C = parse.Combinators(@This(), .{ .debug = parse.SilentDebug });

    // Primitives
    // String <- '"' [^"]* '"'
    pub const String = C.seq(.{
        C.CH('"'),
        C.many0(C.alt(.{
            C.seq(.{ C.CH('\\'), C.CH('"') }), // escaped quote
            C.seq(.{ C.CH('\\'), C.CH('\\') }), // escaped backslash  
            C.seq(.{ C.CH('\\'), C.CH('n') }),  // newline
            C.seq(.{ C.CH('\\'), C.CH('t') }),  // tab
            // Any char except quote and backslash
            C.alt(.{
                C.CH('a'), C.CH('b'), C.CH('c'), C.CH('d'), C.CH('e'), C.CH('f'), C.CH('g'), C.CH('h'),
                C.CH('i'), C.CH('j'), C.CH('k'), C.CH('l'), C.CH('m'), C.CH('n'), C.CH('o'), C.CH('p'),
                C.CH('q'), C.CH('r'), C.CH('s'), C.CH('t'), C.CH('u'), C.CH('v'), C.CH('w'), C.CH('x'),
                C.CH('y'), C.CH('z'), C.CH('A'), C.CH('B'), C.CH('C'), C.CH('D'), C.CH('E'), C.CH('F'),
                C.CH('G'), C.CH('H'), C.CH('I'), C.CH('J'), C.CH('K'), C.CH('L'), C.CH('M'), C.CH('N'),
                C.CH('O'), C.CH('P'), C.CH('Q'), C.CH('R'), C.CH('S'), C.CH('T'), C.CH('U'), C.CH('V'),
                C.CH('W'), C.CH('X'), C.CH('Y'), C.CH('Z'), C.CH('0'), C.CH('1'), C.CH('2'), C.CH('3'),
                C.CH('4'), C.CH('5'), C.CH('6'), C.CH('7'), C.CH('8'), C.CH('9'), C.CH(' '), C.CH('\t'),
                C.CH('\n'), C.CH('\r'), C.CH('!'), C.CH('#'), C.CH('$'), C.CH('%'), C.CH('&'), C.CH('\''),
                C.CH('('), C.CH(')'), C.CH('*'), C.CH('+'), C.CH(','), C.CH('-'), C.CH('.'), C.CH('/'),
                C.CH(':'), C.CH(';'), C.CH('<'), C.CH('='), C.CH('>'), C.CH('?'), C.CH('@'), C.CH('['),
                C.CH(']'), C.CH('^'), C.CH('_'), C.CH('`'), C.CH('{'), C.CH('|'), C.CH('}'), C.CH('~')
            })
        })),
        C.CH('"'),
        C.RET
    });

    // Boolean <- 'true' / 'false'
    pub const Boolean = C.seq(.{
        C.alt(.{
            C.STR("true"),
            C.STR("false")
        }),
        C.RET
    });

    // Literal <- Number / String / Boolean / Ident
    pub const Literal = C.seq(.{
        C.alt(.{
            C.NUMBER,
            C.Call(.String),
            C.Call(.Boolean),
            C.IDENT
        }),
        C.RET
    });

    // ArrayLiteral <- '[' WS (Expr (WS ',' WS Expr)*)? WS ']'
    pub const ArrayLiteral = C.seq(.{
        C.CH('['), C.WS,
        C.opt(C.seq(.{
            C.Call(.Expr),
            C.many0(C.seq(.{ C.WS, C.CH(','), C.WS, C.Call(.Expr) }))
        })),
        C.WS, C.CH(']'),
        C.RET
    });

    // ObjectLiteral <- '{' WS (Ident WS ':' WS Expr (WS ',' WS Ident WS ':' WS Expr)*)? WS '}'
    pub const ObjectLiteral = C.seq(.{
        C.CH('{'), C.WS,
        C.opt(C.seq(.{
            C.IDENT, C.WS, C.CH(':'), C.WS, C.Call(.Expr),
            C.many0(C.seq(.{ C.WS, C.CH(','), C.WS, C.IDENT, C.WS, C.CH(':'), C.WS, C.Call(.Expr) }))
        })),
        C.WS, C.CH('}'),
        C.RET
    });

    // Primary <- '(' WS Expr WS ')' / ArrayLiteral / ObjectLiteral / Literal
    pub const Primary = C.seq(.{
        C.alt(.{
            C.seq(.{ C.CH('('), C.WS, C.Call(.Expr), C.WS, C.CH(')') }),
            C.Call(.ArrayLiteral),
            C.Call(.ObjectLiteral), 
            C.Call(.Literal)
        }),
        C.RET
    });

    // FunctionCall <- Primary WS '(' WS (Expr (WS ',' WS Expr)*)? WS ')'
    pub const FunctionCall = C.seq(.{
        C.Call(.Primary), C.WS,
        C.opt(C.seq(.{
            C.CH('('), C.WS,
            C.opt(C.seq(.{
                C.Call(.Expr),
                C.many0(C.seq(.{ C.WS, C.CH(','), C.WS, C.Call(.Expr) }))
            })),
            C.WS, C.CH(')')
        })),
        C.RET
    });

    // MemberAccess <- FunctionCall (WS '.' WS Ident)*
    pub const MemberAccess = C.seq(.{
        C.Call(.FunctionCall),
        C.many0(C.seq(.{ C.WS, C.CH('.'), C.WS, C.IDENT })),
        C.RET
    });

    // UnaryExpr <- ('-' / '+' / '!') WS UnaryExpr / MemberAccess
    pub const UnaryExpr = C.seq(.{
        C.alt(.{
            C.seq(.{
                C.alt(.{ C.CH('-'), C.CH('+'), C.CH('!') }),
                C.WS, C.Call(.UnaryExpr)
            }),
            C.Call(.MemberAccess)
        }),
        C.RET
    });

    // MulExpr <- UnaryExpr (WS ('*' / '/' / '%') WS UnaryExpr)*
    pub const MulExpr = C.seq(.{
        C.Call(.UnaryExpr),
        C.many0(C.seq(.{
            C.WS, C.alt(.{ C.CH('*'), C.CH('/'), C.CH('%') }), C.WS, C.Call(.UnaryExpr)
        })),
        C.RET
    });

    // AddExpr <- MulExpr (WS ('+' / '-') WS MulExpr)*
    pub const AddExpr = C.seq(.{
        C.Call(.MulExpr),
        C.many0(C.seq(.{
            C.WS, C.alt(.{ C.CH('+'), C.CH('-') }), C.WS, C.Call(.MulExpr)
        })),
        C.RET
    });

    // RelExpr <- AddExpr (WS ('<=' / '>=' / '<' / '>') WS AddExpr)*
    pub const RelExpr = C.seq(.{
        C.Call(.AddExpr),
        C.many0(C.seq(.{
            C.WS, C.alt(.{
                C.STR("<="), C.STR(">="), C.CH('<'), C.CH('>')
            }), C.WS, C.Call(.AddExpr)
        })),
        C.RET
    });

    // EqExpr <- RelExpr (WS ('==' / '!=') WS RelExpr)*
    pub const EqExpr = C.seq(.{
        C.Call(.RelExpr),
        C.many0(C.seq(.{
            C.WS, C.alt(.{ C.STR("=="), C.STR("!=") }), C.WS, C.Call(.RelExpr)
        })),
        C.RET
    });

    // LogicalAndExpr <- EqExpr (WS '&&' WS EqExpr)*
    pub const LogicalAndExpr = C.seq(.{
        C.Call(.EqExpr),
        C.many0(C.seq(.{ C.WS, C.STR("&&"), C.WS, C.Call(.EqExpr) })),
        C.RET
    });

    // LogicalOrExpr <- LogicalAndExpr (WS '||' WS LogicalAndExpr)*
    pub const LogicalOrExpr = C.seq(.{
        C.Call(.LogicalAndExpr),
        C.many0(C.seq(.{ C.WS, C.STR("||"), C.WS, C.Call(.LogicalAndExpr) })),
        C.RET
    });

    // Expr <- LogicalOrExpr
    pub const Expr = C.seq(.{ C.Call(.LogicalOrExpr), C.RET });

    // VarDecl <- 'let' WS Ident WS '=' WS Expr ';'
    pub const VarDecl = C.seq(.{
        C.STR("let"), C.WS, C.IDENT, C.WS, C.CH('='), C.WS, C.Call(.Expr), C.WS, C.CH(';'),
        C.RET
    });

    // IfStmt <- 'if' WS '(' WS Expr WS ')' WS Block (WS 'else' WS Block)?
    pub const IfStmt = C.seq(.{
        C.STR("if"), C.WS, C.CH('('), C.WS, C.Call(.Expr), C.WS, C.CH(')'), C.WS, C.Call(.Block),
        C.opt(C.seq(.{ C.WS, C.STR("else"), C.WS, C.Call(.Block) })),
        C.RET
    });

    // WhileLoop <- 'while' WS '(' WS Expr WS ')' WS Block
    pub const WhileLoop = C.seq(.{
        C.STR("while"), C.WS, C.CH('('), C.WS, C.Call(.Expr), C.WS, C.CH(')'), C.WS, C.Call(.Block),
        C.RET
    });

    // ReturnStmt <- 'return' (WS Expr)? WS ';'
    pub const ReturnStmt = C.seq(.{
        C.STR("return"), C.opt(C.seq(.{ C.WS, C.Call(.Expr) })), C.WS, C.CH(';'),
        C.RET
    });

    // ExprStmt <- Expr WS ';'
    pub const ExprStmt = C.seq(.{
        C.Call(.Expr), C.WS, C.CH(';'),
        C.RET
    });

    // Stmt <- VarDecl / IfStmt / WhileLoop / ReturnStmt / ExprStmt
    pub const Stmt = C.seq(.{
        C.alt(.{
            C.Call(.VarDecl),
            C.Call(.IfStmt),
            C.Call(.WhileLoop),
            C.Call(.ReturnStmt),
            C.Call(.ExprStmt)
        }),
        C.RET
    });

    // Block <- '{' WS Stmt* WS '}'
    pub const Block = C.seq(.{
        C.CH('{'), C.WS,
        C.many0(C.seq(.{ C.Call(.Stmt), C.WS })),
        C.CH('}'),
        C.RET
    });

    // FuncParam <- Ident
    pub const FuncParam = C.seq(.{ C.IDENT, C.RET });

    // FuncDecl <- 'function' WS Ident WS '(' WS (FuncParam (WS ',' WS FuncParam)*)? WS ')' WS Block
    pub const FuncDecl = C.seq(.{
        C.STR("function"), C.WS, C.IDENT, C.WS,
        C.CH('('), C.WS,
        C.opt(C.seq(.{
            C.Call(.FuncParam),
            C.many0(C.seq(.{ C.WS, C.CH(','), C.WS, C.Call(.FuncParam) }))
        })),
        C.WS, C.CH(')'), C.WS, C.Call(.Block),
        C.RET
    });

    // Program <- WS (FuncDecl WS / Stmt WS)* EOF
    pub const Program = C.seq(.{
        C.WS,
        C.many0(C.seq(.{
            C.alt(.{ C.Call(.FuncDecl), C.Call(.Stmt) }),
            C.WS
        })),
        C.END, C.ACCEPT
    });

    // Start rule
    pub const Start = C.Call(.Program);
};
